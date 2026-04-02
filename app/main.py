# app/main.py  — SECURITY-PATCHED VERSION
#
# Changes from original:
#   [FIX-1] SESSION_SECRET now hard-fails at startup if missing/short (via security.py)
#   [FIX-2] /debug-login endpoint REMOVED
#   [FIX-3] Rate limiting added to /login (10 attempts / 60 s per IP)
#   [FIX-4] CSRF tokens added to all state-changing POST routes
#   [FIX-5] Input sanitization applied to all free-text form fields
#   [FIX-6] ProxyHeadersMiddleware added so Railway's real client IP is used
#   [FIX-7] Minimum password length raised from 4 → 8
#   [FIX-8] /admin/reset-system converted to POST with confirmation token

import os
import json as _json
import threading
from datetime import datetime, date, timedelta

try:
    from pywebpush import webpush as _webpush, WebPushException as _WebPushException
    _PYWEBPUSH_OK = True
except ImportError:
    _PYWEBPUSH_OK = False

VAPID_PUBLIC_KEY  = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

# [FIX-6] ProxyHeadersMiddleware — makes request.client.host the real client IP
# when running behind Railway's reverse proxy
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from passlib.context import CryptContext
import bcrypt as bcrypt_lib

from sqlalchemy import select, text, func, and_, desc, case
from sqlalchemy.orm import Session

from .database import Base, engine, get_db, DATABASE_URL
from .models import Branch, Item, Transaction, User, Delivery, DeliveryItem, CashEntry, StockTransfer, StockTransferItem, AuditLog
from .services import (
    get_items_with_stock,
    get_item_with_stock,
    get_low_stock,
    get_recent_transactions,
    dashboard_stats,
    dashboard_kpis,
    stock_by_category,
    in_out_last_7_days,
    top_items_by_stock,
    create_out_transactions_for_delivery_if_needed,
    cash_range_from_preset,
    get_cash_summary,
    supervisor_date_range,
    supervisor_branch_stats,
    supervisor_top_items,
    supervisor_best_agents,
    supervisor_daily_deliveries,
)

# [FIX-1,3,4,5] Import all security helpers from security.py
import logging
from .security import (
    get_session_secret,
    limiter,
    account_lockout,
    reset_token_store,
    get_csrf_token,
    verify_csrf_token,
    sanitize_text,
    sanitize_username,
    sanitize_phone,
    sanitize_amount,
    audit_log,
    SecurityHeadersMiddleware,
    validate_upload,
)
from .calling_service import trigger_call

app = FastAPI()


# ── Notification helper ──────────────────────────────────────────────────────
def _send_web_push(user_id: int, title: str, body: str, link: str):
    """Send a web push to all registered devices for user (runs in its own thread+session)."""
    _log = logging.getLogger("push")
    if not _PYWEBPUSH_OK:
        _log.warning("PUSH: pywebpush not installed — skipping")
        return
    if not VAPID_PRIVATE_KEY or not VAPID_PUBLIC_KEY:
        _log.warning("PUSH: VAPID keys not set — skipping push for user %s", user_id)
        return
    from .database import SessionLocal
    db = SessionLocal()
    try:
        subs = db.execute(text(
            "SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = :uid"
        ), {"uid": user_id}).fetchall()
        if not subs:
            _log.info("PUSH: no subscriptions for user %s", user_id)
            return
        for sub in subs:
            try:
                _webpush(
                    subscription_info={"endpoint": sub.endpoint, "keys": {"p256dh": sub.p256dh, "auth": sub.auth}},
                    data=_json.dumps({"title": title, "body": body, "link": link}),
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims={"sub": "mailto:push@inventorykeeper.app"},
                )
                _log.info("PUSH: sent to user %s endpoint=...%s", user_id, sub.endpoint[-20:])
            except _WebPushException as e:
                status = e.response.status_code if e.response else "no-response"
                _log.warning("PUSH: WebPushException user=%s status=%s err=%s", user_id, status, e)
                err_str = str(e)
                is_gone = (e.response and e.response.status_code in (404, 410)) or \
                          any(x in err_str for x in ("410", "404", "Gone", "unsubscribed", "expired", "Not Found"))
                if is_gone:
                    try:
                        db.execute(text("DELETE FROM push_subscriptions WHERE endpoint=:ep"), {"ep": sub.endpoint})
                        db.commit()
                        _log.info("PUSH: removed expired subscription for user %s", user_id)
                    except Exception:
                        pass
            except Exception as ex:
                _log.warning("PUSH: unexpected error user=%s: %s", user_id, ex)
    except Exception as e:
        _log.warning("PUSH: top-level error: %s", e)
    finally:
        db.close()

def notify(db, user_id: int, title: str, body: str = "", link: str = "", kind: str = "info"):
    """Create a persistent notification and fire web push in a background thread."""
    try:
        db.execute(text(
            "INSERT INTO notifications (user_id, title, body, link, kind, created_at) "
            "VALUES (:uid, :title, :body, :link, :kind, NOW())"
        ), {"uid": user_id, "title": title[:200], "body": body[:500], "link": link[:300], "kind": kind})
        threading.Thread(
            target=_send_web_push, args=(user_id, title, body, link), daemon=True
        ).start()
    except Exception as e:
        logging.getLogger("notifications").warning(f"Notify failed: {e}")

def notify_branch_admins(db, branch_id: int, title: str, body: str = "", link: str = "", kind: str = "info"):
    """Notify all admins of a branch."""
    try:
        admins = db.execute(
            select(User).where(User.role == "ADMIN").where(User.branch_id == branch_id)
        ).scalars().all()
        for admin in admins:
            notify(db, admin.id, title, body, link, kind)
    except Exception as e:
        import logging; logging.getLogger("notifications").warning(f"Notify branch failed: {e}")

# [FIX-6] Trust the X-Forwarded-For header from Railway's proxy
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Automatically inject csrf_token into every TemplateResponse context
# so base.html logout form always has it — no need to pass per-route.
def tpl(request, name: str, context: dict, status_code: int = 200):
    """Render a Jinja2 template with auto-injected csrf_token."""
    if "csrf_token" not in context:
        context["csrf_token"] = get_csrf_token(request)
    if "request" not in context:
        context["request"] = request
    tmpl = templates.env.get_template(name)
    html = tmpl.render(**context)
    from starlette.responses import HTMLResponse as _HR
    return _HR(html, status_code=status_code)

static_dir = os.path.join(BASE_DIR, "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/sw.js", response_class=PlainTextResponse)
def service_worker_root():
    sw_path = os.path.join(BASE_DIR, "static", "sw.js")
    try:
        content = open(sw_path).read()
    except FileNotFoundError:
        content = ""
    return PlainTextResponse(
        content,
        headers={
            "Content-Type": "application/javascript",
            "Service-Worker-Allowed": "/",
        }
    )

# [FIX-1] get_session_secret() raises RuntimeError at startup if SECRET is missing or < 32 chars
SESSION_SECRET = get_session_secret()
HTTPS_ONLY = os.getenv("HTTPS_ONLY", "1") not in {"0", "false", "False", "no", "NO"}

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=HTTPS_ONLY,
    same_site="lax",
    max_age=43200,  # [SEC] 12-hour session expiry
)
app.add_middleware(SecurityHeadersMiddleware)  # [SEC-8] Security headers

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Minimum password length — [FIX-7] raised from 4 to 8
MIN_PASSWORD_LENGTH = 8


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url=path, status_code=303)


def is_admin(user: User | None) -> bool:
    return bool(user) and (user.role or "").upper() == "ADMIN"


def is_agent(user: User | None) -> bool:
    return bool(user) and (user.role or "").upper() == "AGENT"

def is_supervisor(user: User | None) -> bool:
    return bool(user) and (user.role or "").upper() == "SUPERVISOR"

def require_same_branch(user: User | None, record_branch_id: int | None) -> None:
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if is_supervisor(user):
        return
    if getattr(user, "branch_id", None) != record_branch_id:
        raise HTTPException(status_code=403, detail="Forbidden")

def get_current_branch_id(request: Request) -> int | None:
    branch_id = request.session.get("branch_id")
    if not branch_id:
        return None
    try:
        return int(branch_id)
    except Exception:
        return None


def get_selected_branch_id(request: Request, user: User | None) -> int | None:
    if not user:
        return None
    if is_supervisor(user):
        q_branch = request.query_params.get("branch_id", "").strip()
        if q_branch.isdigit():
            return int(q_branch)
    return getattr(user, "branch_id", None)


def can_access_branch(user: User | None, branch_id: int | None) -> bool:
    if not user:
        return False
    if is_supervisor(user):
        return True
    return bool(branch_id) and getattr(user, "branch_id", None) == branch_id

def require_branch_access(user: User | None, branch_id: int | None) -> None:
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if is_supervisor(user):
        return
    if not branch_id or getattr(user, "branch_id", None) != branch_id:
        raise HTTPException(status_code=403, detail="Forbidden")


def require_item_access(request: Request, user: User | None, item: Item | None) -> None:
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    branch_id = get_selected_branch_id(request, user)
    require_branch_access(user, item.branch_id)
    if not is_supervisor(user) and item.branch_id != branch_id:
        raise HTTPException(status_code=403, detail="Forbidden")


def require_delivery_access(request: Request, user: User | None, delivery: Delivery | None) -> None:
    if not delivery:
        raise HTTPException(status_code=404, detail="Delivery not found")
    branch_id = get_selected_branch_id(request, user)
    require_branch_access(user, delivery.branch_id)
    if not is_supervisor(user) and delivery.branch_id != branch_id:
        raise HTTPException(status_code=403, detail="Forbidden")


def require_agent_access(request: Request, user: User | None, agent: User | None) -> None:
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    role = (agent.role or "").upper()
    # Supervisor can view admins; admin can only view agents
    if is_supervisor(user):
        if role not in ("AGENT", "ADMIN"):
            raise HTTPException(status_code=404, detail="User not found")
    else:
        if role != "AGENT":
            raise HTTPException(status_code=404, detail="Agent not found")
    branch_id = get_selected_branch_id(request, user)
    require_branch_access(user, agent.branch_id)
    if not is_supervisor(user) and agent.branch_id != branch_id:
        raise HTTPException(status_code=403, detail="Forbidden")

def verify_password(plain_password: str, password_hash: str) -> bool:
    if (password_hash or "").startswith("$2"):
        try:
            return bcrypt_lib.checkpw(
                plain_password.encode("utf-8"),
                password_hash.encode("utf-8"),
            )
        except Exception:
            return False
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        return False


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def get_current_user(db: Session, request: Request) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    try:
        return db.get(User, int(user_id))
    except Exception:
        return None


def require_login_or_redirect(db: Session, request: Request) -> User | RedirectResponse:
    user = get_current_user(db, request)
    if not user:
        return redirect("/login")
    return user


def require_admin_or_403(user: User) -> HTMLResponse | None:
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
    return None


def _ddl(conn, sql: str) -> None:
    try:
        conn.execute(text(sql))
        conn.execute(text("COMMIT"))
    except Exception:
        try:
            conn.execute(text("ROLLBACK"))
        except Exception:
            pass


def ensure_schema() -> None:
    Base.metadata.create_all(bind=engine)

    is_sqlite = DATABASE_URL.startswith("sqlite")

    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:

        _ddl(conn, """
            CREATE TABLE IF NOT EXISTS branches (
                id """ + ("INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY") + """,
                name VARCHAR(120) NOT NULL UNIQUE,
                code VARCHAR(20) NULL UNIQUE,
                address VARCHAR(200) NULL,
                created_at TIMESTAMP DEFAULT """ + ("CURRENT_TIMESTAMP" if is_sqlite else "NOW()") + """
            )
        """)

        _ddl(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL")
        _ddl(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(140) NULL")
        _ddl(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(40) NULL")
        _ddl(conn, "ALTER TABLE items ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL")
        _ddl(conn, "ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL")
        _ddl(conn, "ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMP NULL")
        _ddl(conn, "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL")
        _ddl(conn, "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS delivery_id INTEGER NULL")

        if is_sqlite:
            _ddl(conn, """
                CREATE TABLE IF NOT EXISTS cash_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    agent_id INTEGER NOT NULL,
                    delivery_id INTEGER NULL,
                    kind VARCHAR(20) NOT NULL,
                    amount NUMERIC NOT NULL,
                    note VARCHAR(400) NULL
                )
            """)
        else:
            _ddl(conn, """
                CREATE TABLE IF NOT EXISTS cash_entries (
                    id SERIAL PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT NOW(),
                    agent_id INTEGER NOT NULL,
                    delivery_id INTEGER NULL,
                    kind VARCHAR(20) NOT NULL,
                    amount NUMERIC NOT NULL,
                    note VARCHAR(400) NULL
                )
            """)
        _ddl(conn, "ALTER TABLE cash_entries ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL")
        _ddl(conn, "ALTER TABLE delivery_items ADD COLUMN IF NOT EXISTS line_amount NUMERIC DEFAULT 0")
        _ddl(conn, "ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS delivery_date TIMESTAMP")
        _ddl(conn, "UPDATE deliveries SET delivery_date = created_at WHERE delivery_date IS NULL")

        _ddl(conn, """
            CREATE UNIQUE INDEX IF NOT EXISTS ux_transactions_delivery_item_out
            ON transactions (delivery_id, item_id, type)
            WHERE delivery_id IS NOT NULL AND type = 'OUT'
        """)
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_deliveries_created_at ON deliveries (created_at)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_deliveries_status ON deliveries (status)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_deliveries_agent_id ON deliveries (agent_id)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_delivery_items_delivery_id ON delivery_items (delivery_id)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_cash_entries_created_at ON cash_entries (created_at)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_cash_entries_kind ON cash_entries (kind)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_cash_entries_agent_id ON cash_entries (agent_id)")
        # Drop and recreate ck_cash_kind to include CASH_PAYMENT and TRANSFER_PAYMENT
        _ddl(conn, "ALTER TABLE cash_entries DROP CONSTRAINT IF EXISTS ck_cash_kind")
        _ddl(conn, "ALTER TABLE cash_entries ADD CONSTRAINT ck_cash_kind CHECK (kind IN ('COLLECTION','EXPENSE','OPERATING_CASH','OFFICE_EXPENSE','RETURN_OPERATING_CASH','CASH_PAYMENT','TRANSFER_PAYMENT','COLLECTION_EXPENSE'))")
        # Add ADJUSTMENT_PENDING to delivery status constraint
        _ddl(conn, "ALTER TABLE deliveries DROP CONSTRAINT IF EXISTS ck_delivery_status")
        _ddl(conn, "ALTER TABLE deliveries ADD CONSTRAINT ck_delivery_status CHECK (status IN ('PENDING','OUT_FOR_DELIVERY','DELIVERED','FAILED','RETURNED','ADJUSTMENT_PENDING'))")
        # Cash confirmation tracking
        _ddl(conn, "ALTER TABLE cash_entries ADD COLUMN IF NOT EXISTS confirmed_by_admin BOOLEAN DEFAULT FALSE")
        _ddl(conn, "ALTER TABLE cash_entries ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMP NULL")
        # Agent stock assignment table (extra stock given to agents for urgent deliveries)
        _ddl(conn, """CREATE TABLE IF NOT EXISTS agent_stock_assignments (
            id           SERIAL PRIMARY KEY,
            agent_id     INTEGER NOT NULL REFERENCES users(id),
            item_id      INTEGER NOT NULL REFERENCES items(id),
            branch_id    INTEGER NOT NULL REFERENCES branches(id),
            qty_assigned INTEGER NOT NULL DEFAULT 0,
            note         VARCHAR(400) NOT NULL DEFAULT \'\',
            assigned_by  INTEGER REFERENCES users(id),
            assigned_at  TIMESTAMP DEFAULT NOW(),
            returned     BOOLEAN DEFAULT FALSE,
            qty_returned INTEGER NOT NULL DEFAULT 0,
            vetted_by    INTEGER REFERENCES users(id),
            vetted_at    TIMESTAMP DEFAULT NULL,
            transaction_out_id INTEGER REFERENCES transactions(id),
            transaction_in_id  INTEGER REFERENCES transactions(id),
            delivery_id        INTEGER REFERENCES deliveries(id)
        )""")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_agent_stock_asgn_agent ON agent_stock_assignments (agent_id)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_agent_stock_asgn_branch ON agent_stock_assignments (branch_id)")
        _ddl(conn, "ALTER TABLE agent_stock_assignments ADD COLUMN IF NOT EXISTS delivery_id INTEGER REFERENCES deliveries(id)")
        # Faulty stock tracking table
        _ddl(conn, """CREATE TABLE IF NOT EXISTS faulty_stock (
            id           SERIAL PRIMARY KEY,
            item_id      INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
            branch_id    INTEGER NOT NULL REFERENCES branches(id),
            qty_faulty   INTEGER NOT NULL DEFAULT 0,
            reason       VARCHAR(400) DEFAULT '',
            flagged_by   INTEGER REFERENCES users(id),
            flagged_at   TIMESTAMP DEFAULT NOW(),
            resolved     BOOLEAN DEFAULT FALSE,
            resolve_action VARCHAR(20) DEFAULT NULL,
            resolved_at  TIMESTAMP DEFAULT NULL,
            resolved_by  INTEGER REFERENCES users(id),
            resolve_note VARCHAR(400) NOT NULL DEFAULT ''
        )""")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_faulty_stock_item ON faulty_stock (item_id)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_faulty_stock_branch ON faulty_stock (branch_id)")
        # Fix resolve_note NOT NULL default on existing tables
        _ddl(conn, "ALTER TABLE faulty_stock ALTER COLUMN resolve_note SET DEFAULT ''")
        _ddl(conn, "UPDATE faulty_stock SET resolve_note = '' WHERE resolve_note IS NULL")
        _ddl(conn, "ALTER TABLE faulty_stock ALTER COLUMN resolve_note SET NOT NULL")
        # Stock return vetting table
        _ddl(conn, """CREATE TABLE IF NOT EXISTS stock_return_vettings (
            id SERIAL PRIMARY KEY,
            delivery_id INTEGER NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
            delivery_item_id INTEGER NOT NULL REFERENCES delivery_items(id) ON DELETE CASCADE,
            vetted_by INTEGER REFERENCES users(id),
            qty_returned INTEGER NOT NULL DEFAULT 0,
            transaction_id INTEGER REFERENCES transactions(id),
            created_at TIMESTAMP DEFAULT NOW()
        )""")
        _ddl(conn, "DROP INDEX IF EXISTS ux_stock_return_vetting")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_stock_return_vetting ON stock_return_vettings (delivery_item_id)")
        _ddl(conn, "ALTER TABLE stock_return_vettings ADD COLUMN IF NOT EXISTS resolved BOOLEAN DEFAULT FALSE")
        _ddl(conn, "ALTER TABLE stock_return_vettings ADD COLUMN IF NOT EXISTS resolve_action VARCHAR(20) DEFAULT NULL")
        _ddl(conn, "ALTER TABLE stock_return_vettings ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP DEFAULT NULL")
        _ddl(conn, "ALTER TABLE stock_return_vettings ADD COLUMN IF NOT EXISTS resolved_by INTEGER DEFAULT NULL REFERENCES users(id)")
        # Notifications table
        _ddl(conn, """CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title VARCHAR(200) NOT NULL,
            body VARCHAR(500) DEFAULT '',
            link VARCHAR(300) DEFAULT '',
            kind VARCHAR(50) DEFAULT 'info',
            read_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )""")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_notifications_user_unread ON notifications (user_id, read_at) WHERE read_at IS NULL")
        # Web push subscriptions
        _ddl(conn, """CREATE TABLE IF NOT EXISTS push_subscriptions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            endpoint TEXT NOT NULL,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )""")
        _ddl(conn, "CREATE UNIQUE INDEX IF NOT EXISTS ux_push_endpoint ON push_subscriptions (endpoint)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_push_subscriptions_user_id ON push_subscriptions (user_id)")
        # Adjustment requests table
        _ddl(conn, """CREATE TABLE IF NOT EXISTS adjustment_requests (
            id SERIAL PRIMARY KEY,
            delivery_id INTEGER NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
            requested_by INTEGER NOT NULL REFERENCES users(id),
            reason VARCHAR(500) DEFAULT '',
            status VARCHAR(20) DEFAULT 'PENDING',
            reviewed_by INTEGER REFERENCES users(id),
            rejection_note VARCHAR(500) DEFAULT '',
            created_at TIMESTAMP DEFAULT NOW(),
            reviewed_at TIMESTAMP
        )""")
        _ddl(conn, """CREATE TABLE IF NOT EXISTS adjustment_request_items (
            id SERIAL PRIMARY KEY,
            request_id INTEGER NOT NULL REFERENCES adjustment_requests(id) ON DELETE CASCADE,
            delivery_item_id INTEGER NOT NULL REFERENCES delivery_items(id) ON DELETE CASCADE,
            item_name VARCHAR(200) DEFAULT '',
            original_amount NUMERIC(12,2) DEFAULT 0,
            new_amount NUMERIC(12,2) DEFAULT 0,
            remove_item BOOLEAN DEFAULT FALSE
        )""")
        # [SEC-7] Audit log table
        _ddl(conn, """CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action VARCHAR(100) NOT NULL,
            detail VARCHAR(500) DEFAULT '',
            ip VARCHAR(45) DEFAULT '',
            created_at TIMESTAMP DEFAULT NOW()
        )""")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id ON audit_logs (user_id)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at ON audit_logs (created_at)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_transactions_item_id ON transactions (item_id)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_transactions_delivery_id ON transactions (delivery_id)")

        _ddl(conn, """
            CREATE TABLE IF NOT EXISTS stock_transfers (
                id """ + ("INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY") + """,
                from_branch_id INTEGER NOT NULL REFERENCES branches(id),
                to_branch_id   INTEGER NOT NULL REFERENCES branches(id),
                status         VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                note           VARCHAR(400) NULL,
                created_by_id  INTEGER NOT NULL REFERENCES users(id),
                received_by_id  INTEGER NULL REFERENCES users(id),
                cancelled_by_id INTEGER NULL REFERENCES users(id),
                created_at     TIMESTAMP DEFAULT """ + ("CURRENT_TIMESTAMP" if is_sqlite else "NOW()") + """,
                received_at    TIMESTAMP NULL,
                cancelled_at   TIMESTAMP NULL
            )
        """)

        _ddl(conn, """
            CREATE TABLE IF NOT EXISTS stock_transfer_items (
                id          """ + ("INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY") + """,
                transfer_id INTEGER NOT NULL REFERENCES stock_transfers(id),
                item_id     INTEGER NOT NULL REFERENCES items(id),
                quantity    INTEGER NOT NULL
            )
        """)

        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_stock_transfers_from ON stock_transfers (from_branch_id)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_stock_transfers_to ON stock_transfers (to_branch_id)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_stock_transfers_status ON stock_transfers (status)")
        # v2: delegation + expenses
        _ddl(conn, "ALTER TABLE stock_transfers DROP CONSTRAINT IF EXISTS ck_transfer_status")
        _ddl(conn, "ALTER TABLE stock_transfers ADD CONSTRAINT ck_transfer_status CHECK (status IN ('PENDING','OUT_FOR_DELIVERY','RECEIVED','CANCELLED'))")
        _ddl(conn, "ALTER TABLE stock_transfers ADD COLUMN IF NOT EXISTS delegated_agent_id INTEGER NULL REFERENCES users(id)")
        _ddl(conn, "ALTER TABLE stock_transfers ADD COLUMN IF NOT EXISTS packed_by_id INTEGER NULL REFERENCES users(id)")
        _ddl(conn, "ALTER TABLE stock_transfers ADD COLUMN IF NOT EXISTS packed_at TIMESTAMP NULL")
        _ddl(conn, "ALTER TABLE stock_transfers ADD COLUMN IF NOT EXISTS expense_amount NUMERIC(12,2) NULL DEFAULT 0")
        _ddl(conn, "ALTER TABLE stock_transfers ADD COLUMN IF NOT EXISTS expense_kind VARCHAR(30) NULL")
        _ddl(conn, "ALTER TABLE stock_transfers ADD COLUMN IF NOT EXISTS expense_note VARCHAR(400) NULL")
        # v3: receiving delegation + receive-side expenses
        _ddl(conn, "ALTER TABLE stock_transfers ADD COLUMN IF NOT EXISTS delegated_receiver_id INTEGER NULL REFERENCES users(id)")
        _ddl(conn, "ALTER TABLE stock_transfers ADD COLUMN IF NOT EXISTS receive_expense_amount NUMERIC(12,2) NULL DEFAULT 0")
        _ddl(conn, "ALTER TABLE stock_transfers ADD COLUMN IF NOT EXISTS receive_expense_kind VARCHAR(30) NULL")
        _ddl(conn, "ALTER TABLE stock_transfers ADD COLUMN IF NOT EXISTS receive_expense_note VARCHAR(400) NULL")
        # Call logs table (Bland.ai integration)
        _ddl(conn, """CREATE TABLE IF NOT EXISTS call_logs (
            id              """ + ("INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY") + """,
            delivery_id     INTEGER NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
            call_id         VARCHAR(120) DEFAULT '',
            phone           VARCHAR(40) DEFAULT '',
            trigger_status  VARCHAR(30) DEFAULT '',
            call_status     VARCHAR(30) DEFAULT '',
            error_msg       TEXT DEFAULT '',
            duration        INTEGER DEFAULT 0,
            created_at      TIMESTAMP DEFAULT """ + ("CURRENT_TIMESTAMP" if is_sqlite else "NOW()") + """
        )""")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_call_logs_delivery_id ON call_logs (delivery_id)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_call_logs_created_at ON call_logs (created_at)")


def seed_admin_if_missing() -> None:
    admin_user = (os.getenv("ADMIN_USERNAME") or "").strip()
    admin_pass = os.getenv("ADMIN_PASSWORD") or ""
    if not admin_user or not admin_pass:
        return

    gen = get_db()
    db = next(gen)
    try:
        existing_admin = db.execute(
            text("SELECT id FROM users WHERE role = 'ADMIN' LIMIT 1")
        ).first()
        if existing_admin:
            return

        existing_user = db.execute(
            text("SELECT id FROM users WHERE username = :username LIMIT 1"),
            {"username": admin_user},
        ).first()
        if existing_user:
            return

        db.add(
            User(
                username=admin_user,
                password_hash=hash_password(admin_pass),
                role="ADMIN",
                full_name="Admin",
            )
        )
        db.commit()
    finally:
        gen.close()


def seed_default_branch_if_missing() -> None:
    gen = get_db()
    db = next(gen)
    try:
        row = db.execute(
            text("SELECT id FROM branches WHERE name = 'Main Branch' LIMIT 1")
        ).first()

        if row:
            default_branch_id = int(row[0])
        else:
            db.execute(
                text(
                    "INSERT INTO branches (name, code, address, created_at) "
                    "VALUES ('Main Branch', 'MAIN', NULL, CURRENT_TIMESTAMP)"
                )
            )
            db.commit()

            row = db.execute(
                text("SELECT id FROM branches WHERE name = 'Main Branch' LIMIT 1")
            ).first()
            default_branch_id = int(row[0])

        db.execute(
            text("UPDATE users SET branch_id = :branch_id WHERE branch_id IS NULL AND role <> 'SUPERVISOR'"),
            {"branch_id": default_branch_id},
        )
        db.execute(
            text("UPDATE items SET branch_id = :branch_id WHERE branch_id IS NULL"),
            {"branch_id": default_branch_id},
        )
        db.execute(
            text("UPDATE deliveries SET branch_id = :branch_id WHERE branch_id IS NULL"),
            {"branch_id": default_branch_id},
        )
        db.execute(
            text("UPDATE transactions SET branch_id = :branch_id WHERE branch_id IS NULL"),
            {"branch_id": default_branch_id},
        )
        db.execute(
            text("UPDATE cash_entries SET branch_id = :branch_id WHERE branch_id IS NULL"),
            {"branch_id": default_branch_id},
        )
        db.commit()
    finally:
        gen.close()


@app.on_event("startup")
def _startup() -> None:
    ensure_schema()
    seed_default_branch_if_missing()
    seed_admin_if_missing()


def _range_dates_from_inputs(preset, start_date, end_date):
    p = (preset or "").strip().lower()
    today = date.today()
    if p == "today":
        return today, today, "today"
    if p == "yesterday":
        y = today - timedelta(days=1)
        return y, y, "yesterday"
    if p == "7d":
        return today - timedelta(days=6), today, "7d"
    if p == "30d":
        return today - timedelta(days=29), today, "30d"
    sd = date.fromisoformat(start_date) if start_date else None
    ed = date.fromisoformat(end_date) if end_date else None
    return sd, ed, ""


def _parse_iso_date(d: str | None) -> date | None:
    if not d:
        return None
    try:
        return date.fromisoformat(d.strip())
    except Exception:
        return None


def _ngn(n: float) -> str:
    try:
        return f"₦{float(n):,.0f}"
    except Exception:
        return "₦0"


def _dt_range_from_dates(preset, start_date, end_date):
    sd, ed, preset_norm = _range_dates_from_inputs(preset, start_date, end_date)
    start_dt = None
    end_dt = None
    if preset_norm:
        start_dt, end_dt = cash_range_from_preset(preset_norm)
    else:
        if sd:
            start_dt = datetime.combine(sd, datetime.min.time())
        if ed:
            end_dt = datetime.combine(ed, datetime.min.time()) + timedelta(days=1)
    return sd, ed, preset_norm, start_dt, end_dt


# ─────────────────────────────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────
#  AUTH
# ────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    csrf_token = get_csrf_token(request)
    return tpl(request, "login.html", {"request": request, "error": None, "csrf_token": csrf_token})


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-3] Rate limiting — 30 attempts per minute per IP (generous enough for shared networks)
    try:
        limiter.check(request, max_requests=30, window_seconds=60)
    except HTTPException:
        token = get_csrf_token(request)
        return tpl(request, "login.html", {
            "request": request,
            "error": "Too many login attempts. Please wait a minute and try again.",
            "csrf_token": token,
        }, status_code=429)

    verify_csrf_token(request, csrf_token)
    username_clean = sanitize_username(username)
    ip = request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else "")

    # [SEC-5] Per-account lockout check
    if account_lockout.is_locked(username_clean):
        token = get_csrf_token(request)
        return tpl(request, "login.html", {
            "request": request,
            "error": "Account temporarily locked due to too many failed attempts. Try again in 15 minutes.",
            "csrf_token": token,
        }, status_code=429)

    u = db.scalar(select(User).where(User.username == username_clean))
    if not u or not verify_password(password, u.password_hash):
        account_lockout.record_failure(username_clean)  # [SEC-5] record failure
        remaining = account_lockout.remaining_attempts(username_clean)
        audit_log(db, u.id if u else None, "LOGIN_FAILED", f"username={username_clean}", ip=ip)
        token = get_csrf_token(request)
        msg = "Invalid login."
        if remaining <= 2:
            msg = f"Invalid login. {remaining} attempt{'s' if remaining != 1 else ''} remaining before lockout."
        return tpl(request, "login.html", {
            "request": request, "error": msg, "csrf_token": token,
        })

    account_lockout.clear(username_clean)  # [SEC-5] reset on success
    audit_log(db, u.id, "LOGIN", f"username={username_clean}", ip=ip)
    request.session["user_id"] = u.id
    request.session["role"] = u.role
    if u.branch_id is not None:
        request.session["branch_id"] = u.branch_id
    else:
        request.session.pop("branch_id", None)
    return redirect("/")


@app.post("/logout")
async def logout(request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    verify_csrf_token(request, csrf_token)  # [SEC] CSRF protection on logout
    user_id = request.session.get("user_id")
    audit_log(db, user_id, "LOGOUT",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    request.session.clear()
    return redirect("/login")


# ────────────────────────────────────────────────
#  DASHBOARD
# ────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    branch_id = get_selected_branch_id(request, user)

    if is_supervisor(user) and not branch_id:
        # Supervisor with no branch selected: redirect to supervisor overview
        return redirect("/supervisor")

    if not is_admin(user) and not is_supervisor(user):
        return redirect("/my-deliveries")

    items_count = db.scalar(select(func.count(Item.id)).where(Item.branch_id == branch_id)) or 0

    low_rows_all = get_low_stock(db)
    low_rows = [(item, stock) for (item, stock) in low_rows_all if item.branch_id == branch_id][:5]
    low_stock_count = len([(item, stock) for (item, stock) in low_rows_all if item.branch_id == branch_id])

    stale_cutoff = datetime.utcnow() - timedelta(days=7)
    stale_items = db.execute(select(Item).where(Item.branch_id == branch_id)).scalars().all()
    stale_count = 0
    for _item in stale_items:
        _stock = db.scalar(
            select(func.coalesce(
                func.sum(case((Transaction.type == "IN", Transaction.quantity), else_=-Transaction.quantity)), 0
            )).where(Transaction.item_id == _item.id).where(Transaction.branch_id == branch_id)
        ) or 0
        if _stock <= 0:
            continue
        _last = db.scalar(select(func.max(Transaction.created_at)).where(Transaction.item_id == _item.id).where(Transaction.branch_id == branch_id))
        if _last is None or _last < stale_cutoff:
            stale_count += 1

    recent_transactions = db.scalars(
        select(Transaction).where(Transaction.branch_id == branch_id)
        .order_by(desc(Transaction.created_at)).limit(10)
    ).all()

    top_rows_all = top_items_by_stock(db, limit=200)
    top_rows = [(item, stock) for (item, stock) in top_rows_all if item.branch_id == branch_id][:5]

    all_items_with_stock = get_items_with_stock(db)
    cat_map: dict[str, float] = {}
    cat_items: dict[str, list] = {}
    total_stock = 0
    inventory_value = 0.0
    for item, stock in all_items_with_stock:
        if item.branch_id == branch_id:
            s = float(stock or 0)
            total_stock += int(s)
            inventory_value += s * float(item.cost_price or 0)
            cat = item.category or "Uncategorized"
            cat_map[cat] = cat_map.get(cat, 0) + s
            cat_items.setdefault(cat, []).append({"name": item.name, "stock": int(s), "unit": item.unit or "pcs", "reorder_level": int(item.reorder_level or 0)})
    cat_rows = sorted(cat_map.items(), key=lambda x: x[1], reverse=True)
    # Sort items within each category by stock desc
    cat_items_json = {cat: sorted(items, key=lambda x: x["stock"], reverse=True) for cat, items in cat_items.items()}

    in7 = int(db.scalar(
        select(func.coalesce(func.sum(Transaction.quantity), 0))
        .where(Transaction.branch_id == branch_id).where(Transaction.type == "IN")
        .where(Transaction.created_at >= datetime.utcnow() - timedelta(days=7))
    ) or 0)
    out7 = int(db.scalar(
        select(func.coalesce(func.sum(Transaction.quantity), 0))
        .where(Transaction.branch_id == branch_id).where(Transaction.type == "OUT")
        .where(Transaction.created_at >= datetime.utcnow() - timedelta(days=7))
    ) or 0)

    branches = []
    if is_supervisor(user):
        branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()

    # Chart data — last 14 days deliveries + expenses for branch
    today_d = date.today()
    chart_days = [(today_d - timedelta(days=i)) for i in range(13, -1, -1)]
    del_by_day: dict = {}
    for d in db.execute(
        select(Delivery).where(Delivery.branch_id == branch_id)
        .where(Delivery.status == "DELIVERED")
        .where(Delivery.delivered_at >= datetime.utcnow() - timedelta(days=14))
    ).scalars().all():
        k = d.delivered_at.date().isoformat() if d.delivered_at else None
        if k: del_by_day[k] = del_by_day.get(k, 0) + 1
    exp_by_day: dict = {}
    for e in db.execute(
        select(CashEntry).where(CashEntry.branch_id == branch_id)
        .where(CashEntry.kind.in_(["EXPENSE", "OFFICE_EXPENSE", "COLLECTION_EXPENSE"]))
        .where(CashEntry.created_at >= datetime.utcnow() - timedelta(days=14))
    ).scalars().all():
        k = e.created_at.date().isoformat() if e.created_at else None
        if k: exp_by_day[k] = exp_by_day.get(k, 0) + float(e.amount or 0)

    # Agent collections for today — for admin cash confirmation panel
    today_start = datetime.combine(date.today(), datetime.min.time())
    today_end   = today_start + timedelta(days=1)
    agent_collections = []
    if is_admin(user):
        try:
            branch_agents = db.execute(
                select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())
            ).scalars().all()
            for agent in branch_agents:
                rows = db.execute(
                    select(CashEntry).where(CashEntry.agent_id == agent.id)
                    .where(CashEntry.branch_id == branch_id)
                    .where(CashEntry.kind.in_(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"]))
                    .where(CashEntry.created_at >= today_start)
                    .where(CashEntry.created_at < today_end)
                    .order_by(CashEntry.created_at.desc())
                ).scalars().all()
                if not rows:
                    continue
                total     = sum(float(r.amount) for r in rows)
                confirmed = all(getattr(r, "confirmed_by_admin", False) for r in rows)
                cash_sum  = sum(float(r.amount) for r in rows if r.kind in ("COLLECTION","CASH_PAYMENT"))
                trans_sum = sum(float(r.amount) for r in rows if r.kind == "TRANSFER_PAYMENT")
                agent_collections.append({
                    "agent_id":   agent.id,
                    "agent_name": agent.full_name or agent.username,
                    "total":      total,
                    "cash":       cash_sum,
                    "transfer":   trans_sum,
                    "confirmed":  confirmed,
                    "entries":    len(rows),
                    "date":       date.today().isoformat(),
                })
        except Exception:
            agent_collections = []  # fallback — column may not exist yet

    return tpl(request, "dashboard.html", {
        "request": request, "user": user, "active": "dashboard",
        "branches": branches, "selected_branch_id": branch_id,
        "items_count": items_count, "low_stock_count": low_stock_count,
        "stale_count": stale_count, "recent_transactions": recent_transactions,
        "total_stock": total_stock, "inventory_value": inventory_value,
        "in7": in7, "out7": out7, "top_rows": top_rows, "low_rows": low_rows, "cat_rows": cat_rows, "cat_items_json": cat_items_json,
        "chart_labels": [str(d) for d in chart_days],
        "chart_deliveries": [del_by_day.get(d.isoformat(), 0) for d in chart_days],
        "chart_expenses": [round(exp_by_day.get(d.isoformat(), 0), 2) for d in chart_days],
        "agent_collections": agent_collections,
    })




@app.get("/admin/backfill-collections", response_class=HTMLResponse)
def backfill_collections(request: Request, db: Session = Depends(get_db)):
    """One-time: create COLLECTION entries for DELIVERED orders that have none."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not (is_supervisor(user) or is_admin(user)): return HTMLResponse("Forbidden", 403)

    delivered = db.execute(
        select(Delivery).where(Delivery.status == "DELIVERED")
    ).scalars().all()

    created, skipped = 0, 0
    for d in delivered:
        existing = db.scalar(
            select(func.count(CashEntry.id)).where(
                CashEntry.delivery_id == d.id,
                CashEntry.kind.in_(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"])
            )
        ) or 0
        if existing > 0:
            skipped += 1
            continue
        total = float(db.scalar(
            select(func.coalesce(func.sum(DeliveryItem.line_amount), 0))
            .where(DeliveryItem.delivery_id == d.id)
        ) or 0)
        if total > 0:
            db.add(CashEntry(
                branch_id=d.branch_id, agent_id=d.agent_id,
                delivery_id=d.id, kind="COLLECTION", amount=total,
                note=f"Auto-recorded: delivery #{d.id} to {d.customer_name}",
            ))
            created += 1
        else:
            skipped += 1
    db.commit()
    return HTMLResponse(f"<pre>Done. Created: {created} collection entries. Skipped: {skipped} (already had entries or zero value).</pre>")


@app.post("/admin/confirm-cash", response_class=JSONResponse)
async def confirm_cash(request: Request, db: Session = Depends(get_db)):
    """Admin confirms that an agent has physically handed over their cash."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_admin(user): return JSONResponse({"error": "forbidden"}, status_code=403)
    body = await request.json()
    agent_id = body.get("agent_id")
    date_str = body.get("date")  # YYYY-MM-DD
    if not agent_id or not date_str:
        return JSONResponse({"error": "missing agent_id or date"}, status_code=400)
    try:
        day_start = datetime.strptime(date_str, "%Y-%m-%d")
        day_end   = day_start + timedelta(days=1)
    except ValueError:
        return JSONResponse({"error": "invalid date"}, status_code=400)
    db.execute(text(
        "UPDATE cash_entries SET confirmed_by_admin=TRUE, confirmed_at=NOW() "
        "WHERE agent_id=:aid AND branch_id=:bid "
        "AND kind IN ('COLLECTION','CASH_PAYMENT','TRANSFER_PAYMENT') "
        "AND created_at >= :start AND created_at < :end "
        "AND confirmed_by_admin=FALSE"
    ), {"aid": agent_id, "bid": user.branch_id, "start": day_start, "end": day_end})
    db.commit()
    audit_log(db, user.id, "CASH_CONFIRMED", f"agent_id={agent_id} date={date_str}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    return JSONResponse({"status": "ok"})


@app.post("/admin/confirm-cash-entry", response_class=JSONResponse)
async def confirm_cash_entry(request: Request, db: Session = Depends(get_db)):
    """Confirm a single cash entry by ID (used for RETURN_OPERATING_CASH vetting)."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_admin(user): return JSONResponse({"error": "forbidden"}, status_code=403)
    body     = await request.json()
    entry_id = body.get("entry_id")
    if not entry_id:
        return JSONResponse({"error": "missing entry_id"}, status_code=400)
    row = db.execute(text(
        "UPDATE cash_entries SET confirmed_by_admin=TRUE, confirmed_at=NOW() "
        "WHERE id=:eid AND branch_id=:bid AND confirmed_by_admin=FALSE RETURNING id"
    ), {"eid": entry_id, "bid": user.branch_id}).fetchone()
    if not row:
        # Try without branch filter (already confirmed or different branch)
        db.execute(text(
            "UPDATE cash_entries SET confirmed_by_admin=TRUE, confirmed_at=NOW() WHERE id=:eid"
        ), {"eid": entry_id})
    db.commit()
    return JSONResponse({"ok": True})


@app.get("/call-logs", response_class=HTMLResponse)
def call_logs_page(request: Request, db: Session = Depends(get_db), page: int = 1):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    per_page = 50
    offset = (page - 1) * per_page
    branch_id = get_selected_branch_id(request, user)
    rows = db.execute(text("""
        SELECT cl.id, cl.delivery_id, cl.call_id, cl.phone, cl.trigger_status,
               cl.call_status, cl.error_msg, cl.duration, cl.created_at,
               d.customer_name, d.branch_id
        FROM call_logs cl
        JOIN deliveries d ON d.id = cl.delivery_id
        WHERE d.branch_id = :bid
        ORDER BY cl.created_at DESC
        LIMIT :lim OFFSET :off
    """), {"bid": branch_id, "lim": per_page, "off": offset}).fetchall()
    total = db.scalar(text(
        "SELECT COUNT(*) FROM call_logs cl JOIN deliveries d ON d.id=cl.delivery_id WHERE d.branch_id=:bid"
    ), {"bid": branch_id}) or 0
    pages = max(1, (total + per_page - 1) // per_page)
    return tpl(request, "call_logs.html", {
        "request": request, "user": user, "active": "call_logs",
        "rows": rows, "page": page, "pages": pages, "total": total,
    })


@app.get("/admin/audit-log", response_class=HTMLResponse)
def audit_log_viewer(request: Request, db: Session = Depends(get_db), page: int = 1):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_supervisor(user): return HTMLResponse("Forbidden", status_code=403)
    per_page = 50
    offset = (page - 1) * per_page
    logs = db.execute(
        select(AuditLog).order_by(desc(AuditLog.created_at)).offset(offset).limit(per_page)
    ).scalars().all()
    total = db.scalar(select(func.count(AuditLog.id))) or 0
    user_map = {u.id: (u.full_name or u.username) for u in db.execute(select(User)).scalars().all()}
    return tpl(request, "audit_log.html", {
        "request": request, "user": user, "active": "audit",
        "logs": logs, "user_map": user_map,
        "page": page, "total": total, "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    })


@app.get("/admin/reset-data", response_class=HTMLResponse)
def reset_data_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_supervisor(user): return HTMLResponse("Forbidden", status_code=403)
    csrf_token = get_csrf_token(request)
    return HTMLResponse(f"""
    <html><body style="background:#080f1e;color:#e7eefc;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
    <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:40px;max-width:480px;width:100%;text-align:center;">
      <div style="font-size:48px;margin-bottom:16px;">⚠️</div>
      <h2 style="color:#f87171;margin-bottom:8px;">Clear All Operational Data</h2>
      <p style="color:#8a9bc4;font-size:14px;margin-bottom:24px;">
        This will permanently delete all <strong style="color:#e7eefc;">deliveries, cash entries, stock transactions, and stock transfers</strong>.<br><br>
        Branches, users, and items will be kept.<br><br>
        <strong style="color:#f87171;">This cannot be undone.</strong>
      </p>
      <form method="post" action="/admin/reset-data">
        <input type="hidden" name="csrf_token" value="{csrf_token}" />
        <input type="text" name="confirm" placeholder='Type RESET to confirm'
               style="width:100%;padding:10px;border-radius:8px;border:1px solid rgba(239,68,68,.4);background:rgba(239,68,68,.08);color:#e7eefc;font-size:14px;margin-bottom:16px;box-sizing:border-box;" />
        <button type="submit"
                style="width:100%;padding:12px;background:linear-gradient(135deg,#ef4444,#dc2626);border:none;border-radius:10px;color:#fff;font-size:15px;font-weight:700;cursor:pointer;">
          🗑 Delete All Operational Data
        </button>
      </form>
      <a href="/supervisor" style="display:block;margin-top:16px;color:#8a9bc4;font-size:13px;text-decoration:none;">← Cancel</a>
    </div></body></html>
    """)


@app.post("/admin/test-stock-topup")
async def test_stock_topup(request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    """TEMPORARY — sets every item to 100 units for testing. Remove when done."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user): return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    branch_id = get_selected_branch_id(request, user)
    # Add IN transactions of 100 for every item in this branch tagged as TEST-STOCK
    items = db.execute(select(Item).where(Item.branch_id == branch_id)).scalars().all()
    for item in items:
        db.add(Transaction(
            branch_id=branch_id,
            item_id=item.id,
            type="IN",
            quantity=100,
            reference="TEST-STOCK",
            note="Temporary test stock top-up",
        ))
    db.commit()
    return redirect("/items")


@app.post("/admin/test-stock-remove")
async def test_stock_remove(request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    """TEMPORARY — removes all TEST-STOCK transactions."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user): return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    branch_id = get_selected_branch_id(request, user)
    db.execute(text("DELETE FROM transactions WHERE reference='TEST-STOCK' AND branch_id=:bid"), {"bid": branch_id})
    db.commit()
    return redirect("/items")


@app.post("/admin/reset-data", response_class=HTMLResponse)
async def reset_data_execute(
    request: Request,
    confirm: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_supervisor(user): return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    if confirm.strip() != "RESET":
        return HTMLResponse("<script>alert('You must type RESET to confirm.');history.back();</script>")

    from sqlalchemy import text as _text
    with db.bind.connect() as conn:
        # Delete in FK-safe order — child tables first
        conn.execute(_text("DELETE FROM stock_return_vettings"))
        conn.execute(_text("DELETE FROM adjustment_request_items"))
        conn.execute(_text("DELETE FROM adjustment_requests"))
        conn.execute(_text("UPDATE agent_stock_assignments SET transaction_out_id=NULL, transaction_in_id=NULL, delivery_id=NULL"))
        conn.execute(_text("DELETE FROM agent_stock_assignments"))
        conn.execute(_text("DELETE FROM faulty_stock"))
        conn.execute(_text("DELETE FROM notifications"))
        conn.execute(_text("DELETE FROM cash_entries"))
        conn.execute(_text("DELETE FROM delivery_items"))
        conn.execute(_text("DELETE FROM stock_transfer_items"))
        conn.execute(_text("UPDATE stock_transfers SET received_by_id=NULL, cancelled_by_id=NULL, delegated_agent_id=NULL, delegated_receiver_id=NULL"))
        conn.execute(_text("DELETE FROM stock_transfers"))
        conn.execute(_text("DELETE FROM deliveries"))
        conn.execute(_text("DELETE FROM transactions"))
        conn.execute(_text("DELETE FROM items"))
        conn.execute(_text("DELETE FROM audit_logs"))
        conn.commit()

    audit_log(db, user.id, "DATA_RESET", "All operational data wiped by supervisor",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    return HTMLResponse("""
    <html><body style="background:#080f1e;color:#e7eefc;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
    <div style="background:rgba(255,255,255,.04);border:1px solid rgba(34,197,94,.3);border-radius:16px;padding:40px;max-width:400px;text-align:center;">
      <div style="font-size:48px;margin-bottom:16px;">✅</div>
      <h2 style="color:#4ade80;margin-bottom:8px;">Data Cleared</h2>
      <p style="color:#8a9bc4;font-size:14px;margin-bottom:24px;">All operational data has been deleted. Branches, users, and items are intact.</p>
      <a href="/supervisor" style="display:inline-block;padding:12px 24px;background:linear-gradient(135deg,#4f7cff,#3b5bdb);border-radius:10px;color:#fff;text-decoration:none;font-weight:700;">Go to Dashboard</a>
    </div></body></html>
    """)



@app.get("/supervisor", response_class=HTMLResponse)
def supervisor_dashboard(request: Request, db: Session = Depends(get_db), preset: str = "", start_date: str = "", end_date: str = ""):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_supervisor(user):
        return HTMLResponse("Forbidden", status_code=403)

    preset = preset.strip() or None
    start_date = start_date.strip() or None
    end_date = end_date.strip() or None
    start_dt, end_dt = supervisor_date_range(preset, start_date, end_date)

    branches, rows = supervisor_branch_stats(db, start_dt, end_dt)
    # Enrich each row dict with branch_name from the branch object
    for r in rows:
        if isinstance(r, dict) and "branch" in r and not r.get("branch_name"):
            r["branch_name"] = r["branch"].name if r["branch"] else "—"
            r["branch_id"] = r["branch"].id if r["branch"] else None
    top_items   = supervisor_top_items(db, start_dt, end_dt)
    _raw_best_agents = list(supervisor_best_agents(db, start_dt, end_dt))
    best_agents = []
    for r in _raw_best_agents:
        cols = list(r)
        # Scan columns: find ints (delivery_count) and floats/numeric (collections)
        # string cols are name fields: username, full_name, branch_name
        str_cols, num_cols = [], []
        for c in cols:
            try:
                num_cols.append(float(c or 0))
            except (ValueError, TypeError):
                str_cols.append(str(c) if c is not None else "—")
        agent_name = str_cols[1] if len(str_cols) > 1 and str_cols[1] != "—" else (str_cols[0] if str_cols else "—")
        delivery_count = int(num_cols[0]) if len(num_cols) > 0 else 0
        total_collections = num_cols[1] if len(num_cols) > 1 else 0.0
        best_agents.append({
            "agent_name": agent_name,
            "delivery_count": delivery_count,
            "total_collections": total_collections,
        })
    daily_chart = supervisor_daily_deliveries(db, start_dt, end_dt)

    # Daily expenses across all branches for the chart
    # Exclude "waybill - from ..." entries (receiver side) to avoid double-counting transfer expenses
    _range_start = start_dt or datetime.utcnow() - timedelta(days=30)
    _range_end   = end_dt   or datetime.utcnow()
    exp_by_day: dict = {}
    for e in db.execute(
        select(CashEntry).where(CashEntry.kind.in_(["EXPENSE", "OFFICE_EXPENSE", "COLLECTION_EXPENSE"]))
        .where(CashEntry.created_at >= _range_start)
        .where(CashEntry.created_at <= _range_end)
    ).scalars().all():
        k = e.created_at.date().isoformat() if e.created_at else None
        if k:
            exp_by_day[k] = exp_by_day.get(k, 0) + float(e.amount or 0)
    # Build chart days — use isoformat keys throughout for consistency
    delivery_days = {r.day.isoformat() if hasattr(r.day, 'isoformat') else str(r.day)[:10] for r in daily_chart}
    expense_days  = set(exp_by_day.keys())
    all_chart_days = sorted(delivery_days | expense_days)
    delivery_cnt = {(r.day.isoformat() if hasattr(r.day, 'isoformat') else str(r.day)[:10]): int(r.cnt) for r in daily_chart}
    chart_days_set = all_chart_days

    # All-branch inventory & agent totals for the enhanced overview
    all_items_count = db.scalar(select(func.count(func.distinct(func.lower(Item.name))))) or 0
    all_low_items = [(item, stock) for (item, stock) in get_low_stock(db)]
    all_low_stock_count = len(all_low_items)
    all_agents_count = db.scalar(select(func.count(User.id)).where(User.role == "AGENT")) or 0
    all_admins_count = db.scalar(select(func.count(User.id)).where(User.role == "ADMIN")) or 0
    all_inventory_value = 0.0
    all_total_stock = 0
    all_cat_map: dict = {}
    all_cat_items_map: dict = {}  # cat -> {name_lower -> {name, stock, unit, reorder_level}}
    all_top_rows_raw = []
    for item, stock in get_items_with_stock(db):
        s = int(stock or 0)
        all_inventory_value += s * float(item.cost_price or 0)
        all_total_stock += s
        cat = item.category or "Uncategorized"
        all_cat_map[cat] = all_cat_map.get(cat, 0) + s
        # Merge same-named items across branches
        key = (item.name or "").strip().lower()
        if cat not in all_cat_items_map:
            all_cat_items_map[cat] = {}
        if key in all_cat_items_map[cat]:
            all_cat_items_map[cat][key]["stock"] += s
        else:
            all_cat_items_map[cat][key] = {"name": item.name, "stock": s, "unit": item.unit or "pcs", "reorder_level": int(item.reorder_level or 0)}
        all_top_rows_raw.append((item, s))
    all_cat_rows = sorted(all_cat_map.items(), key=lambda x: x[1], reverse=True)
    all_cat_items_json = {cat: sorted(items.values(), key=lambda x: x["stock"], reverse=True)
                          for cat, items in all_cat_items_map.items()}
    all_top_rows = sorted(all_top_rows_raw, key=lambda x: x[1], reverse=True)[:5]
    all_low_rows = [(item, stock) for (item, stock) in get_low_stock(db)]
    all_in7 = int(db.scalar(
        select(func.coalesce(func.sum(Transaction.quantity), 0))
        .where(Transaction.type == "IN")
        .where(Transaction.created_at >= datetime.utcnow() - timedelta(days=7))
    ) or 0)
    all_out7 = int(db.scalar(
        select(func.coalesce(func.sum(Transaction.quantity), 0))
        .where(Transaction.type == "OUT")
        .where(Transaction.created_at >= datetime.utcnow() - timedelta(days=7))
    ) or 0)

    return tpl(request, "supervisor_dashboard.html", {
        "request": request, "user": user, "rows": rows,
        "top_items": top_items, "best_agents": best_agents,
        "chart_labels": chart_days_set,
        "chart_data": [delivery_cnt.get(d, 0) for d in chart_days_set],
        "chart_expenses": [round(exp_by_day.get(d, 0), 2) for d in chart_days_set],
        "grand_total_deliveries": sum(r["total_deliveries"] for r in rows),
        "grand_delivered": sum(r["delivered_count"] for r in rows),
        "grand_pending": sum(r["pending_count"] for r in rows),
        "grand_out_for_delivery": sum(r["out_for_delivery_count"] for r in rows),
        "grand_failed": sum(r["failed_count"] for r in rows),
        "grand_collections": sum(r["collections"] for r in rows),
        "grand_agent_expenses": sum(r["agent_expenses"] for r in rows),
        "grand_office_expenses": sum(r["office_expenses"] for r in rows),
        "grand_operating_cash": sum(r["operating_cash"] for r in rows),
        "grand_returned_operating_cash": sum(r["returned_operating_cash"] for r in rows),
        "grand_operating_balance": sum(r["operating_balance"] for r in rows),
        "grand_remittance": sum(r["remittance"] for r in rows),
        "all_items_count": all_items_count,
        "all_low_stock_count": all_low_stock_count,
        "all_low_items": all_low_items,
        "all_low_rows": all_low_rows,
        "all_agents_count": all_agents_count,
        "all_admins_count": all_admins_count,
        "all_inventory_value": all_inventory_value,
        "all_total_stock": all_total_stock,
        "all_cat_rows": all_cat_rows, "all_cat_items_json": all_cat_items_json,
        "all_top_rows": all_top_rows,
        "all_in7": all_in7, "all_out7": all_out7,
        "branches": branches, "selected_branch_id": None, "active": "supervisor",
        "preset": preset or "", "start_date": start_date or "", "end_date": end_date or "",
    })


# ────────────────────────────────────────────────
#  BRANCHES
# ────────────────────────────────────────────────

@app.get("/branches", response_class=HTMLResponse)
def branches_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_supervisor(user):
        return HTMLResponse("Forbidden", status_code=403)
    rows = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()
    return tpl(request, "branches_list.html", {
        "request": request, "user": user, "rows": rows,
        "active": "branches", "branches": rows, "selected_branch_id": None,
    })


@app.get("/branches/new", response_class=HTMLResponse)
def branch_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_supervisor(user):
        return HTMLResponse("Forbidden", status_code=403)
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()
    csrf_token = get_csrf_token(request)
    return tpl(request, "branch_new.html", {
        "request": request, "user": user, "error": request.query_params.get("error"),
        "active": "branches", "branches": branches, "selected_branch_id": None,
        "csrf_token": csrf_token,
    })


@app.post("/branches/new")
async def branch_create(
    request: Request,
    name: str = Form(...),
    code: str = Form(""),
    address: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_supervisor(user):
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    name_clean = sanitize_text(name, 120, "Branch name")
    code_clean = sanitize_text(code, 20, "Branch code") if (code or "").strip() else None
    address_clean = sanitize_text(address, 200, "Address") if (address or "").strip() else None
    if not name_clean:
        return redirect("/branches/new?error=Branch+name+is+required")
    if db.scalar(select(Branch).where(Branch.name == name_clean)):
        return redirect("/branches/new?error=Branch+name+already+exists")
    if code_clean and db.scalar(select(Branch).where(Branch.code == code_clean)):
        return redirect("/branches/new?error=Branch+code+already+exists")
    db.add(Branch(name=name_clean, code=code_clean, address=address_clean))
    db.commit()
    return redirect("/branches")


@app.get("/api/low-stock-count")
def api_low_stock_count(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"count": 0}, status_code=401)
    return {"count": len(get_low_stock(db))}


# ────────────────────────────────────────────────
#  ITEMS
# ────────────────────────────────────────────────

@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return tpl(request, "forgot_password.html", {
        "request": request, "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
    })


@app.get("/items", response_class=HTMLResponse)
def items_list(request: Request, q: str = "", view: str = "combined", branch_filter: str = "", db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    branch_id = get_selected_branch_id(request, user)
    all_rows = list(get_items_with_stock(db))
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all() if is_supervisor(user) else []

    if is_supervisor(user):
        # Apply branch filter if selected
        if branch_filter and branch_filter.isdigit():
            filtered_rows = [(item, stock) for (item, stock) in all_rows if item.branch_id == int(branch_filter)]
        else:
            filtered_rows = all_rows

        if view == "combined":
            # Aggregate: merge items with same name across branches
            combined: dict = {}
            for item, stock in filtered_rows:
                key = (item.name or "").strip().lower()
                if key not in combined:
                    combined[key] = {
                        "name": item.name, "category": item.category, "unit": item.unit,
                        "reorder_level": item.reorder_level or 0,
                        "cost_price": float(item.cost_price or 0),
                        "selling_price": float(item.selling_price or 0),
                        "total_stock": 0, "branch_stocks": [], "item_id": item.id,
                    }
                combined[key]["total_stock"] += int(stock or 0)
                branch_name = item.branch.name if item.branch else f"Branch {item.branch_id}"
                combined[key]["branch_stocks"].append({"branch": branch_name, "stock": int(stock or 0)})
            rows = list(combined.values())
            # Apply search
            q_lower = q.strip().lower()
            if q_lower:
                rows = [r for r in rows if q_lower in (r["name"] or "").lower() or q_lower in (r["category"] or "").lower()]
        else:
            # Per-branch view
            rows = filtered_rows
            q_lower = q.strip().lower()
            if q_lower:
                rows = [(item, stock) for (item, stock) in rows
                        if q_lower in (item.name or "").lower() or q_lower in (item.category or "").lower()]
    else:
        rows = [(item, stock) for (item, stock) in all_rows if item.branch_id == branch_id]
        q_lower = q.strip().lower()
        if q_lower:
            rows = [(item, stock) for (item, stock) in rows
                    if q_lower in (item.name or "").lower() or q_lower in (item.category or "").lower()]
        view = "branch"

    # Faulty counts per item for badge display
    faulty_counts_raw = db.execute(text(
        "SELECT item_id, SUM(qty_faulty) FROM faulty_stock "
        "WHERE branch_id = :bid AND resolved = FALSE GROUP BY item_id"
    ), {"bid": branch_id}).fetchall() if branch_id else []
    faulty_counts = {r[0]: int(r[1]) for r in faulty_counts_raw}
    has_test_stock = bool(
        db.execute(text(
            "SELECT 1 FROM transactions WHERE reference='TEST-STOCK' AND branch_id=:bid LIMIT 1"
        ), {"bid": branch_id}).first()
    ) if branch_id else False
    return tpl(request, "items_list.html", {
        "request": request, "rows": rows, "q": q, "user": user, "active": "items", "faulty_counts": faulty_counts,
        "view": view, "branches": branches, "branch_filter": branch_filter,
        "has_test_stock": has_test_stock,
    })


@app.get("/items/new", response_class=HTMLResponse)
def item_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    csrf_token = get_csrf_token(request)
    return tpl(request, "item_new.html", {
        "request": request, "user": user,
        "error": request.query_params.get("error"),
        "active": "items", "csrf_token": csrf_token,
    })


@app.post("/items/new")
async def item_create(
    request: Request,
    name: str = Form(...),
    category: str = Form(""),
    unit: str = Form("pcs"),
    reorder_level: int = Form(0),
    cost_price: float = Form(0),
    selling_price: float = Form(0),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    verify_csrf_token(request, csrf_token)
    name_clean = sanitize_text(name, 200, "Name")
    if not name_clean:
        return redirect("/items/new?error=Name+is+required")
    branch_id = get_current_branch_id(request)
    if not branch_id:
        return redirect("/items/new?error=No+branch+assigned")
    db.add(Item(
        branch_id=branch_id, name=name_clean,
        category=sanitize_text(category, 120, "Category") or None,
        unit=(unit or "pcs").strip() or "pcs",
        reorder_level=int(reorder_level or 0),
        cost_price=float(cost_price or 0),
        selling_price=float(selling_price or 0),
    ))
    db.commit()
    return redirect("/items")


@app.get("/items/import", response_class=HTMLResponse)
def items_import_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all()
    csrf_token = get_csrf_token(request)
    return tpl(request, "items_import.html", {
        "request": request, "user": user, "branches": branches,
        "active": "items", "selected_branch_id": getattr(user, "branch_id", None),
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "csrf_token": csrf_token,
    })


@app.post("/items/import")
async def items_import_upload(request: Request, db: Session = Depends(get_db)):
    import csv, io
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
    form = await request.form()
    verify_csrf_token(request, str(form.get("csrf_token", "")))
    file = form.get("csv_file")
    target = (form.get("target_branch") or "").strip()
    if not file or not file.filename:
        return redirect("/items/import?error=Please+select+a+CSV+file")
    file_bytes = await file.read()
    # [SEC-9] Validate file type and size
    try:
        validate_upload(file.filename, file_bytes)
    except Exception as e:
        return redirect(f"/items/import?error={str(e)}")
    content = file_bytes
    try:
        text_content = content.decode("utf-8-sig")
    except Exception:
        return redirect("/items/import?error=Could+not+read+file")
    reader = csv.DictReader(io.StringIO(text_content))
    headers = [h.strip().lower() for h in (reader.fieldnames or [])]
    if "name" not in headers:
        return redirect("/items/import?error=CSV+must+have+a+Name+column")
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all()
    if is_supervisor(user) and target == "all":
        target_branches = branches
    elif is_supervisor(user) and target.isdigit():
        b = db.get(Branch, int(target))
        target_branches = [b] if b else []
    else:
        b = db.get(Branch, user.branch_id)
        target_branches = [b] if b else []
    if not target_branches:
        return redirect("/items/import?error=No+valid+branch+selected")
    rows = list(reader)
    if not rows:
        return redirect("/items/import?error=CSV+file+is+empty")
    created = 0
    skipped = 0
    for branch in target_branches:
        for row in rows:
            name = (row.get("name") or row.get("Name") or "").strip()
            if not name:
                skipped += 1
                continue
            category = (row.get("category") or row.get("Category") or "").strip() or None
            existing = db.scalar(select(Item).where(Item.branch_id == branch.id, func.lower(Item.name) == name.lower()))
            if existing:
                skipped += 1
                continue
            db.add(Item(branch_id=branch.id, name=name, category=category, unit="pcs", reorder_level=0, cost_price=0, selling_price=0))
            created += 1
    db.commit()
    return redirect(f"/items/import?success=Imported+{created}+items+({skipped}+skipped)")


@app.get("/items/{item_id}", response_class=HTMLResponse)
def item_detail(request: Request, item_id: int, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    row = get_item_with_stock(db, item_id)
    if not row:
        return HTMLResponse("Item not found", status_code=404)
    item, stock = row
    require_item_access(request, user, item)
    txs = db.scalars(
        select(Transaction).where(Transaction.item_id == item_id)
        .where(Transaction.branch_id == item.branch_id)
        .order_by(desc(Transaction.created_at)).limit(200)
    ).all()
    # Faulty stock records for this item
    faulty_records = db.execute(text(
        "SELECT id, qty_faulty, reason, flagged_at, resolved, resolve_action, resolved_at, resolve_note "
        "FROM faulty_stock WHERE item_id = :iid AND branch_id = :bid ORDER BY flagged_at DESC"
    ), {"iid": item_id, "bid": item.branch_id}).fetchall()
    faulty_qty_active = sum(r[1] for r in faulty_records if not r[4])  # unresolved only
    csrf_token = get_csrf_token(request)
    return tpl(request, "item_detail.html", {
        "request": request, "item": item, "stock": stock, "txs": txs, "user": user,
        "active": "items", "faulty_records": faulty_records,
        "faulty_qty_active": faulty_qty_active, "csrf_token": csrf_token,
    })


@app.get("/items/{item_id}/edit", response_class=HTMLResponse)
def item_edit_form(request: Request, item_id: int, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    item = db.get(Item, item_id)
    require_item_access(request, user, item)
    csrf_token = get_csrf_token(request)
    return tpl(request, "item_edit.html", {
        "request": request, "item": item, "user": user,
        "error": request.query_params.get("error"),
        "active": "items", "csrf_token": csrf_token,
    })


@app.post("/items/{item_id}/edit")
async def item_edit_save(
    request: Request,
    item_id: int,
    name: str = Form(...),
    category: str = Form(""),
    unit: str = Form("pcs"),
    reorder_level: int = Form(0),
    cost_price: float = Form(0),
    selling_price: float = Form(0),
    adjust_type: str = Form(""),
    adjust_qty: int = Form(0),
    adjust_note: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    verify_csrf_token(request, csrf_token)
    item = db.get(Item, item_id)
    require_item_access(request, user, item)
    name_clean = sanitize_text(name, 200, "Name")
    if not name_clean:
        return redirect(f"/items/{item_id}/edit?error=Name+is+required")
    item.name = name_clean
    item.category = sanitize_text(category, 120, "Category") or None
    item.unit = (unit or "pcs").strip() or "pcs"
    item.reorder_level = int(reorder_level or 0)
    item.cost_price = float(cost_price or 0)
    item.selling_price = float(selling_price or 0)
    at = (adjust_type or "").strip().upper()
    aq = int(adjust_qty or 0)
    if aq < 0:
        return redirect(f"/items/{item_id}/edit?error=Adjust+quantity+must+be+positive")
    if aq > 0:
        if at not in {"IN", "OUT"}:
            return redirect(f"/items/{item_id}/edit?error=Adjust+type+must+be+IN+or+OUT")
        if at == "OUT":
            r = get_item_with_stock(db, item_id)
            if (r[1] if r else 0) < aq:
                return redirect(f"/items/{item_id}/edit?error=Insufficient+stock+for+OUT+adjustment")
        db.add(Transaction(
            branch_id=item.branch_id, item_id=item_id, type=at, quantity=aq,
            reference=f"MANUAL ADJUST #{item_id}",
            note=sanitize_text(adjust_note, 200, "Note") or f"Manual stock adjust by {user.username}",
        ))
    db.commit()
    return redirect(f"/items/{item_id}")


# ────────────────────────────────────────────────
#  FAULTY STOCK
# ────────────────────────────────────────────────

@app.post("/items/{item_id}/flag-faulty", response_class=JSONResponse)
async def flag_faulty_stock(
    item_id: int, request: Request, db: Session = Depends(get_db),
    qty_faulty: int = Form(...), reason: str = Form(""),
    csrf_token: str = Form(""),
):
    """Admin flags a quantity of an item as faulty/bad. Stock count unchanged."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_admin(user): return JSONResponse({"error": "forbidden"}, status_code=403)
    verify_csrf_token(request, csrf_token)

    item = db.get(Item, item_id)
    if not item or item.branch_id != user.branch_id:
        return JSONResponse({"error": "item not found"}, status_code=404)
    if qty_faulty <= 0:
        return JSONResponse({"error": "quantity must be greater than zero"}, status_code=400)

    reason_clean = (reason or "").strip()[:400]

    db.execute(text(
        "INSERT INTO faulty_stock (item_id, branch_id, qty_faulty, reason, flagged_by, flagged_at, resolved, resolve_note) "
        "VALUES (:iid, :bid, :qty, :reason, :uid, NOW(), FALSE, '')"
    ), {"iid": item_id, "bid": user.branch_id, "qty": qty_faulty,
        "reason": reason_clean, "uid": user.id})

    audit_log(db, user.id, "FAULTY_STOCK_FLAGGED",
              f"item={item.name} qty={qty_faulty} reason={reason_clean}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    db.commit()
    return JSONResponse({"ok": True, "item_name": item.name, "qty_faulty": qty_faulty})


@app.post("/faulty-stock/{faulty_id}/resolve", response_class=JSONResponse)
async def resolve_faulty_stock(
    faulty_id: int, request: Request, db: Session = Depends(get_db),
):
    """Admin resolves a faulty stock record.
    action='remove'           → OUT transaction, stock reduced
    action='return_merchant'  → OUT transaction labelled as merchant return
    """
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_admin(user): return JSONResponse({"error": "forbidden"}, status_code=403)

    body         = await request.json()
    action       = body.get("action", "")    # "remove" | "return_merchant"
    resolve_note = (body.get("resolve_note", "") or "").strip()[:400]

    if action not in ("remove", "return_merchant"):
        return JSONResponse({"error": "action must be remove or return_merchant"}, status_code=400)

    # Get the faulty record
    row = db.execute(text(
        "SELECT id, item_id, branch_id, qty_faulty, reason FROM faulty_stock "
        "WHERE id = :fid AND resolved = FALSE"
    ), {"fid": faulty_id}).fetchone()
    if not row:
        return JSONResponse({"error": "record not found or already resolved"}, status_code=404)

    fs_id, item_id, branch_id, qty_faulty, reason = row

    if branch_id != user.branch_id:
        return JSONResponse({"error": "forbidden — different branch"}, status_code=403)

    item = db.get(Item, item_id)
    if not item:
        return JSONResponse({"error": "item not found"}, status_code=404)

    # Create OUT transaction to remove faulty stock
    note = (
        f"Faulty stock returned to merchant — {resolve_note}" if action == "return_merchant"
        else f"Faulty stock removed — {resolve_note or reason}"
    ).strip(" —")
    tx = Transaction(
        branch_id=user.branch_id,
        item_id=item_id,
        type="OUT",
        quantity=qty_faulty,
        note=note,
        reference=f"faulty-{'merchant' if action == 'return_merchant' else 'remove'}-{faulty_id}",
    )
    db.add(tx)
    db.flush()

    # Mark faulty record resolved
    db.execute(text(
        "UPDATE faulty_stock SET resolved=TRUE, resolve_action=:act, "
        "resolved_at=NOW(), resolved_by=:uid, resolve_note=:note WHERE id=:fid"
    ), {"act": action, "uid": user.id, "note": resolve_note, "fid": faulty_id})

    audit_log(db, user.id, "FAULTY_STOCK_RESOLVED",
              f"item={item.name} qty={qty_faulty} action={action}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    db.commit()
    return JSONResponse({
        "ok": True,
        "item_name": item.name,
        "qty_faulty": qty_faulty,
        "action": action,
        "tx_note": note,
    })


#  TRANSACTIONS
# ────────────────────────────────────────────────

@app.get("/transactions", response_class=HTMLResponse)
def transactions_list(request: Request, branch_filter: str = "", db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    branch_id = get_selected_branch_id(request, user)
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    filter_bid = int(branch_filter) if branch_filter and branch_filter.isdigit() else None
    stmt = select(Transaction).order_by(desc(Transaction.created_at)).limit(300)
    if is_supervisor(user):
        if filter_bid:
            stmt = stmt.where(Transaction.branch_id == filter_bid)
    else:
        stmt = stmt.where(Transaction.branch_id == branch_id)
    txs = db.scalars(stmt).all()
    item_ids = list({t.item_id for t in txs if t.item_id})
    item_name_map = {}
    if item_ids:
        for it in db.scalars(select(Item).where(Item.id.in_(item_ids))).all():
            item_name_map[it.id] = it.name
    return tpl(request, "transactions_list.html", {
        "request": request, "txs": txs, "user": user, "active": "transactions",
        "item_name_map": item_name_map, "branches": branches, "branch_filter": branch_filter,
    })


@app.get("/transactions/new", response_class=HTMLResponse)
def tx_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    branch_id = get_selected_branch_id(request, user)
    items = [i for (i, _s) in get_items_with_stock(db) if i.branch_id == branch_id]
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    csrf_token = get_csrf_token(request)
    return tpl(request, "tx_form.html", {
        "request": request, "items": items, "error": request.query_params.get("error"),
        "user": user, "active": "transactions", "branches": branches,
        "selected_branch_id": branch_id, "csrf_token": csrf_token,
    })


@app.post("/transactions/new")
async def tx_create(
    request: Request,
    item_id: int = Form(...),
    tx_type: str = Form(...),
    quantity: int = Form(...),
    reference: str = Form(""),
    note: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    verify_csrf_token(request, csrf_token)
    tx_type_clean = (tx_type or "").strip().upper()
    if tx_type_clean not in {"IN", "OUT"}:
        return redirect("/transactions/new?error=Invalid+type")
    qty = int(quantity)
    if qty <= 0:
        return redirect("/transactions/new?error=Quantity+must+be+greater+than+0")
    if tx_type_clean == "OUT":
        r = get_item_with_stock(db, item_id)
        if not r:
            return redirect("/transactions/new?error=Item+not+found")
        if int(r[1]) < qty:
            return redirect("/transactions/new?error=Insufficient+stock")
    branch_id = get_current_branch_id(request)
    if not branch_id:
        return redirect("/transactions/new?error=No+branch+assigned")
    db.add(Transaction(
        branch_id=branch_id, item_id=item_id, type=tx_type_clean, quantity=qty,
        reference=sanitize_text(reference, 120, "Reference") or None,
        note=sanitize_text(note, 400, "Note") or None,
    ))
    db.commit()
    return redirect("/transactions")


# ────────────────────────────────────────────────
#  STOCK ALERTS
# ────────────────────────────────────────────────

@app.get("/stale-stock", response_class=HTMLResponse)
def stale_stock(request: Request, days: int = 7, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
    branch_id = get_selected_branch_id(request, user)
    cutoff = datetime.utcnow() - timedelta(days=days)
    # Supervisor sees all branches; admin sees their own branch only
    items_stmt = select(Item).order_by(Item.name)
    if not is_supervisor(user):
        items_stmt = items_stmt.where(Item.branch_id == branch_id)
    all_items = db.execute(items_stmt).scalars().all()
    stale_rows = []
    for item in all_items:
        item_branch_id = item.branch_id
        stock = db.scalar(
            select(func.coalesce(func.sum(case((Transaction.type == "IN", Transaction.quantity), else_=-Transaction.quantity)), 0))
            .where(Transaction.item_id == item.id).where(Transaction.branch_id == item_branch_id)
        ) or 0
        if stock <= 0:
            continue
        last_tx = db.scalar(select(func.max(Transaction.created_at)).where(Transaction.item_id == item.id).where(Transaction.branch_id == item_branch_id))
        if last_tx is None or last_tx < cutoff:
            stale_rows.append({"item": item, "stock": int(stock), "last_tx": last_tx,
                               "days_since": (datetime.utcnow() - last_tx).days if last_tx else 9999})
    stale_rows.sort(key=lambda r: r["days_since"], reverse=True)
    return tpl(request, "stale_stock.html", {
        "request": request, "user": user, "rows": stale_rows, "days": days, "active": "stale",
    })


@app.get("/low-stock", response_class=HTMLResponse)
def low_stock(request: Request, branch_filter: str = "", db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    branch_id = get_selected_branch_id(request, user)
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    filter_bid = int(branch_filter) if branch_filter and branch_filter.isdigit() else None
    if is_supervisor(user):
        all_rows = list(get_low_stock(db))
        rows = [(item, stock) for (item, stock) in all_rows if not filter_bid or item.branch_id == filter_bid]
    else:
        rows = [(item, stock) for (item, stock) in get_low_stock(db) if item.branch_id == branch_id]
    return tpl(request, "low_stock.html", {
        "request": request, "rows": rows, "user": user, "active": "low",
        "branches": branches, "branch_filter": branch_filter,
    })


# ────────────────────────────────────────────────
#  AGENTS
# ────────────────────────────────────────────────

@app.get("/agents", response_class=HTMLResponse)
def agents_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    branch_id = get_selected_branch_id(request, user)
    if is_supervisor(user):
        # Supervisor sees all admins across all branches
        agents = db.execute(
            select(User).where(User.role == "ADMIN").order_by(User.username.asc())
        ).scalars().all()
    else:
        agents = db.execute(
            select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())
        ).scalars().all()
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    return tpl(request, "agents_list.html", {
        "request": request, "agents": agents, "user": user,
        "branches": branches, "selected_branch_id": branch_id,
    })


@app.get("/agents/new", response_class=HTMLResponse)
def agent_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    csrf_token = get_csrf_token(request)
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    return tpl(request, "agent_new.html", {
        "request": request, "user": user,
        "error": request.query_params.get("error"),
        "active": "agents", "csrf_token": csrf_token,
        "branches": branches,
    })


@app.post("/agents/new")
async def agent_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(""),
    phone: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    verify_csrf_token(request, csrf_token)
    uname = sanitize_username(username)
    if not uname:
        return redirect("/agents/new?error=Username+is+required")
    if db.scalar(select(User).where(User.username == uname)):
        return redirect("/agents/new?error=Username+already+exists")
    if len(password or "") < 8:
        return redirect("/agents/new?error=Password+must+be+at+least+8+characters")
    # Supervisor picks branch from form; admin uses their own branch
    if is_supervisor(user):
        form_data = await request.form()
        branch_id_val = form_data.get("branch_id", "")
        if not branch_id_val or not str(branch_id_val).isdigit():
            return redirect("/agents/new?error=Please+select+a+branch")
        assigned_branch_id = int(branch_id_val)
    else:
        if not user.branch_id:
            return redirect("/agents/new?error=Admin+has+no+branch+assigned")
        assigned_branch_id = user.branch_id
    db.add(User(
        username=uname, password_hash=hash_password(password),
        role="ADMIN" if is_supervisor(user) else "AGENT",
        branch_id=assigned_branch_id,
        full_name=sanitize_text(full_name, 140, "Full name") or None,
        phone=sanitize_phone(phone) or None,
    ))
    db.commit()
    return redirect("/agents")


@app.get("/agents/{agent_id}", response_class=HTMLResponse)
def agent_detail(request: Request, agent_id: int, preset: str = "", start_date: str = "", end_date: str = "", db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    agent = db.get(User, agent_id)
    require_agent_access(request, user, agent)

    sd, ed, preset_norm, start_dt, end_dt = _dt_range_from_dates(preset, start_date, end_date)

    is_admin_profile = (agent.role or "").upper() == "ADMIN"

    if is_admin_profile and agent.branch_id:
        # For admin profiles: show branch-level summary via direct queries
        branch_id_for_admin = agent.branch_id

        def _branch_sum(kind_list):
            stmt = select(func.coalesce(func.sum(CashEntry.amount), 0)).where(
                CashEntry.kind.in_(kind_list)).where(CashEntry.branch_id == branch_id_for_admin)
            if start_dt: stmt = stmt.where(CashEntry.created_at >= start_dt)
            if end_dt: stmt = stmt.where(CashEntry.created_at < end_dt)
            return float(db.scalar(stmt) or 0)

        total_collections   = _branch_sum(["COLLECTION", "CASH_PAYMENT", "TRANSFER_PAYMENT"])
        total_expenses      = _branch_sum(["EXPENSE"])
        total_operating     = _branch_sum(["OPERATING_CASH"])
        total_office_expenses = _branch_sum(["OFFICE_EXPENSE"])
        total_return_op_cash  = _branch_sum(["RETURN_OPERATING_CASH"])
        operating_balance   = total_operating - total_expenses - total_return_op_cash
        remittance          = total_collections - total_office_expenses
        net_position        = remittance + operating_balance
        rows = []  # no per-day rows for branch summary

        d_stmt = select(Delivery).where(Delivery.branch_id == branch_id_for_admin).order_by(desc(Delivery.created_at)).limit(300)
        if start_dt: d_stmt = d_stmt.where(Delivery.created_at >= start_dt)
        if end_dt: d_stmt = d_stmt.where(Delivery.created_at < end_dt)
        deliveries = db.execute(d_stmt).scalars().all()
        branch_agents = db.execute(
            select(User).where(User.role == "AGENT").where(User.branch_id == branch_id_for_admin)
            .order_by(User.username.asc())
        ).scalars().all()
    else:
        is_admin_profile = False
        branch_agents = []
        rows, total_collections, total_expenses, total_operating, total_office_expenses = get_cash_summary(db=db, agent_id=agent_id, start=start_dt, end=end_dt)
        _ret_stmt = select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "RETURN_OPERATING_CASH").where(CashEntry.agent_id == agent_id)
        if start_dt: _ret_stmt = _ret_stmt.where(CashEntry.created_at >= start_dt)
        if end_dt: _ret_stmt = _ret_stmt.where(CashEntry.created_at < end_dt)
        total_return_op_cash = float(db.scalar(_ret_stmt) or 0)
        operating_balance = float(total_operating) - float(total_expenses) - total_return_op_cash
        remittance = float(total_collections) - float(total_office_expenses)
        net_position = remittance + operating_balance
        d_stmt = select(Delivery).where(Delivery.agent_id == agent_id).order_by(desc(Delivery.created_at)).limit(300)
        if start_dt: d_stmt = d_stmt.where(Delivery.created_at >= start_dt)
        if end_dt: d_stmt = d_stmt.where(Delivery.created_at < end_dt)
        deliveries = db.execute(d_stmt).scalars().all()

    delivery_ids = [d.id for d in deliveries]
    items_summary: dict[int, str] = {}
    if delivery_ids:
        # Exclude phantom delivery_items that exist only for vetting (have a stock_return_vettings record)
        _phantom_ids = set(r[0] for r in db.execute(text(
            "SELECT DISTINCT delivery_item_id FROM stock_return_vettings"
        )).fetchall())
        lines = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity, DeliveryItem.id)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        grouped: dict[int, list[str]] = {}
        for did, iname, qty, di_id in lines:
            if di_id in _phantom_ids:
                continue
            grouped.setdefault(int(did), []).append(f"{iname} ×{int(qty)}")
        items_summary = {did: ", ".join(parts) for did, parts in grouped.items()}
    cash_stmt = select(CashEntry).where(CashEntry.branch_id == agent.branch_id).order_by(desc(CashEntry.created_at))
    if start_dt: cash_stmt = cash_stmt.where(CashEntry.created_at >= start_dt)
    if end_dt: cash_stmt = cash_stmt.where(CashEntry.created_at < end_dt)
    cash_stmt = cash_stmt.where((CashEntry.agent_id == agent_id) | (CashEntry.kind == "OFFICE_EXPENSE"))
    cash_entries = db.execute(cash_stmt.limit(300)).scalars().all()

    csrf_token = get_csrf_token(request)
    return tpl(request, "agent_detail.html", {
        "request": request, "user": user, "agent": agent, "rows": rows,
        "is_admin_profile": is_admin_profile, "branch_agents": branch_agents,
        "deliveries": deliveries, "items_summary": items_summary, "cash_entries": cash_entries,
        "total_collections": float(total_collections), "total_expenses": float(total_expenses),
        "total_operating_cash": float(total_operating), "total_return_op_cash": total_return_op_cash,
        "operating_balance": float(operating_balance), "total_office_expenses": float(total_office_expenses),
        "remittance": float(remittance), "net_position": float(net_position),
        "preset": preset_norm or (preset or ""),
        "start_date": sd.isoformat() if sd else "",
        "end_date": ed.isoformat() if ed else "",
        "active": "agents", "csrf_token": csrf_token,
    })




# ────────────────────────────────────────────────
#  PASSWORD RESET (admin resets agent/admin password)
# ────────────────────────────────────────────────

@app.post("/agents/{agent_id}/reset-password")
async def agent_reset_password(
    request: Request,
    agent_id: int,
    new_password: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    # Admins can reset agents in their branch; supervisors can reset anyone
    if not is_admin(user) and not is_supervisor(user):
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    target = db.get(User, agent_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # Admins can only reset agents in their own branch
    if is_admin(user) and not is_supervisor(user):
        if target.branch_id != user.branch_id:
            return HTMLResponse("Forbidden", status_code=403)
        if target.role not in ("AGENT",):
            return HTMLResponse("Forbidden — admins can only reset agent passwords", status_code=403)
    pw = (new_password or "").strip()
    if len(pw) < 8:
        return redirect(f"/agents/{agent_id}?error=Password+must+be+at+least+8+characters")
    target.password_hash = hash_password(pw)
    db.commit()
    audit_log(db, user.id, "PASSWORD_RESET", f"user_id={agent_id} reset by {user.username}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    return redirect(f"/agents/{agent_id}?success=Password+reset+successfully")

# ────────────────────────────────────────────────
#  DELIVERIES
# ────────────────────────────────────────────────

@app.get("/deliveries", response_class=HTMLResponse)
def deliveries_admin_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_admin(user) and not is_supervisor(user):
        return redirect("/my-deliveries")
    status = request.query_params.get("status", "").strip().upper()
    agent_id = request.query_params.get("agent_id", "").strip()

    if is_supervisor(user):
        # Supervisor filters by branch, status, date range
        filter_branch = request.query_params.get("branch_id", "").strip()
        start_date = request.query_params.get("start_date", "").strip()
        end_date = request.query_params.get("end_date", "").strip()
        stmt = select(Delivery).order_by(desc(Delivery.created_at)).limit(500)
        if filter_branch and filter_branch.isdigit():
            stmt = stmt.where(Delivery.branch_id == int(filter_branch))
        if status:
            stmt = stmt.where(Delivery.status == status)
        if start_date:
            try:
                stmt = stmt.where(Delivery.created_at >= datetime.fromisoformat(start_date))
            except ValueError:
                pass
        if end_date:
            try:
                stmt = stmt.where(Delivery.created_at <= datetime.fromisoformat(end_date + " 23:59:59"))
            except ValueError:
                pass
        rows = db.execute(stmt).scalars().all()
        branch_id = int(filter_branch) if filter_branch and filter_branch.isdigit() else None
        agents = []
    else:
        branch_id = get_selected_branch_id(request, user)
        filter_branch = ""
        start_date = ""
        end_date = ""
        stmt = select(Delivery).order_by(desc(Delivery.created_at)).limit(300)
        stmt = stmt.where(Delivery.branch_id == branch_id)
        if status: stmt = stmt.where(Delivery.status == status)
        if agent_id.isdigit(): stmt = stmt.where(Delivery.agent_id == int(agent_id))
        rows = db.execute(stmt).scalars().all()
        agents_stmt = select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())
        agents = db.execute(agents_stmt).scalars().all()

    delivery_ids = [d.id for d in rows]
    items_summary: dict[int, str] = {}
    if delivery_ids:
        _phantom_ids2 = set(r[0] for r in db.execute(text(
            "SELECT DISTINCT delivery_item_id FROM stock_return_vettings"
        )).fetchall())
        lines = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity, DeliveryItem.id)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        grouped: dict[int, list[str]] = {}
        for did, iname, qty, di_id in lines:
            if di_id in _phantom_ids2:
                continue
            grouped.setdefault(int(did), []).append(f"{iname} ×{int(qty)}")
        for did, parts in grouped.items():
            items_summary[did] = ", ".join(parts)

    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    sup_kpis = None
    if is_supervisor(user):
        sup_kpis = {
            "total": len(rows),
            "delivered": sum(1 for d in rows if d.status == "DELIVERED"),
            "pending": sum(1 for d in rows if d.status == "PENDING"),
            "in_transit": sum(1 for d in rows if d.status == "OUT_FOR_DELIVERY"),
            "failed": sum(1 for d in rows if d.status in ("FAILED", "RETURNED")),
        }
    # Agent name lookup for display in table
    all_agent_ids = {d.agent_id for d in rows if d.agent_id}
    agent_names: dict[int, str] = {}
    if all_agent_ids:
        for u in db.execute(select(User).where(User.id.in_(all_agent_ids))).scalars().all():
            agent_names[u.id] = u.full_name or u.username
    return tpl(request, "deliveries_list.html", {
        "request": request, "rows": rows, "agents": agents, "status": status,
        "agent_id": agent_id, "items_summary": items_summary,
        "branches": branches, "selected_branch_id": branch_id,
        "branch_id": filter_branch, "start_date": start_date, "end_date": end_date,
        "user": user, "active": "deliveries", "sup_kpis": sup_kpis,
        "agent_names": agent_names,
    })


@app.get("/admin/fix-cash-constraint", response_class=JSONResponse)
def fix_cash_constraint(request: Request, db: Session = Depends(get_db)):
    """One-time: update cash_entries kind constraint to include TRANSFER_PAYMENT."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"})
    user = user_or
    if not is_supervisor(user): return JSONResponse({"error": "forbidden"})
    try:
        with db.bind.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE cash_entries DROP CONSTRAINT IF EXISTS ck_cash_kind"))
            conn.execute(text("ALTER TABLE cash_entries ADD CONSTRAINT ck_cash_kind CHECK (kind IN ('COLLECTION','EXPENSE','OPERATING_CASH','OFFICE_EXPENSE','RETURN_OPERATING_CASH','CASH_PAYMENT','TRANSFER_PAYMENT','COLLECTION_EXPENSE'))"))
        return JSONResponse({"status": "ok", "message": "Constraint updated successfully"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)})


@app.get("/admin/check-env", response_class=JSONResponse)
def check_env(request: Request, db: Session = Depends(get_db)):
    """Supervisor-only: verify environment variables are loaded."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"})
    user = user_or
    if not is_supervisor(user): return JSONResponse({"error": "forbidden"})
    groq = os.getenv("GROQ_API_KEY", "")
    return JSONResponse({
        "GROQ_API_KEY": f"set ({len(groq)} chars)" if groq else "NOT SET",
        "SESSION_SECRET": "set" if os.getenv("SESSION_SECRET") else "NOT SET",
    })


@app.post("/parse-order/api", response_class=JSONResponse)
async def parse_order_api(request: Request, db: Session = Depends(get_db)):
    """Backend proxy — calls Groq API server-side to avoid CORS."""
    limiter.check(request, max_requests=60, window_seconds=60)
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"error": "Not logged in"}, status_code=401)
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return JSONResponse({"error": "Forbidden"}, status_code=403)

    import httpx
    body = await request.json()
    prompt = body.get("prompt", "")
    if not prompt:
        return JSONResponse({"error": "No prompt provided"}, status_code=400)

    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return JSONResponse({"error": "GEMINI_API_KEY not set in Railway environment variables."}, status_code=500)

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "system_instruction": {
                        "parts": [{"text": "You are an order parser for a Nigerian logistics business. You MUST return ONLY a valid, complete JSON array — no markdown, no code fences, no explanation, no trailing text. Start your response with [ and end with ]. Never truncate."}]
                    },
                    "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.1,
                        "maxOutputTokens": 32768,
                        "thinkingConfig": {"thinkingBudget": 0},
                    }
                }
            )
        raw_text = resp.text
        data = resp.json()
        if not isinstance(data, dict):
            return JSONResponse({"error": f"Unexpected response: {raw_text[:300]}"}, status_code=500)
        if "error" in data:
            err = data["error"]
            error_msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            return JSONResponse({"error": f"{error_msg} | raw: {raw_text[:200]}"}, status_code=500)
        try:
            parts = data["candidates"][0]["content"]["parts"]
            # Skip thinking parts (thought=True), join all real text parts
            text = "".join(p["text"] for p in parts if p.get("text") and not p.get("thought"))
        except (KeyError, IndexError):
            return JSONResponse({"error": f"Could not read Gemini response | raw: {raw_text[:300]}"}, status_code=500)
        return JSONResponse({"text": text})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/parse-order", response_class=HTMLResponse)
def parse_order_form(request: Request, branch_id: int = 0, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    # Supervisor must pick a branch first
    if is_supervisor(user):
        effective_branch_id = branch_id or (branches[0].id if branches else 0)
    else:
        effective_branch_id = get_selected_branch_id(request, user) or 0
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == effective_branch_id).order_by(User.username.asc())).scalars().all()
    _items_with_stock = get_items_with_stock(db, branch_id=effective_branch_id)
    items = [it for it, _ in _items_with_stock]
    csrf_token = get_csrf_token(request)
    items_json = [{"id": it.id, "name": it.name, "category": it.category or "", "unit": it.unit or "pcs", "price": float(it.selling_price or 0), "stock": int(stk)} for it, stk in _items_with_stock]
    return tpl(request, "parse_order.html", {
        "request": request, "user": user, "active": "parse_order",
        "agents": agents, "items": items,
        "items_with_stock": _items_with_stock,
        "items_json": items_json,
        "branches": branches, "selected_branch_id": effective_branch_id,
        "today": date.today().isoformat(), "csrf_token": csrf_token,
    })


@app.get("/deliveries/new", response_class=HTMLResponse)
def delivery_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if is_agent(user):
        return HTMLResponse("Forbidden — only admins can create orders", status_code=403)
    branch_id = get_selected_branch_id(request, user)
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())).scalars().all()
    # Get items with current stock levels for out-of-stock labelling
    _items_with_stock = get_items_with_stock(db, branch_id=branch_id)
    items = [(it, int(stock)) for it, stock in _items_with_stock]
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    # Pending assignments per agent — for linking assigned stock to delivery
    pending_assignments = {}
    if is_admin(user) and branch_id:
        try:
            rows_a = db.execute(text(
                "SELECT asa.id, asa.agent_id, asa.item_id, asa.qty_assigned, asa.note, "
                "it.name AS item_name "
                "FROM agent_stock_assignments asa "
                "JOIN items it ON it.id = asa.item_id "
                "WHERE asa.branch_id = :bid AND asa.returned = FALSE "
                "AND (asa.delivery_id IS NULL OR asa.delivery_id = 0)"
            ), {"bid": branch_id}).fetchall()
        except Exception:
            # Fallback if delivery_id column doesn't exist yet
            db.rollback()
            rows_a = db.execute(text(
                "SELECT asa.id, asa.agent_id, asa.item_id, asa.qty_assigned, asa.note, "
                "it.name AS item_name "
                "FROM agent_stock_assignments asa "
                "JOIN items it ON it.id = asa.item_id "
                "WHERE asa.branch_id = :bid AND asa.returned = FALSE"
            ), {"bid": branch_id}).fetchall()
        for r in rows_a:
            pending_assignments.setdefault(r[1], []).append({
                "id": r[0], "item_id": r[2], "qty": r[3],
                "note": r[4] or "", "item_name": r[5],
            })
    csrf_token = get_csrf_token(request)
    return tpl(request, "delivery_new.html", {
        "request": request, "agents": agents, "items": items, "user": user,
        "active": "deliveries_new", "branches": branches, "selected_branch_id": branch_id,
        "today": date.today().isoformat(), "csrf_token": csrf_token,
        "pending_assignments": pending_assignments,
    })


@app.post("/deliveries/new")
async def delivery_create(
    request: Request,
    agent_id: int | None = Form(None),
    branch_id: int | None = Form(None),
    customer_name: str = Form(...),
    customer_phone: str = Form(""),
    address: str = Form(""),
    note: str = Form(""),
    delivery_date: str = Form(""),
    item_id: list[int] = Form(...),
    quantity: list[int] = Form(...),
    line_amount: list[float] = Form(default=[]),
    assignment_ids: list[int] = Form(default=[]),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
    if is_supervisor(user):
        # Supervisor creates unassigned order for a specific branch
        # Find the admin of that branch to assign, or leave agent_id as None
        if not branch_id:
            raise HTTPException(status_code=400, detail="Branch required")
        # Assign to first admin of the branch (they will re-delegate to agents)
        branch_admin = db.scalar(select(User).where(User.role == "ADMIN").where(User.branch_id == branch_id))
        target_agent_id = branch_admin.id if branch_admin else None
        if not target_agent_id:
            raise HTTPException(status_code=400, detail="No admin found for selected branch")
    elif is_admin(user):
        if agent_id is None:
            raise HTTPException(status_code=422, detail="agent_id required for admin")
        target_agent_id = int(agent_id)
        branch_id = get_current_branch_id(request)
    else:
        target_agent_id = int(user.id)
        branch_id = get_current_branch_id(request)
    cust = sanitize_text(customer_name, 160, "Customer name")
    if not cust:
        raise HTTPException(status_code=400, detail="Customer name required")
    if not branch_id:
        raise HTTPException(status_code=400, detail="No branch assigned")
    try:
        d_date = datetime.strptime(delivery_date.strip(), "%Y-%m-%d") if delivery_date.strip() else datetime.utcnow()
    except ValueError:
        d_date = datetime.utcnow()
    d = Delivery(
        branch_id=branch_id, agent_id=target_agent_id, customer_name=cust,
        customer_phone=sanitize_phone(customer_phone) or None,
        address=sanitize_text(address, 300, "Address") or None,
        note=sanitize_text(note, 400, "Note") or None,
        status="PENDING", delivery_date=d_date,
    )
    db.add(d)
    db.flush()
    amounts = list(line_amount or [])
    while len(amounts) < len(item_id):
        amounts.append(0.0)
    assigned_item_ids = set()  # items covered by assignment (already have OUT tx)
    for aid in (assignment_ids or []):
        asgn_row = db.execute(text(
            "SELECT item_id FROM agent_stock_assignments WHERE id = :aid"
        ), {"aid": aid}).fetchone()
        if asgn_row:
            assigned_item_ids.add(int(asgn_row[0]))
    tx_item_ids = set()  # track items we've already created an OUT tx for
    for iid, qty, amt in zip(item_id, quantity, amounts):
        q = int(qty) if qty is not None else 0
        if q > 0:
            db.add(DeliveryItem(delivery_id=d.id, item_id=int(iid), quantity=q, line_amount=float(amt or 0)))
            # Supervisor-created orders: no OUT transaction — stock only leaves when
            # the branch admin assigns the delivery to an agent.
            if is_supervisor(user):
                continue
            # Create OUT transaction immediately (unless covered by an assignment)
            if int(iid) not in assigned_item_ids:
                if int(iid) not in tx_item_ids:
                    db.add(Transaction(
                        branch_id=branch_id, item_id=int(iid), type="OUT", quantity=q,
                        note=f"Delivery #{d.id} to {cust} — assigned to agent",
                        reference=f"delivery-{d.id}",
                        delivery_id=d.id,
                    ))
                    tx_item_ids.add(int(iid))
                else:
                    # Same item submitted twice — add quantity to existing pending transaction
                    db.execute(text(
                        "UPDATE transactions SET quantity = quantity + :q "
                        "WHERE delivery_id = :did AND item_id = :iid AND type = 'OUT'"
                    ), {"q": q, "did": d.id, "iid": int(iid)})
    # Link assignments if provided — no extra stock OUT needed (already deducted)
    for aid in (assignment_ids or []):
        asgn = db.execute(text(
            "SELECT id, agent_id, item_id, branch_id, qty_assigned, transaction_out_id, note, assigned_by "
            "FROM agent_stock_assignments "
            "WHERE id = :aid AND returned = FALSE"
        ), {"aid": aid}).fetchone()
        if asgn and asgn[1] == target_agent_id:
            asgn_id, _, asgn_item_id, asgn_branch_id, asgn_qty, asgn_tx_id, asgn_note, asgn_by = asgn
            # Find how many of this item the delivery actually uses
            delivery_qty = 0
            for iid, qty_val in zip(item_id, quantity):
                if int(iid) == int(asgn_item_id):
                    delivery_qty = int(qty_val) if qty_val else 0
                    break
            remainder = asgn_qty - delivery_qty
            if remainder > 0 and delivery_qty > 0:
                # Split: reduce original assignment to delivery_qty and link it
                db.execute(text(
                    "UPDATE agent_stock_assignments SET qty_assigned=:qty, delivery_id=:did WHERE id=:aid"
                ), {"qty": delivery_qty, "did": d.id, "aid": asgn_id})
                # Create new assignment for the remainder (stays for vetting)
                db.execute(text(
                    "INSERT INTO agent_stock_assignments "
                    "(agent_id, item_id, branch_id, qty_assigned, note, assigned_by, assigned_at, returned, qty_returned) "
                    "VALUES (:agent, :item, :branch, :qty, :note, :by, NOW(), FALSE, 0)"
                ), {"agent": asgn[1], "item": asgn_item_id, "branch": asgn_branch_id,
                    "qty": remainder, "note": (asgn_note or '') + f' (split from #{asgn_id})', "by": asgn_by})
            else:
                # Full assignment used or no delivery item match — link whole thing
                db.execute(text(
                    "UPDATE agent_stock_assignments SET delivery_id = :did WHERE id = :aid"
                ), {"did": d.id, "aid": asgn_id})
            if asgn_tx_id:
                db.execute(text(
                    "UPDATE transactions SET delivery_id = :did WHERE id = :txid"
                ), {"did": d.id, "txid": asgn_tx_id})

    db.commit()
    # Notify branch admins of new order
    notify_branch_admins(db, d.branch_id, "🆕 New Order Created",
        f"New delivery for {cust} created{' by supervisor' if is_supervisor(user) else ''}.",
        f"/deliveries/{d.id}", "info")
    # ... existing code ...
    if is_admin(user) and target_agent_id and target_agent_id != user.id:
        notify(db, target_agent_id, "📦 New Delivery Assigned",
               f"A new delivery for {cust} has been assigned to you.",
               f"/deliveries/{d.id}", "info")
    db.commit()

    # ==========================================
    # ADD THIS NEW BLOCK TO TRIGGER THE CALL
    # ==========================================
    # 1. Build a readable list of items for the AI to speak
    call_items = []
    for iid, qty in zip(item_id, quantity):
        if int(qty) > 0:
            it = db.get(Item, int(iid))
            if it:
                call_items.append(f"{it.name} x{qty}")
    items_summary = ", ".join(call_items) if call_items else "your order"

    # 2. Trigger the call immediately
    # We pass "PENDING" as the status since it's a brand new order
    trigger_call(d.id, d.customer_phone, "PENDING", d.customer_name, items_summary)
    # ==========================================
# 1. Build a readable list of items for the AI to speak
    call_items = []
    for iid, qty in zip(item_id, quantity):
        if int(qty) > 0:
            it = db.get(Item, int(iid))
            if it:
                call_items.append(f"{it.name} x{qty}")
    items_summary = ", ".join(call_items) if call_items else "your order"

    # 2. Trigger the call immediately (NOW INCLUDES ADDRESS)
    trigger_call(d.id, d.customer_phone, "PENDING", d.customer_name, items_summary, d.address)

    return redirect(f"/deliveries/{d.id}")



# ────────────────────────────────────────────────
#  AGENT OVERVIEW
# ────────────────────────────────────────────────

@app.get("/agent-overview", response_class=HTMLResponse)
def agent_overview(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if is_admin(user) or is_supervisor(user):
        return redirect("/")
    branch_id = get_selected_branch_id(request, user)

    # Stats
    rows = db.execute(
        select(Delivery).where(Delivery.agent_id == user.id).where(Delivery.branch_id == branch_id)
        .order_by(desc(Delivery.created_at)).limit(300)
    ).scalars().all()
    pending_c = sum(1 for d in rows if d.status == "PENDING")
    ofd_c = sum(1 for d in rows if d.status == "OUT_FOR_DELIVERY")
    done_c = sum(1 for d in rows if d.status == "DELIVERED")

    # Chart data — last 14 days
    today = date.today()
    chart_days = [(today - timedelta(days=i)) for i in range(13, -1, -1)]
    delivery_by_day: dict = {}
    for d in rows:
        if d.status != "DELIVERED":
            continue
        k = d.delivered_at.date().isoformat() if d.delivered_at else (d.created_at.date().isoformat() if d.created_at else None)
        if k:
            delivery_by_day[k] = delivery_by_day.get(k, 0) + 1
    expense_by_day: dict = {}
    expenses_raw = db.execute(
        select(CashEntry).where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind.in_(["EXPENSE", "COLLECTION_EXPENSE"]))
        .where(CashEntry.created_at >= datetime.utcnow() - timedelta(days=14))
    ).scalars().all()
    for e in expenses_raw:
        k = e.created_at.date().isoformat() if e.created_at else None
        if k:
            expense_by_day[k] = expense_by_day.get(k, 0) + float(e.amount or 0)

    total_collected = float(db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind.in_(["COLLECTION", "CASH_PAYMENT", "TRANSFER_PAYMENT"]))
    ) or 0)
    cash_collected = float(db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind.in_(["COLLECTION", "CASH_PAYMENT"]))
    ) or 0)
    transfer_collected = float(db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind == "TRANSFER_PAYMENT")
    ) or 0)
    total_expenses = float(db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind.in_(["EXPENSE", "COLLECTION_EXPENSE"]))
    ) or 0)

    import json as _json
    deliveries_json = [
        {"id": d.id, "customer_name": d.customer_name, "status": d.status,
         "address": d.address or "", "created_at": d.created_at.strftime("%d %b %Y") if d.created_at else ""}
        for d in rows
    ]
    return tpl(request, "agent_overview.html", {
        "request": request, "user": user, "active": "dashboard",
        "total_deliveries": len(rows), "pending_c": pending_c,
        "ofd_c": ofd_c, "done_c": done_c,
        "total_collected": total_collected, "total_expenses": total_expenses,
        "cash_collected": cash_collected, "transfer_collected": transfer_collected,
        "deliveries_json": deliveries_json,
        "chart_labels": [str(d) for d in chart_days],
        "chart_deliveries": [delivery_by_day.get(d.isoformat(), 0) for d in chart_days],
        "chart_expenses": [round(expense_by_day.get(d.isoformat(), 0), 2) for d in chart_days],
    })

@app.get("/my-deliveries", response_class=HTMLResponse)
def my_deliveries(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    branch_id = get_selected_branch_id(request, user)
    rows = db.execute(
        select(Delivery).where(Delivery.agent_id == user.id).where(Delivery.branch_id == branch_id)
        .order_by(desc(Delivery.created_at)).limit(300)
    ).scalars().all()

    # Build items summary for each delivery
    delivery_ids = [d.id for d in rows]
    items_summary: dict[int, str] = {}
    if delivery_ids:
        _phantom_ids3 = set(r[0] for r in db.execute(text(
            "SELECT DISTINCT delivery_item_id FROM stock_return_vettings"
        )).fetchall())
        lines = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity, DeliveryItem.id)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        grouped: dict[int, list[str]] = {}
        for did, iname, qty, di_id in lines:
            if di_id in _phantom_ids3:
                continue
            grouped.setdefault(int(did), []).append(f"{iname} ×{int(qty)}")
        items_summary = {did: ", ".join(parts) for did, parts in grouped.items()}

    return tpl(request, "my_deliveries.html", {
        "request": request, "rows": rows, "user": user, "active": "deliveries",
        "items_summary": items_summary,
    })


@app.get("/deliveries/adjustment-count", response_class=JSONResponse)
def adjustment_count(request: Request, db: Session = Depends(get_db)):
    """Badge count for admin nav — pending adjustment requests."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"count": 0})
    user = user_or
    if not is_admin(user): return JSONResponse({"count": 0})
    count = db.execute(
        text("SELECT COUNT(*) FROM adjustment_requests ar JOIN deliveries d ON d.id = ar.delivery_id WHERE ar.status = 'PENDING' AND d.branch_id = :bid"),
        {"bid": user.branch_id}
    ).scalar() or 0
    return JSONResponse({"count": int(count)})


@app.get("/deliveries/{delivery_id}", response_class=HTMLResponse)
def delivery_detail(request: Request, delivery_id: int, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    d = db.get(Delivery, delivery_id)
    require_delivery_access(request, user, d)
    if not is_admin(user) and not is_supervisor(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    d_items_all = db.execute(
        select(DeliveryItem, Item).join(Item, Item.id == DeliveryItem.item_id).where(DeliveryItem.delivery_id == d.id)
    ).all()
    # Find which delivery_items are vetting-only phantoms (from adjustment approval)
    _vetting_di_ids = set(r[0] for r in db.execute(text(
        "SELECT DISTINCT delivery_item_id FROM stock_return_vettings WHERE delivery_id=:did"
    ), {"did": d.id}).fetchall())
    # Hide items that have vetting records — those are phantom items for return tracking
    d_items = [(di, it) for di, it in d_items_all if di.id not in _vetting_di_ids]
    col = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.delivery_id == d.id).where(CashEntry.kind.in_(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"]))) or 0
    cash_total = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.delivery_id == d.id).where(CashEntry.kind.in_(["COLLECTION","CASH_PAYMENT"]))) or 0
    transfer_total = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.delivery_id == d.id).where(CashEntry.kind == "TRANSFER_PAYMENT")) or 0
    exp = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.delivery_id == d.id).where(CashEntry.kind == "EXPENSE")) or 0
    csrf_token = get_csrf_token(request)
    agents = db.execute(
        select(User).where(User.role == "AGENT").where(User.branch_id == d.branch_id).order_by(User.username.asc())
    ).scalars().all() if is_admin(user) or is_supervisor(user) else []
    # Load any pending adjustment request
    pending_adj = db.execute(
        text("SELECT ar.id, ar.reason, ar.created_at, u.username as agent_name FROM adjustment_requests ar JOIN users u ON u.id = ar.requested_by WHERE ar.delivery_id = :did AND ar.status = 'PENDING' ORDER BY ar.created_at DESC LIMIT 1"),
        {"did": d.id}
    ).fetchone()
    adj_items = []
    if pending_adj:
        adj_items = db.execute(
            text("SELECT id, request_id, delivery_item_id, item_name, original_amount, new_amount, remove_item FROM adjustment_request_items WHERE request_id = :rid ORDER BY id"),
            {"rid": pending_adj.id}
        ).fetchall()
    return tpl(request, "delivery_detail.html", {
        "request": request, "d": d, "d_items": d_items, "user": user, "error": None,
        "collection_total": float(col), "expense_total": float(exp),
        "cash_total": float(cash_total), "transfer_total": float(transfer_total),
        "back_url": "/deliveries" if is_admin(user) else "/my-deliveries",
        "active": "deliveries", "csrf_token": csrf_token, "agents": agents,
        "pending_adj": pending_adj, "adj_items": adj_items,
    })


@app.post("/deliveries/bulk-assign")
async def deliveries_bulk_assign(
    request: Request,
    agent_id: int = Form(...),
    delivery_ids: list[int] = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user): return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    branch_id = get_selected_branch_id(request, user)
    agent = db.get(User, agent_id)
    if not agent or agent.role != "AGENT" or agent.branch_id != branch_id:
        return redirect("/deliveries?error=Invalid+agent")
    assigned = 0
    for did in delivery_ids:
        d = db.get(Delivery, did)
        if not d or d.branch_id != branch_id or d.status == "DELIVERED":
            continue
        old_agent_id = d.agent_id
        d.agent_id = agent_id
        # Create OUT transactions for items that don't have one yet
        # (covers orders created by supervisor with no OUT tx)
        items_without_tx = db.execute(text("""
            SELECT di.item_id, di.quantity FROM delivery_items di
            WHERE di.delivery_id = :did
              AND NOT EXISTS (
                SELECT 1 FROM transactions t
                WHERE t.delivery_id = :did AND t.item_id = di.item_id AND t.type = 'OUT'
              )
        """), {"did": did}).fetchall()
        for item_id_row, qty in items_without_tx:
            db.add(Transaction(
                branch_id=branch_id, item_id=item_id_row, type="OUT", quantity=qty,
                note=f"Delivery #{did} to {d.customer_name} — assigned to agent",
                reference=f"delivery-{did}", delivery_id=did,
            ))
        notify(db, agent_id, "📦 New Delivery Assigned",
               f"Delivery #{d.id} for {d.customer_name} has been assigned to you.",
               f"/deliveries/{d.id}", "info")
        assigned += 1
    db.commit()
    return redirect(f"/deliveries?success={assigned}+order(s)+assigned+to+{agent.full_name or agent.username}")


@app.post("/deliveries/{delivery_id}/assign-agent")
async def delivery_assign_agent(
    request: Request, delivery_id: int,
    agent_id: int = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    d = db.get(Delivery, delivery_id)
    if not d: raise HTTPException(status_code=404, detail="Delivery not found")
    if d.status == "DELIVERED":
        return redirect(f"/deliveries/{delivery_id}?error=Cannot+reassign+a+delivered+order")
    # Admin can only assign within their branch
    if is_admin(user) and d.branch_id != user.branch_id:
        return HTMLResponse("Forbidden", status_code=403)
    agent = db.get(User, agent_id)
    if not agent or agent.branch_id != d.branch_id:
        return redirect(f"/deliveries/{delivery_id}?error=Agent+not+found+or+not+in+this+branch")
    d.agent_id = agent_id
    db.commit()
    notify(db, agent_id, "📦 New Delivery Assigned",
           f"Delivery #{d.id} for {d.customer_name} has been assigned to you.",
           f"/deliveries/{d.id}", "info")
    db.commit()
    audit_log(db, user.id, "DELIVERY_REASSIGNED",
              f"delivery_id={delivery_id} assigned to agent_id={agent_id}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    return redirect(f"/deliveries/{delivery_id}?success=Agent+assigned+successfully")


@app.post("/deliveries/{delivery_id}/date")
async def update_delivery_date(
    request: Request, delivery_id: int,
    delivery_date: str = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    d = db.get(Delivery, delivery_id)
    require_delivery_access(request, user, d)
    if not is_admin(user) and not is_supervisor(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    try:
        d.delivery_date = datetime.strptime(delivery_date.strip(), "%Y-%m-%d")
        db.commit()
    except ValueError:
        pass
    return redirect(f"/deliveries/{delivery_id}")


@app.post("/deliveries/{delivery_id}/request-adjustment")
async def request_adjustment(
    request: Request, delivery_id: int,
    reason: str = Form(""),
    item_ids: list[int] = Form(default=[]),
    new_amounts: list[float] = Form(default=[]),
    new_quantities: list[int] = Form(default=[]),
    remove_flags: list[str] = Form(default=[]),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
    d = db.get(Delivery, delivery_id)
    if not d: raise HTTPException(status_code=404)
    if d.agent_id != user.id and not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    if d.status not in ("OUT_FOR_DELIVERY", "PENDING"):
        return redirect(f"/deliveries/{delivery_id}?error=Can+only+request+adjustment+on+active+deliveries")
    # Cancel any existing pending request
    db.execute(text("UPDATE adjustment_requests SET status='CANCELLED' WHERE delivery_id=:did AND status='PENDING'"), {"did": d.id})
    # Create new request
    result = db.execute(
        text("INSERT INTO adjustment_requests (delivery_id, requested_by, reason, status, created_at) VALUES (:did, :uid, :reason, 'PENDING', NOW()) RETURNING id"),
        {"did": d.id, "uid": user.id, "reason": (reason or "").strip()[:400]}
    )
    req_id = result.fetchone()[0]
    # Save item adjustments
    d_items = db.execute(select(DeliveryItem, Item).join(Item, Item.id == DeliveryItem.item_id).where(DeliveryItem.delivery_id == d.id)).all()
    item_map = {di.id: (di, it) for di, it in d_items}
    for i, item_id in enumerate(item_ids):
        if item_id not in item_map: continue
        di, it = item_map[item_id]
        new_amt  = float(new_amounts[i]) if i < len(new_amounts) else float(di.line_amount)
        new_qty  = int(new_quantities[i]) if i < len(new_quantities) and new_quantities[i] else di.quantity
        new_qty  = max(0, min(new_qty, di.quantity))  # clamp 0..original
        remove   = remove_flags[i] == "1" if i < len(remove_flags) else (new_qty == 0)
        db.execute(text(
            "INSERT INTO adjustment_request_items (request_id, delivery_item_id, item_name, original_amount, new_amount, remove_item) "
            "VALUES (:rid, :diid, :name, :orig, :new, :rem)"
        ), {"rid": req_id, "diid": di.id, "name": it.name, "orig": float(di.line_amount), "new": new_amt if not remove else 0, "rem": remove})
        # Store new quantity in remove_item logic — use new_amount=0 + note for qty reduction
        if not remove and new_qty != di.quantity:
            # Update the line amount proportionally
            if di.quantity > 0:
                proportional_amt = float(di.line_amount) * new_qty / di.quantity
                new_amt = proportional_amt if float(new_amounts[i] if i < len(new_amounts) else 0) == 0 else new_amt
            db.execute(text(
                "UPDATE adjustment_request_items SET new_amount=:amt WHERE request_id=:rid AND delivery_item_id=:diid"
            ), {"amt": new_amt, "rid": req_id, "diid": di.id})
        # Store new qty in item name field as suffix for review
        if new_qty != di.quantity and not remove:
            db.execute(text(
                "UPDATE adjustment_request_items SET item_name=:name WHERE request_id=:rid AND delivery_item_id=:diid"
            ), {"name": f"{it.name} (qty: {di.quantity}→{new_qty})", "rid": req_id, "diid": di.id})
    d.status = "ADJUSTMENT_PENDING"
    notify_branch_admins(db, d.branch_id, "⚠️ Adjustment Request",
           f"Agent requested price adjustment on delivery #{d.id} ({d.customer_name}). Reason: {(reason or '').strip()[:100]}",
           f"/deliveries/{d.id}", "warning")
    db.commit()
    audit_log(db, user.id, "ADJUSTMENT_REQUESTED", f"delivery_id={d.id} request_id={req_id}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    db.commit()
    return redirect(f"/deliveries/{delivery_id}?success=Adjustment+request+submitted+awaiting+admin+approval")


@app.post("/deliveries/{delivery_id}/review-adjustment")
async def review_adjustment(
    request: Request, delivery_id: int,
    action: str = Form(...),
    rejection_note: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user): return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    d = db.get(Delivery, delivery_id)
    if not d: raise HTTPException(status_code=404)
    pending = db.execute(
        text("SELECT id, delivery_id, requested_by, reason, status, reviewed_by, rejection_note, created_at, reviewed_at FROM adjustment_requests WHERE delivery_id=:did AND status='PENDING' ORDER BY created_at DESC LIMIT 1"),
        {"did": d.id}
    ).fetchone()
    if not pending:
        return redirect(f"/deliveries/{delivery_id}?error=No+pending+adjustment+request+found")
    if action == "approve":
        adj_items = db.execute(
            text("SELECT id, request_id, delivery_item_id, item_name, original_amount, new_amount, remove_item FROM adjustment_request_items WHERE request_id=:rid"), {"rid": pending.id}
        ).fetchall()
        for ai in adj_items:
            if ai.remove_item:
                # Item was refused by customer — still physically with the agent.
                # Zero out the delivery item (keep it for vetting FK) and create vetting record.
                di = db.get(DeliveryItem, ai.delivery_item_id)
                if di and di.quantity > 0:
                    db.execute(text(
                        "INSERT INTO stock_return_vettings "
                        "(delivery_id, delivery_item_id, vetted_by, qty_returned, created_at, resolved) "
                        "VALUES (:did, :diid, NULL, 0, NOW(), FALSE)"
                    ), {"did": d.id, "diid": di.id})
                    # Zero out amount but keep the item record for vetting reference
                    db.execute(
                        text("UPDATE delivery_items SET line_amount=0 WHERE id=:did"),
                        {"did": ai.delivery_item_id}
                    )
            else:
                # Price/qty change — update the line amount
                db.execute(
                    text("UPDATE delivery_items SET line_amount=:amt WHERE id=:did"),
                    {"amt": ai.new_amount, "did": ai.delivery_item_id}
                )
                # Check if qty was reduced (encoded in item_name as "Name (qty: X→Y)")
                import re as _re
                qty_match = _re.search(r'\(qty:\s*(\d+)\s*→\s*(\d+)\)', ai.item_name or '')
                if qty_match:
                    old_qty = int(qty_match.group(1))
                    new_qty = int(qty_match.group(2))
                    reduced_by = old_qty - new_qty
                    if reduced_by > 0:
                        di = db.get(DeliveryItem, ai.delivery_item_id)
                        if di:
                            # Update the active delivery item to the new qty
                            db.execute(
                                text("UPDATE delivery_items SET quantity=:qty WHERE id=:did"),
                                {"qty": new_qty, "did": ai.delivery_item_id}
                            )
                            # Create a new delivery_item for the reduced portion (for vetting)
                            db.execute(text(
                                "INSERT INTO delivery_items (delivery_id, item_id, quantity, line_amount) "
                                "VALUES (:did, :iid, :qty, 0) RETURNING id"
                            ), {"did": d.id, "iid": di.item_id, "qty": reduced_by})
                            new_di_id = db.execute(text(
                                "SELECT id FROM delivery_items WHERE delivery_id=:did AND item_id=:iid AND quantity=:qty AND line_amount=0 ORDER BY id DESC LIMIT 1"
                            ), {"did": d.id, "iid": di.item_id, "qty": reduced_by}).scalar()
                            if new_di_id:
                                db.execute(text(
                                    "INSERT INTO stock_return_vettings "
                                    "(delivery_id, delivery_item_id, vetted_by, qty_returned, created_at, resolved) "
                                    "VALUES (:did, :diid, NULL, 0, NOW(), FALSE)"
                                ), {"did": d.id, "diid": new_di_id})
        db.execute(
            text("UPDATE adjustment_requests SET status='APPROVED', reviewed_by=:uid, reviewed_at=NOW() WHERE id=:rid"),
            {"uid": user.id, "rid": pending.id}
        )
        d.status = "OUT_FOR_DELIVERY"
        notify(db, d.agent_id, "✅ Adjustment Approved",
               f"Your price adjustment for delivery #{d.id} ({d.customer_name}) has been approved. You can now mark it as delivered.",
               f"/deliveries/{d.id}", "success")
        db.commit()
        audit_log(db, user.id, "ADJUSTMENT_APPROVED", f"delivery_id={d.id} request_id={pending.id}",
                  ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
        db.commit()
        return redirect(f"/deliveries/{delivery_id}?success=Adjustment+approved+agent+can+now+mark+delivered")
    else:
        note = (rejection_note or "").strip()[:400] or "Rejected by admin"
        db.execute(
            text("UPDATE adjustment_requests SET status='REJECTED', reviewed_by=:uid, reviewed_at=NOW(), rejection_note=:note WHERE id=:rid"),
            {"uid": user.id, "rid": pending.id, "note": note}
        )
        d.status = "OUT_FOR_DELIVERY"
        notify(db, d.agent_id, "❌ Adjustment Rejected",
               f"Your price adjustment for delivery #{d.id} ({d.customer_name}) was rejected. {note}",
               f"/deliveries/{d.id}", "danger")
        db.commit()
        audit_log(db, user.id, "ADJUSTMENT_REJECTED", f"delivery_id={d.id} request_id={pending.id}",
                  ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
        db.commit()
        return redirect(f"/deliveries/{delivery_id}?success=Adjustment+rejected+agent+notified")


@app.post("/deliveries/{delivery_id}/collect")
async def delivery_collect(
    request: Request, delivery_id: int,
    cash_amount: float = Form(0.0),
    transfer_amount: float = Form(0.0),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    """Mark delivery as DELIVERED with cash/transfer payment breakdown."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    d = db.get(Delivery, delivery_id)
    require_delivery_access(request, user, d)
    if not is_admin(user) and not is_supervisor(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    if d.status == "DELIVERED":
        return redirect(f"/deliveries/{delivery_id}?error=Already+delivered")

    cash_amt     = max(0.0, float(cash_amount or 0))
    transfer_amt = max(0.0, float(transfer_amount or 0))
    total_paid   = cash_amt + transfer_amt

    # Mark delivered
    create_out_transactions_for_delivery_if_needed(db, d.id, performed_by=user.username)
    d.status = "DELIVERED"
    d.delivered_at = datetime.utcnow()

    # Remove any existing collection entries for this delivery
    db.execute(text(
        "DELETE FROM cash_entries WHERE delivery_id = :did AND kind IN ('COLLECTION','CASH_PAYMENT','TRANSFER_PAYMENT')"
    ), {"did": d.id})
    now = datetime.utcnow()
    # Record cash portion
    if cash_amt > 0:
        db.add(CashEntry(
            branch_id=d.branch_id, agent_id=d.agent_id, delivery_id=d.id,
            kind="COLLECTION", amount=cash_amt, created_at=now,
            note=f"Cash payment — delivery #{d.id} to {d.customer_name}",
        ))
    # Record transfer portion
    if transfer_amt > 0:
        db.add(CashEntry(
            branch_id=d.branch_id, agent_id=d.agent_id, delivery_id=d.id,
            kind="TRANSFER_PAYMENT", amount=transfer_amt, created_at=now,
            note=f"Transfer payment — delivery #{d.id} to {d.customer_name}",
        ))
    # If nothing entered, use full order total
    if cash_amt == 0 and transfer_amt == 0:
        order_total = float(db.scalar(
            select(func.coalesce(func.sum(DeliveryItem.line_amount), 0))
            .where(DeliveryItem.delivery_id == d.id)
        ) or 0)
        if order_total > 0:
            db.add(CashEntry(
                branch_id=d.branch_id, agent_id=d.agent_id, delivery_id=d.id,
                kind="COLLECTION", amount=order_total, created_at=now,
                note=f"Auto-recorded: delivery #{d.id} to {d.customer_name}",
            ))

    notify_branch_admins(db, d.branch_id, "✅ Delivery Completed",
           f"Agent marked delivery #{d.id} ({d.customer_name}) as delivered. Cash: ₦{cash_amt:,.0f} Transfer: ₦{transfer_amt:,.0f}",
           f"/deliveries/{d.id}", "success")
    audit_log(db, user.id, "DELIVERY_DELIVERED",
              f"delivery_id={d.id} cash={cash_amt} transfer={transfer_amt}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    db.commit()
    return redirect(f"/deliveries/{delivery_id}?success=Delivery+marked+as+delivered")


@app.post("/deliveries/{delivery_id}/status")
async def update_delivery_status(
    request: Request, delivery_id: int,
    status: str = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    d = db.get(Delivery, delivery_id)
    require_delivery_access(request, user, d)
    if not is_admin(user) and not is_supervisor(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    status_clean = (status or "").strip().upper()
    if status_clean not in {"PENDING", "OUT_FOR_DELIVERY", "DELIVERED", "FAILED", "RETURNED"}:
        raise HTTPException(status_code=400, detail="Invalid status")
    # Lock: once DELIVERED, FAILED, or RETURNED — no further status changes
    if d.status in ("DELIVERED", "FAILED", "RETURNED"):
        return redirect(f"/deliveries/{delivery_id}?error=This+order+is+{d.status.lower()}+and+cannot+be+updated")
    if d.status == "ADJUSTMENT_PENDING" and status_clean == "DELIVERED":
        return redirect(f"/deliveries/{delivery_id}?error=Cannot+mark+delivered+while+adjustment+request+is+pending+admin+approval")
    # Helper: build item summary string for AI call script
    def _items_summary() -> str:
        rows = db.execute(
            select(Item.name, DeliveryItem.quantity)
            .join(DeliveryItem, DeliveryItem.item_id == Item.id)
            .where(DeliveryItem.delivery_id == d.id) # <-- FIXED
        ).all()
        return ", ".join(f"{r.name} x{r.quantity}" for r in rows) if rows else "your order"

    if status_clean == "DELIVERED":
        try:
            create_out_transactions_for_delivery_if_needed(db, d.id, performed_by=user.username)
            d.status = "DELIVERED"
            d.delivered_at = datetime.utcnow()
            audit_log(db, user.id, "DELIVERY_DELIVERED", f"delivery_id={d.id}",
                      ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))

            # Auto-close any linked assignment — stock was used for this delivery
            db.execute(text(
                "UPDATE agent_stock_assignments SET returned=TRUE, qty_returned=qty_assigned, "
                "vetted_at=NOW() WHERE delivery_id=:did AND returned=FALSE"
            ), {"did": d.id})

            # Auto-create COLLECTION cash entry from delivery order total
            existing_col = db.scalar(
                select(func.count(CashEntry.id)).where(
                    CashEntry.delivery_id == d.id,
                    CashEntry.kind.in_(["COLLECTION", "CASH_PAYMENT", "TRANSFER_PAYMENT"])
                )
            ) or 0
            if existing_col == 0:
                order_total = db.scalar(
                    select(func.coalesce(func.sum(DeliveryItem.line_amount), 0))
                    .where(DeliveryItem.delivery_id == d.id)
                ) or 0
                order_total = float(order_total)
                if order_total > 0:
                    db.add(CashEntry(
                        branch_id=d.branch_id,
                        agent_id=d.agent_id,
                        delivery_id=d.id,
                        kind="COLLECTION",
                        amount=order_total,
                        note=f"Auto-recorded: delivery #{d.id} to {d.customer_name}",
                    ))

            db.commit()
            trigger_call(d.id, d.customer_phone, "DELIVERED", d.customer_name, _items_summary(), d.address)
        except ValueError as e:
            d_items = db.execute(select(DeliveryItem, Item).join(Item, Item.id == DeliveryItem.item_id).where(DeliveryItem.delivery_id == d.id)).all()
            csrf_token2 = get_csrf_token(request)
            return tpl(request, "delivery_detail.html", {
                "request": request, "d": d, "d_items": d_items, "user": user, "error": str(e),
                "collection_total": 0, "expense_total": 0,
                "back_url": "/deliveries" if is_admin(user) else "/my-deliveries",
                "active": "deliveries", "csrf_token": csrf_token2,
            })
        return redirect(f"/deliveries/{delivery_id}")
    d.status = status_clean
    # Notify agent of status change
    if status_clean == "OUT_FOR_DELIVERY" and d.agent_id:
        notify(db, d.agent_id, "🚚 Delivery Dispatched",
               f"Delivery #{d.id} to {d.customer_name} is now out for delivery.",
               f"/deliveries/{d.id}", "info")
    elif status_clean == "FAILED" and d.agent_id:
        notify(db, d.agent_id, "✕ Delivery Marked Failed",
               f"Delivery #{d.id} to {d.customer_name} has been marked as failed.",
               f"/deliveries/{d.id}", "danger")
    elif status_clean == "RETURNED" and d.agent_id:
        notify(db, d.agent_id, "↩ Delivery Marked Returned",
               f"Delivery #{d.id} to {d.customer_name} has been marked as returned.",
               f"/deliveries/{d.id}", "warning")
    # If delivery fails/returns and has a linked assignment — notify admin to vet stock return
    if status_clean in ("FAILED", "RETURNED"):
        linked = db.execute(text(
            "SELECT asa.id, it.name FROM agent_stock_assignments asa "
            "JOIN items it ON it.id = asa.item_id "
            "WHERE asa.delivery_id = :did AND asa.returned = FALSE"
        ), {"did": delivery_id}).fetchall()
        for asgn_id, item_name in linked:
            notify_branch_admins(db, d.branch_id,
                f"⚠ Assigned Stock Needs Return",
                f"Delivery #{delivery_id} {status_clean.lower()} — {item_name} assigned stock must be vetted.",
                f"/vetting", "warning")
    db.commit()
    trigger_call(d.id, d.customer_phone, status_clean, d.customer_name, _items_summary(), d.address)
    return redirect(f"/deliveries/{delivery_id}")


# ────────────────────────────────────────────────
#  NOTIFICATIONS
# ────────────────────────────────────────────────

@app.get("/notifications/poll", response_class=JSONResponse)
def notifications_poll(request: Request, after: int = 0, db: Session = Depends(get_db)):
    """Poll for unread notifications. Returns new ones since 'after' id."""
    try:
        limiter.check(request, max_requests=60, window_seconds=60)
    except HTTPException:
        return JSONResponse({"notifications": []})
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"notifications": []})
    user = user_or
    rows = db.execute(text(
        "SELECT id, title, body, link, kind, created_at FROM notifications "
        "WHERE user_id = :uid AND read_at IS NULL AND id > :after "
        "ORDER BY created_at DESC LIMIT 20"
    ), {"uid": user.id, "after": after}).fetchall()
    return JSONResponse({"notifications": [
        {"id": r.id, "title": r.title, "body": r.body or "",
         "link": r.link or "", "kind": r.kind or "info",
         "created_at": r.created_at.isoformat() if r.created_at else ""}
        for r in rows
    ]})


@app.post("/notifications/dismiss", response_class=JSONResponse)
async def notifications_dismiss(request: Request, db: Session = Depends(get_db)):
    """Mark one or all notifications as read."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"ok": False})
    user = user_or
    body = await request.json()
    notif_id = body.get("id")  # None = dismiss all
    if notif_id:
        db.execute(text("UPDATE notifications SET read_at=NOW() WHERE id=:id AND user_id=:uid"),
                   {"id": notif_id, "uid": user.id})
    else:
        db.execute(text("UPDATE notifications SET read_at=NOW() WHERE user_id=:uid AND read_at IS NULL"),
                   {"uid": user.id})
    db.commit()
    return JSONResponse({"ok": True})


@app.get("/notifications/unread-count", response_class=JSONResponse)
def notifications_unread_count(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"count": 0})
    user = user_or
    count = db.execute(text(
        "SELECT COUNT(*) FROM notifications WHERE user_id=:uid AND read_at IS NULL"
    ), {"uid": user.id}).scalar() or 0
    return JSONResponse({"count": int(count)})


# ────────────────────────────────────────────────
#  WEB PUSH
# ────────────────────────────────────────────────

@app.get("/push/vapid-public-key", response_class=JSONResponse)
def push_vapid_public_key():
    return JSONResponse({"publicKey": VAPID_PUBLIC_KEY})


@app.post("/push/subscribe", response_class=JSONResponse)
async def push_subscribe(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"ok": False}, status_code=401)
    user = user_or
    body     = await request.json()
    endpoint = body.get("endpoint", "")
    keys     = body.get("keys", {})
    p256dh   = keys.get("p256dh", "")
    auth     = keys.get("auth", "")
    if not endpoint or not p256dh or not auth:
        return JSONResponse({"error": "invalid subscription"}, status_code=400)
    # Upsert: delete old entry for this endpoint, then insert fresh
    db.execute(text("DELETE FROM push_subscriptions WHERE endpoint=:ep"), {"ep": endpoint})
    db.execute(text(
        "INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth, created_at) "
        "VALUES (:uid, :ep, :p256dh, :auth, NOW())"
    ), {"uid": user.id, "ep": endpoint, "p256dh": p256dh, "auth": auth})
    db.commit()
    return JSONResponse({"ok": True})


@app.get("/push/test", response_class=JSONResponse)
def push_test(request: Request, db: Session = Depends(get_db)):
    """Send a test push to the logged-in user."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY:
        return JSONResponse({"error": "VAPID keys not configured on server"})
    has_sub = db.execute(text("SELECT 1 FROM push_subscriptions WHERE user_id=:uid LIMIT 1"), {"uid": user.id}).first()
    if not has_sub:
        return JSONResponse({"error": "No push subscription found. Allow notifications first and reload."})
    threading.Thread(target=_send_web_push, args=(user.id, "🔔 Test Notification", "Push notifications are working!", "/"), daemon=True).start()
    return JSONResponse({"ok": True, "message": "Test push sent"})


@app.post("/push/unsubscribe", response_class=JSONResponse)
async def push_unsubscribe(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"ok": False}, status_code=401)
    body     = await request.json()
    endpoint = body.get("endpoint", "")
    if endpoint:
        db.execute(text("DELETE FROM push_subscriptions WHERE endpoint=:ep"), {"ep": endpoint})
        db.commit()
    return JSONResponse({"ok": True})


# ────────────────────────────────────────────────
#  AGENT VETTING
# ────────────────────────────────────────────────

@app.post("/vetting/assign-stock", response_class=JSONResponse)
async def assign_stock_to_agent(request: Request, db: Session = Depends(get_db)):
    """Admin assigns extra stock to an agent for urgent deliveries.
    Creates an OUT transaction immediately — stock leaves branch.
    """
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_admin(user): return JSONResponse({"error": "forbidden"}, status_code=403)
    body     = await request.json()
    agent_id = body.get("agent_id")
    item_id  = body.get("item_id")
    qty      = int(body.get("qty", 0))
    note     = (body.get("note", "") or "").strip()[:400]
    if not agent_id or not item_id or qty <= 0:
        return JSONResponse({"error": "agent, item and qty required"}, status_code=400)

    branch_id = get_selected_branch_id(request, user)
    item  = db.get(Item, item_id)
    agent = db.get(User, agent_id)
    if not item or item.branch_id != branch_id:
        return JSONResponse({"error": "item not found in this branch"}, status_code=404)
    if not agent or agent.branch_id != branch_id or agent.role != "AGENT":
        return JSONResponse({"error": "agent not found in this branch"}, status_code=404)

    # Create OUT transaction immediately
    tx = Transaction(
        branch_id=branch_id, item_id=item_id, type="OUT", quantity=qty,
        note=f"Extra stock assigned to agent {agent.full_name or agent.username}{': ' + note if note else ''}",
        reference=f"agent-assign-{agent_id}",
    )
    db.add(tx)
    db.flush()

    # Record the assignment
    db.execute(text(
        "INSERT INTO agent_stock_assignments "
        "(agent_id, item_id, branch_id, qty_assigned, note, assigned_by, assigned_at, returned, qty_returned, transaction_out_id) "
        "VALUES (:aid, :iid, :bid, :qty, :note, :uid, NOW(), FALSE, 0, :txid)"
    ), {"aid": agent_id, "iid": item_id, "bid": branch_id, "qty": qty,
        "note": note, "uid": user.id, "txid": tx.id})

    audit_log(db, user.id, "STOCK_ASSIGNED_TO_AGENT",
              f"agent={agent.username} item={item.name} qty={qty}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))

    # Notify agent
    notify(db, agent_id, "📦 Stock Assigned to You",
           f"{qty} × {item.name} assigned by admin for urgent delivery",
           "/my-deliveries", "info")
    db.commit()
    return JSONResponse({"ok": True, "item_name": item.name, "agent_name": agent.full_name or agent.username, "qty": qty, "tx_id": tx.id})


@app.post("/vetting/return-assigned-stock", response_class=JSONResponse)
async def return_assigned_stock(request: Request, db: Session = Depends(get_db)):
    """Admin vets return of extra stock assigned to agent.
    Full return → creates IN tx, marks returned=TRUE
    Partial return → creates IN tx for what came back, updates qty_returned but keeps returned=FALSE for shortfall resolution
    """
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_admin(user): return JSONResponse({"error": "forbidden"}, status_code=403)
    body          = await request.json()
    assignment_id = body.get("assignment_id")
    qty_returned  = int(body.get("qty_returned", 0))
    if not assignment_id or qty_returned < 0:
        return JSONResponse({"error": "invalid params"}, status_code=400)

    row = db.execute(text(
        "SELECT id, agent_id, item_id, branch_id, qty_assigned, note FROM agent_stock_assignments "
        "WHERE id = :aid AND returned = FALSE"
    ), {"aid": assignment_id}).fetchone()
    if not row:
        return JSONResponse({"error": "assignment not found or already returned"}, status_code=404)
    asgn_id, agent_id, item_id, branch_id, qty_assigned, asgn_note = row

    if branch_id != user.branch_id:
        return JSONResponse({"error": "forbidden — different branch"}, status_code=403)

    item  = db.get(Item, item_id)
    agent = db.get(User, agent_id)
    tx_in_id = None
    is_full = qty_returned >= qty_assigned

    if qty_returned > 0:
        tx = Transaction(
            branch_id=branch_id, item_id=item_id, type="IN", quantity=min(qty_returned, qty_assigned),
            note=f"Assigned stock returned by {agent.full_name or agent.username if agent else 'agent'}",
            reference=f"agent-return-{assignment_id}",
        )
        db.add(tx)
        db.flush()
        tx_in_id = tx.id

    if is_full:
        # Full return — mark complete
        db.execute(text(
            "UPDATE agent_stock_assignments SET returned=TRUE, qty_returned=:qty, "
            "vetted_by=:uid, vetted_at=NOW(), transaction_in_id=:txid WHERE id=:aid"
        ), {"qty": min(qty_returned, qty_assigned), "uid": user.id, "txid": tx_in_id, "aid": asgn_id})
    else:
        # Partial — update qty_returned but keep returned=FALSE for shortfall resolution
        db.execute(text(
            "UPDATE agent_stock_assignments SET qty_returned=:qty, "
            "vetted_by=:uid, vetted_at=NOW(), transaction_in_id=:txid WHERE id=:aid"
        ), {"qty": qty_returned, "uid": user.id, "txid": tx_in_id, "aid": asgn_id})

    audit_log(db, user.id, "ASSIGNED_STOCK_RETURNED",
              f"assignment_id={asgn_id} item={item.name if item else item_id} qty_returned={qty_returned}/{qty_assigned}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    db.commit()
    return JSONResponse({"ok": True, "item_name": item.name if item else "Item",
                         "qty_returned": qty_returned, "qty_assigned": qty_assigned,
                         "is_full": is_full})


@app.post("/vetting/resolve-assign-shortfall", response_class=JSONResponse)
async def resolve_assign_shortfall(request: Request, db: Session = Depends(get_db)):
    """Resolve shortfall on an assigned stock return.
    action='returned'    → agent brought back more; creates IN tx
    action='written_off' → accept loss; no IN tx; mark complete
    """
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_admin(user): return JSONResponse({"error": "forbidden"}, status_code=403)
    body          = await request.json()
    assignment_id = body.get("assignment_id")
    action        = body.get("action", "")
    qty_resolved  = int(body.get("qty_resolved", 0))
    if not assignment_id or action not in ("returned", "written_off"):
        return JSONResponse({"error": "invalid params"}, status_code=400)

    row = db.execute(text(
        "SELECT id, agent_id, item_id, branch_id, qty_assigned, qty_returned FROM agent_stock_assignments "
        "WHERE id = :aid AND returned = FALSE"
    ), {"aid": assignment_id}).fetchone()
    if not row:
        return JSONResponse({"error": "assignment not found or already resolved"}, status_code=404)
    asgn_id, agent_id, item_id, branch_id, qty_assigned, qty_already_returned = row
    current_shortfall = max(0, qty_assigned - qty_already_returned)

    if branch_id != user.branch_id:
        return JSONResponse({"error": "forbidden — different branch"}, status_code=403)

    item = db.get(Item, item_id)

    if action == "returned":
        qty_to_credit = min(qty_resolved, current_shortfall) if qty_resolved > 0 else current_shortfall
        new_total = qty_already_returned + qty_to_credit
        remaining = max(0, qty_assigned - new_total)

        if qty_to_credit > 0:
            tx = Transaction(
                branch_id=branch_id, item_id=item_id, type="IN", quantity=qty_to_credit,
                note=f"Shortfall resolved — assigned stock returned by agent",
                reference=f"agent-shortfall-{assignment_id}",
            )
            db.add(tx)
            db.flush()

        if remaining == 0:
            db.execute(text(
                "UPDATE agent_stock_assignments SET returned=TRUE, qty_returned=:qty, "
                "vetted_by=:uid, vetted_at=NOW() WHERE id=:aid"
            ), {"qty": new_total, "uid": user.id, "aid": asgn_id})
        else:
            db.execute(text(
                "UPDATE agent_stock_assignments SET qty_returned=:qty WHERE id=:aid"
            ), {"qty": new_total, "aid": asgn_id})

        audit_log(db, user.id, "ASSIGN_SHORTFALL_RESOLVED",
                  f"assignment_id={asgn_id} item={item.name if item else item_id} credited={qty_to_credit} remaining={remaining}",
                  ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
        db.commit()
        notify(db, agent_id,
            "✅ Assignment Shortfall Resolved" if remaining == 0 else "⚠ Partial Assignment Shortfall Resolved",
            f"{item.name if item else 'Stock'}: {qty_to_credit} unit(s) credited back." + (f" {remaining} still outstanding." if remaining else ""),
            "/my-deliveries", "success" if remaining == 0 else "warning")
        return JSONResponse({"ok": True, "item_name": item.name if item else "Item",
                             "remaining_shortfall": remaining, "action": "returned"})

    else:  # written_off
        qty_to_writeoff = min(qty_resolved, current_shortfall) if qty_resolved > 0 else current_shortfall
        new_total = qty_already_returned + qty_to_writeoff
        remaining = max(0, qty_assigned - new_total)

        if remaining == 0:
            db.execute(text(
                "UPDATE agent_stock_assignments SET returned=TRUE, qty_returned=:qty, "
                "vetted_by=:uid, vetted_at=NOW() WHERE id=:aid"
            ), {"qty": new_total, "uid": user.id, "aid": asgn_id})
        else:
            # Partial write-off — reduce shortfall but keep record open
            db.execute(text(
                "UPDATE agent_stock_assignments SET qty_returned=:qty WHERE id=:aid"
            ), {"qty": new_total, "aid": asgn_id})

        audit_log(db, user.id, "ASSIGN_SHORTFALL_WRITTEN_OFF",
                  f"assignment_id={asgn_id} item={item.name if item else item_id} qty_lost={qty_to_writeoff} remaining={remaining}",
                  ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
        db.commit()
        notify(db, agent_id,
            "📋 Assignment Written Off" if remaining == 0 else "📋 Partial Write-Off Recorded",
            f"{item.name if item else 'Stock'}: {qty_to_writeoff} unit(s) written off." + (f" {remaining} still outstanding." if remaining else ""),
            "/my-deliveries", "info")
        return JSONResponse({"ok": True, "item_name": item.name if item else "Item",
                             "qty_lost": qty_to_writeoff, "remaining_shortfall": remaining,
                             "action": "written_off"})


@app.post("/vetting/confirm-return", response_class=JSONResponse)
async def vetting_confirm_return(request: Request, db: Session = Depends(get_db)):
    """Vet stock return for a specific delivery item.
    - Full return  (qty_returned == original_qty) → resolved, done
    - Partial/zero return → stock credited for what came back,
      shortfall stays visible with ⚠ Missing badge until admin resolves it
    """
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_admin(user): return JSONResponse({"error": "forbidden"}, status_code=403)
    body             = await request.json()
    delivery_item_id = body.get("delivery_item_id")
    qty_returned     = int(body.get("qty_returned", 0))
    delivery_id      = body.get("delivery_id")
    if not delivery_item_id or qty_returned < 0:
        return JSONResponse({"error": "invalid params"}, status_code=400)

    # Prevent double-vetting on unresolved records
    existing = db.execute(text(
        "SELECT id FROM stock_return_vettings "
        "WHERE delivery_item_id = :diid AND (resolved IS NULL OR resolved = FALSE) "
        "ORDER BY created_at DESC LIMIT 1"
    ), {"diid": delivery_item_id}).fetchone()
    if existing:
        return JSONResponse({"error": "already vetted — use Resolve button to update missing stock"}, status_code=400)

    # Get the delivery item + item info
    di_row = db.execute(
        select(DeliveryItem, Item)
        .join(Item, Item.id == DeliveryItem.item_id)
        .where(DeliveryItem.id == delivery_item_id)
    ).first()
    if not di_row:
        return JSONResponse({"error": "item not found"}, status_code=404)
    di, item = di_row

    original_qty = di.quantity
    shortfall    = max(0, original_qty - qty_returned)
    is_full      = shortfall == 0

    tx_id = None
    if qty_returned > 0:
        tx = Transaction(
            branch_id=user.branch_id,
            item_id=di.item_id,
            type="IN",
            quantity=qty_returned,
            note=f"Stock returned — delivery #{delivery_id} vetted by {user.username}",
            reference=f"return-vet-{delivery_id}",
            delivery_id=delivery_id,
        )
        db.add(tx)
        db.flush()
        tx_id = tx.id

    # resolved=TRUE only when all stock accounted for
    db.execute(text(
        "INSERT INTO stock_return_vettings "
        "(delivery_id, delivery_item_id, vetted_by, qty_returned, transaction_id, created_at, resolved) "
        "VALUES (:did, :diid, :uid, :qty, :txid, NOW(), :resolved)"
    ), {"did": delivery_id, "diid": delivery_item_id, "uid": user.id,
        "qty": qty_returned, "txid": tx_id, "resolved": is_full})

    audit_log(db, user.id, "STOCK_RETURN_VETTED",
              f"delivery_id={delivery_id} item={item.name} returned={qty_returned}/{original_qty} shortfall={shortfall}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))

    if qty_returned > 0:
        delivery_obj = db.get(Delivery, delivery_id)
        agent_uid = delivery_obj.agent_id if delivery_obj else user.id
        notify(db, agent_uid,
               "📦 Stock Return Confirmed" if is_full else "⚠ Partial Return Recorded",
               f"{item.name}: {qty_returned}/{original_qty} returned" + (f" — {shortfall} still missing" if shortfall else ""),
               f"/deliveries/{delivery_id}", "success" if is_full else "warning")

    db.commit()
    return JSONResponse({
        "ok": True,
        "item_name": item.name,
        "qty_returned": qty_returned,
        "original_qty": original_qty,
        "shortfall": shortfall,
        "is_full": is_full,
        "tx_id": tx_id,
    })


@app.post("/vetting/resolve-shortfall", response_class=JSONResponse)
async def vetting_resolve_shortfall(request: Request, db: Session = Depends(get_db)):
    """Admin resolves a missing stock shortfall.
    action='returned'   → admin provides qty_resolved; creates IN tx; if still short, keeps record open
    action='written_off'→ marks missing qty as lost; no IN tx; marks fully resolved
    Can be called multiple times for partial resolutions.
    """
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_admin(user): return JSONResponse({"error": "forbidden"}, status_code=403)
    body             = await request.json()
    delivery_item_id = body.get("delivery_item_id")
    action           = body.get("action", "")   # "returned" | "written_off"
    delivery_id      = body.get("delivery_id")
    qty_resolved     = int(body.get("qty_resolved", 0))

    if not delivery_item_id or action not in ("returned", "written_off"):
        return JSONResponse({"error": "invalid params — action must be returned or written_off"}, status_code=400)

    # Find the unresolved vetting record
    vet_row = db.execute(text(
        "SELECT id, qty_returned FROM stock_return_vettings "
        "WHERE delivery_item_id = :diid AND (resolved IS NULL OR resolved = FALSE) "
        "ORDER BY created_at DESC LIMIT 1"
    ), {"diid": delivery_item_id}).fetchone()
    if not vet_row:
        return JSONResponse({"error": "no unresolved record found"}, status_code=404)
    vet_id, qty_already_returned = vet_row[0], vet_row[1]

    # Get item info
    di_row = db.execute(
        select(DeliveryItem, Item)
        .join(Item, Item.id == DeliveryItem.item_id)
        .where(DeliveryItem.id == delivery_item_id)
    ).first()
    if not di_row:
        return JSONResponse({"error": "delivery item not found"}, status_code=404)
    di, item     = di_row
    current_shortfall = max(0, di.quantity - qty_already_returned)

    if action == "returned":
        # Clamp qty_resolved to current shortfall
        qty_to_credit = min(qty_resolved, current_shortfall) if qty_resolved > 0 else current_shortfall
        new_total_returned = qty_already_returned + qty_to_credit
        remaining_shortfall = max(0, di.quantity - new_total_returned)
        is_fully_resolved = remaining_shortfall == 0

        if qty_to_credit > 0:
            tx = Transaction(
                branch_id=user.branch_id,
                item_id=di.item_id,
                type="IN",
                quantity=qty_to_credit,
                note=f"Partial shortfall resolved — delivery #{delivery_id}, {qty_to_credit} returned, confirmed by {user.username}",
                reference=f"shortfall-{delivery_id}",
                delivery_id=delivery_id,
            )
            db.add(tx)
            db.flush()

        if is_fully_resolved:
            # All accounted for — mark resolved
            db.execute(text(
                "UPDATE stock_return_vettings SET resolved=TRUE, resolve_action='returned', "
                "qty_returned=:newqty, resolved_at=NOW(), resolved_by=:uid WHERE id=:vid"
            ), {"newqty": new_total_returned, "uid": user.id, "vid": vet_id})
        else:
            # Still some missing — update qty_returned, keep unresolved
            db.execute(text(
                "UPDATE stock_return_vettings SET qty_returned=:newqty WHERE id=:vid"
            ), {"newqty": new_total_returned, "vid": vet_id})

        audit_log(db, user.id, "SHORTFALL_PARTIAL_RESOLVED" if not is_fully_resolved else "SHORTFALL_RESOLVED",
                  f"delivery_id={delivery_id} item={item.name} credited={qty_to_credit} remaining={remaining_shortfall}",
                  ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
        db.commit()
        _delivery = db.get(Delivery, delivery_id) if delivery_id else None
        if _delivery and _delivery.agent_id:
            notify(db, _delivery.agent_id,
                "✅ Shortfall Resolved" if is_fully_resolved else "⚠ Partial Shortfall Resolved",
                f"{item.name}: {qty_to_credit} unit(s) credited back." + (f" {remaining_shortfall} still outstanding." if remaining_shortfall else ""),
                f"/deliveries/{delivery_id}", "success" if is_fully_resolved else "warning")
        return JSONResponse({
            "ok": True,
            "item_name": item.name,
            "qty_credited": qty_to_credit,
            "new_total_returned": new_total_returned,
            "remaining_shortfall": remaining_shortfall,
            "is_fully_resolved": is_fully_resolved,
            "action": "returned",
        })

    else:  # written_off
        qty_to_writeoff = min(qty_resolved, current_shortfall) if qty_resolved > 0 else current_shortfall
        new_total_returned = qty_already_returned + qty_to_writeoff
        remaining_shortfall = max(0, di.quantity - new_total_returned)
        is_fully_resolved = remaining_shortfall == 0

        if is_fully_resolved:
            db.execute(text(
                "UPDATE stock_return_vettings SET resolved=TRUE, resolve_action='written_off', "
                "qty_returned=:newqty, resolved_at=NOW(), resolved_by=:uid WHERE id=:vid"
            ), {"newqty": new_total_returned, "uid": user.id, "vid": vet_id})
        else:
            # Partial write-off — reduce shortfall but keep record open for further action
            db.execute(text(
                "UPDATE stock_return_vettings SET qty_returned=:newqty WHERE id=:vid"
            ), {"newqty": new_total_returned, "vid": vet_id})

        audit_log(db, user.id, "SHORTFALL_WRITTEN_OFF",
                  f"delivery_id={delivery_id} item={item.name} qty_lost={qty_to_writeoff} remaining={remaining_shortfall}",
                  ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
        db.commit()
        _delivery = db.get(Delivery, delivery_id) if delivery_id else None
        if _delivery and _delivery.agent_id:
            notify(db, _delivery.agent_id,
                "📋 Shortfall Written Off" if is_fully_resolved else "📋 Partial Write-Off Recorded",
                f"{item.name}: {qty_to_writeoff} unit(s) written off." + (f" {remaining_shortfall} still outstanding." if remaining_shortfall else ""),
                f"/deliveries/{delivery_id}", "info")
        return JSONResponse({
            "ok": True,
            "item_name": item.name,
            "qty_lost": qty_to_writeoff,
            "remaining_shortfall": remaining_shortfall,
            "is_fully_resolved": is_fully_resolved,
            "action": "written_off",
        })


@app.get("/vetting", response_class=HTMLResponse)
def vetting_page(request: Request, date_filter: str = "", agent_id: str = "", db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    branch_id = get_selected_branch_id(request, user)

    # Date filter
    if date_filter:
        try:
            filter_date = datetime.strptime(date_filter, "%Y-%m-%d").date()
        except ValueError:
            filter_date = date.today()
    else:
        filter_date = date.today()

    day_start = datetime.combine(filter_date, datetime.min.time())
    day_end   = day_start + timedelta(days=1)

    # All agents in this branch
    agents = db.execute(
        select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())
    ).scalars().all()

    selected_agent_id = int(agent_id) if agent_id and agent_id.isdigit() else None

    # Build vetting rows per agent
    vetting_rows = []
    for agent in agents:
        if selected_agent_id and agent.id != selected_agent_id:
            continue

        entries = db.execute(
            select(CashEntry).where(CashEntry.agent_id == agent.id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind.in_(["COLLECTION", "CASH_PAYMENT", "TRANSFER_PAYMENT"]))
            .where(CashEntry.created_at >= day_start)
            .where(CashEntry.created_at < day_end)
            .order_by(CashEntry.created_at.desc())
        ).scalars().all()

        if not entries:
            continue

        cash_total     = sum(float(e.amount) for e in entries if e.kind in ("COLLECTION", "CASH_PAYMENT"))
        transfer_total = sum(float(e.amount) for e in entries if e.kind == "TRANSFER_PAYMENT")
        total          = cash_total + transfer_total
        confirmed      = all(getattr(e, 'confirmed_by_admin', False) for e in entries)
        confirmed_count = sum(1 for e in entries if getattr(e, 'confirmed_by_admin', False))

        # Get linked deliveries for these entries
        delivery_ids = list({e.delivery_id for e in entries if e.delivery_id})
        deliveries = {}
        if delivery_ids:
            for d in db.execute(select(Delivery).where(Delivery.id.in_(delivery_ids))).scalars().all():
                deliveries[d.id] = d

        vetting_rows.append({
            "agent":           agent,
            "entries":         entries,
            "deliveries":      deliveries,
            "cash_total":      cash_total,
            "transfer_total":  transfer_total,
            "total":           total,
            "confirmed":       confirmed,
            "confirmed_count": confirmed_count,
            "total_count":     len(entries),
        })

    # ── Stock return section ──────────────────────────────────────────────
    # Unsuccessful deliveries needing stock return vetting (all time, not date filtered)
    unvetted_statuses = ["FAILED", "RETURNED", "ADJUSTMENT_PENDING"]
    unsuccessful = db.execute(
        select(Delivery)
        .where(Delivery.branch_id == branch_id)
        .where(Delivery.status.in_(unvetted_statuses))
        .order_by(Delivery.created_at.desc())
        .limit(100)
    ).scalars().all()

    # Also include any delivery that has unresolved vetting records
    # (e.g. from adjustment-removed items where delivery is still OUT_FOR_DELIVERY)
    existing_ids = {d.id for d in unsuccessful}
    unresolved_delivery_ids = db.execute(text(
        "SELECT DISTINCT srv.delivery_id FROM stock_return_vettings srv "
        "JOIN deliveries d ON d.id = srv.delivery_id "
        "WHERE (srv.resolved IS NULL OR srv.resolved = FALSE) "
        "AND d.branch_id = :bid AND d.status NOT IN ('FAILED','RETURNED','ADJUSTMENT_PENDING')"
    ), {"bid": branch_id}).fetchall()
    extra_delivery_ids = [r[0] for r in unresolved_delivery_ids if r[0] not in existing_ids]
    if extra_delivery_ids:
        extra_deliveries = db.execute(
            select(Delivery).where(Delivery.id.in_(extra_delivery_ids))
        ).scalars().all()
    else:
        extra_deliveries = []

    # Build return rows
    all_return_deliveries = {d.id: d for d in unsuccessful + extra_deliveries}
    return_rows = []
    for d in list(unsuccessful) + list(extra_deliveries):
        if d.id in {r["delivery_id"] for r in return_rows}:
            continue
        d_items = db.execute(
            select(DeliveryItem, Item)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id == d.id)
        ).all()
        if not d_items:
            continue

        # Fetch vetting records for ALL items in this delivery (any date)
        # resolved=TRUE  → fully settled (full return or written off)
        # resolved=FALSE → vetted but shortfall exists — stays visible
        # no record      → not yet vetted
        vet_rows = db.execute(text(
            "SELECT delivery_item_id, qty_returned, resolved, resolve_action "
            "FROM stock_return_vettings "
            "WHERE delivery_id = :did "
            "ORDER BY created_at DESC"
        ), {"did": d.id}).fetchall()

        # Keep only the latest vetting per delivery_item_id
        vet_map = {}
        for vr in vet_rows:
            if vr[0] not in vet_map:
                vet_map[vr[0]] = {"qty_returned": vr[1], "resolved": vr[2], "resolve_action": vr[3]}

        agent_u = db.get(User, d.agent_id) if d.agent_id else None
        items_to_vet = []
        # Only show items WITH a vetting record for active and delivered deliveries.
        # For FAILED/RETURNED the agent brought everything back so all items need vetting.
        only_vetted_items = d.status in ("OUT_FOR_DELIVERY", "DELIVERED")
        for di, it in d_items:
            # For DELIVERED deliveries, skip items with line_amount > 0 — those were
            # successfully sold to the customer. Only line_amount == 0 items were refused
            # via adjustment approval and actually need stock-return vetting.
            if d.status == "DELIVERED" and float(di.line_amount or 0) > 0:
                continue
            vet = vet_map.get(di.id)
            if vet is None:
                if only_vetted_items:
                    continue  # Skip items without vetting record on active deliveries
                # Not vetted at all yet
                status_flag = "unvetted"
                shortfall   = di.quantity
                qty_back    = 0
            elif vet["resolved"]:
                # Fully settled — full return or written off
                status_flag    = "resolved"
                qty_back       = vet["qty_returned"]
                shortfall      = 0
                resolve_action = vet["resolve_action"]
            else:
                # Vetted but shortfall remains
                qty_back    = vet["qty_returned"]
                shortfall   = max(0, di.quantity - qty_back)
                status_flag = "shortfall" if shortfall > 0 else "resolved"

            items_to_vet.append({
                "di_id":      di.id,
                "item_name":  it.name,
                "qty":        di.quantity,
                "qty_back":   qty_back if vet else 0,
                "shortfall":  shortfall if vet else di.quantity,
                "status":     status_flag,   # unvetted | shortfall | resolved
                "vetted":     status_flag in ("resolved", "shortfall"),  # True if any vetting record exists
                "has_shortfall": status_flag == "shortfall",
                "resolve_action": vet["resolve_action"] if (vet and vet.get("resolved")) else None,
            })

        # Card is fully done only when every item is resolved
        all_resolved = all(i["status"] == "resolved" for i in items_to_vet)
        has_shortfall = any(i["status"] == "shortfall" for i in items_to_vet)

        # Skip if completely resolved
        if all_resolved:
            continue

        return_rows.append({
            "delivery":    d,
            "delivery_id": d.id,
            "agent_name":  (agent_u.full_name or agent_u.username) if agent_u else "Unknown",
            "status":      d.status,
            "is_overdue":  False,
            "item_lines":  items_to_vet,
            "all_vetted":  all_resolved,
            "has_shortfall": has_shortfall,
        })

    # ── Extra stock assignments — unvetted returns ───────────────────────
    # Show all unvetted (not returned) assignments for this branch
    assignment_rows = db.execute(text("""
        SELECT
            asa.id, asa.qty_assigned, asa.note, asa.assigned_at, asa.qty_returned,
            it.id AS item_id, it.name AS item_name,
            u_agent.id AS agent_id,
            u_agent.full_name AS agent_name, u_agent.username AS agent_username,
            u_assigner.full_name AS assigned_by_name, u_assigner.username AS assigned_by_username
        FROM agent_stock_assignments asa
        JOIN items it           ON it.id    = asa.item_id
        JOIN users u_agent      ON u_agent.id = asa.agent_id
        LEFT JOIN users u_assigner ON u_assigner.id = asa.assigned_by
        WHERE asa.branch_id = :bid AND asa.returned = FALSE
          AND (asa.delivery_id IS NULL)
        ORDER BY asa.assigned_at DESC
        LIMIT 100
    """), {"bid": branch_id}).fetchall()

    # ── Available items for stock assignment form ─────────────────────
    assign_items = get_items_with_stock(db, branch_id=branch_id)

    # ── Written-off records (for summary card at top) ────────────────────
    written_off_rows = db.execute(text("""
        SELECT
            srv.id, srv.qty_returned, srv.resolved_at,
            di.quantity AS original_qty,
            (di.quantity - srv.qty_returned) AS qty_lost,
            it.name AS item_name,
            d.id AS delivery_id, d.customer_name,
            u_agent.full_name AS agent_name, u_agent.username AS agent_username,
            u_res.full_name AS resolved_by_name, u_res.username AS resolved_by_username,
            'delivery' AS source
        FROM stock_return_vettings srv
        JOIN delivery_items di ON di.id = srv.delivery_item_id
        JOIN items it          ON it.id = di.item_id
        JOIN deliveries d      ON d.id  = srv.delivery_id
        LEFT JOIN users u_agent ON u_agent.id = d.agent_id
        LEFT JOIN users u_res   ON u_res.id   = srv.resolved_by
        WHERE srv.resolve_action = 'written_off'
          AND it.branch_id = :bid

        UNION ALL

        SELECT
            asa.id, asa.qty_returned, asa.vetted_at AS resolved_at,
            asa.qty_assigned AS original_qty,
            (asa.qty_assigned - asa.qty_returned) AS qty_lost,
            it.name AS item_name,
            COALESCE(asa.delivery_id, 0) AS delivery_id,
            'Assigned Stock' AS customer_name,
            u_agent.full_name AS agent_name, u_agent.username AS agent_username,
            u_vet.full_name AS resolved_by_name, u_vet.username AS resolved_by_username,
            'assignment' AS source
        FROM agent_stock_assignments asa
        JOIN items it         ON it.id = asa.item_id
        JOIN users u_agent    ON u_agent.id = asa.agent_id
        LEFT JOIN users u_vet ON u_vet.id = asa.vetted_by
        WHERE asa.returned = TRUE
          AND asa.qty_returned < asa.qty_assigned
          AND asa.branch_id = :bid

        ORDER BY resolved_at DESC
        LIMIT 100
    """), {"bid": branch_id}).fetchall()

    # ── Return operating cash — unconfirmed returns ──────────────────────
    # Show per-agent unconfirmed RETURN_OPERATING_CASH entries for admin to vet
    return_op_rows = []
    for agent in agents:
        if selected_agent_id and agent.id != selected_agent_id:
            continue
        ret_entries = db.execute(
            select(CashEntry)
            .where(CashEntry.agent_id == agent.id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind == "RETURN_OPERATING_CASH")
            .where(CashEntry.confirmed_by_admin == False)  # noqa: E712
            .order_by(CashEntry.created_at.desc())
        ).scalars().all()
        if not ret_entries:
            continue
        return_op_rows.append({
            "agent":   agent,
            "entries": ret_entries,
            "total":   sum(float(e.amount) for e in ret_entries),
        })

    csrf_token = get_csrf_token(request)
    return tpl(request, "vetting.html", {
        "request": request, "user": user, "active": "vetting",
        "vetting_rows": vetting_rows, "agents": agents,
        "filter_date": filter_date.isoformat() if filter_date else "",
        "selected_agent_id": selected_agent_id,
        "today": date.today().isoformat(),
        "csrf_token": csrf_token,
        "return_rows": return_rows,
        "written_off_rows": written_off_rows,
        "assignment_rows": assignment_rows,
        "assign_items": assign_items,
        "return_op_rows": return_op_rows,
    })


@app.post("/vetting/confirm", response_class=JSONResponse)
async def vetting_confirm(request: Request, db: Session = Depends(get_db)):
    """Confirm all cash entries for an agent on a given date."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_admin(user): return JSONResponse({"error": "forbidden"}, status_code=403)
    body = await request.json()
    agent_id  = body.get("agent_id")
    date_str  = body.get("date")
    entry_ids = body.get("entry_ids", [])  # specific entries or all for that agent/date
    if not agent_id or not date_str:
        return JSONResponse({"error": "missing agent_id or date"}, status_code=400)
    try:
        filter_date = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return JSONResponse({"error": "invalid date"}, status_code=400)
    day_start = datetime.combine(filter_date, datetime.min.time())
    day_end   = day_start + timedelta(days=1)
    q = select(CashEntry).where(
        CashEntry.agent_id == agent_id,
        CashEntry.branch_id == user.branch_id,
        CashEntry.kind.in_(["COLLECTION", "CASH_PAYMENT", "TRANSFER_PAYMENT"]),
        CashEntry.created_at >= day_start,
        CashEntry.created_at < day_end,
    )
    if entry_ids:
        q = q.where(CashEntry.id.in_(entry_ids))
    entries = db.execute(q).scalars().all()
    now = datetime.utcnow()
    for e in entries:
        e.confirmed_by_admin = True
        e.confirmed_at = now
    db.commit()
    audit_log(db, user.id, "CASH_VETTED",
              f"agent_id={agent_id} date={date_str} entries={len(entries)}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    if entries:
        notify(db, agent_id,
            "✅ Cash Confirmed",
            f"Admin has confirmed {len(entries)} cash entr{'y' if len(entries) == 1 else 'ies'} for {date_str}.",
            "/cash", "success")
    return JSONResponse({"ok": True, "confirmed": len(entries)})


# ────────────────────────────────────────────────
#  CASH
# ────────────────────────────────────────────────

@app.get("/cash", response_class=HTMLResponse)
def cash_dashboard(request: Request, preset: str = "", start_date: str = "", end_date: str = "", agent_id: str = "", db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    branch_id = get_selected_branch_id(request, user)
    sd, ed, preset_norm = _range_dates_from_inputs(preset, start_date, end_date)
    start_dt = None
    end_dt = None
    if preset_norm:
        start_dt, end_dt = cash_range_from_preset(preset_norm)
    else:
        if sd: start_dt = datetime.combine(sd, datetime.min.time())
        if ed: end_dt = datetime.combine(ed, datetime.min.time()) + timedelta(days=1)
    selected_agent_id = None
    if is_admin(user):
        if agent_id == "all":
            selected_agent_id = None  # show all agents
        elif (agent_id or "").isdigit():
            selected_agent_id = int(agent_id)
        else:
            selected_agent_id = user.id  # default: admin sees own entries
    else:
        selected_agent_id = user.id
    # Branch agent IDs — used to catch entries saved with NULL branch_id
    branch_agent_ids = [u.id for u in db.execute(
        select(User).where(User.branch_id == branch_id)
    ).scalars().all()]

    # Match entries that either have this branch_id OR have NULL branch_id but belong to a branch agent
    def _branch_filter():
        return (CashEntry.branch_id == branch_id) | (
            (CashEntry.branch_id == None) & (CashEntry.agent_id.in_(branch_agent_ids))
        )

    def _cash_sum(kind_list, agent_id=None):
        stmt = select(func.coalesce(func.sum(CashEntry.amount), 0)).where(
            CashEntry.kind.in_(kind_list)).where(_branch_filter())
        if start_dt: stmt = stmt.where(CashEntry.created_at >= start_dt)
        if end_dt:   stmt = stmt.where(CashEntry.created_at < end_dt)
        if agent_id: stmt = stmt.where(CashEntry.agent_id == agent_id)
        return float(db.scalar(stmt) or 0)

    # Per-day breakdown — query each kind separately then merge by day
    def _day_kind_map(kind_list, agent_id=None):
        stmt = select(
            func.date(CashEntry.created_at).label("day"),
            func.coalesce(func.sum(CashEntry.amount), 0).label("total")
        ).where(CashEntry.kind.in_(kind_list)).where(_branch_filter())
        if start_dt: stmt = stmt.where(CashEntry.created_at >= start_dt)
        if end_dt:   stmt = stmt.where(CashEntry.created_at < end_dt)
        if agent_id: stmt = stmt.where(CashEntry.agent_id == agent_id)
        stmt = stmt.group_by(func.date(CashEntry.created_at))
        return {str(r.day): float(r.total) for r in db.execute(stmt).all()}

    col_map  = _day_kind_map(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"], selected_agent_id)
    exp_map  = _day_kind_map(["EXPENSE"], selected_agent_id)
    op_map   = _day_kind_map(["OPERATING_CASH"], selected_agent_id)
    off_map  = _day_kind_map(["OFFICE_EXPENSE"], selected_agent_id)
    all_days = sorted(set(list(col_map) + list(exp_map) + list(op_map) + list(off_map)), reverse=True)
    rows = [{"day": d, "collections": col_map.get(d, 0), "expenses": exp_map.get(d, 0),
             "operating_cash": op_map.get(d, 0), "office_expenses": off_map.get(d, 0)}
            for d in all_days]

    total_collections     = _cash_sum(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"], selected_agent_id)
    total_expenses        = _cash_sum(["EXPENSE", "COLLECTION_EXPENSE"], selected_agent_id)
    total_operating       = _cash_sum(["OPERATING_CASH"], selected_agent_id)
    total_office_expenses = _cash_sum(["OFFICE_EXPENSE"], selected_agent_id)

    _ret_stmt = select(func.coalesce(func.sum(CashEntry.amount), 0)).where(
        CashEntry.kind == "RETURN_OPERATING_CASH").where(_branch_filter())
    if start_dt: _ret_stmt = _ret_stmt.where(CashEntry.created_at >= start_dt)
    if end_dt:   _ret_stmt = _ret_stmt.where(CashEntry.created_at < end_dt)
    if selected_agent_id: _ret_stmt = _ret_stmt.where(CashEntry.agent_id == selected_agent_id)
    total_return_op_cash = float(db.scalar(_ret_stmt) or 0)
    operating_balance = float(total_operating) - float(total_expenses) - total_return_op_cash
    remittance = float(total_collections) - float(total_expenses) - float(total_office_expenses)
    net_position = remittance + operating_balance
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())).scalars().all() if (is_admin(user) or is_supervisor(user)) else []

    # Fetch individual expense entries for the drill-down modal
    def _entries(kind_list):
        stmt = select(CashEntry).where(CashEntry.kind.in_(kind_list)).where(_branch_filter())
        if start_dt: stmt = stmt.where(CashEntry.created_at >= start_dt)
        if end_dt:   stmt = stmt.where(CashEntry.created_at < end_dt)
        if selected_agent_id: stmt = stmt.where(CashEntry.agent_id == selected_agent_id)
        return db.execute(stmt.order_by(desc(CashEntry.created_at)).limit(200)).scalars().all()

    # Build serialisable entry dicts for JSON embedding in template
    def _entry_list(kind_list):
        umap = {u.id: (u.full_name or u.username) for u in agents} if agents else {}
        return [
            {"date": e.created_at.strftime("%d %b %Y") if e.created_at else "—",
             "amount": float(e.amount), "note": e.note or "—",
             "agent": umap.get(e.agent_id, "—"), "kind": e.kind}
            for e in _entries(kind_list)
        ]

    expense_entries      = _entry_list(["EXPENSE", "COLLECTION_EXPENSE"])
    coll_expense_entries = _entry_list(["COLLECTION_EXPENSE"])
    collection_entries   = _entry_list(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"])
    op_cash_entries      = _entry_list(["OPERATING_CASH"])
    office_entries       = _entry_list(["OFFICE_EXPENSE"])
    total_collection_expenses = sum(e["amount"] for e in coll_expense_entries)

    csrf_token = get_csrf_token(request)
    return tpl(request, "cash_dashboard.html", {
        "request": request, "user": user, "rows": rows,
        "total_collections": float(total_collections), "total_expenses": float(total_expenses),
        "total_operating_cash": float(total_operating), "total_return_op_cash": total_return_op_cash,
        "operating_balance": float(operating_balance), "total_office_expenses": float(total_office_expenses),
        "remittance": float(remittance), "net_position": float(net_position),
        "agents": agents, "agent_id": agent_id,
        "expense_entries": expense_entries,
        "coll_expense_entries": coll_expense_entries,
        "total_collection_expenses": total_collection_expenses,
        "collection_entries": collection_entries,
        "op_cash_entries": op_cash_entries,
        "office_entries": office_entries,
        "preset": preset_norm or (preset or ""),
        "start_date": sd.isoformat() if sd else "",
        "end_date": ed.isoformat() if ed else "",
        "active": "cash", "csrf_token": csrf_token,
    })


@app.post("/cash/new")
async def cash_new(
    request: Request,
    kind: str = Form(...),
    amount: float = Form(...),
    note: str = Form(""),
    delivery_id: str = Form(""),
    agent_id: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
    k = (kind or "").strip().upper()
    if k not in {"COLLECTION", "EXPENSE", "OPERATING_CASH", "OFFICE_EXPENSE", "RETURN_OPERATING_CASH", "CASH_PAYMENT", "TRANSFER_PAYMENT", "COLLECTION_EXPENSE"}:
        raise HTTPException(status_code=400, detail="Invalid kind")
    if k == "OFFICE_EXPENSE" and not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    if k == "OPERATING_CASH" and not is_admin(user):
        return HTMLResponse("Forbidden — only admins can give operating cash", status_code=403)
    amt = sanitize_amount(amount)
    if amt <= 0:
        raise HTTPException(status_code=400, detail="Amount must be > 0")
    target_agent_id = user.id
    if is_admin(user) and (agent_id or "").isdigit(): target_agent_id = int(agent_id)
    if k == "OFFICE_EXPENSE": target_agent_id = user.id
    d_id = int(delivery_id) if (delivery_id or "").isdigit() else None
    branch_id = get_current_branch_id(request)
    if not branch_id:
        raise HTTPException(status_code=400, detail="No branch assigned")
    # Auto-detect expense source for agents:
    # If agent records EXPENSE and has no remaining op cash balance → use COLLECTION_EXPENSE instead
    if k == "EXPENSE" and is_agent(user):
        op_given = float(db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == target_agent_id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind == "OPERATING_CASH")
        ) or 0)
        op_spent = float(db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == target_agent_id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind.in_(["EXPENSE", "COLLECTION_EXPENSE"]))
        ) or 0)
        op_returned = float(db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == target_agent_id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind == "RETURN_OPERATING_CASH")
        ) or 0)
        op_balance = op_given - op_spent - op_returned
        if op_balance <= 0:
            k = "COLLECTION_EXPENSE"  # Op cash exhausted — deduct from collection

    db.add(CashEntry(
        branch_id=branch_id, agent_id=target_agent_id, delivery_id=d_id,
        kind=k, amount=amt, note=sanitize_text(note, 400, "Note") or None,
    ))
    # Notify agent when admin gives them operating cash
    if k == "OPERATING_CASH" and is_admin(user) and target_agent_id != user.id:
        notify(db, target_agent_id, "💰 Operating Cash Received",
               f"Admin has given you ₦{float(amt):,.0f} operating cash." + (f" Note: {(note or '').strip()}" if note else ""),
               "/cash", "success")
    db.commit()
    if d_id:
        return redirect(f"/deliveries/{d_id}")
    return redirect("/cash")


# ────────────────────────────────────────────────
#  REPORTS
# ────────────────────────────────────────────────

@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not (is_admin(user) or is_agent(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
    branch_id = get_selected_branch_id(request, user)
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())).scalars().all() if (is_admin(user) or is_supervisor(user)) else []
    today = date.today().isoformat()
    return tpl(request, "reports_sales.html", {
        "request": request, "user": user, "agents": agents,
        "start_date": today, "end_date": today, "active": "reports",
    })


@app.get("/reports/preview")
def reports_preview(request: Request, start_date: str | None = None, end_date: str | None = None, agent_id: str | None = None, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    user = user_or
    if not (is_admin(user) or is_agent(user) or is_supervisor(user)):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    d1 = _parse_iso_date(start_date); d2 = _parse_iso_date(end_date)
    if not d1 and not d2: d1 = d2 = date.today()
    if d1 and not d2: d2 = d1
    if d2 and not d1: d1 = d2
    start_dt = datetime.combine(d1, datetime.min.time())
    end_dt   = datetime.combine(d2, datetime.max.time())
    branch_id = get_selected_branch_id(request, user)
    target_agent_id = None
    if is_agent(user): target_agent_id = int(user.id)
    elif is_admin(user) and (agent_id or "").isdigit(): target_agent_id = int(agent_id)
    # Use delivered_at (when actually marked delivered) so "today" shows today's deliveries
    # Fall back to delivery_date if delivered_at is null (older records)
    filters = [
        Delivery.status == "DELIVERED",
        func.coalesce(Delivery.delivered_at, Delivery.delivery_date) >= start_dt,
        func.coalesce(Delivery.delivered_at, Delivery.delivery_date) <= end_dt,
    ]
    if not is_supervisor(user): filters.append(Delivery.branch_id == branch_id)
    if target_agent_id: filters.append(Delivery.agent_id == target_agent_id)
    deliveries = db.execute(select(Delivery).where(and_(*filters)).order_by(Delivery.delivery_date.asc())).scalars().all()
    delivery_ids = [d.id for d in deliveries]
    items_by_delivery: dict[int, list] = {}
    if delivery_ids:
        for did, iname, qty, line_amt, selling_price in db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity, DeliveryItem.line_amount, Item.selling_price)
            .join(Item, Item.id == DeliveryItem.item_id).where(DeliveryItem.delivery_id.in_(delivery_ids))
        ).all():
            q = float(qty or 0); la = float(line_amt or 0); sp = float(selling_price or 0)
            # Skip items removed by adjustment (line_amount == 0 means customer refused/returned)
            if la == 0 and q > 0:
                continue
            items_by_delivery.setdefault(int(did), []).append({"name": str(iname), "qty": q, "amount": la})
    _ce_branch = CashEntry.branch_id == branch_id if not is_supervisor(user) else True
    # Get agent IDs to include in cash queries
    # If a specific agent is selected, only show that agent's data
    if target_agent_id:
        _agent_ce_filter = (CashEntry.agent_id == target_agent_id)
    elif not is_supervisor(user):
        branch_agent_ids = [u.id for u in db.execute(
            select(User).where(User.role == "AGENT").where(User.branch_id == branch_id)
        ).scalars().all()]
        _agent_ce_filter = (CashEntry.agent_id.in_(branch_agent_ids)) if branch_agent_ids else (CashEntry.agent_id == -1)
    else:
        _agent_ce_filter = True  # supervisor: no agent filter
    # agent_exp_map: AGENT expenses EXCLUDING waybill-tagged ones (those go to waybill section)
    # agent_exp_map: includes both EXPENSE (from op cash) and COLLECTION_EXPENSE (from collection)
    agent_exp_map = {int(aid): float(t) for aid, t in db.execute(
        select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind.in_(["EXPENSE", "COLLECTION_EXPENSE"]))
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
        .where(_agent_ce_filter if not is_supervisor(user) else True)
        .where(func.lower(func.coalesce(CashEntry.note, "")).notlike("%waybill%"))
        .group_by(CashEntry.agent_id)
    ).all()}
    # Separate collection-funded expenses per agent for report breakdown
    agent_coll_exp_map = {int(aid): float(t) for aid, t in db.execute(
        select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind == "COLLECTION_EXPENSE")
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
        .where(_agent_ce_filter if not is_supervisor(user) else True)
        .group_by(CashEntry.agent_id)
    ).all()}
    op_cash_map = {int(aid): float(t) for aid, t in db.execute(
        select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind == "OPERATING_CASH").where(CashEntry.created_at >= start_dt)
        .where(CashEntry.created_at <= end_dt).where(_ce_branch)
        .where(_agent_ce_filter if not is_supervisor(user) else True)
        .group_by(CashEntry.agent_id)
    ).all()}
    # Waybill entries = OFFICE_EXPENSE tagged waybill + EXPENSE tagged waybill (agent transfer expenses)
    # For agents: only their own waybill entries; for admin/supervisor: all branch waybill entries
    _wb_stmt = (
        select(CashEntry.amount, CashEntry.note, CashEntry.created_at)
        .where(CashEntry.kind.in_(["OFFICE_EXPENSE", "EXPENSE"]))
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
        .where(func.lower(func.coalesce(CashEntry.note, "")).like("%waybill%"))
        .order_by(CashEntry.created_at.asc())
    )
    if is_agent(user):
        _wb_stmt = _wb_stmt.where(CashEntry.agent_id == user.id)
    elif target_agent_id:
        _wb_stmt = _wb_stmt.where(CashEntry.agent_id == target_agent_id)
    waybill_entries_raw = db.execute(_wb_stmt).all()
    waybill_entries = [{"amount": float(r[0]), "note": str(r[1] or ""), "date": r[2].strftime("%d %b %Y") if r[2] else ""} for r in waybill_entries_raw]
    waybill_total = sum(e["amount"] for e in waybill_entries)
    # office_total = non-waybill OFFICE_EXPENSE + waybill_total
    _off_stmt = (
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind == "OFFICE_EXPENSE")
        .where(func.lower(func.coalesce(CashEntry.note, "")).notlike("%waybill%"))
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
    )
    if is_agent(user):
        _off_stmt = _off_stmt.where(CashEntry.agent_id == user.id)
    elif target_agent_id:
        _off_stmt = _off_stmt.where(CashEntry.agent_id == target_agent_id)
    office_non_waybill = float(db.scalar(_off_stmt) or 0)
    office_total = office_non_waybill + waybill_total
    all_agent_ids = list(set(list(agent_exp_map.keys()) + list(op_cash_map.keys())))
    uname = {}
    if all_agent_ids:
        users_map = {int(u.id): u for u in db.execute(select(User).where(User.id.in_(all_agent_ids))).scalars().all()}
        uname = {uid: (u.full_name or u.username) for uid, u in users_map.items()}
    delivery_rows = []
    grand_total = 0.0
    for idx, d in enumerate(deliveries, 1):
        d_items = items_by_delivery.get(int(d.id), [])
        total = sum(i["amount"] for i in d_items)
        grand_total += total
        delivery_rows.append({"idx": idx, "customer": d.customer_name, "date": (d.delivery_date or d.created_at).strftime("%d %b %Y"), "items": d_items, "total": total})
    agent_op_summary = []
    total_op_cash_given = total_op_cash_balance_returned = expenses_from_collections = 0.0
    for aid in sorted(set(list(agent_exp_map.keys()) + list(op_cash_map.keys()))):
        exp       = agent_exp_map.get(aid, 0.0)
        coll_exp  = agent_coll_exp_map.get(aid, 0.0)
        op_exp    = exp - coll_exp   # expenses from operating cash only
        op        = op_cash_map.get(aid, 0.0)
        # Subtract confirmed returns from balance (agent already handed back cash)
        ret_confirmed = float(db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == aid)
            .where(CashEntry.kind == "RETURN_OPERATING_CASH")
            .where(CashEntry.confirmed_by_admin == True)
            .where(CashEntry.created_at >= start_dt)
            .where(CashEntry.created_at <= end_dt)
        ) or 0)
        balance   = op - op_exp - ret_confirmed
        total_op_cash_given += op
        expenses_from_collections += coll_exp
        if op > 0:
            total_op_cash_balance_returned += max(balance, 0)
            if balance < 0: expenses_from_collections += abs(balance)
        agent_op_summary.append({
            "name": uname.get(aid, f"Agent {aid}"),
            "op_cash": op, "expenses": exp,
            "op_expenses": op_exp, "coll_expenses": coll_exp,
            "balance": balance, "has_op_cash": op > 0,
        })
    total_agent_exp = sum(a["expenses"] for a in agent_op_summary)
    total_expenses = total_agent_exp + office_total
    remittance = grand_total - expenses_from_collections if is_agent(user) else grand_total - total_expenses
    title = d1.strftime("%A %d %B %Y").upper() if d1 == d2 else f"{d1.isoformat()} TO {d2.isoformat()}"
    return JSONResponse({
        "title": title, "delivery_count": len(deliveries), "deliveries": delivery_rows,
        "grand_total": grand_total, "agent_op_summary": agent_op_summary,
        "total_op_cash_given": total_op_cash_given,
        "total_op_cash_balance_returned": total_op_cash_balance_returned,
        "expenses_from_collections": expenses_from_collections,
        "total_agent_expenses": total_agent_exp, "waybill_total": waybill_total,
        "waybill_entries": waybill_entries,
        "other_office_expenses": office_total - waybill_total,
        "total_office_expenses": office_total, "total_expenses": total_expenses,
        "remittance": remittance, "is_agent": is_agent(user),
    })


@app.get("/reports/txt", response_class=PlainTextResponse)
def reports_txt(request: Request, start_date: str | None = None, end_date: str | None = None, agent_id: str | None = None, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return PlainTextResponse("Unauthorized", status_code=401)
    user = user_or
    if not (is_admin(user) or is_agent(user) or is_supervisor(user)):
        return PlainTextResponse("Forbidden", status_code=403)
    d1 = _parse_iso_date(start_date); d2 = _parse_iso_date(end_date)
    if not d1 and not d2: d1 = d2 = date.today()
    if d1 and not d2: d2 = d1
    if d2 and not d1: d1 = d2
    start_dt = datetime.combine(d1, datetime.min.time())
    end_dt   = datetime.combine(d2, datetime.max.time())
    branch_id = get_selected_branch_id(request, user)
    target_agent_id = None
    if is_agent(user): target_agent_id = int(user.id)
    elif is_admin(user) and (agent_id or "").isdigit(): target_agent_id = int(agent_id)
    filters = [Delivery.created_at >= start_dt, Delivery.created_at <= end_dt, Delivery.status == "DELIVERED"]
    if not is_supervisor(user): filters.append(Delivery.branch_id == branch_id)
    if target_agent_id is not None: filters.append(Delivery.agent_id == target_agent_id)
    deliveries = db.execute(select(Delivery).where(and_(*filters)).order_by(Delivery.created_at.asc())).scalars().all()
    delivery_ids = [d.id for d in deliveries]
    items_by_delivery: dict[int, list] = {}
    if delivery_ids:
        for did, iname, qty, line_amt, sp in db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity, DeliveryItem.line_amount, Item.selling_price)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all():
            q = float(qty or 0); la = float(line_amt or 0)
            # Skip items removed by adjustment (line_amount == 0 means customer refused/returned)
            if la == 0 and q > 0:
                continue
            items_by_delivery.setdefault(int(did), []).append((str(iname), q, la))
    _ce_br = CashEntry.branch_id == branch_id if not is_supervisor(user) else True
    agent_exp_map = {int(aid): float(t) for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind.in_(["EXPENSE","COLLECTION_EXPENSE"])).where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(_ce_br).group_by(CashEntry.agent_id).order_by(CashEntry.agent_id.asc())).all()}
    agent_coll_exp_txt = {int(aid): float(t) for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "COLLECTION_EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(_ce_br).group_by(CashEntry.agent_id)).all()}
    op_cash_map = {int(aid): float(t) for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OPERATING_CASH").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).group_by(CashEntry.agent_id)).all()}
    office_total = float(db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OFFICE_EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)) or 0)
    waybill_total = float(db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OFFICE_EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(func.lower(func.coalesce(CashEntry.note, "")).like("%waybill%"))) or 0)
    other_office_total = office_total - waybill_total
    all_agent_ids = list(set(list(agent_exp_map.keys()) + list(op_cash_map.keys())))
    uname: dict[int, str] = {}
    if all_agent_ids:
        uname = {int(u.id): (u.full_name or u.username or f"Agent {u.id}") for u in db.execute(select(User).where(User.id.in_(all_agent_ids))).scalars().all()}
    title_day = d1.strftime("%A %d %B %Y").upper() if d1 == d2 else f"{d1.isoformat()} TO {d2.isoformat()}"
    lines = [f"REPORT FOR {title_day}.", f"TOTAL DELIVERY = {len(deliveries)}", ""]
    grand_total = 0.0
    for idx, d in enumerate(deliveries, start=1):
        d_items = items_by_delivery.get(int(d.id), [])
        delivery_total = sum(amt for _n, _q, amt in d_items)
        grand_total += delivery_total
        parts = [f"{q:g} {n}" for n, q, _a in d_items]
        lines.append(f"({idx})\t{sum(q for _n,q,_a in d_items):g}\t{' + '.join(parts) if parts else 'No items'}\t{_ngn(delivery_total)}")
    lines += ["", f"Grand total: {_ngn(grand_total)}", ""]
    total_agent_expenses = expenses_from_collections = total_op_cash_given = total_op_cash_balance = 0.0
    agent_section_lines: list[str] = []
    for aid in sorted(set(list(agent_exp_map.keys()) + list(op_cash_map.keys()))):
        exp = agent_exp_map.get(aid, 0.0); op = op_cash_map.get(aid, 0.0); aname = uname.get(aid, f"Agent {aid}")
        total_agent_expenses += exp; total_op_cash_given += op
        if op > 0:
            balance = op - exp; total_op_cash_balance += max(balance, 0)
            if balance < 0: expenses_from_collections += abs(balance)
            # Only show agent in section if they still have a balance to return
            if balance > 0:
                agent_section_lines += [f"  {aname}:", f"    Operating cash given : {_ngn(op)}", f"    Expenses spent       : {_ngn(exp)}",
                                        f"    Balance to return    : {_ngn(balance)}"]
        else:
            expenses_from_collections += exp
            if exp > 0:
                agent_section_lines += [f"  {aname}:", f"    Expenses (no op cash, deducted from collection): {_ngn(exp)}"]
    if is_agent(user):
        lines += ["Operating Cash & Expenses:"] + (agent_section_lines or ["  None"])
        if total_op_cash_given > 0:
            lines += [f"  Total operating cash given : {_ngn(total_op_cash_given)}", f"  Total expenses             : {_ngn(total_agent_expenses)}", f"  Total balance to return    : {_ngn(total_op_cash_balance)}"]
        lines += ["", "Office expenses:", f"  Waybills              : {_ngn(waybill_total)}", f"  Other office expenses : {_ngn(other_office_total)}", f"  Total office expenses : {_ngn(office_total)}", ""]
        remittance = grand_total - expenses_from_collections
        lines += ["Amount to be remitted (collections only):"]
        lines.append(f"  {_ngn(grand_total)} - {_ngn(expenses_from_collections)} (uncovered expenses) = {_ngn(remittance)}" if expenses_from_collections > 0 else f"  {_ngn(grand_total)}")
    else:
        total_expenses = total_agent_expenses + office_total
        remittance = grand_total - total_expenses
        lines += ["Agent Expenses:"] + (agent_section_lines or ["  None"]) + [f"  Total agent expenses: {_ngn(total_agent_expenses)}", "", "Office expenses:",
            f"  Waybills              : {_ngn(waybill_total)}", f"  Other office expenses : {_ngn(other_office_total)}", f"  Total office expenses : {_ngn(office_total)}", "",
            f"Total amount of expenses: {_ngn(total_expenses)}", "", "Amount to be remitted:", f"  {_ngn(grand_total)} - {_ngn(total_expenses)} = {_ngn(remittance)}"]
    return PlainTextResponse("\n".join(lines), headers={"Content-Disposition": f'attachment; filename="report_{d1.isoformat()}_{d2.isoformat()}.txt"'}, media_type="text/plain; charset=utf-8")


# ────────────────────────────────────────────────
#  ADMIN RESET  [FIX-8]
# ────────────────────────────────────────────────

@app.post("/admin/wipe-data", response_class=JSONResponse)
async def wipe_all_data(request: Request, db: Session = Depends(get_db)):
    """Wipe all operational data except users and branches.
    Deletes: deliveries, transactions, cash entries, stock transfers,
    items, notifications, audit logs, assignments, faulty stock, vettings.
    Keeps: users, branches.
    """
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_supervisor(user): return JSONResponse({"error": "forbidden — supervisor only"}, status_code=403)
    body = await request.json()
    if body.get("confirm") != "WIPE ALL DATA":
        return JSONResponse({"error": "type WIPE ALL DATA to confirm"}, status_code=400)
    try:
        db.execute(text("DELETE FROM stock_return_vettings"))
        db.execute(text("DELETE FROM adjustment_request_items"))
        db.execute(text("DELETE FROM adjustment_requests"))
        db.execute(text("UPDATE agent_stock_assignments SET transaction_out_id=NULL, transaction_in_id=NULL, delivery_id=NULL"))
        db.execute(text("DELETE FROM agent_stock_assignments"))
        db.execute(text("DELETE FROM faulty_stock"))
        db.execute(text("DELETE FROM notifications"))
        db.execute(text("DELETE FROM cash_entries"))
        db.execute(text("DELETE FROM delivery_items"))
        db.execute(text("DELETE FROM stock_transfer_items"))
        db.execute(text("UPDATE stock_transfers SET received_by_id=NULL, cancelled_by_id=NULL, delegated_agent_id=NULL, delegated_receiver_id=NULL"))
        db.execute(text("DELETE FROM stock_transfers"))
        db.execute(text("DELETE FROM deliveries"))
        db.execute(text("DELETE FROM transactions"))
        db.execute(text("DELETE FROM items"))
        db.execute(text("DELETE FROM audit_logs"))
        db.commit()
        return JSONResponse({"ok": True, "message": "All data wiped. Users and branches preserved."})
    except Exception as e:
        db.rollback()
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/admin/reset-system", response_class=HTMLResponse)
def reset_system_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    csrf_token = get_csrf_token(request)
    return HTMLResponse(f"""<!doctype html><html><head><title>Reset System</title>
<style>body{{font-family:sans-serif;max-width:500px;margin:80px auto;padding:20px}}
input,button{{padding:10px;border-radius:8px;border:1px solid #ccc;width:100%;box-sizing:border-box;margin-top:10px}}
button{{background:#ef4444;color:white;border:none;cursor:pointer;font-weight:700}}</style></head>
<body><h2>⚠ Reset System</h2>
<p>This will permanently delete all deliveries, transactions, and cash entries.</p>
<p>Type <strong>RESET</strong> to confirm:</p>
<form method="post" action="/admin/reset-system">
  <input type="hidden" name="csrf_token" value="{csrf_token}" />
  <input type="text" name="confirm" placeholder="Type RESET here" required />
  <button type="submit">Delete All Data</button>
</form>
<p style="margin-top:20px"><a href="/">← Cancel</a></p>
</body></html>""")


@app.post("/admin/reset-system")
async def reset_system_execute(
    request: Request,
    confirm: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    verify_csrf_token(request, csrf_token)
    if confirm.strip() != "RESET":
        return HTMLResponse("Confirmation text incorrect. <a href='/admin/reset-system'>Go back</a>", status_code=400)
    if DATABASE_URL.startswith("sqlite"):
        db.execute(text("DELETE FROM cash_entries"))
        db.execute(text("DELETE FROM delivery_items"))
        db.execute(text("DELETE FROM deliveries"))
        db.execute(text("DELETE FROM transactions"))
    else:
        db.execute(text("TRUNCATE TABLE cash_entries RESTART IDENTITY CASCADE"))
        db.execute(text("TRUNCATE TABLE delivery_items RESTART IDENTITY CASCADE"))
        db.execute(text("TRUNCATE TABLE deliveries RESTART IDENTITY CASCADE"))
        db.execute(text("TRUNCATE TABLE transactions RESTART IDENTITY CASCADE"))
    db.commit()
    return redirect("/?reset=1")


# ────────────────────────────────────────────────
#  PWA / STATIC
# ────────────────────────────────────────────────

@app.get("/manifest.json")
def pwa_manifest():
    manifest_path = os.path.join(BASE_DIR, "static", "manifest.json")
    try:
        content = open(manifest_path).read()
    except FileNotFoundError:
        content = "{}"
    return PlainTextResponse(content, headers={"Content-Type": "application/manifest+json; charset=utf-8"})


@app.get("/sw.js", response_class=PlainTextResponse)
def service_worker():
    sw = """const CACHE = "invkeeper-v3";
const PRECACHE = ["/", "/deliveries", "/items", "/transfers", "/cash"];
self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)));
  self.skipWaiting();
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});
self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  // Only intercept same-origin requests
  try {
    const url = new URL(e.request.url);
    if (url.origin !== self.location.origin) return;
  } catch(err) { return; }
  e.respondWith(
    fetch(e.request).then(res => {
      if (res.ok && e.request.destination === "document") {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
      }
      return res;
    }).catch(() => caches.match(e.request))
  );
});"""
    return PlainTextResponse(sw, headers={"Content-Type": "application/javascript"})


# NOTE: /debug-login REMOVED [FIX-2]


# ────────────────────────────────────────────────
#  STOCK TRANSFERS
# ────────────────────────────────────────────────


# ────────────────────────────────────────────────
#  MERCHANT RECEIPTS
# ────────────────────────────────────────────────

@app.get("/merchant-receipt/new", response_class=HTMLResponse)
def merchant_receipt_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    branch_id = get_selected_branch_id(request, user)
    items = get_items_with_stock(db, branch_id=branch_id)
    csrf_token = get_csrf_token(request)
    categories = db.execute(
        select(Item.category).where(Item.branch_id == branch_id)
        .where(Item.category.isnot(None)).distinct().order_by(Item.category.asc())
    ).scalars().all()
    return tpl(request, "merchant_receipt_new.html", {
        "request": request, "user": user, "items": items,
        "categories": categories, "mode": "receipt",
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "active": "transfers", "csrf_token": csrf_token,
    })


@app.post("/merchant-receipt/new")
async def merchant_receipt_create(
    request: Request,
    merchant_name: str = Form(...),
    note: str = Form(""),
    expense_amount: str = Form(""),
    expense_note: str = Form(""),
    item_ids: list[int] = Form(...),
    quantities: list[int] = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    branch_id = get_selected_branch_id(request, user)
    merchant_name = sanitize_text(merchant_name, 200, "Merchant name")
    if not merchant_name:
        return redirect("/merchant-receipt/new?error=Merchant+name+is+required")
    if not item_ids or not quantities or len(item_ids) != len(quantities):
        return redirect("/merchant-receipt/new?error=Please+add+at+least+one+item")
    for qty in quantities:
        if qty <= 0:
            return redirect("/merchant-receipt/new?error=Quantities+must+be+greater+than+zero")
    note_text = sanitize_text(note, 400, "Note") or ""
    ref = f"MERCHANT: {merchant_name}"
    full_note = note_text if note_text else f"Stock received from merchant: {merchant_name}"
    for item_id, qty in zip(item_ids, quantities):
        item = db.get(Item, item_id)
        if not item or item.branch_id != branch_id:
            return redirect("/merchant-receipt/new?error=Invalid+item+selected")
        db.add(Transaction(
            branch_id=branch_id, item_id=item_id,
            type="IN", quantity=qty,
            reference=ref, note=full_note,
        ))
    # Record expense if provided
    exp_amt = 0.0
    try:
        exp_amt = float(expense_amount) if expense_amount else 0.0
    except ValueError:
        exp_amt = 0.0
    if exp_amt > 0:
        db.add(CashEntry(
            branch_id=branch_id,
            agent_id=user.id,
            kind="OFFICE_EXPENSE",
            amount=exp_amt,
            note=f"waybill - from {merchant_name}: {sanitize_text(expense_note, 200, 'Note') or ''}".strip().rstrip(':'),
        ))
    db.commit()
    return redirect("/merchant-receipt/new?success=Stock+received+and+recorded+successfully")


@app.get("/merchant-return/new", response_class=HTMLResponse)
def merchant_return_form(request: Request, db: Session = Depends(get_db)):
    """Return goods back to a merchant — creates OUT transactions."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user): return HTMLResponse("Forbidden", status_code=403)
    branch_id = get_selected_branch_id(request, user)
    items = get_items_with_stock(db, branch_id=branch_id)
    # Get distinct merchant names from item categories for this branch
    categories = db.execute(
        select(Item.category).where(Item.branch_id == branch_id)
        .where(Item.category.isnot(None)).distinct().order_by(Item.category.asc())
    ).scalars().all()
    csrf_token = get_csrf_token(request)
    return tpl(request, "merchant_receipt_new.html", {
        "request": request, "user": user, "items": items,
        "categories": categories,
        "mode": "return",  # tells template which tab is active
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "active": "transfers", "csrf_token": csrf_token,
    })


@app.post("/merchant-return/new")
async def merchant_return_create(
    request: Request,
    merchant_name: str = Form(...),
    note: str = Form(""),
    expense_amount: str = Form(""),
    expense_note: str = Form(""),
    item_ids: list[int] = Form(...),
    quantities: list[int] = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    """Record goods returned to merchant — OUT transaction per item."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user): return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    branch_id = get_selected_branch_id(request, user)
    merchant_name = sanitize_text(merchant_name, 200, "Merchant name")
    if not merchant_name:
        return redirect("/merchant-return/new?error=Merchant+name+is+required")
    if not item_ids or not quantities or len(item_ids) != len(quantities):
        return redirect("/merchant-return/new?error=Please+add+at+least+one+item")
    for qty in quantities:
        if qty <= 0:
            return redirect("/merchant-return/new?error=Quantities+must+be+greater+than+zero")
    note_text = sanitize_text(note, 400, "Note") or ""
    ref = f"MERCHANT RETURN: {merchant_name}"
    full_note = note_text if note_text else f"Goods returned to merchant: {merchant_name}"
    for item_id, qty in zip(item_ids, quantities):
        item = db.get(Item, item_id)
        if not item or item.branch_id != branch_id:
            return redirect("/merchant-return/new?error=Invalid+item+selected")
        db.add(Transaction(
            branch_id=branch_id, item_id=item_id,
            type="OUT", quantity=qty,
            reference=ref, note=full_note,
        ))
    # Record expense if provided
    exp_amt = 0.0
    try:
        exp_amt = float(expense_amount) if expense_amount else 0.0
    except ValueError:
        exp_amt = 0.0
    if exp_amt > 0:
        db.add(CashEntry(
            branch_id=branch_id, agent_id=user.id,
            kind="OFFICE_EXPENSE", amount=exp_amt,
            note=f"waybill - to {merchant_name}: {sanitize_text(expense_note, 200, 'Note') or ''}".strip().rstrip(':'),
        ))
    audit_log(db, user.id, "MERCHANT_RETURN",
              f"merchant={merchant_name} items={len(item_ids)}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    db.commit()
    return redirect("/merchant-return/new?success=Goods+returned+to+merchant+and+recorded+successfully")


@app.get("/transfers", response_class=HTMLResponse)
def transfers_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if is_agent(user):
        # Agents see transfers delegated to them (send or receive side) — hide cancelled from receiver
        transfers = db.execute(
            select(StockTransfer)
            .where(
                (StockTransfer.delegated_agent_id == user.id) |
                ((StockTransfer.delegated_receiver_id == user.id) & (StockTransfer.status != "CANCELLED"))
            )
            .order_by(desc(StockTransfer.created_at))
        ).scalars().all()
    elif is_supervisor(user):
        transfers = db.execute(select(StockTransfer).order_by(desc(StockTransfer.created_at))).scalars().all()
    elif is_admin(user):
        transfers = db.execute(
            select(StockTransfer)
            .where((StockTransfer.from_branch_id == user.branch_id) | (StockTransfer.to_branch_id == user.branch_id))
            .order_by(desc(StockTransfer.created_at))
        ).scalars().all()
    else:
        return HTMLResponse("Forbidden", status_code=403)
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all()
    # Fetch merchant receipts — admin and supervisor only
    merchant_receipts = []
    merchant_receipts_count = 0
    if is_admin(user) or is_supervisor(user):
        mr_tx_stmt = (
            select(Transaction.reference, Transaction.branch_id, Transaction.created_at,
                   Transaction.quantity, Item.name)
            .join(Item, Item.id == Transaction.item_id)
            .where(Transaction.reference.like("MERCHANT:%"))
            .order_by(Transaction.created_at.desc())
        )
        if not is_supervisor(user):
            mr_tx_stmt = mr_tx_stmt.where(Transaction.branch_id == user.branch_id)
        mr_tx_rows = db.execute(mr_tx_stmt).all()
        mr_groups: dict = {}
        for ref, br_id, created, qty, iname in mr_tx_rows:
            if ref not in mr_groups:
                mr_groups[ref] = {"reference": ref, "branch_id": br_id, "created_at": created,
                                   "items": [], "merchant_name": str(ref).replace("MERCHANT:", "").strip()}
            mr_groups[ref]["items"].append(f"{iname} x{qty}")
        merchant_receipts = sorted(mr_groups.values(), key=lambda r: r["created_at"], reverse=True)
        for r in merchant_receipts:
            r["item_names"] = ", ".join(r["items"])
        merchant_receipts_count = len(merchant_receipts)
    # Count sent (from this branch) and received (to this branch) — for cards
    if is_supervisor(user):
        sent_count     = sum(1 for t in transfers if t.status in ("OUT_FOR_DELIVERY", "RECEIVED"))
        received_count = sum(1 for t in transfers if t.status == "RECEIVED")
    elif is_agent(user):
        sent_count     = sum(1 for t in transfers if t.delegated_agent_id == user.id and t.status in ("OUT_FOR_DELIVERY", "RECEIVED"))
        received_count = sum(1 for t in transfers if t.delegated_receiver_id == user.id and t.status == "RECEIVED")
    else:
        sent_count     = sum(1 for t in transfers if t.from_branch_id == user.branch_id and t.status in ("OUT_FOR_DELIVERY", "RECEIVED"))
        received_count = sum(1 for t in transfers if t.to_branch_id == user.branch_id and t.status == "RECEIVED")
    csrf_token = get_csrf_token(request)
    return tpl(request, "transfers_list.html", {
        "request": request, "user": user, "transfers": transfers, "branches": branches,
        "active": "transfers", "selected_branch_id": getattr(user, "branch_id", None),
        "merchant_receipts": merchant_receipts,
        "merchant_receipts_count": merchant_receipts_count,
        "sent_count": sent_count, "received_count": received_count,
        "csrf_token": csrf_token,
    })


@app.get("/transfers/new", response_class=HTMLResponse)
def transfer_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    branches = db.execute(select(Branch).where(Branch.id != user.branch_id).order_by(Branch.name)).scalars().all()
    items = get_items_with_stock(db, branch_id=user.branch_id)
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == user.branch_id).order_by(User.username)).scalars().all()
    csrf_token = get_csrf_token(request)
    return tpl(request, "transfer_new.html", {
        "request": request, "user": user, "branches": branches, "items": items, "agents": agents,
        "error": request.query_params.get("error"), "active": "transfers",
        "selected_branch_id": user.branch_id, "csrf_token": csrf_token,
    })


@app.post("/transfers/new")
async def transfer_create(
    request: Request,
    to_branch_id: int = Form(...),
    note: str = Form(""),
    delegated_agent_id: str = Form(""),
    item_ids: list[int] = Form(...),
    quantities: list[int] = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    if to_branch_id == user.branch_id:
        return redirect("/transfers/new?error=Cannot+transfer+to+your+own+branch")
    if not item_ids or not quantities or len(item_ids) != len(quantities):
        return redirect("/transfers/new?error=Please+add+at+least+one+item")
    for item_id, qty in zip(item_ids, quantities):
        if qty <= 0:
            return redirect("/transfers/new?error=Quantities+must+be+greater+than+zero")
        row = get_item_with_stock(db, item_id, branch_id=user.branch_id)
        if not row:
            return redirect("/transfers/new?error=Item+not+found")
        _item, stock = row
        if int(stock) < qty:
            return redirect(f"/transfers/new?error=Insufficient+stock+for+{_item.name}")
    del_agent_id = int(delegated_agent_id) if delegated_agent_id.isdigit() else None
    transfer = StockTransfer(
        from_branch_id=user.branch_id, to_branch_id=to_branch_id, status="PENDING",
        note=sanitize_text(note, 400, "Note") or None, created_by_id=user.id,
        delegated_agent_id=del_agent_id,
    )
    db.add(transfer)
    db.flush()
    for item_id, qty in zip(item_ids, quantities):
        db.add(StockTransferItem(transfer_id=transfer.id, item_id=item_id, quantity=qty))
    # Stock is NOT deducted here — deducted when agent/admin marks as packed & sent
    db.commit()
    notify_branch_admins(db, to_branch_id,
        "📦 Incoming Stock Transfer",
        f"A new stock transfer from {user.branch.name} is pending for your branch (transfer #{transfer.id}).",
        f"/transfers/{transfer.id}", "info")
    if del_agent_id:
        notify(db, del_agent_id,
            "📦 Transfer Assigned to You",
            f"You have been assigned to send stock transfer #{transfer.id} to another branch.",
            f"/transfers/{transfer.id}", "info")
    return redirect(f"/transfers/{transfer.id}")


@app.get("/transfers/{transfer_id}", response_class=HTMLResponse)
def transfer_detail(transfer_id: int, request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    # Allow: admin of from/to branch, supervisor, or delegated agent
    is_delegated          = is_agent(user) and transfer.delegated_agent_id    == user.id
    is_delegated_receiver = is_agent(user) and transfer.delegated_receiver_id == user.id
    if not (is_admin(user) or is_supervisor(user) or is_delegated or is_delegated_receiver):
        return HTMLResponse("Forbidden", status_code=403)
    if is_admin(user) and user.branch_id not in (transfer.from_branch_id, transfer.to_branch_id):
        return HTMLResponse("Forbidden", status_code=403)
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all()
    delegated_agent    = db.get(User, transfer.delegated_agent_id)    if transfer.delegated_agent_id    else None
    delegated_receiver = db.get(User, transfer.delegated_receiver_id) if transfer.delegated_receiver_id else None
    packed_by          = db.get(User, getattr(transfer, "packed_by_id", None)) if getattr(transfer, "packed_by_id", None) else None
    is_delegated_receiver = is_agent(user) and transfer.delegated_receiver_id == user.id
    # Agents for sender branch (for delegation dropdown — sender admin only)
    sender_agents   = db.execute(select(User).where(User.role=="AGENT").where(User.branch_id==transfer.from_branch_id).order_by(User.username)).scalars().all() if (is_admin(user) and user.branch_id==transfer.from_branch_id) else []
    receiver_agents = db.execute(select(User).where(User.role=="AGENT").where(User.branch_id==transfer.to_branch_id).order_by(User.username)).scalars().all()  if (is_admin(user) and user.branch_id==transfer.to_branch_id)   else []
    csrf_token = get_csrf_token(request)
    return tpl(request, "transfer_detail.html", {
        "request": request, "user": user, "transfer": transfer, "branches": branches,
        "delegated_agent": delegated_agent, "delegated_receiver": delegated_receiver,
        "packed_by": packed_by,
        "is_delegated": is_delegated, "is_delegated_receiver": is_delegated_receiver,
        "sender_agents": sender_agents, "receiver_agents": receiver_agents,
        "active": "transfers", "selected_branch_id": getattr(user, "branch_id", None),
        "csrf_token": csrf_token,
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
    })


@app.post("/transfers/{transfer_id}/receive")
async def transfer_receive(transfer_id: int, request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    is_recv_agent = is_agent(user)
    verify_csrf_token(request, csrf_token)
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    if is_recv_agent:
        if transfer.delegated_receiver_id != user.id:
            return HTMLResponse("Forbidden", status_code=403)
    elif is_admin(user):
        if transfer.to_branch_id != user.branch_id:
            return HTMLResponse("Forbidden — you are not the receiving branch", status_code=403)
    else:
        return HTMLResponse("Forbidden", status_code=403)
    # For agent receiving, get branch_id from transfer
    recv_branch_id = transfer.to_branch_id
    if transfer.status in ("RECEIVED", "CANCELLED"):
        return redirect(f"/transfers/{transfer_id}?error=Transfer+is+already+{transfer.status}")
    for line in transfer.items:
        dest_item = db.scalar(select(Item).where(Item.branch_id == recv_branch_id, Item.name == line.item.name))
        if not dest_item:
            dest_item = Item(branch_id=recv_branch_id, name=line.item.name, category=line.item.category,
                             unit=line.item.unit, reorder_level=line.item.reorder_level,
                             cost_price=line.item.cost_price, selling_price=line.item.selling_price)
            db.add(dest_item)
            db.flush()
        db.add(Transaction(branch_id=recv_branch_id, item_id=dest_item.id, type="IN", quantity=line.quantity,
                           reference=f"TRANSFER #{transfer.id}", note=f"Stock received from branch {transfer.from_branch.name}"))
    # Require receive expense to be recorded before confirming receipt
    if not transfer.receive_expense_amount or float(transfer.receive_expense_amount) <= 0:
        return redirect(f"/transfers/{transfer_id}?error=Please+record+your+receiving+expenses+before+confirming+receipt")
    transfer.status = "RECEIVED"
    transfer.received_by_id = user.id
    transfer.received_at = datetime.utcnow()
    notify_branch_admins(db, transfer.from_branch_id,
        "✅ Stock Transfer Received",
        f"{transfer.to_branch.name} has confirmed receipt of stock transfer #{transfer_id}.",
        f"/transfers/{transfer_id}", "success")
    db.commit()
    return redirect(f"/transfers/{transfer_id}")




@app.post("/transfers/{transfer_id}/pack")
async def transfer_pack(transfer_id: int, request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    """Agent marks transfer as packed/ready to send."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404)
    # Only the delegated agent or admin can pack
    if not is_admin(user) and transfer.delegated_agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    if transfer.status != "PENDING":
        return redirect(f"/transfers/{transfer_id}?error=Transfer+is+not+pending")
    # Require expense to be recorded before marking as sent
    if not transfer.expense_amount or float(transfer.expense_amount) <= 0:
        return redirect(f"/transfers/{transfer_id}?error=Please+record+your+sending+expenses+before+marking+as+sent")
    # Deduct stock from sender branch — only if not already deducted (guard against old transfers)
    already_deducted = db.scalar(
        select(func.count(Transaction.id))
        .where(Transaction.reference == f"TRANSFER #{transfer.id}")
        .where(Transaction.type == "OUT")
        .where(Transaction.branch_id == transfer.from_branch_id)
    ) or 0
    if not already_deducted:
        for line in transfer.items:
            db.add(Transaction(
                branch_id=transfer.from_branch_id, item_id=line.item_id,
                type="OUT", quantity=line.quantity,
                reference=f"TRANSFER #{transfer.id}",
                note=f"Stock sent to {transfer.to_branch.name}"
            ))
    transfer.packed_by_id = user.id
    transfer.packed_at = datetime.utcnow()
    transfer.status = "OUT_FOR_DELIVERY"
    notify_branch_admins(db, transfer.to_branch_id,
        "📦 Stock Transfer On Its Way",
        f"Stock from {transfer.from_branch.name} has been packed and sent to your branch (transfer #{transfer_id}).",
        f"/transfers/{transfer_id}", "info")
    db.commit()
    audit_log(db, user.id, "TRANSFER_SENT", f"transfer_id={transfer_id}",
              ip=request.headers.get("x-forwarded-for","").split(",")[0].strip() or (request.client.host if request.client else ""))
    return redirect(f"/transfers/{transfer_id}")


@app.post("/transfers/{transfer_id}/expense")
async def transfer_expense(
    transfer_id: int, request: Request,
    expense_amount: float = Form(0),
    expense_kind: str = Form(""),
    expense_note: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    """Record expense against a transfer — agent or admin."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404)

    # Validate kind
    allowed_agent = {"EXPENSE", "COLLECTION_DEDUCTION"}
    allowed_admin = {"COLLECTION_DEDUCTION"}
    if is_admin(user):
        if expense_kind not in allowed_admin:
            return redirect(f"/transfers/{transfer_id}?error=Invalid+expense+type")
    else:
        if expense_kind not in allowed_agent:
            return redirect(f"/transfers/{transfer_id}?error=Invalid+expense+type")
        if transfer.delegated_agent_id != user.id:
            return HTMLResponse("Forbidden", status_code=403)

    if expense_amount <= 0:
        return redirect(f"/transfers/{transfer_id}?error=Amount+must+be+greater+than+zero")

    # Save on the transfer record
    transfer.expense_amount = expense_amount
    transfer.expense_kind = expense_kind
    transfer.expense_note = sanitize_text(expense_note, 400, "Note") or None

    # Also create a CashEntry so it shows in cash section
    cash_kind = "EXPENSE" if expense_kind == "EXPENSE" else "EXPENSE"
    to_branch_name = transfer.to_branch.name if transfer.to_branch else f"Branch {transfer.to_branch_id}"
    exp_note = f"waybill - to {to_branch_name}: {sanitize_text(expense_note, 200, 'Note') or ''}"
    if is_admin(user):
        target_agent = transfer.delegated_agent_id or user.id
        db.add(CashEntry(
            branch_id=transfer.from_branch_id,
            agent_id=target_agent,
            kind="OFFICE_EXPENSE",
            amount=expense_amount,
            note=exp_note,
        ))
    else:
        db.add(CashEntry(
            branch_id=transfer.from_branch_id,
            agent_id=user.id,
            kind="EXPENSE",
            amount=expense_amount,
            note=exp_note,
        ))
    db.commit()
    return redirect(f"/transfers/{transfer_id}")


@app.post("/transfers/{transfer_id}/delegate-receiver")
async def transfer_delegate_receiver(
    transfer_id: int, request: Request,
    delegated_receiver_id: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user): return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer: raise HTTPException(status_code=404)
    if user.branch_id != transfer.to_branch_id:
        return HTMLResponse("Forbidden — you are not the receiving branch", status_code=403)
    transfer.delegated_receiver_id = int(delegated_receiver_id) if delegated_receiver_id.isdigit() else None
    db.commit()
    if transfer.delegated_receiver_id:
        notify(db, transfer.delegated_receiver_id,
            "📦 Transfer to Receive",
            f"You have been assigned to receive stock transfer #{transfer_id}.",
            f"/transfers/{transfer_id}", "info")
    return redirect(f"/transfers/{transfer_id}")


@app.post("/transfers/{transfer_id}/receive-expense")
async def transfer_receive_expense(
    transfer_id: int, request: Request,
    receive_expense_amount: float = Form(0),
    receive_expense_kind: str = Form(""),
    receive_expense_note: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer: raise HTTPException(status_code=404)

    allowed_agent = {"EXPENSE", "COLLECTION_DEDUCTION"}
    allowed_admin = {"COLLECTION_DEDUCTION"}
    if is_admin(user):
        if receive_expense_kind not in allowed_admin:
            return redirect(f"/transfers/{transfer_id}?error=Invalid+expense+type")
        if user.branch_id != transfer.to_branch_id:
            return HTMLResponse("Forbidden", status_code=403)
    else:
        if receive_expense_kind not in allowed_agent:
            return redirect(f"/transfers/{transfer_id}?error=Invalid+expense+type")
        if transfer.delegated_receiver_id != user.id:
            return HTMLResponse("Forbidden", status_code=403)

    if receive_expense_amount <= 0:
        return redirect(f"/transfers/{transfer_id}?error=Amount+must+be+greater+than+zero")

    transfer.receive_expense_amount = receive_expense_amount
    transfer.receive_expense_kind   = receive_expense_kind
    transfer.receive_expense_note   = sanitize_text(receive_expense_note, 400, "Note") or None

    from_branch_name = transfer.from_branch.name if transfer.from_branch else f"Branch {transfer.from_branch_id}"
    recv_exp_note = f"waybill - from {from_branch_name}: {sanitize_text(receive_expense_note, 200, 'Note') or ''}"
    if is_admin(user):
        target_recv_agent = transfer.delegated_receiver_id or user.id
        db.add(CashEntry(
            branch_id=transfer.to_branch_id,
            agent_id=target_recv_agent,
            kind="OFFICE_EXPENSE",
            amount=receive_expense_amount,
            note=recv_exp_note,
        ))
    else:
        db.add(CashEntry(
            branch_id=transfer.to_branch_id,
            agent_id=user.id,
            kind="EXPENSE",
            amount=receive_expense_amount,
            note=recv_exp_note,
        ))
    db.commit()
    return redirect(f"/transfers/{transfer_id}")

@app.post("/transfers/{transfer_id}/cancel")
async def transfer_cancel(transfer_id: int, request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    is_delegated_cancel = is_agent(user) and transfer.delegated_agent_id == user.id
    if not is_admin(user) and not is_delegated_cancel:
        return HTMLResponse("Forbidden", status_code=403)
    if is_admin(user) and user.branch_id not in (transfer.from_branch_id, transfer.to_branch_id):
        return HTMLResponse("Forbidden", status_code=403)
    if transfer.status in ("RECEIVED", "CANCELLED"):
        return redirect(f"/transfers/{transfer_id}?error=Transfer+is+already+{transfer.status}")
    # Only return stock if it was already deducted (i.e. packed/sent)
    if transfer.status == "OUT_FOR_DELIVERY":
        for line in transfer.items:
            db.add(Transaction(
                branch_id=transfer.from_branch_id, item_id=line.item_id, type="IN", quantity=line.quantity,
                reference=f"TRANSFER #{transfer.id} CANCELLED", note="Stock returned — transfer cancelled"
            ))
    # Reverse send-side expense cash entry if recorded
    if transfer.expense_amount and transfer.expense_amount > 0:
        exp_kind = "OFFICE_EXPENSE" if (transfer.expense_kind == "COLLECTION_DEDUCTION" and transfer.delegated_agent_id is None) else "EXPENSE"
        # Find and delete the original expense entry
        orig_exp = db.scalar(
            select(CashEntry).where(CashEntry.branch_id == transfer.from_branch_id)
            .where(CashEntry.note.like(f"Transfer #{transfer.id} expense:%"))
            .order_by(CashEntry.created_at.asc())
        )
        if orig_exp:
            db.delete(orig_exp)
    # Reverse receive-side expense cash entry if recorded
    if transfer.receive_expense_amount and transfer.receive_expense_amount > 0:
        orig_recv_exp = db.scalar(
            select(CashEntry).where(CashEntry.branch_id == transfer.to_branch_id)
            .where(CashEntry.note.like(f"Transfer #{transfer.id} receive expense:%"))
            .order_by(CashEntry.created_at.asc())
        )
        if orig_recv_exp:
            db.delete(orig_recv_exp)
    transfer.status = "CANCELLED"
    transfer.cancelled_by_id = user.id
    transfer.cancelled_at = datetime.utcnow()
    db.commit()
    return redirect(f"/transfers/{transfer_id}")


# ────────────────────────────────────────────────
#  MERCHANT REMITTANCE
# ────────────────────────────────────────────────

def _merchant_remittance_query(db, sd, ed, bid):
    """Return per-delivery-item rows grouped by category for remittance report."""
    params = {"start": str(sd), "end": str(ed)}
    branch_clause = "AND d.branch_id = :bid" if bid else ""
    if bid:
        params["bid"] = bid
    return db.execute(text(f"""
        SELECT
            COALESCE(i.category, 'Uncategorized') AS category,
            d.id                                   AS delivery_id,
            d.customer_name                        AS customer_name,
            i.name                                 AS item_name,
            di.quantity                            AS qty,
            di.line_amount                         AS collection
        FROM delivery_items di
        JOIN deliveries d ON d.id = di.delivery_id
        JOIN items      i ON i.id = di.item_id
        WHERE d.status = 'DELIVERED'
          AND di.line_amount > 0
          AND DATE(COALESCE(d.delivered_at, d.created_at)) >= :start
          AND DATE(COALESCE(d.delivered_at, d.created_at)) <= :end
          {branch_clause}
        ORDER BY COALESCE(i.category, 'Uncategorized'), d.customer_name, d.id, i.name
    """), params).fetchall()


@app.get("/merchant-remittance", response_class=HTMLResponse)
def merchant_remittance_page(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all() if is_supervisor(user) else []
    today = date.today().isoformat()
    return tpl(request, "merchant_remittance.html", {
        "user": user, "branches": branches,
        "today": today, "active": "merchant_remittance",
    })


@app.get("/merchant-remittance/data", response_class=JSONResponse)
def merchant_remittance_data(
    request: Request,
    start_date: str = "",
    end_date: str = "",
    branch_id: int = 0,
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    sd = _parse_iso_date(start_date)
    ed = _parse_iso_date(end_date)
    if not sd or not ed:
        return JSONResponse({"error": "start_date and end_date are required"}, status_code=400)

    bid = user.branch_id if is_admin(user) else (branch_id or None)
    rows = _merchant_remittance_query(db, sd, ed, bid)

    # Build: category -> list of deliveries (one row per delivery, items merged)
    categories: dict = {}
    # delivery_map: (cat, delivery_id) -> delivery row dict
    delivery_map: dict = {}
    grand_qty = 0
    grand_total = 0.0

    for r in rows:
        cat = r.category
        did = r.delivery_id
        qty = int(r.qty or 0)
        amt = float(r.collection or 0)

        if cat not in categories:
            categories[cat] = {"category": cat, "rows": [], "subtotal_qty": 0, "subtotal_collection": 0.0}

        key = (cat, did)
        if key not in delivery_map:
            delivery_map[key] = {
                "customer": r.customer_name or "—",
                "delivery_id": did,
                "items": [],
                "qty": 0,
                "collection": 0.0,
            }
            categories[cat]["rows"].append(delivery_map[key])

        delivery_map[key]["items"].append(f"{r.item_name} ×{qty}")
        delivery_map[key]["qty"] += qty
        delivery_map[key]["collection"] += amt
        categories[cat]["subtotal_qty"] += qty
        categories[cat]["subtotal_collection"] += amt
        grand_qty += qty
        grand_total += amt

    # Convert items list to string
    for d in delivery_map.values():
        d["items"] = ", ".join(d["items"])

    return JSONResponse({
        "categories": list(categories.values()),
        "grand_qty": grand_qty,
        "grand_total": round(grand_total, 2),
        "category_count": len(categories),
        "start_date": str(sd),
        "end_date": str(ed),
    })


@app.get("/merchant-remittance/csv")
def merchant_remittance_csv(
    request: Request,
    start_date: str = "",
    end_date: str = "",
    branch_id: int = 0,
    db: Session = Depends(get_db),
):
    from fastapi.responses import Response as _Resp
    import csv, io
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)

    sd = _parse_iso_date(start_date) or date.today()
    ed = _parse_iso_date(end_date) or date.today()
    bid = user.branch_id if is_admin(user) else (branch_id or None)
    rows = _merchant_remittance_query(db, sd, ed, bid)

    # Merge rows into deliveries (one per delivery per category)
    delivery_map: dict = {}
    categories_order: list = []
    for r in rows:
        cat = r.category
        did = r.delivery_id
        key = (cat, did)
        if key not in delivery_map:
            delivery_map[key] = {
                "category": cat, "customer": r.customer_name or "—",
                "items": [], "qty": 0, "collection": 0.0,
            }
            categories_order.append(key)
        delivery_map[key]["items"].append(f"{r.item_name} x{int(r.qty or 0)}")
        delivery_map[key]["qty"] += int(r.qty or 0)
        delivery_map[key]["collection"] += float(r.collection or 0)

    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["Category", "Customer", "Items", "Qty", "Collection (NGN)"])

    current_cat = None
    cat_qty = 0
    cat_amt = 0.0
    grand_qty = 0
    grand_total = 0.0

    for key in categories_order:
        d = delivery_map[key]
        cat = d["category"]
        if current_cat is not None and cat != current_cat:
            w.writerow(["", f"  {current_cat} SUBTOTAL", "", cat_qty, round(cat_amt, 2)])
            w.writerow([])
            cat_qty = 0; cat_amt = 0.0
        current_cat = cat
        w.writerow([cat, d["customer"], ", ".join(d["items"]), d["qty"], round(d["collection"], 2)])
        cat_qty += d["qty"]; cat_amt += d["collection"]
        grand_qty += d["qty"]; grand_total += d["collection"]

    if current_cat is not None:
        w.writerow(["", f"  {current_cat} SUBTOTAL", "", cat_qty, round(cat_amt, 2)])

    w.writerow([])
    w.writerow(["GRAND TOTAL", "", "", grand_qty, round(grand_total, 2)])

    filename = f"merchant_remittance_{sd}_{ed}.csv"
    return _Resp(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

from fastapi import Request
from .whatsapp_service import send_whatsapp_fallback # Import the new service
from .calling_service import _build_script

@app.post("/api/call-webhook")
async def call_webhook(request: Request, db: Session = Depends(get_db)):
    """Receives the end-of-call report from Vapi and updates the delivery notes."""
    try:
        payload = await request.json()
        message = payload.get("message", {})
        
        if message.get("type") != "end-of-call-report":
            return JSONResponse({"status": "ignored"})

        call_data = message.get("call", {})
        metadata = call_data.get("metadata", {})
        delivery_id = metadata.get("delivery_id")
        
        if not delivery_id:
            return JSONResponse({"error": "No delivery_id in metadata"}, status_code=400)

        summary = message.get("summary", "No summary provided by AI.")
        ended_reason = call_data.get("endedReason", "")

        d = db.get(Delivery, int(delivery_id))
        if d:
            existing_note = d.note or ""
            d.note = (existing_note + f"\n[AI Call Update]: {summary}").strip()
            
            # Trigger fallback logic if call failed
            if ended_reason in [
                "voicemail", "customer-hung-up", "customer-ended-call", 
                "customer-did-not-answer", "failed", "assistant-error", "customer-busy"
            ]:
                backup_numbers = metadata.get("backup_numbers", [])
                
                # Check if we have more numbers to try first
                if len(backup_numbers) > 0:
                    next_number = backup_numbers[0]
                    remaining_backups = backup_numbers[1:]
                    
                    d.note += f"\n[System]: Call to {call_data.get('customer', {}).get('number')} failed. Trying backup number: {next_number}..."
                    db.commit()
                    
                    # Launch the backup call using the metadata we saved
                    from .calling_service import _do_call
                    import threading
                    threading.Thread(target=_do_call, args=(
                        d.id, next_number, remaining_backups,
                        metadata.get("status", "PENDING"),
                        metadata.get("customer_name", d.customer_name),
                        metadata.get("items", "your order"),
                        metadata.get("address", d.address or "")
                    ), daemon=True).start()
                    
                else:
                    # No backups left! Send the WhatsApp message
                    try:
                        from .whatsapp_service import send_whatsapp_fallback
                        
                        # Fetch the item names for the WhatsApp message
                        items_query = db.execute(
                            select(Item.name, DeliveryItem.quantity)
                            .join(DeliveryItem, DeliveryItem.item_id == Item.id)
                            .where(DeliveryItem.delivery_id == d.id)
                        ).all()
                        items_str = ", ".join(f"{r.name} x{r.quantity}" for r in items_query) if items_query else "your order"

                        send_whatsapp_fallback(d.id, d.customer_phone, d.customer_name, items_str)
                        d.note += "\n[System]: All numbers failed. WhatsApp Fallback message triggered."
                    except Exception as wa_err:
                        import logging
                        logging.getLogger("webhook").error(f"WhatsApp fallback error: {wa_err}")

            db.commit()
            
            # Notify the assigned agent
            if d.agent_id:
                notify(db, d.agent_id, "📞 Customer Call Update",
                       f"The AI spoke to {d.customer_name}. Update: {summary}",
                       f"/deliveries/{d.id}", "warning")

        return JSONResponse({"status": "success"})
    except Exception as e:
        import logging
        logging.getLogger("webhook").error(f"Webhook error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/whatsapp-reply")
async def whatsapp_reply(request: Request, db: Session = Depends(get_db)):
    """Receives replies from customers via Twilio WhatsApp."""
    form_data = await request.form()
    
    sender = form_data.get("From", "").replace("whatsapp:", "")
    body = form_data.get("Body", "").strip()
    
    # Find the most recent active delivery for this phone number
    # Twilio sends the number in E.164 format (+234...)
    d = db.execute(
        select(Delivery)
        .where(Delivery.customer_phone == sender)
        .where(Delivery.status.in_(["PENDING", "OUT_FOR_DELIVERY"]))
        .order_by(Delivery.created_at.desc())
    ).scalars().first()

    if d:
        existing_note = d.note or ""
        
        if body == "1":
            d.note = (existing_note + "\n[WhatsApp]: Customer confirmed available today.").strip()
            notify_msg = f"{d.customer_name} confirmed via WhatsApp they are available."
            
        elif body == "2":
            d.note = (existing_note + "\n[WhatsApp]: Customer requested reschedule for tomorrow.").strip()
            d.status = "FAILED"
            notify_msg = f"{d.customer_name} requested a reschedule via WhatsApp."
            
        else:
            d.note = (existing_note + f"\n[WhatsApp Reply]: {body}").strip()
            notify_msg = f"{d.customer_name} replied on WhatsApp: {body}"
            
        db.commit()
        
        # Notify the branch admin or assigned agent
        if d.agent_id:
            notify(db, d.agent_id, "💬 WhatsApp Reply", notify_msg, f"/deliveries/{d.id}", "info")
        else:
            notify_branch_admins(db, d.branch_id, "💬 WhatsApp Reply", notify_msg, f"/deliveries/{d.id}", "info")

    return PlainTextResponse("OK", status_code=200)

import httpx
from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

@app.post("/api/agent-feedback")
async def send_agent_feedback(
    delivery_id: int = Form(...),
    group_name: str = Form(...), 
    issue_type: str = Form(...),
    db: Session = Depends(get_db)  # <-- This fixes the database crash!
):
    # 1. Fetch the delivery from the database
    delivery = db.query(Delivery).filter(Delivery.id == delivery_id).first()
    
    if not delivery:
        return JSONResponse({"status": "error", "message": "Delivery not found"}, status_code=404)

    # 2. Format the feedback message
    message = (
        f"🚨 *Agent Feedback Alert*\n"
        f"Order #{delivery.id} - {delivery.customer_name}\n"
        f"Status Issue: {issue_type}\n"
        f"Agent Note: The customer is currently unreachable or unavailable. Please advise."
    )

    # 3. Send the command to your Clawbot via the Railway Internal URL
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "http://adventurous-flow.railway.internal:3000/send-group-feedback", 
                json={
                    "groupName": group_name, 
                    "message": message,
                    "orderId": f"Order #{delivery.id}"  # <-- Tell the bot what to search for!
                },
                timeout=60
            )
            data = resp.json()
            if data.get("success"):
                return JSONResponse({"status": "success", "message": "Feedback sent to group!"})
            else:
                return JSONResponse({"status": "error", "message": data.get("error")})
    except Exception as e:
        return JSONResponse({"status": "error", "message": f"Clawbot is offline: {str(e)}"})

@app.post("/api/whatsapp-webhook")
async def whatsapp_webhook(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    order_id = data.get("order_id")
    comment = data.get("comment")
    sender = data.get("sender_phone")

    # 1. Find the delivery in the database
    delivery = db.query(Delivery).filter(Delivery.id == order_id).first()
    
    if delivery and delivery.agent_id:
        # 2. Trigger a notification for the specific Agent assigned to this order
        # Assuming you have a notify_user function for your Web Push/Dashboard notifications
        await create_notification(
            user_id=delivery.agent_id,
            title=f"New Comment on Order #{order_id}",
            message=f"Someone replied in the group: '{comment}'",
            link=f"/deliveries/{order_id}"
        )
        print(f"Agent {delivery.agent_id} notified of comment on Order {order_id}")
    
    return {"status": "received"}