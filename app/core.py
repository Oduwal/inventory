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

from __future__ import annotations

# Explicit exports — Python's `import *` skips underscore-prefixed names
# unless they appear in __all__.  Every router does `from app.core import *`,
# so any helper starting with _ MUST be listed here.
__all__: list[str] = []   # populated at module end; see _EXPORT_PRIVATE below
_EXPORT_PRIVATE = [
    "_now", "_ngn", "_parse_iso_date",
    "_range_dates_from_inputs", "_dt_range_from_dates",
    "_verify_webhook_token", "_send_web_push",
]
import os
import html
import json as _json
import logging
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, date, timedelta, timezone

# Background task executor to prevent OOM
task_queue = ThreadPoolExecutor(max_workers=10)

try:
    from pywebpush import webpush as _webpush, WebPushException as _WebPushException
    _PYWEBPUSH_OK = True
except ImportError:
    _PYWEBPUSH_OK = False

logging.getLogger("push").info(
    "PUSH STARTUP: pywebpush=%s VAPID_PUBLIC=%s VAPID_PRIVATE=%s",
    _PYWEBPUSH_OK,
    bool(os.environ.get("VAPID_PUBLIC_KEY")),
    bool(os.environ.get("VAPID_PRIVATE_KEY")),
)

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
    validate_push_endpoint,
    verify_origin_for_json,
    verify_twilio_signature_with_params,
    validate_image_upload,
    process_profile_image,
)
from .calling_service import trigger_call
from contextlib import asynccontextmanager


@asynccontextmanager
async def _lifespan(app):
    _run_startup()
    yield

app = FastAPI(lifespan=_lifespan)

# ── Webhook shared secret ───────────────────────────────────────────────────
# Set WEBHOOK_SECRET in env to require authentication on inbound webhooks.
# If not set, webhooks remain open (backward-compatible).
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
if not WEBHOOK_SECRET:
    logging.getLogger("inventory_keeper.security").warning(
        "WEBHOOK_SECRET is not set — webhook endpoints (/api/call-webhook, "
        "/api/whatsapp-webhook, /api/cache-wa-message) are UNPROTECTED. "
        "Set WEBHOOK_SECRET in your environment variables for production."
    )

def _verify_webhook_token(request: Request) -> None:
    """Raise 403 if WEBHOOK_SECRET doesn't match.  Skip check if not configured."""
    if not WEBHOOK_SECRET:
        return  # no secret configured — allow (startup already logged a warning)
    token = (
        request.headers.get("x-webhook-secret", "")
        or request.query_params.get("token", "")
    )
    if not secrets.compare_digest(token, WEBHOOK_SECRET):
        raise HTTPException(status_code=403, detail="Invalid webhook token")


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
            "VALUES (:uid, :title, :body, :link, :kind, :now)"
        ), {"uid": user_id, "title": title[:200], "body": body[:500], "link": link[:300], "kind": kind, "now": datetime.now(timezone.utc)})
        db.commit()
        task_queue.submit(_send_web_push, user_id, title, body, link)
    except Exception as e:
        db.rollback()
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
# Use TRUSTED_PROXY_HOSTS env var for production; defaults to Railway's internal network.
_trusted_hosts = os.getenv("TRUSTED_PROXY_HOSTS", "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=[h.strip() for h in _trusted_hosts.split(",")])

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

# NOTE: /sw.js handler is defined further below with inline service worker code.
# Duplicate file-based handler removed to avoid shadowing.

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


# [FIX-9] Portable timestamp for raw SQL — works on both SQLite and PostgreSQL.
# Instead of NOW() (PostgreSQL-only) or CURRENT_TIMESTAMP (varies by engine),
# pass the timestamp as a bind parameter so it always works.
def _now():
    """Return current UTC datetime for use as a SQL bind parameter."""
    return datetime.now(timezone.utc)


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
        # Enable WAL mode on SQLite so concurrent reads from FastAPI and the
        # Node bot webhook writer don't block each other.
        if is_sqlite:
            _ddl(conn, "PRAGMA journal_mode=WAL")

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
        # Profile picture columns
        _ddl(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture BYTEA NULL")
        _ddl(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture_mime VARCHAR(50) NULL")
        # Username change history — preserves audit trail when accounts change hands
        _ddl(conn, """CREATE TABLE IF NOT EXISTS username_history (
            id """ + ("INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY") + """,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            old_username VARCHAR(80) NOT NULL,
            new_username VARCHAR(80) NOT NULL,
            changed_by   INTEGER REFERENCES users(id),
            reason       VARCHAR(200) DEFAULT '',
            changed_at   TIMESTAMP DEFAULT """ + ("CURRENT_TIMESTAMP" if is_sqlite else "NOW()") + """
        )""")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_username_history_user ON username_history (user_id)")
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
        # Call logs table (VAPI integration)
        _ddl(conn, """CREATE TABLE IF NOT EXISTS call_logs (
            id              """ + ("INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY") + """,
            delivery_id     INTEGER NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
            call_id         VARCHAR(120) DEFAULT '',
            phone           VARCHAR(40) DEFAULT '',
            trigger_status  VARCHAR(30) DEFAULT '',
            call_status     VARCHAR(30) DEFAULT '',
            error_msg       TEXT DEFAULT '',
            summary         TEXT DEFAULT '',
            duration        INTEGER DEFAULT 0,
            created_at      TIMESTAMP DEFAULT """ + ("CURRENT_TIMESTAMP" if is_sqlite else "NOW()") + """
        )""")
        _ddl(conn, "ALTER TABLE call_logs ADD COLUMN IF NOT EXISTS summary TEXT DEFAULT ''")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_call_logs_delivery_id ON call_logs (delivery_id)")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_call_logs_created_at ON call_logs (created_at)")
        _ddl(conn, """CREATE TABLE IF NOT EXISTS wa_comments (
            id           """ + ("INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY") + """,
            delivery_id  INTEGER NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
            direction    VARCHAR(10) DEFAULT 'inbound',
            sender       VARCHAR(80) DEFAULT '',
            body         TEXT NOT NULL,
            created_at   TIMESTAMP DEFAULT """ + ("CURRENT_TIMESTAMP" if is_sqlite else "NOW()") + """
        )""")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_wa_comments_delivery_id ON wa_comments (delivery_id)")
        # Structured Gemini classification stored as JSON per inbound comment
        _ddl(conn, "ALTER TABLE wa_comments ADD COLUMN IF NOT EXISTS classification TEXT DEFAULT NULL")

        # Durable mapping of every bot-sent WhatsApp message_id → delivery order_id.
        # This table survives bot restarts; Python does O(1) lookup to route replies.
        _ddl(conn, """CREATE TABLE IF NOT EXISTS whatsapp_outbound_map (
            message_id  TEXT PRIMARY KEY,
            order_id    INTEGER NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
            body        TEXT NOT NULL DEFAULT '',
            source      TEXT NOT NULL DEFAULT 'bot',
            created_at  TIMESTAMP DEFAULT """ + ("CURRENT_TIMESTAMP" if is_sqlite else "NOW()") + """
        )""")
        _ddl(conn, "ALTER TABLE whatsapp_outbound_map ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'bot'")
        _ddl(conn, "ALTER TABLE whatsapp_outbound_map ADD COLUMN IF NOT EXISTS sender TEXT DEFAULT ''")
        _ddl(conn, "ALTER TABLE whatsapp_outbound_map ADD COLUMN IF NOT EXISTS group_jid TEXT DEFAULT ''")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_wa_outbound_order ON whatsapp_outbound_map (order_id)")

        # Holding table for WhatsApp group messages that arrived BEFORE the
        # delivery was created in the dashboard.  On delivery creation we scan
        # this table and promote matches into whatsapp_outbound_map.
        _ddl(conn, """CREATE TABLE IF NOT EXISTS wa_pending_cache (
            message_id      TEXT PRIMARY KEY,
            body            TEXT NOT NULL DEFAULT '',
            sender          TEXT DEFAULT '',
            group_jid       TEXT DEFAULT '',
            customer_name   TEXT DEFAULT '',
            customer_phone  TEXT DEFAULT '',
            created_at      TIMESTAMP DEFAULT """ + ("CURRENT_TIMESTAMP" if is_sqlite else "NOW()") + """
        )""")

        # [SEC-2] Rate limiter table — survives redeploys
        _ddl(conn, """CREATE TABLE IF NOT EXISTS rate_limit_hits (
            id """ + ("INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY") + """,
            ip VARCHAR(45) NOT NULL,
            created_at TIMESTAMP NOT NULL
        )""")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_rate_limit_ip_time ON rate_limit_hits (ip, created_at)")

        # [SEC-5] Login failures table — survives redeploys
        _ddl(conn, """CREATE TABLE IF NOT EXISTS login_failures (
            id """ + ("INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY") + """,
            username VARCHAR(80) NOT NULL,
            created_at TIMESTAMP NOT NULL
        )""")
        _ddl(conn, "CREATE INDEX IF NOT EXISTS ix_login_failures_user_time ON login_failures (username, created_at)")

        # Feature toggles — supervisor on/off switches for calls & WhatsApp
        _ddl(conn, """CREATE TABLE IF NOT EXISTS feature_toggles (
            key   VARCHAR(80) PRIMARY KEY,
            value VARCHAR(20) NOT NULL DEFAULT 'on',
            updated_at TIMESTAMP DEFAULT """ + ("CURRENT_TIMESTAMP" if is_sqlite else "NOW()") + """
        )""")
        # Seed defaults (all on) — INSERT OR IGNORE for SQLite, ON CONFLICT for PG
        _toggle_defaults = [
            "call_enabled", "call_status_PENDING", "call_status_OUT_FOR_DELIVERY",
            "call_status_FAILED", "call_status_RETURNED",
            "whatsapp_customer_enabled", "whatsapp_seller_enabled",
        ]
        for _tk in _toggle_defaults:
            if is_sqlite:
                conn.execute(text("INSERT OR IGNORE INTO feature_toggles (key, value) VALUES (:k, 'on')"), {"k": _tk})
            else:
                conn.execute(text("INSERT INTO feature_toggles (key, value) VALUES (:k, 'on') ON CONFLICT (key) DO NOTHING"), {"k": _tk})
        conn.commit()


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


def _schedule_daily_backup() -> None:
    """Run database backup once daily in a background thread."""
    import time
    def _backup_loop():
        while True:
            time.sleep(24 * 60 * 60)  # Wait 24 hours
            try:
                from backup_database import run_backup
                run_backup()
            except Exception as e:
                logging.getLogger("backup").error("Scheduled backup failed: %s", e)
    t = threading.Thread(target=_backup_loop, daemon=True)
    t.start()
    logging.getLogger("backup").info("Daily database backup scheduled.")


def _run_startup() -> None:
    ensure_schema()
    seed_default_branch_if_missing()
    seed_admin_if_missing()
    _schedule_daily_backup()


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
# Populate __all__ so `from app.core import *` includes underscore helpers.
# ─────────────────────────────────────────────────────────────────────────────
# Collect every public name defined in this module, plus the private helpers
# that routers rely on.
import types as _types
__all__ = [
    name for name, obj in globals().items()
    if not name.startswith("_")
    and not isinstance(obj, _types.ModuleType)
] + _EXPORT_PRIVATE
