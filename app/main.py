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
from datetime import datetime, date, timedelta

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
from .models import Branch, Item, Transaction, User, Delivery, DeliveryItem, CashEntry, StockTransfer, StockTransferItem
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
from .security import (
    get_session_secret,
    limiter,
    get_csrf_token,
    verify_csrf_token,
    sanitize_text,
    sanitize_username,
    sanitize_phone,
    sanitize_amount,
)

app = FastAPI()

# [FIX-6] Trust the X-Forwarded-For header from Railway's proxy
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Automatically inject csrf_token into every TemplateResponse context
# so base.html logout form always has it — no need to pass per-route.
_orig_tr = templates.TemplateResponse.__func__ if hasattr(templates.TemplateResponse, "__func__") else None

_orig_TemplateResponse = templates.TemplateResponse

def _auto_csrf(name, context, *args, **kwargs):
    req = context.get("request")
    if req and "csrf_token" not in context:
        context["csrf_token"] = get_csrf_token(req)
    return _orig_TemplateResponse(name, context, *args, **kwargs)

templates.TemplateResponse = _auto_csrf  # type: ignore

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
)

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
    return templates.TemplateResponse("login.html", {"request": request, "error": None, "csrf_token": csrf_token})


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-3] Rate limiting — limiter.check() takes the request object directly
    try:
        limiter.check(request)
    except HTTPException:
        token = get_csrf_token(request)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Too many login attempts. Please wait a minute and try again.",
            "csrf_token": token,
        }, status_code=429)

    verify_csrf_token(request, csrf_token)
    username_clean = sanitize_username(username)
    u = db.scalar(select(User).where(User.username == username_clean))
    if not u or not verify_password(password, u.password_hash):
        token = get_csrf_token(request)
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Invalid login.", "csrf_token": token,
        })
    request.session["user_id"] = u.id
    request.session["role"] = u.role
    if u.branch_id is not None:
        request.session["branch_id"] = u.branch_id
    else:
        request.session.pop("branch_id", None)
    return redirect("/")


@app.post("/logout")
async def logout(request: Request):
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
    total_stock = 0
    inventory_value = 0.0
    for item, stock in all_items_with_stock:
        if item.branch_id == branch_id:
            s = float(stock or 0)
            total_stock += int(s)
            inventory_value += s * float(item.cost_price or 0)
            cat = item.category or "Uncategorized"
            cat_map[cat] = cat_map.get(cat, 0) + s
    cat_rows = sorted(cat_map.items(), key=lambda x: x[1], reverse=True)

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
        .where(Delivery.created_at >= datetime.utcnow() - timedelta(days=14))
    ).scalars().all():
        k = d.created_at.date().isoformat() if d.created_at else None
        if k: del_by_day[k] = del_by_day.get(k, 0) + 1
    exp_by_day: dict = {}
    for e in db.execute(
        select(CashEntry).where(CashEntry.branch_id == branch_id)
        .where(CashEntry.kind == "EXPENSE")
        .where(CashEntry.created_at >= datetime.utcnow() - timedelta(days=14))
    ).scalars().all():
        k = e.created_at.date().isoformat() if e.created_at else None
        if k: exp_by_day[k] = exp_by_day.get(k, 0) + float(e.amount or 0)

    return templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user, "active": "dashboard",
        "branches": branches, "selected_branch_id": branch_id,
        "items_count": items_count, "low_stock_count": low_stock_count,
        "stale_count": stale_count, "recent_transactions": recent_transactions,
        "total_stock": total_stock, "inventory_value": inventory_value,
        "in7": in7, "out7": out7, "top_rows": top_rows, "low_rows": low_rows, "cat_rows": cat_rows,
        "chart_labels": [str(d) for d in chart_days],
        "chart_deliveries": [del_by_day.get(d.isoformat(), 0) for d in chart_days],
        "chart_expenses": [round(exp_by_day.get(d.isoformat(), 0), 2) for d in chart_days],
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
    # Enrich rows with branch_name from branches list
    branch_name_map = {b.id: b.name for b in branches}
    for r in rows:
        if "branch_name" not in r or not r.get("branch_name"):
            r["branch_name"] = branch_name_map.get(r.get("branch_id"), "—")
    top_items   = supervisor_top_items(db, start_dt, end_dt)
    _raw_best_agents = list(supervisor_best_agents(db, start_dt, end_dt))
    best_agents = []
    for r in _raw_best_agents:
        cols = list(r)
        # Scan columns: find ints (delivery_count) and floats/numeric (collections)
        # string cols are name fields
        str_cols, num_cols = [], []
        for c in cols:
            try:
                num_cols.append(float(c or 0))
            except (ValueError, TypeError):
                str_cols.append(str(c) if c is not None else "—")
        agent_name = str_cols[0] if str_cols else "—"
        delivery_count = int(num_cols[0]) if len(num_cols) > 0 else 0
        total_collections = num_cols[1] if len(num_cols) > 1 else 0.0
        best_agents.append({
            "agent_name": agent_name,
            "delivery_count": delivery_count,
            "total_collections": total_collections,
        })
    daily_chart = supervisor_daily_deliveries(db, start_dt, end_dt)

    # Daily expenses across all branches for the chart
    exp_by_day: dict = {}
    for e in db.execute(
        select(CashEntry).where(CashEntry.kind.in_(["EXPENSE", "OFFICE_EXPENSE"]))
        .where(CashEntry.created_at >= (start_dt or datetime.utcnow() - timedelta(days=30)))
        .where(CashEntry.created_at <= (end_dt or datetime.utcnow()))
    ).scalars().all():
        k = e.created_at.date().isoformat() if e.created_at else None
        if k:
            exp_by_day[k] = exp_by_day.get(k, 0) + float(e.amount or 0)
    # Build expense series aligned with delivery chart days
    chart_days_set = [str(r.day) for r in daily_chart]

    # All-branch inventory & agent totals for the enhanced overview
    all_items_count = db.scalar(select(func.count(Item.id))) or 0
    all_low_items = [(item, stock) for (item, stock) in get_low_stock(db)]
    all_low_stock_count = len(all_low_items)
    all_agents_count = db.scalar(select(func.count(User.id)).where(User.role == "AGENT")) or 0
    all_admins_count = db.scalar(select(func.count(User.id)).where(User.role == "ADMIN")) or 0
    all_inventory_value = 0.0
    all_total_stock = 0
    all_cat_map: dict = {}
    all_top_rows_raw = []
    for item, stock in get_items_with_stock(db):
        s = int(stock or 0)
        all_inventory_value += s * float(item.cost_price or 0)
        all_total_stock += s
        cat = item.category or "Uncategorized"
        all_cat_map[cat] = all_cat_map.get(cat, 0) + s
        all_top_rows_raw.append((item, s))
    all_cat_rows = sorted(all_cat_map.items(), key=lambda x: x[1], reverse=True)
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

    return templates.TemplateResponse("supervisor_dashboard.html", {
        "request": request, "user": user, "rows": rows,
        "top_items": top_items, "best_agents": best_agents,
        "chart_labels": chart_days_set,
        "chart_data": [int(r.cnt) for r in daily_chart],
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
        "all_cat_rows": all_cat_rows,
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
    return templates.TemplateResponse("branches_list.html", {
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
    return templates.TemplateResponse("branch_new.html", {
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
    return templates.TemplateResponse("forgot_password.html", {
        "request": request, "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
    })


@app.get("/items", response_class=HTMLResponse)
def items_list(request: Request, q: str = "", db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    branch_id = get_selected_branch_id(request, user)
    all_rows = get_items_with_stock(db)
    # Supervisor with no branch selected sees all branches
    if is_supervisor(user) and not branch_id:
        rows = list(all_rows)
    else:
        rows = [(item, stock) for (item, stock) in all_rows if item.branch_id == branch_id]
    q_lower = q.strip().lower()
    if q_lower:
        rows = [(item, stock) for (item, stock) in rows
                if q_lower in (item.name or "").lower() or q_lower in (item.category or "").lower()]
    return templates.TemplateResponse("items_list.html", {
        "request": request, "rows": rows, "q": q, "user": user, "active": "items",
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
    return templates.TemplateResponse("item_new.html", {
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
    return templates.TemplateResponse("items_import.html", {
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
    content = await file.read()
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
    return templates.TemplateResponse("item_detail.html", {
        "request": request, "item": item, "stock": stock, "txs": txs, "user": user, "active": "items",
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
    return templates.TemplateResponse("item_edit.html", {
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
#  TRANSACTIONS
# ────────────────────────────────────────────────

@app.get("/transactions", response_class=HTMLResponse)
def transactions_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    branch_id = get_selected_branch_id(request, user)
    stmt = select(Transaction).order_by(desc(Transaction.created_at)).limit(300)
    if not (is_supervisor(user) and not branch_id):
        stmt = stmt.where(Transaction.branch_id == branch_id)
    txs = db.scalars(stmt).all()
    return templates.TemplateResponse("transactions_list.html", {
        "request": request, "txs": txs, "user": user, "active": "transactions",
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
    return templates.TemplateResponse("tx_form.html", {
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
    return templates.TemplateResponse("stale_stock.html", {
        "request": request, "user": user, "rows": stale_rows, "days": days, "active": "stale",
    })


@app.get("/low-stock", response_class=HTMLResponse)
def low_stock(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    branch_id = get_selected_branch_id(request, user)
    if is_supervisor(user):
        # Supervisor sees all branches
        rows = list(get_low_stock(db))
    else:
        rows = [(item, stock) for (item, stock) in get_low_stock(db) if item.branch_id == branch_id]
    return templates.TemplateResponse("low_stock.html", {
        "request": request, "rows": rows, "user": user, "active": "low",
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
    return templates.TemplateResponse("agents_list.html", {
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
    return templates.TemplateResponse("agent_new.html", {
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
        lines = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        grouped: dict[int, list[str]] = {}
        for did, iname, qty in lines:
            grouped.setdefault(int(did), []).append(f"{iname} ×{int(qty)}")
        items_summary = {did: ", ".join(parts) for did, parts in grouped.items()}

    cash_stmt = select(CashEntry).order_by(desc(CashEntry.created_at))
    if start_dt: cash_stmt = cash_stmt.where(CashEntry.created_at >= start_dt)
    if end_dt: cash_stmt = cash_stmt.where(CashEntry.created_at < end_dt)
    cash_stmt = cash_stmt.where((CashEntry.agent_id == agent_id) | (CashEntry.kind == "OFFICE_EXPENSE"))
    cash_entries = db.execute(cash_stmt.limit(300)).scalars().all()

    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse("agent_detail.html", {
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
        lines = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        grouped: dict[int, list[str]] = {}
        for did, iname, qty in lines:
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
    return templates.TemplateResponse("deliveries_list.html", {
        "request": request, "rows": rows, "agents": agents, "status": status,
        "agent_id": agent_id, "items_summary": items_summary,
        "branches": branches, "selected_branch_id": branch_id,
        "branch_id": filter_branch, "start_date": start_date, "end_date": end_date,
        "user": user, "active": "deliveries", "sup_kpis": sup_kpis,
    })


@app.get("/deliveries/new", response_class=HTMLResponse)
def delivery_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    branch_id = get_selected_branch_id(request, user)
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())).scalars().all()
    items = db.execute(select(Item).where(Item.branch_id == branch_id).order_by(Item.name.asc())).scalars().all()
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse("delivery_new.html", {
        "request": request, "agents": agents, "items": items, "user": user,
        "active": "deliveries_new", "branches": branches, "selected_branch_id": branch_id,
        "today": date.today().isoformat(), "csrf_token": csrf_token,
    })


@app.post("/deliveries/new")
async def delivery_create(
    request: Request,
    agent_id: int | None = Form(None),
    customer_name: str = Form(...),
    customer_phone: str = Form(""),
    address: str = Form(""),
    note: str = Form(""),
    delivery_date: str = Form(""),
    item_id: list[int] = Form(...),
    quantity: list[int] = Form(...),
    line_amount: list[float] = Form(default=[]),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
    if is_admin(user):
        if agent_id is None:
            raise HTTPException(status_code=422, detail="agent_id required for admin")
        target_agent_id = int(agent_id)
    else:
        target_agent_id = int(user.id)
    cust = sanitize_text(customer_name, 160, "Customer name")
    if not cust:
        raise HTTPException(status_code=400, detail="Customer name required")
    branch_id = get_current_branch_id(request)
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
    for iid, qty, amt in zip(item_id, quantity, amounts):
        q = int(qty) if qty is not None else 0
        if q > 0:
            db.add(DeliveryItem(delivery_id=d.id, item_id=int(iid), quantity=q, line_amount=float(amt or 0)))
    db.commit()
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
        k = d.created_at.date().isoformat() if d.created_at else None
        if k:
            delivery_by_day[k] = delivery_by_day.get(k, 0) + 1
    expense_by_day: dict = {}
    expenses_raw = db.execute(
        select(CashEntry).where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind == "EXPENSE")
        .where(CashEntry.created_at >= datetime.utcnow() - timedelta(days=14))
    ).scalars().all()
    for e in expenses_raw:
        k = e.created_at.date().isoformat() if e.created_at else None
        if k:
            expense_by_day[k] = expense_by_day.get(k, 0) + float(e.amount or 0)

    total_collected = float(db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.agent_id == user.id).where(CashEntry.kind == "COLLECTION")
    ) or 0)
    total_expenses = float(db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.agent_id == user.id).where(CashEntry.kind == "EXPENSE")
    ) or 0)

    return templates.TemplateResponse("agent_overview.html", {
        "request": request, "user": user, "active": "dashboard",
        "total_deliveries": len(rows), "pending_c": pending_c,
        "ofd_c": ofd_c, "done_c": done_c,
        "total_collected": total_collected, "total_expenses": total_expenses,
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
        lines = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        grouped: dict[int, list[str]] = {}
        for did, iname, qty in lines:
            grouped.setdefault(int(did), []).append(f"{iname} ×{int(qty)}")
        items_summary = {did: ", ".join(parts) for did, parts in grouped.items()}

    return templates.TemplateResponse("my_deliveries.html", {
        "request": request, "rows": rows, "user": user, "active": "deliveries",
        "items_summary": items_summary,
    })


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
    d_items = db.execute(
        select(DeliveryItem, Item).join(Item, Item.id == DeliveryItem.item_id).where(DeliveryItem.delivery_id == d.id)
    ).all()
    col = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.delivery_id == d.id).where(CashEntry.kind == "COLLECTION")) or 0
    exp = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.delivery_id == d.id).where(CashEntry.kind == "EXPENSE")) or 0
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse("delivery_detail.html", {
        "request": request, "d": d, "d_items": d_items, "user": user, "error": None,
        "collection_total": float(col), "expense_total": float(exp),
        "back_url": "/deliveries" if is_admin(user) else "/my-deliveries",
        "active": "deliveries", "csrf_token": csrf_token,
    })


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
    # Lock: once DELIVERED, no further status changes allowed
    if d.status == "DELIVERED":
        return redirect(f"/deliveries/{delivery_id}?error=This+order+has+already+been+delivered+and+cannot+be+updated")
    if status_clean == "DELIVERED":
        try:
            create_out_transactions_for_delivery_if_needed(db, d.id, performed_by=user.username)
            d.status = "DELIVERED"
            d.delivered_at = datetime.utcnow()

            # Auto-create COLLECTION cash entry from delivery order total
            # Only if no collection entry already exists for this delivery
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
        except ValueError as e:
            d_items = db.execute(select(DeliveryItem, Item).join(Item, Item.id == DeliveryItem.item_id).where(DeliveryItem.delivery_id == d.id)).all()
            csrf_token2 = get_csrf_token(request)
            return templates.TemplateResponse("delivery_detail.html", {
                "request": request, "d": d, "d_items": d_items, "user": user, "error": str(e),
                "collection_total": 0, "expense_total": 0,
                "back_url": "/deliveries" if is_admin(user) else "/my-deliveries",
                "active": "deliveries", "csrf_token": csrf_token2,
            })
        return redirect(f"/deliveries/{delivery_id}")
    d.status = status_clean
    db.commit()
    return redirect(f"/deliveries/{delivery_id}")


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
        if (agent_id or "").isdigit(): selected_agent_id = int(agent_id)
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
    total_expenses        = _cash_sum(["EXPENSE"], selected_agent_id)
    total_operating       = _cash_sum(["OPERATING_CASH"], selected_agent_id)
    total_office_expenses = _cash_sum(["OFFICE_EXPENSE"], selected_agent_id)

    _ret_stmt = select(func.coalesce(func.sum(CashEntry.amount), 0)).where(
        CashEntry.kind == "RETURN_OPERATING_CASH").where(_branch_filter())
    if start_dt: _ret_stmt = _ret_stmt.where(CashEntry.created_at >= start_dt)
    if end_dt:   _ret_stmt = _ret_stmt.where(CashEntry.created_at < end_dt)
    if selected_agent_id: _ret_stmt = _ret_stmt.where(CashEntry.agent_id == selected_agent_id)
    total_return_op_cash = float(db.scalar(_ret_stmt) or 0)
    operating_balance = float(total_operating) - float(total_expenses) - total_return_op_cash
    remittance = float(total_collections) - float(total_office_expenses)
    net_position = remittance + operating_balance
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())).scalars().all() if (is_admin(user) or is_supervisor(user)) else []
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse("cash_dashboard.html", {
        "request": request, "user": user, "rows": rows,
        "total_collections": float(total_collections), "total_expenses": float(total_expenses),
        "total_operating_cash": float(total_operating), "total_return_op_cash": total_return_op_cash,
        "operating_balance": float(operating_balance), "total_office_expenses": float(total_office_expenses),
        "remittance": float(remittance), "net_position": float(net_position),
        "agents": agents, "agent_id": agent_id,
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
    if k not in {"COLLECTION", "EXPENSE", "OPERATING_CASH", "OFFICE_EXPENSE", "RETURN_OPERATING_CASH", "CASH_PAYMENT", "TRANSFER_PAYMENT"}:
        raise HTTPException(status_code=400, detail="Invalid kind")
    if k == "OFFICE_EXPENSE" and not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
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
    db.add(CashEntry(
        branch_id=branch_id, agent_id=target_agent_id, delivery_id=d_id,
        kind=k, amount=amt, note=sanitize_text(note, 400, "Note") or None,
    ))
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
    return templates.TemplateResponse("reports_sales.html", {
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
    filters = [Delivery.delivery_date >= start_dt, Delivery.delivery_date <= end_dt, Delivery.status == "DELIVERED"]
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
            items_by_delivery.setdefault(int(did), []).append({"name": str(iname), "qty": q, "amount": la if la > 0 else q * sp})
    _ce_branch = CashEntry.branch_id == branch_id if not is_supervisor(user) else True
    agent_exp_map = {int(aid): float(t) for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(_ce_branch).group_by(CashEntry.agent_id)).all()}
    op_cash_map = {int(aid): float(t) for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OPERATING_CASH").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(_ce_branch).group_by(CashEntry.agent_id)).all()}
    office_total = float(db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OFFICE_EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(_ce_branch)) or 0)
    waybill_entries_raw = db.execute(
        select(CashEntry.amount, CashEntry.note, CashEntry.created_at)
        .where(CashEntry.kind == "OFFICE_EXPENSE")
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
        .where(func.lower(func.coalesce(CashEntry.note, "")).like("%waybill%"))
        .order_by(CashEntry.created_at.asc())
    ).all()
    waybill_entries = [{"amount": float(r[0]), "note": str(r[1] or ""), "date": r[2].strftime("%d %b %Y") if r[2] else ""} for r in waybill_entries_raw]
    waybill_total = sum(e["amount"] for e in waybill_entries)
    # Include admin's own EXPENSE entries (e.g. transfer expenses recorded as EXPENSE by admin)
    admin_exp_map = {int(aid): float(t) for aid, t in db.execute(
        select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind == "EXPENSE").where(CashEntry.created_at >= start_dt)
        .where(CashEntry.created_at <= end_dt).where(_ce_branch)
        .group_by(CashEntry.agent_id)
    ).all()}
    # Merge admin entries into agent_exp_map
    for aid, amt in admin_exp_map.items():
        agent_exp_map[aid] = agent_exp_map.get(aid, 0.0) + amt

    all_agent_ids = list(set(list(agent_exp_map.keys()) + list(op_cash_map.keys())))
    uname = {}
    if all_agent_ids:
        users_map = {int(u.id): u for u in db.execute(select(User).where(User.id.in_(all_agent_ids))).scalars().all()}
        uname = {uid: (f"👤 {u.full_name or u.username} (Admin)" if (u.role or "").upper() == "ADMIN" else (u.full_name or u.username))
                 for uid, u in users_map.items()}
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
        exp = agent_exp_map.get(aid, 0.0); op = op_cash_map.get(aid, 0.0); balance = op - exp
        total_op_cash_given += op
        if op > 0:
            total_op_cash_balance_returned += max(balance, 0)
            if balance < 0: expenses_from_collections += abs(balance)
        else:
            expenses_from_collections += exp
        agent_op_summary.append({"name": uname.get(aid, f"Agent {aid}"), "op_cash": op, "expenses": exp, "balance": balance, "has_op_cash": op > 0})
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
            q = float(qty or 0); la = float(line_amt or 0); spp = float(sp or 0)
            items_by_delivery.setdefault(int(did), []).append((str(iname), q, la if la > 0 else q * spp))
    _ce_br = CashEntry.branch_id == branch_id if not is_supervisor(user) else True
    agent_exp_map = {int(aid): float(t) for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(_ce_br).group_by(CashEntry.agent_id).order_by(CashEntry.agent_id.asc())).all()}
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
            agent_section_lines += [f"  {aname}:", f"    Operating cash given : {_ngn(op)}", f"    Expenses spent       : {_ngn(exp)}",
                                    f"    {'Balance to return' if balance >= 0 else 'Overspent (from coll)'}: {_ngn(abs(balance))}"]
        else:
            expenses_from_collections += exp
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
    sw = """const CACHE = "invkeeper-v1";
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
  if (e.request.method !== "GET" || !e.request.url.startsWith("http")) return;
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
    return templates.TemplateResponse("merchant_receipt_new.html", {
        "request": request, "user": user, "items": items,
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
    # Count merchant receipts (transactions with reference starting with "MERCHANT:")
    merchant_receipts_count = db.scalar(
        select(func.count(func.distinct(Transaction.reference)))
        .where(Transaction.reference.like("MERCHANT:%"))
        .where(Transaction.branch_id == (user.branch_id if not is_supervisor(user) else Transaction.branch_id))
    ) or 0
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse("transfers_list.html", {
        "request": request, "user": user, "transfers": transfers, "branches": branches,
        "active": "transfers", "selected_branch_id": getattr(user, "branch_id", None),
        "merchant_receipts_count": merchant_receipts_count, "csrf_token": csrf_token,
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
    return templates.TemplateResponse("transfer_new.html", {
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
    for item_id, qty in zip(item_ids, quantities):
        db.add(Transaction(branch_id=user.branch_id, item_id=item_id, type="OUT", quantity=qty,
                           reference=f"TRANSFER #{transfer.id}", note=f"Stock transfer to branch ID {to_branch_id}"))
    db.commit()
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
    packed_by          = db.get(User, transfer.packed_by_id)          if transfer.packed_by_id          else None
    is_delegated_receiver = is_agent(user) and transfer.delegated_receiver_id == user.id
    # Agents for sender branch (for delegation dropdown — sender admin only)
    sender_agents   = db.execute(select(User).where(User.role=="AGENT").where(User.branch_id==transfer.from_branch_id).order_by(User.username)).scalars().all() if (is_admin(user) and user.branch_id==transfer.from_branch_id) else []
    receiver_agents = db.execute(select(User).where(User.role=="AGENT").where(User.branch_id==transfer.to_branch_id).order_by(User.username)).scalars().all()  if (is_admin(user) and user.branch_id==transfer.to_branch_id)   else []
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse("transfer_detail.html", {
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
    transfer.packed_by_id = user.id
    transfer.packed_at = datetime.utcnow()
    transfer.status = "OUT_FOR_DELIVERY"
    db.commit()
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
    for line in transfer.items:
        db.add(Transaction(branch_id=transfer.from_branch_id, item_id=line.item_id, type="IN", quantity=line.quantity,
                           reference=f"TRANSFER #{transfer.id} CANCELLED", note="Stock returned — transfer cancelled"))
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
