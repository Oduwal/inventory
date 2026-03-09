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
    if not agent or (agent.role or "").upper() != "AGENT":
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
    if not is_admin(user):
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

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    # [FIX-4] Generate CSRF token for the login form
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None,
        "csrf_token": csrf_token,
    })


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-3] Rate limit: max 10 login attempts per IP per 60 seconds
    limiter.check(request, max_requests=10, window_seconds=60)

    # [FIX-4] Verify CSRF token
    verify_csrf_token(request, csrf_token)

    u = db.scalar(select(User).where(User.username == username.strip()))
    if not u or not verify_password(password, u.password_hash):
        new_csrf = get_csrf_token(request)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid login.",
            "csrf_token": new_csrf,
        })

    request.session["user_id"] = u.id
    request.session["role"] = u.role
    if u.branch_id is not None:
        request.session["branch_id"] = u.branch_id
    else:
        request.session.pop("branch_id", None)
    return redirect("/")


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form("")):
    # [FIX-4] CSRF check on logout too (prevents logout CSRF attacks)
    verify_csrf_token(request, csrf_token)
    request.session.clear()
    return redirect("/login")


# ─────────────────────────────────────────────────────────────────────────────
# ITEMS
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/items", response_class=HTMLResponse)
def items_list(request: Request, q: str = "", db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    branch_id = get_selected_branch_id(request, user)
    rows = [(item, stock) for (item, stock) in get_items_with_stock(db) if item.branch_id == branch_id]
    q_lower = q.strip().lower()
    if q_lower:
        rows = [
            (item, stock) for (item, stock) in rows
            if q_lower in ((item.name or "").lower()) or q_lower in ((item.category or "").lower())
        ]
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse(
        "items_list.html",
        {"request": request, "rows": rows, "q": q, "user": user, "active": "items", "csrf_token": csrf_token},
    )


@app.get("/items/new", response_class=HTMLResponse)
def item_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    error = request.query_params.get("error")
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse("item_new.html", {
        "request": request, "user": user, "error": error, "active": "items", "csrf_token": csrf_token
    })


@app.post("/items/new")
def item_create(
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
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    # [FIX-5] Sanitize inputs
    name_clean = sanitize_text(name, max_length=200, field_name="name")
    if not name_clean:
        return redirect("/items/new?error=Name+is+required")
    category_clean = sanitize_text(category, max_length=120, field_name="category") or None
    unit_clean = sanitize_text(unit, max_length=20, field_name="unit") or "pcs"

    branch_id = get_current_branch_id(request)
    if not branch_id:
        return redirect("/items/new?error=No+branch+assigned")

    db.add(Item(
        branch_id=branch_id,
        name=name_clean,
        category=category_clean,
        unit=unit_clean,
        reorder_level=int(reorder_level or 0),
        cost_price=float(cost_price or 0),
        selling_price=float(selling_price or 0),
    ))
    db.commit()
    return redirect("/items")


@app.post("/items/{item_id}/edit")
def item_edit_save(
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
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    item = db.get(Item, item_id)
    require_item_access(request, user, item)

    # [FIX-5] Sanitize
    name_clean = sanitize_text(name, max_length=200, field_name="name")
    if not name_clean:
        return redirect(f"/items/{item_id}/edit?error=Name+is+required")

    item.name = name_clean
    item.category = sanitize_text(category, max_length=120) or None
    item.unit = sanitize_text(unit, max_length=20) or "pcs"
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
            row = get_item_with_stock(db, item_id)
            current_stock = int(row[1]) if row else 0
            if current_stock < aq:
                return redirect(f"/items/{item_id}/edit?error=Insufficient+stock+for+OUT+adjustment")
        db.add(Transaction(
            branch_id=item.branch_id,
            item_id=item_id,
            type=at,
            quantity=aq,
            reference=f"MANUAL ADJUST #{item_id}",
            note=sanitize_text(adjust_note, max_length=400) or f"Manual stock adjust by {user.username}",
        ))

    db.commit()
    return redirect(f"/items/{item_id}")


# ─────────────────────────────────────────────────────────────────────────────
# AGENTS
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/agents/new")
def agent_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(""),
    phone: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    # [FIX-5] Sanitize username
    try:
        uname = sanitize_username(username)
    except HTTPException:
        return redirect("/agents/new?error=Invalid+username+format")

    if not uname:
        return redirect("/agents/new?error=Username+is+required")

    if db.scalar(select(User).where(User.username == uname)):
        return redirect("/agents/new?error=Username+already+exists")

    # [FIX-7] Minimum password length raised to 8
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return redirect(f"/agents/new?error=Password+must+be+at+least+{MIN_PASSWORD_LENGTH}+characters")

    if not user.branch_id:
        return redirect("/agents/new?error=Admin+has+no+branch+assigned")

    # [FIX-5] Sanitize optional fields
    full_name_clean = sanitize_text(full_name, max_length=140, field_name="full_name") or None
    phone_clean = sanitize_phone(phone) or None

    db.add(User(
        username=uname,
        password_hash=hash_password(password),
        role="AGENT",
        branch_id=user.branch_id,
        full_name=full_name_clean,
        phone=phone_clean,
    ))
    db.commit()
    return redirect("/agents")


# ─────────────────────────────────────────────────────────────────────────────
# DELIVERIES
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/deliveries/new")
def delivery_create(
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
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if is_admin(user):
        if agent_id is None:
            raise HTTPException(status_code=422, detail="agent_id required for admin")
        target_agent_id = int(agent_id)
    else:
        target_agent_id = int(user.id)

    # [FIX-5] Sanitize free text fields
    cust = sanitize_text(customer_name, max_length=160, field_name="customer_name")
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
        branch_id=branch_id,
        agent_id=target_agent_id,
        customer_name=cust,
        customer_phone=sanitize_phone(customer_phone) or None,
        address=sanitize_text(address, max_length=300, field_name="address") or None,
        note=sanitize_text(note, max_length=400, field_name="note") or None,
        status="PENDING",
        delivery_date=d_date,
    )
    db.add(d)
    db.flush()

    amounts = list(line_amount or [])
    while len(amounts) < len(item_id):
        amounts.append(0.0)

    for iid, qty, amt in zip(item_id, quantity, amounts):
        q = int(qty) if qty is not None else 0
        if q > 0:
            db.add(DeliveryItem(
                delivery_id=d.id,
                item_id=int(iid),
                quantity=q,
                line_amount=float(amt or 0),
            ))

    db.commit()
    return redirect(f"/deliveries/{d.id}")


@app.post("/deliveries/{delivery_id}/status")
def update_delivery_status(
    request: Request,
    delivery_id: int,
    status: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    d = db.get(Delivery, delivery_id)
    require_delivery_access(request, user, d)

    if not is_admin(user) and not is_supervisor(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)

    status_clean = (status or "").strip().upper()
    allowed = {"PENDING", "OUT_FOR_DELIVERY", "DELIVERED", "FAILED", "RETURNED"}
    if status_clean not in allowed:
        raise HTTPException(status_code=400, detail="Invalid status")

    if status_clean == "DELIVERED":
        try:
            create_out_transactions_for_delivery_if_needed(db, d.id, performed_by=user.username)
            d.status = "DELIVERED"
            d.delivered_at = datetime.utcnow()
            db.commit()
        except ValueError as e:
            d_items = db.execute(
                select(DeliveryItem, Item).join(Item, Item.id == DeliveryItem.item_id)
                .where(DeliveryItem.delivery_id == d.id)
            ).all()
            return templates.TemplateResponse("delivery_detail.html", {
                "request": request, "d": d, "d_items": d_items, "user": user,
                "error": str(e), "collection_total": 0, "expense_total": 0,
                "back_url": "/deliveries" if is_admin(user) else "/my-deliveries",
                "active": "deliveries",
            })
        return redirect(f"/deliveries/{delivery_id}")

    d.status = status_clean
    db.commit()
    return redirect(f"/deliveries/{delivery_id}")


# ─────────────────────────────────────────────────────────────────────────────
# CASH
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/cash/new")
def cash_new(
    request: Request,
    kind: str = Form(...),
    amount: float = Form(...),
    note: str = Form(""),
    delivery_id: str = Form(""),
    agent_id: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    k = (kind or "").strip().upper()
    if k not in {"COLLECTION", "EXPENSE", "OPERATING_CASH", "OFFICE_EXPENSE", "RETURN_OPERATING_CASH"}:
        raise HTTPException(status_code=400, detail="Invalid kind")

    if k == "OFFICE_EXPENSE" and not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)

    # [FIX-5] Validate amount
    amt = sanitize_amount(amount, field_name="amount")

    target_agent_id = user.id
    if is_admin(user) and (agent_id or "").isdigit():
        target_agent_id = int(agent_id)

    if k == "OFFICE_EXPENSE":
        target_agent_id = user.id

    d_id = int(delivery_id) if (delivery_id or "").isdigit() else None

    branch_id = get_current_branch_id(request)
    if not branch_id:
        raise HTTPException(status_code=400, detail="No branch assigned")

    db.add(CashEntry(
        branch_id=branch_id,
        agent_id=target_agent_id,
        delivery_id=d_id,
        kind=k,
        amount=amt,
        note=sanitize_text(note, max_length=400, field_name="note") or None,
    ))
    db.commit()

    if d_id:
        return redirect(f"/deliveries/{d_id}")
    return redirect("/cash")


# ─────────────────────────────────────────────────────────────────────────────
# BRANCHES
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/branches/new")
def branch_create(
    request: Request,
    name: str = Form(...),
    code: str = Form(""),
    address: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not is_supervisor(user):
        return HTMLResponse("Forbidden", status_code=403)

    # [FIX-5] Sanitize
    name_clean = sanitize_text(name, max_length=120, field_name="name")
    code_clean = sanitize_text(code, max_length=20, field_name="code") or None
    address_clean = sanitize_text(address, max_length=200, field_name="address") or None

    if not name_clean:
        return redirect("/branches/new?error=Branch+name+is+required")

    existing_name = db.scalar(select(Branch).where(Branch.name == name_clean))
    if existing_name:
        return redirect("/branches/new?error=Branch+name+already+exists")

    if code_clean:
        existing_code = db.scalar(select(Branch).where(Branch.code == code_clean))
        if existing_code:
            return redirect("/branches/new?error=Branch+code+already+exists")

    db.add(Branch(name=name_clean, code=code_clean, address=address_clean))
    db.commit()
    return redirect("/branches")


# ─────────────────────────────────────────────────────────────────────────────
# TRANSFERS
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/transfers/new")
def transfer_create(
    request: Request,
    to_branch_id: int = Form(...),
    note: str = Form(""),
    item_ids: list[int] = Form(...),
    quantities: list[int] = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)

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

    transfer = StockTransfer(
        from_branch_id=user.branch_id,
        to_branch_id=to_branch_id,
        status="PENDING",
        note=sanitize_text(note, max_length=400) or None,
        created_by_id=user.id,
    )
    db.add(transfer)
    db.flush()

    for item_id, qty in zip(item_ids, quantities):
        db.add(StockTransferItem(transfer_id=transfer.id, item_id=item_id, quantity=qty))

    for item_id, qty in zip(item_ids, quantities):
        db.add(Transaction(
            branch_id=user.branch_id,
            item_id=item_id,
            type="OUT",
            quantity=qty,
            reference=f"TRANSFER #{transfer.id}",
            note=f"Stock transfer to branch ID {to_branch_id}",
        ))

    db.commit()
    return redirect(f"/transfers/{transfer.id}")


@app.post("/transfers/{transfer_id}/receive")
def transfer_receive(
    transfer_id: int,
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)

    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    if transfer.to_branch_id != user.branch_id:
        return HTMLResponse("Forbidden — you are not the receiving branch", status_code=403)

    if transfer.status != "PENDING":
        return redirect(f"/transfers/{transfer_id}?error=Transfer+is+already+{transfer.status}")

    for line in transfer.items:
        dest_item = db.scalar(
            select(Item).where(Item.branch_id == user.branch_id, Item.name == line.item.name)
        )
        if not dest_item:
            dest_item = Item(
                branch_id=user.branch_id,
                name=line.item.name,
                category=line.item.category,
                unit=line.item.unit,
                reorder_level=line.item.reorder_level,
                cost_price=line.item.cost_price,
                selling_price=line.item.selling_price,
            )
            db.add(dest_item)
            db.flush()

        db.add(Transaction(
            branch_id=user.branch_id,
            item_id=dest_item.id,
            type="IN",
            quantity=line.quantity,
            reference=f"TRANSFER #{transfer.id}",
            note=f"Stock received from branch {transfer.from_branch.name}",
        ))

    transfer.status = "RECEIVED"
    transfer.received_by_id = user.id
    transfer.received_at = datetime.utcnow()
    db.commit()
    return redirect(f"/transfers/{transfer_id}")


@app.post("/transfers/{transfer_id}/cancel")
def transfer_cancel(
    transfer_id: int,
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)

    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    if user.branch_id not in (transfer.from_branch_id, transfer.to_branch_id):
        return HTMLResponse("Forbidden", status_code=403)

    if transfer.status != "PENDING":
        return redirect(f"/transfers/{transfer_id}?error=Transfer+is+already+{transfer.status}")

    for line in transfer.items:
        db.add(Transaction(
            branch_id=transfer.from_branch_id,
            item_id=line.item_id,
            type="IN",
            quantity=line.quantity,
            reference=f"TRANSFER #{transfer.id} CANCELLED",
            note="Stock returned — transfer cancelled",
        ))

    transfer.status = "CANCELLED"
    transfer.cancelled_by_id = user.id
    transfer.cancelled_at = datetime.utcnow()
    db.commit()
    return redirect(f"/transfers/{transfer_id}")


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN: RESET SYSTEM  [FIX-8] Now POST-only with CSRF + confirmation token
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/admin/reset-system", response_class=HTMLResponse)
def reset_system_form(request: Request, db: Session = Depends(get_db)):
    """Shows a confirmation page before allowing a database reset."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    csrf_token = get_csrf_token(request)
    # Simple inline confirmation page — replace with a proper template if preferred
    html_content = f"""
    <!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px;background:#0b1220;color:#e7eefc">
    <h2 style="color:#ef4444">⚠️ Danger: Reset System</h2>
    <p>This will permanently delete ALL transactions, deliveries, delivery items, and cash entries.</p>
    <p>This action <strong>cannot be undone</strong>.</p>
    <form method="post" action="/admin/reset-system">
        <input type="hidden" name="csrf_token" value="{csrf_token}" />
        <label style="display:block;margin-bottom:10px">
            Type <strong>RESET</strong> to confirm:
            <input name="confirm" type="text" style="margin-left:10px;padding:6px;border-radius:6px;border:1px solid #555;background:#1a2b63;color:#fff" />
        </label>
        <button type="submit" style="background:#ef4444;color:white;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:bold">
            Reset Database
        </button>
        <a href="/" style="margin-left:20px;color:#a7b4d6">Cancel</a>
    </form>
    </body></html>
    """
    return HTMLResponse(html_content)


@app.post("/admin/reset-system")
def reset_system(
    request: Request,
    confirm: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    """[FIX-8] Now requires POST + CSRF + typed confirmation. No more accidental GET resets."""
    # [FIX-4] CSRF check
    verify_csrf_token(request, csrf_token)

    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    if (confirm or "").strip() != "RESET":
        return HTMLResponse(
            "Confirmation failed. Please type RESET exactly. <a href='/admin/reset-system'>Go back</a>",
            status_code=400,
        )

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
    return {"status": "Database reset complete"}


# ─────────────────────────────────────────────────────────────────────────────
# PWA / STATIC HELPERS  (unchanged from original)
# ─────────────────────────────────────────────────────────────────────────────

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
    sw = """
const CACHE = "invkeeper-v1";
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
});
"""
    return PlainTextResponse(sw, headers={"Content-Type": "application/javascript"})

# NOTE: /debug-login has been REMOVED. [FIX-2]
# If you need to test login, do it through the normal /login page.
