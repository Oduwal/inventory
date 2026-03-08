# app/main.py
import os
from datetime import datetime, date, timedelta

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from passlib.context import CryptContext
import bcrypt as bcrypt_lib

from sqlalchemy import select, text, func, and_, desc
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

app = FastAPI()

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

SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me")
HTTPS_ONLY = os.getenv("HTTPS_ONLY", "1") not in {"0", "false", "False", "no", "NO"}

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=HTTPS_ONLY,
    same_site="lax",
)

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


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

    # Supervisor can switch branch with ?branch_id=...
    if is_supervisor(user):
        q_branch = request.query_params.get("branch_id", "").strip()
        if q_branch.isdigit():
            return int(q_branch)

    # Normal users always use their assigned branch
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
    """Execute a single DDL statement, rolling back on error so the connection stays usable."""
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

    # Use AUTOCOMMIT so every statement is its own transaction.
    # On PostgreSQL a failed SELECT inside a regular transaction poisons the
    # whole connection, causing subsequent ALTER TABLE commits to silently
    # do nothing.  AUTOCOMMIT avoids that entirely.
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:

        # branches table
        _ddl(conn, """
            CREATE TABLE IF NOT EXISTS branches (
                id """ + ("INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY") + """,
                name VARCHAR(120) NOT NULL UNIQUE,
                code VARCHAR(20) NULL UNIQUE,
                address VARCHAR(200) NULL,
                created_at TIMESTAMP DEFAULT """ + ("CURRENT_TIMESTAMP" if is_sqlite else "NOW()") + """
            )
        """)

        # users – new columns
        _ddl(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL")
        _ddl(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(140) NULL")
        _ddl(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(40) NULL")

        # items.branch_id
        _ddl(conn, "ALTER TABLE items ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL")

        # deliveries
        _ddl(conn, "ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL")
        _ddl(conn, "ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMP NULL")

        # transactions
        _ddl(conn, "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL")
        _ddl(conn, "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS delivery_id INTEGER NULL")

        # cash_entries table + branch_id column
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

        # delivery_items.line_amount
        _ddl(conn, "ALTER TABLE delivery_items ADD COLUMN IF NOT EXISTS line_amount NUMERIC DEFAULT 0")

        # indexes
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

        # stock_transfers table
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

        # stock_transfer_items table
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
        # Ensure default branch exists
        row = db.execute(
            text("SELECT id FROM branches WHERE name = 'Main Branch' LIMIT 1")
        ).first()

        if row:
            default_branch_id = int(row[0])
        else:
            db.execute(
                text(
                    """
                    INSERT INTO branches (name, code, address, created_at)
                    VALUES ('Main Branch', 'MAIN', NULL, NOW())
                    """
                )
            )
            db.commit()

            row = db.execute(
                text("SELECT id FROM branches WHERE name = 'Main Branch' LIMIT 1")
            ).first()
            default_branch_id = int(row[0])

        # Update old rows with no branch_id using raw SQL
        db.execute(
            text(
                """
                UPDATE users
                SET branch_id = :branch_id
                WHERE branch_id IS NULL
                  AND role <> 'SUPERVISOR'
                """
            ),
            {"branch_id": default_branch_id},
        )

        db.execute(
            text(
                """
                UPDATE items
                SET branch_id = :branch_id
                WHERE branch_id IS NULL
                """
            ),
            {"branch_id": default_branch_id},
        )

        db.execute(
            text(
                """
                UPDATE deliveries
                SET branch_id = :branch_id
                WHERE branch_id IS NULL
                """
            ),
            {"branch_id": default_branch_id},
        )

        db.execute(
            text(
                """
                UPDATE transactions
                SET branch_id = :branch_id
                WHERE branch_id IS NULL
                """
            ),
            {"branch_id": default_branch_id},
        )

        db.execute(
            text(
                """
                UPDATE cash_entries
                SET branch_id = :branch_id
                WHERE branch_id IS NULL
                """
            ),
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


def _range_dates_from_inputs(
    preset: str | None,
    start_date: str | None,
    end_date: str | None,
) -> tuple[date | None, date | None, str]:
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


def _dt_range_from_dates(preset: str, start_date: str, end_date: str):
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


# ---------------- Auth ----------------

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    u = db.scalar(select(User).where(User.username == username.strip()))
    if not u or not verify_password(password, u.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid login."})

    request.session["user_id"] = u.id
    request.session["role"] = u.role
    # Only persist branch_id when actually assigned; absence is handled by get_current_branch_id
    if u.branch_id is not None:
        request.session["branch_id"] = u.branch_id
    else:
        request.session.pop("branch_id", None)
    return redirect("/")


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


# ---------------- Dashboard ----------------

@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    branch_id = get_selected_branch_id(request, user)

    # Supervisor dashboard = overview for selected branch
    if is_supervisor(user):
        if not branch_id:
            branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()
            return templates.TemplateResponse(
                "dashboard.html",
                {
                    "request": request,
                    "user": user,
                    "active": "dashboard",
                    "branches": branches,
                    "selected_branch_id": None,
                    "items_count": 0,
                    "low_stock_count": 0,
                    "recent_transactions": [],
                    "total_stock": 0,
                    "inventory_value": 0,
                    "in7": 0,
                    "out7": 0,
                    "top_rows": [],
                    "low_rows": [],
                    "cat_rows": [],
                },
            )

    if not is_admin(user) and not is_supervisor(user):
        return redirect("/my-deliveries")

    # Branch-filtered dashboard values
    items_stmt = select(Item).where(Item.branch_id == branch_id)
    items = db.execute(items_stmt).scalars().all()
    item_ids = [i.id for i in items]

    items_count = len(items)

    low_rows_all = get_low_stock(db)
    low_rows = [(item, stock) for (item, stock) in low_rows_all if item.branch_id == branch_id][:5]
    low_stock_count = len([(item, stock) for (item, stock) in low_rows_all if item.branch_id == branch_id])

    recent_transactions = db.scalars(
        select(Transaction)
        .where(Transaction.branch_id == branch_id)
        .order_by(desc(Transaction.created_at))
        .limit(10)
    ).all()

    top_rows_all = top_items_by_stock(db, limit=200)
    top_rows = [(item, stock) for (item, stock) in top_rows_all if item.branch_id == branch_id][:5]

    # Build category breakdown and compute stock totals in a single pass
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

    in7 = int(
        db.scalar(
            select(func.coalesce(func.sum(Transaction.quantity), 0))
            .where(Transaction.branch_id == branch_id)
            .where(Transaction.type == "IN")
            .where(Transaction.created_at >= datetime.utcnow() - timedelta(days=7))
        ) or 0
    )

    out7 = int(
        db.scalar(
            select(func.coalesce(func.sum(Transaction.quantity), 0))
            .where(Transaction.branch_id == branch_id)
            .where(Transaction.type == "OUT")
            .where(Transaction.created_at >= datetime.utcnow() - timedelta(days=7))
        ) or 0
    )

    branches = []
    if is_supervisor(user):
        branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "active": "dashboard",
            "branches": branches,
            "selected_branch_id": branch_id,
            "items_count": items_count,
            "low_stock_count": low_stock_count,
            "recent_transactions": recent_transactions,
            "total_stock": total_stock,
            "inventory_value": inventory_value,
            "in7": in7,
            "out7": out7,
            "top_rows": top_rows,
            "low_rows": low_rows,
            "cat_rows": cat_rows,
        },
    )

@app.get("/supervisor", response_class=HTMLResponse)
def supervisor_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    preset: str = "",
    start_date: str = "",
    end_date: str = "",
):
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
    top_items     = supervisor_top_items(db, start_dt, end_dt)
    best_agents   = supervisor_best_agents(db, start_dt, end_dt)
    daily_chart   = supervisor_daily_deliveries(db, start_dt, end_dt)

    grand_total_deliveries       = sum(r["total_deliveries"] for r in rows)
    grand_delivered              = sum(r["delivered_count"] for r in rows)
    grand_pending                = sum(r["pending_count"] for r in rows)
    grand_out_for_delivery       = sum(r["out_for_delivery_count"] for r in rows)
    grand_failed                 = sum(r["failed_count"] for r in rows)
    grand_collections            = sum(r["collections"] for r in rows)
    grand_agent_expenses         = sum(r["agent_expenses"] for r in rows)
    grand_office_expenses        = sum(r["office_expenses"] for r in rows)
    grand_operating_cash         = sum(r["operating_cash"] for r in rows)
    grand_returned_operating_cash = sum(r["returned_operating_cash"] for r in rows)
    grand_operating_balance      = sum(r["operating_balance"] for r in rows)
    grand_remittance             = sum(r["remittance"] for r in rows)

    chart_labels = [str(r.day) for r in daily_chart]
    chart_data   = [int(r.cnt) for r in daily_chart]

    return templates.TemplateResponse(
        "supervisor_dashboard.html",
        {
            "request": request,
            "user": user,
            "rows": rows,
            "top_items": top_items,
            "best_agents": best_agents,
            "chart_labels": chart_labels,
            "chart_data": chart_data,
            "grand_total_deliveries": grand_total_deliveries,
            "grand_delivered": grand_delivered,
            "grand_pending": grand_pending,
            "grand_out_for_delivery": grand_out_for_delivery,
            "grand_failed": grand_failed,
            "grand_collections": grand_collections,
            "grand_agent_expenses": grand_agent_expenses,
            "grand_office_expenses": grand_office_expenses,
            "grand_operating_cash": grand_operating_cash,
            "grand_returned_operating_cash": grand_returned_operating_cash,
            "grand_operating_balance": grand_operating_balance,
            "grand_remittance": grand_remittance,
            "branches": branches,
            "selected_branch_id": None,
            "active": "supervisor",
            "preset": preset or "",
            "start_date": start_date or "",
            "end_date": end_date or "",
        },
    )
@app.get("/branches", response_class=HTMLResponse)
def branches_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not is_supervisor(user):
        return HTMLResponse("Forbidden", status_code=403)

    rows = db.execute(
        select(Branch).order_by(Branch.name.asc())
    ).scalars().all()

    return templates.TemplateResponse(
        "branches_list.html",
        {
            "request": request,
            "user": user,
            "rows": rows,
            "active": "branches",
            "branches": rows,
            "selected_branch_id": None,
        },
    )


@app.get("/branches/new", response_class=HTMLResponse)
def branch_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not is_supervisor(user):
        return HTMLResponse("Forbidden", status_code=403)

    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "branch_new.html",
        {
            "request": request,
            "user": user,
            "error": error,
            "active": "branches",
            "branches": branches,
            "selected_branch_id": None,
        },
    )


@app.post("/branches/new")
def branch_create(
    request: Request,
    name: str = Form(...),
    code: str = Form(""),
    address: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not is_supervisor(user):
        return HTMLResponse("Forbidden", status_code=403)

    name_clean = (name or "").strip()
    code_clean = (code or "").strip() or None
    address_clean = (address or "").strip() or None

    if not name_clean:
        return redirect("/branches/new?error=Branch+name+is+required")

    existing_name = db.scalar(select(Branch).where(Branch.name == name_clean))
    if existing_name:
        return redirect("/branches/new?error=Branch+name+already+exists")

    if code_clean:
        existing_code = db.scalar(select(Branch).where(Branch.code == code_clean))
        if existing_code:
            return redirect("/branches/new?error=Branch+code+already+exists")

    db.add(
        Branch(
            name=name_clean,
            code=code_clean,
            address=address_clean,
        )
    )
    db.commit()
    return redirect("/branches")

@app.get("/api/low-stock-count")
def api_low_stock_count(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"count": 0}, status_code=401)
    return {"count": len(get_low_stock(db))}


# ---------------- Items ----------------

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
            (item, stock)
            for (item, stock) in rows
            if q_lower in ((item.sku or "").lower())
            or q_lower in ((item.name or "").lower())
            or q_lower in ((item.category or "").lower())
        ]

    return templates.TemplateResponse(
        "items_list.html",
        {"request": request, "rows": rows, "q": q, "user": user, "active": "items"},
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
    return templates.TemplateResponse("item_new.html", {"request": request, "user": user, "error": error, "active": "items"})


@app.post("/items/new")
def item_create(
    request: Request,
    name: str = Form(...),
    sku: str = Form(""),
    category: str = Form(""),
    unit: str = Form("pcs"),
    reorder_level: int = Form(0),
    cost_price: float = Form(0),
    selling_price: float = Form(0),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    name_clean = name.strip()
    if not name_clean:
        return redirect("/items/new?error=Name+is+required")

    sku_clean = (sku or "").strip() or None
    if sku_clean and db.scalar(select(Item).where(Item.sku == sku_clean)):
        return redirect("/items/new?error=SKU+already+exists")

    branch_id = get_current_branch_id(request)
    if not branch_id:
        return redirect("/items/new?error=No+branch+assigned")

    db.add(
        Item(
            branch_id=branch_id,
            name=name_clean,
            sku=sku_clean,
            category=(category or "").strip() or None,
            unit=(unit or "pcs").strip() or "pcs",
            reorder_level=int(reorder_level or 0),
            cost_price=float(cost_price or 0),
            selling_price=float(selling_price or 0),
        )
    )
    db.commit()
    return redirect("/items")


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
        select(Transaction)
        .where(Transaction.item_id == item_id)
        .where(Transaction.branch_id == item.branch_id)
        .order_by(desc(Transaction.created_at))
        .limit(200)
    ).all()

    return templates.TemplateResponse(
        "item_detail.html",
        {"request": request, "item": item, "stock": stock, "txs": txs, "user": user, "active": "items"},
    )


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

    error = request.query_params.get("error")
    return templates.TemplateResponse(
        "item_edit.html",
        {"request": request, "item": item, "user": user, "error": error, "active": "items"},
    )


@app.post("/items/{item_id}/edit")
def item_edit_save(
    request: Request,
    item_id: int,
    name: str = Form(...),
    sku: str = Form(""),
    category: str = Form(""),
    unit: str = Form("pcs"),
    reorder_level: int = Form(0),
    cost_price: float = Form(0),
    selling_price: float = Form(0),
    # Stock adjustment (quantity update) via transactions
    adjust_type: str = Form(""),   # "IN" or "OUT" or ""
    adjust_qty: int = Form(0),     # number to add/remove
    adjust_note: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    item = db.get(Item, item_id)
    require_item_access(request, user, item)

    name_clean = (name or "").strip()
    if not name_clean:
        return redirect(f"/items/{item_id}/edit?error=Name+is+required")

    sku_clean = (sku or "").strip() or None
    if sku_clean:
        other = db.scalar(select(Item).where(Item.sku == sku_clean).where(Item.id != item_id))
        if other:
            return redirect(f"/items/{item_id}/edit?error=SKU+already+exists")

    item.name = name_clean
    item.sku = sku_clean
    item.category = (category or "").strip() or None
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
            row = get_item_with_stock(db, item_id)
            current_stock = int(row[1]) if row else 0
            if current_stock < aq:
                return redirect(f"/items/{item_id}/edit?error=Insufficient+stock+for+OUT+adjustment")

        db.add(
            Transaction(
                branch_id=item.branch_id,
                item_id=item_id,
                type=at,
                quantity=aq,
                reference=f"MANUAL ADJUST #{item_id}",
                note=(adjust_note or "").strip() or f"Manual stock adjust by {user.username}",
            )
        )

    db.commit()
    return redirect(f"/items/{item_id}")


# ---------------- Transactions (ADMIN) ----------------

@app.get("/transactions", response_class=HTMLResponse)
def transactions_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    branch_id = get_selected_branch_id(request, user)
    txs = db.scalars(
        select(Transaction)
        .where(Transaction.branch_id == branch_id)
        .order_by(desc(Transaction.created_at))
        .limit(300)
    ).all()
    return templates.TemplateResponse("transactions_list.html", {"request": request, "txs": txs, "user": user, "active": "transactions"})


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

    rows = [
        (item, stock)
        for (item, stock) in get_items_with_stock(db)
        if item.branch_id == branch_id
    ]
    items = [i for (i, _s) in rows]

    error = request.query_params.get("error")

    branches = []
    if is_supervisor(user):
        branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()

    return templates.TemplateResponse(
        "tx_form.html",
        {
            "request": request,
            "items": items,
            "error": error,
            "user": user,
            "active": "transactions",
            "branches": branches,
            "selected_branch_id": branch_id,
        },
    )


@app.post("/transactions/new")
def tx_create(
    request: Request,
    item_id: int = Form(...),
    tx_type: str = Form(...),
    quantity: int = Form(...),
    reference: str = Form(""),
    note: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    tx_type_clean = (tx_type or "").strip().upper()
    if tx_type_clean not in {"IN", "OUT"}:
        return redirect("/transactions/new?error=Invalid+type")

    qty = int(quantity)
    if qty <= 0:
        return redirect("/transactions/new?error=Quantity+must+be+greater+than+0")

    if tx_type_clean == "OUT":
        row = get_item_with_stock(db, item_id)
        if not row:
            return redirect("/transactions/new?error=Item+not+found")
        _it, stock = row
        if int(stock) < qty:
            return redirect("/transactions/new?error=Insufficient+stock")

    branch_id = get_current_branch_id(request)
    if not branch_id:
        return redirect("/transactions/new?error=No+branch+assigned")

    db.add(
        Transaction(
            branch_id=branch_id,
            item_id=item_id,
            type=tx_type_clean,
            quantity=qty,
            reference=(reference or "").strip() or None,
            note=(note or "").strip() or None,
        )
    )
    db.commit()
    return redirect("/transactions")


# ---------------- Low stock ----------------

@app.get("/low-stock", response_class=HTMLResponse)
def low_stock(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    branch_id = get_selected_branch_id(request, user)
    rows = [(item, stock) for (item, stock) in get_low_stock(db) if item.branch_id == branch_id]
    return templates.TemplateResponse("low_stock.html", {"request": request, "rows": rows, "user": user, "active": "low"})


# ---------------- Agents (ADMIN) ----------------

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

    agents = db.execute(
        select(User)
        .where(User.role == "AGENT")
        .where(User.branch_id == branch_id)
        .order_by(User.username.asc())
    ).scalars().all()

    return templates.TemplateResponse(
        "agents_list.html",
        {"request": request, "agents": agents, "user": user}
    )


@app.get("/agents/new", response_class=HTMLResponse)
def agent_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    error = request.query_params.get("error")
    return templates.TemplateResponse("agent_new.html", {"request": request, "user": user, "error": error, "active": "agents"})


@app.post("/agents/new")
def agent_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(""),
    phone: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    uname = username.strip()
    if not uname:
        return redirect("/agents/new?error=Username+is+required")

    if db.scalar(select(User).where(User.username == uname)):
        return redirect("/agents/new?error=Username+already+exists")

    if len(password or "") < 4:
        return redirect("/agents/new?error=Password+too+short")

    if not user.branch_id:
        return redirect("/agents/new?error=Admin+has+no+branch+assigned")

    db.add(
        User(
            username=uname,
            password_hash=hash_password(password),
            role="AGENT",
            branch_id=user.branch_id,
            full_name=(full_name or "").strip() or None,
            phone=(phone or "").strip() or None,
        )
    )
    db.commit()
    return redirect("/agents")


@app.get("/agents/{agent_id}", response_class=HTMLResponse)
def agent_detail(
    request: Request,
    agent_id: int,
    preset: str = "",
    start_date: str = "",
    end_date: str = "",
    db: Session = Depends(get_db),
):
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

    rows, total_collections, total_expenses, total_operating, total_office_expenses = get_cash_summary(
        db=db,
        agent_id=agent_id,
        start=start_dt,
        end=end_dt,
    )

    operating_balance = float(total_operating) - float(total_expenses)
    remittance = float(total_collections) - float(total_office_expenses)
    net_position = remittance + operating_balance

    d_stmt = (
        select(Delivery)
        .where(Delivery.agent_id == agent_id)
        .order_by(desc(Delivery.created_at))
        .limit(300)
    )
    if start_dt:
        d_stmt = d_stmt.where(Delivery.created_at >= start_dt)
    if end_dt:
        d_stmt = d_stmt.where(Delivery.created_at < end_dt)

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
        for did, name, qty in lines:
            grouped.setdefault(int(did), []).append(f"{name} ×{int(qty)}")

        items_summary = {did: ", ".join(parts) for did, parts in grouped.items()}

    cash_stmt = select(CashEntry).order_by(desc(CashEntry.created_at))
    if start_dt:
        cash_stmt = cash_stmt.where(CashEntry.created_at >= start_dt)
    if end_dt:
        cash_stmt = cash_stmt.where(CashEntry.created_at < end_dt)

    cash_stmt = cash_stmt.where((CashEntry.agent_id == agent_id) | (CashEntry.kind == "OFFICE_EXPENSE"))
    cash_entries = db.execute(cash_stmt.limit(300)).scalars().all()

    return templates.TemplateResponse(
        "agent_detail.html",
        {
            "request": request,
            "user": user,
            "agent": agent,
            "rows": rows,
            "deliveries": deliveries,
            "items_summary": items_summary,
            "cash_entries": cash_entries,
            "total_collections": float(total_collections),
            "total_expenses": float(total_expenses),
            "total_operating_cash": float(total_operating),
            "operating_balance": float(operating_balance),
            "total_office_expenses": float(total_office_expenses),
            "remittance": float(remittance),
            "net_position": float(net_position),
            "preset": preset_norm or (preset or ""),
            "start_date": sd.isoformat() if sd else "",
            "end_date": ed.isoformat() if ed else "",
            "active": "agents",
        },
    )


# ---------------- Deliveries ----------------

@app.get("/deliveries", response_class=HTMLResponse)
def deliveries_admin_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not is_admin(user) and not is_supervisor(user):
        return redirect("/my-deliveries")

    branch_id = get_selected_branch_id(request, user)

    status = request.query_params.get("status", "").strip().upper()
    agent_id = request.query_params.get("agent_id", "").strip()

    stmt = (
        select(Delivery)
        .where(Delivery.branch_id == branch_id)
        .order_by(desc(Delivery.created_at))
        .limit(300)
    )

    if status:
        stmt = stmt.where(Delivery.status == status)
    if agent_id.isdigit():
        stmt = stmt.where(Delivery.agent_id == int(agent_id))

    rows = db.execute(stmt).scalars().all()

    agents = db.execute(
        select(User)
        .where(User.role == "AGENT")
        .where(User.branch_id == branch_id)
        .order_by(User.username.asc())
    ).scalars().all()

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
        for did, name, qty in lines:
            grouped.setdefault(int(did), []).append(f"{name} ×{int(qty)}")

        for did, parts in grouped.items():
            items_summary[did] = ", ".join(parts)

    branches = []
    if is_supervisor(user):
        branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()

    return templates.TemplateResponse(
        "deliveries_list.html",
        {
            "request": request,
            "rows": rows,
            "agents": agents,
            "status": status,
            "agent_id": agent_id,
            "items_summary": items_summary,
            "branches": branches,
            "selected_branch_id": branch_id,
            "user": user,
            "active": "deliveries",
        },
    )


@app.get("/deliveries/new", response_class=HTMLResponse)
def delivery_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    branch_id = get_selected_branch_id(request, user)

    agents = db.execute(
        select(User)
        .where(User.role == "AGENT")
        .where(User.branch_id == branch_id)
        .order_by(User.username.asc())
    ).scalars().all()

    items = db.execute(
        select(Item)
        .where(Item.branch_id == branch_id)
        .order_by(Item.name.asc())
    ).scalars().all()

    branches = []
    if is_supervisor(user):
        branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()

    return templates.TemplateResponse(
        "delivery_new.html",
        {
            "request": request,
            "agents": agents,
            "items": items,
            "user": user,
            "active": "deliveries_new",
            "branches": branches,
            "selected_branch_id": branch_id,
        },
    )


@app.post("/deliveries/new")
def delivery_create(
    request: Request,
    agent_id: int | None = Form(None),
    customer_name: str = Form(...),
    customer_phone: str = Form(""),
    address: str = Form(""),
    note: str = Form(""),
    item_id: list[int] = Form(...),
    quantity: list[int] = Form(...),
    line_amount: list[float] = Form(default=[]),
    db: Session = Depends(get_db),
):
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

    cust = (customer_name or "").strip()
    if not cust:
        raise HTTPException(status_code=400, detail="Customer name required")

    branch_id = get_current_branch_id(request)
    if not branch_id:
        raise HTTPException(status_code=400, detail="No branch assigned")

    d = Delivery(
        branch_id=branch_id,
        agent_id=target_agent_id,
        customer_name=cust,
        customer_phone=(customer_phone or "").strip() or None,
        address=(address or "").strip() or None,
        note=(note or "").strip() or None,
        status="PENDING",
    )
    db.add(d)
    db.flush()

    amounts = list(line_amount or [])
    while len(amounts) < len(item_id):
        amounts.append(0.0)

    for iid, qty, amt in zip(item_id, quantity, amounts):
        q = int(qty) if qty is not None else 0
        if q > 0:
            db.add(
                DeliveryItem(
                    delivery_id=d.id,
                    item_id=int(iid),
                    quantity=q,
                    line_amount=float(amt or 0),
                )
            )

    db.commit()
    return redirect(f"/deliveries/{d.id}")


@app.get("/my-deliveries", response_class=HTMLResponse)
def my_deliveries(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    branch_id = get_selected_branch_id(request, user)

    rows = db.execute(
        select(Delivery)
        .where(Delivery.agent_id == user.id)
        .where(Delivery.branch_id == branch_id)
        .order_by(desc(Delivery.created_at))
        .limit(300)
    ).scalars().all()

    return templates.TemplateResponse("my_deliveries.html", {"request": request, "rows": rows, "user": user, "active": "deliveries"})


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
        select(DeliveryItem, Item)
        .join(Item, Item.id == DeliveryItem.item_id)
        .where(DeliveryItem.delivery_id == d.id)
    ).all()

    col = db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.delivery_id == d.id)
        .where(CashEntry.kind == "COLLECTION")
    ) or 0
    exp = db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.delivery_id == d.id)
        .where(CashEntry.kind == "EXPENSE")
    ) or 0

    return templates.TemplateResponse(
        "delivery_detail.html",
        {
            "request": request,
            "d": d,
            "d_items": d_items,
            "user": user,
            "error": None,
            "collection_total": float(col),
            "expense_total": float(exp),
            "back_url": "/deliveries" if is_admin(user) else "/my-deliveries",
            "active": "deliveries",
        },
    )


@app.post("/deliveries/{delivery_id}/status")
def update_delivery_status(
    request: Request,
    delivery_id: int,
    status: str = Form(...),
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
                select(DeliveryItem, Item)
                .join(Item, Item.id == DeliveryItem.item_id)
                .where(DeliveryItem.delivery_id == d.id)
            ).all()
            return templates.TemplateResponse(
                "delivery_detail.html",
                {
                    "request": request,
                    "d": d,
                    "d_items": d_items,
                    "user": user,
                    "error": str(e),
                    "collection_total": 0,
                    "expense_total": 0,
                    "back_url": "/deliveries" if is_admin(user) else "/my-deliveries",
                    "active": "deliveries",
                },
            )
        return redirect(f"/deliveries/{delivery_id}")

    d.status = status_clean
    db.commit()
    return redirect(f"/deliveries/{delivery_id}")


# ---------------- Cash ----------------

@app.get("/cash", response_class=HTMLResponse)
def cash_dashboard(
    request: Request,
    preset: str = "",
    start_date: str = "",
    end_date: str = "",
    agent_id: str = "",
    db: Session = Depends(get_db),
):
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
        if sd:
            start_dt = datetime.combine(sd, datetime.min.time())
        if ed:
            end_dt = datetime.combine(ed, datetime.min.time()) + timedelta(days=1)

    selected_agent_id = None
    if is_admin(user):
        if (agent_id or "").isdigit():
            selected_agent_id = int(agent_id)
    else:
        selected_agent_id = user.id

    rows, total_collections, total_expenses, total_operating, total_office_expenses = get_cash_summary(
        db=db,
        agent_id=selected_agent_id,
        start=start_dt,
        end=end_dt,
    )

    # Filter daily rows to selected branch using cash/delivery records
    branch_delivery_days = set(
        str(x) for x in db.execute(
            select(func.date(Delivery.created_at))
            .where(Delivery.branch_id == branch_id)
        ).scalars().all() if x is not None
    )

    branch_cash_days = set(
        str(x) for x in db.execute(
            select(func.date(CashEntry.created_at))
            .where(CashEntry.branch_id == branch_id)
        ).scalars().all() if x is not None
    )

    allowed_days = branch_delivery_days | branch_cash_days
    rows = [r for r in rows if r["day"] in allowed_days]

    total_collections = float(sum(float(r["collections"]) for r in rows))
    total_expenses = float(sum(float(r["expenses"]) for r in rows))
    total_operating = float(sum(float(r["operating_cash"]) for r in rows))
    total_office_expenses = float(sum(float(r["office_expenses"]) for r in rows))

    operating_balance = float(total_operating) - float(total_expenses)
    remittance = float(total_collections) - float(total_office_expenses)
    net_position = remittance + operating_balance

    agents = []
    if is_admin(user) or is_supervisor(user):
        agents = db.execute(
            select(User)
            .where(User.role == "AGENT")
            .where(User.branch_id == branch_id)
            .order_by(User.username.asc())
        ).scalars().all()

    return templates.TemplateResponse(
        "cash_dashboard.html",
        {
            "request": request,
            "user": user,
            "rows": rows,
            "total_collections": float(total_collections),
            "total_expenses": float(total_expenses),
            "total_operating_cash": float(total_operating),
            "operating_balance": float(operating_balance),
            "total_office_expenses": float(total_office_expenses),
            "remittance": float(remittance),
            "net_position": float(net_position),
            "agents": agents,
            "agent_id": agent_id,
            "preset": preset_norm or (preset or ""),
            "start_date": sd.isoformat() if sd else "",
            "end_date": ed.isoformat() if ed else "",
            "active": "cash",
        },
    )


@app.post("/cash/new")
def cash_new(
    request: Request,
    kind: str = Form(...),
    amount: float = Form(...),
    note: str = Form(""),
    delivery_id: str = Form(""),
    agent_id: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    k = (kind or "").strip().upper()
    if k not in {"COLLECTION", "EXPENSE", "OPERATING_CASH", "OFFICE_EXPENSE"}:
        raise HTTPException(status_code=400, detail="Invalid kind")

    if k == "OFFICE_EXPENSE" and not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)

    amt = float(amount or 0)
    if amt <= 0:
        raise HTTPException(status_code=400, detail="Amount must be > 0")

    target_agent_id = user.id
    if is_admin(user) and (agent_id or "").isdigit():
        target_agent_id = int(agent_id)

    if k == "OFFICE_EXPENSE":
        target_agent_id = user.id

    d_id = int(delivery_id) if (delivery_id or "").isdigit() else None

    branch_id = get_current_branch_id(request)
    if not branch_id:
        raise HTTPException(status_code=400, detail="No branch assigned")
    db.add(
        CashEntry(
            branch_id=branch_id,
            agent_id=target_agent_id,
            delivery_id=d_id,
            kind=k,
            amount=amt,
            note=(note or "").strip() or None,
        )
    )
    db.commit()

    if d_id:
        return redirect(f"/deliveries/{d_id}")
    return redirect("/cash")


# ---------------- Reports (TXT) ----------------

@app.get("/reports", response_class=HTMLResponse)
def reports_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not (is_admin(user) or is_agent(user)):
        return HTMLResponse("Forbidden", status_code=403)

    agents = []
    if is_admin(user):
        agents = db.execute(select(User).where(User.role == "AGENT").order_by(User.username.asc())).scalars().all()

    today = date.today().isoformat()

    html = [
        "<html><head><meta charset='utf-8'><title>Reports</title></head><body>",
        "<h2>Download TXT Report</h2>",
        "<form method='get' action='/reports/txt'>",
        f"<label>Start date</label><br><input name='start_date' type='date' value='{today}'><br><br>",
        f"<label>End date</label><br><input name='end_date' type='date' value='{today}'><br><br>",
    ]

    if is_admin(user):
        html.append("<label>Agent (optional)</label><br><select name='agent_id'><option value=''>All agents</option>")
        for a in agents:
            html.append(f"<option value='{a.id}'>{a.username}</option>")
        html.append("</select><br><br>")

    html.append("<button type='submit'>Download TXT</button></form>")
    html.append("<p>Waybills are counted inside Office Expenses when the note contains the word 'waybill'.</p>")
    html.append("</body></html>")

    return HTMLResponse("".join(html))


@app.get("/reports/txt", response_class=PlainTextResponse)
def reports_txt(
    request: Request,
    start_date: str | None = None,
    end_date: str | None = None,
    agent_id: str | None = None,
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return PlainTextResponse("Unauthorized", status_code=401)
    user = user_or

    if not (is_admin(user) or is_agent(user)):
        return PlainTextResponse("Forbidden", status_code=403)

    d1 = _parse_iso_date(start_date)
    d2 = _parse_iso_date(end_date)

    if not d1 and not d2:
        d1 = date.today()
        d2 = date.today()

    if d1 and not d2:
        d2 = d1
    if d2 and not d1:
        d1 = d2

    start_dt = datetime.combine(d1, datetime.min.time())
    end_dt = datetime.combine(d2, datetime.max.time())

    target_agent_id: int | None = None
    if is_agent(user):
        target_agent_id = int(user.id)
    elif is_admin(user) and (agent_id or "").isdigit():
        target_agent_id = int(agent_id)

    filters = [
        Delivery.created_at >= start_dt,
        Delivery.created_at <= end_dt,
        Delivery.status == "DELIVERED",
    ]
    if target_agent_id is not None:
        filters.append(Delivery.agent_id == target_agent_id)

    deliveries = db.execute(
        select(Delivery).where(and_(*filters)).order_by(Delivery.created_at.asc())
    ).scalars().all()

    delivery_ids = [d.id for d in deliveries]
    items_by_delivery: dict[int, list[tuple[str, float, float]]] = {}
    if delivery_ids:
        rows = db.execute(
            select(
                DeliveryItem.delivery_id,
                Item.name,
                DeliveryItem.quantity,
                DeliveryItem.line_amount,
                Item.selling_price,
            )
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        for did, name, qty, line_amt, selling_price in rows:
            q = float(qty or 0)
            la = float(line_amt or 0)
            sp = float(selling_price or 0)
            items_by_delivery.setdefault(int(did), []).append((str(name), q, la if la > 0 else q * sp))

    exp_stmt = (
        select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind == "EXPENSE")
        .where(CashEntry.created_at >= start_dt)
        .where(CashEntry.created_at <= end_dt)
        .group_by(CashEntry.agent_id)
        .order_by(CashEntry.agent_id.asc())
    )
    agent_exp_rows = db.execute(exp_stmt).all()
    agent_exp_map = {int(aid): float(total) for aid, total in agent_exp_rows}

    office_total = float(
        db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.kind == "OFFICE_EXPENSE")
            .where(CashEntry.created_at >= start_dt)
            .where(CashEntry.created_at <= end_dt)
        ) or 0
    )

    waybill_total = float(
        db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.kind == "OFFICE_EXPENSE")
            .where(CashEntry.created_at >= start_dt)
            .where(CashEntry.created_at <= end_dt)
            .where(func.lower(func.coalesce(CashEntry.note, "")).like("%waybill%"))
        ) or 0
    )

    other_office_total = office_total - waybill_total

    lines: list[str] = []
    title_day = d1.strftime("%A %d %B %Y").upper() if d1 == d2 else f"{d1.isoformat()} TO {d2.isoformat()}"

    lines.append(f"REPORT FOR {title_day}.")
    lines.append(f"TOTAL DELIVERY = {len(deliveries)}")
    lines.append("")

    grand_total = 0.0

    for idx, d in enumerate(deliveries, start=1):
        d_items = items_by_delivery.get(int(d.id), [])
        total_qty = sum(q for _name, q, _amt in d_items)
        delivery_total = sum(amt for _name, _q, amt in d_items)

        parts = []
        for name, q, _amt in d_items:
            parts.append(f"{q:g} {name}")

        items_txt = " + ".join(parts) if parts else "No items"
        grand_total += delivery_total

        lines.append(f"({idx})\t{total_qty:g}\t{items_txt}\t{_ngn(delivery_total)}")

    lines.append("")
    lines.append(f"Grand total: {_ngn(grand_total)}")
    lines.append("")
    lines.append("Expenses:")
    lines.append("")
    lines.append("Agent expenses (delivery spending):")

    total_agent_expenses = 0.0
    if agent_exp_map:
        agent_ids = list(agent_exp_map.keys())
        users = db.execute(select(User).where(User.id.in_(agent_ids))).scalars().all()
        uname = {int(u.id): (u.full_name or u.username or f"Agent {u.id}") for u in users}

        for aid in sorted(agent_exp_map.keys()):
            amt = float(agent_exp_map[aid])
            total_agent_expenses += amt
            lines.append(f"{uname.get(aid, f'Agent {aid}')}: {_ngn(amt)}")
    else:
        lines.append("None")

    lines.append(f"Total agent expenses: {_ngn(total_agent_expenses)}")
    lines.append("")
    lines.append("Office expenses:")
    lines.append(f"Waybills: {_ngn(waybill_total)}")
    lines.append(f"Other office expenses: {_ngn(other_office_total)}")
    lines.append(f"Total office expenses: {_ngn(office_total)}")
    lines.append("")
    total_expenses = total_agent_expenses + office_total
    lines.append(f"Total amount of expenses: {_ngn(total_expenses)}")
    lines.append("")
    lines.append("Amount to be remitted:")
    lines.append(f"{_ngn(grand_total)} - {_ngn(total_expenses)} = {_ngn(grand_total - total_expenses)}")

    body = "\n".join(lines)

    filename = f"report_{d1.isoformat()}_{d2.isoformat()}.txt"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

    return PlainTextResponse(body, headers=headers, media_type="text/plain; charset=utf-8")


# ---------------- Admin: reset (optional) ----------------

@app.get("/admin/reset-system")
def reset_system(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

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


@app.get("/manifest.json")
def pwa_manifest():
    manifest_path = os.path.join(BASE_DIR, "static", "manifest.json")
    try:
        content = open(manifest_path).read()
    except FileNotFoundError:
        content = "{}"
    return PlainTextResponse(
        content,
        headers={"Content-Type": "application/manifest+json; charset=utf-8"}
    )


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


@app.get("/debug-login")
def debug_login(username: str, password: str, db: Session = Depends(get_db)):
    from sqlalchemy import select
    u = db.scalar(select(User).where(User.username == username.strip()))
    if not u:
        return {"error": "user not found", "username": username}
    stored = u.password_hash or ""
    starts_with = stored[:20]
    verified = verify_password(password, stored)
    return {
        "user_found": True,
        "role": u.role,
        "hash_prefix": starts_with,
        "verified": verified,
    }

# ═══════════════════════════════════════════════════
#  STOCK TRANSFERS
# ═══════════════════════════════════════════════════

@app.get("/transfers", response_class=HTMLResponse)
def transfers_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)

    if is_supervisor(user):
        transfers = db.execute(
            select(StockTransfer).order_by(desc(StockTransfer.created_at))
        ).scalars().all()
    else:
        transfers = db.execute(
            select(StockTransfer)
            .where(
                (StockTransfer.from_branch_id == user.branch_id) |
                (StockTransfer.to_branch_id == user.branch_id)
            )
            .order_by(desc(StockTransfer.created_at))
        ).scalars().all()

    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all()

    return templates.TemplateResponse("transfers_list.html", {
        "request": request,
        "user": user,
        "transfers": transfers,
        "branches": branches,
        "active": "transfers",
        "selected_branch_id": getattr(user, "branch_id", None),
    })


@app.get("/transfers/new", response_class=HTMLResponse)
def transfer_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)

    branches = db.execute(
        select(Branch).where(Branch.id != user.branch_id).order_by(Branch.name)
    ).scalars().all()

    items = get_items_with_stock(db, branch_id=user.branch_id)
    error = request.query_params.get("error")

    return templates.TemplateResponse("transfer_new.html", {
        "request": request,
        "user": user,
        "branches": branches,
        "items": items,
        "error": error,
        "active": "transfers",
        "selected_branch_id": user.branch_id,
    })


@app.post("/transfers/new")
def transfer_create(
    request: Request,
    to_branch_id: int = Form(...),
    note: str = Form(""),
    item_ids: list[int] = Form(...),
    quantities: list[int] = Form(...),
    db: Session = Depends(get_db),
):
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

    # validate stock
    for item_id, qty in zip(item_ids, quantities):
        if qty <= 0:
            return redirect("/transfers/new?error=Quantities+must+be+greater+than+zero")
        row = get_item_with_stock(db, item_id, branch_id=user.branch_id)
        if not row:
            return redirect("/transfers/new?error=Item+not+found")
        _item, stock = row
        if int(stock) < qty:
            return redirect(f"/transfers/new?error=Insufficient+stock+for+{_item.name}")

    # create transfer record
    transfer = StockTransfer(
        from_branch_id=user.branch_id,
        to_branch_id=to_branch_id,
        status="PENDING",
        note=(note or "").strip() or None,
        created_by_id=user.id,
    )
    db.add(transfer)
    db.flush()

    # add line items
    for item_id, qty in zip(item_ids, quantities):
        db.add(StockTransferItem(
            transfer_id=transfer.id,
            item_id=item_id,
            quantity=qty,
        ))

    # deduct stock from sender immediately (OUT transactions)
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


@app.get("/transfers/{transfer_id}", response_class=HTMLResponse)
def transfer_detail(transfer_id: int, request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)

    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    if is_admin(user) and user.branch_id not in (transfer.from_branch_id, transfer.to_branch_id):
        return HTMLResponse("Forbidden", status_code=403)

    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all()

    return templates.TemplateResponse("transfer_detail.html", {
        "request": request,
        "user": user,
        "transfer": transfer,
        "branches": branches,
        "active": "transfers",
        "selected_branch_id": getattr(user, "branch_id", None),
    })


@app.post("/transfers/{transfer_id}/receive")
def transfer_receive(transfer_id: int, request: Request, db: Session = Depends(get_db)):
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

    # add stock to receiving branch (IN transactions)
    for line in transfer.items:
        # ensure item exists in receiving branch — if not, create it
        dest_item = db.scalar(
            select(Item).where(Item.branch_id == user.branch_id, Item.name == line.item.name)
        )
        if not dest_item:
            dest_item = Item(
                branch_id=user.branch_id,
                name=line.item.name,
                sku=line.item.sku,
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
def transfer_cancel(transfer_id: int, request: Request, db: Session = Depends(get_db)):
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

    # reverse the OUT transactions — add stock back to sender
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