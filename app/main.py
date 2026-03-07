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

from .database import Base, engine, get_db
from .models import Item, Transaction, User, Delivery, DeliveryItem, CashEntry
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
)

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

static_dir = os.path.join(BASE_DIR, "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

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


def ensure_schema() -> None:
    Base.metadata.create_all(bind=engine)

    with engine.connect() as conn:
        # transactions.delivery_id
        try:
            conn.execute(text("SELECT delivery_id FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE transactions ADD COLUMN delivery_id INTEGER"))
                conn.commit()
            except Exception:
                pass

        # deliveries.delivered_at
        try:
            conn.execute(text("SELECT delivered_at FROM deliveries LIMIT 1"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE deliveries ADD COLUMN delivered_at TIMESTAMP"))
                conn.commit()
            except Exception:
                pass

        # delivery_items.line_amount
        try:
            conn.execute(text("SELECT line_amount FROM delivery_items LIMIT 1"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE delivery_items ADD COLUMN line_amount NUMERIC DEFAULT 0"))
                conn.commit()
            except Exception:
                pass

        # cash_entries table
        try:
            conn.execute(text("SELECT id FROM cash_entries LIMIT 1"))
        except Exception:
            try:
                conn.execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS cash_entries (
                            id SERIAL PRIMARY KEY,
                            created_at TIMESTAMP DEFAULT NOW(),
                            agent_id INTEGER NOT NULL,
                            delivery_id INTEGER NULL,
                            kind VARCHAR(20) NOT NULL,
                            amount NUMERIC NOT NULL,
                            note VARCHAR(400) NULL
                        )
                        """
                    )
                )
                conn.commit()
            except Exception:
                pass

            # prevent duplicate OUT transactions for same delivery + item
        try:
            conn.execute(
                text(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS ux_transactions_delivery_item_out
                    ON transactions (delivery_id, item_id, type)
                    WHERE delivery_id IS NOT NULL AND type = 'OUT'
                    """
                )
            )
            conn.commit()
        except Exception:
            pass

        # indexes for faster reports and dashboards
        try:
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_deliveries_created_at ON deliveries (created_at)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_deliveries_status ON deliveries (status)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_deliveries_agent_id ON deliveries (agent_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_delivery_items_delivery_id ON delivery_items (delivery_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_cash_entries_created_at ON cash_entries (created_at)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_cash_entries_kind ON cash_entries (kind)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_cash_entries_agent_id ON cash_entries (agent_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_transactions_item_id ON transactions (item_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_transactions_delivery_id ON transactions (delivery_id)"
            ))
            conn.commit()
        except Exception:
            pass

def seed_admin_if_missing() -> None:
    admin_user = (os.getenv("ADMIN_USERNAME") or "").strip()
    admin_pass = os.getenv("ADMIN_PASSWORD") or ""
    if not admin_user or not admin_pass:
        return

    gen = get_db()
    db = next(gen)
    try:
        existing_admin = db.scalar(select(User).where(User.role == "ADMIN"))
        if existing_admin:
            return

        username_exists = db.scalar(select(User).where(User.username == admin_user))
        if username_exists:
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


@app.on_event("startup")
def _startup() -> None:
    ensure_schema()
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

    if not is_admin(user):
        return redirect("/my-deliveries")

    stats = dashboard_stats(db)
    total_stock, inventory_value = dashboard_kpis(db)
    cat_rows = stock_by_category(db)
    in7, out7 = in_out_last_7_days(db)
    top_rows = top_items_by_stock(db, limit=5)
    low_rows = get_low_stock(db)[:5]

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "active": "dashboard",
            **stats,
            "total_stock": total_stock,
            "inventory_value": inventory_value,
            "in7": in7,
            "out7": out7,
            "top_rows": top_rows,
            "low_rows": low_rows,
            "cat_rows": cat_rows,
        },
    )


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

    rows = get_items_with_stock(db)
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

    db.add(
        Item(
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
    txs = db.scalars(
        select(Transaction)
        .where(Transaction.item_id == item_id)
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
    if not item:
        return HTMLResponse("Item not found", status_code=404)

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
    if not item:
        return HTMLResponse("Item not found", status_code=404)

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

    txs = get_recent_transactions(db, limit=300)
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

    rows = get_items_with_stock(db)
    items = [i for (i, _s) in rows]
    error = request.query_params.get("error")
    return templates.TemplateResponse("tx_form.html", {"request": request, "items": items, "error": error, "user": user, "active": "transactions"})


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

    db.add(
        Transaction(
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

    rows = get_low_stock(db)
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

    agents = db.execute(select(User).where(User.role == "AGENT").order_by(User.username.asc())).scalars().all()
    return templates.TemplateResponse("agents_list.html", {"request": request, "agents": agents, "user": user, "active": "agents"})


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

    db.add(
        User(
            username=uname,
            password_hash=hash_password(password),
            role="AGENT",
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
    if not agent or (agent.role or "").upper() != "AGENT":
        return HTMLResponse("Agent not found", status_code=404)

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

    if not is_admin(user):
        return redirect("/my-deliveries")

    status = request.query_params.get("status", "").strip().upper()
    agent_id = request.query_params.get("agent_id", "").strip()

    stmt = select(Delivery).order_by(desc(Delivery.created_at)).limit(300)
    if status:
        stmt = stmt.where(Delivery.status == status)
    if agent_id.isdigit():
        stmt = stmt.where(Delivery.agent_id == int(agent_id))

    rows = db.execute(stmt).scalars().all()

    agents = db.execute(
        select(User).where(User.role == "AGENT").order_by(User.username.asc())
    ).scalars().all()

    # Build items_summary: {delivery_id: "Item ×Qty, Item ×Qty"}
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

    return templates.TemplateResponse(
        "deliveries_list.html",
        {
            "request": request,
            "rows": rows,
            "agents": agents,
            "status": status,
            "agent_id": agent_id,
            "items_summary": items_summary,  # ✅ this fixes the crash
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

    agents = db.execute(select(User).where(User.role == "AGENT").order_by(User.username.asc())).scalars().all()
    items = db.execute(select(Item).order_by(Item.name.asc())).scalars().all()

    return templates.TemplateResponse(
        "delivery_new.html",
        {"request": request, "agents": agents, "items": items, "user": user, "active": "deliveries_new"},
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

    d = Delivery(
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

    rows = db.execute(
        select(Delivery)
        .where(Delivery.agent_id == user.id)
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

    d = db.execute(
       select(Delivery)
       .where(Delivery.id == delivery_id)
       .with_for_update()
   ).scalar_one_or_none()

    if not d:
        return HTMLResponse("Not found", status_code=404)

    if not is_admin(user) and d.agent_id != user.id:
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
    if not d:
        return HTMLResponse("Not found", status_code=404)

    if not is_admin(user) and d.agent_id != user.id:
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

    operating_balance = float(total_operating) - float(total_expenses)
    remittance = float(total_collections) - float(total_office_expenses)
    net_position = remittance + operating_balance

    agents = []
    if is_admin(user):
        agents = db.execute(select(User).where(User.role == "AGENT").order_by(User.username.asc())).scalars().all()

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

    db.add(
        CashEntry(
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

    db.execute(text("TRUNCATE TABLE cash_entries RESTART IDENTITY CASCADE"))
    db.execute(text("TRUNCATE TABLE delivery_items RESTART IDENTITY CASCADE"))
    db.execute(text("TRUNCATE TABLE deliveries RESTART IDENTITY CASCADE"))
    db.execute(text("TRUNCATE TABLE transactions RESTART IDENTITY CASCADE"))
    db.commit()
    return {"status": "Database reset complete"}