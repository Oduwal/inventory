# app/main.py
import os
from datetime import datetime, date, timedelta

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from passlib.context import CryptContext
import bcrypt as bcrypt_lib

from sqlalchemy import select, text, desc, func
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


def is_admin(user: User) -> bool:
    return (user.role or "").upper() == "ADMIN"


def is_agent(user: User) -> bool:
    return (user.role or "").upper() == "AGENT"


def verify_password(plain_password: str, password_hash: str) -> bool:
    if (password_hash or "").startswith("$2"):
        try:
            return bcrypt_lib.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
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
    return db.get(User, int(user_id))


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
                conn.execute(text("ALTER TABLE delivery_items ADD COLUMN line_amount NUMERIC"))
                conn.commit()
            except Exception:
                pass

        # cash_entries.kind extension (OPERATING_CASH)
        # If a CHECK constraint exists from older runs, keep runtime safe by trying to relax it.
        try:
            conn.execute(text("SELECT kind FROM cash_entries LIMIT 1"))
        except Exception:
            # Table might not exist yet; Base.metadata.create_all() normally creates it.
            pass

        # Best-effort: drop older constraint name if it exists, then recreate broader one.
        # Failures are ignored to avoid breaking deployment.
        try:
            conn.execute(text("ALTER TABLE cash_entries DROP CONSTRAINT IF EXISTS ck_cash_kind"))
            conn.execute(
                text(
                    "ALTER TABLE cash_entries "
                    "ADD CONSTRAINT ck_cash_kind "
                    "CHECK (kind IN ('COLLECTION','EXPENSE','OPERATING_CASH'))"
                )
            )
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

        if db.scalar(select(User).where(User.username == admin_user)):
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


# ---------------- Items (route order matters) ----------------

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

    return templates.TemplateResponse("items_list.html", {"request": request, "rows": rows, "q": q, "user": user})


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
    return templates.TemplateResponse("item_new.html", {"request": request, "user": user, "error": error})


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


@app.get("/items/import", response_class=HTMLResponse)
def items_import_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    return templates.TemplateResponse("items_import.html", {"request": request, "user": user})


@app.post("/items/import")
def items_import_submit(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    return JSONResponse({"detail": "Import endpoint exists. CSV upload handling can be added next."})


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
    return templates.TemplateResponse("item_edit.html", {"request": request, "user": user, "item": item, "error": error})


@app.post("/items/{item_id}/edit")
def item_edit_submit(
    request: Request,
    item_id: int,
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

    item = db.get(Item, item_id)
    if not item:
        return HTMLResponse("Item not found", status_code=404)

    name_clean = name.strip()
    if not name_clean:
        return redirect(f"/items/{item_id}/edit?error=Name+is+required")

    sku_clean = (sku or "").strip() or None
    if sku_clean:
        exists = db.scalar(select(Item).where(Item.sku == sku_clean).where(Item.id != item_id))
        if exists:
            return redirect(f"/items/{item_id}/edit?error=SKU+already+exists")

    item.name = name_clean
    item.sku = sku_clean
    item.category = (category or "").strip() or None
    item.unit = (unit or "pcs").strip() or "pcs"
    item.reorder_level = int(reorder_level or 0)
    item.cost_price = float(cost_price or 0)
    item.selling_price = float(selling_price or 0)

    db.commit()
    return redirect(f"/items/{item_id}")


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
        select(Transaction).where(Transaction.item_id == item_id).order_by(desc(Transaction.created_at)).limit(200)
    ).all()

    return templates.TemplateResponse(
        "item_detail.html",
        {"request": request, "item": item, "stock": stock, "txs": txs, "user": user},
    )


# ---------------- Transactions ----------------

@app.get("/transactions", response_class=HTMLResponse)
def transactions_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    txs = get_recent_transactions(db, limit=300)
    return templates.TemplateResponse("transactions_list.html", {"request": request, "txs": txs, "user": user})


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
    return templates.TemplateResponse("tx_form.html", {"request": request, "items": items, "error": error, "user": user})


@app.post("/transactions/new")
def tx_create(
    request: Request,
    item_id: int = Form(...),
    tx_type: str = Form(...),
    quantity: int = Form(...),
    reference: str = Form(default=""),
    note: str = Form(default=""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    tx_type = (tx_type or "").strip().upper()
    if tx_type not in {"IN", "OUT"}:
        return redirect("/transactions/new?error=Invalid+type")

    qty = int(quantity)
    if qty <= 0:
        return redirect("/transactions/new?error=Quantity+must+be+greater+than+0")

    if tx_type == "OUT":
        row = get_item_with_stock(db, item_id)
        if not row:
            return redirect("/transactions/new?error=Item+not+found")
        _it, stock = row
        if int(stock) < qty:
            return redirect("/transactions/new?error=Insufficient+stock")

    db.add(
        Transaction(
            item_id=item_id,
            type=tx_type,
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
    return templates.TemplateResponse("agents_list.html", {"request": request, "agents": agents, "user": user})


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
    return templates.TemplateResponse("agent_new.html", {"request": request, "user": user, "error": error})


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


def _range_dates_from_inputs(preset: str | None, start_date: str | None, end_date: str | None):
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

    rows, total_collections, total_expenses, total_operating = get_cash_summary(
        db=db, agent_id=agent_id, start=start_dt, end=end_dt
    )
    operating_balance = float(total_operating) - float(total_expenses)

    expense_entries = db.scalars(
        select(CashEntry)
        .where(CashEntry.agent_id == agent_id)
        .where(CashEntry.kind == "EXPENSE")
        .where(CashEntry.created_at >= (start_dt or datetime.min))
        .where(CashEntry.created_at < (end_dt or datetime.max))
        .order_by(desc(CashEntry.created_at))
        .limit(300)
    ).all()

    delivery_stmt = select(Delivery).where(Delivery.agent_id == agent_id).order_by(desc(Delivery.created_at)).limit(300)
    if start_dt:
        delivery_stmt = delivery_stmt.where(Delivery.created_at >= start_dt)
    if end_dt:
        delivery_stmt = delivery_stmt.where(Delivery.created_at < end_dt)
    deliveries = db.scalars(delivery_stmt).all()

    return templates.TemplateResponse(
        "agent_detail.html",
        {
            "request": request,
            "user": user,
            "agent": agent,
            "rows": rows,
            "total_collections": float(total_collections),
            "total_expenses": float(total_expenses),
            "total_operating_cash": float(total_operating),
            "operating_balance": operating_balance,
            "expense_entries": expense_entries,
            "deliveries": deliveries,
            "preset": preset_norm or (preset or ""),
            "start_date": sd.isoformat() if sd else "",
            "end_date": ed.isoformat() if ed else "",
        },
    )


# ---------------- Deliveries / Orders ----------------

from collections import defaultdict
from sqlalchemy import select, desc
from .models import Delivery, DeliveryItem, Item, User

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

    # Build summary: delivery_id -> "Item ×Qty, Item2 ×Qty2"
    items_summary: dict[int, str] = {}
    delivery_ids = [d.id for d in rows]

    if delivery_ids:
        line_rows = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()

        grouped = defaultdict(list)
        for delivery_id_val, name, qty in line_rows:
            grouped[int(delivery_id_val)].append(f"{name} ×{int(qty)}")

        items_summary = {did: ", ".join(parts) for did, parts in grouped.items()}

    return templates.TemplateResponse(
        "deliveries_list.html",
        {
            "request": request,
            "rows": rows,
            "agents": agents,
            "status": status,
            "agent_id": agent_id,
            "user": user,
            "items_summary": items_summary,
        },
    )

@app.post("/deliveries/new")
def delivery_create(
    request: Request,
    agent_id: int = Form(...),
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

    if not is_admin(user):
        agent_id = user.id

    cust = (customer_name or "").strip()
    if not cust:
        raise HTTPException(status_code=400, detail="Customer name required")

    d = Delivery(
        agent_id=int(agent_id),
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
        select(Delivery).where(Delivery.agent_id == user.id).order_by(desc(Delivery.created_at)).limit(300)
    ).scalars().all()

    return templates.TemplateResponse("my_deliveries.html", {"request": request, "rows": rows, "user": user})


@app.get("/deliveries/{delivery_id}", response_class=HTMLResponse)
def delivery_detail(request: Request, delivery_id: int, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    d = db.get(Delivery, delivery_id)
    if not d:
        return HTMLResponse("Not found", status_code=404)

    if not is_admin(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)

    d_items = db.execute(
        select(DeliveryItem, Item)
        .join(Item, Item.id == DeliveryItem.item_id)
        .where(DeliveryItem.delivery_id == d.id)
    ).all()

    # Delivery cash entries (extra collection + expenses)
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

    collection_total = float(col or 0)
    expense_total = float(exp or 0)

    return templates.TemplateResponse(
        "delivery_detail.html",
        {
            "request": request,
            "d": d,
            "d_items": d_items,
            "user": user,
            "error": None,
            "collection_total": collection_total,
            "expense_total": expense_total,
            "back_url": "/deliveries" if is_admin(user) else "/my-deliveries",
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

    status = (status or "").strip().upper()
    allowed = {"PENDING", "OUT_FOR_DELIVERY", "DELIVERED", "FAILED", "RETURNED"}
    if status not in allowed:
        raise HTTPException(status_code=400, detail="Invalid status")

    if status == "DELIVERED":
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
                },
            )
        return redirect(f"/deliveries/{delivery_id}")

    d.status = status
    db.commit()
    return redirect(f"/deliveries/{delivery_id}")


# ---------------- Cash ----------------
# Uses CashEntry model + includes OPERATING_CASH
# Assumes these helpers exist above:
# - _range_dates_from_inputs(preset, start_date, end_date) -> (sd: date|None, ed: date|None, preset_norm: str)
# - cash_range_from_preset(preset_norm) -> (start_dt: datetime|None, end_dt: datetime|None)
# - get_cash_summary(db, agent_id, start, end) -> (rows, total_collections, total_expenses, total_operating)
# Assumes CashEntry is imported from models and is_admin(), require_login_or_redirect(), redirect() exist.

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

    start_dt: datetime | None = None
    end_dt: datetime | None = None

    if preset_norm:
        start_dt, end_dt = cash_range_from_preset(preset_norm)
    else:
        if sd:
            start_dt = datetime.combine(sd, datetime.min.time())
        if ed:
            # inclusive end date in UI -> exclusive end datetime in DB query
            end_dt = datetime.combine(ed, datetime.min.time()) + timedelta(days=1)

    selected_agent_id: int | None = None
    if is_admin(user):
        if (agent_id or "").isdigit():
            selected_agent_id = int(agent_id)
    else:
        selected_agent_id = user.id

    rows, total_collections, total_expenses, total_operating = get_cash_summary(
        db=db,
        agent_id=selected_agent_id,
        start=start_dt,
        end=end_dt,
    )

    # Expenses reduce ONLY operating cash (as you requested)
    operating_balance = float(total_operating) - float(total_expenses)

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
            "agents": agents,
            "agent_id": agent_id,
            "preset": preset_norm or (preset or ""),
            "start_date": sd.isoformat() if sd else "",
            "end_date": ed.isoformat() if ed else "",
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
    if k not in {"COLLECTION", "EXPENSE", "OPERATING_CASH"}:
        raise HTTPException(status_code=400, detail="Invalid kind")

    amt = float(amount or 0)
    if amt <= 0:
        raise HTTPException(status_code=400, detail="Amount must be > 0")

    # Agent can only create for self; admin can create for any agent.
    target_agent_id = user.id
    if is_admin(user) and (agent_id or "").isdigit():
        target_agent_id = int(agent_id)

    d_id = int(delivery_id) if (delivery_id or "").isdigit() else None

    # Operating cash should not be tied to a delivery (keep it clean)
    if k == "OPERATING_CASH":
        d_id = None

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

    # Redirect back where user came from if possible (nice UX)
    referer = request.headers.get("referer") or ""
    if d_id:
        return redirect(f"/deliveries/{d_id}")
    if "/agents/" in referer:
        return RedirectResponse(referer, status_code=303)
    return redirect("/cash")