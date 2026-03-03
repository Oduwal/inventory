import os
from datetime import datetime
from typing import Generator

from fastapi import FastAPI, Request, Form, Depends, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from passlib.context import CryptContext
from sqlalchemy import select, text, desc
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .models import Item, Transaction, User, Delivery, DeliveryItem
from .services import (
    record_transaction,
    get_dashboard_data,
    add_item,
    update_item,
    delete_item,
    get_items_with_stock,
    get_item_with_stock,
    get_low_stock,
    get_recent_transactions,
    dashboard_stats,
    dashboard_kpis,
    stock_by_category,
    in_out_last_7_days,
    top_items_by_stock,
)

# ------------------------------------------------------------
# App + Templates
# ------------------------------------------------------------

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

static_dir = os.path.join(BASE_DIR, "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Session cookie
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me")
HTTPS_ONLY = os.getenv("HTTPS_ONLY", "1") not in {"0", "false", "False", "no", "NO"}

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=HTTPS_ONLY,
    same_site="lax",
)

# Password hashing
# bcrypt has a 72-byte input limit and can break depending on bcrypt/passlib versions.
# pbkdf2_sha256 avoids those issues and works well for web apps.
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


# ------------------------------------------------------------
# DB helpers
# ------------------------------------------------------------

def ensure_schema() -> None:
    """Create tables and apply small, safe migrations."""
    Base.metadata.create_all(bind=engine)

    # Safe migration: add delivery_id to transactions if missing.
    with engine.connect() as conn:
        try:
            conn.execute(text("SELECT delivery_id FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE transactions ADD COLUMN delivery_id INTEGER"))
            except Exception:
                pass


def seed_admin_if_missing() -> None:
    """Create an ADMIN user once, using env vars ADMIN_USERNAME / ADMIN_PASSWORD."""
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

        existing_username = db.scalar(select(User).where(User.username == admin_user))
        if existing_username:
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


# ------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------

def get_current_user(db: Session, request: Request) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.get(User, int(user_id))


def is_admin(user: User) -> bool:
    return (user.role or "").upper() == "ADMIN"


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url=path, status_code=303)


def require_login_or_redirect(db: Session, request: Request) -> User | RedirectResponse:
    user = get_current_user(db, request)
    if not user:
        return redirect("/login")
    return user


def require_admin_or_403(user: User) -> HTMLResponse | None:
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    return None


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        return False
    # Legacy bcrypt hashes start with $2...
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

@app.get("/create-admin", response_class=HTMLResponse)
def create_admin_page(request: Request, db: Session = Depends(get_db)):
    """
    Admin bootstrap page.

    Access gets allowed without login only if no ADMIN exists yet.
    After an admin exists, access requires an ADMIN session.
    """
    has_admin = db.scalar(select(User).where(User.role == "ADMIN"))
    current = get_current_user(db, request)
    if has_admin and (not current or not is_admin(current)):
        return redirect("/login")

    return HTMLResponse(
        """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Create Admin</title></head>
<body style="font-family: system-ui; max-width: 520px; margin: 40px auto;">
  <h2>Create Admin</h2>
  <form method="post">
    <label>Username</label><br/>
    <input name="username" required style="width:100%; padding:10px; margin:6px 0 14px;"/>
    <label>Password</label><br/>
    <input name="password" type="password" required style="width:100%; padding:10px; margin:6px 0 14px;"/>
    <button type="submit" style="padding:10px 14px;">Create</button>
  </form>
  <p style="margin-top: 16px;"><a href="/login">Login</a></p>
</body>
</html>"""
    )


@app.post("/create-admin")
def create_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    has_admin = db.scalar(select(User).where(User.role == "ADMIN"))
    current = get_current_user(db, request)

    if has_admin and (not current or not is_admin(current)):
        raise HTTPException(status_code=403, detail="Forbidden")

    username = (username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username required")

    existing = db.scalar(select(User).where(User.username == username))
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    db.add(
        User(
            username=username,
            password_hash=hash_password(password),
            role="ADMIN",
            full_name="Admin",
        )
    )
    db.commit()

    return redirect("/login")

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
    if not u or not pwd_context.verify(password, u.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid login."})

    request.session["user_id"] = u.id
    request.session["role"] = u.role
    return redirect("/")


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


# ---------------- Home / Dashboard ----------------

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

    categories = [c for (c, _s) in cat_rows]
    cat_stock = [int(s) for (_c, s) in cat_rows]

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
            "categories": categories,
            "cat_stock": cat_stock,
        },
    )


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
    return templates.TemplateResponse("item_form.html", {"request": request, "mode": "new", "item": None, "error": error, "user": user})


@app.post("/items/new")
def item_create(
    request: Request,
    sku: str = Form(default=""),
    name: str = Form(...),
    category: str = Form(default=""),
    reorder_level: int = Form(default=0),
    cost_price: float = Form(default=0),
    selling_price: float = Form(default=0),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    sku_clean = sku.strip() or None
    if sku_clean and db.scalar(select(Item).where(Item.sku == sku_clean)):
        return redirect("/items/new?error=SKU+already+exists")

    item = Item(
        sku=sku_clean,
        name=name.strip(),
        category=category.strip() or None,
        unit="pcs",
        reorder_level=max(0, int(reorder_level)),
        cost_price=max(0.0, float(cost_price)),
        selling_price=max(0.0, float(selling_price)),
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return redirect(f"/items/{item.id}")


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
        select(Transaction).where(Transaction.item_id == item_id).order_by(desc(Transaction.created_at)).limit(100)
    ).all()

    return templates.TemplateResponse(
        "item_detail.html",
        {"request": request, "item": item, "stock": stock, "txs": txs, "user": user},
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
        "item_form.html",
        {"request": request, "mode": "edit", "item": item, "error": error, "user": user},
    )


@app.post("/items/{item_id}/edit")
def item_update(
    request: Request,
    item_id: int,
    sku: str = Form(default=""),
    name: str = Form(...),
    category: str = Form(default=""),
    reorder_level: int = Form(default=0),
    cost_price: float = Form(default=0),
    selling_price: float = Form(default=0),
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

    sku_clean = sku.strip() or None
    if sku_clean and db.scalar(select(Item).where(Item.sku == sku_clean, Item.id != item_id)):
        return redirect(f"/items/{item_id}/edit?error=SKU+already+exists")

    item.sku = sku_clean
    item.name = name.strip()
    item.category = category.strip() or None
    item.reorder_level = max(0, int(reorder_level))
    item.cost_price = max(0.0, float(cost_price))
    item.selling_price = max(0.0, float(selling_price))
    db.commit()
    return redirect(f"/items/{item_id}")


@app.post("/items/{item_id}/delete")
def item_delete(request: Request, item_id: int, db: Session = Depends(get_db)):
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

    db.delete(item)
    db.commit()
    return redirect("/items")


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

    if tx_type not in ("IN", "OUT"):
        return redirect("/transactions/new?error=Invalid+type")
    if int(quantity) <= 0:
        return redirect("/transactions/new?error=Quantity+must+be+greater+than+0")

    if not db.get(Item, item_id):
        return redirect("/transactions/new?error=Item+not+found")

    tx = Transaction(
        item_id=item_id,
        type=tx_type,
        quantity=int(quantity),
        reference=reference.strip() or None,
        note=note.strip() or None,
    )
    db.add(tx)
    db.commit()
    return redirect(f"/items/{item_id}")


# ---------------- Low Stock ----------------

@app.get("/low-stock", response_class=HTMLResponse)
def low_stock(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    rows = get_low_stock(db)
    return templates.TemplateResponse("low_stock.html", {"request": request, "rows": rows, "user": user})


# ---------------- Import (Admin) ----------------

@app.get("/import", response_class=HTMLResponse)
def import_page(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    return templates.TemplateResponse("import.html", {"request": request, "message": None, "user": user})


@app.post("/import", response_class=HTMLResponse)
async def import_items(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    filename = (file.filename or "").lower()
    if not (filename.endswith(".csv") or filename.endswith(".xlsx")):
        return templates.TemplateResponse("import.html", {"request": request, "message": "Upload a .csv or .xlsx file.", "user": user})

    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(file.file)
        else:
            df = pd.read_excel(file.file)
    except Exception:
        return templates.TemplateResponse("import.html", {"request": request, "message": "File could not be read. Check format.", "user": user})

    df.columns = [str(c).strip().lower() for c in df.columns]
    if "name" not in set(df.columns):
        return templates.TemplateResponse("import.html", {"request": request, "message": "File must have at least a 'name' column.", "user": user})

    created = 0
    updated = 0

    for _, row in df.iterrows():
        name = str(row.get("name", "")).strip()
        if not name or name.lower() == "nan":
            continue

        sku_val = row.get("sku", None)
        sku = None if pd.isna(sku_val) else str(sku_val).strip()
        sku = sku or None

        category_val = row.get("category", None)
        category = None if pd.isna(category_val) else str(category_val).strip()
        category = category or None

        reorder_val = row.get("reorder_level", 0)
        try:
            reorder_level = int(reorder_val) if not pd.isna(reorder_val) else 0
        except Exception:
            reorder_level = 0

        cost_val = row.get("cost_price", 0)
        sell_val = row.get("selling_price", 0)
        try:
            cost_price = float(cost_val) if not pd.isna(cost_val) else 0.0
        except Exception:
            cost_price = 0.0
        try:
            selling_price = float(sell_val) if not pd.isna(sell_val) else 0.0
        except Exception:
            selling_price = 0.0

        item = db.query(Item).filter(Item.sku == sku).first() if sku else None
        if item:
            item.name = name
            item.category = category
            item.reorder_level = max(0, reorder_level)
            item.cost_price = max(0.0, cost_price)
            item.selling_price = max(0.0, selling_price)
            updated += 1
        else:
            db.add(
                Item(
                    sku=sku,
                    name=name,
                    category=category,
                    unit="pcs",
                    reorder_level=max(0, reorder_level),
                    cost_price=max(0.0, cost_price),
                    selling_price=max(0.0, selling_price),
                )
            )
            created += 1

    db.commit()
    return templates.TemplateResponse("import.html", {"request": request, "message": f"Import complete. Created {created}, updated {updated}.", "user": user})


# ---------------- Agents (Admin) ----------------

@app.get("/agents", response_class=HTMLResponse)
def agents_page(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    agents = db.execute(select(User).where(User.role == "AGENT").order_by(User.username.asc())).scalars().all()
    return templates.TemplateResponse("agents.html", {"request": request, "agents": agents, "user": user})


@app.post("/agents/new")
def create_agent(
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

    username = username.strip()
    if not username or db.scalar(select(User).where(User.username == username)):
        return redirect("/agents")

    db.add(
        User(
            username=username,
            password_hash=hash_password(password),
            role="AGENT",
            full_name=full_name.strip() or None,
            phone=phone.strip() or None,
        )
    )
    db.commit()
    return redirect("/agents")


# ---------------- Deliveries ----------------

@app.get("/deliveries", response_class=HTMLResponse)
def deliveries_admin_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    status = request.query_params.get("status", "").strip().upper()
    agent_id = request.query_params.get("agent_id", "").strip()

    stmt = select(Delivery).order_by(desc(Delivery.created_at)).limit(300)

    if status:
        stmt = stmt.where(Delivery.status == status)
    if agent_id.isdigit():
        stmt = stmt.where(Delivery.agent_id == int(agent_id))

    rows = db.execute(stmt).scalars().all()
    agents = db.execute(select(User).where(User.role == "AGENT").order_by(User.username.asc())).scalars().all()

    return templates.TemplateResponse(
        "deliveries_list.html",
        {"request": request, "rows": rows, "agents": agents, "status": status, "agent_id": agent_id, "user": user},
    )


@app.get("/deliveries/new", response_class=HTMLResponse)
def delivery_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    agents = db.execute(select(User).where(User.role == "AGENT").order_by(User.username.asc())).scalars().all()
    items = db.execute(select(Item).order_by(Item.name.asc())).scalars().all()
    return templates.TemplateResponse("delivery_new.html", {"request": request, "agents": agents, "items": items, "user": user})


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
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    forbid = require_admin_or_403(user)
    if forbid:
        return forbid

    d = Delivery(
        agent_id=agent_id,
        customer_name=customer_name.strip(),
        customer_phone=customer_phone.strip() or None,
        address=address.strip() or None,
        note=note.strip() or None,
        status="OUT_FOR_DELIVERY",
    )
    db.add(d)
    db.flush()  # assigns d.id

    for iid, qty in zip(item_id, quantity):
        qty_int = int(qty) if qty is not None else 0
        if qty_int > 0:
            db.add(DeliveryItem(delivery_id=d.id, item_id=int(iid), quantity=qty_int))

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

    return templates.TemplateResponse(
        "delivery_detail.html",
        {"request": request, "d": d, "d_items": d_items, "user": user, "error": None},
    )


@app.post("/deliveries/{delivery_id}/delivered")
def mark_delivered(request: Request, delivery_id: int, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    d = db.get(Delivery, delivery_id)
    if not d:
        return HTMLResponse("Not found", status_code=404)

    if not is_admin(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)

    if d.status == "DELIVERED":
        return redirect(f"/deliveries/{delivery_id}")

    lines = db.execute(select(DeliveryItem).where(DeliveryItem.delivery_id == d.id)).scalars().all()

    # Stock check (prevents negative stock)
    for li in lines:
        row = get_item_with_stock(db, li.item_id)
        if row:
            _it, stock = row
            if int(stock) < int(li.quantity):
                d_items = db.execute(
                    select(DeliveryItem, Item)
                    .join(Item, Item.id == DeliveryItem.item_id)
                    .where(DeliveryItem.delivery_id == d.id)
                ).all()
                return templates.TemplateResponse(
                    "delivery_detail.html",
                    {"request": request, "d": d, "d_items": d_items, "user": user, "error": "Insufficient stock for one or more items."},
                )

    # Deduct stock by writing OUT transactions linked to delivery
    for li in lines:
        db.add(
            Transaction(
                item_id=li.item_id,
                delivery_id=d.id,
                type="OUT",
                quantity=li.quantity,
                reference=f"DELIVERY #{d.id}",
                note=f"Delivered by {user.username}",
            )
        )

    d.status = "DELIVERED"
    d.delivered_at = datetime.utcnow()
    db.commit()
    return redirect(f"/deliveries/{delivery_id}")