import os
from datetime import datetime
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
from .models import Item, Transaction, User, Delivery, DeliveryItem
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


def ensure_schema() -> None:
    Base.metadata.create_all(bind=engine)

    with engine.connect() as conn:
        # Ensure delivery_id exists on transactions for older DBs
        try:
            conn.execute(text("SELECT delivery_id FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE transactions ADD COLUMN delivery_id INTEGER"))
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

    low = get_low_stock(db)
    return {"count": len(low)}


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


# ---------------- Transactions ----------------

@app.get("/transactions", response_class=HTMLResponse)
def transactions_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    txs = get_recent_transactions(db, limit=200)
    return templates.TemplateResponse("transactions_list.html", {"request": request, "txs": txs, "user": user})


# ---------------- Agents ----------------

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


# ---------------- Deliveries / Orders ----------------

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

    # Admin sees agent picker, agent sees self only
    agents = db.execute(select(User).where(User.role == "AGENT").order_by(User.username.asc())).scalars().all()
    items = db.execute(select(Item).order_by(Item.name.asc())).scalars().all()

    return templates.TemplateResponse(
        "delivery_new.html",
        {"request": request, "agents": agents, "items": items, "user": user},
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
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or

    # Agents can only create orders for themselves
    if not is_admin(user):
        agent_id = user.id

    d = Delivery(
        agent_id=int(agent_id),
        customer_name=customer_name.strip(),
        customer_phone=customer_phone.strip() or None,
        address=address.strip() or None,
        note=note.strip() or None,
        status="PENDING",
    )
    db.add(d)
    db.flush()

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
                {"request": request, "d": d, "d_items": d_items, "user": user, "error": str(e)},
            )
        return redirect(f"/deliveries/{delivery_id}")

    d.status = status
    db.commit()
    return redirect(f"/deliveries/{delivery_id}")