from fastapi import FastAPI, Request, Depends, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext

from .database import get_db, engine, Base
from .models import User

app = FastAPI()

# Create tables
Base.metadata.create_all(bind=engine)

# Session middleware
app.add_middleware(SessionMiddleware, secret_key="super-secret-key-change-this")

# Static + Templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# =========================
# AUTH HELPERS
# =========================

def get_current_user(request: Request, db: Session):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def require_login(request: Request, db: Session):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return user


def require_admin(request: Request, db: Session):
    user = get_current_user(request, db)
    if not user or user.role != "ADMIN":
        return RedirectResponse("/", status_code=302)
    return user


# =========================
# LOGIN ROUTES
# =========================

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()

    if not user or not pwd_context.verify(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials"},
        )

    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=302)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# =========================
# CREATE DEFAULT ADMIN
# =========================

@app.get("/create-admin")
def create_admin(db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == "admin").first()
    if existing:
        return {"message": "Admin already exists"}

    hashed = pwd_context.hash("admin123")

    admin = User(
        username="admin",
        full_name="Administrator",
        role="ADMIN",
        password_hash=hashed
    )

    db.add(admin)
    db.commit()

    return {"message": "Admin created successfully"}


# =========================
# DASHBOARD (Protected)
# =========================

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)

    if not user:
        return RedirectResponse("/login", status_code=302)

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
        },
    )