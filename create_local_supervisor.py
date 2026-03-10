import os, sys
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("SESSION_SECRET", "local-dev-secret-at-least-32-chars-long-seed")

from app.database import engine
from app.models import User
from sqlalchemy.orm import Session
from sqlalchemy import select
from passlib.context import CryptContext

pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

with Session(engine) as db:
    existing = db.scalar(select(User).where(User.username == "supervisor"))
    if existing:
        print("Supervisor already exists.")
    else:
        db.add(User(
            username="supervisor",
            password_hash=pwd.hash("Password1!"),
            role="SUPERVISOR",
        ))
        db.commit()
        print("Supervisor created. Login: supervisor / Password1!")
