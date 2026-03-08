import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# If hosting provides DATABASE_URL, use it.
# Otherwise fall back to local SQLite.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./inventory.db")

connect_args = {}
engine_kwargs: dict = {"pool_pre_ping": True}

if DATABASE_URL.startswith("sqlite"):
    # SQLite does not support pool_size / max_overflow (uses StaticPool / NullPool).
    connect_args = {"check_same_thread": False}
else:
    # PostgreSQL (and other server-backed DBs) benefit from connection pooling.
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    **engine_kwargs,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
