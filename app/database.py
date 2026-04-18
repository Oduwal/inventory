import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# If hosting provides DATABASE_URL, use it.
# In production (Railway sets RAILWAY_ENVIRONMENT), fail loudly if missing.
# Only fall back to local SQLite in development.
DATABASE_URL = os.getenv("DATABASE_URL", "")
if not DATABASE_URL:
    if os.getenv("RAILWAY_ENVIRONMENT"):
        raise RuntimeError(
            "DATABASE_URL is required in production but is not set. "
            "Check your Railway service variables."
        )
    DATABASE_URL = "sqlite:///./inventory.db"  # dev-only fallback

connect_args = {}
engine_kwargs: dict = {"pool_pre_ping": True}

if DATABASE_URL.startswith("sqlite"):
    # SQLite does not support pool_size / max_overflow (uses StaticPool / NullPool).
    connect_args = {"check_same_thread": False}
else:
    # PostgreSQL (and other server-backed DBs) benefit from connection pooling.
    # Configurable via env vars so infrastructure can scale without code changes.
    engine_kwargs["pool_size"] = int(os.getenv("DB_POOL_SIZE", "20"))
    engine_kwargs["max_overflow"] = int(os.getenv("DB_MAX_OVERFLOW", "10"))

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
