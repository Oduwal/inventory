"""Lightweight key-value feature toggle helpers."""
from sqlalchemy import text
from sqlalchemy.orm import Session


def is_feature_on(db: Session, key: str) -> bool:
    """Return True if the toggle *key* is 'on' (default if missing)."""
    row = db.execute(text("SELECT value FROM feature_toggles WHERE key = :k"), {"k": key}).first()
    if row is None:
        return True  # default: enabled
    return row[0] == "on"


def set_feature(db: Session, key: str, value: str) -> None:
    """Set a toggle key to 'on' or 'off'."""
    db.execute(
        text("UPDATE feature_toggles SET value = :v, updated_at = CURRENT_TIMESTAMP WHERE key = :k"),
        {"v": value, "k": key},
    )
    db.commit()


def get_all_toggles(db: Session) -> dict[str, bool]:
    """Return {key: True/False} for every toggle row."""
    rows = db.execute(text("SELECT key, value FROM feature_toggles")).fetchall()
    return {r[0]: r[1] == "on" for r in rows}
