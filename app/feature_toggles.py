"""Lightweight key-value feature toggle helpers."""
from sqlalchemy import text
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
import time, logging

_WAT = timezone(timedelta(hours=1))  # West Africa Time (UTC+1)


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


def get_feature_value(db: Session, key: str, default: str = "") -> str:
    """Return the raw string value for a toggle key."""
    row = db.execute(text("SELECT value FROM feature_toggles WHERE key = :k"), {"k": key}).first()
    return row[0] if row else default


def get_all_toggles(db: Session) -> dict[str, bool]:
    """Return {key: True/False} for every toggle row."""
    rows = db.execute(text("SELECT key, value FROM feature_toggles")).fetchall()
    return {r[0]: r[1] == "on" for r in rows}


def get_all_toggles_raw(db: Session) -> dict[str, str]:
    """Return {key: raw_value} for every toggle row."""
    rows = db.execute(text("SELECT key, value FROM feature_toggles")).fetchall()
    return {r[0]: r[1] for r in rows}


def wait_for_contact_hours(db: Session) -> None:
    """If current time (WAT) is outside the configured contact window,
    sleep until the start hour. Call this from background threads only."""
    try:
        start_h = int(get_feature_value(db, "contact_start_hour", "8"))
        end_h = int(get_feature_value(db, "contact_end_hour", "20"))
    except (ValueError, TypeError):
        return  # bad config — don't block

    now_wat = datetime.now(_WAT)
    current_hour = now_wat.hour

    if start_h <= current_hour < end_h:
        return  # within allowed hours

    # Calculate seconds until start_hour
    if current_hour < start_h:
        # Before start today — wait until start today
        target = now_wat.replace(hour=start_h, minute=0, second=0, microsecond=0)
    else:
        # Past end today — wait until start tomorrow
        target = (now_wat + timedelta(days=1)).replace(hour=start_h, minute=0, second=0, microsecond=0)

    delay = (target - now_wat).total_seconds()
    if delay > 0:
        logging.getLogger("contact_hours").info(
            "Outside contact hours (%02d:00–%02d:00 WAT, now %s). Delaying %.0f seconds until %s.",
            start_h, end_h, now_wat.strftime("%H:%M"), delay, target.strftime("%H:%M")
        )
        time.sleep(delay)
