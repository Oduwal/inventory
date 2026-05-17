from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User

UNASSIGNED_USERNAME_PREFIX = "unassigned_b"


def unassigned_username(branch_id: int) -> str:
    return f"{UNASSIGNED_USERNAME_PREFIX}{branch_id}"


def get_or_create_unassigned_user(db: Session, branch_id: int) -> User:
    """Return the per-branch placeholder 'Unassigned' user.

    A Delivery owned by this user means it's still in the /orders queue and
    has not yet been assigned to a real agent. Created on first use so no
    migration is needed.
    """
    uname = unassigned_username(branch_id)
    u = db.scalar(select(User).where(User.username == uname))
    if u:
        return u
    u = User(
        username=uname,
        password_hash="!disabled",
        role="AGENT",
        branch_id=branch_id,
        full_name="Unassigned (queue)",
        is_active=True,
    )
    db.add(u)
    db.flush()
    return u


def is_unassigned_user(user: User) -> bool:
    return bool(user and user.username and user.username.startswith(UNASSIGNED_USERNAME_PREFIX))
