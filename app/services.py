from __future__ import annotations

from datetime import datetime, timedelta
from sqlalchemy import select, func, case, desc
from sqlalchemy.orm import Session

from .models import Item, Transaction


def stock_subquery():
    """
    Calculates stock per item:
    SUM(IN qty) - SUM(OUT qty)
    """
    signed_qty = case(
        (Transaction.type == "IN", Transaction.quantity),
        (Transaction.type == "OUT", -Transaction.quantity),
        else_=0,
    )

    return (
        select(
            Transaction.item_id.label("item_id"),
            func.coalesce(func.sum(signed_qty), 0).label("stock"),
        )
        .group_by(Transaction.item_id)
        .subquery()
    )


def get_items_with_stock(db: Session):
    sq = stock_subquery()
    stmt = (
        select(Item, func.coalesce(sq.c.stock, 0).label("stock"))
        .outerjoin(sq, sq.c.item_id == Item.id)
        .order_by(Item.name.asc())
    )
    return db.execute(stmt).all()  # list[(Item, stock)]


def get_item_with_stock(db: Session, item_id: int):
    sq = stock_subquery()
    stmt = (
        select(Item, func.coalesce(sq.c.stock, 0).label("stock"))
        .outerjoin(sq, sq.c.item_id == Item.id)
        .where(Item.id == item_id)
    )
    return db.execute(stmt).first()  # (Item, stock) | None


def get_low_stock(db: Session):
    sq = stock_subquery()
    stmt = (
        select(Item, func.coalesce(sq.c.stock, 0).label("stock"))
        .outerjoin(sq, sq.c.item_id == Item.id)
        .where(func.coalesce(sq.c.stock, 0) <= Item.reorder_level)
        .order_by((func.coalesce(sq.c.stock, 0) - Item.reorder_level).asc(), Item.name.asc())
    )
    return db.execute(stmt).all()


def get_recent_transactions(db: Session, limit: int = 20):
    stmt = select(Transaction).order_by(desc(Transaction.created_at)).limit(limit)
    return db.scalars(stmt).all()


def dashboard_stats(db: Session):
    items_count = db.scalar(select(func.count(Item.id))) or 0
    low_stock_count = len(get_low_stock(db))
    recent = get_recent_transactions(db, limit=10)
    return {
        "items_count": items_count,
        "low_stock_count": low_stock_count,
        "recent_transactions": recent,
    }


def dashboard_kpis(db: Session):
    sq = stock_subquery()

    total_stock_stmt = select(func.coalesce(func.sum(sq.c.stock), 0))
    total_stock = db.scalar(total_stock_stmt) or 0

    value_stmt = (
        select(func.coalesce(func.sum((func.coalesce(sq.c.stock, 0) * Item.cost_price)), 0))
        .select_from(Item)
        .outerjoin(sq, sq.c.item_id == Item.id)
    )
    inventory_value = float(db.scalar(value_stmt) or 0)

    return int(total_stock), float(inventory_value)


def stock_by_category(db: Session):
    sq = stock_subquery()
    stmt = (
        select(
            func.coalesce(Item.category, "Uncategorized").label("category"),
            func.coalesce(func.sum(func.coalesce(sq.c.stock, 0)), 0).label("stock"),
        )
        .select_from(Item)
        .outerjoin(sq, sq.c.item_id == Item.id)
        .group_by(func.coalesce(Item.category, "Uncategorized"))
        .order_by(func.sum(func.coalesce(sq.c.stock, 0)).desc())
    )
    return db.execute(stmt).all()  # list[(category, stock)]


def in_out_last_7_days(db: Session):
    since = datetime.utcnow() - timedelta(days=7)

    in_sum = func.coalesce(func.sum(case((Transaction.type == "IN", Transaction.quantity), else_=0)), 0)
    out_sum = func.coalesce(func.sum(case((Transaction.type == "OUT", Transaction.quantity), else_=0)), 0)

    stmt = select(in_sum.label("in_qty"), out_sum.label("out_qty")).where(Transaction.created_at >= since)
    row = db.execute(stmt).first()
    in_qty = int(row.in_qty) if row else 0
    out_qty = int(row.out_qty) if row else 0
    return in_qty, out_qty


def top_items_by_stock(db: Session, limit: int = 5):
    sq = stock_subquery()
    stmt = (
        select(Item, func.coalesce(sq.c.stock, 0).label("stock"))
        .select_from(Item)
        .outerjoin(sq, sq.c.item_id == Item.id)
        .order_by(func.coalesce(sq.c.stock, 0).desc(), Item.name.asc())
        .limit(limit)
    )
    return db.execute(stmt).all()