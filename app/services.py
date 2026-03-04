from __future__ import annotations

from datetime import datetime, timedelta, date
from sqlalchemy import select, func, case, desc
from sqlalchemy.orm import Session

from .models import Item, Transaction, Delivery, DeliveryItem, CashEntry


def stock_subquery():
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
    return db.execute(stmt).all()


def get_item_with_stock(db: Session, item_id: int):
    sq = stock_subquery()
    stmt = (
        select(Item, func.coalesce(sq.c.stock, 0).label("stock"))
        .outerjoin(sq, sq.c.item_id == Item.id)
        .where(Item.id == item_id)
    )
    return db.execute(stmt).first()


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
    return db.execute(stmt).all()


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


def create_out_transactions_for_delivery_if_needed(db: Session, delivery_id: int, performed_by: str):
    existing_out = db.scalar(
        select(func.count(Transaction.id))
        .where(Transaction.delivery_id == delivery_id)
        .where(Transaction.type == "OUT")
    ) or 0

    if int(existing_out) > 0:
        return

    delivery = db.get(Delivery, delivery_id)
    if not delivery:
        raise ValueError("Delivery not found")

    lines = db.execute(
        select(DeliveryItem).where(DeliveryItem.delivery_id == delivery_id)
    ).scalars().all()

    if not lines:
        raise ValueError("Order has no items")

    for li in lines:
        row = get_item_with_stock(db, li.item_id)
        if not row:
            raise ValueError("Item missing")
        _it, stock = row
        if int(stock) < int(li.quantity):
            raise ValueError("Insufficient stock for one or more items")

    for li in lines:
        db.add(
            Transaction(
                item_id=li.item_id,
                delivery_id=delivery_id,
                type="OUT",
                quantity=li.quantity,
                reference=f"DELIVERY #{delivery_id}",
                note=f"Auto-deduct on delivered by {performed_by}",
            )
        )

    db.flush()


def delivery_line_total(db: Session, delivery_id: int) -> float:
    total = db.scalar(
        select(func.coalesce(func.sum(DeliveryItem.line_amount), 0))
        .where(DeliveryItem.delivery_id == delivery_id)
    ) or 0
    return float(total)


def delivery_cash_totals(db: Session, delivery_id: int) -> tuple[float, float]:
    collections = db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.delivery_id == delivery_id)
        .where(CashEntry.kind == "COLLECTION")
    ) or 0

    expenses = db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.delivery_id == delivery_id)
        .where(CashEntry.kind == "EXPENSE")
    ) or 0

    return float(collections), float(expenses)


def cash_summary_by_day(
    db: Session,
    start_dt: datetime,
    end_dt: datetime,
    agent_id: int | None = None,
):
    day_col = func.date(CashEntry.created_at).label("day")
    collections = func.coalesce(func.sum(case((CashEntry.kind == "COLLECTION", CashEntry.amount), else_=0)), 0).label("collections")
    expenses = func.coalesce(func.sum(case((CashEntry.kind == "EXPENSE", CashEntry.amount), else_=0)), 0).label("expenses")

    stmt = (
        select(day_col, collections, expenses)
        .where(CashEntry.created_at >= start_dt)
        .where(CashEntry.created_at <= end_dt)
        .group_by(day_col)
        .order_by(day_col.desc())
    )

    if agent_id is not None:
        stmt = stmt.where(CashEntry.agent_id == agent_id)

    return db.execute(stmt).all()


def cash_totals(
    db: Session,
    start_dt: datetime,
    end_dt: datetime,
    agent_id: int | None = None,
):
    collections = func.coalesce(func.sum(case((CashEntry.kind == "COLLECTION", CashEntry.amount), else_=0)), 0)
    expenses = func.coalesce(func.sum(case((CashEntry.kind == "EXPENSE", CashEntry.amount), else_=0)), 0)

    stmt = (
        select(collections.label("collections"), expenses.label("expenses"))
        .where(CashEntry.created_at >= start_dt)
        .where(CashEntry.created_at <= end_dt)
    )

    if agent_id is not None:
        stmt = stmt.where(CashEntry.agent_id == agent_id)

    row = db.execute(stmt).first()
    if not row:
        return 0.0, 0.0
    return float(row.collections), float(row.expenses)