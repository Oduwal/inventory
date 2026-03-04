# app/services.py
from __future__ import annotations

from datetime import datetime, timedelta
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
    return {"items_count": items_count, "low_stock_count": low_stock_count, "recent_transactions": recent}


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

    lines = db.execute(select(DeliveryItem).where(DeliveryItem.delivery_id == delivery_id)).scalars().all()
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


def cash_range_from_preset(preset: str | None):
    p = (preset or "").strip().lower()
    now = datetime.utcnow()
    today = now.date()

    if p == "today":
        start = datetime.combine(today, datetime.min.time())
        end = start + timedelta(days=1)
        return start, end
    if p == "yesterday":
        start = datetime.combine(today - timedelta(days=1), datetime.min.time())
        end = start + timedelta(days=1)
        return start, end
    if p == "7d":
        end = now
        start = now - timedelta(days=7)
        return start, end
    if p == "30d":
        end = now
        start = now - timedelta(days=30)
        return start, end

    return None, None


def get_cash_summary(db: Session, agent_id: int | None, start: datetime | None, end: datetime | None):
    """
    Collections = sum(DeliveryItem.line_amount) + sum(CashEntry COLLECTION)
    Operating cash = sum(CashEntry OPERATING_CASH)
    Expenses = sum(CashEntry EXPENSE)

    Grouped by day.
    """
    d_day = func.date(Delivery.created_at).label("day")

    delivery_stmt = (
        select(
            d_day,
            func.coalesce(func.sum(func.coalesce(DeliveryItem.line_amount, 0)), 0).label("delivery_collections"),
        )
        .select_from(Delivery)
        .join(DeliveryItem, DeliveryItem.delivery_id == Delivery.id)
        .group_by(d_day)
        .order_by(d_day.asc())
    )

    if agent_id:
        delivery_stmt = delivery_stmt.where(Delivery.agent_id == agent_id)
    if start:
        delivery_stmt = delivery_stmt.where(Delivery.created_at >= start)
    if end:
        delivery_stmt = delivery_stmt.where(Delivery.created_at < end)

    delivery_rows = db.execute(delivery_stmt).all()

    c_day = func.date(CashEntry.created_at).label("day")
    expenses_sum = func.coalesce(func.sum(case((CashEntry.kind == "EXPENSE", CashEntry.amount), else_=0)), 0).label(
        "expenses"
    )
    extra_collections_sum = func.coalesce(
        func.sum(case((CashEntry.kind == "COLLECTION", CashEntry.amount), else_=0)), 0
    ).label("extra_collections")
    operating_sum = func.coalesce(
        func.sum(case((CashEntry.kind == "OPERATING_CASH", CashEntry.amount), else_=0)), 0
    ).label("operating_cash")

    cash_stmt = (
        select(c_day, expenses_sum, extra_collections_sum, operating_sum)
        .select_from(CashEntry)
        .group_by(c_day)
        .order_by(c_day.asc())
    )

    if agent_id:
        cash_stmt = cash_stmt.where(CashEntry.agent_id == agent_id)
    if start:
        cash_stmt = cash_stmt.where(CashEntry.created_at >= start)
    if end:
        cash_stmt = cash_stmt.where(CashEntry.created_at < end)

    cash_rows = db.execute(cash_stmt).all()

    by_day: dict[str, dict] = {}

    for r in delivery_rows:
        key = str(r.day)
        by_day.setdefault(key, {"day": key, "collections": 0.0, "expenses": 0.0, "operating_cash": 0.0})
        by_day[key]["collections"] += float(r.delivery_collections or 0)

    for r in cash_rows:
        key = str(r.day)
        by_day.setdefault(key, {"day": key, "collections": 0.0, "expenses": 0.0, "operating_cash": 0.0})
        by_day[key]["collections"] += float(r.extra_collections or 0)
        by_day[key]["expenses"] += float(r.expenses or 0)
        by_day[key]["operating_cash"] += float(r.operating_cash or 0)

    merged = list(by_day.values())
    merged.sort(key=lambda x: x["day"])

    total_collections = sum(x["collections"] for x in merged)
    total_expenses = sum(x["expenses"] for x in merged)
    total_operating = sum(x["operating_cash"] for x in merged)

    return merged, float(total_collections), float(total_expenses), float(total_operating)