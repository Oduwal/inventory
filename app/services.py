from __future__ import annotations

from datetime import datetime, timedelta
from sqlalchemy import select, func, case, desc
from sqlalchemy.orm import Session

from .models import Item, Transaction, Delivery, DeliveryItem, CashLog


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
    """
    Stock gets deducted only when the delivery becomes DELIVERED.
    Idempotent behavior prevents duplicate OUT transactions per delivery.
    """
    existing_out = (
        db.scalar(
            select(func.count(Transaction.id))
            .where(Transaction.delivery_id == delivery_id)
            .where(Transaction.type == "OUT")
        )
        or 0
    )

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

    db.commit()


def get_delivery_finance(db: Session, delivery_id: int):
    """
    Collections = sum(DeliveryItem.line_amount) + extra cash logs (COLLECTION)
    Expenses = sum cash logs (EXPENSE)
    """
    line_total = (
        db.scalar(
            select(func.coalesce(func.sum(DeliveryItem.line_amount), 0))
            .where(DeliveryItem.delivery_id == delivery_id)
        )
        or 0
    )

    extra_collection = (
        db.scalar(
            select(func.coalesce(func.sum(CashLog.amount), 0))
            .where(CashLog.delivery_id == delivery_id)
            .where(CashLog.kind == "COLLECTION")
        )
        or 0
    )

    expense_total = (
        db.scalar(
            select(func.coalesce(func.sum(CashLog.amount), 0))
            .where(CashLog.delivery_id == delivery_id)
            .where(CashLog.kind == "EXPENSE")
        )
        or 0
    )

    collection_total = float(line_total) + float(extra_collection)
    return float(collection_total), float(expense_total)


def _preset_range(preset: str | None):
    now = datetime.utcnow()
    today = now.date()

    if preset == "today":
        start = datetime(today.year, today.month, today.day)
        end = start + timedelta(days=1)
        return start, end

    if preset == "yesterday":
        end = datetime(today.year, today.month, today.day)
        start = end - timedelta(days=1)
        return start, end

    if preset == "7d":
        return now - timedelta(days=7), now

    if preset == "30d":
        return now - timedelta(days=30), now

    return None, None


def get_cash_summary(db: Session, agent_id: int | None, preset: str | None, start_date: str | None, end_date: str | None):
    start_dt, end_dt = _preset_range(preset)

    if start_date:
        y, m, d = [int(x) for x in start_date.split("-")]
        start_dt = datetime(y, m, d)

    if end_date:
        y, m, d = [int(x) for x in end_date.split("-")]
        end_dt = datetime(y, m, d) + timedelta(days=1)

    collections_expr = func.coalesce(func.sum(case((CashLog.kind == "COLLECTION", CashLog.amount), else_=0)), 0)
    expenses_expr = func.coalesce(func.sum(case((CashLog.kind == "EXPENSE", CashLog.amount), else_=0)), 0)

    stmt = select(
        func.date(CashLog.created_at).label("day"),
        collections_expr.label("collections"),
        expenses_expr.label("expenses"),
    )

    if agent_id is not None:
        stmt = stmt.where(CashLog.agent_id == agent_id)

    if start_dt is not None:
        stmt = stmt.where(CashLog.created_at >= start_dt)

    if end_dt is not None:
        stmt = stmt.where(CashLog.created_at < end_dt)

    stmt = stmt.group_by(func.date(CashLog.created_at)).order_by(func.date(CashLog.created_at).desc())

    rows = db.execute(stmt).all()
    total_collections = sum(float(r.collections) for r in rows)
    total_expenses = sum(float(r.expenses) for r in rows)

    return rows, total_collections, total_expenses


def add_cash_log(db: Session, agent_id: int, kind: str, amount: float, note: str | None, delivery_id: int | None):
    kind_norm = (kind or "").strip().upper()
    if kind_norm not in {"EXPENSE", "COLLECTION"}:
        raise ValueError("Invalid type")

    amt = float(amount)
    if amt <= 0:
        raise ValueError("Amount must be greater than 0")

    db.add(
        CashLog(
            agent_id=agent_id,
            delivery_id=delivery_id,
            kind=kind_norm,
            amount=amt,
            note=(note or "").strip() or None,
        )
    )
    db.commit()