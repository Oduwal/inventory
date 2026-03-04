from datetime import datetime, timedelta
from sqlalchemy import select, func, case, desc
from sqlalchemy.orm import Session

from .models import Item, Transaction, DeliveryItem, CashLog


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
        select(Item, func.coalesce(sq.c.stock, 0))
        .outerjoin(sq, sq.c.item_id == Item.id)
        .order_by(Item.name)
    )

    return db.execute(stmt).all()


def get_item_with_stock(db: Session, item_id: int):

    sq = stock_subquery()

    stmt = (
        select(Item, func.coalesce(sq.c.stock, 0))
        .outerjoin(sq, sq.c.item_id == Item.id)
        .where(Item.id == item_id)
    )

    return db.execute(stmt).first()


def get_recent_transactions(db: Session, limit=20):

    stmt = select(Transaction).order_by(desc(Transaction.created_at)).limit(limit)

    return db.scalars(stmt).all()


def create_out_transactions_for_delivery_if_needed(db: Session, delivery_id: int):

    lines = db.execute(
        select(DeliveryItem).where(DeliveryItem.delivery_id == delivery_id)
    ).scalars().all()

    for li in lines:

        db.add(
            Transaction(
                item_id=li.item_id,
                delivery_id=delivery_id,
                type="OUT",
                quantity=li.quantity,
                reference=f"DELIVERY #{delivery_id}",
            )
        )

    db.commit()


def get_delivery_finance(db: Session, delivery_id: int):

    collection = db.scalar(
        select(func.coalesce(func.sum(CashLog.amount), 0))
        .where(CashLog.delivery_id == delivery_id)
        .where(CashLog.kind == "COLLECTION")
    ) or 0

    expense = db.scalar(
        select(func.coalesce(func.sum(CashLog.amount), 0))
        .where(CashLog.delivery_id == delivery_id)
        .where(CashLog.kind == "EXPENSE")
    ) or 0

    return collection, expense