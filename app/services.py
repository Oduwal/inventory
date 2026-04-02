from __future__ import annotations

from datetime import datetime, timedelta
from sqlalchemy import select, func, case, desc
from sqlalchemy.orm import Session

from .models import Item, Transaction, Delivery, DeliveryItem, CashEntry


def stock_subquery(branch_id: int | None = None):
    """
    Returns a subquery of (item_id, stock).
    When branch_id is provided, only transactions for that branch are included.
    """
    signed_qty = case(
        (Transaction.type == "IN", Transaction.quantity),
        (Transaction.type == "OUT", -Transaction.quantity),
        else_=0,
    )

    stmt = select(
        Transaction.item_id.label("item_id"),
        func.coalesce(func.sum(signed_qty), 0).label("stock"),
    )

    if branch_id is not None:
        stmt = stmt.where(Transaction.branch_id == branch_id)

    return stmt.group_by(Transaction.item_id).subquery()


def get_items_with_stock(db: Session, branch_id: int | None = None):
    sq = stock_subquery(branch_id)
    stmt = (
        select(Item, func.coalesce(sq.c.stock, 0).label("stock"))
        .outerjoin(sq, sq.c.item_id == Item.id)
        .order_by(Item.name.asc())
    )
    if branch_id is not None:
        stmt = stmt.where(Item.branch_id == branch_id)
    return db.execute(stmt).all()


def get_item_with_stock(db: Session, item_id: int, branch_id: int | None = None):
    sq = stock_subquery(branch_id)
    stmt = (
        select(Item, func.coalesce(sq.c.stock, 0).label("stock"))
        .outerjoin(sq, sq.c.item_id == Item.id)
        .where(Item.id == item_id)
    )
    return db.execute(stmt).first()


def get_low_stock(db: Session, branch_id: int | None = None):
    sq = stock_subquery(branch_id)
    stmt = (
        select(Item, func.coalesce(sq.c.stock, 0).label("stock"))
        .outerjoin(sq, sq.c.item_id == Item.id)
        .where(func.coalesce(sq.c.stock, 0) <= Item.reorder_level)
        .order_by((func.coalesce(sq.c.stock, 0) - Item.reorder_level).asc(), Item.name.asc())
    )
    if branch_id is not None:
        stmt = stmt.where(Item.branch_id == branch_id)
    return db.execute(stmt).all()


def get_recent_transactions(db: Session, limit: int = 20, branch_id: int | None = None):
    stmt = select(Transaction).order_by(desc(Transaction.created_at)).limit(limit)
    if branch_id is not None:
        stmt = stmt.where(Transaction.branch_id == branch_id)
    return db.scalars(stmt).all()


def dashboard_stats(db: Session, branch_id: int | None = None):
    items_stmt = select(func.count(Item.id))
    if branch_id is not None:
        items_stmt = items_stmt.where(Item.branch_id == branch_id)
    items_count = db.scalar(items_stmt) or 0
    low_stock_count = len(get_low_stock(db, branch_id=branch_id))
    recent = get_recent_transactions(db, limit=10, branch_id=branch_id)
    return {
        "items_count": items_count,
        "low_stock_count": low_stock_count,
        "recent_transactions": recent,
    }


def dashboard_kpis(db: Session, branch_id: int | None = None):
    sq = stock_subquery(branch_id)

    total_stock_stmt = select(func.coalesce(func.sum(sq.c.stock), 0))
    total_stock = db.scalar(total_stock_stmt) or 0

    value_stmt = (
        select(func.coalesce(func.sum((func.coalesce(sq.c.stock, 0) * Item.cost_price)), 0))
        .select_from(Item)
        .outerjoin(sq, sq.c.item_id == Item.id)
    )
    if branch_id is not None:
        value_stmt = value_stmt.where(Item.branch_id == branch_id)
    inventory_value = float(db.scalar(value_stmt) or 0)

    return int(total_stock), float(inventory_value)


def stock_by_category(db: Session, branch_id: int | None = None):
    sq = stock_subquery(branch_id)
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
    if branch_id is not None:
        stmt = stmt.where(Item.branch_id == branch_id)
    return db.execute(stmt).all()


def in_out_last_7_days(db: Session, branch_id: int | None = None):
    since = datetime.utcnow() - timedelta(days=7)

    in_sum = func.coalesce(func.sum(case((Transaction.type == "IN", Transaction.quantity), else_=0)), 0)
    out_sum = func.coalesce(func.sum(case((Transaction.type == "OUT", Transaction.quantity), else_=0)), 0)

    stmt = select(in_sum.label("in_qty"), out_sum.label("out_qty")).where(Transaction.created_at >= since)
    if branch_id is not None:
        stmt = stmt.where(Transaction.branch_id == branch_id)
    row = db.execute(stmt).first()
    in_qty = int(row.in_qty) if row else 0
    out_qty = int(row.out_qty) if row else 0
    return in_qty, out_qty


def top_items_by_stock(db: Session, limit: int = 5, branch_id: int | None = None):
    sq = stock_subquery(branch_id)
    stmt = (
        select(Item, func.coalesce(sq.c.stock, 0).label("stock"))
        .select_from(Item)
        .outerjoin(sq, sq.c.item_id == Item.id)
        .order_by(func.coalesce(sq.c.stock, 0).desc(), Item.name.asc())
        .limit(limit)
    )
    if branch_id is not None:
        stmt = stmt.where(Item.branch_id == branch_id)
    return db.execute(stmt).all()


def create_out_transactions_for_delivery_if_needed(db: Session, delivery_id: int, performed_by: str):
    # Lock the delivery row first so two users cannot process the same delivery at once
    delivery = db.execute(
        select(Delivery)
        .where(Delivery.id == delivery_id)
        .with_for_update()
    ).scalar_one_or_none()

    if not delivery:
        raise ValueError("Delivery not found")

    existing_out = db.scalar(
        select(func.count(Transaction.id))
        .where(Transaction.delivery_id == delivery_id)
        .where(Transaction.type == "OUT")
    ) or 0

    if int(existing_out) > 0:
        return

    lines = db.execute(
        select(DeliveryItem)
        .where(DeliveryItem.delivery_id == delivery_id)
        .order_by(DeliveryItem.item_id.asc())
    ).scalars().all()

    if not lines:
        raise ValueError("Order has no items")

    # Lock all item rows involved in this delivery
    item_ids = sorted({int(li.item_id) for li in lines})
    locked_items = db.execute(
        select(Item)
        .where(Item.id.in_(item_ids))
        .order_by(Item.id.asc())
        .with_for_update()
    ).scalars().all()

    if len(locked_items) != len(item_ids):
        raise ValueError("One or more items are missing")

    # Re-check stock AFTER locking — compute directly in the same session
    # to avoid stale reads from a separate subquery
    for li in lines:
        signed_qty = case(
            (Transaction.type == "IN", Transaction.quantity),
            (Transaction.type == "OUT", -Transaction.quantity),
            else_=0,
        )
        stock = db.scalar(
            select(func.coalesce(func.sum(signed_qty), 0))
            .where(Transaction.item_id == li.item_id)
            .where(Transaction.branch_id == delivery.branch_id)
        ) or 0

        if int(stock) < int(li.quantity):
            raise ValueError("Insufficient stock for one or more items")

    # Create OUT transactions only after the lock + re-check.
    # branch_id is inherited from the delivery itself.
    for li in lines:
        db.add(
            Transaction(
                branch_id=delivery.branch_id,  # FIX: was missing, caused NOT NULL violation
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
    now = datetime.utcnow()
    today = now.date()

    if preset == "today":
        start = datetime.combine(today, datetime.min.time())
        end = start + timedelta(days=1)
        return start, end

    if preset == "yesterday":
        start = datetime.combine(today - timedelta(days=1), datetime.min.time())
        end = start + timedelta(days=1)
        return start, end

    if preset == "7d":
        end = now
        start = now - timedelta(days=7)
        return start, end

    if preset == "30d":
        end = now
        start = now - timedelta(days=30)
        return start, end

    return None, None


def get_cash_summary(db: Session, agent_id: int | None, start: datetime | None, end: datetime | None):
    """
    DAILY SUMMARY

    Collections:
      - DeliveryItem.line_amount summed per day (deliveries)
      - + CashEntry.kind == COLLECTION (extra)

    Operating cash:
      - CashEntry.kind == OPERATING_CASH

    Agent expenses:
      - CashEntry.kind == EXPENSE  (subtract from operating cash only)

    Office expenses (GLOBAL):
      - CashEntry.kind == OFFICE_EXPENSE (subtract from remittance only)
      - Agent filter does NOT apply to office expenses.
    """

    # --- Delivery collections by day (optionally filtered by agent) ---
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

    # --- Cash entries by day (filtered by agent where appropriate) ---
    c_day = func.date(CashEntry.created_at).label("day")

    extra_collections_sum = func.coalesce(
        func.sum(case((CashEntry.kind == "COLLECTION", CashEntry.amount), else_=0)),
        0,
    ).label("extra_collections")

    operating_sum = func.coalesce(
        func.sum(case((CashEntry.kind == "OPERATING_CASH", CashEntry.amount), else_=0)),
        0,
    ).label("operating_cash")

    agent_expenses_sum = func.coalesce(
        func.sum(case((CashEntry.kind == "EXPENSE", CashEntry.amount), else_=0)),
        0,
    ).label("expenses")

    # office expenses are global; agent filter must NOT apply
    office_expenses_sum = func.coalesce(
        func.sum(case((CashEntry.kind == "OFFICE_EXPENSE", CashEntry.amount), else_=0)),
        0,
    ).label("office_expenses")

    cash_stmt = (
        select(
            c_day,
            extra_collections_sum,
            operating_sum,
            agent_expenses_sum,
            office_expenses_sum,
        )
        .select_from(CashEntry)
        .group_by(c_day)
        .order_by(c_day.asc())
    )

    if start:
        cash_stmt = cash_stmt.where(CashEntry.created_at >= start)
    if end:
        cash_stmt = cash_stmt.where(CashEntry.created_at < end)

    # Filter agent-linked kinds only
    if agent_id:
        cash_stmt = cash_stmt.where(
            (CashEntry.kind == "OFFICE_EXPENSE") | (CashEntry.agent_id == agent_id)
        )

    cash_rows = db.execute(cash_stmt).all()

    by_day: dict[str, dict] = {}

    def ensure(day_key: str):
        by_day.setdefault(
            day_key,
            {
                "day": day_key,
                "collections": 0.0,
                "operating_cash": 0.0,
                "expenses": 0.0,
                "office_expenses": 0.0,
            },
        )

    for r in delivery_rows:
        key = str(r.day)
        ensure(key)
        by_day[key]["collections"] += float(r.delivery_collections or 0)

    for r in cash_rows:
        key = str(r.day)
        ensure(key)
        by_day[key]["collections"] += float(r.extra_collections or 0)
        by_day[key]["operating_cash"] += float(r.operating_cash or 0)
        by_day[key]["expenses"] += float(r.expenses or 0)
        by_day[key]["office_expenses"] += float(r.office_expenses or 0)

    merged = list(by_day.values())
    merged.sort(key=lambda x: x["day"])

    total_collections = sum(x["collections"] for x in merged)
    total_operating = sum(x["operating_cash"] for x in merged)
    total_expenses = sum(x["expenses"] for x in merged)
    total_office_expenses = sum(x["office_expenses"] for x in merged)

    return (
        merged,
        float(total_collections),
        float(total_expenses),
        float(total_operating),
        float(total_office_expenses),
    )


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Supervisor analytics helpers
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from .models import Branch, User  # noqa: E402  (already imported via models above)
from sqlalchemy import case as sa_case


def supervisor_date_range(preset: str | None, start_str: str | None, end_str: str | None):
    """Return (start_dt, end_dt) datetimes or (None, None) for all-time."""
    from datetime import date as _date
    today = datetime.utcnow().date()

    if preset == "today":
        s = datetime.combine(today, datetime.min.time())
        return s, s + timedelta(days=1)
    if preset == "yesterday":
        s = datetime.combine(today - timedelta(days=1), datetime.min.time())
        return s, s + timedelta(days=1)
    if preset == "7d":
        return datetime.combine(today - timedelta(days=6), datetime.min.time()), datetime.combine(today + timedelta(days=1), datetime.min.time())
    if preset == "30d":
        return datetime.combine(today - timedelta(days=29), datetime.min.time()), datetime.combine(today + timedelta(days=1), datetime.min.time())
    if preset == "this_month":
        s = datetime.combine(today.replace(day=1), datetime.min.time())
        return s, datetime.combine(today + timedelta(days=1), datetime.min.time())

    # custom range
    try:
        s = datetime.combine(_date.fromisoformat(start_str), datetime.min.time()) if start_str else None
        e = datetime.combine(_date.fromisoformat(end_str) + timedelta(days=1), datetime.min.time()) if end_str else None
        return s, e
    except Exception:
        return None, None


def supervisor_branch_stats(db: Session, start: datetime | None, end: datetime | None):
    """Per-branch delivery & cash summary â€” rewritten to use 3 queries total (was 12Ã— branches)."""
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()
    branch_ids = [b.id for b in branches]
    if not branch_ids:
        return branches, []

    # â”€â”€ Query 1: delivery counts by branch and status in one shot â”€â”€
    from sqlalchemy import case as sa_case
    del_q = (
        select(
            Delivery.branch_id,
            func.count(Delivery.id).label("total"),
            func.sum(sa_case((Delivery.status == "DELIVERED",        1), else_=0)).label("delivered"),
            func.sum(sa_case((Delivery.status == "PENDING",          1), else_=0)).label("pending"),
            func.sum(sa_case((Delivery.status == "OUT_FOR_DELIVERY", 1), else_=0)).label("out"),
            func.sum(sa_case((Delivery.status == "FAILED",           1), else_=0)).label("failed"),
        )
        .where(Delivery.branch_id.in_(branch_ids))
        .group_by(Delivery.branch_id)
    )
    if start: del_q = del_q.where(Delivery.created_at >= start)
    if end:   del_q = del_q.where(Delivery.created_at < end)
    del_map: dict[int, dict] = {}
    for row in db.execute(del_q).all():
        del_map[row.branch_id] = {
            "total": int(row.total or 0), "delivered": int(row.delivered or 0),
            "pending": int(row.pending or 0), "out": int(row.out or 0),
            "failed": int(row.failed or 0),
        }

    # â”€â”€ Query 2: delivery collections (line_amount sum) by branch â”€â”€
    col_q = (
        select(Delivery.branch_id, func.coalesce(func.sum(DeliveryItem.line_amount), 0).label("total"))
        .select_from(Delivery)
        .join(DeliveryItem, DeliveryItem.delivery_id == Delivery.id)
        .where(Delivery.branch_id.in_(branch_ids))
        .where(Delivery.status == "DELIVERED")
        .group_by(Delivery.branch_id)
    )
    if start: col_q = col_q.where(Delivery.created_at >= start)
    if end:   col_q = col_q.where(Delivery.created_at < end)
    col_map: dict[int, float] = {row.branch_id: float(row.total) for row in db.execute(col_q).all()}

    # â”€â”€ Query 3: all cash kinds by branch in one shot â”€â”€
    cash_q = (
        select(
            CashEntry.branch_id,
            CashEntry.kind,
            func.coalesce(func.sum(CashEntry.amount), 0).label("total"),
        )
        .where(CashEntry.branch_id.in_(branch_ids))
        .where(CashEntry.kind.in_(["COLLECTION","EXPENSE","OFFICE_EXPENSE","OPERATING_CASH","RETURN_OPERATING_CASH","COLLECTION_EXPENSE","CASH_PAYMENT","TRANSFER_PAYMENT"]))
        .group_by(CashEntry.branch_id, CashEntry.kind)
    )
    if start: cash_q = cash_q.where(CashEntry.created_at >= start)
    if end:   cash_q = cash_q.where(CashEntry.created_at < end)
    cash_map: dict[int, dict[str, float]] = {}
    for row in db.execute(cash_q).all():
        cash_map.setdefault(row.branch_id, {})[row.kind] = float(row.total)

    # â”€â”€ Assemble rows â”€â”€
    rows = []
    for branch in branches:
        d = del_map.get(branch.id, {})
        c = cash_map.get(branch.id, {})
        delivery_collections = 0.0  # disabled: CashEntry COLLECTION already captures this
        extra_col       = c.get("COLLECTION", 0.0) + c.get("CASH_PAYMENT", 0.0) + c.get("TRANSFER_PAYMENT", 0.0)
        agent_expenses  = c.get("EXPENSE", 0.0) + c.get("COLLECTION_EXPENSE", 0.0)
        office_expenses = c.get("OFFICE_EXPENSE",        0.0)
        operating_cash  = c.get("OPERATING_CASH",        0.0)
        returned_op     = c.get("RETURN_OPERATING_CASH", 0.0)
        total_collections = delivery_collections + extra_col
        operating_balance = operating_cash - agent_expenses - returned_op
        remittance        = total_collections - agent_expenses - office_expenses
        rows.append({
            "branch":                  branch,
            "total_deliveries":        d.get("total",     0),
            "delivered_count":         d.get("delivered", 0),
            "pending_count":           d.get("pending",   0),
            "out_for_delivery_count":  d.get("out",       0),
            "failed_count":            d.get("failed",    0),
            "collections":             total_collections,
            "agent_expenses":          agent_expenses,
            "office_expenses":         office_expenses,
            "operating_cash":          operating_cash,
            "returned_operating_cash": returned_op,
            "operating_balance":       operating_balance,
            "remittance":              remittance,
        })

    return branches, rows


def supervisor_top_items(db: Session, start: datetime | None, end: datetime | None, limit: int = 8):
    """Top items by OUT quantity across all branches in the date range."""
    q = (
        select(
            Item.name.label("name"),
            func.coalesce(Item.category, "Uncategorised").label("category"),
            func.sum(Transaction.quantity).label("qty"),
        )
        .select_from(Transaction)
        .join(Item, Item.id == Transaction.item_id)
        .where(Transaction.type == "OUT")
        .group_by(Item.id, Item.name, Item.category)
        .order_by(func.sum(Transaction.quantity).desc())
        .limit(limit)
    )
    if start:
        q = q.where(Transaction.created_at >= start)
    if end:
        q = q.where(Transaction.created_at < end)
    return db.execute(q).all()


def supervisor_best_agents(db: Session, start: datetime | None, end: datetime | None, limit: int = 8):
    """Top agents by number of DELIVERED deliveries."""
    q = (
        select(
            User.username.label("username"),
            func.coalesce(User.full_name, User.username).label("full_name"),
            Branch.name.label("branch_name"),
            func.count(func.distinct(Delivery.id)).label("delivered"),
            func.coalesce(
                func.sum(DeliveryItem.line_amount), 0
            ).label("collections"),
        )
        .select_from(Delivery)
        .join(User, User.id == Delivery.agent_id)
        .join(Branch, Branch.id == Delivery.branch_id)
        .join(DeliveryItem, DeliveryItem.delivery_id == Delivery.id)
        .where(Delivery.status == "DELIVERED")
        .group_by(User.id, User.username, User.full_name, Branch.name)
        .order_by(func.count(func.distinct(Delivery.id)).desc())
        .limit(limit)
    )
    if start:
        q = q.where(Delivery.created_at >= start)
    if end:
        q = q.where(Delivery.created_at < end)
    return db.execute(q).all()


def supervisor_daily_deliveries(db: Session, start: datetime | None, end: datetime | None):
    """Daily delivered count across all branches â€” for the chart."""
    day_col = func.date(Delivery.created_at).label("day")
    q = (
        select(day_col, func.count(Delivery.id).label("cnt"))
        .where(Delivery.status == "DELIVERED")
        .group_by(day_col)
        .order_by(day_col.asc())
    )
    if start:
        q = q.where(Delivery.created_at >= start)
    if end:
        q = q.where(Delivery.created_at < end)
    return db.execute(q).all()