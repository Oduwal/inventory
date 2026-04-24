from fastapi import APIRouter, Request, Depends, Form, HTTPException, BackgroundTasks, Response, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import text, func
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
import json, csv, io, os, logging
from app.core import *
from app.models import *
from app.security import *
from app.feature_toggles import get_all_toggles, get_all_toggles_raw, set_feature

router = APIRouter()

#  DASHBOARD
# ────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    branch_id = get_selected_branch_id(request, user)

    if is_supervisor(user) and not branch_id:
        # Supervisor with no branch selected: redirect to supervisor overview
        return redirect("/supervisor")

    if not is_admin(user) and not is_supervisor(user):
        return redirect("/my-deliveries")

    items_count = db.scalar(select(func.count(Item.id)).where(Item.branch_id == branch_id)) or 0

    low_rows_all = get_low_stock(db)
    low_rows = [(item, stock) for (item, stock) in low_rows_all if item.branch_id == branch_id][:5]
    low_stock_count = len([(item, stock) for (item, stock) in low_rows_all if item.branch_id == branch_id])

    stale_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    # Single query: items with positive stock whose last transaction is older than cutoff
    _signed = case((Transaction.type == "IN", Transaction.quantity), else_=-Transaction.quantity)
    _stale_q = (
        select(func.count())
        .select_from(
            select(
                Item.id,
                func.coalesce(func.sum(_signed), 0).label("stock"),
                func.max(Transaction.created_at).label("last_tx"),
            )
            .select_from(Item)
            .join(Transaction, and_(Transaction.item_id == Item.id, Transaction.branch_id == branch_id), isouter=True)
            .where(Item.branch_id == branch_id)
            .group_by(Item.id)
            .having(func.coalesce(func.sum(_signed), 0) > 0)
            .having(
                (func.max(Transaction.created_at) == None) |
                (func.max(Transaction.created_at) < stale_cutoff)
            )
            .subquery()
        )
    )
    stale_count = db.scalar(_stale_q) or 0

    recent_transactions = db.scalars(
        select(Transaction).where(Transaction.branch_id == branch_id)
        .order_by(desc(Transaction.created_at)).limit(10)
    ).all()

    top_rows_all = top_items_by_stock(db, limit=200)
    top_rows = [(item, stock) for (item, stock) in top_rows_all if item.branch_id == branch_id][:5]

    all_items_with_stock = get_items_with_stock(db)
    cat_map: dict[str, float] = {}
    cat_items: dict[str, list] = {}
    total_stock = 0
    inventory_value = 0.0
    for item, stock in all_items_with_stock:
        if item.branch_id == branch_id:
            s = stock or 0
            total_stock += int(s)
            inventory_value += s * (item.cost_price or 0)
            cat = item.category or "Uncategorized"
            cat_map[cat] = cat_map.get(cat, 0) + s
            cat_items.setdefault(cat, []).append({"name": item.name, "stock": int(s), "unit": item.unit or "pcs", "reorder_level": int(item.reorder_level or 0)})
    cat_rows = sorted(cat_map.items(), key=lambda x: x[1], reverse=True)
    # Sort items within each category by stock desc
    cat_items_json = {cat: sorted(items, key=lambda x: x["stock"], reverse=True) for cat, items in cat_items.items()}

    in7 = int(db.scalar(
        select(func.coalesce(func.sum(Transaction.quantity), 0))
        .where(Transaction.branch_id == branch_id).where(Transaction.type == "IN")
        .where(Transaction.created_at >= datetime.now(timezone.utc) - timedelta(days=7))
    ) or 0)
    out7 = int(db.scalar(
        select(func.coalesce(func.sum(Transaction.quantity), 0))
        .where(Transaction.branch_id == branch_id).where(Transaction.type == "OUT")
        .where(Transaction.created_at >= datetime.now(timezone.utc) - timedelta(days=7))
    ) or 0)

    branches = []
    if is_supervisor(user):
        branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()

    # Chart data — last 14 days deliveries + expenses for branch
    today_d = date.today()
    chart_days = [(today_d - timedelta(days=i)) for i in range(13, -1, -1)]
    del_by_day: dict = {}
    for d in db.execute(
        select(Delivery).where(Delivery.branch_id == branch_id)
        .where(Delivery.status == "DELIVERED")
        .where(Delivery.delivered_at >= datetime.now(timezone.utc) - timedelta(days=14))
    ).scalars().all():
        k = d.delivered_at.date().isoformat() if d.delivered_at else None
        if k: del_by_day[k] = del_by_day.get(k, 0) + 1
    exp_by_day: dict = {}
    for e in db.execute(
        select(CashEntry).where(CashEntry.branch_id == branch_id)
        .where(CashEntry.kind.in_(["EXPENSE", "OFFICE_EXPENSE", "COLLECTION_EXPENSE"]))
        .where(CashEntry.created_at >= datetime.now(timezone.utc) - timedelta(days=14))
    ).scalars().all():
        k = e.created_at.date().isoformat() if e.created_at else None
        if k: exp_by_day[k] = exp_by_day.get(k, 0) + (e.amount or 0)

    # Agent collections for today — for admin cash confirmation panel
    today_start = datetime.combine(date.today(), datetime.min.time())
    today_end   = today_start + timedelta(days=1)
    agent_collections = []
    if is_admin(user):
        try:
            branch_agents = db.execute(
                select(User).where(User.role == "AGENT").where(User.branch_id == branch_id)
                .where(User.is_active == True).order_by(User.username.asc())
            ).scalars().all()
            for agent in branch_agents:
                rows = db.execute(
                    select(CashEntry).where(CashEntry.agent_id == agent.id)
                    .where(CashEntry.branch_id == branch_id)
                    .where(CashEntry.kind.in_(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"]))
                    .where(CashEntry.created_at >= today_start)
                    .where(CashEntry.created_at < today_end)
                    .order_by(CashEntry.created_at.desc())
                ).scalars().all()
                if not rows:
                    continue
                total     = sum(r.amount for r in rows)
                confirmed = all(getattr(r, "confirmed_by_admin", False) for r in rows)
                cash_sum  = sum(r.amount for r in rows if r.kind in ("COLLECTION","CASH_PAYMENT"))
                trans_sum = sum(r.amount for r in rows if r.kind == "TRANSFER_PAYMENT")
                agent_collections.append({
                    "agent_id":   agent.id,
                    "agent_name": agent.full_name or agent.username,
                    "total":      total,
                    "cash":       cash_sum,
                    "transfer":   trans_sum,
                    "confirmed":  confirmed,
                    "entries":    len(rows),
                    "date":       date.today().isoformat(),
                })
        except Exception:
            agent_collections = []  # fallback — column may not exist yet

    return tpl(request, "dashboard.html", {
        "request": request, "user": user, "active": "dashboard",
        "branches": branches, "selected_branch_id": branch_id,
        "items_count": items_count, "low_stock_count": low_stock_count,
        "stale_count": stale_count, "recent_transactions": recent_transactions,
        "total_stock": total_stock, "inventory_value": inventory_value,
        "in7": in7, "out7": out7, "top_rows": top_rows, "low_rows": low_rows, "cat_rows": cat_rows, "cat_items_json": cat_items_json,
        "chart_labels": [str(d) for d in chart_days],
        "chart_deliveries": [del_by_day.get(d.isoformat(), 0) for d in chart_days],
        "chart_expenses": [round(exp_by_day.get(d.isoformat(), 0), 2) for d in chart_days],
        "agent_collections": agent_collections,
    })




@router.get("/admin/backfill-collections", response_class=HTMLResponse)
def backfill_collections(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    """One-time: create COLLECTION entries for DELIVERED orders that have none."""

    delivered = db.execute(
        select(Delivery).where(Delivery.status == "DELIVERED")
    ).scalars().all()

    created, skipped = 0, 0
    for d in delivered:
        existing = db.scalar(
            select(func.count(CashEntry.id)).where(
                CashEntry.delivery_id == d.id,
                CashEntry.kind.in_(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"])
            )
        ) or 0
        if existing > 0:
            skipped += 1
            continue
        total = db.scalar(
            select(func.coalesce(func.sum(DeliveryItem.line_amount), 0))
            .where(DeliveryItem.delivery_id == d.id)
        ) or 0
        if total > 0:
            db.add(CashEntry(
                branch_id=d.branch_id, agent_id=d.agent_id,
                delivery_id=d.id, kind="COLLECTION", amount=total,
                note=f"Auto-recorded: delivery #{d.id} to {d.customer_name}",
            ))
            created += 1
        else:
            skipped += 1
    db.commit()
    return HTMLResponse(f"<pre>Done. Created: {created} collection entries. Skipped: {skipped} (already had entries or zero value).</pre>")


@router.post("/admin/confirm-cash", response_class=JSONResponse)
async def confirm_cash(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """Admin confirms that an agent has physically handed over their cash."""
    body = await request.json()
    agent_id = body.get("agent_id")
    date_str = body.get("date")  # YYYY-MM-DD
    if not agent_id or not date_str:
        return JSONResponse({"error": "missing agent_id or date"}, status_code=400)
    try:
        day_start = datetime.strptime(date_str, "%Y-%m-%d")
        day_end   = day_start + timedelta(days=1)
    except ValueError:
        return JSONResponse({"error": "invalid date"}, status_code=400)
    db.execute(text(
        "UPDATE cash_entries SET confirmed_by_admin=TRUE, confirmed_at=:_now "
        "WHERE agent_id=:aid AND branch_id=:bid "
        "AND kind IN ('COLLECTION','CASH_PAYMENT','TRANSFER_PAYMENT') "
        "AND created_at >= :start AND created_at < :end "
        "AND confirmed_by_admin=FALSE"
    ), {"aid": agent_id, "bid": user.branch_id, "start": day_start, "end": day_end, "_now": _now()})
    db.commit()
    audit_log(db, user.id, "CASH_CONFIRMED", f"agent_id={agent_id} date={date_str}",
              ip=request.client.host if request.client else "")
    return JSONResponse({"status": "ok"})


@router.post("/admin/confirm-cash-entry", response_class=JSONResponse)
async def confirm_cash_entry(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """Confirm a single cash entry by ID (used for RETURN_OPERATING_CASH vetting)."""
    body     = await request.json()
    entry_id = body.get("entry_id")
    if not entry_id:
        return JSONResponse({"error": "missing entry_id"}, status_code=400)
    row = db.execute(text(
        "UPDATE cash_entries SET confirmed_by_admin=TRUE, confirmed_at=:_now "
        "WHERE id=:eid AND branch_id=:bid AND confirmed_by_admin=FALSE RETURNING id"
    ), {"eid": entry_id, "bid": user.branch_id, "_now": _now()}).fetchone()
    if not row:
        # Try without branch filter (already confirmed or different branch)
        db.execute(text(
            "UPDATE cash_entries SET confirmed_by_admin=TRUE, confirmed_at=:_now WHERE id=:eid"
        ), {"eid": entry_id, "_now": _now()})
    db.commit()
    return JSONResponse({"ok": True})


@router.get("/call-logs", response_class=HTMLResponse)
def call_logs_page(request: Request, db: Session = Depends(get_db), page: int = 1, delivery_id: int | None = None, user: User = Depends(RequireRole("ADMIN"))):
    per_page = 50
    offset = (page - 1) * per_page
    branch_id = get_selected_branch_id(request, user)

    if delivery_id:
        # Filter by specific delivery
        rows = db.execute(text("""
            SELECT cl.id, cl.delivery_id, cl.call_id, cl.phone, cl.trigger_status,
                   cl.call_status, cl.error_msg, cl.summary, cl.duration, cl.created_at,
                   d.customer_name, d.branch_id
            FROM call_logs cl
            JOIN deliveries d ON d.id = cl.delivery_id
            WHERE cl.delivery_id = :did AND d.branch_id = :bid
            ORDER BY cl.created_at DESC
            LIMIT :lim OFFSET :off
        """), {"did": delivery_id, "bid": branch_id, "lim": per_page, "off": offset}).fetchall()
        total = db.scalar(text(
            "SELECT COUNT(*) FROM call_logs cl JOIN deliveries d ON d.id=cl.delivery_id WHERE cl.delivery_id=:did AND d.branch_id=:bid"
        ), {"did": delivery_id, "bid": branch_id}) or 0
    else:
        rows = db.execute(text("""
            SELECT cl.id, cl.delivery_id, cl.call_id, cl.phone, cl.trigger_status,
                   cl.call_status, cl.error_msg, cl.summary, cl.duration, cl.created_at,
                   d.customer_name, d.branch_id
            FROM call_logs cl
            JOIN deliveries d ON d.id = cl.delivery_id
            WHERE d.branch_id = :bid
            ORDER BY cl.created_at DESC
            LIMIT :lim OFFSET :off
        """), {"bid": branch_id, "lim": per_page, "off": offset}).fetchall()
        total = db.scalar(text(
            "SELECT COUNT(*) FROM call_logs cl JOIN deliveries d ON d.id=cl.delivery_id WHERE d.branch_id=:bid"
        ), {"bid": branch_id}) or 0

    pages = max(1, (total + per_page - 1) // per_page)
    return tpl(request, "call_logs.html", {
        "request": request, "user": user, "active": "call_logs",
        "rows": rows, "page": page, "pages": pages, "total": total,
        "delivery_id": delivery_id,
    })



# NOTE: /api/call-webhook handler is defined further below (near line ~5900)
# with full backup-call + WhatsApp fallback logic. Duplicate removed.


@router.get("/admin/audit-log", response_class=HTMLResponse)
def audit_log_viewer(request: Request, db: Session = Depends(get_db), page: int = 1, user: User = Depends(RequireRole("SUPERVISOR"))):
    per_page = 50
    offset = (page - 1) * per_page
    logs = db.execute(
        select(AuditLog).order_by(desc(AuditLog.created_at)).offset(offset).limit(per_page)
    ).scalars().all()
    total = db.scalar(select(func.count(AuditLog.id))) or 0
    referenced_ids = {lg.user_id for lg in logs if lg.user_id}
    user_map = {u.id: (u.full_name or u.username) for u in db.execute(select(User).where(User.id.in_(referenced_ids))).scalars().all()} if referenced_ids else {}
    return tpl(request, "audit_log.html", {
        "request": request, "user": user, "active": "audit",
        "logs": logs, "user_map": user_map,
        "page": page, "total": total, "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    })


@router.get("/admin/reset-data", response_class=HTMLResponse)
def reset_data_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("SUPERVISOR"))):
    csrf_token = get_csrf_token(request)
    return HTMLResponse(f"""
    <html><body style="background:#080f1e;color:#e7eefc;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
    <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:40px;max-width:480px;width:100%;text-align:center;">
      <div style="font-size:48px;margin-bottom:16px;">⚠️</div>
      <h2 style="color:#f87171;margin-bottom:8px;">Full System Reset</h2>
      <p style="color:#8a9bc4;font-size:14px;margin-bottom:24px;">
        This will permanently delete <strong style="color:#e7eefc;">ALL data</strong> including:<br>
        deliveries, stock, cash entries, transfers, items,<br>
        <strong style="color:#f87171;">all users (agents &amp; admins), and all branches</strong>.<br><br>
        Only your supervisor account will be kept.<br><br>
        <strong style="color:#f87171;">This cannot be undone.</strong>
      </p>
      <form method="post" action="/admin/reset-data">
        <input type="hidden" name="csrf_token" value="{csrf_token}" />
        <input type="text" name="confirm" placeholder='Type RESET to confirm'
               style="width:100%;padding:10px;border-radius:8px;border:1px solid rgba(239,68,68,.4);background:rgba(239,68,68,.08);color:#e7eefc;font-size:14px;margin-bottom:16px;box-sizing:border-box;" />
        <button type="submit"
                style="width:100%;padding:12px;background:linear-gradient(135deg,#ef4444,#dc2626);border:none;border-radius:10px;color:#fff;font-size:15px;font-weight:700;cursor:pointer;">
          🗑 Delete Everything &amp; Reset
        </button>
      </form>
      <a href="/supervisor" style="display:block;margin-top:16px;color:#8a9bc4;font-size:13px;text-decoration:none;">← Cancel</a>
    </div></body></html>
    """)


@router.post("/admin/test-stock-topup")
async def test_stock_topup(request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """TEMPORARY — sets every item to 100 units for testing. Remove when done."""
    verify_csrf_token(request, csrf_token)
    branch_id = get_selected_branch_id(request, user)
    # Add IN transactions of 100 for every item in this branch tagged as TEST-STOCK
    items = db.execute(select(Item).where(Item.branch_id == branch_id).limit(1000)).scalars().all()
    for item in items:
        db.add(Transaction(
            branch_id=branch_id,
            item_id=item.id,
            type="IN",
            quantity=100,
            reference="TEST-STOCK",
            note="Temporary test stock top-up",
        ))
    db.commit()
    return redirect("/items")


@router.post("/admin/test-stock-remove")
async def test_stock_remove(request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """TEMPORARY — removes all TEST-STOCK transactions."""
    verify_csrf_token(request, csrf_token)
    branch_id = get_selected_branch_id(request, user)
    db.execute(text("DELETE FROM transactions WHERE reference='TEST-STOCK' AND branch_id=:bid"), {"bid": branch_id})
    db.commit()
    return redirect("/items")


@router.post("/admin/reset-data", response_class=HTMLResponse)
async def reset_data_execute(
    request: Request,
    confirm: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("SUPERVISOR")),
):
    verify_csrf_token(request, csrf_token)
    if confirm.strip() != "RESET":
        return RedirectResponse("/supervisor?error=You+must+type+RESET+to+confirm.", status_code=303)

    from sqlalchemy import text as _text
    supervisor_id = user.id
    with db.bind.connect() as conn:
        # Delete in FK-safe order — child tables first
        conn.execute(_text("DELETE FROM stock_return_vettings"))
        conn.execute(_text("DELETE FROM adjustment_request_items"))
        conn.execute(_text("DELETE FROM adjustment_requests"))
        conn.execute(_text("UPDATE agent_stock_assignments SET transaction_out_id=NULL, transaction_in_id=NULL, delivery_id=NULL"))
        conn.execute(_text("DELETE FROM agent_stock_assignments"))
        conn.execute(_text("DELETE FROM faulty_stock"))
        conn.execute(_text("DELETE FROM notifications"))
        conn.execute(_text("DELETE FROM cash_entries"))
        conn.execute(_text("DELETE FROM delivery_items"))
        conn.execute(_text("DELETE FROM stock_transfer_items"))
        conn.execute(_text("UPDATE stock_transfers SET received_by_id=NULL, cancelled_by_id=NULL, delegated_agent_id=NULL, delegated_receiver_id=NULL"))
        conn.execute(_text("DELETE FROM stock_transfers"))
        conn.execute(_text("DELETE FROM deliveries"))
        conn.execute(_text("DELETE FROM transactions"))
        conn.execute(_text("DELETE FROM items"))
        conn.execute(_text("DELETE FROM audit_logs"))
        # Delete call_logs if table exists
        try:
            conn.execute(_text("DELETE FROM call_logs"))
        except Exception:
            pass
        # Delete all users except the current supervisor
        conn.execute(_text("DELETE FROM users WHERE id != :sid"), {"sid": supervisor_id})
        # Delete all branches
        conn.execute(_text("DELETE FROM branches"))
        # Clear supervisor's branch_id since branches are gone
        conn.execute(_text("UPDATE users SET branch_id = NULL WHERE id = :sid"), {"sid": supervisor_id})
        conn.commit()

    audit_log(db, user.id, "DATA_RESET", "Full system reset — all data, users, and branches deleted",
              ip=request.client.host if request.client else "")
    return HTMLResponse("""
    <html><body style="background:#080f1e;color:#e7eefc;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
    <div style="background:rgba(255,255,255,.04);border:1px solid rgba(34,197,94,.3);border-radius:16px;padding:40px;max-width:400px;text-align:center;">
      <div style="font-size:48px;margin-bottom:16px;">✅</div>
      <h2 style="color:#4ade80;margin-bottom:8px;">System Reset Complete</h2>
      <p style="color:#8a9bc4;font-size:14px;margin-bottom:24px;">All data, users, and branches have been deleted.<br>Only your supervisor account remains.<br><br>Start by creating a new branch.</p>
      <a href="/supervisor" style="display:inline-block;padding:12px 24px;background:linear-gradient(135deg,#4f7cff,#3b5bdb);border-radius:10px;color:#fff;text-decoration:none;font-weight:700;">Go to Dashboard</a>
    </div></body></html>
    """)



@router.get("/supervisor", response_class=HTMLResponse)
def supervisor_dashboard(request: Request, db: Session = Depends(get_db), preset: str = "", start_date: str = "", end_date: str = "", user: User = Depends(RequireRole("SUPERVISOR"))):
    preset = preset.strip() or None
    start_date = start_date.strip() or None
    end_date = end_date.strip() or None
    start_dt, end_dt = supervisor_date_range(preset, start_date, end_date)

    branches, rows = supervisor_branch_stats(db, start_dt, end_dt)
    # Enrich each row dict with branch_name from the branch object
    for r in rows:
        if isinstance(r, dict) and "branch" in r and not r.get("branch_name"):
            r["branch_name"] = r["branch"].name if r["branch"] else "—"
            r["branch_id"] = r["branch"].id if r["branch"] else None
    top_items   = supervisor_top_items(db, start_dt, end_dt)
    _raw_best_agents = list(supervisor_best_agents(db, start_dt, end_dt))
    best_agents = []
    for r in _raw_best_agents:
        cols = list(r)
        # Scan columns: find ints (delivery_count) and floats/numeric (collections)
        # string cols are name fields: username, full_name, branch_name
        str_cols, num_cols = [], []
        for c in cols:
            try:
                num_cols.append(float(c or 0))
            except (ValueError, TypeError):
                str_cols.append(str(c) if c is not None else "—")
        agent_name = str_cols[1] if len(str_cols) > 1 and str_cols[1] != "—" else (str_cols[0] if str_cols else "—")
        delivery_count = int(num_cols[0]) if len(num_cols) > 0 else 0
        total_collections = num_cols[1] if len(num_cols) > 1 else 0.0
        best_agents.append({
            "agent_name": agent_name,
            "delivery_count": delivery_count,
            "total_collections": total_collections,
        })
    daily_chart = supervisor_daily_deliveries(db, start_dt, end_dt)

    # Daily expenses across all branches for the chart
    # Exclude "waybill - from ..." entries (receiver side) to avoid double-counting transfer expenses
    _range_start = start_dt or datetime.now(timezone.utc) - timedelta(days=30)
    _range_end   = end_dt   or datetime.now(timezone.utc)
    exp_by_day: dict = {}
    for e in db.execute(
        select(CashEntry).where(CashEntry.kind.in_(["EXPENSE", "OFFICE_EXPENSE", "COLLECTION_EXPENSE"]))
        .where(CashEntry.created_at >= _range_start)
        .where(CashEntry.created_at <= _range_end)
    ).scalars().all():
        k = e.created_at.date().isoformat() if e.created_at else None
        if k:
            exp_by_day[k] = exp_by_day.get(k, 0) + (e.amount or 0)
    # Build chart days — use isoformat keys throughout for consistency
    delivery_days = {r.day.isoformat() if hasattr(r.day, 'isoformat') else str(r.day)[:10] for r in daily_chart}
    expense_days  = set(exp_by_day.keys())
    all_chart_days = sorted(delivery_days | expense_days)
    delivery_cnt = {(r.day.isoformat() if hasattr(r.day, 'isoformat') else str(r.day)[:10]): int(r.cnt) for r in daily_chart}
    chart_days_set = all_chart_days

    # All-branch inventory & agent totals for the enhanced overview
    all_items_count = db.scalar(select(func.count(func.distinct(func.lower(Item.name))))) or 0
    _all_low_stock_cached = list(get_low_stock(db))
    all_low_items = _all_low_stock_cached
    all_low_stock_count = len(all_low_items)
    all_agents_count = db.scalar(select(func.count(User.id)).where(User.role == "AGENT")) or 0
    all_admins_count = db.scalar(select(func.count(User.id)).where(User.role == "ADMIN")) or 0
    all_inventory_value = 0.0
    all_total_stock = 0
    all_cat_map: dict = {}
    all_cat_items_map: dict = {}  # cat -> {name_lower -> {name, stock, unit, reorder_level}}
    all_top_rows_raw = []
    for item, stock in get_items_with_stock(db):
        s = int(stock or 0)
        all_inventory_value += s * (item.cost_price or 0)
        all_total_stock += s
        cat = item.category or "Uncategorized"
        all_cat_map[cat] = all_cat_map.get(cat, 0) + s
        # Merge same-named items across branches
        key = (item.name or "").strip().lower()
        if cat not in all_cat_items_map:
            all_cat_items_map[cat] = {}
        if key in all_cat_items_map[cat]:
            all_cat_items_map[cat][key]["stock"] += s
        else:
            all_cat_items_map[cat][key] = {"name": item.name, "stock": s, "unit": item.unit or "pcs", "reorder_level": int(item.reorder_level or 0)}
        all_top_rows_raw.append((item, s))
    all_cat_rows = sorted(all_cat_map.items(), key=lambda x: x[1], reverse=True)
    all_cat_items_json = {cat: sorted(items.values(), key=lambda x: x["stock"], reverse=True)
                          for cat, items in all_cat_items_map.items()}
    all_top_rows = sorted(all_top_rows_raw, key=lambda x: x[1], reverse=True)[:5]
    all_low_rows = _all_low_stock_cached
    all_in7 = int(db.scalar(
        select(func.coalesce(func.sum(Transaction.quantity), 0))
        .where(Transaction.type == "IN")
        .where(Transaction.created_at >= datetime.now(timezone.utc) - timedelta(days=7))
    ) or 0)
    all_out7 = int(db.scalar(
        select(func.coalesce(func.sum(Transaction.quantity), 0))
        .where(Transaction.type == "OUT")
        .where(Transaction.created_at >= datetime.now(timezone.utc) - timedelta(days=7))
    ) or 0)

    return tpl(request, "supervisor_dashboard.html", {
        "request": request, "user": user, "rows": rows,
        "top_items": top_items, "best_agents": best_agents,
        "chart_labels": chart_days_set,
        "chart_data": [delivery_cnt.get(d, 0) for d in chart_days_set],
        "chart_expenses": [round(exp_by_day.get(d, 0), 2) for d in chart_days_set],
        "grand_total_deliveries": sum(r["total_deliveries"] for r in rows),
        "grand_delivered": sum(r["delivered_count"] for r in rows),
        "grand_pending": sum(r["pending_count"] for r in rows),
        "grand_out_for_delivery": sum(r["out_for_delivery_count"] for r in rows),
        "grand_failed": sum(r["failed_count"] for r in rows),
        "grand_collections": sum(r["collections"] for r in rows),
        "grand_agent_expenses": sum(r["agent_expenses"] for r in rows),
        "grand_office_expenses": sum(r["office_expenses"] for r in rows),
        "grand_operating_cash": sum(r["operating_cash"] for r in rows),
        "grand_returned_operating_cash": sum(r["returned_operating_cash"] for r in rows),
        "grand_operating_balance": sum(r["operating_balance"] for r in rows),
        "grand_remittance": sum(r["remittance"] for r in rows),
        "all_items_count": all_items_count,
        "all_low_stock_count": all_low_stock_count,
        "all_low_items": all_low_items,
        "all_low_rows": all_low_rows,
        "all_agents_count": all_agents_count,
        "all_admins_count": all_admins_count,
        "all_inventory_value": all_inventory_value,
        "all_total_stock": all_total_stock,
        "all_cat_rows": all_cat_rows, "all_cat_items_json": all_cat_items_json,
        "all_top_rows": all_top_rows,
        "all_in7": all_in7, "all_out7": all_out7,
        "branches": branches, "selected_branch_id": None, "active": "supervisor",
        "preset": preset or "", "start_date": start_date or "", "end_date": end_date or "",
        "toggles": get_all_toggles(db),
        "toggles_raw": get_all_toggles_raw(db),
    })


# ────────────────────────────────────────────────
#  FEATURE TOGGLE API  (supervisor only)
# ────────────────────────────────────────────────

_ALLOWED_TOGGLES = {
    "call_enabled", "call_status_PENDING", "call_status_OUT_FOR_DELIVERY",
    "call_status_FAILED", "call_status_RETURNED",
    "whatsapp_customer_enabled", "whatsapp_seller_enabled",
    "contact_start_hour", "contact_end_hour",
}

@router.get("/api/feature-toggles")
async def get_feature_toggles(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("SUPERVISOR"))):
    return JSONResponse(get_all_toggles(db))


@router.post("/api/feature-toggles")
async def update_feature_toggle(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("SUPERVISOR"))):
    body = await request.json()
    key = str(body.get("key", ""))
    if key not in _ALLOWED_TOGGLES:
        return JSONResponse({"error": "Unknown toggle key"}, status_code=400)
    # Hour-based toggles store a numeric string, not on/off
    if key in ("contact_start_hour", "contact_end_hour"):
        hour_val = int(body.get("value", 8))
        if hour_val < 0 or hour_val > 23:
            return JSONResponse({"error": "Hour must be 0-23"}, status_code=400)
        value = str(hour_val)
    else:
        value = "on" if body.get("value") else "off"
    set_feature(db, key, value)
    return JSONResponse({"ok": True, "key": key, "value": value})


# ────────────────────────────────────────────────
#  STOCK ALERTS
# ────────────────────────────────────────────────

@router.get("/stale-stock", response_class=HTMLResponse)
def stale_stock(request: Request, days: int = 7, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    branch_id = get_selected_branch_id(request, user)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    # Supervisor sees all branches; admin sees their own branch only
    items_stmt = select(Item).order_by(Item.name)
    if not is_supervisor(user):
        items_stmt = items_stmt.where(Item.branch_id == branch_id)
    all_items = db.execute(items_stmt).scalars().all()
    stale_rows = []
    for item in all_items:
        item_branch_id = item.branch_id
        stock = db.scalar(
            select(func.coalesce(func.sum(case((Transaction.type == "IN", Transaction.quantity), else_=-Transaction.quantity)), 0))
            .where(Transaction.item_id == item.id).where(Transaction.branch_id == item_branch_id)
        ) or 0
        if stock <= 0:
            continue
        last_tx = db.scalar(select(func.max(Transaction.created_at)).where(Transaction.item_id == item.id).where(Transaction.branch_id == item_branch_id))
        if last_tx is not None and last_tx.tzinfo is None:
            last_tx = last_tx.replace(tzinfo=timezone.utc)
            
        if last_tx is None or last_tx < cutoff:
            stale_rows.append({"item": item, "stock": int(stock), "last_tx": last_tx,
                               "days_since": (datetime.now(timezone.utc) - last_tx).days if last_tx else 9999})
    stale_rows.sort(key=lambda r: r["days_since"], reverse=True)
    return tpl(request, "stale_stock.html", {
        "request": request, "user": user, "rows": stale_rows, "days": days, "active": "stale",
    })


@router.get("/low-stock", response_class=HTMLResponse)
def low_stock(request: Request, branch_filter: str = "", db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    branch_id = get_selected_branch_id(request, user)
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    filter_bid = int(branch_filter) if branch_filter and branch_filter.isdigit() else None
    if is_supervisor(user):
        all_rows = list(get_low_stock(db))
        rows = [(item, stock) for (item, stock) in all_rows if not filter_bid or item.branch_id == filter_bid]
    else:
        rows = [(item, stock) for (item, stock) in get_low_stock(db) if item.branch_id == branch_id]
    return tpl(request, "low_stock.html", {
        "request": request, "rows": rows, "user": user, "active": "low",
        "branches": branches, "branch_filter": branch_filter,
    })


# ────────────────────────────────────────────────
