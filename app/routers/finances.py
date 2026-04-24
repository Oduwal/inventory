from fastapi import APIRouter, Request, Depends, Form, HTTPException, BackgroundTasks, Response, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import text, func
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
import json, csv, io, os, logging
from urllib.parse import quote_plus
from app.core import *
from app.models import *
from app.security import *

router = APIRouter()

#  CASH
# ────────────────────────────────────────────────

@router.get("/cash", response_class=HTMLResponse)
def cash_dashboard(request: Request, preset: str = "", start_date: str = "", end_date: str = "", agent_id: str = "", db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    branch_id = get_selected_branch_id(request, user)
    sd, ed, preset_norm = _range_dates_from_inputs(preset, start_date, end_date)
    start_dt = None
    end_dt = None
    if preset_norm:
        start_dt, end_dt = cash_range_from_preset(preset_norm)
    else:
        if sd: start_dt = datetime.combine(sd, datetime.min.time())
        if ed: end_dt = datetime.combine(ed, datetime.min.time()) + timedelta(days=1)
    selected_agent_id = None
    if is_admin(user):
        if agent_id == "all":
            selected_agent_id = None  # show all agents
        elif (agent_id or "").isdigit():
            selected_agent_id = int(agent_id)
        else:
            selected_agent_id = user.id  # default: admin sees own entries
    else:
        selected_agent_id = user.id
    # Branch agent IDs — used to catch entries saved with NULL branch_id
    branch_agent_ids = [u.id for u in db.execute(
        select(User).where(User.branch_id == branch_id)
    ).scalars().all()]

    # Match entries that either have this branch_id OR have NULL branch_id but belong to a branch agent
    def _branch_filter():
        return (CashEntry.branch_id == branch_id) | (
            (CashEntry.branch_id == None) & (CashEntry.agent_id.in_(branch_agent_ids))
        )

    def _cash_sum(kind_list, agent_id=None):
        stmt = select(func.coalesce(func.sum(CashEntry.amount), 0)).where(
            CashEntry.kind.in_(kind_list)).where(_branch_filter())
        if start_dt: stmt = stmt.where(CashEntry.created_at >= start_dt)
        if end_dt:   stmt = stmt.where(CashEntry.created_at < end_dt)
        if agent_id: stmt = stmt.where(CashEntry.agent_id == agent_id)
        return db.scalar(stmt) or 0

    # Per-day breakdown — query each kind separately then merge by day
    def _day_kind_map(kind_list, agent_id=None):
        stmt = select(
            func.date(CashEntry.created_at).label("day"),
            func.coalesce(func.sum(CashEntry.amount), 0).label("total")
        ).where(CashEntry.kind.in_(kind_list)).where(_branch_filter())
        if start_dt: stmt = stmt.where(CashEntry.created_at >= start_dt)
        if end_dt:   stmt = stmt.where(CashEntry.created_at < end_dt)
        if agent_id: stmt = stmt.where(CashEntry.agent_id == agent_id)
        stmt = stmt.group_by(func.date(CashEntry.created_at))
        return {str(r.day): r.total for r in db.execute(stmt).all()}

    col_map  = _day_kind_map(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"], selected_agent_id)
    exp_map  = _day_kind_map(["EXPENSE"], selected_agent_id)
    op_map   = _day_kind_map(["OPERATING_CASH"], selected_agent_id)
    off_map  = _day_kind_map(["OFFICE_EXPENSE"], selected_agent_id)
    all_days = sorted(set(list(col_map) + list(exp_map) + list(op_map) + list(off_map)), reverse=True)
    rows = [{"day": d, "collections": col_map.get(d, 0), "expenses": exp_map.get(d, 0),
             "operating_cash": op_map.get(d, 0), "office_expenses": off_map.get(d, 0)}
            for d in all_days]

    total_collections     = _cash_sum(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"], selected_agent_id)
    total_expenses        = _cash_sum(["EXPENSE", "COLLECTION_EXPENSE"], selected_agent_id)
    total_operating       = _cash_sum(["OPERATING_CASH"], selected_agent_id)
    total_office_expenses = _cash_sum(["OFFICE_EXPENSE"], selected_agent_id)

    _ret_stmt = select(func.coalesce(func.sum(CashEntry.amount), 0)).where(
        CashEntry.kind == "RETURN_OPERATING_CASH").where(_branch_filter())
    if start_dt: _ret_stmt = _ret_stmt.where(CashEntry.created_at >= start_dt)
    if end_dt:   _ret_stmt = _ret_stmt.where(CashEntry.created_at < end_dt)
    if selected_agent_id: _ret_stmt = _ret_stmt.where(CashEntry.agent_id == selected_agent_id)
    total_return_op_cash = db.scalar(_ret_stmt) or 0
    operating_balance = total_operating - total_expenses - total_return_op_cash
    remittance = total_collections - total_expenses - total_office_expenses
    net_position = remittance + operating_balance
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).where(User.is_active == True).order_by(User.username.asc())).scalars().all() if (is_admin(user) or is_supervisor(user)) else []

    # Fetch individual expense entries for the drill-down modal
    def _entries(kind_list):
        stmt = select(CashEntry).where(CashEntry.kind.in_(kind_list)).where(_branch_filter())
        if start_dt: stmt = stmt.where(CashEntry.created_at >= start_dt)
        if end_dt:   stmt = stmt.where(CashEntry.created_at < end_dt)
        if selected_agent_id: stmt = stmt.where(CashEntry.agent_id == selected_agent_id)
        return db.execute(stmt.order_by(desc(CashEntry.created_at)).limit(200)).scalars().all()

    # Build serialisable entry dicts for JSON embedding in template
    def _entry_list(kind_list):
        umap = {u.id: (u.full_name or u.username) for u in agents} if agents else {}
        return [
            {"date": e.created_at.strftime("%d %b %Y") if e.created_at else "—",
             "amount": e.amount, "note": e.note or "—",
             "agent": umap.get(e.agent_id, "—"), "kind": e.kind}
            for e in _entries(kind_list)
        ]

    expense_entries      = _entry_list(["EXPENSE", "COLLECTION_EXPENSE"])
    coll_expense_entries = _entry_list(["COLLECTION_EXPENSE"])
    collection_entries   = _entry_list(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"])
    op_cash_entries      = _entry_list(["OPERATING_CASH"])
    office_entries       = _entry_list(["OFFICE_EXPENSE"])
    total_collection_expenses = sum(e["amount"] for e in coll_expense_entries)

    csrf_token = get_csrf_token(request)
    form_token = generate_form_token(request)
    return tpl(request, "cash_dashboard.html", {
        "request": request, "user": user, "rows": rows,
        "total_collections": total_collections, "total_expenses": total_expenses,
        "total_operating_cash": total_operating, "total_return_op_cash": total_return_op_cash,
        "operating_balance": operating_balance, "total_office_expenses": total_office_expenses,
        "remittance": remittance, "net_position": net_position,
        "agents": agents, "agent_id": agent_id,
        "expense_entries": expense_entries,
        "coll_expense_entries": coll_expense_entries,
        "total_collection_expenses": total_collection_expenses,
        "collection_entries": collection_entries,
        "op_cash_entries": op_cash_entries,
        "office_entries": office_entries,
        "preset": preset_norm or (preset or ""),
        "start_date": sd.isoformat() if sd else "",
        "end_date": ed.isoformat() if ed else "",
        "active": "cash", "csrf_token": csrf_token,
        "form_token": form_token,
    })


@router.post("/cash/new")
async def cash_new(
    request: Request,
    kind: str = Form(...),
    amount: float = Form(...),
    note: str = Form(""),
    delivery_id: str = Form(""),
    agent_id: str = Form(""),
    csrf_token: str = Form(""),
    form_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_active_user),
):
    verify_csrf_token(request, csrf_token)
    # [SEC] Idempotency — reject duplicate cash entry submissions
    if not consume_form_token(request, form_token):
        return redirect("/cash?error=Duplicate+submission+detected.+Please+try+again.")
    k = (kind or "").strip().upper()
    if k not in {"COLLECTION", "EXPENSE", "OPERATING_CASH", "OFFICE_EXPENSE", "RETURN_OPERATING_CASH", "CASH_PAYMENT", "TRANSFER_PAYMENT", "COLLECTION_EXPENSE"}:
        raise HTTPException(status_code=400, detail="Invalid kind")
    if k == "OFFICE_EXPENSE" and not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    if k == "OPERATING_CASH" and not is_admin(user):
        return HTMLResponse("Forbidden — only admins can give operating cash", status_code=403)
    amt = sanitize_amount(amount)
    if amt <= 0:
        raise HTTPException(status_code=400, detail="Amount must be > 0")
    target_agent_id = user.id
    if is_admin(user) and (agent_id or "").isdigit(): target_agent_id = int(agent_id)
    if k == "OFFICE_EXPENSE": target_agent_id = user.id
    d_id = int(delivery_id) if (delivery_id or "").isdigit() else None
    branch_id = get_current_branch_id(request)
    if not branch_id:
        raise HTTPException(status_code=400, detail="No branch assigned")
    # Auto-detect expense source for agents:
    # If agent records EXPENSE and has no remaining op cash balance → use COLLECTION_EXPENSE instead
    if k == "EXPENSE" and is_agent(user):
        op_given = db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == target_agent_id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind == "OPERATING_CASH")
        ) or 0
        op_spent = db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == target_agent_id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind.in_(["EXPENSE", "COLLECTION_EXPENSE"]))
        ) or 0
        op_returned = db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == target_agent_id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind == "RETURN_OPERATING_CASH")
        ) or 0
        op_balance = op_given - op_spent - op_returned
        if op_balance <= 0:
            k = "COLLECTION_EXPENSE"  # Op cash exhausted — deduct from collection

    db.add(CashEntry(
        branch_id=branch_id, agent_id=target_agent_id, delivery_id=d_id,
        kind=k, amount=amt, note=sanitize_text(note, 400, "Note") or None,
    ))
    # Notify agent when admin gives them operating cash
    if k == "OPERATING_CASH" and is_admin(user) and target_agent_id != user.id:
        notify(db, target_agent_id, "💰 Operating Cash Received",
               f"Admin has given you ₦{amt:,.0f} operating cash." + (f" Note: {(note or '').strip()}" if note else ""),
               "/cash", "success")
    db.commit()
    if d_id:
        return redirect(f"/deliveries/{d_id}")
    return redirect("/cash")


# ────────────────────────────────────────────────
#  REPORTS
# ────────────────────────────────────────────────

@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    branch_id = get_selected_branch_id(request, user)
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).where(User.is_active == True).order_by(User.username.asc())).scalars().all() if (is_admin(user) or is_supervisor(user)) else []
    today = date.today().isoformat()
    return tpl(request, "reports_sales.html", {
        "request": request, "user": user, "agents": agents,
        "start_date": today, "end_date": today, "active": "reports",
    })


@router.get("/reports/preview")
def reports_preview(request: Request, start_date: str | None = None, end_date: str | None = None, agent_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    d1 = _parse_iso_date(start_date); d2 = _parse_iso_date(end_date)
    if not d1 and not d2: d1 = d2 = date.today()
    if d1 and not d2: d2 = d1
    if d2 and not d1: d1 = d2
    start_dt = datetime.combine(d1, datetime.min.time())
    end_dt   = datetime.combine(d2, datetime.max.time())
    branch_id = get_selected_branch_id(request, user)
    target_agent_id = None
    if is_agent(user): target_agent_id = int(user.id)
    elif is_admin(user) and (agent_id or "").isdigit(): target_agent_id = int(agent_id)
    # Use delivered_at (when actually marked delivered) so "today" shows today's deliveries.
    # Fall back to delivery_date, then created_at for old records where both may be null.
    _effective_date = func.coalesce(Delivery.delivered_at, Delivery.delivery_date, Delivery.created_at)
    filters = [
        Delivery.status == "DELIVERED",
        _effective_date >= start_dt,
        _effective_date <= end_dt,
    ]
    if not is_supervisor(user): filters.append(Delivery.branch_id == branch_id)
    if target_agent_id: filters.append(Delivery.agent_id == target_agent_id)
    deliveries = db.execute(select(Delivery).where(and_(*filters)).order_by(Delivery.delivery_date.asc())).scalars().all()
    delivery_ids = [d.id for d in deliveries]
    items_by_delivery: dict[int, list] = {}
    if delivery_ids:
        for did, iname, qty, line_amt, selling_price in db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity, DeliveryItem.line_amount, Item.selling_price)
            .join(Item, Item.id == DeliveryItem.item_id).where(DeliveryItem.delivery_id.in_(delivery_ids))
        ).all():
            q = qty or 0; la = line_amt or 0; sp = selling_price or 0
            # Skip items removed by adjustment (line_amount == 0 means customer refused/returned)
            if la == 0 and q > 0:
                continue
            items_by_delivery.setdefault(int(did), []).append({"name": str(iname), "qty": q, "amount": la})
    _ce_branch = CashEntry.branch_id == branch_id if not is_supervisor(user) else True
    # Get agent IDs to include in cash queries
    # If a specific agent is selected, only show that agent's data
    if target_agent_id:
        _agent_ce_filter = (CashEntry.agent_id == target_agent_id)
    elif not is_supervisor(user):
        branch_agent_ids = [u.id for u in db.execute(
            select(User).where(User.role == "AGENT").where(User.branch_id == branch_id)
        ).scalars().all()]
        _agent_ce_filter = (CashEntry.agent_id.in_(branch_agent_ids)) if branch_agent_ids else (CashEntry.agent_id == -1)
    else:
        _agent_ce_filter = True  # supervisor: no agent filter
    # agent_exp_map: AGENT expenses EXCLUDING waybill-tagged ones (those go to waybill section)
    # agent_exp_map: includes both EXPENSE (from op cash) and COLLECTION_EXPENSE (from collection)
    agent_exp_map = {int(aid): t for aid, t in db.execute(
        select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind.in_(["EXPENSE", "COLLECTION_EXPENSE"]))
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
        .where(_agent_ce_filter if not is_supervisor(user) else True)
        .where(func.lower(func.coalesce(CashEntry.note, "")).notlike("%waybill%"))
        .group_by(CashEntry.agent_id)
    ).all()}
    # Separate collection-funded expenses per agent for report breakdown
    agent_coll_exp_map = {int(aid): t for aid, t in db.execute(
        select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind == "COLLECTION_EXPENSE")
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
        .where(_agent_ce_filter if not is_supervisor(user) else True)
        .group_by(CashEntry.agent_id)
    ).all()}
    op_cash_map = {int(aid): t for aid, t in db.execute(
        select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind == "OPERATING_CASH").where(CashEntry.created_at >= start_dt)
        .where(CashEntry.created_at <= end_dt).where(_ce_branch)
        .where(_agent_ce_filter if not is_supervisor(user) else True)
        .group_by(CashEntry.agent_id)
    ).all()}
    # Waybill entries = OFFICE_EXPENSE tagged waybill + EXPENSE tagged waybill (agent transfer expenses)
    # For agents: only their own waybill entries; for admin/supervisor: all branch waybill entries
    _wb_stmt = (
        select(CashEntry.amount, CashEntry.note, CashEntry.created_at)
        .where(CashEntry.kind.in_(["OFFICE_EXPENSE", "EXPENSE"]))
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
        .where(func.lower(func.coalesce(CashEntry.note, "")).like("%waybill%"))
        .order_by(CashEntry.created_at.asc())
    )
    if is_agent(user):
        _wb_stmt = _wb_stmt.where(CashEntry.agent_id == user.id)
    elif target_agent_id:
        _wb_stmt = _wb_stmt.where(CashEntry.agent_id == target_agent_id)
    waybill_entries_raw = db.execute(_wb_stmt).all()
    waybill_entries = [{"amount": r[0], "note": str(r[1] or ""), "date": r[2].strftime("%d %b %Y") if r[2] else ""} for r in waybill_entries_raw]
    waybill_total = sum(e["amount"] for e in waybill_entries)
    # office_total = non-waybill OFFICE_EXPENSE + waybill_total
    _off_stmt = (
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind == "OFFICE_EXPENSE")
        .where(func.lower(func.coalesce(CashEntry.note, "")).notlike("%waybill%"))
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
    )
    if is_agent(user):
        _off_stmt = _off_stmt.where(CashEntry.agent_id == user.id)
    elif target_agent_id:
        _off_stmt = _off_stmt.where(CashEntry.agent_id == target_agent_id)
    office_non_waybill = db.scalar(_off_stmt) or 0
    office_total = office_non_waybill + waybill_total
    all_agent_ids = list(set(list(agent_exp_map.keys()) + list(op_cash_map.keys())))
    uname = {}
    if all_agent_ids:
        users_map = {int(u.id): u for u in db.execute(select(User).where(User.id.in_(all_agent_ids))).scalars().all()}
        uname = {uid: (u.full_name or u.username) for uid, u in users_map.items()}
    delivery_rows = []
    grand_total = 0
    for idx, d in enumerate(deliveries, 1):
        d_items = items_by_delivery.get(int(d.id), [])
        total = sum(i["amount"] for i in d_items)
        grand_total += total
        delivery_rows.append({"idx": idx, "customer": d.customer_name, "date": (d.delivery_date or d.created_at).strftime("%d %b %Y"), "items": d_items, "total": total})
    agent_op_summary = []
    total_op_cash_given = total_op_cash_balance_returned = expenses_from_collections = 0
    for aid in sorted(set(list(agent_exp_map.keys()) + list(op_cash_map.keys()))):
        exp       = agent_exp_map.get(aid, 0)
        coll_exp  = agent_coll_exp_map.get(aid, 0)
        op_exp    = exp - coll_exp   # expenses from operating cash only
        op        = op_cash_map.get(aid, 0)
        # Subtract confirmed returns from balance (agent already handed back cash)
        ret_confirmed = db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == aid)
            .where(CashEntry.kind == "RETURN_OPERATING_CASH")
            .where(CashEntry.confirmed_by_admin == True)
            .where(CashEntry.created_at >= start_dt)
            .where(CashEntry.created_at <= end_dt)
        ) or 0
        balance   = op - op_exp - ret_confirmed
        total_op_cash_given += op
        expenses_from_collections += coll_exp
        if op > 0:
            total_op_cash_balance_returned += max(balance, 0)
            if balance < 0: expenses_from_collections += abs(balance)
        agent_op_summary.append({
            "name": uname.get(aid, f"Agent {aid}"),
            "op_cash": op, "expenses": exp,
            "op_expenses": op_exp, "coll_expenses": coll_exp,
            "balance": balance, "has_op_cash": op > 0,
        })
    total_agent_exp = sum(a["expenses"] for a in agent_op_summary)
    total_expenses = total_agent_exp + office_total
    remittance = grand_total - expenses_from_collections if is_agent(user) else grand_total - total_expenses
    title = d1.strftime("%A %d %B %Y").upper() if d1 == d2 else f"{d1.isoformat()} TO {d2.isoformat()}"
    return JSONResponse({
        "title": title, "delivery_count": len(deliveries), "deliveries": delivery_rows,
        "grand_total": grand_total, "agent_op_summary": agent_op_summary,
        "total_op_cash_given": total_op_cash_given,
        "total_op_cash_balance_returned": total_op_cash_balance_returned,
        "expenses_from_collections": expenses_from_collections,
        "total_agent_expenses": total_agent_exp, "waybill_total": waybill_total,
        "waybill_entries": waybill_entries,
        "other_office_expenses": office_total - waybill_total,
        "total_office_expenses": office_total, "total_expenses": total_expenses,
        "remittance": remittance, "is_agent": is_agent(user),
    })


@router.get("/reports/txt", response_class=PlainTextResponse)
def reports_txt(request: Request, start_date: str | None = None, end_date: str | None = None, agent_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    d1 = _parse_iso_date(start_date); d2 = _parse_iso_date(end_date)
    if not d1 and not d2: d1 = d2 = date.today()
    if d1 and not d2: d2 = d1
    if d2 and not d1: d1 = d2
    start_dt = datetime.combine(d1, datetime.min.time())
    end_dt   = datetime.combine(d2, datetime.max.time())
    branch_id = get_selected_branch_id(request, user)
    target_agent_id = None
    if is_agent(user): target_agent_id = int(user.id)
    elif is_admin(user) and (agent_id or "").isdigit(): target_agent_id = int(agent_id)
    _eff_date = func.coalesce(Delivery.delivered_at, Delivery.delivery_date, Delivery.created_at)
    filters = [_eff_date >= start_dt, _eff_date <= end_dt, Delivery.status == "DELIVERED"]
    if not is_supervisor(user): filters.append(Delivery.branch_id == branch_id)
    if target_agent_id is not None: filters.append(Delivery.agent_id == target_agent_id)
    deliveries = db.execute(select(Delivery).where(and_(*filters)).order_by(_eff_date.asc())).scalars().all()
    delivery_ids = [d.id for d in deliveries]
    items_by_delivery: dict[int, list] = {}
    if delivery_ids:
        for did, iname, qty, line_amt, sp in db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity, DeliveryItem.line_amount, Item.selling_price)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all():
            q = qty or 0; la = line_amt or 0
            # Skip items removed by adjustment (line_amount == 0 means customer refused/returned)
            if la == 0 and q > 0:
                continue
            items_by_delivery.setdefault(int(did), []).append((str(iname), q, la))
    _ce_br = CashEntry.branch_id == branch_id if not is_supervisor(user) else True
    agent_exp_map = {int(aid): t for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind.in_(["EXPENSE","COLLECTION_EXPENSE"])).where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(_ce_br).group_by(CashEntry.agent_id).order_by(CashEntry.agent_id.asc())).all()}
    agent_coll_exp_txt = {int(aid): t for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "COLLECTION_EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(_ce_br).group_by(CashEntry.agent_id)).all()}
    op_cash_map = {int(aid): t for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OPERATING_CASH").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).group_by(CashEntry.agent_id)).all()}
    office_total = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OFFICE_EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)) or 0
    waybill_total = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OFFICE_EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(func.lower(func.coalesce(CashEntry.note, "")).like("%waybill%"))) or 0
    other_office_total = office_total - waybill_total
    all_agent_ids = list(set(list(agent_exp_map.keys()) + list(op_cash_map.keys())))
    uname: dict[int, str] = {}
    if all_agent_ids:
        uname = {int(u.id): (u.full_name or u.username or f"Agent {u.id}") for u in db.execute(select(User).where(User.id.in_(all_agent_ids))).scalars().all()}
    title_day = d1.strftime("%A %d %B %Y").upper() if d1 == d2 else f"{d1.isoformat()} TO {d2.isoformat()}"
    lines = [f"REPORT FOR {title_day}.", f"TOTAL DELIVERY = {len(deliveries)}", ""]
    grand_total = 0.0
    for idx, d in enumerate(deliveries, start=1):
        d_items = items_by_delivery.get(int(d.id), [])
        delivery_total = sum(amt for _n, _q, amt in d_items)
        grand_total += delivery_total
        parts = [f"{q:g} {n}" for n, q, _a in d_items]
        lines.append(f"({idx})\t{sum(q for _n,q,_a in d_items):g}\t{' + '.join(parts) if parts else 'No items'}\t{_ngn(delivery_total)}")
    lines += ["", f"Grand total: {_ngn(grand_total)}", ""]
    total_agent_expenses = expenses_from_collections = total_op_cash_given = total_op_cash_balance = 0.0
    agent_section_lines: list[str] = []
    for aid in sorted(set(list(agent_exp_map.keys()) + list(op_cash_map.keys()))):
        exp = agent_exp_map.get(aid, 0.0); op = op_cash_map.get(aid, 0.0); aname = uname.get(aid, f"Agent {aid}")
        total_agent_expenses += exp; total_op_cash_given += op
        if op > 0:
            balance = op - exp; total_op_cash_balance += max(balance, 0)
            if balance < 0: expenses_from_collections += abs(balance)
            # Only show agent in section if they still have a balance to return
            if balance > 0:
                agent_section_lines += [f"  {aname}:", f"    Operating cash given : {_ngn(op)}", f"    Expenses spent       : {_ngn(exp)}",
                                        f"    Balance to return    : {_ngn(balance)}"]
        else:
            expenses_from_collections += exp
            if exp > 0:
                agent_section_lines += [f"  {aname}:", f"    Expenses (no op cash, deducted from collection): {_ngn(exp)}"]
    if is_agent(user):
        lines += ["Operating Cash & Expenses:"] + (agent_section_lines or ["  None"])
        if total_op_cash_given > 0:
            lines += [f"  Total operating cash given : {_ngn(total_op_cash_given)}", f"  Total expenses             : {_ngn(total_agent_expenses)}", f"  Total balance to return    : {_ngn(total_op_cash_balance)}"]
        lines += ["", "Office expenses:", f"  Waybills              : {_ngn(waybill_total)}", f"  Other office expenses : {_ngn(other_office_total)}", f"  Total office expenses : {_ngn(office_total)}", ""]
        remittance = grand_total - expenses_from_collections
        lines += ["Amount to be remitted (collections only):"]
        lines.append(f"  {_ngn(grand_total)} - {_ngn(expenses_from_collections)} (uncovered expenses) = {_ngn(remittance)}" if expenses_from_collections > 0 else f"  {_ngn(grand_total)}")
    else:
        total_expenses = total_agent_expenses + office_total
        remittance = grand_total - total_expenses
        lines += ["Agent Expenses:"] + (agent_section_lines or ["  None"]) + [f"  Total agent expenses: {_ngn(total_agent_expenses)}", "", "Office expenses:",
            f"  Waybills              : {_ngn(waybill_total)}", f"  Other office expenses : {_ngn(other_office_total)}", f"  Total office expenses : {_ngn(office_total)}", "",
            f"Total amount of expenses: {_ngn(total_expenses)}", "", "Amount to be remitted:", f"  {_ngn(grand_total)} - {_ngn(total_expenses)} = {_ngn(remittance)}"]
    return PlainTextResponse("\n".join(lines), headers={"Content-Disposition": f'attachment; filename="report_{d1.isoformat()}_{d2.isoformat()}.txt"'}, media_type="text/plain; charset=utf-8")


# ────────────────────────────────────────────────
#  MERCHANT RECEIPTS
# ────────────────────────────────────────────────

@router.get("/merchant-receipt/new", response_class=HTMLResponse)
def merchant_receipt_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    branch_id = get_selected_branch_id(request, user)
    items = get_items_with_stock(db, branch_id=branch_id)
    csrf_token = get_csrf_token(request)
    categories = db.execute(
        select(Item.category).where(Item.branch_id == branch_id)
        .where(Item.category.isnot(None)).distinct().order_by(Item.category.asc())
    ).scalars().all()
    return tpl(request, "merchant_receipt_new.html", {
        "request": request, "user": user, "items": items,
        "categories": categories, "mode": "receipt",
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "active": "transfers", "csrf_token": csrf_token,
    })


@router.post("/merchant-receipt/new")
async def merchant_receipt_create(
    request: Request,
    merchant_name: str = Form(...),
    note: str = Form(""),
    expense_amount: str = Form(""),
    expense_note: str = Form(""),
    item_ids: list[int] = Form(...),
    quantities: list[int] = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN")),
):
    verify_csrf_token(request, csrf_token)
    branch_id = get_selected_branch_id(request, user)
    merchant_name = sanitize_text(merchant_name, 200, "Merchant name")
    if not merchant_name:
        return redirect("/merchant-receipt/new?error=Merchant+name+is+required")
    if not item_ids or not quantities or len(item_ids) != len(quantities):
        return redirect("/merchant-receipt/new?error=Please+add+at+least+one+item")
    for qty in quantities:
        if qty <= 0:
            return redirect("/merchant-receipt/new?error=Quantities+must+be+greater+than+zero")
    note_text = sanitize_text(note, 400, "Note") or ""
    ref = f"MERCHANT: {merchant_name}"
    full_note = note_text if note_text else f"Stock received from merchant: {merchant_name}"
    for item_id, qty in zip(item_ids, quantities):
        item = db.get(Item, item_id)
        if not item or item.branch_id != branch_id:
            return redirect("/merchant-receipt/new?error=Invalid+item+selected")
        db.add(Transaction(
            branch_id=branch_id, item_id=item_id,
            type="IN", quantity=qty,
            reference=ref, note=full_note,
        ))
    # Record expense if provided
    from decimal import Decimal as _D, InvalidOperation
    exp_amt = 0
    try:
        exp_amt = _D(str(expense_amount)) if expense_amount else 0
    except (InvalidOperation, ValueError):
        exp_amt = 0
    if exp_amt > 0:
        db.add(CashEntry(
            branch_id=branch_id,
            agent_id=user.id,
            kind="OFFICE_EXPENSE",
            amount=exp_amt,
            note=f"waybill - from {merchant_name}: {sanitize_text(expense_note, 200, 'Note') or ''}".strip().rstrip(':'),
        ))
    db.commit()
    return redirect("/merchant-receipt/new?success=Stock+received+and+recorded+successfully")


@router.get("/merchant-return/new", response_class=HTMLResponse)
def merchant_return_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """Return goods back to a merchant — creates OUT transactions."""
    branch_id = get_selected_branch_id(request, user)
    items = get_items_with_stock(db, branch_id=branch_id)
    # Get distinct merchant names from item categories for this branch
    categories = db.execute(
        select(Item.category).where(Item.branch_id == branch_id)
        .where(Item.category.isnot(None)).distinct().order_by(Item.category.asc())
    ).scalars().all()
    csrf_token = get_csrf_token(request)
    return tpl(request, "merchant_receipt_new.html", {
        "request": request, "user": user, "items": items,
        "categories": categories,
        "mode": "return",  # tells template which tab is active
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "active": "transfers", "csrf_token": csrf_token,
    })


@router.post("/merchant-return/new")
async def merchant_return_create(
    request: Request,
    merchant_name: str = Form(...),
    note: str = Form(""),
    expense_amount: str = Form(""),
    expense_note: str = Form(""),
    item_ids: list[int] = Form(...),
    quantities: list[int] = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN")),
):
    """Record goods returned to merchant — OUT transaction per item."""
    verify_csrf_token(request, csrf_token)
    branch_id = get_selected_branch_id(request, user)
    merchant_name = sanitize_text(merchant_name, 200, "Merchant name")
    if not merchant_name:
        return redirect("/merchant-return/new?error=Merchant+name+is+required")
    if not item_ids or not quantities or len(item_ids) != len(quantities):
        return redirect("/merchant-return/new?error=Please+add+at+least+one+item")
    for qty in quantities:
        if qty <= 0:
            return redirect("/merchant-return/new?error=Quantities+must+be+greater+than+zero")
    note_text = sanitize_text(note, 400, "Note") or ""
    ref = f"MERCHANT RETURN: {merchant_name}"
    full_note = note_text if note_text else f"Goods returned to merchant: {merchant_name}"
    # Lock all item rows to prevent concurrent stock modifications
    locked_item_ids = sorted({iid for iid in item_ids})
    db.execute(select(Item).where(Item.id.in_(locked_item_ids)).order_by(Item.id.asc()).with_for_update())
    for item_id, qty in zip(item_ids, quantities):
        item = db.get(Item, item_id)
        if not item or item.branch_id != branch_id:
            return redirect("/merchant-return/new?error=Invalid+item+selected")
        stock = compute_stock(db, item_id, branch_id)
        if stock < qty:
            return redirect(f"/merchant-return/new?error={quote_plus(f'Insufficient stock for {item.name} (available: {stock})')}")
        db.add(Transaction(
            branch_id=branch_id, item_id=item_id,
            type="OUT", quantity=qty,
            reference=ref, note=full_note,
        ))
    # Record expense if provided
    exp_amt = 0
    try:
        exp_amt = _D(str(expense_amount)) if expense_amount else 0
    except (InvalidOperation, ValueError):
        exp_amt = 0
    if exp_amt > 0:
        db.add(CashEntry(
            branch_id=branch_id, agent_id=user.id,
            kind="OFFICE_EXPENSE", amount=exp_amt,
            note=f"waybill - to {merchant_name}: {sanitize_text(expense_note, 200, 'Note') or ''}".strip().rstrip(':'),
        ))
    audit_log(db, user.id, "MERCHANT_RETURN",
              f"merchant={merchant_name} items={len(item_ids)}",
              ip=request.client.host if request.client else "")
    db.commit()
    return redirect("/merchant-return/new?success=Goods+returned+to+merchant+and+recorded+successfully")


@router.get("/transfers", response_class=HTMLResponse)
def transfers_list(request: Request, db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    if is_agent(user):
        # Agents see transfers delegated to them (send or receive side) — hide cancelled from receiver
        transfers = db.execute(
            select(StockTransfer)
            .where(
                (StockTransfer.delegated_agent_id == user.id) |
                ((StockTransfer.delegated_receiver_id == user.id) & (StockTransfer.status != "CANCELLED"))
            )
            .order_by(desc(StockTransfer.created_at))
        ).scalars().all()
    elif is_supervisor(user):
        transfers = db.execute(select(StockTransfer).order_by(desc(StockTransfer.created_at))).scalars().all()
    elif is_admin(user):
        transfers = db.execute(
            select(StockTransfer)
            .where((StockTransfer.from_branch_id == user.branch_id) | (StockTransfer.to_branch_id == user.branch_id))
            .order_by(desc(StockTransfer.created_at))
        ).scalars().all()
    else:
        return HTMLResponse("Forbidden", status_code=403)
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all()
    # Fetch merchant receipts — admin and supervisor only
    merchant_receipts = []
    merchant_receipts_count = 0
    if is_admin(user) or is_supervisor(user):
        mr_tx_stmt = (
            select(Transaction.reference, Transaction.branch_id, Transaction.created_at,
                   Transaction.quantity, Item.name)
            .join(Item, Item.id == Transaction.item_id)
            .where(Transaction.reference.like("MERCHANT:%"))
            .order_by(Transaction.created_at.desc())
        )
        if not is_supervisor(user):
            mr_tx_stmt = mr_tx_stmt.where(Transaction.branch_id == user.branch_id)
        mr_tx_rows = db.execute(mr_tx_stmt).all()
        mr_groups: dict = {}
        for ref, br_id, created, qty, iname in mr_tx_rows:
            if ref not in mr_groups:
                mr_groups[ref] = {"reference": ref, "branch_id": br_id, "created_at": created,
                                   "items": [], "merchant_name": str(ref).replace("MERCHANT:", "").strip()}
            mr_groups[ref]["items"].append(f"{iname} x{qty}")
        merchant_receipts = sorted(mr_groups.values(), key=lambda r: r["created_at"], reverse=True)
        for r in merchant_receipts:
            r["item_names"] = ", ".join(r["items"])
        merchant_receipts_count = len(merchant_receipts)
    # Count sent (from this branch) and received (to this branch) — for cards
    if is_supervisor(user):
        sent_count     = sum(1 for t in transfers if t.status in ("OUT_FOR_DELIVERY", "RECEIVED"))
        received_count = sum(1 for t in transfers if t.status == "RECEIVED")
    elif is_agent(user):
        sent_count     = sum(1 for t in transfers if t.delegated_agent_id == user.id and t.status in ("OUT_FOR_DELIVERY", "RECEIVED"))
        received_count = sum(1 for t in transfers if t.delegated_receiver_id == user.id and t.status == "RECEIVED")
    else:
        sent_count     = sum(1 for t in transfers if t.from_branch_id == user.branch_id and t.status in ("OUT_FOR_DELIVERY", "RECEIVED"))
        received_count = sum(1 for t in transfers if t.to_branch_id == user.branch_id and t.status == "RECEIVED")
    csrf_token = get_csrf_token(request)
    return tpl(request, "transfers_list.html", {
        "request": request, "user": user, "transfers": transfers, "branches": branches,
        "active": "transfers", "selected_branch_id": getattr(user, "branch_id", None),
        "merchant_receipts": merchant_receipts,
        "merchant_receipts_count": merchant_receipts_count,
        "sent_count": sent_count, "received_count": received_count,
        "csrf_token": csrf_token,
    })


@router.get("/transfers/new", response_class=HTMLResponse)
def transfer_new_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    branches = db.execute(select(Branch).where(Branch.id != user.branch_id).order_by(Branch.name)).scalars().all()
    items = get_items_with_stock(db, branch_id=user.branch_id)
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == user.branch_id).where(User.is_active == True).order_by(User.username)).scalars().all()
    csrf_token = get_csrf_token(request)
    return tpl(request, "transfer_new.html", {
        "request": request, "user": user, "branches": branches, "items": items, "agents": agents,
        "error": request.query_params.get("error"), "active": "transfers",
        "selected_branch_id": user.branch_id, "csrf_token": csrf_token,
    })


@router.post("/transfers/new")
async def transfer_create(
    request: Request,
    to_branch_id: int = Form(...),
    note: str = Form(""),
    delegated_agent_id: str = Form(""),
    item_ids: list[int] = Form(...),
    quantities: list[int] = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN")),
):
    verify_csrf_token(request, csrf_token)
    if to_branch_id == user.branch_id:
        return redirect("/transfers/new?error=Cannot+transfer+to+your+own+branch")
    if not item_ids or not quantities or len(item_ids) != len(quantities):
        return redirect("/transfers/new?error=Please+add+at+least+one+item")
    for item_id, qty in zip(item_ids, quantities):
        if qty <= 0:
            return redirect("/transfers/new?error=Quantities+must+be+greater+than+zero")
        row = get_item_with_stock(db, item_id, branch_id=user.branch_id)
        if not row:
            return redirect("/transfers/new?error=Item+not+found")
        _item, stock = row
        if int(stock) < qty:
            return redirect(f"/transfers/new?error=Insufficient+stock+for+{_item.name}")
    del_agent_id = int(delegated_agent_id) if delegated_agent_id.isdigit() else None
    transfer = StockTransfer(
        from_branch_id=user.branch_id, to_branch_id=to_branch_id, status="PENDING",
        note=sanitize_text(note, 400, "Note") or None, created_by_id=user.id,
        delegated_agent_id=del_agent_id,
    )
    db.add(transfer)
    db.flush()
    for item_id, qty in zip(item_ids, quantities):
        db.add(StockTransferItem(transfer_id=transfer.id, item_id=item_id, quantity=qty))
    # Stock is NOT deducted here — deducted when agent/admin marks as packed & sent
    db.commit()
    notify_branch_admins(db, to_branch_id,
        "📦 Incoming Stock Transfer",
        f"A new stock transfer from {user.branch.name} is pending for your branch (transfer #{transfer.id}).",
        f"/transfers/{transfer.id}", "info")
    if del_agent_id:
        notify(db, del_agent_id,
            "📦 Transfer Assigned to You",
            f"You have been assigned to send stock transfer #{transfer.id} to another branch.",
            f"/transfers/{transfer.id}", "info")
    return redirect(f"/transfers/{transfer.id}")


@router.get("/transfers/{transfer_id}", response_class=HTMLResponse)
def transfer_detail(transfer_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    # Allow: admin of from/to branch, supervisor, or delegated agent
    is_delegated          = is_agent(user) and transfer.delegated_agent_id    == user.id
    is_delegated_receiver = is_agent(user) and transfer.delegated_receiver_id == user.id
    if not (is_admin(user) or is_supervisor(user) or is_delegated or is_delegated_receiver):
        return HTMLResponse("Forbidden", status_code=403)
    if is_admin(user) and user.branch_id not in (transfer.from_branch_id, transfer.to_branch_id):
        return HTMLResponse("Forbidden", status_code=403)
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all()
    delegated_agent    = db.get(User, transfer.delegated_agent_id)    if transfer.delegated_agent_id    else None
    delegated_receiver = db.get(User, transfer.delegated_receiver_id) if transfer.delegated_receiver_id else None
    packed_by          = db.get(User, getattr(transfer, "packed_by_id", None)) if getattr(transfer, "packed_by_id", None) else None
    is_delegated_receiver = is_agent(user) and transfer.delegated_receiver_id == user.id
    # Agents for sender branch (for delegation dropdown — sender admin only)
    sender_agents   = db.execute(select(User).where(User.role=="AGENT").where(User.branch_id==transfer.from_branch_id).where(User.is_active==True).order_by(User.username)).scalars().all() if (is_admin(user) and user.branch_id==transfer.from_branch_id) else []
    receiver_agents = db.execute(select(User).where(User.role=="AGENT").where(User.branch_id==transfer.to_branch_id).where(User.is_active==True).order_by(User.username)).scalars().all()  if (is_admin(user) and user.branch_id==transfer.to_branch_id)   else []
    csrf_token = get_csrf_token(request)
    form_token = generate_form_token(request)
    return tpl(request, "transfer_detail.html", {
        "request": request, "user": user, "transfer": transfer, "branches": branches,
        "delegated_agent": delegated_agent, "delegated_receiver": delegated_receiver,
        "packed_by": packed_by,
        "is_delegated": is_delegated, "is_delegated_receiver": is_delegated_receiver,
        "sender_agents": sender_agents, "receiver_agents": receiver_agents,
        "active": "transfers", "selected_branch_id": getattr(user, "branch_id", None),
        "csrf_token": csrf_token, "form_token": form_token,
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
    })


@router.post("/transfers/{transfer_id}/receive")
async def transfer_receive(transfer_id: int, request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    is_recv_agent = is_agent(user)
    verify_csrf_token(request, csrf_token)
    # Lock transfer row to prevent concurrent receive operations
    transfer = db.execute(
        select(StockTransfer).where(StockTransfer.id == transfer_id).with_for_update()
    ).scalar_one_or_none()
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    if is_recv_agent:
        if transfer.delegated_receiver_id != user.id:
            return HTMLResponse("Forbidden", status_code=403)
    elif is_admin(user):
        if transfer.to_branch_id != user.branch_id:
            return HTMLResponse("Forbidden — you are not the receiving branch", status_code=403)
    else:
        return HTMLResponse("Forbidden", status_code=403)
    # For agent receiving, get branch_id from transfer
    recv_branch_id = transfer.to_branch_id
    if transfer.status in ("RECEIVED", "CANCELLED"):
        return redirect(f"/transfers/{transfer_id}?error=Transfer+is+already+{transfer.status}")
    for line in transfer.items:
        dest_item = db.scalar(select(Item).where(Item.branch_id == recv_branch_id, Item.name == line.item.name))
        if not dest_item:
            dest_item = Item(branch_id=recv_branch_id, name=line.item.name, category=line.item.category,
                             unit=line.item.unit, reorder_level=line.item.reorder_level,
                             cost_price=line.item.cost_price, selling_price=line.item.selling_price)
            db.add(dest_item)
            db.flush()
        db.add(Transaction(branch_id=recv_branch_id, item_id=dest_item.id, type="IN", quantity=line.quantity,
                           reference=f"TRANSFER #{transfer.id}", note=f"Stock received from branch {transfer.from_branch.name}"))
    # Require receive expense to be recorded before confirming receipt
    if not transfer.receive_expense_amount or transfer.receive_expense_amount <= 0:
        return redirect(f"/transfers/{transfer_id}?error=Please+record+your+receiving+expenses+before+confirming+receipt")
    transfer.status = "RECEIVED"
    transfer.received_by_id = user.id
    transfer.received_at = datetime.now(timezone.utc)
    notify_branch_admins(db, transfer.from_branch_id,
        "✅ Stock Transfer Received",
        f"{transfer.to_branch.name} has confirmed receipt of stock transfer #{transfer_id}.",
        f"/transfers/{transfer_id}", "success")
    db.commit()
    return redirect(f"/transfers/{transfer_id}?success=Stock+received+successfully")




@router.post("/transfers/{transfer_id}/pack")
async def transfer_pack(transfer_id: int, request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    """Agent marks transfer as packed/ready to send."""
    verify_csrf_token(request, csrf_token)
    # Lock transfer row to prevent concurrent pack operations
    transfer = db.execute(
        select(StockTransfer).where(StockTransfer.id == transfer_id).with_for_update()
    ).scalar_one_or_none()
    if not transfer:
        raise HTTPException(status_code=404)
    # Only the delegated agent or admin can pack
    if not is_admin(user) and transfer.delegated_agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    if transfer.status != "PENDING":
        return redirect(f"/transfers/{transfer_id}?error=Transfer+is+not+pending")
    # Require expense to be recorded before marking as sent
    if not transfer.expense_amount or transfer.expense_amount <= 0:
        return redirect(f"/transfers/{transfer_id}?error=Please+record+your+sending+expenses+before+marking+as+sent")
    # Deduct stock from sender branch — only if not already deducted (guard against old transfers)
    already_deducted = db.scalar(
        select(func.count(Transaction.id))
        .where(Transaction.reference == f"TRANSFER #{transfer.id}")
        .where(Transaction.type == "OUT")
        .where(Transaction.branch_id == transfer.from_branch_id)
    ) or 0
    if not already_deducted:
        for line in transfer.items:
            db.add(Transaction(
                branch_id=transfer.from_branch_id, item_id=line.item_id,
                type="OUT", quantity=line.quantity,
                reference=f"TRANSFER #{transfer.id}",
                note=f"Stock sent to {transfer.to_branch.name}"
            ))
    transfer.packed_by_id = user.id
    transfer.packed_at = datetime.now(timezone.utc)
    transfer.status = "OUT_FOR_DELIVERY"
    notify_branch_admins(db, transfer.to_branch_id,
        "📦 Stock Transfer On Its Way",
        f"Stock from {transfer.from_branch.name} has been packed and sent to your branch (transfer #{transfer_id}).",
        f"/transfers/{transfer_id}", "info")
    db.commit()
    audit_log(db, user.id, "TRANSFER_SENT", f"transfer_id={transfer_id}",
              ip=request.client.host if request.client else "")
    return redirect(f"/transfers/{transfer_id}?success=Transfer+packed+and+sent")


@router.post("/transfers/{transfer_id}/expense")
async def transfer_expense(
    transfer_id: int, request: Request,
    expense_amount: float = Form(0),
    expense_kind: str = Form(""),
    expense_note: str = Form(""),
    csrf_token: str = Form(""),
    form_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_active_user),
):
    """Record expense against a transfer — agent or admin."""
    verify_csrf_token(request, csrf_token)
    if not consume_form_token(request, form_token):
        return redirect(f"/transfers/{transfer_id}?error=Duplicate+submission")
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404)

    # Validate kind
    allowed_agent = {"EXPENSE", "COLLECTION_DEDUCTION"}
    allowed_admin = {"COLLECTION_DEDUCTION"}
    if is_admin(user):
        if expense_kind not in allowed_admin:
            return redirect(f"/transfers/{transfer_id}?error=Invalid+expense+type")
    else:
        if expense_kind not in allowed_agent:
            return redirect(f"/transfers/{transfer_id}?error=Invalid+expense+type")
        if transfer.delegated_agent_id != user.id:
            return HTMLResponse("Forbidden", status_code=403)

    if expense_amount <= 0:
        return redirect(f"/transfers/{transfer_id}?error=Amount+must+be+greater+than+zero")

    # Save on the transfer record
    transfer.expense_amount = expense_amount
    transfer.expense_kind = expense_kind
    transfer.expense_note = sanitize_text(expense_note, 400, "Note") or None

    # Also create a CashEntry so it shows in cash section
    cash_kind = "EXPENSE" if expense_kind == "EXPENSE" else "EXPENSE"
    to_branch_name = transfer.to_branch.name if transfer.to_branch else f"Branch {transfer.to_branch_id}"
    exp_note = f"waybill - to {to_branch_name}: {sanitize_text(expense_note, 200, 'Note') or ''}"
    if is_admin(user):
        target_agent = transfer.delegated_agent_id or user.id
        db.add(CashEntry(
            branch_id=transfer.from_branch_id,
            agent_id=target_agent,
            kind="OFFICE_EXPENSE",
            amount=expense_amount,
            note=exp_note,
        ))
    else:
        db.add(CashEntry(
            branch_id=transfer.from_branch_id,
            agent_id=user.id,
            kind="EXPENSE",
            amount=expense_amount,
            note=exp_note,
        ))
    db.commit()
    return redirect(f"/transfers/{transfer_id}")


@router.post("/transfers/{transfer_id}/delegate-receiver")
async def transfer_delegate_receiver(
    transfer_id: int, request: Request,
    delegated_receiver_id: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN")),
):
    verify_csrf_token(request, csrf_token)
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer: raise HTTPException(status_code=404)
    if user.branch_id != transfer.to_branch_id:
        return HTMLResponse("Forbidden — you are not the receiving branch", status_code=403)
    transfer.delegated_receiver_id = int(delegated_receiver_id) if delegated_receiver_id.isdigit() else None
    db.commit()
    if transfer.delegated_receiver_id:
        notify(db, transfer.delegated_receiver_id,
            "📦 Transfer to Receive",
            f"You have been assigned to receive stock transfer #{transfer_id}.",
            f"/transfers/{transfer_id}", "info")
    return redirect(f"/transfers/{transfer_id}")


@router.post("/transfers/{transfer_id}/receive-expense")
async def transfer_receive_expense(
    transfer_id: int, request: Request,
    receive_expense_amount: float = Form(0),
    receive_expense_kind: str = Form(""),
    receive_expense_note: str = Form(""),
    csrf_token: str = Form(""),
    form_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_active_user),
):
    verify_csrf_token(request, csrf_token)
    if not consume_form_token(request, form_token):
        return redirect(f"/transfers/{transfer_id}?error=Duplicate+submission")
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer: raise HTTPException(status_code=404)

    allowed_agent = {"EXPENSE", "COLLECTION_DEDUCTION"}
    allowed_admin = {"COLLECTION_DEDUCTION"}
    if is_admin(user):
        if receive_expense_kind not in allowed_admin:
            return redirect(f"/transfers/{transfer_id}?error=Invalid+expense+type")
        if user.branch_id != transfer.to_branch_id:
            return HTMLResponse("Forbidden", status_code=403)
    else:
        if receive_expense_kind not in allowed_agent:
            return redirect(f"/transfers/{transfer_id}?error=Invalid+expense+type")
        if transfer.delegated_receiver_id != user.id:
            return HTMLResponse("Forbidden", status_code=403)

    if receive_expense_amount <= 0:
        return redirect(f"/transfers/{transfer_id}?error=Amount+must+be+greater+than+zero")

    transfer.receive_expense_amount = receive_expense_amount
    transfer.receive_expense_kind   = receive_expense_kind
    transfer.receive_expense_note   = sanitize_text(receive_expense_note, 400, "Note") or None

    from_branch_name = transfer.from_branch.name if transfer.from_branch else f"Branch {transfer.from_branch_id}"
    recv_exp_note = f"waybill - from {from_branch_name}: {sanitize_text(receive_expense_note, 200, 'Note') or ''}"
    if is_admin(user):
        target_recv_agent = transfer.delegated_receiver_id or user.id
        db.add(CashEntry(
            branch_id=transfer.to_branch_id,
            agent_id=target_recv_agent,
            kind="OFFICE_EXPENSE",
            amount=receive_expense_amount,
            note=recv_exp_note,
        ))
    else:
        db.add(CashEntry(
            branch_id=transfer.to_branch_id,
            agent_id=user.id,
            kind="EXPENSE",
            amount=receive_expense_amount,
            note=recv_exp_note,
        ))
    db.commit()
    return redirect(f"/transfers/{transfer_id}")

@router.post("/transfers/{transfer_id}/cancel")
async def transfer_cancel(transfer_id: int, request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    verify_csrf_token(request, csrf_token)
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    is_delegated_cancel = is_agent(user) and transfer.delegated_agent_id == user.id
    if not is_admin(user) and not is_delegated_cancel:
        return HTMLResponse("Forbidden", status_code=403)
    if is_admin(user) and user.branch_id not in (transfer.from_branch_id, transfer.to_branch_id):
        return HTMLResponse("Forbidden", status_code=403)
    if transfer.status in ("RECEIVED", "CANCELLED"):
        return redirect(f"/transfers/{transfer_id}?error=Transfer+is+already+{transfer.status}")
    # Only return stock if it was already deducted (i.e. packed/sent)
    if transfer.status == "OUT_FOR_DELIVERY":
        for line in transfer.items:
            db.add(Transaction(
                branch_id=transfer.from_branch_id, item_id=line.item_id, type="IN", quantity=line.quantity,
                reference=f"TRANSFER #{transfer.id} CANCELLED", note="Stock returned — transfer cancelled"
            ))
    # Reverse send-side expense cash entry — find original by matching the "waybill - to" note pattern
    if transfer.expense_amount and transfer.expense_amount > 0:
        to_branch_name = transfer.to_branch.name if transfer.to_branch else ""
        orig_exp = db.scalar(
            select(CashEntry).where(CashEntry.branch_id == transfer.from_branch_id)
            .where(CashEntry.amount == transfer.expense_amount)
            .where(CashEntry.note.like(f"waybill - to {to_branch_name}%"))
            .order_by(CashEntry.created_at.desc())
        )
        if orig_exp:
            db.delete(orig_exp)
    # Reverse receive-side expense cash entry — find original by matching the "waybill - from" note pattern
    if transfer.receive_expense_amount and transfer.receive_expense_amount > 0:
        from_branch_name = transfer.from_branch.name if transfer.from_branch else ""
        orig_recv_exp = db.scalar(
            select(CashEntry).where(CashEntry.branch_id == transfer.to_branch_id)
            .where(CashEntry.amount == transfer.receive_expense_amount)
            .where(CashEntry.note.like(f"waybill - from {from_branch_name}%"))
            .order_by(CashEntry.created_at.desc())
        )
        if orig_recv_exp:
            db.delete(orig_recv_exp)
    transfer.status = "CANCELLED"
    transfer.cancelled_by_id = user.id
    transfer.cancelled_at = datetime.now(timezone.utc)
    db.commit()
    audit_log(db, user.id, "TRANSFER_CANCELLED", f"transfer_id={transfer_id}",
              ip=request.client.host if request.client else "")
    return redirect(f"/transfers/{transfer_id}?success=Transfer+cancelled+and+expenses+reversed")


# ────────────────────────────────────────────────
#  MERCHANT REMITTANCE
# ────────────────────────────────────────────────

def _merchant_remittance_query(db, sd, ed, bid):
    """Return per-delivery-item rows grouped by category for remittance report."""
    params = {"start": str(sd), "end": str(ed)}
    branch_clause = "AND d.branch_id = :bid" if bid else ""
    if bid:
        params["bid"] = bid
    return db.execute(text(f"""
        SELECT
            COALESCE(i.category, 'Uncategorized') AS category,
            d.id                                   AS delivery_id,
            d.customer_name                        AS customer_name,
            i.name                                 AS item_name,
            di.quantity                            AS qty,
            di.line_amount                         AS collection
        FROM delivery_items di
        JOIN deliveries d ON d.id = di.delivery_id
        JOIN items      i ON i.id = di.item_id
        WHERE d.status = 'DELIVERED'
          AND di.line_amount > 0
          AND DATE(COALESCE(d.delivered_at, d.created_at)) >= :start
          AND DATE(COALESCE(d.delivered_at, d.created_at)) <= :end
          {branch_clause}
        ORDER BY COALESCE(i.category, 'Uncategorized'), d.customer_name, d.id, i.name
    """), params).fetchall()


@router.get("/merchant-remittance", response_class=HTMLResponse)
def merchant_remittance_page(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all() if is_supervisor(user) else []
    today = date.today().isoformat()
    return tpl(request, "merchant_remittance.html", {
        "user": user, "branches": branches,
        "today": today, "active": "merchant_remittance",
    })


@router.get("/merchant-remittance/data", response_class=JSONResponse)
def merchant_remittance_data(
    request: Request,
    start_date: str = "",
    end_date: str = "",
    branch_id: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    sd = _parse_iso_date(start_date)
    ed = _parse_iso_date(end_date)
    if not sd or not ed:
        return JSONResponse({"error": "start_date and end_date are required"}, status_code=400)

    bid = user.branch_id if is_admin(user) else (branch_id or None)
    rows = _merchant_remittance_query(db, sd, ed, bid)

    # Build: category -> list of deliveries (one row per delivery, items merged)
    categories: dict = {}
    # delivery_map: (cat, delivery_id) -> delivery row dict
    delivery_map: dict = {}
    grand_qty = 0
    grand_total = 0.0

    for r in rows:
        cat = r.category
        did = r.delivery_id
        qty = int(r.qty or 0)
        amt = r.collection or 0

        if cat not in categories:
            categories[cat] = {"category": cat, "rows": [], "subtotal_qty": 0, "subtotal_collection": 0}

        key = (cat, did)
        if key not in delivery_map:
            delivery_map[key] = {
                "customer": r.customer_name or "—",
                "delivery_id": did,
                "items": [],
                "qty": 0,
                "collection": 0.0,
            }
            categories[cat]["rows"].append(delivery_map[key])

        delivery_map[key]["items"].append(f"{r.item_name} ×{qty}")
        delivery_map[key]["qty"] += qty
        delivery_map[key]["collection"] += amt
        categories[cat]["subtotal_qty"] += qty
        categories[cat]["subtotal_collection"] += amt
        grand_qty += qty
        grand_total += amt

    # Convert items list to string
    for d in delivery_map.values():
        d["items"] = ", ".join(d["items"])

    return JSONResponse({
        "categories": list(categories.values()),
        "grand_qty": grand_qty,
        "grand_total": round(grand_total, 2),
        "category_count": len(categories),
        "start_date": str(sd),
        "end_date": str(ed),
    })


@router.get("/merchant-remittance/csv")
def merchant_remittance_csv(
    request: Request,
    start_date: str = "",
    end_date: str = "",
    branch_id: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    from fastapi.responses import Response as _Resp
    import csv, io

    sd = _parse_iso_date(start_date) or date.today()
    ed = _parse_iso_date(end_date) or date.today()
    bid = user.branch_id if is_admin(user) else (branch_id or None)
    rows = _merchant_remittance_query(db, sd, ed, bid)

    # Merge rows into deliveries (one per delivery per category)
    delivery_map: dict = {}
    categories_order: list = []
    for r in rows:
        cat = r.category
        did = r.delivery_id
        key = (cat, did)
        if key not in delivery_map:
            delivery_map[key] = {
                "category": cat, "customer": r.customer_name or "—",
                "items": [], "qty": 0, "collection": 0,
            }
            categories_order.append(key)
        delivery_map[key]["items"].append(f"{r.item_name} x{int(r.qty or 0)}")
        delivery_map[key]["qty"] += int(r.qty or 0)
        delivery_map[key]["collection"] += r.collection or 0

    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["Category", "Customer", "Items", "Qty", "Collection (NGN)"])

    current_cat = None
    cat_qty = 0
    cat_amt = 0.0
    grand_qty = 0
    grand_total = 0.0

    for key in categories_order:
        d = delivery_map[key]
        cat = d["category"]
        if current_cat is not None and cat != current_cat:
            w.writerow(["", f"  {current_cat} SUBTOTAL", "", cat_qty, round(cat_amt, 2)])
            w.writerow([])
            cat_qty = 0; cat_amt = 0.0
        current_cat = cat
        w.writerow([cat, d["customer"], ", ".join(d["items"]), d["qty"], round(d["collection"], 2)])
        cat_qty += d["qty"]; cat_amt += d["collection"]
        grand_qty += d["qty"]; grand_total += d["collection"]

    if current_cat is not None:
        w.writerow(["", f"  {current_cat} SUBTOTAL", "", cat_qty, round(cat_amt, 2)])

    w.writerow([])
    w.writerow(["GRAND TOTAL", "", "", grand_qty, round(grand_total, 2)])

    filename = f"merchant_remittance_{sd}_{ed}.csv"
    return _Resp(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )



