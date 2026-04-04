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

router = APIRouter()

#  CASH
# ────────────────────────────────────────────────

@router.get("/cash", response_class=HTMLResponse)
def cash_dashboard(request: Request, preset: str = "", start_date: str = "", end_date: str = "", agent_id: str = "", db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
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
        return float(db.scalar(stmt) or 0)

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
        return {str(r.day): float(r.total) for r in db.execute(stmt).all()}

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
    total_return_op_cash = float(db.scalar(_ret_stmt) or 0)
    operating_balance = float(total_operating) - float(total_expenses) - total_return_op_cash
    remittance = float(total_collections) - float(total_expenses) - float(total_office_expenses)
    net_position = remittance + operating_balance
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())).scalars().all() if (is_admin(user) or is_supervisor(user)) else []

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
             "amount": float(e.amount), "note": e.note or "—",
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
    return tpl(request, "cash_dashboard.html", {
        "request": request, "user": user, "rows": rows,
        "total_collections": float(total_collections), "total_expenses": float(total_expenses),
        "total_operating_cash": float(total_operating), "total_return_op_cash": total_return_op_cash,
        "operating_balance": float(operating_balance), "total_office_expenses": float(total_office_expenses),
        "remittance": float(remittance), "net_position": float(net_position),
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
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
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
        op_given = float(db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == target_agent_id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind == "OPERATING_CASH")
        ) or 0)
        op_spent = float(db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == target_agent_id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind.in_(["EXPENSE", "COLLECTION_EXPENSE"]))
        ) or 0)
        op_returned = float(db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == target_agent_id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind == "RETURN_OPERATING_CASH")
        ) or 0)
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
               f"Admin has given you ₦{float(amt):,.0f} operating cash." + (f" Note: {(note or '').strip()}" if note else ""),
               "/cash", "success")
    db.commit()
    if d_id:
        return redirect(f"/deliveries/{d_id}")
    return redirect("/cash")


# ────────────────────────────────────────────────
#  REPORTS
# ────────────────────────────────────────────────

@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not (is_admin(user) or is_agent(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
    branch_id = get_selected_branch_id(request, user)
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).order_by(User.username.asc())).scalars().all() if (is_admin(user) or is_supervisor(user)) else []
    today = date.today().isoformat()
    return tpl(request, "reports_sales.html", {
        "request": request, "user": user, "agents": agents,
        "start_date": today, "end_date": today, "active": "reports",
    })


@router.get("/reports/preview")
def reports_preview(request: Request, start_date: str | None = None, end_date: str | None = None, agent_id: str | None = None, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    user = user_or
    if not (is_admin(user) or is_agent(user) or is_supervisor(user)):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
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
            q = float(qty or 0); la = float(line_amt or 0); sp = float(selling_price or 0)
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
    agent_exp_map = {int(aid): float(t) for aid, t in db.execute(
        select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind.in_(["EXPENSE", "COLLECTION_EXPENSE"]))
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
        .where(_agent_ce_filter if not is_supervisor(user) else True)
        .where(func.lower(func.coalesce(CashEntry.note, "")).notlike("%waybill%"))
        .group_by(CashEntry.agent_id)
    ).all()}
    # Separate collection-funded expenses per agent for report breakdown
    agent_coll_exp_map = {int(aid): float(t) for aid, t in db.execute(
        select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.kind == "COLLECTION_EXPENSE")
        .where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)
        .where(_ce_branch)
        .where(_agent_ce_filter if not is_supervisor(user) else True)
        .group_by(CashEntry.agent_id)
    ).all()}
    op_cash_map = {int(aid): float(t) for aid, t in db.execute(
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
    waybill_entries = [{"amount": float(r[0]), "note": str(r[1] or ""), "date": r[2].strftime("%d %b %Y") if r[2] else ""} for r in waybill_entries_raw]
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
    office_non_waybill = float(db.scalar(_off_stmt) or 0)
    office_total = office_non_waybill + waybill_total
    all_agent_ids = list(set(list(agent_exp_map.keys()) + list(op_cash_map.keys())))
    uname = {}
    if all_agent_ids:
        users_map = {int(u.id): u for u in db.execute(select(User).where(User.id.in_(all_agent_ids))).scalars().all()}
        uname = {uid: (u.full_name or u.username) for uid, u in users_map.items()}
    delivery_rows = []
    grand_total = 0.0
    for idx, d in enumerate(deliveries, 1):
        d_items = items_by_delivery.get(int(d.id), [])
        total = sum(i["amount"] for i in d_items)
        grand_total += total
        delivery_rows.append({"idx": idx, "customer": d.customer_name, "date": (d.delivery_date or d.created_at).strftime("%d %b %Y"), "items": d_items, "total": total})
    agent_op_summary = []
    total_op_cash_given = total_op_cash_balance_returned = expenses_from_collections = 0.0
    for aid in sorted(set(list(agent_exp_map.keys()) + list(op_cash_map.keys()))):
        exp       = agent_exp_map.get(aid, 0.0)
        coll_exp  = agent_coll_exp_map.get(aid, 0.0)
        op_exp    = exp - coll_exp   # expenses from operating cash only
        op        = op_cash_map.get(aid, 0.0)
        # Subtract confirmed returns from balance (agent already handed back cash)
        ret_confirmed = float(db.scalar(
            select(func.coalesce(func.sum(CashEntry.amount), 0))
            .where(CashEntry.agent_id == aid)
            .where(CashEntry.kind == "RETURN_OPERATING_CASH")
            .where(CashEntry.confirmed_by_admin == True)
            .where(CashEntry.created_at >= start_dt)
            .where(CashEntry.created_at <= end_dt)
        ) or 0)
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
def reports_txt(request: Request, start_date: str | None = None, end_date: str | None = None, agent_id: str | None = None, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return PlainTextResponse("Unauthorized", status_code=401)
    user = user_or
    if not (is_admin(user) or is_agent(user) or is_supervisor(user)):
        return PlainTextResponse("Forbidden", status_code=403)
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
            q = float(qty or 0); la = float(line_amt or 0)
            # Skip items removed by adjustment (line_amount == 0 means customer refused/returned)
            if la == 0 and q > 0:
                continue
            items_by_delivery.setdefault(int(did), []).append((str(iname), q, la))
    _ce_br = CashEntry.branch_id == branch_id if not is_supervisor(user) else True
    agent_exp_map = {int(aid): float(t) for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind.in_(["EXPENSE","COLLECTION_EXPENSE"])).where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(_ce_br).group_by(CashEntry.agent_id).order_by(CashEntry.agent_id.asc())).all()}
    agent_coll_exp_txt = {int(aid): float(t) for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "COLLECTION_EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(_ce_br).group_by(CashEntry.agent_id)).all()}
    op_cash_map = {int(aid): float(t) for aid, t in db.execute(select(CashEntry.agent_id, func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OPERATING_CASH").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).group_by(CashEntry.agent_id)).all()}
    office_total = float(db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OFFICE_EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt)) or 0)
    waybill_total = float(db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "OFFICE_EXPENSE").where(CashEntry.created_at >= start_dt).where(CashEntry.created_at <= end_dt).where(func.lower(func.coalesce(CashEntry.note, "")).like("%waybill%"))) or 0)
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
def merchant_receipt_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
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
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
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
    exp_amt = 0.0
    try:
        exp_amt = float(expense_amount) if expense_amount else 0.0
    except ValueError:
        exp_amt = 0.0
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
def merchant_return_form(request: Request, db: Session = Depends(get_db)):
    """Return goods back to a merchant — creates OUT transactions."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user): return HTMLResponse("Forbidden", status_code=403)
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
):
    """Record goods returned to merchant — OUT transaction per item."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user): return HTMLResponse("Forbidden", status_code=403)
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
    for item_id, qty in zip(item_ids, quantities):
        item = db.get(Item, item_id)
        if not item or item.branch_id != branch_id:
            return redirect("/merchant-return/new?error=Invalid+item+selected")
        db.add(Transaction(
            branch_id=branch_id, item_id=item_id,
            type="OUT", quantity=qty,
            reference=ref, note=full_note,
        ))
    # Record expense if provided
    exp_amt = 0.0
    try:
        exp_amt = float(expense_amount) if expense_amount else 0.0
    except ValueError:
        exp_amt = 0.0
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
def transfers_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
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
def transfer_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    branches = db.execute(select(Branch).where(Branch.id != user.branch_id).order_by(Branch.name)).scalars().all()
    items = get_items_with_stock(db, branch_id=user.branch_id)
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == user.branch_id).order_by(User.username)).scalars().all()
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
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
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
def transfer_detail(transfer_id: int, request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
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
    sender_agents   = db.execute(select(User).where(User.role=="AGENT").where(User.branch_id==transfer.from_branch_id).order_by(User.username)).scalars().all() if (is_admin(user) and user.branch_id==transfer.from_branch_id) else []
    receiver_agents = db.execute(select(User).where(User.role=="AGENT").where(User.branch_id==transfer.to_branch_id).order_by(User.username)).scalars().all()  if (is_admin(user) and user.branch_id==transfer.to_branch_id)   else []
    csrf_token = get_csrf_token(request)
    return tpl(request, "transfer_detail.html", {
        "request": request, "user": user, "transfer": transfer, "branches": branches,
        "delegated_agent": delegated_agent, "delegated_receiver": delegated_receiver,
        "packed_by": packed_by,
        "is_delegated": is_delegated, "is_delegated_receiver": is_delegated_receiver,
        "sender_agents": sender_agents, "receiver_agents": receiver_agents,
        "active": "transfers", "selected_branch_id": getattr(user, "branch_id", None),
        "csrf_token": csrf_token,
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
    })


@router.post("/transfers/{transfer_id}/receive")
async def transfer_receive(transfer_id: int, request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    is_recv_agent = is_agent(user)
    verify_csrf_token(request, csrf_token)
    transfer = db.get(StockTransfer, transfer_id)
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
    if not transfer.receive_expense_amount or float(transfer.receive_expense_amount) <= 0:
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
async def transfer_pack(transfer_id: int, request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    """Agent marks transfer as packed/ready to send."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
    transfer = db.get(StockTransfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404)
    # Only the delegated agent or admin can pack
    if not is_admin(user) and transfer.delegated_agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    if transfer.status != "PENDING":
        return redirect(f"/transfers/{transfer_id}?error=Transfer+is+not+pending")
    # Require expense to be recorded before marking as sent
    if not transfer.expense_amount or float(transfer.expense_amount) <= 0:
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
    db: Session = Depends(get_db),
):
    """Record expense against a transfer — agent or admin."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
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
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not is_admin(user): return HTMLResponse("Forbidden", status_code=403)
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
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
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
async def transfer_cancel(transfer_id: int, request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
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
    if transfer.expense_amount and float(transfer.expense_amount) > 0:
        to_branch_name = transfer.to_branch.name if transfer.to_branch else ""
        orig_exp = db.scalar(
            select(CashEntry).where(CashEntry.branch_id == transfer.from_branch_id)
            .where(CashEntry.amount == float(transfer.expense_amount))
            .where(CashEntry.note.like(f"waybill - to {to_branch_name}%"))
            .order_by(CashEntry.created_at.desc())
        )
        if orig_exp:
            db.delete(orig_exp)
    # Reverse receive-side expense cash entry — find original by matching the "waybill - from" note pattern
    if transfer.receive_expense_amount and float(transfer.receive_expense_amount) > 0:
        from_branch_name = transfer.from_branch.name if transfer.from_branch else ""
        orig_recv_exp = db.scalar(
            select(CashEntry).where(CashEntry.branch_id == transfer.to_branch_id)
            .where(CashEntry.amount == float(transfer.receive_expense_amount))
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
def merchant_remittance_page(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
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
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return JSONResponse({"error": "forbidden"}, status_code=403)

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
        amt = float(r.collection or 0)

        if cat not in categories:
            categories[cat] = {"category": cat, "rows": [], "subtotal_qty": 0, "subtotal_collection": 0.0}

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
):
    from fastapi.responses import Response as _Resp
    import csv, io
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)

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
                "items": [], "qty": 0, "collection": 0.0,
            }
            categories_order.append(key)
        delivery_map[key]["items"].append(f"{r.item_name} x{int(r.qty or 0)}")
        delivery_map[key]["qty"] += int(r.qty or 0)
        delivery_map[key]["collection"] += float(r.collection or 0)

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

from fastapi import Request
from app.whatsapp_service import send_whatsapp_fallback # Import the new service
from app.calling_service import _build_script

@router.post("/api/call-webhook")
async def call_webhook(request: Request, db: Session = Depends(get_db)):
    """Receives the end-of-call report from Vapi and updates the delivery notes."""
    _verify_webhook_token(request)
    try:
        payload = await request.json()
        message = payload.get("message", {})
        
        if message.get("type") != "end-of-call-report":
            return JSONResponse({"status": "ignored"})

        call_data = message.get("call", {})
        metadata = call_data.get("metadata", {})
        delivery_id = metadata.get("delivery_id")
        
        if not delivery_id:
            return JSONResponse({"error": "No delivery_id in metadata"}, status_code=400)

        summary = message.get("summary", "No summary provided by AI.")
        ended_reason = call_data.get("endedReason", "")

        d = db.get(Delivery, int(delivery_id))
        if d:
            existing_note = d.note or ""
            d.note = (existing_note + f"\n[AI Call Update]: {summary}").strip()
            
            # Trigger fallback logic if call failed
            if ended_reason in [
                "voicemail", "customer-hung-up", "customer-ended-call", 
                "customer-did-not-answer", "failed", "assistant-error", "customer-busy"
            ]:
                backup_numbers = metadata.get("backup_numbers", [])
                
                # Check if we have more numbers to try first
                if len(backup_numbers) > 0:
                    next_number = backup_numbers[0]
                    remaining_backups = backup_numbers[1:]
                    
                    d.note += f"\n[System]: Call to {call_data.get('customer', {}).get('number')} failed. Trying backup number: {next_number}..."
                    db.commit()
                    
                    # Launch the backup call using the metadata we saved
                    from app.calling_service import _do_call
                    task_queue.submit(
                        _do_call, d.id, next_number, remaining_backups,
                        metadata.get("status", "PENDING"),
                        metadata.get("customer_name", d.customer_name),
                        metadata.get("items", "your order"),
                        metadata.get("address", d.address or "")
                    )
                    
                else:
                    # No backups left! Send the WhatsApp message
                    try:
                        from .whatsapp_service import send_whatsapp_fallback
                        
                        # Fetch the item names for the WhatsApp message
                        items_query = db.execute(
                            select(Item.name, DeliveryItem.quantity)
                            .join(DeliveryItem, DeliveryItem.item_id == Item.id)
                            .where(DeliveryItem.delivery_id == d.id)
                        ).all()
                        items_str = ", ".join(f"{r.name} x{r.quantity}" for r in items_query) if items_query else "your order"

                        send_whatsapp_fallback(d.id, d.customer_phone, d.customer_name, items_str)
                        d.note += "\n[System]: All numbers failed. WhatsApp Fallback message triggered."
                    except Exception as wa_err:
                        import logging
                        logging.getLogger("webhook").error(f"WhatsApp fallback error: {wa_err}")

            db.commit()
            
            # Notify the assigned agent
            if d.agent_id:
                notify(db, d.agent_id, "📞 Customer Call Update",
                       f"The AI spoke to {d.customer_name}. Update: {summary}",
                       f"/deliveries/{d.id}", "warning")

        return JSONResponse({"status": "success"})
    except Exception as e:
        import logging
        logging.getLogger("webhook").error(f"Webhook error: {e}")
        return JSONResponse({"error": "Internal webhook processing error."}, status_code=500)


@router.post("/api/whatsapp-reply")
async def whatsapp_reply(request: Request, db: Session = Depends(get_db)):
    """Receives replies from customers via Twilio WhatsApp.
    Protected by Twilio's HMAC-SHA1 signature verification (uses TWILIO_AUTH_TOKEN).
    This endpoint is also listed in _ORIGIN_CHECK_EXEMPT in security.py.
    """
    form_data = await request.form()
    # [SEC-11] Verify Twilio signature — rejects forged requests
    verify_twilio_signature_with_params(request, dict(form_data))

    sender = form_data.get("From", "").replace("whatsapp:", "")
    body = form_data.get("Body", "").strip()
    
    # Find the most recent active delivery for this phone number
    # Twilio sends the number in E.164 format (+234...)
    d = db.execute(
        select(Delivery)
        .where(Delivery.customer_phone == sender)
        .where(Delivery.status.in_(["PENDING", "OUT_FOR_DELIVERY"]))
        .order_by(Delivery.created_at.desc())
    ).scalars().first()

    if d:
        existing_note = d.note or ""
        
        if body == "1":
            d.note = (existing_note + "\n[WhatsApp]: Customer confirmed available today.").strip()
            notify_msg = f"{d.customer_name} confirmed via WhatsApp they are available."
            
        elif body == "2":
            d.note = (existing_note + "\n[WhatsApp]: Customer requested reschedule for tomorrow.").strip()
            d.status = "FAILED"
            notify_msg = f"{d.customer_name} requested a reschedule via WhatsApp."
            
        else:
            d.note = (existing_note + f"\n[WhatsApp Reply]: {body}").strip()
            notify_msg = f"{d.customer_name} replied on WhatsApp: {body}"
            
        db.commit()
        
        # Notify the branch admin or assigned agent
        if d.agent_id:
            notify(db, d.agent_id, "💬 WhatsApp Reply", notify_msg, f"/deliveries/{d.id}", "info")
        else:
            notify_branch_admins(db, d.branch_id, "💬 WhatsApp Reply", notify_msg, f"/deliveries/{d.id}", "info")

    return PlainTextResponse("OK", status_code=200)

import httpx
import asyncio
from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

# ─────────────────────────────────────────────────────────────────
# SSE CONNECTION MANAGER
# Each delivery page that is open holds an asyncio.Queue here.
# When a new WA comment arrives we put an event into every queue.
# ─────────────────────────────────────────────────────────────────
_sse_queues: dict[int, list[asyncio.Queue]] = {}   # delivery_id → [queue, ...]

def _sse_broadcast(delivery_id: int, html_fragment: str):
    """Push an SSE event to all open browser tabs for this delivery."""
    for q in _sse_queues.get(delivery_id, []):
        try:
            q.put_nowait(html_fragment)
        except asyncio.QueueFull:
            pass

@router.get("/api/stream/{delivery_id}")
async def sse_stream(delivery_id: int, request: Request, db: Session = Depends(get_db)):
    """
    Server-Sent Events endpoint.  The delivery detail page connects here
    and receives new wa_comments HTML fragments in real time.
    """
    # [SEC] Require authentication — prevent unauthenticated data leaks
    user = get_current_user(db, request)
    if not user:
        return PlainTextResponse("Unauthorized", status_code=401)
    q: asyncio.Queue = asyncio.Queue(maxsize=50)
    _sse_queues.setdefault(delivery_id, []).append(q)

    async def generator():
        try:
            yield "retry: 5000\n\n"   # tell browser to reconnect after 5s
            while True:
                if await request.is_disconnected():
                    break
                try:
                    html = await asyncio.wait_for(q.get(), timeout=25)
                    yield f"event: wa_comment\ndata: {html}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"   # keep-alive comment
        finally:
            lst = _sse_queues.get(delivery_id, [])
            if q in lst:
                lst.remove(q)

    return StreamingResponse(generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─────────────────────────────────────────────────────────────────
# GEMINI MULTI-TURN CLASSIFICATION (runs in threadpool so it doesn't
# block the event loop — Gemini HTTP call can take 2-5s)
# ─────────────────────────────────────────────────────────────────
_GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")
_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

def _call_gemini_classify(thread: list[dict], latest_reply: str) -> dict:
    """
    Build a transcript of the last few messages and ask Gemini to classify
    the latest seller reply IN CONTEXT.  Returns a dict matching the schema:
    { "classification": str, "contextual_summary": str, "action_required": bool }
    """
    if not _GEMINI_KEY:
        return {"classification": "OTHER", "contextual_summary": latest_reply[:100], "action_required": False}

    transcript_lines = []
    for m in thread:
        direction = "Agent → Group" if m["direction"] == "outbound" else "Seller reply"
        transcript_lines.append(f"[{direction}]: {m['body']}")
    transcript = "\n".join(transcript_lines)

    prompt = (
        "You are a precise logistics coordinator AI. Below is a WhatsApp conversation thread "
        "between a delivery agent (sending updates to a seller group) and sellers replying.\n\n"
        f"THREAD:\n{transcript}\n\n"
        f"The latest seller reply is:\n\"{latest_reply}\"\n\n"
        "Evaluate the latest reply IN CONTEXT of the full thread and respond ONLY with valid JSON "
        "matching this exact schema (no markdown, no explanation):\n"
        '{"classification": "<QUESTION|COMPLAINT|CONFIRMED_AVAILABLE|RESCHEDULE_REQUEST|ADDRESS_CHANGE|RESOLVED|OTHER>", '
        '"contextual_summary": "<one sentence max 20 words explaining what the seller needs>", '
        '"action_required": <true|false>}'
    )

    try:
        resp = httpx.post(
            f"{_GEMINI_URL}?key={_GEMINI_KEY}",
            json={"contents": [{"role": "user", "parts": [{"text": prompt}]}],
                  "generationConfig": {"temperature": 0.1, "maxOutputTokens": 150}},
            timeout=10,
        )
        text_out = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        # Strip markdown fences if Gemini wraps anyway
        if text_out.startswith("```"):
            text_out = text_out.strip("`").lstrip("json").strip()
        return json.loads(text_out)
    except Exception as e:
        logging.getLogger("gemini").warning("Gemini classify failed: %s", e)
        return {"classification": "OTHER", "contextual_summary": latest_reply[:100], "action_required": False}


# ─────────────────────────────────────────────────────────────────
# AGENT FEEDBACK  (agent clicks a button → bot sends to group)
# ─────────────────────────────────────────────────────────────────
@router.post("/api/agent-feedback")
async def send_agent_feedback(
    request: Request,
    delivery_id: int = Form(...),
    issue_type: str = Form(...),
    custom_message: str = Form(""),
    group_name: str = Form(""),
    db: Session = Depends(get_db)
):
    # [SEC] Require login — prevent unauthenticated users from sending messages
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"status": "error", "message": "Not logged in"}, status_code=401)

    delivery = db.execute(select(Delivery).where(Delivery.id == delivery_id)).scalar_one_or_none()
    if not delivery:
        return JSONResponse({"status": "error", "message": "Delivery not found"}, status_code=404)

    update_templates = {
        "OUT_FOR_DELIVERY": f"🚚 *Update: Out for Delivery*\nOrder #{delivery.id} - {delivery.customer_name}\nYour order is on its way and will be delivered shortly.",
        "CALLED_CUSTOMER":  f"📞 *Update: Customer Called*\nOrder #{delivery.id} - {delivery.customer_name}\nOur agent has called the customer to confirm delivery.",
        "NOT_PICKING":      f"📵 *Update: Customer Not Reachable*\nOrder #{delivery.id} - {delivery.customer_name}\nWe are unable to reach the customer. Please advise.",
        "DELIVERED":        f"✅ *Update: Delivered*\nOrder #{delivery.id} - {delivery.customer_name}\nOrder has been successfully delivered. Thank you!",
    }
    if issue_type == "CUSTOM" and custom_message.strip():
        message = f"💬 *Note from Agent*\nOrder #{delivery.id} - {delivery.customer_name}\n{custom_message.strip()}"
    else:
        message = update_templates.get(
            issue_type,
            f"📣 *Update*\nOrder #{delivery.id} - {delivery.customer_name}\n{issue_type}"
        )

    # Always quote the ORIGINAL group order post (source='group'), not a bot update.
    # This anchors the reply thread to the seller's original message in the group,
    # making it obvious which order is being discussed regardless of how many updates
    # the agent has sent.
    # 1. Safely read from the database using index numbers to prevent crashes
    orig_map = db.execute(text(
        "SELECT message_id, body, sender, group_jid FROM whatsapp_outbound_map "
        "WHERE order_id = :oid AND source = 'group' ORDER BY created_at ASC LIMIT 1"
    ), {"oid": delivery.id}).first()

    if orig_map:
        quote_id     = orig_map[0]
        quote_body   = orig_map[1]
        quote_sender = orig_map[2]
        fallback_grp = orig_map[3] # <--- Extracts the group_jid safely
    else:
        quote_id = quote_body = quote_sender = fallback_grp = None

    # 2. GROUP ROUTING — trust the ACTUAL group the seller posted in first.
    # Only fall back to category-based guessing if we don't have the original group.
    _default_cgm = {
        "DAGGO":   "120363418850903362@g.us",
        "NEXTILE": "120363304493232977@g.us",
        "NEWLIFE": "120363287198677451@g.us",
        "LOCO":    "120363239510350827@g.us"
    }
    try:
        CATEGORY_GROUP_MAP = json.loads(os.getenv("CATEGORY_GROUP_MAP", "")) or _default_cgm
    except (ValueError, TypeError):
        CATEGORY_GROUP_MAP = _default_cgm

    if fallback_grp:
        # We KNOW which group the seller originally posted in — use that.
        target_group = fallback_grp
    else:
        # No original group saved — fall back to category lookup
        delivery_category = db.execute(
            select(Item.category)
            .join(DeliveryItem, DeliveryItem.item_id == Item.id)
            .where(DeliveryItem.delivery_id == delivery.id)
            .limit(1)
        ).scalar()
        target_group = CATEGORY_GROUP_MAP.get(delivery_category, "") if delivery_category else ""

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                os.getenv("WHATSAPP_BOT_URL", "http://adventurous-flow.railway.internal:3000") + "/send-group-feedback",
                json={
                    "orderId":            str(delivery.id),
                    "message":            message,
                    "quoteMessageId":     quote_id,
                    "quoteMessageBody":   quote_body,
                    "quoteMessageSender": quote_sender,
                    "quoteMessageFromMe": False,
                    "targetGroupJid":     target_group,
                },
                timeout=60,
            )
            data = resp.json()

        if not data.get("success"):
            return JSONResponse({"status": "error", "message": data.get("error", "Bot error")})

        # Persist the new Baileys message_id so future sends can quote it,
        # and inbound replies can be routed back to this order in O(1).
        new_msg_id = data.get("message_id", "")
        is_sqlite = DATABASE_URL.startswith("sqlite")
        if new_msg_id:
            if is_sqlite:
                upsert_sql = (
                    "INSERT OR REPLACE INTO whatsapp_outbound_map (message_id, order_id, body, source, sender, group_jid, created_at) "
                    "VALUES (:mid, :oid, :body, 'bot', '', :gjid, :_now)"
                )
            else:
                upsert_sql = (
                    "INSERT INTO whatsapp_outbound_map (message_id, order_id, body, source, sender, group_jid, created_at) "
                    "VALUES (:mid, :oid, :body, 'bot', '', :gjid, :_now) "
                    "ON CONFLICT (message_id) DO UPDATE SET order_id=EXCLUDED.order_id, body=EXCLUDED.body, source=EXCLUDED.source, sender=EXCLUDED.sender, group_jid=EXCLUDED.group_jid"
                )
            db.execute(text(upsert_sql), {"mid": new_msg_id, "oid": delivery.id, "body": message, "gjid": target_group, "_now": _now()})
            db.commit()

        # Save outbound comment for the chat thread UI
        db.execute(text(
            "INSERT INTO wa_comments (delivery_id, direction, sender, body, created_at) "
            "VALUES (:did, 'outbound', 'Agent', :body, :_now)"
        ), {"did": delivery.id, "body": message, "_now": _now()})
        db.commit()

        # SSE broadcast so open tabs update immediately
        now_str  = datetime.now(timezone.utc).strftime("%d %b %H:%M")
        _sse_msg = html.escape(message)
        fragment = (
            f'<div style="display:flex;gap:10px;align-items:flex-start;flex-direction:row-reverse;">'
            f'<div style="width:28px;height:28px;border-radius:50%;background:rgba(79,124,255,.2);'
            f'display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0;">🤖</div>'
            f'<div style="max-width:80%;background:rgba(79,124,255,.08);border:1px solid rgba(255,255,255,.07);'
            f'border-radius:10px;padding:8px 12px;">'
            f'<div style="font-size:10px;color:#8a9bc4;margin-bottom:4px;font-family:monospace;">Agent → Group · {now_str}</div>'
            f'<div style="font-size:13px;white-space:pre-wrap;">{_sse_msg}</div>'
            f'</div></div>'
        )
        _sse_broadcast(delivery.id, fragment)

        return JSONResponse({"status": "success", "message": "Feedback sent to group!"})

    except Exception as e:
        return JSONResponse({"status": "error", "message": f"Clawbot is offline: {str(e)}"})


# ─────────────────────────────────────────────────────────────────
# WHATSAPP WEBHOOK  (bot posts inbound seller replies here)
# ─────────────────────────────────────────────────────────────────
@router.post("/api/whatsapp-webhook")
async def whatsapp_webhook(request: Request, db: Session = Depends(get_db)):
    _verify_webhook_token(request)
    data                = await request.json()
    quoted_msg_id       = data.get("quoted_message_id", "").strip()
    quoted_msg_body     = data.get("quoted_message_body", "").strip()
    reply_text          = data.get("reply_text", "").strip()
    sender              = data.get("sender_phone", "")
    group_jid           = data.get("groupJid", "").strip()

    if not reply_text:
        return {"status": "ignored"}

    _log = logging.getLogger("wa_webhook")

    import re
    order_id = None

    # ── Step 0: Direct Regex Match (100% Bulletproof) ─────────────────
    # Check if the seller typed "Order 123" or quoted a bot message saying "Order #123"
    combined_text = f"{reply_text} {quoted_msg_body}"
    direct_match = re.search(r'order\s*#?\s*(\d+)', combined_text, re.IGNORECASE)
    if direct_match:
        extracted_id = int(direct_match.group(1))
        valid = db.execute(text("SELECT id FROM deliveries WHERE id = :oid"), {"oid": extracted_id}).first()
        if valid:
            order_id = extracted_id
            _log.info("Matched by explicit text regex → Order #%s", order_id)

    # ── Step 1: O(1) lookup by quoted message ID ──────────────────────
    if not order_id and quoted_msg_id:
        row = db.execute(text(
            "SELECT order_id FROM whatsapp_outbound_map WHERE message_id = :mid"
        ), {"mid": quoted_msg_id}).first()
        if row:
            order_id = row[0]
            _log.info("Matched by message_id → Order #%s", order_id)

    # ── Step 2: Fallback — strict phone match ─────────────────────────
    if not order_id and quoted_msg_body:
        _log.info("ID lookup missed — trying strict phone match on quoted body")
        phone_m = re.search(r'(?:\+?234|0)[789]\d[\s\-]?\d{3,4}[\s\-]?\d{3,4}', quoted_msg_body)
        qphone  = phone_m.group(0).replace(' ', '').replace('-', '') if phone_m else ''
        qphone_digits = qphone.replace('+234', '0')[-10:] if qphone else ''

        if qphone_digits:
            # Also try to extract a name from the quoted body for stricter matching
            # Typical format: "Customer Name\nPhone: 080...\nItems: ..."
            qname_lines = [ln.strip() for ln in quoted_msg_body.split('\n') if ln.strip()]
            q_name = ""
            _SKIP_RE = re.compile(r'^(phone|address|item|product|qty|quantity|note|location|area|delivery|order|price|amount|date|status)', re.IGNORECASE)
            for ln in qname_lines:
                if _SKIP_RE.match(ln) or re.match(r'^[\d\+\(]', ln):
                    continue
                name_words = [w for w in ln.split() if re.match(r'^[A-Za-z\'-]{2,}$', w)]
                if len(name_words) >= 2:
                    q_name = ln.strip().lower()
                    break

            candidates = db.execute(text(
                "SELECT id, customer_phone, customer_name FROM deliveries "
                "WHERE status IN ('PENDING','OUT_FOR_DELIVERY') ORDER BY id DESC LIMIT 200"
            )).fetchall()

            # Prefer: same-group > phone+name > phone-only
            same_group_match = None
            phone_and_name_match = None
            phone_only_match = None
            for c in candidates:
                c_id, c_phone, c_name = c[0], c[1], c[2]
                db_phone = (c_phone or '').replace(' ', '').replace('-', '')[-10:]
                if not (db_phone and qphone_digits == db_phone):
                    continue

                # Check name match if we extracted one from the quoted body
                c_name_lower = (c_name or '').lower()
                name_match = False
                if q_name and c_name_lower:
                    q_words = [w for w in q_name.split() if len(w) > 2]
                    if len(q_words) >= 2 and all(w in c_name_lower for w in q_words):
                        name_match = True
                    elif q_name == c_name_lower:
                        name_match = True

                # Same-group is highest priority
                if group_jid:
                    grp_row = db.execute(text(
                        "SELECT 1 FROM whatsapp_outbound_map WHERE order_id = :oid AND group_jid = :gjid LIMIT 1"
                    ), {"oid": c_id, "gjid": group_jid}).first()
                    if grp_row:
                        same_group_match = c_id
                        break

                if q_name and name_match and not phone_and_name_match:
                    phone_and_name_match = c_id
                if not phone_only_match:
                    phone_only_match = c_id

            order_id = same_group_match or phone_and_name_match or phone_only_match
            if order_id:
                _log.info("Matched by phone in quoted body → Order #%s (same_group=%s)", order_id, bool(same_group_match))
                if quoted_msg_id:
                    conflict = "ON CONFLICT (message_id) DO NOTHING" if not DATABASE_URL.startswith("sqlite") else ""
                    try:
                        db.execute(text(
                            f"INSERT INTO whatsapp_outbound_map (message_id, order_id, body, source, group_jid, created_at) "
                            f"VALUES (:mid, :oid, :body, 'group', :gjid, :_now) {conflict}"
                        ), {"mid": quoted_msg_id, "oid": order_id, "body": quoted_msg_body, "gjid": group_jid, "_now": _now()})
                        db.commit()
                    except Exception:
                        pass

    if not order_id:
        _log.warning("Could not match reply to any delivery — quoted_id=%s", quoted_msg_id)
        return {"status": "unmatched"}

    delivery = db.execute(select(Delivery).where(Delivery.id == order_id)).scalar_one_or_none()
    if not delivery:
        return {"status": "not_found"}

    # Fetch last 8 messages for multi-turn Gemini context
    thread_rows = db.execute(text(
        "SELECT direction, body FROM wa_comments "
        "WHERE delivery_id = :did ORDER BY created_at DESC LIMIT 8"
    ), {"did": order_id}).fetchall()
    thread = [{"direction": r[0], "body": r[1]} for r in reversed(thread_rows)]

    # Classify in a thread so we don't block the event loop
    loop = asyncio.get_event_loop()
    ai   = await loop.run_in_executor(None, _call_gemini_classify, thread, reply_text)
    classification_json = json.dumps(ai)

    # Render comment body: show AI summary prominently, raw text below
    label   = ai.get("classification", "OTHER")
    summary = ai.get("contextual_summary", reply_text[:100])
    
    # Add the quoted message so the agent knows what the seller is replying to
    quote_context = f"\n\nReplying to:\n> {quoted_msg_body}" if quoted_msg_body else ""
    comment_body = f"[{label}] {summary}{quote_context}\n\nSeller said: \"{reply_text}\""

    db.execute(text(
        "INSERT INTO wa_comments (delivery_id, direction, sender, body, classification, created_at) "
        "VALUES (:did, 'inbound', :sender, :body, :clf, :_now)"
    ), {"did": order_id, "sender": sender, "body": comment_body, "clf": classification_json, "_now": _now()})
    db.commit()

    # SSE — push fragment to any open delivery detail tabs
    now_str  = datetime.now(timezone.utc).strftime("%d %b %H:%M")
    action_badge = ' <span style="color:#f59e0b;font-size:10px;">⚠ ACTION NEEDED</span>' if ai.get("action_required") else ""
    _sse_sender = html.escape(sender or "Seller")
    _sse_body   = html.escape(comment_body)
    fragment = (
        f'<div style="display:flex;gap:10px;align-items:flex-start;">'
        f'<div style="width:28px;height:28px;border-radius:50%;background:rgba(34,197,94,.15);'
        f'display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0;">💬</div>'
        f'<div style="max-width:80%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);'
        f'border-radius:10px;padding:8px 12px;">'
        f'<div style="font-size:10px;color:#8a9bc4;margin-bottom:4px;font-family:monospace;">'
        f'{_sse_sender} → You · {now_str}{action_badge}</div>'
        f'<div style="font-size:13px;white-space:pre-wrap;">{_sse_body}</div>'
        f'</div></div>'
    )
    _sse_broadcast(order_id, fragment)

    # Persistent notifications (bell + web push)
    notif_title = f"💬 Seller Reply — Order #{order_id}"
    notif_msg   = f"{sender or 'Seller'}: {summary}"
    notif_link  = f"/deliveries/{order_id}"
    if delivery.agent_id:
        notify(db, delivery.agent_id, notif_title, notif_msg, notif_link, "info")
    admin_ids = db.execute(text("SELECT id FROM users WHERE role='ADMIN'")).scalars().all()
    for aid in admin_ids:
        if aid != delivery.agent_id:
            notify(db, aid, notif_title, notif_msg, notif_link, "info")

    return {"status": "received", "order_id": order_id, "classification": label}


@router.post("/api/cache-wa-message")
async def cache_wa_message(request: Request, db: Session = Depends(get_db)):
    """
    Called by the bot for every non-reply group message.
    The bot uses Gemini to extract customer_name and customer_phone from the text.
    Python fuzzy-matches those against its delivery records to find the order_id.
    Stores (message_id → order_id, source='group') so agent-feedback can always
    quote the ORIGINAL group post when sending updates.
    """
    _verify_webhook_token(request)
    data           = await request.json()
    message_id     = (data.get("message_id") or "").strip()
    body           = (data.get("body") or "").strip()
    sender         = (data.get("sender") or "").strip()
    group_jid      = (data.get("groupJid") or "").strip()
    customer_name  = (data.get("customer_name") or "").strip().lower()
    customer_phone = (data.get("customer_phone") or "").strip().replace(" ", "")

    if not message_id or (not customer_name and not customer_phone):
        return {"status": "ignored"}

    # Fuzzy match against recent PENDING/OUT_FOR_DELIVERY deliveries only
    candidates = db.execute(text(
        "SELECT id, customer_name, customer_phone FROM deliveries "
        "WHERE status IN ('PENDING','OUT_FOR_DELIVERY') "
        "ORDER BY created_at DESC LIMIT 200"
    )).fetchall()

    matched_order_id = None
    for row in candidates:
        r_id, r_name, r_phone = row[0], row[1], row[2]
        db_name  = (r_name or "").lower()
        db_phone = (r_phone or "").replace(" ", "").replace("-", "")

        # 🛡️ THE ANTI-STEAL SAFEGUARD: 
        # If this order ALREADY has an original group message linked to it, DO NOT steal it.
        has_group_msg = db.execute(text(
            "SELECT 1 FROM whatsapp_outbound_map WHERE order_id = :oid AND source = 'group'"
        ), {"oid": r_id}).first()
        if has_group_msg:
            continue

        # Match logic: use BOTH phone+name when both are available to avoid
        # conflicts when the same phone number appears on multiple orders.
        phone_ok = False
        if customer_phone and db_phone and len(customer_phone) >= 10:
            phone_ok = (customer_phone[-10:] == db_phone[-10:])

        name_ok = False
        if customer_name and db_name and len(customer_name) > 3:
            words = [w for w in customer_name.split() if len(w) > 2]
            if len(words) >= 2 and all(w in db_name for w in words):
                name_ok = True
            elif customer_name == db_name:
                name_ok = True

        # When we have BOTH phone and name from WhatsApp → require both to match
        if customer_phone and customer_name:
            if phone_ok and name_ok:
                matched_order_id = r_id
                break
        # Only phone available → phone-only is fine
        elif customer_phone:
            if phone_ok:
                matched_order_id = r_id
                break
        # Only name available → name-only is fine
        elif customer_name:
            if name_ok:
                matched_order_id = r_id
                break

    if not matched_order_id:
        logging.getLogger("cache_wa").info(
            "cache-wa-message: no delivery matched name='%s' phone='%s' — saving to pending cache", customer_name, customer_phone
        )
        # Save to pending cache so it can be matched when the delivery IS created
        _pend_conflict = "ON CONFLICT (message_id) DO NOTHING" if not DATABASE_URL.startswith("sqlite") else "OR IGNORE"
        try:
            db.execute(text(
                f"INSERT {_pend_conflict} INTO wa_pending_cache "
                f"(message_id, body, sender, group_jid, customer_name, customer_phone, created_at) "
                f"VALUES (:mid, :body, :sender, :gjid, :cname, :cphone, :_now)"
            ), {"mid": message_id, "body": body, "sender": sender, "gjid": group_jid,
                "cname": customer_name, "cphone": customer_phone, "_now": _now()})
            db.commit()
        except Exception:
            db.rollback()
        return {"status": "pending"}

    # ── Persist the mapping so replies and agent-feedback can find this order ──
    is_sqlite = DATABASE_URL.startswith("sqlite")
    if is_sqlite:
        upsert_sql = (
            "INSERT OR REPLACE INTO whatsapp_outbound_map "
            "(message_id, order_id, body, source, sender, group_jid, created_at) "
            "VALUES (:mid, :oid, :body, 'group', :sender, :gjid, :_now)"
        )
    else:
        upsert_sql = (
            "INSERT INTO whatsapp_outbound_map "
            "(message_id, order_id, body, source, sender, group_jid, created_at) "
            "VALUES (:mid, :oid, :body, 'group', :sender, :gjid, :_now) "
            "ON CONFLICT (message_id) DO UPDATE SET order_id=EXCLUDED.order_id, "
            "body=EXCLUDED.body, source=EXCLUDED.source, sender=EXCLUDED.sender, group_jid=EXCLUDED.group_jid"
        )
    try:
        db.execute(text(upsert_sql), {
            "mid": message_id, "oid": matched_order_id,
            "body": body, "sender": sender, "gjid": group_jid, "_now": _now()
        })
        db.commit()
        logging.getLogger("cache_wa").info(
            "cache-wa-message: saved message_id=%s → Order #%s (group=%s)",
            message_id[:20], matched_order_id, group_jid[:20] if group_jid else ""
        )
    except Exception as e:
        logging.getLogger("cache_wa").error("cache-wa-message: failed to save mapping: %s", e)
        db.rollback()

    return {"status": "matched", "order_id": matched_order_id}