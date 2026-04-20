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

# ────────────────────────────────────────────────
#  PROFILE PICTURE ENDPOINTS
# ────────────────────────────────────────────────

# Default avatar SVG — a nice person silhouette
_DEFAULT_AVATAR_SVG = b'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400">
<rect width="400" height="400" rx="200" fill="#1e2a4a"/>
<circle cx="200" cy="155" r="72" fill="#3b5998"/>
<ellipse cx="200" cy="340" rx="120" ry="100" fill="#3b5998"/>
</svg>'''


@router.get("/users/{user_id}/avatar")
def user_avatar(user_id: int, db: Session = Depends(get_db)):
    """Serve a user's profile picture, or a default SVG placeholder."""
    from sqlalchemy.orm import undefer
    u = db.execute(
        select(User).where(User.id == user_id).options(undefer(User.profile_picture))
    ).scalar()
    if u and u.profile_picture:
        return Response(
            content=u.profile_picture,
            media_type=u.profile_picture_mime or "image/jpeg",
            headers={"Cache-Control": "public, max-age=3600"},
        )
    return Response(
        content=_DEFAULT_AVATAR_SVG,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@router.post("/profile/upload-picture")
async def upload_profile_picture(
    request: Request,
    file: UploadFile = File(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_active_user),
):
    """Upload and auto-resize a profile picture for the currently logged-in user."""
    verify_csrf_token(request, csrf_token)

    file_bytes = await file.read()
    validate_image_upload(file.filename or "", file_bytes)

    # Auto-resize and compress (even a 10MB photo becomes ~50-100KB)
    compressed_bytes, mime_type = process_profile_image(file_bytes)

    from sqlalchemy.orm import undefer
    u = db.execute(
        select(User).where(User.id == user.id).options(undefer(User.profile_picture))
    ).scalar()
    u.profile_picture = compressed_bytes
    u.profile_picture_mime = mime_type
    db.commit()

    # Redirect back to wherever they came from
    referer = request.headers.get("referer", "/")
    return redirect(referer.split("?")[0] + "?success=Profile+picture+updated")


@router.post("/agents/{agent_id}/remove-picture")
async def remove_agent_picture(
    request: Request,
    agent_id: int,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    """Admin/supervisor removes a user's profile picture."""
    verify_csrf_token(request, csrf_token)

    from sqlalchemy.orm import undefer
    target = db.execute(
        select(User).where(User.id == agent_id).options(undefer(User.profile_picture))
    ).scalar()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.profile_picture = None
    target.profile_picture_mime = None
    db.commit()
    return redirect(f"/agents/{agent_id}?success=Profile+picture+removed")


@router.post("/agents/{agent_id}/edit-profile")
async def edit_agent_profile(
    request: Request,
    agent_id: int,
    username: str = Form(""),
    full_name: str = Form(""),
    phone: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    """Admin/supervisor edits an agent/admin's name and phone."""
    verify_csrf_token(request, csrf_token)

    target = db.get(User, agent_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # Admin can only edit agents in their own branch
    if is_admin(user) and not is_supervisor(user):
        if target.branch_id != user.branch_id:
            return HTMLResponse("Forbidden", status_code=403)
        if target.role != "AGENT":
            return HTMLResponse("Forbidden — admins can only edit agent profiles", status_code=403)

    # Username change — validate uniqueness
    new_username = sanitize_username(username)
    if new_username != target.username:
        existing = db.scalar(select(User).where(User.username == new_username))
        if existing:
            return redirect(f"/agents/{agent_id}?error=Username+'{new_username}'+is+already+taken")
        old_username = target.username
        # Record the change permanently so historical records can be traced
        db.execute(text(
            "INSERT INTO username_history (user_id, old_username, new_username, changed_by, changed_at) "
            "VALUES (:uid, :old, :new, :by, :now)"
        ), {"uid": agent_id, "old": old_username, "new": new_username, "by": user.id, "now": _now()})
        target.username = new_username
    else:
        old_username = target.username

    target.full_name = sanitize_text(full_name, 140, "Full name") or None
    target.phone = sanitize_phone(phone) or None
    db.commit()
    audit_log(db, user.id, "PROFILE_EDITED", f"user_id={agent_id} username={target.username} name={target.full_name} phone={target.phone}",
              ip=request.client.host if request.client else "")
    return redirect(f"/agents/{agent_id}?success=Profile+updated+successfully")


#  AGENTS
# ────────────────────────────────────────────────

@router.get("/agents", response_class=HTMLResponse)
def agents_list(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    branch_id = get_selected_branch_id(request, user)
    if is_supervisor(user):
        # Supervisor sees all admins across all branches (including deactivated)
        agents = db.execute(
            select(User).where(User.role == "ADMIN")
            .order_by(User.is_active.desc(), User.username.asc()).limit(500)
        ).scalars().all()
    else:
        # Admin sees all agents in their branch (including deactivated)
        agents = db.execute(
            select(User).where(User.role == "AGENT").where(User.branch_id == branch_id)
            .order_by(User.is_active.desc(), User.username.asc()).limit(500)
        ).scalars().all()
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    return tpl(request, "agents_list.html", {
        "request": request, "agents": agents, "user": user,
        "branches": branches, "selected_branch_id": branch_id,
    })


@router.get("/agents/new", response_class=HTMLResponse)
def agent_new_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    csrf_token = get_csrf_token(request)
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    return tpl(request, "agent_new.html", {
        "request": request, "user": user,
        "error": request.query_params.get("error"),
        "active": "agents", "csrf_token": csrf_token,
        "branches": branches,
    })


@router.post("/agents/new")
async def agent_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(""),
    phone: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    verify_csrf_token(request, csrf_token)
    uname = sanitize_username(username)
    if not uname:
        return redirect("/agents/new?error=Username+is+required")
    if db.scalar(select(User).where(User.username == uname)):
        return redirect("/agents/new?error=Username+already+exists")
    if len(password or "") < 8:
        return redirect("/agents/new?error=Password+must+be+at+least+8+characters")
    # Supervisor picks branch and role from form; admin uses their own branch
    if is_supervisor(user):
        form_data = await request.form()
        selected_role = (form_data.get("role", "ADMIN") or "ADMIN").upper()
        if selected_role not in ("ADMIN", "SUPERVISOR"):
            selected_role = "ADMIN"
        if selected_role == "SUPERVISOR":
            assigned_branch_id = None
        else:
            branch_id_val = form_data.get("branch_id", "")
            if not branch_id_val or not str(branch_id_val).isdigit():
                return redirect("/agents/new?error=Please+select+a+branch")
            assigned_branch_id = int(branch_id_val)
    else:
        selected_role = "AGENT"
        if not user.branch_id:
            return redirect("/agents/new?error=Admin+has+no+branch+assigned")
        assigned_branch_id = user.branch_id
    db.add(User(
        username=uname, password_hash=hash_password(password),
        role=selected_role,
        branch_id=assigned_branch_id,
        full_name=sanitize_text(full_name, 140, "Full name") or None,
        phone=sanitize_phone(phone) or None,
    ))
    db.commit()
    return redirect("/agents")


@router.get("/agents/{agent_id}", response_class=HTMLResponse)
def agent_detail(request: Request, preset: str = "", start_date: str = "", end_date: str = "", db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")), agent: User = Depends(get_authorized_agent)):

    sd, ed, preset_norm, start_dt, end_dt = _dt_range_from_dates(preset, start_date, end_date)

    is_admin_profile = (agent.role or "").upper() == "ADMIN"

    if is_admin_profile and agent.branch_id:
        # For admin profiles: show branch-level summary via direct queries
        branch_id_for_admin = agent.branch_id

        def _branch_sum(kind_list):
            stmt = select(func.coalesce(func.sum(CashEntry.amount), 0)).where(
                CashEntry.kind.in_(kind_list)).where(CashEntry.branch_id == branch_id_for_admin)
            if start_dt: stmt = stmt.where(CashEntry.created_at >= start_dt)
            if end_dt: stmt = stmt.where(CashEntry.created_at < end_dt)
            return db.scalar(stmt) or 0

        total_collections   = _branch_sum(["COLLECTION", "CASH_PAYMENT", "TRANSFER_PAYMENT"])
        total_expenses      = _branch_sum(["EXPENSE"])
        total_operating     = _branch_sum(["OPERATING_CASH"])
        total_office_expenses = _branch_sum(["OFFICE_EXPENSE"])
        total_return_op_cash  = _branch_sum(["RETURN_OPERATING_CASH"])
        operating_balance   = total_operating - total_expenses - total_return_op_cash
        remittance          = total_collections - total_office_expenses
        net_position        = remittance + operating_balance
        rows = []  # no per-day rows for branch summary

        _eff_a = func.coalesce(Delivery.delivered_at, Delivery.delivery_date, Delivery.created_at)
        d_stmt = select(Delivery).where(Delivery.branch_id == branch_id_for_admin).order_by(desc(_eff_a)).limit(300)
        if start_dt: d_stmt = d_stmt.where(_eff_a >= start_dt)
        if end_dt: d_stmt = d_stmt.where(_eff_a < end_dt)
        deliveries = db.execute(d_stmt).scalars().all()
        branch_agents = db.execute(
            select(User).where(User.role == "AGENT").where(User.branch_id == branch_id_for_admin)
            .where(User.is_active == True).order_by(User.username.asc())
        ).scalars().all()
    else:
        is_admin_profile = False
        branch_agents = []
        rows, total_collections, total_expenses, total_operating, total_office_expenses = get_cash_summary(db=db, agent_id=agent_id, start=start_dt, end=end_dt)
        _ret_stmt = select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.kind == "RETURN_OPERATING_CASH").where(CashEntry.agent_id == agent_id)
        if start_dt: _ret_stmt = _ret_stmt.where(CashEntry.created_at >= start_dt)
        if end_dt: _ret_stmt = _ret_stmt.where(CashEntry.created_at < end_dt)
        total_return_op_cash = db.scalar(_ret_stmt) or 0
        operating_balance = total_operating - total_expenses - total_return_op_cash
        remittance = total_collections - total_office_expenses
        net_position = remittance + operating_balance
        _eff = func.coalesce(Delivery.delivered_at, Delivery.delivery_date, Delivery.created_at)
        d_stmt = select(Delivery).where(Delivery.agent_id == agent_id).order_by(desc(_eff)).limit(300)
        if start_dt: d_stmt = d_stmt.where(_eff >= start_dt)
        if end_dt: d_stmt = d_stmt.where(_eff < end_dt)
        deliveries = db.execute(d_stmt).scalars().all()

    delivery_ids = [d.id for d in deliveries]
    items_summary: dict[int, str] = {}
    if delivery_ids:
        # Exclude phantom delivery_items that exist only for vetting (have a stock_return_vettings record)
        _phantom_ids = set(db.scalars(
            select(StockReturnVetting.delivery_item_id)
            .where(StockReturnVetting.delivery_id.in_(delivery_ids))
            .distinct()
        ).all())
        lines = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity, DeliveryItem.id)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        grouped: dict[int, list[str]] = {}
        for did, iname, qty, di_id in lines:
            if di_id in _phantom_ids:
                continue
            grouped.setdefault(int(did), []).append(f"{iname} ×{int(qty)}")
        items_summary = {did: ", ".join(parts) for did, parts in grouped.items()}
    cash_stmt = select(CashEntry).where(CashEntry.branch_id == agent.branch_id).order_by(desc(CashEntry.created_at))
    if start_dt: cash_stmt = cash_stmt.where(CashEntry.created_at >= start_dt)
    if end_dt: cash_stmt = cash_stmt.where(CashEntry.created_at < end_dt)
    cash_stmt = cash_stmt.where((CashEntry.agent_id == agent_id) | (CashEntry.kind == "OFFICE_EXPENSE"))
    cash_entries = db.execute(cash_stmt.limit(300)).scalars().all()

    csrf_token = get_csrf_token(request)
    # Load username change history for this account
    username_history = db.execute(text(
        "SELECT uh.old_username, uh.new_username, uh.changed_at, u.username as changed_by_name "
        "FROM username_history uh LEFT JOIN users u ON u.id = uh.changed_by "
        "WHERE uh.user_id = :uid ORDER BY uh.changed_at DESC LIMIT 50"
    ), {"uid": agent_id}).fetchall()
    return tpl(request, "agent_detail.html", {
        "request": request, "user": user, "agent": agent, "rows": rows,
        "is_admin_profile": is_admin_profile, "branch_agents": branch_agents,
        "deliveries": deliveries, "items_summary": items_summary, "cash_entries": cash_entries,
        "total_collections": total_collections, "total_expenses": total_expenses,
        "total_operating_cash": total_operating, "total_return_op_cash": total_return_op_cash,
        "operating_balance": operating_balance, "total_office_expenses": total_office_expenses,
        "remittance": remittance, "net_position": net_position,
        "preset": preset_norm or (preset or ""),
        "start_date": sd.isoformat() if sd else "",
        "end_date": ed.isoformat() if ed else "",
        "active": "agents", "csrf_token": csrf_token,
        "username_history": username_history,
    })




# ────────────────────────────────────────────────
#  PASSWORD RESET (admin resets agent/admin password)
# ────────────────────────────────────────────────

@router.post("/agents/{agent_id}/reset-password")
async def agent_reset_password(
    request: Request,
    agent_id: int,
    new_password: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    verify_csrf_token(request, csrf_token)
    target = db.get(User, agent_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # Admins can only reset agents in their own branch
    if is_admin(user) and not is_supervisor(user):
        if target.branch_id != user.branch_id:
            return HTMLResponse("Forbidden", status_code=403)
        if target.role not in ("AGENT",):
            return HTMLResponse("Forbidden — admins can only reset agent passwords", status_code=403)
    pw = (new_password or "").strip()
    if len(pw) < 8:
        return redirect(f"/agents/{agent_id}?error=Password+must+be+at+least+8+characters")
    target.password_hash = hash_password(pw)
    db.commit()
    audit_log(db, user.id, "PASSWORD_RESET", f"user_id={agent_id} reset by {user.username}",
              ip=request.client.host if request.client else "")
    return redirect(f"/agents/{agent_id}?success=Password+reset+successfully")

# ────────────────────────────────────────────────
#  ACTIVATE / DEACTIVATE USER
# ────────────────────────────────────────────────

@router.post("/agents/{agent_id}/toggle-active")
def toggle_agent_active(
    request: Request,
    agent_id: int,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    verify_csrf_token(request, csrf_token)
    target = db.get(User, agent_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # Admins can only toggle agents in their own branch
    if is_admin(user) and not is_supervisor(user):
        if target.branch_id != user.branch_id:
            return HTMLResponse("Forbidden", status_code=403)
        if target.role not in ("AGENT",):
            return HTMLResponse("Forbidden — admins can only deactivate agents", status_code=403)
    # Cannot deactivate yourself
    if target.id == user.id:
        return redirect(f"/agents/{agent_id}?error=You+cannot+deactivate+your+own+account")
    target.is_active = not target.is_active
    db.commit()
    action = "REACTIVATED" if target.is_active else "DEACTIVATED"
    audit_log(db, user.id, f"USER_{action}", f"user_id={agent_id} ({target.username}) by {user.username}",
              ip=request.client.host if request.client else "")
    msg = f"Account+{action.lower()}+successfully"
    return redirect(f"/agents/{agent_id}?success={msg}")

# ────────────────────────────────────────────────
#  AGENT OVERVIEW
# ────────────────────────────────────────────────

@router.get("/agent-overview", response_class=HTMLResponse)
def agent_overview(request: Request, db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    if is_admin(user) or is_supervisor(user):
        return redirect("/")
    branch_id = get_selected_branch_id(request, user)

    # Stats
    rows = db.execute(
        select(Delivery).where(Delivery.agent_id == user.id).where(Delivery.branch_id == branch_id)
        .order_by(desc(Delivery.created_at)).limit(300)
    ).scalars().all()
    pending_c = sum(1 for d in rows if d.status == "PENDING")
    ofd_c = sum(1 for d in rows if d.status == "OUT_FOR_DELIVERY")
    done_c = sum(1 for d in rows if d.status == "DELIVERED")

    # Chart data — last 14 days
    today = date.today()
    chart_days = [(today - timedelta(days=i)) for i in range(13, -1, -1)]
    delivery_by_day: dict = {}
    for d in rows:
        if d.status != "DELIVERED":
            continue
        k = d.delivered_at.date().isoformat() if d.delivered_at else (d.created_at.date().isoformat() if d.created_at else None)
        if k:
            delivery_by_day[k] = delivery_by_day.get(k, 0) + 1
    expense_by_day: dict = {}
    expenses_raw = db.execute(
        select(CashEntry).where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind.in_(["EXPENSE", "COLLECTION_EXPENSE"]))
        .where(CashEntry.created_at >= datetime.now(timezone.utc) - timedelta(days=14))
    ).scalars().all()
    for e in expenses_raw:
        k = e.created_at.date().isoformat() if e.created_at else None
        if k:
            expense_by_day[k] = expense_by_day.get(k, 0) + (e.amount or 0)

    total_collected = db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind.in_(["COLLECTION", "CASH_PAYMENT", "TRANSFER_PAYMENT"]))
    ) or 0
    cash_collected = db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind.in_(["COLLECTION", "CASH_PAYMENT"]))
    ) or 0
    transfer_collected = db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind == "TRANSFER_PAYMENT")
    ) or 0
    total_expenses = db.scalar(
        select(func.coalesce(func.sum(CashEntry.amount), 0))
        .where(CashEntry.agent_id == user.id)
        .where(CashEntry.kind.in_(["EXPENSE", "COLLECTION_EXPENSE"]))
    ) or 0

    import json as _json
    deliveries_json = [
        {"id": d.id, "customer_name": d.customer_name, "status": d.status,
         "address": d.address or "", "created_at": d.created_at.strftime("%d %b %Y") if d.created_at else ""}
        for d in rows
    ]
    return tpl(request, "agent_overview.html", {
        "request": request, "user": user, "active": "dashboard",
        "total_deliveries": len(rows), "pending_c": pending_c,
        "ofd_c": ofd_c, "done_c": done_c,
        "total_collected": total_collected, "total_expenses": total_expenses,
        "cash_collected": cash_collected, "transfer_collected": transfer_collected,
        "deliveries_json": deliveries_json,
        "chart_labels": [str(d) for d in chart_days],
        "chart_deliveries": [delivery_by_day.get(d.isoformat(), 0) for d in chart_days],
        "chart_expenses": [round(expense_by_day.get(d.isoformat(), 0), 2) for d in chart_days],
    })

@router.get("/my-deliveries", response_class=HTMLResponse)
def my_deliveries(request: Request, db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    branch_id = get_selected_branch_id(request, user)
    rows = db.execute(
        select(Delivery).where(Delivery.agent_id == user.id).where(Delivery.branch_id == branch_id)
        .order_by(desc(Delivery.created_at)).limit(300)
    ).scalars().all()

    # Build items summary for each delivery
    delivery_ids = [d.id for d in rows]
    items_summary: dict[int, str] = {}
    if delivery_ids:
        lines = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        grouped: dict[int, list[str]] = {}
        for did, iname, qty in lines:
            grouped.setdefault(int(did), []).append(f"{iname} ×{int(qty)}")
        items_summary = {did: ", ".join(parts) for did, parts in grouped.items()}

    # Attention flags: deliveries needing action
    attention_ids: set[int] = set()
    wa_attention_ids: set[int] = set()
    if delivery_ids:
        id_placeholders = ",".join(str(i) for i in delivery_ids)
        wa_last = db.execute(text(f"""
            SELECT wc.delivery_id, wc.direction
            FROM wa_comments wc
            WHERE wc.delivery_id IN ({id_placeholders})
              AND wc.created_at = (
                SELECT MAX(created_at) FROM wa_comments wc2 WHERE wc2.delivery_id = wc.delivery_id
              )
        """)).fetchall()
        for _wrow in wa_last:
            if _wrow[1] == 'inbound':
                wa_attention_ids.add(_wrow[0])
        attention_ids |= wa_attention_ids
    adj_ids = {d.id for d in rows if d.status == "ADJUSTMENT_PENDING"}
    attention_ids |= adj_ids

    return tpl(request, "my_deliveries.html", {
        "request": request, "rows": rows, "user": user, "active": "deliveries",
        "items_summary": items_summary,
        "attention_ids": attention_ids,
        "wa_attention_ids": wa_attention_ids,
    })


@router.get("/deliveries/adjustment-count", response_class=JSONResponse)
def adjustment_count(request: Request, db: Session = Depends(get_db)):
    """Badge count for admin nav — pending adjustment requests."""
    user = get_current_user(db, request)
    if not user or not is_admin(user): return JSONResponse({"count": 0})
    count = db.execute(
        text("SELECT COUNT(*) FROM adjustment_requests ar JOIN deliveries d ON d.id = ar.delivery_id WHERE ar.status = 'PENDING' AND d.branch_id = :bid"),
        {"bid": user.branch_id}
    ).scalar() or 0
    return JSONResponse({"count": int(count)})


@router.get("/deliveries/{delivery_id}", response_class=HTMLResponse)
def delivery_detail(request: Request, delivery_id: int, db: Session = Depends(get_db), user: User = Depends(get_active_user), d: Delivery = Depends(get_authorized_delivery)):
    if not is_admin(user) and not is_supervisor(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    d_items_all = db.execute(
        select(DeliveryItem, Item).join(Item, Item.id == DeliveryItem.item_id).where(DeliveryItem.delivery_id == d.id)
    ).all()
    # Find which delivery_items are vetting-only phantoms (from adjustment approval)
    _vetting_di_ids = set(r[0] for r in db.execute(text(
        "SELECT DISTINCT delivery_item_id FROM stock_return_vettings WHERE delivery_id=:did"
    ), {"did": d.id}).fetchall())
    # Hide items that have vetting records — those are phantom items for return tracking
    d_items = [(di, it) for di, it in d_items_all if di.id not in _vetting_di_ids]
    col = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.delivery_id == d.id).where(CashEntry.kind.in_(["COLLECTION","CASH_PAYMENT","TRANSFER_PAYMENT"]))) or 0
    cash_total = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.delivery_id == d.id).where(CashEntry.kind.in_(["COLLECTION","CASH_PAYMENT"]))) or 0
    transfer_total = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.delivery_id == d.id).where(CashEntry.kind == "TRANSFER_PAYMENT")) or 0
    exp = db.scalar(select(func.coalesce(func.sum(CashEntry.amount), 0)).where(CashEntry.delivery_id == d.id).where(CashEntry.kind == "EXPENSE")) or 0
    csrf_token = get_csrf_token(request)
    agents = db.execute(
        select(User).where(User.role == "AGENT").where(User.branch_id == d.branch_id)
        .where(User.is_active == True).order_by(User.username.asc())
    ).scalars().all() if is_admin(user) or is_supervisor(user) else []
    # Load any pending adjustment request
    pending_adj = db.execute(
        text("SELECT ar.id, ar.reason, ar.created_at, u.username as agent_name FROM adjustment_requests ar JOIN users u ON u.id = ar.requested_by WHERE ar.delivery_id = :did AND ar.status = 'PENDING' ORDER BY ar.created_at DESC LIMIT 1"),
        {"did": d.id}
    ).fetchone()
    adj_items = []
    if pending_adj:
        adj_items = db.execute(
            text("SELECT id, request_id, delivery_item_id, item_name, original_amount, new_amount, remove_item FROM adjustment_request_items WHERE request_id = :rid ORDER BY id"),
            {"rid": pending_adj.id}
        ).fetchall()
    wa_comments = db.execute(
        text("SELECT id, direction, sender, body, media_mime, created_at FROM wa_comments WHERE delivery_id=:did ORDER BY created_at ASC"),
        {"did": d.id}
    ).fetchall()
    return tpl(request, "delivery_detail.html", {
        "request": request, "d": d, "d_items": d_items, "user": user, "error": None,
        "collection_total": col, "expense_total": exp,
        "cash_total": cash_total, "transfer_total": transfer_total,
        "back_url": "/deliveries" if is_admin(user) else "/my-deliveries",
        "active": "deliveries", "csrf_token": csrf_token, "agents": agents,
        "pending_adj": pending_adj, "adj_items": adj_items,
        "wa_comments": wa_comments,
    })


@router.post("/deliveries/bulk-assign")
async def deliveries_bulk_assign(
    request: Request,
    agent_id: int = Form(...),
    delivery_ids: list[int] = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN")),
):
    verify_csrf_token(request, csrf_token)
    branch_id = get_selected_branch_id(request, user)
    agent = db.get(User, agent_id)
    if not agent or agent.role != "AGENT" or agent.branch_id != branch_id:
        return redirect("/deliveries?error=Invalid+agent")
    assigned = 0
    for did in delivery_ids:
        d = db.get(Delivery, did)
        if not d or d.branch_id != branch_id or d.status == "DELIVERED":
            continue
        old_agent_id = d.agent_id
        d.agent_id = agent_id
        # Create OUT transactions for items that don't have one yet
        # (covers orders created by supervisor with no OUT tx)
        items_without_tx = db.execute(text("""
            SELECT di.item_id, di.quantity FROM delivery_items di
            WHERE di.delivery_id = :did
              AND NOT EXISTS (
                SELECT 1 FROM transactions t
                WHERE t.delivery_id = :did AND t.item_id = di.item_id AND t.type = 'OUT'
              )
        """), {"did": did}).fetchall()
        for item_id_row, qty in items_without_tx:
            db.add(Transaction(
                branch_id=branch_id, item_id=item_id_row, type="OUT", quantity=qty,
                note=f"Delivery #{did} to {d.customer_name} — assigned to agent",
                reference=f"delivery-{did}", delivery_id=did,
            ))
        notify(db, agent_id, "📦 New Delivery Assigned",
               f"Delivery #{d.id} for {d.customer_name} has been assigned to you.",
               f"/deliveries/{d.id}", "info")
        assigned += 1
    db.commit()
    return redirect(f"/deliveries?success={assigned}+order(s)+assigned+to+{agent.full_name or agent.username}")


@router.post("/deliveries/{delivery_id}/assign-agent")
async def delivery_assign_agent(
    request: Request, delivery_id: int,
    agent_id: int = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    verify_csrf_token(request, csrf_token)
    d = db.get(Delivery, delivery_id)
    if not d: raise HTTPException(status_code=404, detail="Delivery not found")
    if d.status == "DELIVERED":
        return redirect(f"/deliveries/{delivery_id}?error=Cannot+reassign+a+delivered+order")
    # Admin can only assign within their branch
    if is_admin(user) and d.branch_id != user.branch_id:
        return HTMLResponse("Forbidden", status_code=403)
    agent = db.get(User, agent_id)
    if not agent or agent.branch_id != d.branch_id:
        return redirect(f"/deliveries/{delivery_id}?error=Agent+not+found+or+not+in+this+branch")
    d.agent_id = agent_id
    notify(db, agent_id, "📦 New Delivery Assigned",
           f"Delivery #{d.id} for {d.customer_name} has been assigned to you.",
           f"/deliveries/{d.id}", "info")
    db.commit()
    audit_log(db, user.id, "DELIVERY_REASSIGNED",
              f"delivery_id={delivery_id} assigned to agent_id={agent_id}",
              ip=request.client.host if request.client else "")
    return redirect(f"/deliveries/{delivery_id}?success=Agent+assigned+successfully")


@router.post("/deliveries/{delivery_id}/date")
async def update_delivery_date(
    request: Request, delivery_id: int,
    delivery_date: str = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_active_user),
    d: Delivery = Depends(get_authorized_delivery),
):
    if not is_admin(user) and not is_supervisor(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    try:
        d.delivery_date = datetime.strptime(delivery_date.strip(), "%Y-%m-%d")
        db.commit()
    except ValueError:
        pass
    return redirect(f"/deliveries/{delivery_id}")


@router.post("/deliveries/{delivery_id}/request-adjustment")
async def request_adjustment(
    request: Request, delivery_id: int,
    reason: str = Form(""),
    item_ids: list[int] = Form(default=[]),
    new_amounts: list[float] = Form(default=[]),
    new_quantities: list[int] = Form(default=[]),
    remove_flags: list[str] = Form(default=[]),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_active_user),
):
    verify_csrf_token(request, csrf_token)
    d = db.get(Delivery, delivery_id)
    if not d: raise HTTPException(status_code=404)
    if d.agent_id != user.id and not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    if d.status not in ("OUT_FOR_DELIVERY", "PENDING"):
        return redirect(f"/deliveries/{delivery_id}?error=Can+only+request+adjustment+on+active+deliveries")
    # Cancel any existing pending request
    db.execute(text("UPDATE adjustment_requests SET status='CANCELLED' WHERE delivery_id=:did AND status='PENDING'"), {"did": d.id})
    # Create new request
    result = db.execute(
        text("INSERT INTO adjustment_requests (delivery_id, requested_by, reason, status, created_at) VALUES (:did, :uid, :reason, 'PENDING', :_now) RETURNING id"),
        {"did": d.id, "uid": user.id, "reason": (reason or "").strip()[:400], "_now": _now()}
    )
    req_id = result.fetchone()[0]
    # Save item adjustments
    d_items = db.execute(select(DeliveryItem, Item).join(Item, Item.id == DeliveryItem.item_id).where(DeliveryItem.delivery_id == d.id)).all()
    item_map = {di.id: (di, it) for di, it in d_items}
    for i, item_id in enumerate(item_ids):
        if item_id not in item_map: continue
        di, it = item_map[item_id]
        from decimal import Decimal as _D, InvalidOperation as _IO
        try:
            new_amt = _D(str(new_amounts[i])) if i < len(new_amounts) else (di.line_amount or 0)
        except (_IO, ValueError):
            new_amt = di.line_amount or 0
        new_qty  = int(new_quantities[i]) if i < len(new_quantities) and new_quantities[i] else di.quantity
        new_qty  = max(0, min(new_qty, di.quantity))  # clamp 0..original
        remove   = remove_flags[i] == "1" if i < len(remove_flags) else (new_qty == 0)
        db.execute(text(
            "INSERT INTO adjustment_request_items (request_id, delivery_item_id, item_name, original_amount, new_amount, remove_item) "
            "VALUES (:rid, :diid, :name, :orig, :new, :rem)"
        ), {"rid": req_id, "diid": di.id, "name": it.name, "orig": di.line_amount or 0, "new": new_amt if not remove else 0, "rem": remove})
        # Store new quantity in remove_item logic — use new_amount=0 + note for qty reduction
        if not remove and new_qty != di.quantity:
            # Update the line amount proportionally
            if di.quantity > 0:
                proportional_amt = (di.line_amount or 0) * new_qty / di.quantity
                try:
                    _user_amt = _D(str(new_amounts[i])) if i < len(new_amounts) else 0
                except (_IO, ValueError):
                    _user_amt = 0
                new_amt = proportional_amt if _user_amt == 0 else new_amt
            db.execute(text(
                "UPDATE adjustment_request_items SET new_amount=:amt WHERE request_id=:rid AND delivery_item_id=:diid"
            ), {"amt": new_amt, "rid": req_id, "diid": di.id})
        # Store new qty in item name field as suffix for review
        if new_qty != di.quantity and not remove:
            db.execute(text(
                "UPDATE adjustment_request_items SET item_name=:name WHERE request_id=:rid AND delivery_item_id=:diid"
            ), {"name": f"{it.name} (qty: {di.quantity}→{new_qty})", "rid": req_id, "diid": di.id})
    d.status = "ADJUSTMENT_PENDING"
    notify_branch_admins(db, d.branch_id, "⚠️ Adjustment Request",
           f"Agent requested price adjustment on delivery #{d.id} ({d.customer_name}). Reason: {(reason or '').strip()[:100]}",
           f"/deliveries/{d.id}", "warning")
    db.commit()
    audit_log(db, user.id, "ADJUSTMENT_REQUESTED", f"delivery_id={d.id} request_id={req_id}",
              ip=request.client.host if request.client else "")
    return redirect(f"/deliveries/{delivery_id}?success=Adjustment+request+submitted+awaiting+admin+approval")


@router.post("/deliveries/{delivery_id}/review-adjustment")
async def review_adjustment(
    request: Request, delivery_id: int,
    action: str = Form(...),
    rejection_note: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN")),
):
    verify_csrf_token(request, csrf_token)
    d = db.get(Delivery, delivery_id)
    if not d: raise HTTPException(status_code=404)
    pending = db.execute(
        text("SELECT id, delivery_id, requested_by, reason, status, reviewed_by, rejection_note, created_at, reviewed_at FROM adjustment_requests WHERE delivery_id=:did AND status='PENDING' ORDER BY created_at DESC LIMIT 1"),
        {"did": d.id}
    ).fetchone()
    if not pending:
        return redirect(f"/deliveries/{delivery_id}?error=No+pending+adjustment+request+found")
    if action == "approve":
        adj_items = db.execute(
            text("SELECT id, request_id, delivery_item_id, item_name, original_amount, new_amount, remove_item FROM adjustment_request_items WHERE request_id=:rid"), {"rid": pending.id}
        ).fetchall()
        for ai in adj_items:
            if ai.remove_item:
                # Item was refused by customer — still physically with the agent.
                # Zero out the delivery item (keep it for vetting FK) and create vetting record.
                di = db.get(DeliveryItem, ai.delivery_item_id)
                if di and di.quantity > 0:
                    db.execute(text(
                        "INSERT INTO stock_return_vettings "
                        "(delivery_id, delivery_item_id, vetted_by, qty_returned, created_at, resolved) "
                        "VALUES (:did, :diid, NULL, 0, :_now, FALSE)"
                    ), {"did": d.id, "diid": di.id, "_now": _now()})
                    # Zero out amount but keep the item record for vetting reference
                    db.execute(
                        text("UPDATE delivery_items SET line_amount=0 WHERE id=:did"),
                        {"did": ai.delivery_item_id}
                    )
            else:
                # Price/qty change — update the line amount
                db.execute(
                    text("UPDATE delivery_items SET line_amount=:amt WHERE id=:did"),
                    {"amt": ai.new_amount, "did": ai.delivery_item_id}
                )
                # Check if qty was reduced (encoded in item_name as "Name (qty: X→Y)")
                import re as _re
                qty_match = _re.search(r'\(qty:\s*(\d+)\s*→\s*(\d+)\)', ai.item_name or '')
                if qty_match:
                    old_qty = int(qty_match.group(1))
                    new_qty = int(qty_match.group(2))
                    reduced_by = old_qty - new_qty
                    if reduced_by > 0:
                        di = db.get(DeliveryItem, ai.delivery_item_id)
                        if di:
                            # Update the active delivery item to the new qty
                            db.execute(
                                text("UPDATE delivery_items SET quantity=:qty WHERE id=:did"),
                                {"qty": new_qty, "did": ai.delivery_item_id}
                            )
                            # Create a new delivery_item for the reduced portion (for vetting)
                            db.execute(text(
                                "INSERT INTO delivery_items (delivery_id, item_id, quantity, line_amount) "
                                "VALUES (:did, :iid, :qty, 0) RETURNING id"
                            ), {"did": d.id, "iid": di.item_id, "qty": reduced_by})
                            new_di_id = db.execute(text(
                                "SELECT id FROM delivery_items WHERE delivery_id=:did AND item_id=:iid AND quantity=:qty AND line_amount=0 ORDER BY id DESC LIMIT 1"
                            ), {"did": d.id, "iid": di.item_id, "qty": reduced_by}).scalar()
                            if new_di_id:
                                db.execute(text(
                                    "INSERT INTO stock_return_vettings "
                                    "(delivery_id, delivery_item_id, vetted_by, qty_returned, created_at, resolved) "
                                    "VALUES (:did, :diid, NULL, 0, :_now, FALSE)"
                                ), {"did": d.id, "diid": new_di_id, "_now": _now()})
        db.execute(
            text("UPDATE adjustment_requests SET status='APPROVED', reviewed_by=:uid, reviewed_at=:_now WHERE id=:rid"),
            {"uid": user.id, "rid": pending.id, "_now": _now()}
        )
        d.status = "OUT_FOR_DELIVERY"
        notify(db, d.agent_id, "✅ Adjustment Approved",
               f"Your price adjustment for delivery #{d.id} ({d.customer_name}) has been approved. You can now mark it as delivered.",
               f"/deliveries/{d.id}", "success")
        db.commit()
        audit_log(db, user.id, "ADJUSTMENT_APPROVED", f"delivery_id={d.id} request_id={pending.id}",
                  ip=request.client.host if request.client else "")
        return redirect(f"/deliveries/{delivery_id}?success=Adjustment+approved+agent+can+now+mark+delivered")
    else:
        note = (rejection_note or "").strip()[:400] or "Rejected by admin"
        db.execute(
            text("UPDATE adjustment_requests SET status='REJECTED', reviewed_by=:uid, reviewed_at=:_now, rejection_note=:note WHERE id=:rid"),
            {"uid": user.id, "rid": pending.id, "note": note, "_now": _now()}
        )
        d.status = "OUT_FOR_DELIVERY"
        notify(db, d.agent_id, "❌ Adjustment Rejected",
               f"Your price adjustment for delivery #{d.id} ({d.customer_name}) was rejected. {note}",
               f"/deliveries/{d.id}", "danger")
        db.commit()
        audit_log(db, user.id, "ADJUSTMENT_REJECTED", f"delivery_id={d.id} request_id={pending.id}",
                  ip=request.client.host if request.client else "")
        return redirect(f"/deliveries/{delivery_id}?success=Adjustment+rejected+agent+notified")


@router.post("/deliveries/{delivery_id}/collect")
async def delivery_collect(
    request: Request, delivery_id: int,
    cash_amount: float = Form(0.0),
    transfer_amount: float = Form(0.0),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_active_user),
    d: Delivery = Depends(get_authorized_delivery),
):
    """Mark delivery as DELIVERED with cash/transfer payment breakdown."""
    if not is_admin(user) and not is_supervisor(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    if d.status == "DELIVERED":
        return redirect(f"/deliveries/{delivery_id}?error=Already+delivered")
    if d.status == "ADJUSTMENT_PENDING":
        return redirect(f"/deliveries/{delivery_id}?error=Status+is+locked+%E2%80%94+an+adjustment+request+is+pending+approval.+Approve+or+reject+it+first.")

    from decimal import Decimal as _D, InvalidOperation as _IO
    try:
        cash_amt = max(0, _D(str(cash_amount or 0)))
    except (_IO, ValueError):
        cash_amt = _D("0")
    try:
        transfer_amt = max(0, _D(str(transfer_amount or 0)))
    except (_IO, ValueError):
        transfer_amt = _D("0")
    total_paid   = cash_amt + transfer_amt

    # Mark delivered
    create_out_transactions_for_delivery_if_needed(db, d.id, performed_by=user.username)
    d.status = "DELIVERED"
    d.delivered_at = datetime.now(timezone.utc)

    # Remove any existing collection entries for this delivery
    db.execute(text(
        "DELETE FROM cash_entries WHERE delivery_id = :did AND kind IN ('COLLECTION','CASH_PAYMENT','TRANSFER_PAYMENT')"
    ), {"did": d.id})
    now = datetime.now(timezone.utc)
    # Record cash portion
    if cash_amt > 0:
        db.add(CashEntry(
            branch_id=d.branch_id, agent_id=d.agent_id, delivery_id=d.id,
            kind="COLLECTION", amount=cash_amt, created_at=now,
            note=f"Cash payment — delivery #{d.id} to {d.customer_name}",
        ))
    # Record transfer portion
    if transfer_amt > 0:
        db.add(CashEntry(
            branch_id=d.branch_id, agent_id=d.agent_id, delivery_id=d.id,
            kind="TRANSFER_PAYMENT", amount=transfer_amt, created_at=now,
            note=f"Transfer payment — delivery #{d.id} to {d.customer_name}",
        ))
    # If nothing entered, use full order total
    if cash_amt == 0 and transfer_amt == 0:
        order_total = db.scalar(
            select(func.coalesce(func.sum(DeliveryItem.line_amount), 0))
            .where(DeliveryItem.delivery_id == d.id)
        ) or 0
        if order_total > 0:
            db.add(CashEntry(
                branch_id=d.branch_id, agent_id=d.agent_id, delivery_id=d.id,
                kind="COLLECTION", amount=order_total, created_at=now,
                note=f"Auto-recorded: delivery #{d.id} to {d.customer_name}",
            ))

    notify_branch_admins(db, d.branch_id, "✅ Delivery Completed",
           f"Agent marked delivery #{d.id} ({d.customer_name}) as delivered. Cash: ₦{cash_amt:,.0f} Transfer: ₦{transfer_amt:,.0f}",
           f"/deliveries/{d.id}", "success")
    audit_log(db, user.id, "DELIVERY_DELIVERED",
              f"delivery_id={d.id} cash={cash_amt} transfer={transfer_amt}",
              ip=request.client.host if request.client else "")
    db.commit()
    return redirect(f"/deliveries/{delivery_id}?success=Delivery+marked+as+delivered")


@router.post("/deliveries/{delivery_id}/status")
async def update_delivery_status(
    request: Request, delivery_id: int,
    status: str = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_active_user),
    d: Delivery = Depends(get_authorized_delivery),
):
    if not is_admin(user) and not is_supervisor(user) and d.agent_id != user.id:
        return HTMLResponse("Forbidden", status_code=403)
    verify_csrf_token(request, csrf_token)
    status_clean = (status or "").strip().upper()
    if status_clean not in {"PENDING", "OUT_FOR_DELIVERY", "DELIVERED", "FAILED", "RETURNED"}:
        raise HTTPException(status_code=400, detail="Invalid status")
    # Lock: once DELIVERED, FAILED, or RETURNED — no further status changes
    if d.status in ("DELIVERED", "FAILED", "RETURNED"):
        return redirect(f"/deliveries/{delivery_id}?error=This+order+is+{d.status.lower()}+and+cannot+be+updated")
    if d.status == "ADJUSTMENT_PENDING":
        return redirect(f"/deliveries/{delivery_id}?error=Status+is+locked+%E2%80%94+an+adjustment+request+is+pending+approval.+Approve+or+reject+it+first.")
    # Helper: build item summary string for AI call script
    def _items_summary() -> str:
        rows = db.execute(
            select(Item.name, DeliveryItem.quantity)
            .join(DeliveryItem, DeliveryItem.item_id == Item.id)
            .where(DeliveryItem.delivery_id == d.id) # <-- FIXED
        ).all()
        return ", ".join(f"{r.name} x{r.quantity}" for r in rows) if rows else "your order"

    if status_clean == "DELIVERED":
        try:
            create_out_transactions_for_delivery_if_needed(db, d.id, performed_by=user.username)
            d.status = "DELIVERED"
            d.delivered_at = datetime.now(timezone.utc)
            audit_log(db, user.id, "DELIVERY_DELIVERED", f"delivery_id={d.id}",
                      ip=request.client.host if request.client else "")

            # Auto-close any linked assignment — stock was used for this delivery
            db.execute(text(
                "UPDATE agent_stock_assignments SET returned=TRUE, qty_returned=qty_assigned, "
                "vetted_at=:_now WHERE delivery_id=:did AND returned=FALSE"
            ), {"did": d.id, "_now": _now()})

            # Auto-create COLLECTION cash entry from delivery order total
            existing_col = db.scalar(
                select(func.count(CashEntry.id)).where(
                    CashEntry.delivery_id == d.id,
                    CashEntry.kind.in_(["COLLECTION", "CASH_PAYMENT", "TRANSFER_PAYMENT"])
                )
            ) or 0
            if existing_col == 0:
                order_total = db.scalar(
                    select(func.coalesce(func.sum(DeliveryItem.line_amount), 0))
                    .where(DeliveryItem.delivery_id == d.id)
                ) or 0
                if order_total > 0:
                    db.add(CashEntry(
                        branch_id=d.branch_id,
                        agent_id=d.agent_id,
                        delivery_id=d.id,
                        kind="COLLECTION",
                        amount=order_total,
                        note=f"Auto-recorded: delivery #{d.id} to {d.customer_name}",
                    ))

            db.commit()
            trigger_call(d.id, d.customer_phone, "DELIVERED", d.customer_name, _items_summary(), d.address)
        except ValueError as e:
            d_items = db.execute(select(DeliveryItem, Item).join(Item, Item.id == DeliveryItem.item_id).where(DeliveryItem.delivery_id == d.id)).all()
            csrf_token2 = get_csrf_token(request)
            return tpl(request, "delivery_detail.html", {
                "request": request, "d": d, "d_items": d_items, "user": user, "error": str(e),
                "collection_total": 0, "expense_total": 0,
                "back_url": "/deliveries" if is_admin(user) else "/my-deliveries",
                "active": "deliveries", "csrf_token": csrf_token2,
            })
        return redirect(f"/deliveries/{delivery_id}")
    d.status = status_clean
    # Notify agent of status change
    if status_clean == "OUT_FOR_DELIVERY" and d.agent_id:
        notify(db, d.agent_id, "🚚 Delivery Dispatched",
               f"Delivery #{d.id} to {d.customer_name} is now out for delivery.",
               f"/deliveries/{d.id}", "info")
    elif status_clean == "FAILED" and d.agent_id:
        notify(db, d.agent_id, "✕ Delivery Marked Failed",
               f"Delivery #{d.id} to {d.customer_name} has been marked as failed.",
               f"/deliveries/{d.id}", "danger")
    elif status_clean == "RETURNED" and d.agent_id:
        notify(db, d.agent_id, "↩ Delivery Marked Returned",
               f"Delivery #{d.id} to {d.customer_name} has been marked as returned.",
               f"/deliveries/{d.id}", "warning")
    # If delivery fails/returns and has a linked assignment — notify admin to vet stock return
    if status_clean in ("FAILED", "RETURNED"):
        linked = db.execute(text(
            "SELECT asa.id, it.name FROM agent_stock_assignments asa "
            "JOIN items it ON it.id = asa.item_id "
            "WHERE asa.delivery_id = :did AND asa.returned = FALSE"
        ), {"did": delivery_id}).fetchall()
        for asgn_id, item_name in linked:
            notify_branch_admins(db, d.branch_id,
                f"⚠ Assigned Stock Needs Return",
                f"Delivery #{delivery_id} {status_clean.lower()} — {item_name} assigned stock must be vetted.",
                f"/vetting", "warning")
    db.commit()
    trigger_call(d.id, d.customer_phone, status_clean, d.customer_name, _items_summary(), d.address)
    return redirect(f"/deliveries/{delivery_id}")


# ────────────────────────────────────────────────
