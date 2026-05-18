from fastapi import APIRouter, Request, Depends, Form, HTTPException, BackgroundTasks, Response, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import text, func, bindparam
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
import json, csv, io, os, logging
from urllib.parse import quote_plus
from app.core import *
from app.models import *
from app.security import *
from app.whatsapp_service import send_whatsapp_fallback
from app.unassigned_user import (
    UNASSIGNED_USERNAME_PREFIX,
    get_or_create_unassigned_user,
    is_unassigned_user,
)

router = APIRouter()

#  DELIVERIES
# ────────────────────────────────────────────────

@router.get("/deliveries", response_class=HTMLResponse)
def deliveries_admin_list(request: Request, db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    set_rls_context(db, user)
    if not is_admin(user) and not is_supervisor(user):
        return redirect("/my-deliveries")
    # Hide queue (placeholder-owned) deliveries from /deliveries — they live on /orders
    status = request.query_params.get("status", "").strip().upper()
    agent_id = request.query_params.get("agent_id", "").strip()
    sub_zone_filter = request.query_params.get("sub_zone_id", "").strip()
    per_page = 50
    try:
        page = max(1, int(request.query_params.get("page", "1")))
    except ValueError:
        page = 1
    offset = (page - 1) * per_page

    # Build filter conditions as a reusable list
    # kpi_filters = same but without the status filter (so KPI cards always show all statuses)
    filters = []
    kpi_filters = []
    if is_supervisor(user):
        filter_branch = request.query_params.get("branch_id", "").strip()
        start_date = request.query_params.get("start_date", "").strip()
        end_date = request.query_params.get("end_date", "").strip()
        if filter_branch and filter_branch.isdigit():
            filters.append(Delivery.branch_id == int(filter_branch))
            kpi_filters.append(Delivery.branch_id == int(filter_branch))
        if status:
            filters.append(Delivery.status == status)
        if start_date:
            try:
                filters.append(Delivery.created_at >= datetime.fromisoformat(start_date))
                kpi_filters.append(Delivery.created_at >= datetime.fromisoformat(start_date))
            except ValueError:
                pass
        if end_date:
            try:
                filters.append(Delivery.created_at <= datetime.fromisoformat(end_date + " 23:59:59"))
                kpi_filters.append(Delivery.created_at <= datetime.fromisoformat(end_date + " 23:59:59"))
            except ValueError:
                pass
        branch_id = int(filter_branch) if filter_branch and filter_branch.isdigit() else None
        # Apply sub-zone filter for supervisor too (only meaningful with a branch selected)
        if branch_id and sub_zone_filter == "unassigned":
            filters.append(Delivery.sub_zone_id.is_(None))
        elif branch_id and sub_zone_filter.isdigit():
            filters.append(Delivery.sub_zone_id == int(sub_zone_filter))
        agents = []
    else:
        branch_id = get_selected_branch_id(request, user)
        filter_branch = ""
        start_date = ""
        end_date = ""
        filters.append(Delivery.branch_id == branch_id)
        if status:
            filters.append(Delivery.status == status)
        if agent_id.isdigit():
            filters.append(Delivery.agent_id == int(agent_id))
        # Sub-zone filter: "unassigned" → NULL, numeric → exact id
        if sub_zone_filter == "unassigned":
            filters.append(Delivery.sub_zone_id.is_(None))
        elif sub_zone_filter.isdigit():
            filters.append(Delivery.sub_zone_id == int(sub_zone_filter))
        agents_stmt = (
            select(User)
            .where(User.role == "AGENT")
            .where(User.branch_id == branch_id)
            .where(User.is_active == True)
            .where(~User.username.like(f"{UNASSIGNED_USERNAME_PREFIX}%"))
            .order_by(User.username.asc())
        )
        agents = db.execute(agents_stmt).scalars().all()

    # Exclude orders still in the /orders queue (owned by a placeholder Unassigned user)
    _unassigned_uid_subq = select(User.id).where(User.username.like(f"{UNASSIGNED_USERNAME_PREFIX}%"))
    filters.append(Delivery.agent_id.notin_(_unassigned_uid_subq))
    kpi_filters.append(Delivery.agent_id.notin_(_unassigned_uid_subq))
    total = db.scalar(select(func.count(Delivery.id)).where(*filters) if filters else select(func.count(Delivery.id))) or 0
    rows = db.execute((select(Delivery).where(*filters) if filters else select(Delivery)).order_by(desc(Delivery.created_at)).offset(offset).limit(per_page)).scalars().all()
    total_pages = max(1, (total + per_page - 1) // per_page)

    delivery_ids = [d.id for d in rows]
    items_summary: dict[int, str] = {}
    if delivery_ids:
        lines = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            # Hide vetting phantoms: rows with line_amount=0 are placeholders
            # inserted when an adjustment reduces qty (e.g. 2 → 1 leaves a
            # qty=1, line_amount=0 phantom for stock-return tracking). They
            # double-up the items popup, so exclude them from the summary.
            .where(DeliveryItem.line_amount != 0)
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        grouped: dict[int, list[str]] = {}
        for did, iname, qty in lines:
            grouped.setdefault(int(did), []).append(f"{iname} ×{int(qty)}")
        for did, parts in grouped.items():
            items_summary[did] = ", ".join(parts)

    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    sup_kpis = None
    if is_supervisor(user):
        def _kpi_count(st):
            return db.scalar(select(func.count(Delivery.id)).where(*kpi_filters, Delivery.status == st)) or 0
        sup_kpis = {
            "total": db.scalar(select(func.count(Delivery.id)).where(*kpi_filters)) or 0,
            "delivered": _kpi_count("DELIVERED"),
            "pending": _kpi_count("PENDING"),
            "in_transit": _kpi_count("OUT_FOR_DELIVERY"),
            "failed": db.scalar(select(func.count(Delivery.id)).where(*kpi_filters, Delivery.status.in_(["FAILED", "RETURNED"]))) or 0,
        }
    # Agent name lookup for display in table
    all_agent_ids = {d.agent_id for d in rows if d.agent_id}
    agent_names: dict[int, str] = {}
    if all_agent_ids:
        for u in db.execute(select(User).where(User.id.in_(all_agent_ids))).scalars().all():
            agent_names[u.id] = u.full_name or u.username

    # Attention flags: deliveries needing action (current page only, for dot display)
    # — last WhatsApp message is inbound (customer or seller reply waiting)
    # — adjustment pending approval
    attention_ids: set[int] = set()
    wa_attention_ids: set[int] = set()  # specifically has unread WA
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
    # ADJUSTMENT_PENDING deliveries always need attention
    adj_ids = {d.id for d in rows if d.status == "ADJUSTMENT_PENDING"}
    attention_ids |= adj_ids

    # Cross-page attention counts — so user knows if other pages have items needing action
    hidden_wa_count = 0
    hidden_adj_count = 0
    if total_pages > 1:
        current_ids_tuple = tuple(delivery_ids) if delivery_ids else (0,)
        # All filtered delivery IDs not on the current page
        other_filters = filters + [Delivery.id.not_in(current_ids_tuple)]
        all_other_ids = db.execute(
            select(Delivery.id).where(*other_filters)
        ).scalars().all()
        if all_other_ids:
            other_ids_tuple = tuple(all_other_ids)
            wa_rows = db.execute(text("""
                SELECT wc.delivery_id
                FROM wa_comments wc
                WHERE wc.delivery_id IN :other_ids
                  AND wc.created_at = (
                    SELECT MAX(created_at) FROM wa_comments wc2 WHERE wc2.delivery_id = wc.delivery_id
                  )
                  AND wc.direction = 'inbound'
            """).bindparams(bindparam("other_ids", expanding=True)),
            {"other_ids": list(other_ids_tuple)}).fetchall()
            hidden_wa_count = len(wa_rows)
            hidden_adj_count = db.scalar(
                select(func.count(Delivery.id)).where(
                    Delivery.id.in_(other_ids_tuple),
                    Delivery.status == "ADJUSTMENT_PENDING"
                )
            ) or 0

    # Sub-zones for the current branch — used by the filter dropdown + the
    # per-row "Assign zone" picker on Unassigned rows.
    sub_zones = []
    sub_zone_names: dict[int, str] = {}
    if branch_id:
        sub_zones = db.execute(
            select(SubZone).where(SubZone.branch_id == branch_id).order_by(SubZone.name.asc())
        ).scalars().all()
        sub_zone_names = {z.id: z.name for z in sub_zones}
    csrf_token = get_csrf_token(request)

    return tpl(request, "deliveries_list.html", {
        "request": request, "rows": rows, "agents": agents, "status": status,
        "agent_id": agent_id, "items_summary": items_summary,
        "branches": branches, "selected_branch_id": branch_id,
        "branch_id": filter_branch, "start_date": start_date, "end_date": end_date,
        "user": user, "active": "deliveries", "sup_kpis": sup_kpis,
        "agent_names": agent_names,
        "attention_ids": attention_ids,
        "wa_attention_ids": wa_attention_ids,
        "page": page, "total_pages": total_pages, "total": total,
        "hidden_wa_count": hidden_wa_count, "hidden_adj_count": hidden_adj_count,
        "sub_zones": sub_zones,
        "sub_zone_names": sub_zone_names,
        "sub_zone_filter": sub_zone_filter,
        "csrf_token": csrf_token,
    })


@router.get("/orders", response_class=HTMLResponse)
def orders_queue_list(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    """Staging queue: orders created (auto from WhatsApp or manually) but not
    yet assigned to a real agent. Each row's agent_id points at the per-branch
    Unassigned placeholder. Bulk-assign moves them to /deliveries."""
    set_rls_context(db, user)

    # Supervisor: optional branch filter; default = all branches.
    if is_supervisor(user):
        filter_branch = request.query_params.get("branch_id", "").strip()
        branch_id = int(filter_branch) if filter_branch.isdigit() else None
        branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()
    else:
        branch_id = get_selected_branch_id(request, user)
        filter_branch = ""
        branches = []

    filters = [Delivery.status == "PENDING"]
    if branch_id:
        filters.append(Delivery.branch_id == branch_id)
        placeholder_uid = get_or_create_unassigned_user(db, branch_id).id
        filters.append(Delivery.agent_id == placeholder_uid)
    else:
        # Supervisor with no branch filter — match any placeholder user
        placeholder_subq = select(User.id).where(User.username.like(f"unassigned_b%"))
        filters.append(Delivery.agent_id.in_(placeholder_subq))

    rows = db.execute(
        select(Delivery)
        .where(*filters)
        # zone-tagged rows first, then unassigned-zone rows; within each group, newest first
        .order_by(Delivery.sub_zone_id.is_(None).asc(), Delivery.sub_zone_id.asc(), desc(Delivery.created_at))
    ).scalars().all()

    delivery_ids = [d.id for d in rows]
    items_summary: dict[int, str] = {}
    if delivery_ids:
        lines = db.execute(
            select(DeliveryItem.delivery_id, Item.name, DeliveryItem.quantity)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id.in_(delivery_ids))
            # Hide vetting phantoms: rows with line_amount=0 are placeholders
            # inserted when an adjustment reduces qty (e.g. 2 → 1 leaves a
            # qty=1, line_amount=0 phantom for stock-return tracking). They
            # double-up the items popup, so exclude them from the summary.
            .where(DeliveryItem.line_amount != 0)
            .order_by(DeliveryItem.delivery_id.asc(), Item.name.asc())
        ).all()
        grouped: dict[int, list[str]] = {}
        for did, iname, qty in lines:
            grouped.setdefault(int(did), []).append(f"{iname} ×{int(qty)}")
        for did, parts in grouped.items():
            items_summary[did] = ", ".join(parts)

    # Sub-zones + agents for the current branch (only meaningful when one branch is in view)
    sub_zones: list = []
    sub_zone_names: dict[int, str] = {}
    agents: list = []
    if branch_id:
        sub_zones = db.execute(
            select(SubZone).where(SubZone.branch_id == branch_id).order_by(SubZone.name.asc())
        ).scalars().all()
        sub_zone_names = {z.id: z.name for z in sub_zones}
        agents = db.execute(
            select(User)
            .where(User.role == "AGENT")
            .where(User.branch_id == branch_id)
            .where(User.is_active == True)
            .where(~User.username.like(f"{UNASSIGNED_USERNAME_PREFIX}%"))
            .order_by(User.username.asc())
        ).scalars().all()

    csrf_token = get_csrf_token(request)
    return tpl(request, "orders_list.html", {
        "request": request, "rows": rows, "items_summary": items_summary,
        "agents": agents, "sub_zones": sub_zones, "sub_zone_names": sub_zone_names,
        "branches": branches, "selected_branch_id": branch_id, "branch_id": filter_branch,
        "user": user, "active": "orders", "csrf_token": csrf_token,
        "total": len(rows),
    })


@router.get("/admin/fix-cash-constraint", response_class=JSONResponse)
def fix_cash_constraint(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("SUPERVISOR"))):
    """One-time: update cash_entries kind constraint to include TRANSFER_PAYMENT."""
    set_rls_context(db, user)
    try:
        with db.bind.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE cash_entries DROP CONSTRAINT IF EXISTS ck_cash_kind"))
            conn.execute(text("ALTER TABLE cash_entries ADD CONSTRAINT ck_cash_kind CHECK (kind IN ('COLLECTION','EXPENSE','OPERATING_CASH','OFFICE_EXPENSE','RETURN_OPERATING_CASH','CASH_PAYMENT','TRANSFER_PAYMENT','COLLECTION_EXPENSE'))"))
        return JSONResponse({"status": "ok", "message": "Constraint updated successfully"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)})


@router.get("/admin/check-env", response_class=JSONResponse)
def check_env(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("SUPERVISOR"))):
    """Supervisor-only: verify environment variables are loaded."""
    set_rls_context(db, user)
    groq = os.getenv("GROQ_API_KEY", "")
    return JSONResponse({
        "GROQ_API_KEY": f"set ({len(groq)} chars)" if groq else "NOT SET",
        "SESSION_SECRET": "set" if os.getenv("SESSION_SECRET") else "NOT SET",
    })


@router.post("/parse-order/api", response_class=JSONResponse)
async def parse_order_api(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    """Backend proxy — calls Groq API server-side to avoid CORS."""
    set_rls_context(db, user)
    limiter.check(request, max_requests=60, window_seconds=60)

    import httpx
    body = await request.json()
    prompt = body.get("prompt", "")
    if not prompt:
        return JSONResponse({"error": "No prompt provided"}, status_code=400)

    from app.gemini_client import call_gemini_async
    payload = {
        "system_instruction": {
            "parts": [{"text": "You are an order parser for a Nigerian logistics business. You MUST return ONLY a valid, complete JSON array — no markdown, no code fences, no explanation, no trailing text. Start your response with [ and end with ]. Never truncate."}]
        },
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 32768,
            "thinkingConfig": {"thinkingBudget": 0},
        }
    }
    try:
        data = await call_gemini_async(payload, timeout=60)
        if not data:
            return JSONResponse({"error": "Gemini unavailable on all backends. Check server logs."}, status_code=503)
        if "error" in data:
            err = data["error"]
            error_msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            return JSONResponse({"error": error_msg}, status_code=500)
        try:
            parts = data["candidates"][0]["content"]["parts"]
            # Skip thinking parts (thought=True), join all real text parts
            text = "".join(p["text"] for p in parts if p.get("text") and not p.get("thought"))
        except (KeyError, IndexError):
            return JSONResponse({"error": "Could not read Gemini response."}, status_code=500)
        return JSONResponse({"text": text})
    except Exception as e:
        logging.getLogger("parse_order").error("Parse order failed: %s", e)
        return JSONResponse({"error": "Failed to process order. Check server logs."}, status_code=500)


@router.get("/parse-order", response_class=HTMLResponse)
def parse_order_form(request: Request, branch_id: int = 0, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    set_rls_context(db, user)
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    # Supervisor must pick a branch first
    if is_supervisor(user):
        effective_branch_id = branch_id or (branches[0].id if branches else 0)
    else:
        effective_branch_id = get_selected_branch_id(request, user) or 0
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == effective_branch_id).where(User.is_active == True).order_by(User.username.asc())).scalars().all()
    _items_with_stock = get_items_with_stock(db, branch_id=effective_branch_id)
    items = [it for it, _ in _items_with_stock]
    csrf_token = get_csrf_token(request)
    form_token = generate_form_token(request)
    items_json = [{"id": it.id, "name": it.name, "category": it.category or "", "unit": it.unit or "pcs", "price": it.selling_price or 0, "stock": int(stk), "aliases": (it.aliases or "")} for it, stk in _items_with_stock]
    return tpl(request, "parse_order.html", {
        "request": request, "user": user, "active": "parse_order",
        "agents": agents, "items": items,
        "items_with_stock": _items_with_stock,
        "items_json": items_json,
        "branches": branches, "selected_branch_id": effective_branch_id,
        "today": date.today().isoformat(), "csrf_token": csrf_token,
        "form_token": form_token,
    })


@router.get("/deliveries/new", response_class=HTMLResponse)
def delivery_new_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    set_rls_context(db, user)
    branch_id = get_selected_branch_id(request, user)
    agents = db.execute(select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).where(User.is_active == True).order_by(User.username.asc())).scalars().all()
    # Get items with current stock levels for out-of-stock labelling
    _items_with_stock = get_items_with_stock(db, branch_id=branch_id)
    items = [(it, int(stock)) for it, stock in _items_with_stock]
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    # Pending assignments per agent — for linking assigned stock to delivery
    pending_assignments = {}
    if is_admin(user) and branch_id:
        try:
            rows_a = db.execute(text(
                "SELECT asa.id, asa.agent_id, asa.item_id, "
                "asa.qty_assigned - COALESCE(asa.qty_returned, 0) AS qty_available, "
                "asa.note, it.name AS item_name "
                "FROM agent_stock_assignments asa "
                "JOIN items it ON it.id = asa.item_id "
                "WHERE asa.branch_id = :bid AND asa.returned = FALSE "
                "AND (asa.delivery_id IS NULL OR asa.delivery_id = 0) "
                "AND (asa.qty_assigned - COALESCE(asa.qty_returned, 0)) > 0 "
                "LIMIT 200"
            ), {"bid": branch_id}).fetchall()
        except Exception:
            # Fallback if delivery_id column doesn't exist yet
            db.rollback()
            rows_a = db.execute(text(
                "SELECT asa.id, asa.agent_id, asa.item_id, "
                "asa.qty_assigned - COALESCE(asa.qty_returned, 0) AS qty_available, "
                "asa.note, it.name AS item_name "
                "FROM agent_stock_assignments asa "
                "JOIN items it ON it.id = asa.item_id "
                "WHERE asa.branch_id = :bid AND asa.returned = FALSE "
                "AND (asa.qty_assigned - COALESCE(asa.qty_returned, 0)) > 0 "
                "LIMIT 200"
            ), {"bid": branch_id}).fetchall()
        for r in rows_a:
            pending_assignments.setdefault(r[1], []).append({
                "id": r[0], "item_id": r[2], "qty": r[3],
                "note": r[4] or "", "item_name": r[5],
            })
    # Sub-zones for the current branch (for the zone dropdown)
    sub_zones = []
    if branch_id:
        sub_zones = db.execute(
            select(SubZone).where(SubZone.branch_id == branch_id).order_by(SubZone.name.asc())
        ).scalars().all()
    csrf_token = get_csrf_token(request)
    form_token = generate_form_token(request)
    return tpl(request, "delivery_new.html", {
        "request": request, "agents": agents, "items": items, "user": user,
        "active": "deliveries_new", "branches": branches, "selected_branch_id": branch_id,
        "today": date.today().isoformat(), "csrf_token": csrf_token,
        "form_token": form_token,
        "pending_assignments": pending_assignments,
        "sub_zones": sub_zones,
    })


@router.post("/deliveries/new")
async def delivery_create(
    request: Request,
    agent_id: str | None = Form(None),
    branch_id: int | None = Form(None),
    customer_name: str = Form(...),
    customer_phone: str = Form(""),
    customer_whatsapp: str = Form(""),
    address: str = Form(""),
    note: str = Form(""),
    delivery_date: str = Form(""),
    sub_zone_id: int | None = Form(None),
    item_id: list[int] = Form(...),
    quantity: list[int] = Form(...),
    line_amount: list[float] = Form(default=[]),
    assignment_ids: list[int] = Form(default=[]),
    csrf_token: str = Form(""),
    form_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_active_user),
):
    set_rls_context(db, user)
    verify_csrf_token(request, csrf_token)
    # [SEC] Idempotency — reject duplicate form submissions
    if not consume_form_token(request, form_token):
        return redirect("/deliveries?error=Duplicate+submission+detected.+Please+try+again.")
    if is_supervisor(user):
        # Supervisor-created orders land in the /orders queue for the chosen
        # branch — owned by the per-branch placeholder "Unassigned" user.
        if not branch_id:
            raise HTTPException(status_code=400, detail="Branch required")
        target_agent_id = get_or_create_unassigned_user(db, branch_id).id
    elif is_admin(user):
        if agent_id is None or (isinstance(agent_id, str) and not agent_id.strip()):
            raise HTTPException(status_code=422, detail="agent_id required for admin")
        branch_id = get_current_branch_id(request)
        if isinstance(agent_id, str) and agent_id.strip().lower() == "unassigned":
            target_agent_id = get_or_create_unassigned_user(db, branch_id).id
        else:
            try:
                target_agent_id = int(agent_id)
            except (TypeError, ValueError):
                raise HTTPException(status_code=422, detail="agent_id must be 'unassigned' or a user id")
            # [SEC] Verify target agent belongs to this admin's branch
            target_agent = db.get(User, target_agent_id)
            if not target_agent or target_agent.branch_id != branch_id:
                raise HTTPException(status_code=403, detail="Agent not in your branch")
    else:
        target_agent_id = int(user.id)
        branch_id = get_current_branch_id(request)
    cust = sanitize_text(customer_name, 160, "Customer name")
    if not cust:
        raise HTTPException(status_code=400, detail="Customer name required")
    if not branch_id:
        raise HTTPException(status_code=400, detail="No branch assigned")
    try:
        d_date = datetime.strptime(delivery_date.strip(), "%Y-%m-%d") if delivery_date.strip() else datetime.now(timezone.utc)
    except ValueError:
        d_date = datetime.now(timezone.utc)
    _clean_phone = sanitize_phone(customer_phone) or ""
    _clean_wa = sanitize_phone(customer_whatsapp) or ""
    # Append WhatsApp number to call list if not already present
    if _clean_wa and _clean_wa not in _clean_phone:
        _call_numbers = (_clean_phone + ", " + _clean_wa).strip(", ")
    else:
        _call_numbers = _clean_phone or None
    # Validate sub_zone belongs to this branch (silently drop if not)
    _sub_zone_id = None
    if sub_zone_id:
        _sz = db.get(SubZone, int(sub_zone_id))
        if _sz and _sz.branch_id == branch_id:
            _sub_zone_id = _sz.id
    d = Delivery(
        branch_id=branch_id, agent_id=target_agent_id, customer_name=cust,
        customer_phone=_call_numbers or None,
        customer_whatsapp=_clean_wa or None,
        address=sanitize_text(address, 300, "Address") or None,
        note=sanitize_text(note, 400, "Note") or None,
        status="PENDING", delivery_date=d_date,
        sub_zone_id=_sub_zone_id,
    )
    db.add(d)
    db.flush()
    amounts = list(line_amount or [])
    while len(amounts) < len(item_id):
        amounts.append(0.0)
    assigned_item_ids = set()  # items covered by assignment (already have OUT tx)
    for aid in (assignment_ids or []):
        asgn_row = db.execute(text(
            "SELECT item_id FROM agent_stock_assignments WHERE id = :aid"
        ), {"aid": aid}).fetchone()
        if asgn_row:
            assigned_item_ids.add(int(asgn_row[0]))
    # Lock all item rows that need OUT transactions (sorted by ID to avoid deadlocks)
    # Orders parked with the per-branch Unassigned user also defer stock OUT —
    # it happens at bulk-assign time, the same way supervisor-created orders do.
    _target_user = db.get(User, target_agent_id)
    _deferred_stock_out = is_supervisor(user) or is_unassigned_user(_target_user)
    needs_out = not _deferred_stock_out
    if needs_out:
        out_item_ids = sorted({int(iid) for iid, qty in zip(item_id, quantity)
                               if int(qty or 0) > 0 and int(iid) not in assigned_item_ids})
        if out_item_ids:
            db.execute(
                select(Item).where(Item.id.in_(out_item_ids)).order_by(Item.id.asc()).with_for_update()
            )
            # Aggregate quantities per item to check stock
            qty_per_item: dict[int, int] = {}
            for iid_val, qty_val in zip(item_id, quantity):
                q = int(qty_val) if qty_val is not None else 0
                if q > 0 and int(iid_val) not in assigned_item_ids:
                    qty_per_item[int(iid_val)] = qty_per_item.get(int(iid_val), 0) + q
            for locked_iid, total_qty in qty_per_item.items():
                stock = compute_stock(db, locked_iid, branch_id)
                if stock < total_qty:
                    item_obj = db.get(Item, locked_iid)
                    item_name = item_obj.name if item_obj else f"#{locked_iid}"
                    return redirect(f"/deliveries/new?error={quote_plus(f'Insufficient stock for {item_name} (available: {stock}, requested: {total_qty})')}")
    tx_item_ids = set()  # track items we've already created an OUT tx for
    for iid, qty, amt in zip(item_id, quantity, amounts):
        q = int(qty) if qty is not None else 0
        if q > 0:
            db.add(DeliveryItem(delivery_id=d.id, item_id=int(iid), quantity=q, line_amount=amt or 0))
            # Supervisor-created or Unassigned-queued orders: no OUT transaction —
            # stock only leaves when the order is bulk-assigned to a real agent.
            if _deferred_stock_out:
                continue
            # Create OUT transaction immediately (unless covered by an assignment)
            if int(iid) not in assigned_item_ids:
                if int(iid) not in tx_item_ids:
                    db.add(Transaction(
                        branch_id=branch_id, item_id=int(iid), type="OUT", quantity=q,
                        note=f"Delivery #{d.id} to {cust} — assigned to agent",
                        reference=f"delivery-{d.id}",
                        delivery_id=d.id,
                    ))
                    tx_item_ids.add(int(iid))
                else:
                    # Same item submitted twice — add quantity to existing pending transaction
                    db.execute(text(
                        "UPDATE transactions SET quantity = quantity + :q "
                        "WHERE delivery_id = :did AND item_id = :iid AND type = 'OUT'"
                    ), {"q": q, "did": d.id, "iid": int(iid)})
    # Link assignments if provided — no extra stock OUT needed (already deducted)
    for aid in (assignment_ids or []):
        asgn = db.execute(text(
            "SELECT id, agent_id, item_id, branch_id, qty_assigned, transaction_out_id, note, assigned_by "
            "FROM agent_stock_assignments "
            "WHERE id = :aid AND returned = FALSE"
        ), {"aid": aid}).fetchone()
        if asgn and asgn[1] == target_agent_id:
            asgn_id, _, asgn_item_id, asgn_branch_id, asgn_qty, asgn_tx_id, asgn_note, asgn_by = asgn
            # Find how many of this item the delivery actually uses
            delivery_qty = 0
            for iid, qty_val in zip(item_id, quantity):
                if int(iid) == int(asgn_item_id):
                    delivery_qty = int(qty_val) if qty_val else 0
                    break
            remainder = asgn_qty - delivery_qty
            if remainder > 0 and delivery_qty > 0:
                # Split: reduce original assignment to delivery_qty and link it
                db.execute(text(
                    "UPDATE agent_stock_assignments SET qty_assigned=:qty, delivery_id=:did WHERE id=:aid"
                ), {"qty": delivery_qty, "did": d.id, "aid": asgn_id})
                # Create new assignment for the remainder (stays for vetting)
                db.execute(text(
                    "INSERT INTO agent_stock_assignments "
                    "(agent_id, item_id, branch_id, qty_assigned, note, assigned_by, assigned_at, returned, qty_returned) "
                    "VALUES (:agent, :item, :branch, :qty, :note, :by, :_now, FALSE, 0)"
                ), {"agent": asgn[1], "item": asgn_item_id, "branch": asgn_branch_id,
                    "qty": remainder, "note": (asgn_note or '') + f' (split from #{asgn_id})', "by": asgn_by, "_now": _now()})
            else:
                # Full assignment used or no delivery item match — link whole thing
                db.execute(text(
                    "UPDATE agent_stock_assignments SET delivery_id = :did WHERE id = :aid"
                ), {"did": d.id, "aid": asgn_id})
            if asgn_tx_id:
                db.execute(text(
                    "UPDATE transactions SET delivery_id = :did WHERE id = :txid"
                ), {"did": d.id, "txid": asgn_tx_id})

    # Notify branch admins of new order
    notify_branch_admins(db, d.branch_id, "🆕 New Order Created",
        f"New delivery for {cust} created{' by supervisor' if is_supervisor(user) else ''}.",
        f"/deliveries/{d.id}", "info")
    if is_admin(user) and target_agent_id and target_agent_id != user.id:
        notify(db, target_agent_id, "📦 New Delivery Assigned",
               f"A new delivery for {cust} has been assigned to you.",
               f"/deliveries/{d.id}", "info")
    db.commit()

    # ── Check wa_pending_cache for WhatsApp messages that arrived before this order ──
    try:
        import re as _re
        db_name_lower = (d.customer_name or "").lower()
        # Build last-10-digit keys for every phone on this delivery (call + whatsapp,
        # supports comma/semicolon-separated multi-number fields).
        db_phone_keys: set[str] = set()
        for raw in _re.split(r"[,;]", (d.customer_phone or "") + "," + (d.customer_whatsapp or "")):
            digits = _re.sub(r"\D", "", raw)
            if len(digits) >= 10:
                db_phone_keys.add(digits[-10:])

        pending_rows = db.execute(text(
            "SELECT message_id, body, sender, group_jid, customer_name, customer_phone "
            "FROM wa_pending_cache ORDER BY created_at DESC LIMIT 50"
        )).fetchall()

        logging.getLogger("cache_wa").info(
            "Pending scan for new Order #%s: name=%r phone_keys=%s pending_count=%d",
            d.id, db_name_lower, sorted(db_phone_keys), len(pending_rows)
        )

        for pr in pending_rows:
            p_mid, p_body, p_sender, p_gjid, p_cname, p_cphone = pr[0], pr[1], pr[2], pr[3], pr[4], pr[5]

            # Phone check — last 10 digits against any number on the delivery
            p_phone_digits = _re.sub(r"\D", "", p_cphone or "")[-10:] if p_cphone else ""
            phone_ok = bool(p_phone_digits and p_phone_digits in db_phone_keys)

            # Name check
            name_ok = False
            if p_cname and db_name_lower and len(p_cname) > 3:
                p_words = [w for w in p_cname.split() if len(w) > 2]
                if len(p_words) >= 2 and all(w in db_name_lower for w in p_words):
                    name_ok = True
                elif p_cname == db_name_lower:
                    name_ok = True

            # Phone is the strongest signal; fall back to name match when phone
            # is missing OR when Gemini may have mis-extracted it (digit dupes).
            matched = phone_ok or name_ok
            logging.getLogger("cache_wa").info(
                "Pending row mid=%s p_name=%r p_phone=%r → phone_ok=%s name_ok=%s matched=%s",
                (p_mid or "")[:20], p_cname, p_cphone, phone_ok, name_ok, matched
            )

            if matched:
                _is_sqlite = DATABASE_URL.startswith("sqlite")
                if _is_sqlite:
                    _upsert = (
                        "INSERT OR REPLACE INTO whatsapp_outbound_map "
                        "(message_id, order_id, body, source, sender, group_jid, created_at) "
                        "VALUES (:mid, :oid, :body, 'group', :sender, :gjid, :_now)"
                    )
                else:
                    _upsert = (
                        "INSERT INTO whatsapp_outbound_map "
                        "(message_id, order_id, body, source, sender, group_jid, created_at) "
                        "VALUES (:mid, :oid, :body, 'group', :sender, :gjid, :_now) "
                        "ON CONFLICT (message_id) DO UPDATE SET order_id=EXCLUDED.order_id"
                    )
                db.execute(text(_upsert), {
                    "mid": p_mid, "oid": d.id, "body": p_body, "sender": p_sender, "gjid": p_gjid, "_now": _now()
                })
                db.execute(text("DELETE FROM wa_pending_cache WHERE message_id = :mid"), {"mid": p_mid})
                db.commit()
                logging.getLogger("cache_wa").info(
                    "Linked pending WA message %s → new Order #%s", p_mid[:20], d.id
                )
                break  # One original message per delivery
    except Exception as e:
        logging.getLogger("cache_wa").warning("Pending WA cache scan failed: %s", e)

    # Build item summary and trigger AI call on new order
    call_items = []
    for iid, qty in zip(item_id, quantity):
        if int(qty) > 0:
            it = db.get(Item, int(iid))
            if it:
                call_items.append(f"{it.name} x{qty}")
    items_summary = ", ".join(call_items) if call_items else "your order"
    trigger_call(d.id, d.customer_phone, "PENDING", d.customer_name, items_summary, d.address or "", whatsapp_number=d.customer_whatsapp)

    # Auto-send WhatsApp template to customer when delivery is created
    if d.customer_phone or d.customer_whatsapp:
        try:
            from app.utils import get_whatsapp_phone
            wa_phone = get_whatsapp_phone(d.customer_whatsapp or "", d.customer_phone or "")
            if wa_phone:
                submit_task(send_whatsapp_fallback, d.id, wa_phone, d.customer_name or "Customer", items_summary)
        except Exception as e:
            logging.getLogger("whatsapp").warning("Failed to queue WA template for delivery #%s: %s", d.id, e)

    return redirect(f"/deliveries/{d.id}")


@router.post("/deliveries/{delivery_id}/set-zone")
def delivery_set_zone(
    delivery_id: int,
    request: Request,
    sub_zone_id: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    """Reassign (or clear) a delivery's sub-zone. ADMIN scoped to own branch."""
    set_rls_context(db, user)
    verify_csrf_token(request, csrf_token)
    d = db.get(Delivery, delivery_id)
    if not d:
        raise HTTPException(status_code=404, detail="Delivery not found")
    if is_admin(user) and d.branch_id != user.branch_id:
        raise HTTPException(status_code=403, detail="Not in your branch")
    new_zone_id = None
    sz_clean = (sub_zone_id or "").strip()
    if sz_clean and sz_clean.isdigit():
        z = db.get(SubZone, int(sz_clean))
        if not z or z.branch_id != d.branch_id:
            raise HTTPException(status_code=400, detail="Zone does not belong to this branch")
        new_zone_id = z.id
    old_zone_id = d.sub_zone_id
    d.sub_zone_id = new_zone_id
    db.commit()
    audit_log(db, user.id, "delivery_set_zone",
              f"delivery={delivery_id} old={old_zone_id} new={new_zone_id}",
              request.client.host if request.client else "")
    # Preserve the user's filter/page state on redirect
    referer = request.headers.get("referer", "/deliveries")
    return redirect(referer)



# ────────────────────────────────────────────────
