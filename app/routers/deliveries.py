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
from app.whatsapp_service import send_whatsapp_fallback

router = APIRouter()

#  DELIVERIES
# ────────────────────────────────────────────────

@router.get("/deliveries", response_class=HTMLResponse)
def deliveries_admin_list(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if not is_admin(user) and not is_supervisor(user):
        return redirect("/my-deliveries")
    status = request.query_params.get("status", "").strip().upper()
    agent_id = request.query_params.get("agent_id", "").strip()

    if is_supervisor(user):
        # Supervisor filters by branch, status, date range
        filter_branch = request.query_params.get("branch_id", "").strip()
        start_date = request.query_params.get("start_date", "").strip()
        end_date = request.query_params.get("end_date", "").strip()
        stmt = select(Delivery).order_by(desc(Delivery.created_at)).limit(500)
        if filter_branch and filter_branch.isdigit():
            stmt = stmt.where(Delivery.branch_id == int(filter_branch))
        if status:
            stmt = stmt.where(Delivery.status == status)
        if start_date:
            try:
                stmt = stmt.where(Delivery.created_at >= datetime.fromisoformat(start_date))
            except ValueError:
                pass
        if end_date:
            try:
                stmt = stmt.where(Delivery.created_at <= datetime.fromisoformat(end_date + " 23:59:59"))
            except ValueError:
                pass
        rows = db.execute(stmt).scalars().all()
        branch_id = int(filter_branch) if filter_branch and filter_branch.isdigit() else None
        agents = []
    else:
        branch_id = get_selected_branch_id(request, user)
        filter_branch = ""
        start_date = ""
        end_date = ""
        stmt = select(Delivery).order_by(desc(Delivery.created_at)).limit(300)
        stmt = stmt.where(Delivery.branch_id == branch_id)
        if status: stmt = stmt.where(Delivery.status == status)
        if agent_id.isdigit(): stmt = stmt.where(Delivery.agent_id == int(agent_id))
        rows = db.execute(stmt).scalars().all()
        agents_stmt = select(User).where(User.role == "AGENT").where(User.branch_id == branch_id).where(User.is_active == True).order_by(User.username.asc())
        agents = db.execute(agents_stmt).scalars().all()

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
        for did, parts in grouped.items():
            items_summary[did] = ", ".join(parts)

    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    sup_kpis = None
    if is_supervisor(user):
        sup_kpis = {
            "total": len(rows),
            "delivered": sum(1 for d in rows if d.status == "DELIVERED"),
            "pending": sum(1 for d in rows if d.status == "PENDING"),
            "in_transit": sum(1 for d in rows if d.status == "OUT_FOR_DELIVERY"),
            "failed": sum(1 for d in rows if d.status in ("FAILED", "RETURNED")),
        }
    # Agent name lookup for display in table
    all_agent_ids = {d.agent_id for d in rows if d.agent_id}
    agent_names: dict[int, str] = {}
    if all_agent_ids:
        for u in db.execute(select(User).where(User.id.in_(all_agent_ids))).scalars().all():
            agent_names[u.id] = u.full_name or u.username

    # Attention flags: deliveries needing action
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

    return tpl(request, "deliveries_list.html", {
        "request": request, "rows": rows, "agents": agents, "status": status,
        "agent_id": agent_id, "items_summary": items_summary,
        "branches": branches, "selected_branch_id": branch_id,
        "branch_id": filter_branch, "start_date": start_date, "end_date": end_date,
        "user": user, "active": "deliveries", "sup_kpis": sup_kpis,
        "agent_names": agent_names,
        "attention_ids": attention_ids,
        "wa_attention_ids": wa_attention_ids,
    })


@router.get("/admin/fix-cash-constraint", response_class=JSONResponse)
def fix_cash_constraint(request: Request, db: Session = Depends(get_db)):
    """One-time: update cash_entries kind constraint to include TRANSFER_PAYMENT."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"})
    user = user_or
    if not is_supervisor(user): return JSONResponse({"error": "forbidden"})
    try:
        with db.bind.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE cash_entries DROP CONSTRAINT IF EXISTS ck_cash_kind"))
            conn.execute(text("ALTER TABLE cash_entries ADD CONSTRAINT ck_cash_kind CHECK (kind IN ('COLLECTION','EXPENSE','OPERATING_CASH','OFFICE_EXPENSE','RETURN_OPERATING_CASH','CASH_PAYMENT','TRANSFER_PAYMENT','COLLECTION_EXPENSE'))"))
        return JSONResponse({"status": "ok", "message": "Constraint updated successfully"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)})


@router.get("/admin/check-env", response_class=JSONResponse)
def check_env(request: Request, db: Session = Depends(get_db)):
    """Supervisor-only: verify environment variables are loaded."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"})
    user = user_or
    if not is_supervisor(user): return JSONResponse({"error": "forbidden"})
    groq = os.getenv("GROQ_API_KEY", "")
    return JSONResponse({
        "GROQ_API_KEY": f"set ({len(groq)} chars)" if groq else "NOT SET",
        "SESSION_SECRET": "set" if os.getenv("SESSION_SECRET") else "NOT SET",
    })


@router.post("/parse-order/api", response_class=JSONResponse)
async def parse_order_api(request: Request, db: Session = Depends(get_db)):
    """Backend proxy — calls Groq API server-side to avoid CORS."""
    limiter.check(request, max_requests=60, window_seconds=60)
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"error": "Not logged in"}, status_code=401)
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return JSONResponse({"error": "Forbidden"}, status_code=403)

    import httpx
    body = await request.json()
    prompt = body.get("prompt", "")
    if not prompt:
        return JSONResponse({"error": "No prompt provided"}, status_code=400)

    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return JSONResponse({"error": "GEMINI_API_KEY not set in Railway environment variables."}, status_code=500)

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}",
                headers={"Content-Type": "application/json"},
                json={
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
            )
        raw_text = resp.text
        data = resp.json()
        if not isinstance(data, dict):
            return JSONResponse({"error": f"Unexpected response: {raw_text[:300]}"}, status_code=500)
        if "error" in data:
            err = data["error"]
            error_msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            return JSONResponse({"error": f"{error_msg} | raw: {raw_text[:200]}"}, status_code=500)
        try:
            parts = data["candidates"][0]["content"]["parts"]
            # Skip thinking parts (thought=True), join all real text parts
            text = "".join(p["text"] for p in parts if p.get("text") and not p.get("thought"))
        except (KeyError, IndexError):
            return JSONResponse({"error": f"Could not read Gemini response | raw: {raw_text[:300]}"}, status_code=500)
        return JSONResponse({"text": text})
    except Exception as e:
        logging.getLogger("parse_order").error("Parse order failed: %s", e)
        return JSONResponse({"error": "Failed to process order. Check server logs."}, status_code=500)


@router.get("/parse-order", response_class=HTMLResponse)
def parse_order_form(request: Request, branch_id: int = 0, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return user_or
    user = user_or
    if not (is_admin(user) or is_supervisor(user)):
        return HTMLResponse("Forbidden", status_code=403)
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
    items_json = [{"id": it.id, "name": it.name, "category": it.category or "", "unit": it.unit or "pcs", "price": float(it.selling_price or 0), "stock": int(stk)} for it, stk in _items_with_stock]
    return tpl(request, "parse_order.html", {
        "request": request, "user": user, "active": "parse_order",
        "agents": agents, "items": items,
        "items_with_stock": _items_with_stock,
        "items_json": items_json,
        "branches": branches, "selected_branch_id": effective_branch_id,
        "today": date.today().isoformat(), "csrf_token": csrf_token,
    })


@router.get("/deliveries/new", response_class=HTMLResponse)
def delivery_new_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    if is_agent(user):
        return HTMLResponse("Forbidden — only admins can create orders", status_code=403)
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
                "AND (asa.qty_assigned - COALESCE(asa.qty_returned, 0)) > 0"
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
                "AND (asa.qty_assigned - COALESCE(asa.qty_returned, 0)) > 0"
            ), {"bid": branch_id}).fetchall()
        for r in rows_a:
            pending_assignments.setdefault(r[1], []).append({
                "id": r[0], "item_id": r[2], "qty": r[3],
                "note": r[4] or "", "item_name": r[5],
            })
    csrf_token = get_csrf_token(request)
    return tpl(request, "delivery_new.html", {
        "request": request, "agents": agents, "items": items, "user": user,
        "active": "deliveries_new", "branches": branches, "selected_branch_id": branch_id,
        "today": date.today().isoformat(), "csrf_token": csrf_token,
        "pending_assignments": pending_assignments,
    })


@router.post("/deliveries/new")
async def delivery_create(
    request: Request,
    agent_id: int | None = Form(None),
    branch_id: int | None = Form(None),
    customer_name: str = Form(...),
    customer_phone: str = Form(""),
    address: str = Form(""),
    note: str = Form(""),
    delivery_date: str = Form(""),
    item_id: list[int] = Form(...),
    quantity: list[int] = Form(...),
    line_amount: list[float] = Form(default=[]),
    assignment_ids: list[int] = Form(default=[]),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    verify_csrf_token(request, csrf_token)
    if is_supervisor(user):
        # Supervisor creates unassigned order for a specific branch
        # Find the admin of that branch to assign, or leave agent_id as None
        if not branch_id:
            raise HTTPException(status_code=400, detail="Branch required")
        # Assign to first admin of the branch (they will re-delegate to agents)
        branch_admin = db.scalar(select(User).where(User.role == "ADMIN").where(User.branch_id == branch_id).where(User.is_active == True))
        target_agent_id = branch_admin.id if branch_admin else None
        if not target_agent_id:
            raise HTTPException(status_code=400, detail="No admin found for selected branch")
    elif is_admin(user):
        if agent_id is None:
            raise HTTPException(status_code=422, detail="agent_id required for admin")
        target_agent_id = int(agent_id)
        branch_id = get_current_branch_id(request)
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
    d = Delivery(
        branch_id=branch_id, agent_id=target_agent_id, customer_name=cust,
        customer_phone=sanitize_phone(customer_phone) or None,
        address=sanitize_text(address, 300, "Address") or None,
        note=sanitize_text(note, 400, "Note") or None,
        status="PENDING", delivery_date=d_date,
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
    tx_item_ids = set()  # track items we've already created an OUT tx for
    for iid, qty, amt in zip(item_id, quantity, amounts):
        q = int(qty) if qty is not None else 0
        if q > 0:
            db.add(DeliveryItem(delivery_id=d.id, item_id=int(iid), quantity=q, line_amount=float(amt or 0)))
            # Supervisor-created orders: no OUT transaction — stock only leaves when
            # the branch admin assigns the delivery to an agent.
            if is_supervisor(user):
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
        db_name_lower = (d.customer_name or "").lower()
        db_phone_clean = (d.customer_phone or "").replace(" ", "").replace("-", "")
        db_phone_digits = db_phone_clean[-10:] if db_phone_clean else ""

        pending_rows = db.execute(text(
            "SELECT message_id, body, sender, group_jid, customer_name, customer_phone "
            "FROM wa_pending_cache ORDER BY created_at DESC LIMIT 50"
        )).fetchall()

        for pr in pending_rows:
            p_mid, p_body, p_sender, p_gjid, p_cname, p_cphone = pr[0], pr[1], pr[2], pr[3], pr[4], pr[5]

            # Phone check
            p_phone_digits = (p_cphone or "").replace(" ", "").replace("-", "")[-10:]
            phone_ok = (db_phone_digits and p_phone_digits and len(p_phone_digits) >= 10
                        and db_phone_digits == p_phone_digits)

            # Name check
            name_ok = False
            if p_cname and db_name_lower and len(p_cname) > 3:
                p_words = [w for w in p_cname.split() if len(w) > 2]
                if len(p_words) >= 2 and all(w in db_name_lower for w in p_words):
                    name_ok = True
                elif p_cname == db_name_lower:
                    name_ok = True

            # Phone is the strongest signal — always trust it
            if p_cphone:
                matched = phone_ok
            elif p_cname:
                matched = name_ok
            else:
                matched = False

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
    trigger_call(d.id, d.customer_phone, "PENDING", d.customer_name, items_summary, d.address or "")

    # Auto-send WhatsApp template to customer when delivery is created
    if d.customer_phone:
        try:
            submit_task(send_whatsapp_fallback, d.id, d.customer_phone, d.customer_name or "Customer", items_summary)
        except Exception as e:
            logging.getLogger("whatsapp").warning("Failed to queue WA template for delivery #%s: %s", d.id, e)

    return redirect(f"/deliveries/{d.id}")



# ────────────────────────────────────────────────
