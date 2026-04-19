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

#  AGENT VETTING
# ────────────────────────────────────────────────

@router.post("/vetting/assign-stock", response_class=JSONResponse)
async def assign_stock_to_agent(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """Admin assigns extra stock to an agent for urgent deliveries.
    Creates an OUT transaction immediately — stock leaves branch.
    """
    body     = await request.json()
    agent_id = body.get("agent_id")
    item_id  = body.get("item_id")
    qty      = int(body.get("qty", 0))
    note     = (body.get("note", "") or "").strip()[:400]
    if not agent_id or not item_id or qty <= 0:
        return JSONResponse({"error": "agent, item and qty required"}, status_code=400)

    branch_id = get_selected_branch_id(request, user)
    item  = db.get(Item, item_id)
    agent = db.get(User, agent_id)
    if not item or item.branch_id != branch_id:
        return JSONResponse({"error": "item not found in this branch"}, status_code=404)
    if not agent or agent.branch_id != branch_id or agent.role != "AGENT":
        return JSONResponse({"error": "agent not found in this branch"}, status_code=404)

    # Create OUT transaction immediately
    tx = Transaction(
        branch_id=branch_id, item_id=item_id, type="OUT", quantity=qty,
        note=f"Extra stock assigned to agent {agent.full_name or agent.username}{': ' + note if note else ''}",
        reference=f"agent-assign-{agent_id}",
    )
    db.add(tx)
    db.flush()

    # Record the assignment
    db.execute(text(
        "INSERT INTO agent_stock_assignments "
        "(agent_id, item_id, branch_id, qty_assigned, note, assigned_by, assigned_at, returned, qty_returned, transaction_out_id) "
        "VALUES (:aid, :iid, :bid, :qty, :note, :uid, :_now, FALSE, 0, :txid)"
    ), {"aid": agent_id, "iid": item_id, "bid": branch_id, "qty": qty,
        "note": note, "uid": user.id, "txid": tx.id, "_now": _now()})

    audit_log(db, user.id, "STOCK_ASSIGNED_TO_AGENT",
              f"agent={agent.username} item={item.name} qty={qty}",
              ip=request.client.host if request.client else "")

    # Notify agent
    notify(db, agent_id, "📦 Stock Assigned to You",
           f"{qty} × {item.name} assigned by admin for urgent delivery",
           "/my-deliveries", "info")
    db.commit()
    return JSONResponse({"ok": True, "item_name": item.name, "agent_name": agent.full_name or agent.username, "qty": qty, "tx_id": tx.id})


@router.post("/vetting/return-assigned-stock", response_class=JSONResponse)
async def return_assigned_stock(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """Admin vets return of extra stock assigned to agent.
    Full return → creates IN tx, marks returned=TRUE
    Partial return → creates IN tx for what came back, updates qty_returned but keeps returned=FALSE for shortfall resolution
    """
    body          = await request.json()
    assignment_id = body.get("assignment_id")
    qty_returned  = int(body.get("qty_returned", 0))
    if not assignment_id or qty_returned < 0:
        return JSONResponse({"error": "invalid params"}, status_code=400)

    row = db.execute(text(
        "SELECT id, agent_id, item_id, branch_id, qty_assigned, note, COALESCE(writeoff_qty, 0) "
        "FROM agent_stock_assignments "
        "WHERE id = :aid AND returned = FALSE"
    ), {"aid": assignment_id}).fetchone()
    if not row:
        return JSONResponse({"error": "assignment not found or already returned"}, status_code=404)
    asgn_id, agent_id, item_id, branch_id, qty_assigned, asgn_note, existing_writeoff = row

    if branch_id != user.branch_id:
        return JSONResponse({"error": "forbidden — different branch"}, status_code=403)

    item  = db.get(Item, item_id)
    agent = db.get(User, agent_id)
    tx_in_id = None
    # Account for already written-off qty when checking if this return completes the assignment
    effective_assigned = qty_assigned - existing_writeoff
    actual_return = min(qty_returned, effective_assigned)
    is_full = actual_return >= effective_assigned

    if actual_return > 0:
        tx = Transaction(
            branch_id=branch_id, item_id=item_id, type="IN", quantity=actual_return,
            note=f"Assigned stock returned by {agent.full_name or agent.username if agent else 'agent'}",
            reference=f"agent-return-{assignment_id}",
        )
        db.add(tx)
        db.flush()
        tx_in_id = tx.id

    if is_full:
        # Full return (accounting for write-offs) — mark complete
        db.execute(text(
            "UPDATE agent_stock_assignments SET returned=TRUE, qty_returned=:qty, "
            "vetted_by=:uid, vetted_at=:_now, transaction_in_id=:txid WHERE id=:aid"
        ), {"qty": existing_writeoff + actual_return, "uid": user.id, "txid": tx_in_id, "aid": asgn_id, "_now": _now()})
    else:
        # Partial — update qty_returned but keep returned=FALSE for shortfall resolution
        db.execute(text(
            "UPDATE agent_stock_assignments SET qty_returned=:qty, "
            "vetted_by=:uid, vetted_at=:_now, transaction_in_id=:txid WHERE id=:aid"
        ), {"qty": existing_writeoff + actual_return, "uid": user.id, "txid": tx_in_id, "aid": asgn_id, "_now": _now()})

    audit_log(db, user.id, "ASSIGNED_STOCK_RETURNED",
              f"assignment_id={asgn_id} item={item.name if item else item_id} qty_returned={actual_return}/{qty_assigned} writeoff={existing_writeoff}",
              ip=request.client.host if request.client else "")
    db.commit()
    remaining_shortfall = max(0, qty_assigned - (existing_writeoff + actual_return)) if not is_full else 0
    return JSONResponse({"ok": True, "item_name": item.name if item else "Item",
                         "qty_returned": actual_return, "qty_assigned": qty_assigned,
                         "is_full": is_full, "remaining_shortfall": remaining_shortfall})


@router.post("/vetting/resolve-assign-shortfall", response_class=JSONResponse)
async def resolve_assign_shortfall(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """Resolve shortfall on an assigned stock return.
    action='returned'    → agent brought back more; creates IN tx
    action='written_off' → accept loss; no IN tx; mark complete
    """
    body          = await request.json()
    assignment_id = body.get("assignment_id")
    action        = body.get("action", "")
    qty_resolved  = int(body.get("qty_resolved", 0))
    writeoff_note = str(body.get("note", "")).strip()
    if not assignment_id or action not in ("returned", "written_off"):
        return JSONResponse({"error": "invalid params"}, status_code=400)

    row = db.execute(text(
        "SELECT id, agent_id, item_id, branch_id, qty_assigned, qty_returned, COALESCE(writeoff_qty, 0) "
        "FROM agent_stock_assignments "
        "WHERE id = :aid AND returned = FALSE"
    ), {"aid": assignment_id}).fetchone()
    if not row:
        return JSONResponse({"error": "assignment not found or already resolved"}, status_code=404)
    asgn_id, agent_id, item_id, branch_id, qty_assigned, qty_already_returned, existing_writeoff = row
    current_shortfall = max(0, qty_assigned - qty_already_returned)

    if branch_id != user.branch_id:
        return JSONResponse({"error": "forbidden — different branch"}, status_code=403)

    item = db.get(Item, item_id)

    if action == "returned":
        qty_to_credit = min(qty_resolved, current_shortfall) if qty_resolved > 0 else current_shortfall
        new_total = qty_already_returned + qty_to_credit
        remaining = max(0, qty_assigned - new_total)

        if qty_to_credit > 0:
            tx = Transaction(
                branch_id=branch_id, item_id=item_id, type="IN", quantity=qty_to_credit,
                note=f"Shortfall resolved — assigned stock returned by agent",
                reference=f"agent-shortfall-{assignment_id}",
            )
            db.add(tx)
            db.flush()

        if remaining == 0:
            db.execute(text(
                "UPDATE agent_stock_assignments SET returned=TRUE, qty_returned=:qty, "
                "vetted_by=:uid, vetted_at=:_now WHERE id=:aid"
            ), {"qty": new_total, "uid": user.id, "aid": asgn_id, "_now": _now()})
        else:
            db.execute(text(
                "UPDATE agent_stock_assignments SET qty_returned=:qty WHERE id=:aid"
            ), {"qty": new_total, "aid": asgn_id})

        audit_log(db, user.id, "ASSIGN_SHORTFALL_RESOLVED",
                  f"assignment_id={asgn_id} item={item.name if item else item_id} credited={qty_to_credit} remaining={remaining}",
                  ip=request.client.host if request.client else "")
        db.commit()
        notify(db, agent_id,
            "✅ Assignment Shortfall Resolved" if remaining == 0 else "⚠ Partial Assignment Shortfall Resolved",
            f"{item.name if item else 'Stock'}: {qty_to_credit} unit(s) credited back." + (f" {remaining} still outstanding." if remaining else ""),
            "/my-deliveries", "success" if remaining == 0 else "warning")
        return JSONResponse({"ok": True, "item_name": item.name if item else "Item",
                             "remaining_shortfall": remaining, "action": "returned"})

    else:  # written_off
        qty_to_writeoff = min(qty_resolved, current_shortfall) if qty_resolved > 0 else current_shortfall
        new_total = qty_already_returned + qty_to_writeoff
        remaining = max(0, qty_assigned - new_total)
        # Accumulate writeoff_qty (don't overwrite — may be a second partial write-off)
        total_writeoff = existing_writeoff + qty_to_writeoff
        # Append note to existing note if there's already one
        combined_note = writeoff_note or ""
        if existing_writeoff > 0 and writeoff_note:
            # Fetch existing note to append
            _existing_note = db.execute(text(
                "SELECT writeoff_note FROM agent_stock_assignments WHERE id = :aid"
            ), {"aid": asgn_id}).scalar() or ""
            if _existing_note:
                combined_note = _existing_note + "; " + writeoff_note

        if remaining == 0:
            db.execute(text(
                "UPDATE agent_stock_assignments SET returned=TRUE, qty_returned=:qty, "
                "resolve_action='written_off', writeoff_note=:note, writeoff_qty=:wq, "
                "vetted_by=:uid, vetted_at=:_now WHERE id=:aid"
            ), {"qty": new_total, "uid": user.id, "aid": asgn_id, "_now": _now(), "note": combined_note, "wq": total_writeoff})
        else:
            # Partial write-off — reduce shortfall but keep record open
            db.execute(text(
                "UPDATE agent_stock_assignments SET qty_returned=:qty, resolve_action='written_off', writeoff_qty=:wq, writeoff_note=:note, "
                "vetted_by=:uid, vetted_at=:_now WHERE id=:aid"
            ), {"qty": new_total, "aid": asgn_id, "wq": total_writeoff, "note": combined_note, "uid": user.id, "_now": _now()})

        audit_log(db, user.id, "ASSIGN_SHORTFALL_WRITTEN_OFF",
                  f"assignment_id={asgn_id} item={item.name if item else item_id} qty_lost={qty_to_writeoff} remaining={remaining}" + (f" note={writeoff_note}" if writeoff_note else ""),
                  ip=request.client.host if request.client else "")
        db.commit()
        notify(db, agent_id,
            "📋 Assignment Written Off" if remaining == 0 else "📋 Partial Write-Off Recorded",
            f"{item.name if item else 'Stock'}: {qty_to_writeoff} unit(s) written off." + (f" {remaining} still outstanding." if remaining else ""),
            "/my-deliveries", "info")
        return JSONResponse({"ok": True, "item_name": item.name if item else "Item",
                             "qty_lost": qty_to_writeoff, "remaining_shortfall": remaining,
                             "action": "written_off"})


@router.post("/vetting/confirm-return", response_class=JSONResponse)
async def vetting_confirm_return(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """Vet stock return for a specific delivery item.
    - Full return  (qty_returned == original_qty) → resolved, done
    - Partial/zero return → stock credited for what came back,
      shortfall stays visible with ⚠ Missing badge until admin resolves it
    """
    body             = await request.json()
    delivery_item_id = body.get("delivery_item_id")
    qty_returned     = int(body.get("qty_returned", 0))
    delivery_id      = body.get("delivery_id")
    if not delivery_item_id or qty_returned < 0:
        return JSONResponse({"error": "invalid params"}, status_code=400)

    # Prevent double-vetting on unresolved records
    existing = db.execute(text(
        "SELECT id FROM stock_return_vettings "
        "WHERE delivery_item_id = :diid AND (resolved IS NULL OR resolved = FALSE) "
        "ORDER BY created_at DESC LIMIT 1"
    ), {"diid": delivery_item_id}).fetchone()
    if existing:
        return JSONResponse({"error": "already vetted — use Resolve button to update missing stock"}, status_code=400)

    # Get the delivery item + item info
    di_row = db.execute(
        select(DeliveryItem, Item)
        .join(Item, Item.id == DeliveryItem.item_id)
        .where(DeliveryItem.id == delivery_item_id)
    ).first()
    if not di_row:
        return JSONResponse({"error": "item not found"}, status_code=404)
    di, item = di_row

    original_qty = di.quantity
    shortfall    = max(0, original_qty - qty_returned)
    is_full      = shortfall == 0

    tx_id = None
    if qty_returned > 0:
        tx = Transaction(
            branch_id=user.branch_id,
            item_id=di.item_id,
            type="IN",
            quantity=qty_returned,
            note=f"Stock returned — delivery #{delivery_id} vetted by {user.username}",
            reference=f"return-vet-{delivery_id}",
            delivery_id=delivery_id,
        )
        db.add(tx)
        db.flush()
        tx_id = tx.id

    # resolved=TRUE only when all stock accounted for
    db.execute(text(
        "INSERT INTO stock_return_vettings "
        "(delivery_id, delivery_item_id, vetted_by, qty_returned, transaction_id, created_at, resolved) "
        "VALUES (:did, :diid, :uid, :qty, :txid, :_now, :resolved)"
    ), {"did": delivery_id, "diid": delivery_item_id, "uid": user.id,
        "qty": qty_returned, "txid": tx_id, "resolved": is_full, "_now": _now()})

    audit_log(db, user.id, "STOCK_RETURN_VETTED",
              f"delivery_id={delivery_id} item={item.name} returned={qty_returned}/{original_qty} shortfall={shortfall}",
              ip=request.client.host if request.client else "")

    if qty_returned > 0:
        delivery_obj = db.get(Delivery, delivery_id)
        agent_uid = delivery_obj.agent_id if delivery_obj else user.id
        notify(db, agent_uid,
               "📦 Stock Return Confirmed" if is_full else "⚠ Partial Return Recorded",
               f"{item.name}: {qty_returned}/{original_qty} returned" + (f" — {shortfall} still missing" if shortfall else ""),
               f"/deliveries/{delivery_id}", "success" if is_full else "warning")

    db.commit()
    return JSONResponse({
        "ok": True,
        "item_name": item.name,
        "qty_returned": qty_returned,
        "original_qty": original_qty,
        "shortfall": shortfall,
        "is_full": is_full,
        "tx_id": tx_id,
    })


@router.post("/vetting/resolve-shortfall", response_class=JSONResponse)
async def vetting_resolve_shortfall(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """Admin resolves a missing stock shortfall.
    action='returned'   → admin provides qty_resolved; creates IN tx; if still short, keeps record open
    action='written_off'→ marks missing qty as lost; no IN tx; marks fully resolved
    Can be called multiple times for partial resolutions.
    """
    body             = await request.json()
    delivery_item_id = body.get("delivery_item_id")
    action           = body.get("action", "")   # "returned" | "written_off"
    delivery_id      = body.get("delivery_id")
    qty_resolved     = int(body.get("qty_resolved", 0))
    writeoff_note    = str(body.get("note", "")).strip()

    if not delivery_item_id or action not in ("returned", "written_off"):
        return JSONResponse({"error": "invalid params — action must be returned or written_off"}, status_code=400)

    # Find the unresolved vetting record
    vet_row = db.execute(text(
        "SELECT id, qty_returned FROM stock_return_vettings "
        "WHERE delivery_item_id = :diid AND (resolved IS NULL OR resolved = FALSE) "
        "ORDER BY created_at DESC LIMIT 1"
    ), {"diid": delivery_item_id}).fetchone()
    if not vet_row:
        return JSONResponse({"error": "no unresolved record found"}, status_code=404)
    vet_id, qty_already_returned = vet_row[0], vet_row[1]

    # Get item info
    di_row = db.execute(
        select(DeliveryItem, Item)
        .join(Item, Item.id == DeliveryItem.item_id)
        .where(DeliveryItem.id == delivery_item_id)
    ).first()
    if not di_row:
        return JSONResponse({"error": "delivery item not found"}, status_code=404)
    di, item     = di_row
    current_shortfall = max(0, di.quantity - qty_already_returned)

    if action == "returned":
        # Clamp qty_resolved to current shortfall
        qty_to_credit = min(qty_resolved, current_shortfall) if qty_resolved > 0 else current_shortfall
        new_total_returned = qty_already_returned + qty_to_credit
        remaining_shortfall = max(0, di.quantity - new_total_returned)
        is_fully_resolved = remaining_shortfall == 0

        if qty_to_credit > 0:
            tx = Transaction(
                branch_id=user.branch_id,
                item_id=di.item_id,
                type="IN",
                quantity=qty_to_credit,
                note=f"Partial shortfall resolved — delivery #{delivery_id}, {qty_to_credit} returned, confirmed by {user.username}",
                reference=f"shortfall-{delivery_id}",
                delivery_id=delivery_id,
            )
            db.add(tx)
            db.flush()

        if is_fully_resolved:
            # All accounted for — mark resolved
            db.execute(text(
                "UPDATE stock_return_vettings SET resolved=TRUE, resolve_action='returned', "
                "qty_returned=:newqty, resolved_at=:_now, resolved_by=:uid WHERE id=:vid"
            ), {"newqty": new_total_returned, "uid": user.id, "vid": vet_id, "_now": _now()})
        else:
            # Still some missing — update qty_returned, keep unresolved
            db.execute(text(
                "UPDATE stock_return_vettings SET qty_returned=:newqty WHERE id=:vid"
            ), {"newqty": new_total_returned, "vid": vet_id})

        audit_log(db, user.id, "SHORTFALL_PARTIAL_RESOLVED" if not is_fully_resolved else "SHORTFALL_RESOLVED",
                  f"delivery_id={delivery_id} item={item.name} credited={qty_to_credit} remaining={remaining_shortfall}",
                  ip=request.client.host if request.client else "")
        db.commit()
        _delivery = db.get(Delivery, delivery_id) if delivery_id else None
        if _delivery and _delivery.agent_id:
            notify(db, _delivery.agent_id,
                "✅ Shortfall Resolved" if is_fully_resolved else "⚠ Partial Shortfall Resolved",
                f"{item.name}: {qty_to_credit} unit(s) credited back." + (f" {remaining_shortfall} still outstanding." if remaining_shortfall else ""),
                f"/deliveries/{delivery_id}", "success" if is_fully_resolved else "warning")
        return JSONResponse({
            "ok": True,
            "item_name": item.name,
            "qty_credited": qty_to_credit,
            "new_total_returned": new_total_returned,
            "remaining_shortfall": remaining_shortfall,
            "is_fully_resolved": is_fully_resolved,
            "action": "returned",
        })

    else:  # written_off
        qty_to_writeoff = min(qty_resolved, current_shortfall) if qty_resolved > 0 else current_shortfall
        new_total_returned = qty_already_returned + qty_to_writeoff
        remaining_shortfall = max(0, di.quantity - new_total_returned)
        is_fully_resolved = remaining_shortfall == 0

        if is_fully_resolved:
            db.execute(text(
                "UPDATE stock_return_vettings SET resolved=TRUE, resolve_action='written_off', "
                "qty_returned=:newqty, writeoff_qty=:wq, writeoff_note=:note, resolved_at=:_now, resolved_by=:uid WHERE id=:vid"
            ), {"newqty": new_total_returned, "wq": qty_to_writeoff, "note": writeoff_note or "", "uid": user.id, "vid": vet_id, "_now": _now()})
        else:
            # Partial write-off — reduce shortfall but keep record open for further action
            db.execute(text(
                "UPDATE stock_return_vettings SET qty_returned=:newqty, writeoff_qty=:wq, writeoff_note=:note WHERE id=:vid"
            ), {"newqty": new_total_returned, "vid": vet_id, "wq": qty_to_writeoff, "note": writeoff_note or ""})

        audit_log(db, user.id, "SHORTFALL_WRITTEN_OFF",
                  f"delivery_id={delivery_id} item={item.name} qty_lost={qty_to_writeoff} remaining={remaining_shortfall}" + (f" note={writeoff_note}" if writeoff_note else ""),
                  ip=request.client.host if request.client else "")
        db.commit()
        _delivery = db.get(Delivery, delivery_id) if delivery_id else None
        if _delivery and _delivery.agent_id:
            notify(db, _delivery.agent_id,
                "📋 Shortfall Written Off" if is_fully_resolved else "📋 Partial Write-Off Recorded",
                f"{item.name}: {qty_to_writeoff} unit(s) written off." + (f" {remaining_shortfall} still outstanding." if remaining_shortfall else ""),
                f"/deliveries/{delivery_id}", "info")
        return JSONResponse({
            "ok": True,
            "item_name": item.name,
            "qty_lost": qty_to_writeoff,
            "remaining_shortfall": remaining_shortfall,
            "is_fully_resolved": is_fully_resolved,
            "action": "written_off",
        })


@router.get("/vetting", response_class=HTMLResponse)
def vetting_page(request: Request, date_filter: str = "", agent_id: str = "", db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    branch_id = get_selected_branch_id(request, user)

    # Date filter
    if date_filter:
        try:
            filter_date = datetime.strptime(date_filter, "%Y-%m-%d").date()
        except ValueError:
            filter_date = date.today()
    else:
        filter_date = date.today()

    day_start = datetime.combine(filter_date, datetime.min.time())
    day_end   = day_start + timedelta(days=1)

    # All agents in this branch
    agents = db.execute(
        select(User).where(User.role == "AGENT").where(User.branch_id == branch_id)
        .where(User.is_active == True).order_by(User.username.asc())
    ).scalars().all()

    selected_agent_id = int(agent_id) if agent_id and agent_id.isdigit() else None

    # Build vetting rows per agent
    vetting_rows = []
    for agent in agents:
        if selected_agent_id and agent.id != selected_agent_id:
            continue

        entries = db.execute(
            select(CashEntry).where(CashEntry.agent_id == agent.id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind.in_(["COLLECTION", "CASH_PAYMENT", "TRANSFER_PAYMENT"]))
            .where(CashEntry.created_at >= day_start)
            .where(CashEntry.created_at < day_end)
            .order_by(CashEntry.created_at.desc())
        ).scalars().all()

        if not entries:
            continue

        cash_total     = sum(float(e.amount) for e in entries if e.kind in ("COLLECTION", "CASH_PAYMENT"))
        transfer_total = sum(float(e.amount) for e in entries if e.kind == "TRANSFER_PAYMENT")
        total          = cash_total + transfer_total
        confirmed      = all(getattr(e, 'confirmed_by_admin', False) for e in entries)
        confirmed_count = sum(1 for e in entries if getattr(e, 'confirmed_by_admin', False))

        # Get linked deliveries for these entries
        delivery_ids = list({e.delivery_id for e in entries if e.delivery_id})
        deliveries = {}
        if delivery_ids:
            for d in db.execute(select(Delivery).where(Delivery.id.in_(delivery_ids))).scalars().all():
                deliveries[d.id] = d

        vetting_rows.append({
            "agent":           agent,
            "entries":         entries,
            "deliveries":      deliveries,
            "cash_total":      cash_total,
            "transfer_total":  transfer_total,
            "total":           total,
            "confirmed":       confirmed,
            "confirmed_count": confirmed_count,
            "total_count":     len(entries),
        })

    # ── Stock return section ──────────────────────────────────────────────
    # Unsuccessful deliveries needing stock return vetting (all time, not date filtered)
    unvetted_statuses = ["FAILED", "RETURNED", "ADJUSTMENT_PENDING"]
    unsuccessful = db.execute(
        select(Delivery)
        .where(Delivery.branch_id == branch_id)
        .where(Delivery.status.in_(unvetted_statuses))
        .order_by(Delivery.created_at.desc())
        .limit(100)
    ).scalars().all()

    # Also include any delivery that has unresolved vetting records
    # (e.g. from adjustment-removed items where delivery is still OUT_FOR_DELIVERY)
    existing_ids = {d.id for d in unsuccessful}
    unresolved_delivery_ids = db.execute(text(
        "SELECT DISTINCT srv.delivery_id FROM stock_return_vettings srv "
        "JOIN deliveries d ON d.id = srv.delivery_id "
        "WHERE (srv.resolved IS NULL OR srv.resolved = FALSE) "
        "AND d.branch_id = :bid AND d.status NOT IN ('FAILED','RETURNED','ADJUSTMENT_PENDING')"
    ), {"bid": branch_id}).fetchall()
    extra_delivery_ids = [r[0] for r in unresolved_delivery_ids if r[0] not in existing_ids]
    if extra_delivery_ids:
        extra_deliveries = db.execute(
            select(Delivery).where(Delivery.id.in_(extra_delivery_ids))
        ).scalars().all()
    else:
        extra_deliveries = []

    # Build return rows
    all_return_deliveries = {d.id: d for d in unsuccessful + extra_deliveries}
    return_rows = []
    for d in list(unsuccessful) + list(extra_deliveries):
        if d.id in {r["delivery_id"] for r in return_rows}:
            continue
        d_items = db.execute(
            select(DeliveryItem, Item)
            .join(Item, Item.id == DeliveryItem.item_id)
            .where(DeliveryItem.delivery_id == d.id)
        ).all()
        if not d_items:
            continue

        # Fetch vetting records for ALL items in this delivery (any date)
        # resolved=TRUE  → fully settled (full return or written off)
        # resolved=FALSE → vetted but shortfall exists — stays visible
        # no record      → not yet vetted
        vet_rows = db.execute(text(
            "SELECT delivery_item_id, qty_returned, resolved, resolve_action "
            "FROM stock_return_vettings "
            "WHERE delivery_id = :did "
            "ORDER BY created_at DESC"
        ), {"did": d.id}).fetchall()

        # Keep only the latest vetting per delivery_item_id
        vet_map = {}
        for vr in vet_rows:
            if vr[0] not in vet_map:
                vet_map[vr[0]] = {"qty_returned": vr[1], "resolved": vr[2], "resolve_action": vr[3]}

        agent_u = db.get(User, d.agent_id) if d.agent_id else None
        items_to_vet = []
        # Only show items WITH a vetting record for active and delivered deliveries.
        # For FAILED/RETURNED the agent brought everything back so all items need vetting.
        only_vetted_items = d.status in ("OUT_FOR_DELIVERY", "DELIVERED")
        for di, it in d_items:
            # For DELIVERED deliveries, skip items with line_amount > 0 — those were
            # successfully sold to the customer. Only line_amount == 0 items were refused
            # via adjustment approval and actually need stock-return vetting.
            if d.status == "DELIVERED" and float(di.line_amount or 0) > 0:
                continue
            vet = vet_map.get(di.id)
            if vet is None:
                if only_vetted_items:
                    continue  # Skip items without vetting record on active deliveries
                # Not vetted at all yet
                status_flag = "unvetted"
                shortfall   = di.quantity
                qty_back    = 0
            elif vet["resolved"]:
                # Fully settled — full return or written off
                status_flag    = "resolved"
                qty_back       = vet["qty_returned"]
                shortfall      = 0
                resolve_action = vet["resolve_action"]
            else:
                # Vetted but shortfall remains
                qty_back    = vet["qty_returned"]
                shortfall   = max(0, di.quantity - qty_back)
                status_flag = "shortfall" if shortfall > 0 else "resolved"

            items_to_vet.append({
                "di_id":      di.id,
                "item_name":  it.name,
                "qty":        di.quantity,
                "qty_back":   qty_back if vet else 0,
                "shortfall":  shortfall if vet else di.quantity,
                "status":     status_flag,   # unvetted | shortfall | resolved
                "vetted":     status_flag in ("resolved", "shortfall"),  # True if any vetting record exists
                "has_shortfall": status_flag == "shortfall",
                "resolve_action": vet["resolve_action"] if (vet and vet.get("resolved")) else None,
            })

        # Card is fully done only when every item is resolved
        all_resolved = all(i["status"] == "resolved" for i in items_to_vet)
        has_shortfall = any(i["status"] == "shortfall" for i in items_to_vet)

        # Skip if completely resolved
        if all_resolved:
            continue

        return_rows.append({
            "delivery":    d,
            "delivery_id": d.id,
            "agent_name":  (agent_u.full_name or agent_u.username) if agent_u else "Unknown",
            "status":      d.status,
            "is_overdue":  False,
            "item_lines":  items_to_vet,
            "all_vetted":  all_resolved,
            "has_shortfall": has_shortfall,
        })

    # ── Extra stock assignments — unvetted returns ───────────────────────
    # Show all unvetted (not returned) assignments for this branch
    assignment_rows = db.execute(text("""
        SELECT
            asa.id, asa.qty_assigned, asa.note, asa.assigned_at, asa.qty_returned,
            it.id AS item_id, it.name AS item_name,
            u_agent.id AS agent_id,
            u_agent.full_name AS agent_name, u_agent.username AS agent_username,
            u_assigner.full_name AS assigned_by_name, u_assigner.username AS assigned_by_username,
            COALESCE(asa.writeoff_qty, 0) AS writeoff_qty
        FROM agent_stock_assignments asa
        JOIN items it           ON it.id    = asa.item_id
        JOIN users u_agent      ON u_agent.id = asa.agent_id
        LEFT JOIN users u_assigner ON u_assigner.id = asa.assigned_by
        WHERE asa.branch_id = :bid AND asa.returned = FALSE
          AND (asa.delivery_id IS NULL)
        ORDER BY asa.assigned_at DESC
        LIMIT 100
    """), {"bid": branch_id}).fetchall()

    # ── Available items for stock assignment form ─────────────────────
    assign_items = get_items_with_stock(db, branch_id=branch_id)

    # ── Written-off records (for summary card at top) ────────────────────
    written_off_rows = db.execute(text("""
        SELECT
            srv.id, srv.qty_returned, srv.resolved_at,
            di.quantity AS original_qty,
            COALESCE(NULLIF(srv.writeoff_qty, 0), di.quantity - srv.qty_returned) AS qty_lost,
            it.name AS item_name,
            d.id AS delivery_id, d.customer_name,
            u_agent.full_name AS agent_name, u_agent.username AS agent_username,
            u_res.full_name AS resolved_by_name, u_res.username AS resolved_by_username,
            'delivery' AS source,
            COALESCE(srv.writeoff_note, '') AS reason
        FROM stock_return_vettings srv
        JOIN delivery_items di ON di.id = srv.delivery_item_id
        JOIN items it          ON it.id = di.item_id
        JOIN deliveries d      ON d.id  = srv.delivery_id
        LEFT JOIN users u_agent ON u_agent.id = d.agent_id
        LEFT JOIN users u_res   ON u_res.id   = srv.resolved_by
        WHERE srv.resolve_action = 'written_off'
          AND it.branch_id = :bid

        UNION ALL

        SELECT
            asa.id, asa.qty_returned, asa.vetted_at AS resolved_at,
            asa.qty_assigned AS original_qty,
            COALESCE(NULLIF(asa.writeoff_qty, 0), asa.qty_assigned - asa.qty_returned) AS qty_lost,
            it.name AS item_name,
            COALESCE(asa.delivery_id, 0) AS delivery_id,
            'Assigned Stock' AS customer_name,
            u_agent.full_name AS agent_name, u_agent.username AS agent_username,
            u_vet.full_name AS resolved_by_name, u_vet.username AS resolved_by_username,
            'assignment' AS source,
            COALESCE(asa.writeoff_note, '') AS reason
        FROM agent_stock_assignments asa
        JOIN items it         ON it.id = asa.item_id
        JOIN users u_agent    ON u_agent.id = asa.agent_id
        LEFT JOIN users u_vet ON u_vet.id = asa.vetted_by
        WHERE asa.resolve_action = 'written_off'
          AND asa.branch_id = :bid

        ORDER BY resolved_at DESC
        LIMIT 100
    """), {"bid": branch_id}).fetchall()

    # ── Return operating cash — unconfirmed returns ──────────────────────
    # Show per-agent unconfirmed RETURN_OPERATING_CASH entries for admin to vet
    return_op_rows = []
    for agent in agents:
        if selected_agent_id and agent.id != selected_agent_id:
            continue
        ret_entries = db.execute(
            select(CashEntry)
            .where(CashEntry.agent_id == agent.id)
            .where(CashEntry.branch_id == branch_id)
            .where(CashEntry.kind == "RETURN_OPERATING_CASH")
            .where(CashEntry.confirmed_by_admin == False)  # noqa: E712
            .order_by(CashEntry.created_at.desc())
        ).scalars().all()
        if not ret_entries:
            continue
        return_op_rows.append({
            "agent":   agent,
            "entries": ret_entries,
            "total":   sum(float(e.amount) for e in ret_entries),
        })

    csrf_token = get_csrf_token(request)
    return tpl(request, "vetting.html", {
        "request": request, "user": user, "active": "vetting",
        "vetting_rows": vetting_rows, "agents": agents,
        "filter_date": filter_date.isoformat() if filter_date else "",
        "selected_agent_id": selected_agent_id,
        "today": date.today().isoformat(),
        "csrf_token": csrf_token,
        "return_rows": return_rows,
        "written_off_rows": written_off_rows,
        "assignment_rows": assignment_rows,
        "assign_items": assign_items,
        "return_op_rows": return_op_rows,
    })


@router.post("/vetting/confirm", response_class=JSONResponse)
async def vetting_confirm(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN"))):
    """Confirm all cash entries for an agent on a given date."""
    body = await request.json()
    agent_id  = body.get("agent_id")
    date_str  = body.get("date")
    entry_ids = body.get("entry_ids", [])  # specific entries or all for that agent/date
    if not agent_id or not date_str:
        return JSONResponse({"error": "missing agent_id or date"}, status_code=400)
    try:
        filter_date = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return JSONResponse({"error": "invalid date"}, status_code=400)
    day_start = datetime.combine(filter_date, datetime.min.time())
    day_end   = day_start + timedelta(days=1)
    q = select(CashEntry).where(
        CashEntry.agent_id == agent_id,
        CashEntry.branch_id == user.branch_id,
        CashEntry.kind.in_(["COLLECTION", "CASH_PAYMENT", "TRANSFER_PAYMENT"]),
        CashEntry.created_at >= day_start,
        CashEntry.created_at < day_end,
    )
    if entry_ids:
        q = q.where(CashEntry.id.in_(entry_ids))
    entries = db.execute(q).scalars().all()
    now = datetime.now(timezone.utc)
    for e in entries:
        e.confirmed_by_admin = True
        e.confirmed_at = now
    db.commit()
    audit_log(db, user.id, "CASH_VETTED",
              f"agent_id={agent_id} date={date_str} entries={len(entries)}",
              ip=request.client.host if request.client else "")
    if entries:
        notify(db, agent_id,
            "✅ Cash Confirmed",
            f"Admin has confirmed {len(entries)} cash entr{'y' if len(entries) == 1 else 'ies'} for {date_str}.",
            "/cash", "success")
    return JSONResponse({"ok": True, "confirmed": len(entries)})


# ────────────────────────────────────────────────
