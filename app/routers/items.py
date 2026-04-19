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

#  ITEMS
# ────────────────────────────────────────────────

@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return tpl(request, "forgot_password.html", {
        "request": request, "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
    })


@router.get("/items", response_class=HTMLResponse)
def items_list(request: Request, q: str = "", view: str = "combined", branch_filter: str = "", db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    branch_id = get_selected_branch_id(request, user)
    all_rows = list(get_items_with_stock(db))
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all() if is_supervisor(user) else []

    if is_supervisor(user):
        # Apply branch filter if selected
        if branch_filter and branch_filter.isdigit():
            filtered_rows = [(item, stock) for (item, stock) in all_rows if item.branch_id == int(branch_filter)]
        else:
            filtered_rows = all_rows

        if view == "combined":
            # Aggregate: merge items with same name across branches
            combined: dict = {}
            for item, stock in filtered_rows:
                key = (item.name or "").strip().lower()
                if key not in combined:
                    combined[key] = {
                        "name": item.name, "category": item.category, "unit": item.unit,
                        "reorder_level": item.reorder_level or 0,
                        "cost_price": float(item.cost_price or 0),
                        "selling_price": float(item.selling_price or 0),
                        "total_stock": 0, "branch_stocks": [], "item_id": item.id,
                    }
                combined[key]["total_stock"] += int(stock or 0)
                branch_name = item.branch.name if item.branch else f"Branch {item.branch_id}"
                combined[key]["branch_stocks"].append({"branch": branch_name, "stock": int(stock or 0)})
            rows = list(combined.values())
            # Apply search
            q_lower = q.strip().lower()
            if q_lower:
                rows = [r for r in rows if q_lower in (r["name"] or "").lower() or q_lower in (r["category"] or "").lower()]
        else:
            # Per-branch view
            rows = filtered_rows
            q_lower = q.strip().lower()
            if q_lower:
                rows = [(item, stock) for (item, stock) in rows
                        if q_lower in (item.name or "").lower() or q_lower in (item.category or "").lower()]
    else:
        rows = [(item, stock) for (item, stock) in all_rows if item.branch_id == branch_id]
        q_lower = q.strip().lower()
        if q_lower:
            rows = [(item, stock) for (item, stock) in rows
                    if q_lower in (item.name or "").lower() or q_lower in (item.category or "").lower()]
        view = "branch"

    # Faulty counts per item for badge display
    faulty_counts_raw = db.execute(text(
        "SELECT item_id, SUM(qty_faulty) FROM faulty_stock "
        "WHERE branch_id = :bid AND resolved = FALSE GROUP BY item_id"
    ), {"bid": branch_id}).fetchall() if branch_id else []
    faulty_counts = {r[0]: int(r[1]) for r in faulty_counts_raw}
    has_test_stock = bool(
        db.execute(text(
            "SELECT 1 FROM transactions WHERE reference='TEST-STOCK' AND branch_id=:bid LIMIT 1"
        ), {"bid": branch_id}).first()
    ) if branch_id else False
    return tpl(request, "items_list.html", {
        "request": request, "rows": rows, "q": q, "user": user, "active": "items", "faulty_counts": faulty_counts,
        "view": view, "branches": branches, "branch_filter": branch_filter,
        "has_test_stock": has_test_stock,
    })


@router.get("/items/new", response_class=HTMLResponse)
def item_new_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    csrf_token = get_csrf_token(request)
    return tpl(request, "item_new.html", {
        "request": request, "user": user,
        "error": request.query_params.get("error"),
        "active": "items", "csrf_token": csrf_token,
    })


@router.post("/items/new")
async def item_create(
    request: Request,
    name: str = Form(...),
    category: str = Form(""),
    unit: str = Form("pcs"),
    reorder_level: int = Form(0),
    cost_price: float = Form(0),
    selling_price: float = Form(0),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    verify_csrf_token(request, csrf_token)
    name_clean = sanitize_text(name, 200, "Name")
    if not name_clean:
        return redirect("/items/new?error=Name+is+required")
    branch_id = get_current_branch_id(request)
    if not branch_id:
        return redirect("/items/new?error=No+branch+assigned")
    db.add(Item(
        branch_id=branch_id, name=name_clean,
        category=sanitize_text(category, 120, "Category") or None,
        unit=(unit or "pcs").strip() or "pcs",
        reorder_level=int(reorder_level or 0),
        cost_price=float(cost_price or 0),
        selling_price=float(selling_price or 0),
    ))
    db.commit()
    return redirect("/items")


@router.get("/items/import", response_class=HTMLResponse)
def items_import_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all()
    csrf_token = get_csrf_token(request)
    return tpl(request, "items_import.html", {
        "request": request, "user": user, "branches": branches,
        "active": "items", "selected_branch_id": getattr(user, "branch_id", None),
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "csrf_token": csrf_token,
    })


@router.post("/items/import")
async def items_import_upload(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    import csv, io
    form = await request.form()
    verify_csrf_token(request, str(form.get("csrf_token", "")))
    file = form.get("csv_file")
    target = (form.get("target_branch") or "").strip()
    if not file or not file.filename:
        return redirect("/items/import?error=Please+select+a+CSV+file")
    file_bytes = await file.read()
    # [SEC-9] Validate file type and size
    try:
        validate_upload(file.filename, file_bytes)
    except Exception as e:
        return redirect(f"/items/import?error={str(e)}")
    content = file_bytes
    try:
        text_content = content.decode("utf-8-sig")
    except Exception:
        return redirect("/items/import?error=Could+not+read+file")
    reader = csv.DictReader(io.StringIO(text_content))
    headers = [h.strip().lower() for h in (reader.fieldnames or [])]
    if "name" not in headers:
        return redirect("/items/import?error=CSV+must+have+a+Name+column")
    branches = db.execute(select(Branch).order_by(Branch.name)).scalars().all()
    if is_supervisor(user) and target == "all":
        target_branches = branches
    elif is_supervisor(user) and target.isdigit():
        b = db.get(Branch, int(target))
        target_branches = [b] if b else []
    else:
        b = db.get(Branch, user.branch_id)
        target_branches = [b] if b else []
    if not target_branches:
        return redirect("/items/import?error=No+valid+branch+selected")
    rows = list(reader)
    if not rows:
        return redirect("/items/import?error=CSV+file+is+empty")
    created = 0
    skipped = 0
    for branch in target_branches:
        for row in rows:
            name = (row.get("name") or row.get("Name") or "").strip()
            if not name:
                skipped += 1
                continue
            category = (row.get("category") or row.get("Category") or "").strip() or None
            existing = db.scalar(select(Item).where(Item.branch_id == branch.id, func.lower(Item.name) == name.lower()))
            if existing:
                skipped += 1
                continue
            db.add(Item(branch_id=branch.id, name=name, category=category, unit="pcs", reorder_level=0, cost_price=0, selling_price=0))
            created += 1
    db.commit()
    return redirect(f"/items/import?success=Imported+{created}+items+({skipped}+skipped)")


@router.get("/items/{item_id}", response_class=HTMLResponse)
def item_detail(request: Request, item_id: int, db: Session = Depends(get_db), user: User = Depends(get_active_user), row=Depends(get_authorized_item_with_stock)):
    item, stock = row
    txs = db.scalars(
        select(Transaction).where(Transaction.item_id == item_id)
        .where(Transaction.branch_id == item.branch_id)
        .order_by(desc(Transaction.created_at)).limit(200)
    ).all()
    # Faulty stock records for this item
    faulty_records = db.execute(text(
        "SELECT id, qty_faulty, reason, flagged_at, resolved, resolve_action, resolved_at, resolve_note "
        "FROM faulty_stock WHERE item_id = :iid AND branch_id = :bid ORDER BY flagged_at DESC"
    ), {"iid": item_id, "bid": item.branch_id}).fetchall()
    faulty_qty_active = sum(r[1] for r in faulty_records if not r[4])  # unresolved only
    csrf_token = get_csrf_token(request)
    return tpl(request, "item_detail.html", {
        "request": request, "item": item, "stock": stock, "txs": txs, "user": user,
        "active": "items", "faulty_records": faulty_records,
        "faulty_qty_active": faulty_qty_active, "csrf_token": csrf_token,
    })


@router.get("/items/{item_id}/edit", response_class=HTMLResponse)
def item_edit_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")), item: Item = Depends(get_authorized_item)):
    csrf_token = get_csrf_token(request)
    return tpl(request, "item_edit.html", {
        "request": request, "item": item, "user": user,
        "error": request.query_params.get("error"),
        "active": "items", "csrf_token": csrf_token,
    })


@router.post("/items/{item_id}/edit")
async def item_edit_save(
    request: Request,
    item_id: int,
    name: str = Form(...),
    category: str = Form(""),
    unit: str = Form("pcs"),
    reorder_level: int = Form(0),
    cost_price: float = Form(0),
    selling_price: float = Form(0),
    adjust_type: str = Form(""),
    adjust_qty: int = Form(0),
    adjust_note: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
    item: Item = Depends(get_authorized_item),
):
    verify_csrf_token(request, csrf_token)
    name_clean = sanitize_text(name, 200, "Name")
    if not name_clean:
        return redirect(f"/items/{item_id}/edit?error=Name+is+required")
    item.name = name_clean
    item.category = sanitize_text(category, 120, "Category") or None
    item.unit = (unit or "pcs").strip() or "pcs"
    item.reorder_level = int(reorder_level or 0)
    item.cost_price = float(cost_price or 0)
    item.selling_price = float(selling_price or 0)
    at = (adjust_type or "").strip().upper()
    aq = int(adjust_qty or 0)
    if aq < 0:
        return redirect(f"/items/{item_id}/edit?error=Adjust+quantity+must+be+positive")
    if aq > 0:
        if at not in {"IN", "OUT"}:
            return redirect(f"/items/{item_id}/edit?error=Adjust+type+must+be+IN+or+OUT")
        if at == "OUT":
            r = get_item_with_stock(db, item_id)
            if (r[1] if r else 0) < aq:
                return redirect(f"/items/{item_id}/edit?error=Insufficient+stock+for+OUT+adjustment")
        db.add(Transaction(
            branch_id=item.branch_id, item_id=item_id, type=at, quantity=aq,
            reference=f"MANUAL ADJUST #{item_id}",
            note=sanitize_text(adjust_note, 200, "Note") or f"Manual stock adjust by {user.username}",
        ))
    db.commit()
    return redirect(f"/items/{item_id}")


# ────────────────────────────────────────────────
#  FAULTY STOCK
# ────────────────────────────────────────────────

@router.post("/items/{item_id}/flag-faulty", response_class=JSONResponse)
async def flag_faulty_stock(
    item_id: int, request: Request, db: Session = Depends(get_db),
    qty_faulty: int = Form(...), reason: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(RequireRole("ADMIN")),
):
    """Admin flags a quantity of an item as faulty/bad. Stock count unchanged."""
    verify_csrf_token(request, csrf_token)

    item = db.get(Item, item_id)
    if not item or item.branch_id != user.branch_id:
        return JSONResponse({"error": "item not found"}, status_code=404)
    if qty_faulty <= 0:
        return JSONResponse({"error": "quantity must be greater than zero"}, status_code=400)

    reason_clean = (reason or "").strip()[:400]

    db.execute(text(
        "INSERT INTO faulty_stock (item_id, branch_id, qty_faulty, reason, flagged_by, flagged_at, resolved, resolve_note) "
        "VALUES (:iid, :bid, :qty, :reason, :uid, :_now, FALSE, '')"
    ), {"iid": item_id, "bid": user.branch_id, "qty": qty_faulty,
        "reason": reason_clean, "uid": user.id, "_now": _now()})

    audit_log(db, user.id, "FAULTY_STOCK_FLAGGED",
              f"item={item.name} qty={qty_faulty} reason={reason_clean}",
              ip=request.client.host if request.client else "")
    db.commit()
    return JSONResponse({"ok": True, "item_name": item.name, "qty_faulty": qty_faulty})


@router.post("/faulty-stock/{faulty_id}/resolve", response_class=JSONResponse)
async def resolve_faulty_stock(
    faulty_id: int, request: Request, db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN")),
):
    """Admin resolves a faulty stock record.
    action='remove'           → OUT transaction, stock reduced
    action='return_merchant'  → OUT transaction labelled as merchant return
    """

    body         = await request.json()
    action       = body.get("action", "")    # "remove" | "return_merchant"
    resolve_note = (body.get("resolve_note", "") or "").strip()[:400]

    if action not in ("remove", "return_merchant"):
        return JSONResponse({"error": "action must be remove or return_merchant"}, status_code=400)

    # Get the faulty record
    row = db.execute(text(
        "SELECT id, item_id, branch_id, qty_faulty, reason FROM faulty_stock "
        "WHERE id = :fid AND resolved = FALSE"
    ), {"fid": faulty_id}).fetchone()
    if not row:
        return JSONResponse({"error": "record not found or already resolved"}, status_code=404)

    fs_id, item_id, branch_id, qty_faulty, reason = row

    if branch_id != user.branch_id:
        return JSONResponse({"error": "forbidden — different branch"}, status_code=403)

    item = db.get(Item, item_id)
    if not item:
        return JSONResponse({"error": "item not found"}, status_code=404)

    # Create OUT transaction to remove faulty stock
    note = (
        f"Faulty stock returned to merchant — {resolve_note}" if action == "return_merchant"
        else f"Faulty stock removed — {resolve_note or reason}"
    ).strip(" —")
    tx = Transaction(
        branch_id=user.branch_id,
        item_id=item_id,
        type="OUT",
        quantity=qty_faulty,
        note=note,
        reference=f"faulty-{'merchant' if action == 'return_merchant' else 'remove'}-{faulty_id}",
    )
    db.add(tx)
    db.flush()

    # Mark faulty record resolved
    db.execute(text(
        "UPDATE faulty_stock SET resolved=TRUE, resolve_action=:act, "
        "resolved_at=:_now, resolved_by=:uid, resolve_note=:note WHERE id=:fid"
    ), {"act": action, "uid": user.id, "note": resolve_note, "fid": faulty_id, "_now": _now()})

    audit_log(db, user.id, "FAULTY_STOCK_RESOLVED",
              f"item={item.name} qty={qty_faulty} action={action}",
              ip=request.client.host if request.client else "")
    db.commit()
    return JSONResponse({
        "ok": True,
        "item_name": item.name,
        "qty_faulty": qty_faulty,
        "action": action,
        "tx_note": note,
    })


#  TRANSACTIONS
# ────────────────────────────────────────────────

@router.get("/transactions", response_class=HTMLResponse)
def transactions_list(request: Request, branch_filter: str = "", db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    branch_id = get_selected_branch_id(request, user)
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    filter_bid = int(branch_filter) if branch_filter and branch_filter.isdigit() else None
    stmt = select(Transaction).order_by(desc(Transaction.created_at)).limit(300)
    if is_supervisor(user):
        if filter_bid:
            stmt = stmt.where(Transaction.branch_id == filter_bid)
    else:
        stmt = stmt.where(Transaction.branch_id == branch_id)
    txs = db.scalars(stmt).all()
    item_ids = list({t.item_id for t in txs if t.item_id})
    item_name_map = {}
    if item_ids:
        for it in db.scalars(select(Item).where(Item.id.in_(item_ids))).all():
            item_name_map[it.id] = it.name
    return tpl(request, "transactions_list.html", {
        "request": request, "txs": txs, "user": user, "active": "transactions",
        "item_name_map": item_name_map, "branches": branches, "branch_filter": branch_filter,
    })


@router.get("/transactions/new", response_class=HTMLResponse)
def tx_new_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    branch_id = get_selected_branch_id(request, user)
    items = [i for (i, _s) in get_items_with_stock(db) if i.branch_id == branch_id]
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    csrf_token = get_csrf_token(request)
    return tpl(request, "tx_form.html", {
        "request": request, "items": items, "error": request.query_params.get("error"),
        "user": user, "active": "transactions", "branches": branches,
        "selected_branch_id": branch_id, "csrf_token": csrf_token,
    })


@router.post("/transactions/new")
async def tx_create(
    request: Request,
    item_id: int = Form(...),
    tx_type: str = Form(...),
    quantity: int = Form(...),
    reference: str = Form(""),
    note: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    verify_csrf_token(request, csrf_token)
    tx_type_clean = (tx_type or "").strip().upper()
    if tx_type_clean not in {"IN", "OUT"}:
        return redirect("/transactions/new?error=Invalid+type")
    qty = int(quantity)
    if qty <= 0:
        return redirect("/transactions/new?error=Quantity+must+be+greater+than+0")
    if tx_type_clean == "OUT":
        r = get_item_with_stock(db, item_id)
        if not r:
            return redirect("/transactions/new?error=Item+not+found")
        if int(r[1]) < qty:
            return redirect("/transactions/new?error=Insufficient+stock")
    branch_id = get_current_branch_id(request)
    if not branch_id:
        return redirect("/transactions/new?error=No+branch+assigned")
    db.add(Transaction(
        branch_id=branch_id, item_id=item_id, type=tx_type_clean, quantity=qty,
        reference=sanitize_text(reference, 120, "Reference") or None,
        note=sanitize_text(note, 400, "Note") or None,
    ))
    db.commit()
    return redirect("/transactions")


# ────────────────────────────────────────────────
