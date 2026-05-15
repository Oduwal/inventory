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

#  BRANCHES
# ────────────────────────────────────────────────

@router.get("/branches", response_class=HTMLResponse)
def branches_list(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("SUPERVISOR"))):
    set_rls_context(db, user)
    rows = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()
    return tpl(request, "branches_list.html", {
        "request": request, "user": user, "rows": rows,
        "active": "branches", "branches": rows, "selected_branch_id": None,
    })


@router.get("/branches/new", response_class=HTMLResponse)
def branch_new_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("SUPERVISOR"))):
    set_rls_context(db, user)
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()
    csrf_token = get_csrf_token(request)
    return tpl(request, "branch_new.html", {
        "request": request, "user": user, "error": request.query_params.get("error"),
        "active": "branches", "branches": branches, "selected_branch_id": None,
        "csrf_token": csrf_token,
    })


@router.post("/branches/new")
async def branch_create(
    request: Request,
    name: str = Form(...),
    code: str = Form(""),
    address: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("SUPERVISOR")),
):
    set_rls_context(db, user)
    verify_csrf_token(request, csrf_token)
    name_clean = sanitize_text(name, 120, "Branch name")
    code_clean = sanitize_text(code, 20, "Branch code") if (code or "").strip() else None
    address_clean = sanitize_text(address, 200, "Address") if (address or "").strip() else None
    if not name_clean:
        return redirect("/branches/new?error=Branch+name+is+required")
    if db.scalar(select(Branch).where(Branch.name == name_clean)):
        return redirect("/branches/new?error=Branch+name+already+exists")
    if code_clean and db.scalar(select(Branch).where(Branch.code == code_clean)):
        return redirect("/branches/new?error=Branch+code+already+exists")
    db.add(Branch(name=name_clean, code=code_clean, address=address_clean))
    db.commit()
    return redirect("/branches")


@router.get("/api/low-stock-count")
def api_low_stock_count(request: Request, db: Session = Depends(get_db), user: User = Depends(get_active_user)):
    set_rls_context(db, user)
    branch_id = None if is_supervisor(user) else user.branch_id
    return {"count": len(get_low_stock(db, branch_id=branch_id))}


# ────────────────────────────────────────────────
#  SUB-ZONES (per-branch delivery zones)
# ────────────────────────────────────────────────

import re as _re_zone

_ZONE_CODE_RE = _re_zone.compile(r"^[A-Z0-9]{2,8}$")


def _check_zone_access(user: User, branch_id: int) -> None:
    """ADMIN may manage only their own branch; SUPERVISOR may manage any."""
    if is_supervisor(user):
        return
    if is_admin(user) and user.branch_id == branch_id:
        return
    raise HTTPException(status_code=403, detail="Not authorized for this branch")


@router.get("/branches/{branch_id}/sub-zones", response_class=HTMLResponse)
def sub_zones_list(branch_id: int, request: Request,
                   db: Session = Depends(get_db),
                   user: User = Depends(RequireRole("ADMIN", "SUPERVISOR"))):
    set_rls_context(db, user)
    _check_zone_access(user, branch_id)
    branch = db.get(Branch, branch_id)
    if not branch:
        raise HTTPException(status_code=404, detail="Branch not found")
    zones = db.execute(
        select(SubZone).where(SubZone.branch_id == branch_id).order_by(SubZone.name.asc())
    ).scalars().all()
    branches = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all() if is_supervisor(user) else []
    csrf_token = get_csrf_token(request)
    return tpl(request, "sub_zones.html", {
        "request": request, "user": user, "branch": branch, "zones": zones,
        "active": "branches", "branches": branches,
        "selected_branch_id": branch_id if not is_supervisor(user) else None,
        "csrf_token": csrf_token,
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
    })


@router.post("/branches/{branch_id}/sub-zones")
def sub_zone_create(
    branch_id: int,
    request: Request,
    name: str = Form(...),
    code: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    set_rls_context(db, user)
    verify_csrf_token(request, csrf_token)
    _check_zone_access(user, branch_id)
    branch = db.get(Branch, branch_id)
    if not branch:
        raise HTTPException(status_code=404, detail="Branch not found")
    name_clean = sanitize_text(name, 80, "Zone name")
    code_clean = (code or "").strip().upper()
    if not name_clean:
        return redirect(f"/branches/{branch_id}/sub-zones?error=Zone+name+is+required")
    if not _ZONE_CODE_RE.match(code_clean):
        return redirect(f"/branches/{branch_id}/sub-zones?error=Code+must+be+2-8+letters/digits")
    if db.scalar(select(SubZone).where(SubZone.branch_id == branch_id, SubZone.name == name_clean)):
        return redirect(f"/branches/{branch_id}/sub-zones?error=Zone+name+already+exists+for+this+branch")
    if db.scalar(select(SubZone).where(SubZone.branch_id == branch_id, SubZone.code == code_clean)):
        return redirect(f"/branches/{branch_id}/sub-zones?error=Code+already+used+in+this+branch")
    zone = SubZone(branch_id=branch_id, name=name_clean, code=code_clean)
    db.add(zone)
    db.commit()
    audit_log(db, user.id, "sub_zone_create",
              f"branch={branch_id} name={name_clean} code={code_clean}",
              request.client.host if request.client else "")
    return redirect(f"/branches/{branch_id}/sub-zones?success=Zone+added")


@router.post("/sub-zones/{zone_id}/delete")
def sub_zone_delete(
    zone_id: int,
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(RequireRole("ADMIN", "SUPERVISOR")),
):
    set_rls_context(db, user)
    verify_csrf_token(request, csrf_token)
    zone = db.get(SubZone, zone_id)
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")
    _check_zone_access(user, zone.branch_id)
    branch_id = zone.branch_id
    zone_name = zone.name
    zone_code = zone.code
    db.delete(zone)
    db.commit()
    audit_log(db, user.id, "sub_zone_delete",
              f"branch={branch_id} name={zone_name} code={zone_code}",
              request.client.host if request.client else "")
    return redirect(f"/branches/{branch_id}/sub-zones?success=Zone+deleted")


# ────────────────────────────────────────────────
