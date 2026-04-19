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
    rows = db.execute(select(Branch).order_by(Branch.name.asc())).scalars().all()
    return tpl(request, "branches_list.html", {
        "request": request, "user": user, "rows": rows,
        "active": "branches", "branches": rows, "selected_branch_id": None,
    })


@router.get("/branches/new", response_class=HTMLResponse)
def branch_new_form(request: Request, db: Session = Depends(get_db), user: User = Depends(RequireRole("SUPERVISOR"))):
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
    return {"count": len(get_low_stock(db))}


# ────────────────────────────────────────────────
