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

# [SEC] Pre-computed dummy hash for constant-time login responses.
# When a non-existent username is submitted, we still run the password
# verification against this dummy so the response time is indistinguishable
# from a real-user check (prevents username enumeration via timing).
_DUMMY_HASH = hash_password("dummy-timing-pad")

@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    csrf_token = get_csrf_token(request)
    return tpl(request, "login.html", {"request": request, "error": None, "csrf_token": csrf_token})


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    # [FIX-3] Rate limiting — 30 attempts per minute per IP (generous enough for shared networks)
    try:
        limiter.check(request, max_requests=30, window_seconds=60)
    except HTTPException:
        token = get_csrf_token(request)
        return tpl(request, "login.html", {
            "request": request,
            "error": "Too many login attempts. Please wait a minute and try again.",
            "csrf_token": token,
        }, status_code=429)

    verify_csrf_token(request, csrf_token)
    username_clean = sanitize_username(username)
    ip = request.client.host if request.client else ""

    # [SEC-5] Per-account lockout check
    if account_lockout.is_locked(username_clean):
        token = get_csrf_token(request)
        return tpl(request, "login.html", {
            "request": request,
            "error": "Account temporarily locked due to too many failed attempts. Try again in 15 minutes.",
            "csrf_token": token,
        }, status_code=429)

    u = db.scalar(select(User).where(User.username == username_clean))
    # [SEC] Always run verify_password — even for non-existent users — to
    # prevent timing-based username enumeration.
    pw_ok = verify_password(password, u.password_hash if u else _DUMMY_HASH)
    if not u or not pw_ok:
        account_lockout.record_failure(username_clean)  # [SEC-5] record failure
        remaining = account_lockout.remaining_attempts(username_clean)
        audit_log(db, u.id if u else None, "LOGIN_FAILED", f"username={username_clean}", ip=ip)
        token = get_csrf_token(request)
        msg = "Invalid login."
        if remaining <= 2:
            msg = f"Invalid login. {remaining} attempt{'s' if remaining != 1 else ''} remaining before lockout."
        return tpl(request, "login.html", {
            "request": request, "error": msg, "csrf_token": token,
        })

    account_lockout.clear(username_clean)  # [SEC-5] reset on success
    # [SEC] Reject deactivated accounts
    if not u.is_active:
        audit_log(db, u.id, "LOGIN_BLOCKED_INACTIVE", f"username={username_clean}", ip=ip)
        token = get_csrf_token(request)
        return tpl(request, "login.html", {
            "request": request,
            "error": "This account has been deactivated. Contact your administrator.",
            "csrf_token": token,
        })
    # Auto-rehash legacy bcrypt passwords to current scheme (pbkdf2_sha256)
    if (u.password_hash or "").startswith("$2"):
        u.password_hash = hash_password(password)
        db.commit()
    audit_log(db, u.id, "LOGIN", f"username={username_clean}", ip=ip)
    # [SEC] Clear old session state before setting new values to prevent
    # session fixation and stale role/branch leakage.
    request.session.clear()
    request.session["user_id"] = u.id
    if u.branch_id is not None:
        request.session["branch_id"] = u.branch_id
    return redirect("/")


@router.post("/logout")
async def logout(request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    verify_csrf_token(request, csrf_token)  # [SEC] CSRF protection on logout
    user_id = request.session.get("user_id")
    audit_log(db, user_id, "LOGOUT",
              ip=request.client.host if request.client else "")
    request.session.clear()
    return redirect("/login")


# ────────────────────────────────────────────────
