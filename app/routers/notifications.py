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

#  NOTIFICATIONS
# ────────────────────────────────────────────────

@router.get("/notifications/poll", response_class=JSONResponse)
def notifications_poll(request: Request, after: int = 0, db: Session = Depends(get_db)):
    """Poll for unread notifications. Returns new ones since 'after' id."""
    try:
        limiter.check(request, max_requests=60, window_seconds=60)
    except HTTPException:
        return JSONResponse({"notifications": []})
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"notifications": []})
    user = user_or
    rows = db.execute(text(
        "SELECT id, title, body, link, kind, created_at FROM notifications "
        "WHERE user_id = :uid AND read_at IS NULL AND id > :after "
        "ORDER BY created_at DESC LIMIT 20"
    ), {"uid": user.id, "after": after}).fetchall()
    return JSONResponse({"notifications": [
        {"id": r.id, "title": r.title, "body": r.body or "",
         "link": r.link or "", "kind": r.kind or "info",
         "created_at": r.created_at.isoformat() if r.created_at else ""}
        for r in rows
    ]})


@router.post("/notifications/dismiss", response_class=JSONResponse)
async def notifications_dismiss(request: Request, db: Session = Depends(get_db)):
    """Mark one or all notifications as read."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"ok": False})
    user = user_or
    body = await request.json()
    notif_id = body.get("id")  # None = dismiss all
    if notif_id:
        db.execute(text("UPDATE notifications SET read_at=:_now WHERE id=:id AND user_id=:uid"),
                   {"id": notif_id, "uid": user.id, "_now": _now()})
    else:
        db.execute(text("UPDATE notifications SET read_at=:_now WHERE user_id=:uid AND read_at IS NULL"),
                   {"uid": user.id, "_now": _now()})
    db.commit()
    return JSONResponse({"ok": True})


@router.get("/notifications/unread-count", response_class=JSONResponse)
def notifications_unread_count(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"count": 0})
    user = user_or
    count = db.execute(text(
        "SELECT COUNT(*) FROM notifications WHERE user_id=:uid AND read_at IS NULL"
    ), {"uid": user.id}).scalar() or 0
    return JSONResponse({"count": int(count)})


# ────────────────────────────────────────────────
#  WEB PUSH
# ────────────────────────────────────────────────

@router.get("/push/vapid-public-key", response_class=JSONResponse)
def push_vapid_public_key():
    return JSONResponse({"publicKey": VAPID_PUBLIC_KEY})


@router.post("/push/subscribe", response_class=JSONResponse)
async def push_subscribe(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"ok": False}, status_code=401)
    user = user_or
    body     = await request.json()
    endpoint = body.get("endpoint", "")
    keys     = body.get("keys", {})
    p256dh   = keys.get("p256dh", "")
    auth     = keys.get("auth", "")
    if not endpoint or not p256dh or not auth:
        return JSONResponse({"error": "invalid subscription"}, status_code=400)
    validate_push_endpoint(endpoint)  # [SEC] Reject non-HTTPS or bogus endpoints
    # Upsert: delete old entry for this endpoint, then insert fresh
    db.execute(text("DELETE FROM push_subscriptions WHERE endpoint=:ep"), {"ep": endpoint})
    db.execute(text(
        "INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth, created_at) "
        "VALUES (:uid, :ep, :p256dh, :auth, :_now)"
    ), {"uid": user.id, "ep": endpoint, "p256dh": p256dh, "auth": auth, "_now": _now()})
    db.commit()
    return JSONResponse({"ok": True})


@router.get("/push/test", response_class=JSONResponse)
def push_test(request: Request, db: Session = Depends(get_db)):
    """Send a test push to the logged-in user."""
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY:
        return JSONResponse({"error": "VAPID keys not configured on server"})
    has_sub = db.execute(text("SELECT 1 FROM push_subscriptions WHERE user_id=:uid LIMIT 1"), {"uid": user.id}).first()
    if not has_sub:
        return JSONResponse({"error": "No push subscription found. Allow notifications first and reload."})
    task_queue.submit(_send_web_push, user.id, "🔔 Test Notification", "Push notifications are working!", "/")
    return JSONResponse({"ok": True, "message": "Test push sent"})


@router.post("/push/unsubscribe", response_class=JSONResponse)
async def push_unsubscribe(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"ok": False}, status_code=401)
    body     = await request.json()
    endpoint = body.get("endpoint", "")
    if endpoint:
        db.execute(text("DELETE FROM push_subscriptions WHERE endpoint=:ep"), {"ep": endpoint})
        db.commit()
    return JSONResponse({"ok": True})


# ────────────────────────────────────────────────
