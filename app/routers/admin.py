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

#  ADMIN RESET  [FIX-8]
# ────────────────────────────────────────────────

@router.post("/admin/wipe-data", response_class=JSONResponse)
async def wipe_all_data(request: Request, db: Session = Depends(get_db)):
    """Wipe all operational data except users and branches.
    Deletes: deliveries, transactions, cash entries, stock transfers,
    items, notifications, audit logs, assignments, faulty stock, vettings.
    Keeps: users, branches.
    """
    limiter.check(request, max_requests=5, window_seconds=60)  # [SEC] Rate limit destructive ops
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse): return JSONResponse({"error": "not logged in"}, status_code=401)
    user = user_or
    if not is_supervisor(user): return JSONResponse({"error": "forbidden — supervisor only"}, status_code=403)
    verify_origin_for_json(request)  # [SEC] CSRF defense for JSON endpoint
    body = await request.json()
    if body.get("confirm") != "WIPE ALL DATA":
        return JSONResponse({"error": "type WIPE ALL DATA to confirm"}, status_code=400)
    try:
        db.execute(text("DELETE FROM stock_return_vettings"))
        db.execute(text("DELETE FROM adjustment_request_items"))
        db.execute(text("DELETE FROM adjustment_requests"))
        db.execute(text("UPDATE agent_stock_assignments SET transaction_out_id=NULL, transaction_in_id=NULL, delivery_id=NULL"))
        db.execute(text("DELETE FROM agent_stock_assignments"))
        db.execute(text("DELETE FROM faulty_stock"))
        db.execute(text("DELETE FROM notifications"))
        db.execute(text("DELETE FROM cash_entries"))
        db.execute(text("DELETE FROM delivery_items"))
        db.execute(text("DELETE FROM stock_transfer_items"))
        db.execute(text("UPDATE stock_transfers SET received_by_id=NULL, cancelled_by_id=NULL, delegated_agent_id=NULL, delegated_receiver_id=NULL"))
        db.execute(text("DELETE FROM stock_transfers"))
        db.execute(text("DELETE FROM deliveries"))
        db.execute(text("DELETE FROM transactions"))
        db.execute(text("DELETE FROM items"))
        db.execute(text("DELETE FROM audit_logs"))
        db.commit()
        return JSONResponse({"ok": True, "message": "All data wiped. Users and branches preserved."})
    except Exception as e:
        db.rollback()
        logging.getLogger("admin").error("Wipe data failed: %s", e)
        return JSONResponse({"error": "An internal error occurred. Check server logs."}, status_code=500)


@router.get("/admin/reset-system", response_class=HTMLResponse)
def reset_system_form(request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    csrf_token = get_csrf_token(request)
    return HTMLResponse(f"""<!doctype html><html><head><title>Reset System</title>
<style>body{{font-family:sans-serif;max-width:500px;margin:80px auto;padding:20px}}
input,button{{padding:10px;border-radius:8px;border:1px solid #ccc;width:100%;box-sizing:border-box;margin-top:10px}}
button{{background:#ef4444;color:white;border:none;cursor:pointer;font-weight:700}}</style></head>
<body><h2>⚠ Reset System</h2>
<p>This will permanently delete all deliveries, transactions, and cash entries.</p>
<p>Type <strong>RESET</strong> to confirm:</p>
<form method="post" action="/admin/reset-system">
  <input type="hidden" name="csrf_token" value="{csrf_token}" />
  <input type="text" name="confirm" placeholder="Type RESET here" required />
  <button type="submit">Delete All Data</button>
</form>
<p style="margin-top:20px"><a href="/">← Cancel</a></p>
</body></html>""")


@router.post("/admin/reset-system")
async def reset_system_execute(
    request: Request,
    confirm: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    limiter.check(request, max_requests=5, window_seconds=60)  # [SEC] Rate limit destructive ops
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return user_or
    user = user_or
    forbid = require_admin_or_403(user)
    if forbid:
        return forbid
    verify_csrf_token(request, csrf_token)
    if confirm.strip() != "RESET":
        return HTMLResponse("Confirmation text incorrect. <a href='/admin/reset-system'>Go back</a>", status_code=400)
    if DATABASE_URL.startswith("sqlite"):
        db.execute(text("DELETE FROM cash_entries"))
        db.execute(text("DELETE FROM delivery_items"))
        db.execute(text("DELETE FROM deliveries"))
        db.execute(text("DELETE FROM transactions"))
    else:
        db.execute(text("TRUNCATE TABLE cash_entries RESTART IDENTITY CASCADE"))
        db.execute(text("TRUNCATE TABLE delivery_items RESTART IDENTITY CASCADE"))
        db.execute(text("TRUNCATE TABLE deliveries RESTART IDENTITY CASCADE"))
        db.execute(text("TRUNCATE TABLE transactions RESTART IDENTITY CASCADE"))
    db.commit()
    return redirect("/?reset=1")


# ────────────────────────────────────────────────
