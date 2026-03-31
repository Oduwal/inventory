"""
Bland.ai outbound calling service.
Triggers AI voice calls to customers on delivery status changes.
"""
import os
import logging
import threading
from datetime import datetime

import httpx

logger = logging.getLogger("calling")

BLAND_API_KEY = os.getenv("BLAND_API_KEY", "")
BLAND_BASE_URL = "https://api.bland.ai/v1"

# ── Scripts per status ───────────────────────────────────────────
SCRIPTS: dict[str, str] = {
    "OUT_FOR_DELIVERY": (
        "Hello, may I speak with {customer_name}? "
        "This is a message from {business_name}. "
        "Your order of {items} is currently on its way to you. "
        "Our delivery agent will arrive at your location shortly. "
        "Please make sure someone is available to receive it. "
        "Thank you and have a great day!"
    ),
    "DELIVERED": (
        "Hello, may I speak with {customer_name}? "
        "This is {business_name} calling to confirm that your order of {items} "
        "has been successfully delivered. "
        "We hope you are satisfied with your purchase. "
        "Thank you for choosing us!"
    ),
    "FAILED": (
        "Hello, may I speak with {customer_name}? "
        "This is {business_name}. We attempted to deliver your order of {items} today "
        "but unfortunately we were unable to complete the delivery. "
        "Please contact us so we can reschedule your delivery at a convenient time. "
        "We apologise for the inconvenience."
    ),
    "RETURNED": (
        "Hello, may I speak with {customer_name}? "
        "This is {business_name}. We are calling to let you know that your order of {items} "
        "has been returned to our office. "
        "Please reach out to us to arrange a new delivery or discuss your options. "
        "Thank you."
    ),
}


def _build_script(status: str, customer_name: str, items: str) -> str:
    business_name = os.getenv("BUSINESS_NAME", "our store")
    template = SCRIPTS.get(status, "Hello {customer_name}, this is {business_name} calling about your order.")
    return template.format(
        customer_name=customer_name or "valued customer",
        business_name=business_name,
        items=items or "your order",
    )


def _do_call(delivery_id: int, phone: str, status: str, customer_name: str, items: str) -> None:
    """Runs in a background thread — makes the Bland.ai API call and logs the result."""
    if not BLAND_API_KEY:
        logger.warning("BLAND_API_KEY not set — skipping call for delivery #%s", delivery_id)
        return

    script = _build_script(status, customer_name, items)

    try:
        resp = httpx.post(
            f"{BLAND_BASE_URL}/calls",
            headers={"authorization": BLAND_API_KEY, "Content-Type": "application/json"},
            json={
                "phone_number": phone,
                "task": script,
                "voice": "maya",
                "wait_for_greeting": True,
                "record": True,
                "max_duration": 2,          # minutes
                "answered_by_enabled": True,
                "metadata": {"delivery_id": delivery_id, "status": status},
            },
            timeout=15,
        )
        data = resp.json()
        call_id = data.get("call_id") or data.get("id") or ""
        call_status = "initiated" if resp.status_code == 200 else "failed"
        error_msg = "" if resp.status_code == 200 else str(data.get("error", data))[:300]
        logger.info("Bland.ai call for delivery #%s: call_id=%s status=%s", delivery_id, call_id, call_status)
    except Exception as e:
        call_id = ""
        call_status = "failed"
        error_msg = str(e)[:300]
        logger.error("Bland.ai call error for delivery #%s: %s", delivery_id, e)

    # Persist log to DB
    _save_call_log(delivery_id, call_id, phone, status, call_status, error_msg)


def _save_call_log(delivery_id: int, call_id: str, phone: str, trigger_status: str,
                   call_status: str, error_msg: str) -> None:
    try:
        from .database import SessionLocal
        db = SessionLocal()
        try:
            db.execute(
                __import__("sqlalchemy").text(
                    "INSERT INTO call_logs "
                    "(delivery_id, call_id, phone, trigger_status, call_status, error_msg, created_at) "
                    "VALUES (:did, :cid, :phone, :ts, :cs, :err, :now)"
                ),
                {
                    "did": delivery_id,
                    "cid": call_id,
                    "phone": phone,
                    "ts": trigger_status,
                    "cs": call_status,
                    "err": error_msg,
                    "now": datetime.utcnow(),
                },
            )
            db.commit()
        finally:
            db.close()
    except Exception as e:
        logger.error("Failed to save call log for delivery #%s: %s", delivery_id, e)


def trigger_call(delivery_id: int, phone: str | None, status: str,
                 customer_name: str, items: str) -> None:
    """
    Public entry point — called from main.py on status change.
    Fires in a background daemon thread so it never blocks the request.
    """
    if not phone or not phone.strip():
        logger.info("No phone for delivery #%s — skipping call", delivery_id)
        return
    if status not in SCRIPTS:
        return
    threading.Thread(
        target=_do_call,
        args=(delivery_id, phone.strip(), status, customer_name, items),
        daemon=True,
    ).start()
