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

VAPI_API_KEY = os.getenv("VAPI_API_KEY", "")
VAPI_PHONE_NUMBER_ID = os.getenv("VAPI_PHONE_NUMBER_ID", "")

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
    """Runs in a background thread — makes the Vapi API call and logs the result."""
    if not VAPI_API_KEY or not VAPI_PHONE_NUMBER_ID:
        logger.warning("VAPI keys not set — skipping call for delivery #%s", delivery_id)
        return

    # Generate the initial message using your existing templates
    script = _build_script(status, customer_name, items)
    business_name = os.getenv("BUSINESS_NAME", "our logistics company")

    try:
        resp = httpx.post(
            "https://api.vapi.ai/call/phone",
            headers={
                "Authorization": f"Bearer {VAPI_API_KEY}", 
                "Content-Type": "application/json"
            },
            json={
                "phoneNumberId": VAPI_PHONE_NUMBER_ID,
                "customer": {
                    "number": phone
                },
                "assistant": {
                    "firstMessage": script,
                    "model": {
                        "provider": "openai",
                        "model": "gpt-3.5-turbo",
                        "messages": [
                            {
                                "role": "system",
                                "content": f"You are a helpful customer service AI for {business_name}. You are calling to provide a delivery update. The exact update is: '{script}'. Be polite, concise, and answer any simple questions the customer has about this update."
                            }
                        ]
                    },
                    "voice": {
                        "provider": "11labs",
                        "voiceId": "burt" # You can change this to any Vapi supported voice
                    }
                }
            },
            timeout=15,
        )
        data = resp.json()
        call_id = data.get("id") or ""
        
        # Vapi returns 201 Created for a successful call initiation
        call_status = "initiated" if resp.status_code in (200, 201) else "failed"
        error_msg = "" if resp.status_code in (200, 201) else str(data.get("message", data))[:300]
        logger.info("Vapi call for delivery #%s: call_id=%s status=%s", delivery_id, call_id, call_status)
    except Exception as e:
        call_id = ""
        call_status = "failed"
        error_msg = str(e)[:300]
        logger.error("Vapi call error for delivery #%s: %s", delivery_id, e)

    # Persist log to DB using your existing logging function
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
