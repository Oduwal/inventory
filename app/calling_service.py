import os
import logging
import threading
from datetime import datetime
import httpx

logger = logging.getLogger("calling")

VAPI_API_KEY = os.getenv("VAPI_API_KEY", "")
VAPI_PHONE_NUMBER_ID = os.getenv("VAPI_PHONE_NUMBER_ID", "")

def format_nigerian_phone(phone: str) -> str:
    """Automatically cleans and formats phone numbers to E.164 (+234...)."""
    if not phone: return ""
    clean = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "").strip()
    if clean.startswith("0") and len(clean) == 11: return "+234" + clean[1:]
    if clean.startswith("234") and len(clean) == 13: return "+" + clean
    if clean.startswith("+"): return clean
    return clean

SCRIPTS: dict[str, str] = {
    "PENDING": (
        "Good day! Am I speaking with {customer_name}? "
        "I am calling from {business_name}. Your order of {items} has been received at our branch. "
        "The delivery address on file is: {address}. "
        "If you have any specific instructions or want to change the time, just let me know and I will note it for the dispatch rider."
    ),
    "OUT_FOR_DELIVERY": (
        "Good day! Am I speaking with {customer_name}? "
        "I am calling from {business_name}. Your order of {items} is currently out for delivery and heading to {address}. "
        "Our dispatch rider will arrive shortly. "
        "If you want me to tell the rider to come at a specific time today, please tell me now and I will take the message."
    ),
    "DELIVERED": (
        "Hello {customer_name}, this is {business_name}. "
        "We are just calling to confirm your order of {items} was successfully delivered. Thank you for your patronage!"
    ),
    "FAILED": (
        "Hello {customer_name}, this is {business_name}. "
        "We attempted to deliver your order of {items} today to {address} but were unsuccessful. "
        "When would you like us to reschedule this delivery?"
    ),
}

def _build_script(status: str, customer_name: str, items: str, address: str) -> str:
    business_name = os.getenv("BUSINESS_NAME", "Atomic Logistics")
    template = SCRIPTS.get(status, "Hello {customer_name}, this is {business_name} calling.")
    display_address = address if address and address.strip() else "an unconfirmed address"
    return template.format(
        customer_name=customer_name or "valued customer",
        business_name=business_name,
        items=items or "your order",
        address=display_address
    )

def _do_call(delivery_id: int, phone: str, status: str, customer_name: str, items: str, address: str) -> None:
    if not VAPI_API_KEY or not VAPI_PHONE_NUMBER_ID:
        logger.warning("VAPI keys not set — skipping call for delivery #%s", delivery_id)
        return

    formatted_phone = format_nigerian_phone(phone)
    if not formatted_phone: return

    script = _build_script(status, customer_name, items, address)
    business_name = os.getenv("BUSINESS_NAME", "Atomic Logistics")
    
    # .rstrip('/') prevents the double-slash error (//api/call-webhook)
    YOUR_RAILWAY_APP_URL = os.getenv("APP_URL", "https://inventory-production-d41e.up.railway.app").rstrip('/')

    try:
        resp = httpx.post(
            "https://api.vapi.ai/call/phone",
            headers={"Authorization": f"Bearer {VAPI_API_KEY}", "Content-Type": "application/json"},
            json={
                "phoneNumberId": VAPI_PHONE_NUMBER_ID,
                "customer": {"number": formatted_phone},
                "assistant": {
                    "firstMessage": script,
                    "model": {
                        "provider": "openai",
                        "model": "gpt-3.5-turbo",
                        "messages": [{
                            "role": "system",
                            "content": f"You are a smart, polite customer service assistant for {business_name}. "
                                       f"You are calling regarding this exact update: '{script}'. "
                                       "CRITICAL INSTRUCTION: If the customer asks you to reschedule, change the time, or update the address, DO NOT say you cannot communicate with the agent. "
                                       "Instead, reply with: 'I have noted that down, and I will immediately pass the message to the dispatch rider.' "
                                       "Answer simple questions and let them lead the conversation."
                        }]
                    },
                    "voice": {"provider": "11labs", "voiceId": "burt"},
                    "serverUrl": f"{YOUR_RAILWAY_APP_URL}/api/call-webhook",
                    "serverMessages": ["end-of-call-report"],
                    "clientMessages": ["transcript", "hang", "function-call"],
                    "endCallFunctionEnabled": True
                },
                "metadata": {"delivery_id": delivery_id}
            },
            timeout=15,
        )
        
        try:
            data = resp.json()
        except Exception:
            data = {"message": f"RAW ERROR: {resp.text}"}
            
        call_id = data.get("id") or ""
        call_status = "initiated" if resp.status_code in (200, 201) else "failed"
        error_msg = "" if resp.status_code in (200, 201) else str(data.get("message", data))[:300]
        
    except Exception as e:
        call_id = ""
        call_status = "failed"
        error_msg = str(e)[:300]

    try:
        from .database import SessionLocal
        db = SessionLocal()
        try:
            db.execute(
                __import__("sqlalchemy").text(
                    "INSERT INTO call_logs (delivery_id, call_id, phone, trigger_status, call_status, error_msg, created_at) "
                    "VALUES (:did, :cid, :phone, :ts, :cs, :err, :now)"
                ),
                {"did": delivery_id, "cid": call_id, "phone": formatted_phone, "ts": status, "cs": call_status, "err": error_msg, "now": datetime.utcnow()}
            )
            db.commit()
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Failed to save log: {e}")

def trigger_call(delivery_id: int, phone: str | None, status: str, customer_name: str, items: str, address: str = "") -> None:
    if not phone or not phone.strip() or status not in SCRIPTS: return
    threading.Thread(target=_do_call, args=(delivery_id, phone.strip(), status, customer_name, items, address), daemon=True).start()