import os
import logging
import threading
import random
from datetime import datetime, timezone
import httpx
from sqlalchemy import text as sa_text

from .utils import format_nigerian_phone

logger = logging.getLogger("calling")

VAPI_API_KEY = os.getenv("VAPI_API_KEY", "")
VAPI_PHONE_NUMBER_ID = os.getenv("VAPI_PHONE_NUMBER_ID", "")

# ==============================================================
# 1. THE AGENT ROSTER (Add as many as you want!)
# ==============================================================
AVAILABLE_AGENTS = [
    {"name": "Olabisi", "voiceId": "eOHsvebhdtt0XFeHVMQY"}, # Deep, professional male
    {"name": "Flourish", "voiceId": "3AKbojRHFojiSeAMRPt3"}, # Polite, clear female
    {"name": "Tobi",  "voiceId": "D9xwB6HNBJ9h4YvQFWuE"},  # Energetic, young male
    {"name": "Tolani",  "voiceId": "JMwQvjJt08OhYlPBWeyc"},
    {"name": "Taiwo",  "voiceId": "RAVWJW17BPoSIf05iXxf"},
    {"name": "Chineye",  "voiceId": "PSIwmc50KeuW20kehlBE"},
    {"name": "Samuel",  "voiceId": "ddDFRErfhdc2asyySOG5"},
    {"name": "John",  "voiceId": "3mwVS2Cu52S8MzAVx66c"}
]
# ==============================================================
# RESTORED HELPER FUNCTION (Prevents main.py from crashing)
# ==============================================================
SCRIPTS: dict[str, str] = {
    "PENDING": "Your order of {items} has been received.",
    "OUT_FOR_DELIVERY": "Your order of {items} is currently out for delivery to {address}.",
    "DELIVERED": "Your order of {items} was successfully delivered.",
    "FAILED": "We attempted to deliver your order of {items} to {address} but were unsuccessful."
}

def _build_script(status: str, customer_name: str, items: str, address: str) -> str:
    """Provides a basic script preview for the main dashboard."""
    business_name = os.getenv("BUSINESS_NAME", "Atomic Logistics")
    template = SCRIPTS.get(status, "Hello {customer_name}, this is {business_name} calling.")
    display_address = address if address and address.strip() else "an unconfirmed address"
    return template.format(
        customer_name=customer_name or "valued customer",
        business_name=business_name,
        items=items or "your order",
        address=display_address
    )

def _do_call(delivery_id: int, phone: str, backup_numbers: list, status: str, customer_name: str, items: str, address: str) -> None:
    if not VAPI_API_KEY or not VAPI_PHONE_NUMBER_ID:
        logger.warning("VAPI keys not set — skipping call for delivery #%s", delivery_id)
        return

    formatted_phone = format_nigerian_phone(phone)
    if not formatted_phone: return

    business_name = os.getenv("BUSINESS_NAME", "Atomic Logistics")
    YOUR_RAILWAY_APP_URL = os.getenv("APP_URL", "https://inventory-production-d41e.up.railway.app").rstrip('/')
    display_name = customer_name or "valued customer"
    display_address = address if address and address.strip() else "your saved address"

    agent = random.choice(AVAILABLE_AGENTS)
    agent_name = agent["name"]
    agent_voice_id = agent["voiceId"]

    first_message = f"Hello? Is this {display_name}?"
    
    company_knowledge = (
        f"COMPANY KNOWLEDGE BASE: "
        f"- Business Name: {business_name}. "
        f"- Operating Hours: {os.getenv('BUSINESS_HOURS', '8:00 AM to 6:00 PM, Monday to Saturday. Closed on Sundays.')} "
        f"- Delivery Zones: {os.getenv('DELIVERY_ZONES', 'We deliver across major cities in Nigeria.')} "
        f"- Rescheduling: Customers can reschedule a delivery to the next day for free. "
        f"- Payment: We accept bank transfers and cash on delivery. "
        f"- Support: If they have a major complaint, tell them to message our WhatsApp support line."
    )

    spoken_status = status.replace('_', ' ').lower()

    system_prompt = (
        f"You are {agent_name}, a friendly, patient, and highly professional dispatch coordinator for {business_name}. "
        f"You are calling to update the customer on their order: {items}. "
        f"Delivery Status: {spoken_status}. Delivery Address: {display_address}. "
        f"{company_knowledge} "
        f"\n\nCRITICAL CONVERSATION RULES: "
        f"\n1. NEVER rush the customer. You must act like a real, patient human having a real conversation. "
        f"\n2. PRONUNCIATION RULE: Do NOT say 'X2' or 'X1'. If the order items say 'Biscuits X2', you must smoothly say 'two Biscuits'. Read the quantities naturally like a human. "
        f"\n3. When they answer and confirm their name, say: 'Hi, I'm {agent_name} from {business_name}. I am calling because your order is currently {spoken_status}. Will you be available at the address to receive it?' then STOP TALKING and listen. "
        f"\n4. If they interrupt you, STOP TALKING immediately, listen to them, and acknowledge what they said. "
        f"\n5. Answer any questions they have confidently using the COMPANY KNOWLEDGE BASE. "
        f"\n6. HOW TO END THE CALL: When the main topic is resolved, YOU MUST ASK: 'Is there anything else I can help you with today?'. "
        f"\n7. STRICT GOODBYE RULE: If the customer says 'No', you MUST recite exactly: 'Thank you. Do have a nice day. Bye.' You MUST generate this full spoken sentence FIRST before triggering the hang-up function. NEVER just say 'goodbye'."
    )

    summary_prompt = (
        "You are an expert executive assistant. Summarize this phone call accurately in 1 to 2 sentences. "
        "You MUST include: 1. Did the customer confirm they will be available to receive the delivery? "
        "2. Did they ask to reschedule or change the address? 3. Any specific questions or complaints they had. "
        "Write this clearly so the human dispatch team knows exactly what to do next."
    )

    try:
        resp = httpx.post(
            "https://api.vapi.ai/call/phone",
            headers={"Authorization": f"Bearer {VAPI_API_KEY}", "Content-Type": "application/json"},
            json={
                "phoneNumberId": VAPI_PHONE_NUMBER_ID,
                "customer": {"number": formatted_phone},
                "assistant": {
                    "firstMessage": first_message,
                    "model": {
                        "provider": "google",
                        "model": "gemini-2.5-flash-lite",
                        "messages": [{"role": "system", "content": system_prompt}]
                    },
                    "voice": {
                        "provider": "11labs",
                        "voiceId": agent_voice_id
                    },
                    "summaryPrompt": summary_prompt,
                    "serverUrl": f"{YOUR_RAILWAY_APP_URL}/api/call-webhook",
                    "serverMessages": ["end-of-call-report"],
                    "clientMessages": ["transcript", "hang", "function-call"],
                    "endCallFunctionEnabled": True
                },
                "metadata": {
                    "delivery_id": delivery_id,
                    "backup_numbers": backup_numbers,
                    "status": status,
                    "customer_name": customer_name,
                    "items": items,
                    "address": address
                }
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
                sa_text(
                    "INSERT INTO call_logs (delivery_id, call_id, phone, trigger_status, call_status, error_msg, created_at) "
                    "VALUES (:did, :cid, :phone, :ts, :cs, :err, :now)"
                ),
                {"did": delivery_id, "cid": call_id, "phone": formatted_phone, "ts": status, "cs": call_status, "err": error_msg, "now": datetime.now(timezone.utc)}
            )
            db.commit()
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Failed to save log: {e}")

def trigger_call(delivery_id: int, phone: str | None, status: str, customer_name: str, items: str, address: str = "") -> None:
    if not phone or not phone.strip(): return

    # Check supervisor toggles before placing any call
    try:
        from app.database import SessionLocal
        from app.feature_toggles import is_feature_on
        _db = SessionLocal()
        try:
            if not is_feature_on(_db, "call_enabled"):
                logger.info("Calls disabled by supervisor toggle. Skipping delivery #%s", delivery_id)
                return
            if not is_feature_on(_db, f"call_status_{status}"):
                logger.info("Calls for status %s disabled by supervisor toggle. Skipping delivery #%s", status, delivery_id)
                return
        finally:
            _db.close()
    except Exception as _e:
        logger.warning("Could not check feature toggles: %s — proceeding with call", _e)

    # Safely split numbers separated by comma, slash, or space
    raw_numbers = [p.strip() for p in phone.replace(';', ',').replace('/', ',').split(',') if p.strip()]
    if not raw_numbers: return

    primary = raw_numbers[0]
    backups = raw_numbers[1:]

    from app.core import task_queue
    task_queue.submit(_do_call, delivery_id, primary, backups, status, customer_name, items, address)