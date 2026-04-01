import os
import logging
import threading
import random
from datetime import datetime
import httpx

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
# Note: You can replace these Voice IDs ywith your custom ElevenLabs ones!

def format_nigerian_phone(phone: str) -> str:
    """Automatically cleans and formats phone numbers to E.164 (+234...)."""
    if not phone: return ""
    clean = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "").strip()
    if clean.startswith("0") and len(clean) == 11: return "+234" + clean[1:]
    if clean.startswith("234") and len(clean) == 13: return "+" + clean
    if clean.startswith("+"): return clean
    return clean

def _do_call(delivery_id: int, phone: str, status: str, customer_name: str, items: str, address: str) -> None:
    if not VAPI_API_KEY or not VAPI_PHONE_NUMBER_ID:
        logger.warning("VAPI keys not set — skipping call for delivery #%s", delivery_id)
        return

    formatted_phone = format_nigerian_phone(phone)
    if not formatted_phone: return

    business_name = os.getenv("BUSINESS_NAME", "Atomic Logistics")
    YOUR_RAILWAY_APP_URL = os.getenv("APP_URL", "https://inventory-production-d41e.up.railway.app").rstrip('/')
    display_name = customer_name or "valued customer"
    display_address = address if address and address.strip() else "your saved address"

    # ==============================================================
    # 2. RANDOMLY SELECT AN AGENT FOR THIS CALL
    # ==============================================================
    agent = random.choice(AVAILABLE_AGENTS)
    agent_name = agent["name"]
    agent_voice_id = agent["voiceId"]

    # ==============================================================
    # 3. CONVERSATIONAL PROMPT SETTINGS
    # ==============================================================
    # The AI only says this to start, forcing the user to speak first.
    first_message = f"Hello? Is this {display_name}?"
    
    # This is the AI's "Brain". It knows the details but won't dump them all at once.
    system_prompt = (
        f"You are {agent_name}, a highly professional, human-like dispatch coordinator for {business_name}. "
        f"You are calling to update them on their order: {items}. "
        f"Delivery Status: {status}. Delivery Address: {display_address}. "
        f"CRITICAL CONVERSATION RULES: "
        f"1. When the customer confirms their name, introduce yourself naturally: 'Hi, I'm {agent_name} from {business_name}...' and state the reason for your call. "
        f"2. Keep your responses EXTREMELY short (1 to 2 sentences max). "
        f"3. Speak casually, use conversational filler words like 'hmm' or 'ah', and PAUSE frequently so the customer can interrupt you. "
        f"4. Do NOT read the entire address or item list unless they ask for it. "
        f"5. If they want to reschedule or change the address, say: 'I have noted that down, and I will immediately pass the message to the dispatch rider.' "
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
                        "provider": "openai",
                        "model": "gpt-3.5-turbo",
                        "messages": [{"role": "system", "content": system_prompt}],
                        "temperature": 0.7 # Makes the AI sound less robotic and more natural
                    },
                    "voice": {
                        "provider": "11labs", 
                        "voiceId": agent_voice_id,
                        "elevenLabsConfig": {
                            "modelId": "eleven_multilingual_v2" # Helps adapt to local accents better
                        }
                    },
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

    # Save to database
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
    if not phone or not phone.strip(): return
    threading.Thread(target=_do_call, args=(delivery_id, phone.strip(), status, customer_name, items, address), daemon=True).start()