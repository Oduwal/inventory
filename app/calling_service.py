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
    "PENDING": (
        "You are a polite and professional customer service agent working for a Nigerian logistics company named {business_name}. "
        "You are calling a customer named {customer_name} regarding their recent order. "
        "The order contains the following items: {items}. "
        "The delivery address currently on file is: {address}. "
        "INSTRUCTIONS: "
        "1. Greet the customer warmly (e.g., 'Good day'). "
        "2. Inform them you are calling from {business_name} to confirm their order of {items} has been received by the branch. "
        "3. If the delivery address is exactly 'MISSING_ADDRESS', you MUST politely ask the customer to provide their full delivery address so you can process the dispatch. "
        "4. If the delivery address is NOT 'MISSING_ADDRESS', read the address to them and ask if it is correct. "
        "5. Answer any quick questions they have politely, and end the call."
    ),
    "OUT_FOR_DELIVERY": (
        "Hello, may I speak with {customer_name}? "
        "This is a message from {business_name}. "
        "Your order of {items} is currently on its way to your address at {address}. "
        "Our delivery agent will arrive shortly. Please make sure someone is available to receive it. "
        "Thank you and have a great day!"
    ),
    "DELIVERED": (
        "Hello, may I speak with {customer_name}? "
        "This is {business_name} calling to confirm that your order of {items} "
        "has been successfully delivered to {address}. "
        "We hope you are satisfied with your purchase. Thank you for choosing us!"
    ),
    "FAILED": (
        "Hello, may I speak with {customer_name}? "
        "This is {business_name}. We attempted to deliver your order of {items} to {address} today "
        "but unfortunately we were unable to complete the delivery. "
        "Please contact us so we can reschedule."
    ),
    "RETURNED": (
        "Hello, may I speak with {customer_name}? "
        "This is {business_name}. We are calling to let you know that your order of {items} "
        "has been returned to our office. Please reach out to us."
    ),
}

def _build_script(status: str, customer_name: str, items: str, address: str = "") -> str:
    business_name = os.getenv("BUSINESS_NAME", "our logistics company")
    template = SCRIPTS.get(status, "Hello {customer_name}, this is {business_name} calling about your order.")
    
    # Flag empty addresses so the AI knows to ask for it
    display_address = address if address and address.strip() else "MISSING_ADDRESS"
    
    return template.format(
        customer_name=customer_name or "valued customer",
        business_name=business_name,
        items=items or "your order",
        address=display_address
    )

def _do_call(delivery_id: int, phone: str, status: str, customer_name: str, items: str, address: str) -> None:
    """Runs in a background thread — makes the Vapi API call and logs the result."""
    if not VAPI_API_KEY or not VAPI_PHONE_NUMBER_ID:
        logger.warning("VAPI keys not set — skipping call for delivery #%s", delivery_id)
        return

    script = _build_script(status, customer_name, items, address)
    business_name = os.getenv("BUSINESS_NAME", "Atomic Logistics")
    
    # Ensure this is your actual live Railway app URL
    YOUR_RAILWAY_APP_URL = os.getenv("APP_URL", "https://inventory-production-d41e.up.railway.app")

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
                        "voiceId": "burt"
                    },
                    # Tell the AI to summarize the call focusing on logistics details
                    "serverMessages": ["end-of-call-report"],
                    "clientMessages": ["transcript", "hang", "function-call"],
                    "endCallFunctionEnabled": True
                },
                # Vapi will send the summary to this endpoint when the call hangs up
                "serverUrl": f"{YOUR_RAILWAY_APP_URL}/api/call-webhook",
                # Pass the delivery_id so the webhook knows which order to update
                "metadata": {
                    "delivery_id": delivery_id
                }
            },
            timeout=15,
        )
        
        # ==========================================
        # NEW SAFER PARSING LOGIC
        # ==========================================
        try:
            data = resp.json()
        except Exception:
            # If Vapi returns plain text (like an unauthorized or gateway error)
            data = {"message": f"RAW ERROR: {resp.text}"}
            
        call_id = data.get("id") or ""
        call_status = "initiated" if resp.status_code in (200, 201) else "failed"
        
        # Capture the real error message safely
        if resp.status_code in (200, 201):
            error_msg = ""
            logger.info("Vapi call for delivery #%s: call_id=%s status=%s", delivery_id, call_id, call_status)
        else:
            error_msg = str(data.get("message", data))[:300]
            logger.error("Vapi rejected call #%s (Status %s): %s", delivery_id, resp.status_code, error_msg)
        # ==========================================
            
    except Exception as e:
        call_id = ""
        call_status = "failed"
        error_msg = str(e)[:300]
        logger.error("Vapi call error for delivery #%s: %s", delivery_id, e)

    # Persist log to DB
    _save_call_log(delivery_id, call_id, phone, status, call_status, error_msg)

def _save_call_log(delivery_id: int, call_id: str, phone: str, status: str, call_status: str, error_msg: str) -> None:
    """Save the call log to the database."""
    # TODO: Implement database logging for call records
    logger.debug("Call log for delivery #%s: call_id=%s phone=%s status=%s call_status=%s error=%s",
                 delivery_id, call_id, phone, status, call_status, error_msg)

def trigger_call(delivery_id: int, phone: str | None, status: str,
                 customer_name: str, items: str, address: str | None = None) -> None:
    if not phone or not phone.strip():
        logger.info("No phone for delivery #%s — skipping call", delivery_id)
        return
    if status not in SCRIPTS:
        return
    threading.Thread(
        target=_do_call,
        args=(delivery_id, phone.strip(), status, customer_name, items, address or ""),
        daemon=True,
    ).start()
