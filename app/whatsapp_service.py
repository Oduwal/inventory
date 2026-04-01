import os
import logging
from twilio.rest import Client

logger = logging.getLogger("whatsapp")

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_WHATSAPP_NUMBER = os.getenv("TWILIO_WHATSAPP_NUMBER", "")

def format_nigerian_phone(phone: str) -> str:
    """Automatically cleans and formats phone numbers to E.164 (+234...)."""
    if not phone: return ""
    clean = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "").strip()
    if clean.startswith("0") and len(clean) == 11: return "+234" + clean[1:]
    if clean.startswith("234") and len(clean) == 13: return "+" + clean
    if clean.startswith("+"): return clean
    return clean

def send_whatsapp_fallback(delivery_id: int, phone: str, customer_name: str, items: str):
    """Sends a WhatsApp message when the AI call goes to voicemail or fails."""
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        logger.warning("Twilio credentials missing. Skipping WhatsApp.")
        return

    # Use the smart formatter so Twilio doesn't reject it!
    clean_phone = format_nigerian_phone(phone)
    if not clean_phone:
        return
        
    whatsapp_to = f"whatsapp:{clean_phone}"
    business_name = os.getenv("BUSINESS_NAME", "Atomic Logistics")

    message_body = (
        f"Hello {customer_name},\n\n"
        f"We are trying to reach you from {business_name} regarding your order of {items}.\n\n"
        f"Are you available to receive this delivery today?\n"
        f"Reply *1* for YES (Available)\n"
        f"Reply *2* for NO (Reschedule for tomorrow)"
    )

    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            from_=TWILIO_WHATSAPP_NUMBER,
            body=message_body,
            to=whatsapp_to
        )
        logger.info(f"WhatsApp fallback sent to {clean_phone} for delivery #{delivery_id}. SID: {message.sid}")
    except Exception as e:
        logger.error(f"Failed to send WhatsApp to {clean_phone}: {str(e)}")