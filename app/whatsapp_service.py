import os
import json
import logging
from twilio.rest import Client

from .utils import format_nigerian_phone

logger = logging.getLogger("whatsapp")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_WHATSAPP_NUMBER = os.getenv("TWILIO_WHATSAPP_NUMBER", "")
# Set this to your approved WhatsApp Content Template SID (e.g. "HXxxxxxxx")
# Required for messaging customers outside the 24-hour window
TWILIO_CONTENT_SID = os.getenv("TWILIO_CONTENT_SID", "")
BUSINESS_PHONE = os.getenv("BUSINESS_PHONE", "")

def send_whatsapp_fallback(delivery_id: int, phone: str, customer_name: str, items: str):
    """Sends a WhatsApp message when the AI call goes to voicemail or fails."""
    logger.info("WhatsApp send triggered for delivery #%s, phone=%s, from=%s, content_sid=%s",
                delivery_id, phone, TWILIO_WHATSAPP_NUMBER, TWILIO_CONTENT_SID[:10] if TWILIO_CONTENT_SID else "NONE")
    try:
        from app.database import SessionLocal
        from app.feature_toggles import is_feature_on
        _db = SessionLocal()
        try:
            if not is_feature_on(_db, "whatsapp_customer_enabled"):
                logger.info("Customer WhatsApp disabled by supervisor toggle. Skipping delivery #%s", delivery_id)
                return
        finally:
            _db.close()
    except Exception as _e:
        logger.warning("Could not check feature toggles: %s — proceeding with WhatsApp", _e)

    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        logger.warning("Twilio credentials missing. Skipping WhatsApp.")
        return

    # Use the smart formatter so Twilio doesn't reject it!
    clean_phone = format_nigerian_phone(phone)
    if not clean_phone:
        logger.warning("Phone format rejected for delivery #%s: %s", delivery_id, phone)
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

        if TWILIO_CONTENT_SID:
            # Use approved template — required for first-contact (outside 24h window)
            message = client.messages.create(
                from_=TWILIO_WHATSAPP_NUMBER,
                content_sid=TWILIO_CONTENT_SID,
                content_variables=json.dumps({
                    "1": customer_name or "Valued Customer",
                    "2": items or "your order",
                    "3": BUSINESS_PHONE or "our office",
                }),
                to=whatsapp_to,
            )
            logger.info("WhatsApp template sent to %s for delivery #%s. SID: %s, Status: %s",
                        clean_phone, delivery_id, message.sid, message.status)
        else:
            # Freeform — only works within 24-hour window
            message = client.messages.create(
                from_=TWILIO_WHATSAPP_NUMBER,
                body=message_body,
                to=whatsapp_to,
            )
            logger.info("WhatsApp freeform sent to %s for delivery #%s. SID: %s, Status: %s",
                        clean_phone, delivery_id, message.sid, message.status)

    except Exception as e:
        logger.error(f"Failed to send WhatsApp to {clean_phone}: {str(e)}")