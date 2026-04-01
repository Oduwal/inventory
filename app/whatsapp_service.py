import os
import logging
from twilio.rest import Client

logger = logging.getLogger("whatsapp")

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_WHATSAPP_NUMBER = os.getenv("TWILIO_WHATSAPP_NUMBER", "")

def send_whatsapp_fallback(delivery_id: int, phone: str, customer_name: str, items: str):
    """Sends a WhatsApp message when the AI call goes to voicemail or fails."""
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        logger.warning("Twilio credentials missing. Skipping WhatsApp.")
        return

    # Format the phone number for WhatsApp
    clean_phone = phone.strip()
    if not clean_phone.startswith('+'):
        clean_phone = '+' + clean_phone
    whatsapp_to = f"whatsapp:{clean_phone}"
    business_name = os.getenv("BUSINESS_NAME", "Daggo Africa")

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
        logger.info(f"WhatsApp fallback sent to {phone} for delivery #{delivery_id}. SID: {message.sid}")
    except Exception as e:
        logger.error(f"Failed to send WhatsApp to {phone}: {str(e)}")