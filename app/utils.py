"""Shared utility functions used across multiple modules."""


def get_whatsapp_phone(customer_whatsapp: str, customer_phone: str) -> str:
    """Return the WhatsApp number to use for a delivery.
    Prefers the dedicated customer_whatsapp field; falls back to the first
    number in customer_phone if customer_whatsapp is empty.
    """
    wa = (customer_whatsapp or "").strip()
    if wa:
        return wa
    phone = (customer_phone or "").strip()
    if not phone:
        return ""
    return phone.replace(";", ",").replace("/", ",").split(",")[0].strip()


def format_nigerian_phone(phone: str) -> str:
    """Automatically cleans and formats phone numbers to E.164 (+234...)."""
    if not phone:
        return ""
    clean = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "").strip()
    if clean.startswith("0") and len(clean) == 11:
        return "+234" + clean[1:]
    if clean.startswith("234") and len(clean) == 13:
        return "+" + clean
    if clean.startswith("+"):
        return clean
    return clean
