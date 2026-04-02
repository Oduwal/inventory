"""Shared utility functions used across multiple modules."""


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
