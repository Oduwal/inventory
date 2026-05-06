import os
import json
import re
import logging

import httpx
from sqlalchemy import select

from app.models import Item

_log = logging.getLogger("order_parser")

SYSTEM_INSTRUCTION = (
    "You are an order parser for a Nigerian logistics business. "
    "You MUST return ONLY a valid JSON object — no markdown, no code "
    "fences, no explanation. Start with { and end with }."
)


def _build_prompt(text: str, items_catalog) -> str:
    # Catalog prices are intentionally NOT included in the prompt.
    # Pricing is set per-order in the WhatsApp message body, not on the SKU.
    # Aliases give Gemini synonyms sellers might use for the same item.
    catalog = "\n".join(
        f"{i.id}|{i.name}|{(i.aliases or '').strip()}" for i in items_catalog
    )
    return (
        "Parse this Nigerian order message into JSON.\n\n"
        f"Available items (id|name|aliases):\n{catalog}\n\n"
        "MATCHING RULE: A product line in the message matches an item if "
        "either the catalog name OR any comma-separated alias substring "
        "appears in the seller's product description (case-insensitive). "
        "If 'aliases' is empty, only the name is used. "
        "If a single phrase like 'female tea set' matches aliases on TWO "
        "different items, include BOTH items in the order (qty=1 each unless "
        "stated). Set matched=true and use the catalog id.\n\n"
        "PRICING CONVENTION — read carefully:\n"
        "- Prices come ONLY from the message body. Never invent a price.\n"
        "- A product line may list ONE number after the qty/product or TWO "
        "numbers separated by a comma or space.\n"
        "- ONE number → that number is the LINE TOTAL for the whole line. "
        "Compute unit_price = line_total / quantity. "
        "Example: 'zudes 5, 10000' → quantity=5, line_total=10000, "
        "unit_price=2000.\n"
        "- TWO numbers → the FIRST is unit_price, the SECOND is line_total. "
        "Example: 'zudes 5, 2000, 10000' → quantity=5, unit_price=2000, "
        "line_total=10000.\n"
        "- Numbers near labels like 'Total order value', 'Amount to collect', "
        "'Grand total' belong in total_price, NOT inside any item line.\n"
        "- If a line has no price at all, leave unit_price=0 and line_total=0.\n\n"
        "Return JSON with: customer_name, customer_phone, customer_whatsapp, "
        "address, note, total_price, items[{item_id,item_name,quantity,"
        "unit_price,line_total,matched}], unmatched_items[], confidence "
        "(\"high\"|\"medium\"|\"low\"). line_total must equal "
        "unit_price * quantity exactly.\n\n"
        f"Message:\n\"\"\"{text}\"\"\""
    )


async def parse_order_text(text: str, db, branch_id: int) -> dict | None:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return None
    items = db.execute(
        select(Item).where(Item.branch_id == branch_id, Item.is_active == True).order_by(Item.name.asc())
    ).scalars().all()
    if not items:
        return None
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"gemini-2.5-flash:generateContent?key={api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
                    "contents": [{"role": "user", "parts": [{"text": _build_prompt(text, items)}]}],
                    "generationConfig": {
                        "temperature": 0.1,
                        "maxOutputTokens": 32768,
                        "thinkingConfig": {"thinkingBudget": 0},
                    },
                },
            )
        data = resp.json()
        if "error" in data:
            return None
        parts = data["candidates"][0]["content"]["parts"]
        raw = "".join(p["text"] for p in parts if p.get("text") and not p.get("thought"))
        raw = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception as e:
        _log.warning("parse_order_text failed: %s", e)
        return None
