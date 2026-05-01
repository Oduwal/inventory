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
    catalog = "\n".join(
        f"{i.id}|{i.name}|{float(i.selling_price or 0)}" for i in items_catalog
    )
    return (
        "Parse this Nigerian order message into JSON.\n\n"
        f"Available items (id|name|unit_price):\n{catalog}\n\n"
        "Return JSON with: customer_name, customer_phone, customer_whatsapp, "
        "address, note, total_price, items[{item_id,item_name,quantity,"
        "unit_price,matched}], unmatched_items[], confidence "
        "(\"high\"|\"medium\"|\"low\").\n\n"
        f"Message:\n\"\"\"{text}\"\"\""
    )


async def parse_order_text(text: str, db, branch_id: int) -> dict | None:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return None
    items = db.execute(
        select(Item).where(Item.branch_id == branch_id).order_by(Item.name.asc())
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
