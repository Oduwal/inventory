from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime, timezone
import json, os, logging, re, asyncio, httpx
from app.core import *
from app.models import *
from app.security import *
from app.whatsapp_service import send_whatsapp_fallback
from app.calling_service import _build_script

router = APIRouter()
_log = logging.getLogger("whatsapp")


# ─────────────────────────────────────────────────────────────────
# CALL WEBHOOK  (Vapi end-of-call report)
# ─────────────────────────────────────────────────────────────────
@router.post("/api/call-webhook")
async def call_webhook(request: Request, db: Session = Depends(get_db)):
    """Receives the end-of-call report from Vapi and updates call_logs + delivery notes.
    No webhook token check — Vapi is an external service that cannot send custom headers.
    Protected by delivery_id metadata validation instead."""
    try:
        payload = await request.json()
        _log = logging.getLogger("webhook")
        _log.info("Vapi webhook received: keys=%s", list(payload.keys()))

        message = payload.get("message", {})
        msg_type = message.get("type", "")
        _log.info("Vapi message type: '%s'", msg_type)

        if msg_type != "end-of-call-report":
            return JSONResponse({"status": "ignored"})

        call_data = message.get("call", {})
        metadata = call_data.get("metadata", {})
        delivery_id = metadata.get("delivery_id")
        call_id = call_data.get("id", "")

        if not delivery_id:
            return JSONResponse({"error": "No delivery_id in metadata"}, status_code=400)

        # Log full structure to find where Vapi puts summary/endedReason
        _log.info("Vapi call_data keys=%s", list(call_data.keys()) if call_data else "NONE")
        _log.info("Vapi message-level keys=%s", list(message.keys()))

        # Vapi puts summary in different places depending on version
        # NOTE: use `or {}` at end — .get() returns None if key exists with value None
        analysis = message.get("analysis") or call_data.get("analysis") or {}
        summary = (
            message.get("summary", "")
            or analysis.get("summary", "")
            or call_data.get("summary", "")
            or ""
        )
        ended_reason = (
            message.get("endedReason", "")
            or call_data.get("endedReason", "")
            or ""
        )
        duration = int(message.get("durationSeconds") or call_data.get("duration") or 0)

        _log.info("Vapi extracted: summary='%s' endedReason='%s' duration=%s", summary[:80], ended_reason, duration)

        if not summary:
            summary = "No summary provided by AI."

        # ── Update call_logs with summary, duration, and final status ──
        call_status = "completed" if ended_reason not in (
            "error", "assistant-error", "failed"
        ) else "failed"
        if call_id:
            db.execute(text(
                "UPDATE call_logs SET summary=:s, duration=:d, call_status=:cs "
                "WHERE call_id=:cid"
            ), {"s": summary[:1000], "d": duration, "cs": call_status, "cid": call_id})

        # ── Update delivery notes ──
        d = db.get(Delivery, int(delivery_id))
        if d:
            existing_note = d.note or ""
            d.note = (existing_note + f"\n[AI Call Update]: {summary}").strip()

            logging.getLogger("webhook").info(
                "Call %s ended: reason='%s' status='%s' duration=%ss",
                delivery_id, ended_reason, call_status, duration
            )

            # Trigger fallback logic if call failed
            if ended_reason in [
                "voicemail", "customer-hung-up", "customer-ended-call",
                "customer-did-not-answer", "failed", "assistant-error", "customer-busy"
            ]:
                backup_numbers = metadata.get("backup_numbers", [])

                # Check if we have more numbers to try first
                if len(backup_numbers) > 0:
                    next_number = backup_numbers[0]
                    remaining_backups = backup_numbers[1:]

                    d.note += f"\n[System]: Call to {call_data.get('customer', {}).get('number')} failed. Trying backup number: {next_number}..."
                    db.commit()

                    # Launch the backup call using the metadata we saved
                    from app.calling_service import _do_call
                    task_queue.submit(
                        _do_call, d.id, next_number, remaining_backups,
                        metadata.get("status", "PENDING"),
                        metadata.get("customer_name", d.customer_name),
                        metadata.get("items", "your order"),
                        metadata.get("address", d.address or "")
                    )

                else:
                    # No backups left! Send the WhatsApp message
                    try:
                        # Fetch the item names for the WhatsApp message
                        items_query = db.execute(
                            select(Item.name, DeliveryItem.quantity)
                            .join(DeliveryItem, DeliveryItem.item_id == Item.id)
                            .where(DeliveryItem.delivery_id == d.id)
                        ).all()
                        items_str = ", ".join(f"{r.name} x{r.quantity}" for r in items_query) if items_query else "your order"

                        send_whatsapp_fallback(d.id, d.customer_phone, d.customer_name, items_str)
                        d.note += "\n[System]: All numbers failed. WhatsApp Fallback message triggered."
                        logging.getLogger("webhook").info(f"Fallback WhatsApp message triggered for delivery {d.id} to {d.customer_phone}")
                    except Exception as wa_err:
                        logging.getLogger("webhook").error(f"WhatsApp fallback error: {wa_err}")

            db.commit()

            # Notify the assigned agent
            if d.agent_id:
                notify(db, d.agent_id, "📞 Customer Call Update",
                       f"The AI spoke to {d.customer_name}. Update: {summary}",
                       f"/deliveries/{d.id}", "warning")

        return JSONResponse({"status": "success"})
    except Exception as e:
        logging.getLogger("webhook").error(f"Webhook error: %s", e, exc_info=True)
        return JSONResponse({"error": "Internal webhook processing error."}, status_code=500)


# ─────────────────────────────────────────────────────────────────
# TWILIO WHATSAPP REPLY  (customer replies via Twilio)
# ─────────────────────────────────────────────────────────────────
@router.post("/api/whatsapp-reply")
async def whatsapp_reply(request: Request, db: Session = Depends(get_db)):
    """Receives replies from customers via Twilio WhatsApp.
    Uses AI to understand the message and respond intelligently.
    Protected by Twilio's HMAC-SHA1 signature verification (uses TWILIO_AUTH_TOKEN).
    This endpoint is also listed in _ORIGIN_CHECK_EXEMPT in security.py.
    """
    form_data = await request.form()
    # [SEC-11] Verify Twilio signature — rejects forged requests
    verify_twilio_signature_with_params(request, dict(form_data))

    sender = form_data.get("From", "").replace("whatsapp:", "")
    body = form_data.get("Body", "").strip()
    num_media = int(form_data.get("NumMedia", "0"))
    _log.info("WhatsApp reply from %s: body='%s' media=%d", sender, body[:200], num_media)

    # Handle voice notes / audio messages
    if num_media > 0 and not body:
        media_url = form_data.get("MediaUrl0", "")
        media_type = form_data.get("MediaContentType0", "")
        _log.info("Media attachment: type=%s url=%s", media_type, media_url[:100])

        if media_type and media_type.startswith("audio/"):
            loop = asyncio.get_event_loop()
            body = await loop.run_in_executor(None, _transcribe_voice_note, media_url, media_type)
            if body:
                _log.info("Voice note transcribed: %s", body[:200])
                body = f"[Voice Note]: {body}"
            else:
                body = "[Voice Note]: (could not transcribe)"
        elif media_type and media_type.startswith("image/"):
            body = "[Image sent — no text provided]"
        else:
            body = f"[Media: {media_type}]"

    if not body:
        return PlainTextResponse("OK", status_code=200)

    # Find the most recent active delivery for this phone number
    # Twilio sends E.164 (+234...), DB may store as 080... or +234...
    # Try multiple formats for matching
    phone_variants = [sender]
    if sender.startswith("+234"):
        phone_variants.append("0" + sender[4:])   # +2348012345678 → 08012345678
        phone_variants.append(sender[1:])          # +2348012345678 → 2348012345678
    elif sender.startswith("0"):
        phone_variants.append("+234" + sender[1:])

    d = None
    for variant in phone_variants:
        d = db.execute(
            select(Delivery)
            .where(Delivery.customer_phone.contains(variant))
            .where(Delivery.status.in_(["PENDING", "OUT_FOR_DELIVERY"]))
            .order_by(Delivery.created_at.desc())
        ).scalars().first()
        if d:
            break

    if not d:
        _log.info("WhatsApp reply from %s — no matching delivery found", sender)
        return PlainTextResponse("OK", status_code=200)

    # Fetch items for context
    items_query = db.execute(
        select(Item.name, DeliveryItem.quantity)
        .join(DeliveryItem, DeliveryItem.item_id == Item.id)
        .where(DeliveryItem.delivery_id == d.id)
    ).all()
    items_str = ", ".join(f"{r.name} x{r.quantity}" for r in items_query) if items_query else "your order"

    # Build conversation history from delivery notes
    existing_note = d.note or ""
    business_name = os.getenv("BUSINESS_NAME", "Atomic Logistics")
    business_phone = os.getenv("BUSINESS_PHONE", "")

    # Use AI to understand and respond
    loop = asyncio.get_event_loop()
    ai_result = await loop.run_in_executor(
        None, _handle_customer_reply, body, d.customer_name, items_str,
        d.address or "", d.status, existing_note, business_name, business_phone
    )

    ai_reply = ai_result.get("reply", "")
    classification = ai_result.get("classification", "OTHER")
    summary = ai_result.get("summary", body[:100])

    # Log the conversation on delivery notes
    d.note = (existing_note + f"\n[Customer WhatsApp]: {body}\n[AI Reply]: {ai_reply}\n[Classification]: {classification}").strip()

    # Handle specific classifications
    notify_msg = f"{d.customer_name} via WhatsApp: {summary}"
    if classification == "CONFIRMED_AVAILABLE":
        d.note += "\n[System]: Customer confirmed availability."
    elif classification == "RESCHEDULE_REQUEST":
        d.note += "\n[System]: Customer wants to reschedule."
    elif classification == "ADDRESS_CHANGE":
        d.note += "\n[System]: Customer wants to change delivery address — needs manual review."
    elif classification == "COMPLAINT":
        d.note += "\n[System]: Customer has a complaint — needs attention."

    db.commit()

    # Send the AI reply back to the customer via Twilio (within 24hr window since they just messaged)
    _send_twilio_reply(sender, ai_reply)

    # Notify the assigned agent or branch admins
    if d.agent_id:
        notify(db, d.agent_id, "💬 WhatsApp Reply", notify_msg, f"/deliveries/{d.id}", "info")
    else:
        notify_branch_admins(db, d.branch_id, "💬 WhatsApp Reply", notify_msg, f"/deliveries/{d.id}", "info")

    return PlainTextResponse("OK", status_code=200)


# ─────────────────────────────────────────────────────────────────
# AGENT WHATSAPP REPLY (agent sends message to customer from dashboard)
# ─────────────────────────────────────────────────────────────────
@router.post("/api/agent-whatsapp-reply")
async def agent_whatsapp_reply(request: Request, db: Session = Depends(get_db)):
    """Allows an agent/admin to send a WhatsApp message to a customer from the delivery page."""
    user = get_current_user(db, request)
    if not user:
        return JSONResponse({"ok": False, "error": "Not logged in"}, status_code=401)

    body = await request.json()
    delivery_id = body.get("delivery_id")
    message = (body.get("message") or "").strip()

    if not delivery_id or not message:
        return JSONResponse({"ok": False, "error": "Missing delivery_id or message"}, status_code=400)

    d = db.get(Delivery, int(delivery_id))
    if not d:
        return JSONResponse({"ok": False, "error": "Delivery not found"}, status_code=404)
    if not d.customer_phone:
        return JSONResponse({"ok": False, "error": "No customer phone number on this delivery"}, status_code=400)

    from app.utils import format_nigerian_phone
    phone = format_nigerian_phone(d.customer_phone.split(",")[0].strip())
    if not phone:
        return JSONResponse({"ok": False, "error": "Invalid phone number"}, status_code=400)

    # Send via Twilio
    _send_twilio_reply(phone, message)

    # Log on delivery notes
    existing_note = d.note or ""
    agent_name = user.full_name or user.username
    d.note = (existing_note + f"\n[Agent {agent_name}]: {message}").strip()
    db.commit()

    _log.info("Agent %s replied to delivery %s: %s", agent_name, delivery_id, message[:100])
    return JSONResponse({"ok": True})


# ─────────────────────────────────────────────────────────────────
# VOICE NOTE TRANSCRIPTION (Gemini)
# ─────────────────────────────────────────────────────────────────
def _transcribe_voice_note(media_url: str, media_type: str) -> str:
    """Download audio from Twilio and transcribe via Gemini."""
    if not _GEMINI_KEY:
        _log.warning("No GEMINI_API_KEY — cannot transcribe voice note")
        return ""

    # Twilio requires auth to download media
    from app.whatsapp_service import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN
    try:
        audio_resp = httpx.get(media_url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN), timeout=15, follow_redirects=True)
        if audio_resp.status_code != 200:
            _log.warning("Failed to download voice note: HTTP %s", audio_resp.status_code)
            return ""
        audio_bytes = audio_resp.content
        if len(audio_bytes) > 10_000_000:  # 10MB limit
            _log.warning("Voice note too large: %d bytes", len(audio_bytes))
            return ""
    except Exception as e:
        _log.error("Error downloading voice note: %s", e)
        return ""

    import base64
    audio_b64 = base64.b64encode(audio_bytes).decode()

    # Map common Twilio media types to Gemini mime types
    mime_map = {"audio/ogg": "audio/ogg", "audio/mpeg": "audio/mpeg", "audio/amr": "audio/amr",
                "audio/aac": "audio/aac", "audio/mp4": "audio/mp4", "audio/ogg; codecs=opus": "audio/ogg"}
    mime_type = mime_map.get(media_type, media_type.split(";")[0].strip())

    try:
        resp = httpx.post(
            f"{_GEMINI_URL}?key={_GEMINI_KEY}",
            json={
                "contents": [{
                    "role": "user",
                    "parts": [
                        {"inlineData": {"mimeType": mime_type, "data": audio_b64}},
                        {"text": "Transcribe this voice message exactly as spoken. Return ONLY the transcription text, nothing else. If you cannot understand it, return 'unclear'."},
                    ],
                }],
                "generationConfig": {"temperature": 0.1, "maxOutputTokens": 500},
            },
            timeout=20,
        )
        text_out = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        return text_out
    except Exception as e:
        _log.error("Gemini voice transcription failed: %s", e)
        return ""


# ─────────────────────────────────────────────────────────────────
# AI-POWERED CUSTOMER REPLY HANDLER
# ─────────────────────────────────────────────────────────────────
def _handle_customer_reply(
    customer_msg: str, customer_name: str, items: str,
    address: str, status: str, existing_notes: str,
    business_name: str, business_phone: str
) -> dict:
    """Use Gemini to understand a customer's WhatsApp reply and generate a response."""
    if not _GEMINI_KEY:
        return {
            "reply": f"Thank you for your message. Our team will get back to you shortly. For urgent enquiries, please call {business_phone or 'our office'}.",
            "classification": "OTHER",
            "summary": customer_msg[:100],
        }

    spoken_status = status.replace("_", " ").lower()
    phone_line = f"Our contact number is {business_phone}." if business_phone else ""

    # Include recent notes for context (last 500 chars)
    recent_notes = existing_notes[-500:] if existing_notes else "No prior notes."

    # Company knowledge base — same as calling service
    company_knowledge = (
        f"COMPANY KNOWLEDGE BASE (use this to answer customer questions):\n"
        f"- Business Name: {business_name}\n"
        f"- Operating Hours: {os.getenv('BUSINESS_HOURS', '8:00 AM to 6:00 PM, Monday to Saturday. Closed on Sundays.')}\n"
        f"- Delivery Zones: {os.getenv('DELIVERY_ZONES', 'We deliver across major cities in Nigeria.')}\n"
        f"- Rescheduling: Customers can reschedule a delivery to the next day for free.\n"
        f"- Modifications: Even after a delivery is out for dispatch, customers can still request modifications (add/remove items, change address, special instructions). Just let the customer know and the team will handle it.\n"
        f"- Payment: We accept bank transfers and cash on delivery.\n"
        f"- Contact: {phone_line or 'Customer can reply to this chat.'}\n"
        f"- Support: For major complaints, customers should message our WhatsApp support line.\n"
    )

    prompt = (
        f"You are a friendly customer service agent for {business_name}. "
        f"A customer named {customer_name} replied to a WhatsApp message about their delivery.\n\n"
        f"{company_knowledge}\n"
        f"DELIVERY DETAILS:\n"
        f"Order: {items}. Status: {spoken_status}. Address: {address or 'Not specified'}.\n"
        f"Recent notes: {recent_notes[-300:]}\n\n"
        f"Customer said: \"{customer_msg}\"\n\n"
        f"Write a clear WhatsApp reply (2-4 sentences). Be warm, professional, and helpful. "
        f"Make sure the customer fully understands what is happening with their order and what to expect next. "
        f"If they asked a question, answer it using the COMPANY KNOWLEDGE BASE above. "
        f"If they confirmed something, acknowledge it and explain the next step. "
        f"Do not make up information that is not in the knowledge base. "
        f"Do not start with 'Hi {customer_name}' every time — vary your greeting. "
        f"Reply with ONLY the message text, nothing else."
    )

    # Classify intent with simple keyword matching (no need for Gemini)
    msg_lower = customer_msg.lower()
    if any(w in msg_lower for w in ["yes", "available", "i'm home", "im home", "i am home", "come", "ready"]):
        classification = "CONFIRMED_AVAILABLE"
    elif any(w in msg_lower for w in ["reschedule", "tomorrow", "next", "not today", "another day", "later"]):
        classification = "RESCHEDULE_REQUEST"
    elif any(w in msg_lower for w in ["address", "location", "move", "changed address"]):
        classification = "ADDRESS_CHANGE"
    elif any(w in msg_lower for w in ["complain", "bad", "angry", "worst", "terrible", "disappointed", "rubbish"]):
        classification = "COMPLAINT"
    elif any(w in msg_lower for w in ["when", "what time", "how long", "where", "how much", "?"]):
        classification = "QUESTION"
    else:
        classification = "OTHER"

    try:
        resp = httpx.post(
            f"{_GEMINI_URL}?key={_GEMINI_KEY}",
            json={
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.4, "maxOutputTokens": 2048},
            },
            timeout=20,
        )

        if resp.status_code != 200:
            _log.error("Gemini reply API error: %s", resp.text[:500])
            raise ValueError(f"Gemini API returned {resp.status_code}")

        reply_text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        # Clean up any JSON or markdown artifacts Gemini might add
        reply_text = re.sub(r'^```.*\n?', '', reply_text)
        reply_text = reply_text.strip('`"')
        _log.info("Gemini reply: %s", reply_text[:200])

        return {"reply": reply_text, "classification": classification, "summary": customer_msg[:100]}
    except Exception as e:
        _log.error("Gemini customer-reply failed: %s", e)
        return {
            "reply": f"Thank you for your message. Our team has been notified and will get back to you shortly.",
            "classification": classification,
            "summary": customer_msg[:100],
        }


def _send_twilio_reply(to_number: str, message: str):
    """Send a freeform WhatsApp reply via Twilio (within 24hr window)."""
    from app.whatsapp_service import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_NUMBER
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not message:
        return
    try:
        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(
            from_=TWILIO_WHATSAPP_NUMBER,
            body=message,
            to=f"whatsapp:{to_number}",
        )
        _log.info("Twilio AI reply sent to %s", to_number)
    except Exception as e:
        _log.error("Failed to send Twilio reply to %s: %s", to_number, e)


# ─────────────────────────────────────────────────────────────────
# SSE CONNECTION MANAGER
# Each delivery page that is open holds an asyncio.Queue here.
# When a new WA comment arrives we put an event into every queue.
# ─────────────────────────────────────────────────────────────────
_sse_queues: dict[int, list[asyncio.Queue]] = {}   # delivery_id → [queue, ...]

def _sse_broadcast(delivery_id: int, html_fragment: str):
    """Push an SSE event to all open browser tabs for this delivery."""
    for q in _sse_queues.get(delivery_id, []):
        try:
            q.put_nowait(html_fragment)
        except asyncio.QueueFull:
            pass

@router.get("/api/stream/{delivery_id}")
async def sse_stream(delivery_id: int, request: Request, db: Session = Depends(get_db)):
    """
    Server-Sent Events endpoint.  The delivery detail page connects here
    and receives new wa_comments HTML fragments in real time.
    """
    # [SEC] Require authentication — prevent unauthenticated data leaks
    user = get_current_user(db, request)
    if not user:
        return PlainTextResponse("Unauthorized", status_code=401)
    q: asyncio.Queue = asyncio.Queue(maxsize=50)
    _sse_queues.setdefault(delivery_id, []).append(q)

    async def generator():
        try:
            yield "retry: 5000\n\n"   # tell browser to reconnect after 5s
            while True:
                if await request.is_disconnected():
                    break
                try:
                    html_frag = await asyncio.wait_for(q.get(), timeout=25)
                    yield f"event: wa_comment\ndata: {html_frag}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"   # keep-alive comment
        finally:
            lst = _sse_queues.get(delivery_id, [])
            if q in lst:
                lst.remove(q)

    return StreamingResponse(generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─────────────────────────────────────────────────────────────────
# GEMINI MULTI-TURN CLASSIFICATION (runs in threadpool so it doesn't
# block the event loop — Gemini HTTP call can take 2-5s)
# ─────────────────────────────────────────────────────────────────
_GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")
_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

def _call_gemini_classify(thread: list[dict], latest_reply: str) -> dict:
    """
    Build a transcript of the last few messages and ask Gemini to classify
    the latest seller reply IN CONTEXT.  Returns a dict matching the schema:
    { "classification": str, "contextual_summary": str, "action_required": bool }
    """
    if not _GEMINI_KEY:
        return {"classification": "OTHER", "contextual_summary": latest_reply[:100], "action_required": False}

    transcript_lines = []
    for m in thread:
        direction = "Agent → Group" if m["direction"] == "outbound" else "Seller reply"
        transcript_lines.append(f"[{direction}]: {m['body']}")
    transcript = "\n".join(transcript_lines)

    prompt = (
        "You are a precise logistics coordinator AI. Below is a WhatsApp conversation thread "
        "between a delivery agent (sending updates to a seller group) and sellers replying.\n\n"
        f"THREAD:\n{transcript}\n\n"
        f"The latest seller reply is:\n\"{latest_reply}\"\n\n"
        "Evaluate the latest reply IN CONTEXT of the full thread and respond ONLY with valid JSON "
        "matching this exact schema (no markdown, no explanation):\n"
        '{"classification": "<QUESTION|COMPLAINT|CONFIRMED_AVAILABLE|RESCHEDULE_REQUEST|ADDRESS_CHANGE|RESOLVED|OTHER>", '
        '"contextual_summary": "<one sentence max 20 words explaining what the seller needs>", '
        '"action_required": <true|false>}'
    )

    try:
        resp = httpx.post(
            f"{_GEMINI_URL}?key={_GEMINI_KEY}",
            json={"contents": [{"role": "user", "parts": [{"text": prompt}]}],
                  "generationConfig": {"temperature": 0.1, "maxOutputTokens": 150}},
            timeout=10,
        )
        text_out = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        # Strip markdown fences if Gemini wraps anyway
        if text_out.startswith("```"):
            text_out = text_out.strip("`").lstrip("json").strip()
        return json.loads(text_out)
    except Exception as e:
        logging.getLogger("gemini").warning("Gemini classify failed: %s", e)
        return {"classification": "OTHER", "contextual_summary": latest_reply[:100], "action_required": False}


# ─────────────────────────────────────────────────────────────────
# GROUP PARTICIPANTS (fetch members for @mention picker)
# ─────────────────────────────────────────────────────────────────
@router.get("/api/group-participants/{delivery_id}")
async def get_group_participants(delivery_id: int, request: Request, db: Session = Depends(get_db)):
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"error": "Not logged in"}, status_code=401)

    delivery = db.execute(select(Delivery).where(Delivery.id == delivery_id)).scalar_one_or_none()
    if not delivery:
        return JSONResponse({"error": "Delivery not found"}, status_code=404)

    # Find group JID: from outbound map or category map
    orig_map = db.execute(text(
        "SELECT group_jid FROM whatsapp_outbound_map "
        "WHERE order_id = :oid AND source = 'group' ORDER BY created_at ASC LIMIT 1"
    ), {"oid": delivery.id}).first()

    group_jid = orig_map[0] if orig_map else None

    if not group_jid:
        try:
            cgm = json.loads(os.getenv("CATEGORY_GROUP_MAP", "{}"))
        except (ValueError, TypeError):
            cgm = {}
        cat = db.execute(
            select(Item.category)
            .join(DeliveryItem, DeliveryItem.item_id == Item.id)
            .where(DeliveryItem.delivery_id == delivery.id)
            .limit(1)
        ).scalar()
        group_jid = cgm.get(cat, "")

    if not group_jid:
        return JSONResponse({"participants": [], "group": ""})

    try:
        bot_url = os.getenv("WHATSAPP_BOT_URL", "http://adventurous-flow.railway.internal:3000")
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{bot_url}/group-participants", params={"jid": group_jid}, timeout=15)
            return JSONResponse(resp.json())
    except Exception as e:
        return JSONResponse({"error": str(e), "participants": []})


# AGENT FEEDBACK  (agent clicks a button → bot sends to group)
# ─────────────────────────────────────────────────────────────────
@router.post("/api/agent-feedback")
async def send_agent_feedback(
    request: Request,
    delivery_id: int = Form(...),
    issue_type: str = Form(...),
    custom_message: str = Form(""),
    group_name: str = Form(""),
    mention_phone: str = Form(""),
    db: Session = Depends(get_db)
):
    # [SEC] Require login — prevent unauthenticated users from sending messages
    user_or = require_login_or_redirect(db, request)
    if isinstance(user_or, RedirectResponse):
        return JSONResponse({"status": "error", "message": "Not logged in"}, status_code=401)

    delivery = db.execute(select(Delivery).where(Delivery.id == delivery_id)).scalar_one_or_none()
    if not delivery:
        return JSONResponse({"status": "error", "message": "Delivery not found"}, status_code=404)

    from app.feature_toggles import is_feature_on
    if not is_feature_on(db, "whatsapp_seller_enabled"):
        return JSONResponse({"status": "error", "message": "Seller WhatsApp messaging is currently disabled by the supervisor."}, status_code=403)

    update_templates = {
        "OUT_FOR_DELIVERY": f"🚚 *Out for Delivery*\n{delivery.customer_name} — on its way, will be delivered shortly.",
        "CALLED_CUSTOMER":  f"📞 *Customer Called*\n{delivery.customer_name} — agent has called to confirm delivery.",
        "NOT_PICKING":      f"📵 *Customer Not Reachable*\n{delivery.customer_name} — unable to reach. Please advise.",
        "DELIVERED":        f"✅ *Delivered*\n{delivery.customer_name} — successfully delivered. Thank you!",
    }
    if issue_type == "CUSTOM" and custom_message.strip():
        message = custom_message.strip()
    else:
        message = update_templates.get(
            issue_type,
            f"📣 {delivery.customer_name} — {issue_type}"
        )

    # Mention tag will be appended after we know who posted the original order
    # Always quote the ORIGINAL group order post (source='group'), not a bot update.
    # This anchors the reply thread to the seller's original message in the group,
    # making it obvious which order is being discussed regardless of how many updates
    # the agent has sent.
    # 1. Safely read from the database using index numbers to prevent crashes
    orig_map = db.execute(text(
        "SELECT message_id, body, sender, group_jid FROM whatsapp_outbound_map "
        "WHERE order_id = :oid AND source = 'group' ORDER BY created_at ASC LIMIT 1"
    ), {"oid": delivery.id}).first()

    if orig_map:
        quote_id     = orig_map[0]
        quote_body   = orig_map[1]
        raw_sender   = orig_map[2] or ""
        fallback_grp = orig_map[3]
        # Parse "Name|jid" format or plain jid
        if "|" in raw_sender:
            seller_name, quote_sender = raw_sender.split("|", 1)
        else:
            seller_name = ""
            quote_sender = raw_sender
    else:
        quote_id = quote_body = quote_sender = fallback_grp = seller_name = None

    # Build mentions list and append @tags to the message
    mention_jids = []
    mention_tags = []

    # Only mention people explicitly picked by the agent from the live group picker.
    # Auto-mentioning from DB is unreliable — JIDs change when WhatsApp is reconnected.
    if mention_phone:
        if "@" in mention_phone:
            # Already a JID from the picker
            if mention_phone not in mention_jids:
                mention_jids.append(mention_phone)
                digits = mention_phone.replace("@s.whatsapp.net", "").replace("@lid", "")
                mention_tags.append(f"@{digits}")
        else:
            # Raw phone number typed manually
            from app.utils import format_nigerian_phone
            clean = format_nigerian_phone(mention_phone)
            if clean:
                digits = clean.lstrip("+")
                jid = f"{digits}@s.whatsapp.net"
                if jid not in mention_jids:
                    mention_jids.append(jid)
                    mention_tags.append(f"@{digits}")

    if mention_tags:
        message += "\n\n" + " ".join(mention_tags)

    # 2. STRICT CATEGORY ROUTING FOR MULTIPLE GROUPS
    # Configurable via CATEGORY_GROUP_MAP env var as JSON, e.g.:
    # {"DAGGO":"120363418850903362@g.us","NEXTILE":"120363304493232977@g.us"}
    try:
        CATEGORY_GROUP_MAP = json.loads(os.getenv("CATEGORY_GROUP_MAP", "{}"))
    except (ValueError, TypeError):
        CATEGORY_GROUP_MAP = {}

    delivery_category = db.execute(
        select(Item.category)
        .join(DeliveryItem, DeliveryItem.item_id == Item.id)
        .where(DeliveryItem.delivery_id == delivery.id)
        .limit(1)
    ).scalar()

    # Priority: category map from env (always current) → DB fallback → empty
    # The DB group_jid can become stale when WhatsApp is reconnected with a new number,
    # so prefer the env var which the user keeps up-to-date.
    known_groups = set(CATEGORY_GROUP_MAP.values())
    if delivery_category and delivery_category in CATEGORY_GROUP_MAP:
        target_group = CATEGORY_GROUP_MAP[delivery_category]
    elif fallback_grp and (not known_groups or fallback_grp in known_groups):
        target_group = fallback_grp
    else:
        target_group = list(known_groups)[0] if known_groups else ""

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                os.getenv("WHATSAPP_BOT_URL", "http://adventurous-flow.railway.internal:3000") + "/send-group-feedback",
                json={
                    "orderId":            str(delivery.id),
                    "message":            message,
                    "quoteMessageId":     quote_id,
                    "quoteMessageBody":   quote_body,
                    "quoteMessageSender": quote_sender,
                    "quoteMessageFromMe": False,
                    "targetGroupJid":     target_group,
                    "mentions":           mention_jids,
                },
                timeout=60,
            )
            data = resp.json()

        if not data.get("success"):
            return JSONResponse({"status": "error", "message": data.get("error", "Bot error")})

        # Persist the new Baileys message_id so future sends can quote it,
        # and inbound replies can be routed back to this order in O(1).
        new_msg_id = data.get("message_id", "")
        is_sqlite = DATABASE_URL.startswith("sqlite")
        if new_msg_id:
            if is_sqlite:
                upsert_sql = (
                    "INSERT OR REPLACE INTO whatsapp_outbound_map (message_id, order_id, body, source, sender, group_jid, created_at) "
                    "VALUES (:mid, :oid, :body, 'bot', '', :gjid, :_now)"
                )
            else:
                upsert_sql = (
                    "INSERT INTO whatsapp_outbound_map (message_id, order_id, body, source, sender, group_jid, created_at) "
                    "VALUES (:mid, :oid, :body, 'bot', '', :gjid, :_now) "
                    "ON CONFLICT (message_id) DO UPDATE SET order_id=EXCLUDED.order_id, body=EXCLUDED.body, source=EXCLUDED.source, sender=EXCLUDED.sender, group_jid=EXCLUDED.group_jid"
                )
            db.execute(text(upsert_sql), {"mid": new_msg_id, "oid": delivery.id, "body": message, "gjid": target_group, "_now": _now()})
            db.commit()

        # Save outbound comment for the chat thread UI
        db.execute(text(
            "INSERT INTO wa_comments (delivery_id, direction, sender, body, created_at) "
            "VALUES (:did, 'outbound', 'Agent', :body, :_now)"
        ), {"did": delivery.id, "body": message, "_now": _now()})
        db.commit()

        # SSE broadcast so open tabs update immediately
        now_str  = datetime.now(timezone.utc).strftime("%d %b %H:%M")
        _sse_msg = html.escape(message)
        fragment = (
            f'<div style="align-self:flex-end;max-width:80%;background:#005c4b;color:#e9edef;'
            f'padding:6px 10px;border-radius:8px 0 8px 8px;font-size:13px;line-height:1.4;">'
            f'<span style="font-size:10px;color:#8fdfcb;font-weight:600;display:block;margin-bottom:2px;">Agent → Group</span>'
            f'<div style="white-space:pre-wrap;">{_sse_msg}</div>'
            f'<div style="font-size:9px;color:rgba(255,255,255,.45);text-align:right;margin-top:2px;">{now_str}</div>'
            f'</div>'
        )
        _sse_broadcast(delivery.id, fragment)

        return JSONResponse({"status": "success", "message": "Feedback sent to group!"})

    except Exception as e:
        return JSONResponse({"status": "error", "message": f"Clawbot is offline: {str(e)}"})


# ─────────────────────────────────────────────────────────────────
# WHATSAPP WEBHOOK  (bot posts inbound seller replies here)
# ─────────────────────────────────────────────────────────────────
@router.post("/api/whatsapp-webhook")
async def whatsapp_webhook(request: Request, db: Session = Depends(get_db)):
    _verify_webhook_token(request)
    data                = await request.json()
    quoted_msg_id       = data.get("quoted_message_id", "").strip()
    quoted_msg_body     = data.get("quoted_message_body", "").strip()
    reply_text          = data.get("reply_text", "").strip()
    sender              = data.get("sender_phone", "")
    sender_name         = data.get("sender_name", "").strip()
    group_jid           = data.get("groupJid", "").strip()

    if not reply_text:
        return {"status": "ignored"}

    _log = logging.getLogger("wa_webhook")

    order_id = None

    # ── Step 0: Direct Regex Match (100% Bulletproof) ─────────────────
    # Check if the seller typed "Order 123" or quoted a bot message saying "Order #123"
    combined_text = f"{reply_text} {quoted_msg_body}"
    direct_match = re.search(r'order\s*#?\s*(\d+)', combined_text, re.IGNORECASE)
    if direct_match:
        extracted_id = int(direct_match.group(1))
        valid = db.execute(text("SELECT id FROM deliveries WHERE id = :oid"), {"oid": extracted_id}).first()
        if valid:
            order_id = extracted_id
            _log.info("Matched by explicit text regex → Order #%s", order_id)

    # ── Step 1: O(1) lookup by quoted message ID ──────────────────────
    if not order_id and quoted_msg_id:
        row = db.execute(text(
            "SELECT order_id FROM whatsapp_outbound_map WHERE message_id = :mid"
        ), {"mid": quoted_msg_id}).first()
        if row:
            order_id = row[0]
            _log.info("Matched by message_id → Order #%s", order_id)

    # ── Step 2: Fallback — strict phone match ─────────────────────────
    if not order_id and quoted_msg_body:
        _log.info("ID lookup missed — trying strict phone match on quoted body")
        phone_m = re.search(r'(?:\+?234|0)[789]\d[\s\-]?\d{3,4}[\s\-]?\d{3,4}', quoted_msg_body)
        qphone  = phone_m.group(0).replace(' ', '').replace('-', '') if phone_m else ''
        qphone_digits = qphone.replace('+234', '0')[-10:] if qphone else ''

        if qphone_digits:
            # Also try to extract a name from the quoted body for stricter matching
            # Typical format: "Customer Name\nPhone: 080...\nItems: ..."
            qname_lines = [ln.strip() for ln in quoted_msg_body.split('\n') if ln.strip()]
            q_name = ""
            _SKIP_RE = re.compile(r'^(phone|address|item|product|qty|quantity|note|location|area|delivery|order|price|amount|date|status)', re.IGNORECASE)
            for ln in qname_lines:
                if _SKIP_RE.match(ln) or re.match(r'^[\d\+\(]', ln):
                    continue
                name_words = [w for w in ln.split() if re.match(r"^[A-Za-z\'-]{2,}$", w)]
                if len(name_words) >= 2:
                    q_name = ln.strip().lower()
                    break

            candidates = db.execute(text(
                "SELECT id, customer_phone, customer_name FROM deliveries "
                "WHERE status IN ('PENDING','OUT_FOR_DELIVERY') ORDER BY id DESC LIMIT 200"
            )).fetchall()

            # Prefer: same-group > phone+name > phone-only
            same_group_match = None
            phone_and_name_match = None
            phone_only_match = None
            for c in candidates:
                c_id, c_phone, c_name = c[0], c[1], c[2]
                db_phone = (c_phone or '').replace(' ', '').replace('-', '')[-10:]
                if not (db_phone and qphone_digits == db_phone):
                    continue

                # Check name match if we extracted one from the quoted body
                c_name_lower = (c_name or '').lower()
                name_match = False
                if q_name and c_name_lower:
                    q_words = [w for w in q_name.split() if len(w) > 2]
                    if len(q_words) >= 2 and all(w in c_name_lower for w in q_words):
                        name_match = True
                    elif q_name == c_name_lower:
                        name_match = True

                # Same-group is highest priority
                if group_jid:
                    grp_row = db.execute(text(
                        "SELECT 1 FROM whatsapp_outbound_map WHERE order_id = :oid AND group_jid = :gjid LIMIT 1"
                    ), {"oid": c_id, "gjid": group_jid}).first()
                    if grp_row:
                        same_group_match = c_id
                        break

                if q_name and name_match and not phone_and_name_match:
                    phone_and_name_match = c_id
                if not phone_only_match:
                    phone_only_match = c_id

            order_id = same_group_match or phone_and_name_match or phone_only_match
            if order_id:
                _log.info("Matched by phone in quoted body → Order #%s (same_group=%s)", order_id, bool(same_group_match))
                if quoted_msg_id:
                    conflict = "ON CONFLICT (message_id) DO NOTHING" if not DATABASE_URL.startswith("sqlite") else ""
                    try:
                        db.execute(text(
                            f"INSERT INTO whatsapp_outbound_map (message_id, order_id, body, source, group_jid, created_at) "
                            f"VALUES (:mid, :oid, :body, 'group', :gjid, :_now) {conflict}"
                        ), {"mid": quoted_msg_id, "oid": order_id, "body": quoted_msg_body, "gjid": group_jid, "_now": _now()})
                        db.commit()
                    except Exception:
                        pass

    if not order_id:
        _log.warning("Could not match reply to any delivery — quoted_id=%s", quoted_msg_id)
        return {"status": "unmatched"}

    delivery = db.execute(select(Delivery).where(Delivery.id == order_id)).scalar_one_or_none()
    if not delivery:
        return {"status": "not_found"}

    # Fetch last 8 messages for multi-turn Gemini context
    thread_rows = db.execute(text(
        "SELECT direction, body FROM wa_comments "
        "WHERE delivery_id = :did ORDER BY created_at DESC LIMIT 8"
    ), {"did": order_id}).fetchall()
    thread = [{"direction": r[0], "body": r[1]} for r in reversed(thread_rows)]

    # Classify in a thread so we don't block the event loop
    loop = asyncio.get_event_loop()
    ai   = await loop.run_in_executor(None, _call_gemini_classify, thread, reply_text)
    classification_json = json.dumps(ai)

    # Render comment body: show AI summary prominently, raw text below
    label   = ai.get("classification", "OTHER")
    summary = ai.get("contextual_summary", reply_text[:100])
    
    # Add the quoted message so the agent knows what the seller is replying to
    quote_context = f"\n\nReplying to:\n> {quoted_msg_body}" if quoted_msg_body else ""
    comment_body = f"[{label}] {summary}{quote_context}\n\nSeller said: \"{reply_text}\""

    # Use friendly name for display, fall back to phone digits
    display_sender = sender_name or sender.replace("@s.whatsapp.net", "").replace("@lid", "")
    db.execute(text(
        "INSERT INTO wa_comments (delivery_id, direction, sender, body, classification, created_at) "
        "VALUES (:did, 'inbound', :sender, :body, :clf, :_now)"
    ), {"did": order_id, "sender": display_sender, "body": comment_body, "clf": classification_json, "_now": _now()})
    db.commit()

    # SSE — push fragment to any open delivery detail tabs
    now_str  = datetime.now(timezone.utc).strftime("%d %b %H:%M")
    action_badge = ' <span style="color:#f59e0b;font-size:10px;">⚠ ACTION</span>' if ai.get("action_required") else ""
    _sse_sender = html.escape(display_sender or "Seller")
    _sse_body   = html.escape(comment_body)
    fragment = (
        f'<div style="align-self:flex-start;max-width:80%;background:#1f2c34;color:#e9edef;'
        f'padding:6px 10px;border-radius:0 8px 8px 8px;font-size:13px;line-height:1.4;">'
        f'<span style="font-size:10px;color:#53bdeb;font-weight:600;display:block;margin-bottom:2px;">'
        f'{_sse_sender}{action_badge}</span>'
        f'<div style="white-space:pre-wrap;">{_sse_body}</div>'
        f'<div style="font-size:9px;color:rgba(255,255,255,.35);margin-top:2px;">{now_str}</div>'
        f'</div>'
    )
    _sse_broadcast(order_id, fragment)

    # Persistent notifications (bell + web push)
    notif_title = f"💬 Seller Reply — Order #{order_id}"
    notif_msg   = f"{display_sender or 'Seller'}: {summary}"
    notif_link  = f"/deliveries/{order_id}"
    if delivery.agent_id:
        notify(db, delivery.agent_id, notif_title, notif_msg, notif_link, "info")
    admin_ids = db.execute(text("SELECT id FROM users WHERE role='ADMIN'")).scalars().all()
    for aid in admin_ids:
        if aid != delivery.agent_id:
            notify(db, aid, notif_title, notif_msg, notif_link, "info")

    return {"status": "received", "order_id": order_id, "classification": label}


# ─────────────────────────────────────────────────────────────────
# CACHE WA MESSAGE  (bot caches group messages for order matching)
# ─────────────────────────────────────────────────────────────────
@router.post("/api/cache-wa-message")
async def cache_wa_message(request: Request, db: Session = Depends(get_db)):
    """
    Called by the bot for every non-reply group message.
    The bot uses Gemini to extract customer_name and customer_phone from the text.
    Python fuzzy-matches those against its delivery records to find the order_id.
    Stores (message_id → order_id, source='group') so agent-feedback can always
    quote the ORIGINAL group post when sending updates.
    """
    _verify_webhook_token(request)
    data           = await request.json()
    message_id     = (data.get("message_id") or "").strip()
    body           = (data.get("body") or "").strip()
    sender         = (data.get("sender") or "").strip()
    sender_name    = (data.get("sender_name") or "").strip()
    group_jid      = (data.get("groupJid") or "").strip()
    customer_name  = (data.get("customer_name") or "").strip().lower()
    customer_phone = (data.get("customer_phone") or "").strip().replace(" ", "")

    if not message_id or (not customer_name and not customer_phone):
        return {"status": "ignored"}

    # Fuzzy match against recent PENDING/OUT_FOR_DELIVERY deliveries only
    candidates = db.execute(text(
        "SELECT id, customer_name, customer_phone FROM deliveries "
        "WHERE status IN ('PENDING','OUT_FOR_DELIVERY') "
        "ORDER BY created_at DESC LIMIT 200"
    )).fetchall()

    matched_order_id = None
    for row in candidates:
        r_id, r_name, r_phone = row[0], row[1], row[2]
        db_name  = (r_name or "").lower()
        db_phone = (r_phone or "").replace(" ", "").replace("-", "")

        # 🛡️ THE ANTI-STEAL SAFEGUARD: 
        # If this order ALREADY has an original group message linked to it, DO NOT steal it.
        has_group_msg = db.execute(text(
            "SELECT 1 FROM whatsapp_outbound_map WHERE order_id = :oid AND source = 'group'"
        ), {"oid": r_id}).first()
        if has_group_msg:
            continue

        # Match logic: use BOTH phone+name when both are available to avoid
        # conflicts when the same phone number appears on multiple orders.
        phone_ok = False
        if customer_phone and db_phone and len(customer_phone) >= 10:
            phone_ok = (customer_phone[-10:] == db_phone[-10:])

        name_ok = False
        if customer_name and db_name and len(customer_name) > 3:
            words = [w for w in customer_name.split() if len(w) > 2]
            if len(words) >= 2 and all(w in db_name for w in words):
                name_ok = True
            elif customer_name == db_name:
                name_ok = True

        # Phone match is the strongest signal — always trust it
        if phone_ok:
            matched_order_id = r_id
            break
        # Name-only match (no phone extracted) — acceptable fallback
        if name_ok and not customer_phone:
            matched_order_id = r_id
            break

    if not matched_order_id:
        logging.getLogger("cache_wa").info(
            "cache-wa-message: no delivery matched name='%s' phone='%s' — saving to pending cache", customer_name, customer_phone
        )
        # Save to pending cache so it can be matched when the delivery IS created
        _pend_conflict = "ON CONFLICT (message_id) DO NOTHING" if not DATABASE_URL.startswith("sqlite") else "OR IGNORE"
        try:
            pend_sender = f"{sender_name}|{sender}" if sender_name else sender
            db.execute(text(
                f"INSERT {_pend_conflict} INTO wa_pending_cache "
                f"(message_id, body, sender, group_jid, customer_name, customer_phone, created_at) "
                f"VALUES (:mid, :body, :sender, :gjid, :cname, :cphone, :_now)"
            ), {"mid": message_id, "body": body, "sender": pend_sender, "gjid": group_jid,
                "cname": customer_name, "cphone": customer_phone, "_now": _now()})
            db.commit()
        except Exception:
            db.rollback()
        return {"status": "pending"}

    # ── Persist the mapping so replies and agent-feedback can find this order ──
    is_sqlite = DATABASE_URL.startswith("sqlite")
    if is_sqlite:
        upsert_sql = (
            "INSERT OR REPLACE INTO whatsapp_outbound_map "
            "(message_id, order_id, body, source, sender, group_jid, created_at) "
            "VALUES (:mid, :oid, :body, 'group', :sender, :gjid, :_now)"
        )
    else:
        upsert_sql = (
            "INSERT INTO whatsapp_outbound_map "
            "(message_id, order_id, body, source, sender, group_jid, created_at) "
            "VALUES (:mid, :oid, :body, 'group', :sender, :gjid, :_now) "
            "ON CONFLICT (message_id) DO UPDATE SET order_id=EXCLUDED.order_id, "
            "body=EXCLUDED.body, source=EXCLUDED.source, sender=EXCLUDED.sender, group_jid=EXCLUDED.group_jid"
        )
    # Store JID for quoting, but keep sender_name for display
    # Format: "Name|jid" so we can split later for both quoting and display
    sender_value = f"{sender_name}|{sender}" if sender_name else sender
    try:
        db.execute(text(upsert_sql), {
            "mid": message_id, "oid": matched_order_id,
            "body": body, "sender": sender_value, "gjid": group_jid, "_now": _now()
        })
        db.commit()
        logging.getLogger("cache_wa").info(
            "cache-wa-message: saved message_id=%s → Order #%s (group=%s)",
            message_id[:20], matched_order_id, group_jid[:20] if group_jid else ""
        )
    except Exception as e:
        logging.getLogger("cache_wa").error("cache-wa-message: failed to save mapping: %s", e)
        db.rollback()

    return {"status": "matched", "order_id": matched_order_id}
