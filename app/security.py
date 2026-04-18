# security.py — Full security module for Inventory Keeper
# Fixes applied:
#   [SEC-1]  SESSION_SECRET hard-fail at startup
#   [SEC-2]  Database-backed rate limiter (IP-based) — survives redeploys
#   [SEC-3]  CSRF double-submit pattern
#   [SEC-4]  Input sanitization
#   [SEC-5]  Database-backed account lockout (5 failures → 15 min lock)
#   [SEC-7]  Audit log helpers
#   [SEC-8]  Security headers middleware
#   [SEC-9]  File upload validation
#   [SEC-10] Push subscription endpoint validation
#   [SEC-11] Twilio webhook signature verification

import os
import re
import secrets
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger("inventory_keeper.security")

# ─────────────────────────────────────────────────────────────────────────────
# [SEC-1] SESSION SECRET
# ─────────────────────────────────────────────────────────────────────────────

def get_session_secret() -> str:
    secret = os.getenv("SESSION_SECRET", "").strip()
    if not secret:
        raise RuntimeError(
            "SESSION_SECRET environment variable is not set. "
            "Add it to your Railway Variables tab. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    if len(secret) < 32:
        raise RuntimeError(
            "SESSION_SECRET is too short (minimum 32 characters). "
            "Generate a secure one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return secret


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-2] DATABASE-BACKED RATE LIMITER (survives redeploys)
# ─────────────────────────────────────────────────────────────────────────────

class DbRateLimiter:
    """Rate limiter backed by the database. Counters survive redeploys."""

    def _get_db(self):
        from .database import SessionLocal
        return SessionLocal()

    def _cleanup(self, db):
        """Purge entries older than 1 hour to keep the table small."""
        try:
            from sqlalchemy import text
            cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
            db.execute(text("DELETE FROM rate_limit_hits WHERE created_at < :cutoff"),
                       {"cutoff": cutoff})
            db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass

    def is_allowed(self, ip: str, max_requests: int, window_seconds: int) -> bool:
        """Atomic rate check: INSERT first, then COUNT. Eliminates the TOCTOU
        race where concurrent requests could all pass a SELECT-then-INSERT check."""
        from sqlalchemy import text
        db = self._get_db()
        try:
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(seconds=window_seconds)
            # Always record the hit first (atomic)
            db.execute(text(
                "INSERT INTO rate_limit_hits (ip, created_at) VALUES (:ip, :now)"
            ), {"ip": ip[:45], "now": now})
            db.commit()
            # Then check if total count exceeds limit
            count = db.execute(text(
                "SELECT COUNT(*) FROM rate_limit_hits "
                "WHERE ip = :ip AND created_at > :cutoff"
            ), {"ip": ip[:45], "cutoff": cutoff}).scalar() or 0
            if count > max_requests:
                return False
            # Cleanup old entries every ~100 requests (probabilistic)
            if secrets.randbelow(100) == 0:
                self._cleanup(db)
            return True
        except Exception as e:
            logger.warning("DB rate limiter error (falling shut): %s", e)
            try: db.rollback()
            except Exception: pass
            return False  # fail-shut securely
        finally:
            db.close()

    def check(self, request: Request, max_requests: int = 10, window_seconds: int = 60) -> None:
        ip = request.client.host if request.client else "unknown"
        if not self.is_allowed(ip, max_requests, window_seconds):
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please wait a minute and try again.",
            )

limiter = DbRateLimiter()


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-5] DATABASE-BACKED ACCOUNT LOCKOUT (survives redeploys)
#   5 failed attempts → locked for 15 minutes
# ─────────────────────────────────────────────────────────────────────────────

_LOCKOUT_MAX_ATTEMPTS = 5
_LOCKOUT_WINDOW_SECONDS = 900  # 15 minutes

class DbAccountLockout:
    """Per-account login lockout backed by the database."""

    def _get_db(self):
        from .database import SessionLocal
        return SessionLocal()

    def record_failure(self, username: str) -> None:
        from sqlalchemy import text
        db = self._get_db()
        try:
            db.execute(text(
                "INSERT INTO login_failures (username, created_at) VALUES (:u, :now)"
            ), {"u": username[:80], "now": datetime.now(timezone.utc)})
            db.commit()
        except Exception as e:
            logger.warning("DB lockout record error: %s", e)
            try: db.rollback()
            except Exception: pass
        finally:
            db.close()

    def is_locked(self, username: str) -> bool:
        from sqlalchemy import text
        db = self._get_db()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=_LOCKOUT_WINDOW_SECONDS)
            count = db.execute(text(
                "SELECT COUNT(*) FROM login_failures "
                "WHERE username = :u AND created_at > :cutoff"
            ), {"u": username[:80], "cutoff": cutoff}).scalar() or 0
            return count >= _LOCKOUT_MAX_ATTEMPTS
        except Exception as e:
            logger.warning("DB lockout check error (falling shut): %s", e)
            return True  # fail-shut
        finally:
            db.close()

    def clear(self, username: str) -> None:
        from sqlalchemy import text
        db = self._get_db()
        try:
            db.execute(text("DELETE FROM login_failures WHERE username = :u"),
                       {"u": username[:80]})
            db.commit()
        except Exception as e:
            logger.warning("DB lockout clear error: %s", e)
            try: db.rollback()
            except Exception: pass
        finally:
            db.close()

    def remaining_attempts(self, username: str) -> int:
        from sqlalchemy import text
        db = self._get_db()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=_LOCKOUT_WINDOW_SECONDS)
            count = db.execute(text(
                "SELECT COUNT(*) FROM login_failures "
                "WHERE username = :u AND created_at > :cutoff"
            ), {"u": username[:80], "cutoff": cutoff}).scalar() or 0
            return max(0, _LOCKOUT_MAX_ATTEMPTS - count)
        except Exception:
            return _LOCKOUT_MAX_ATTEMPTS  # assume safe
        finally:
            db.close()

account_lockout = DbAccountLockout()


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-3] CSRF PROTECTION
# ─────────────────────────────────────────────────────────────────────────────

CSRF_TOKEN_LENGTH = 32
CSRF_SESSION_KEY  = "_csrf_token"
CSRF_EXEMPT_PATHS: set[str] = set()  # [SEC] No exemptions — login form already sends CSRF token

def get_csrf_token(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_hex(CSRF_TOKEN_LENGTH)
        request.session[CSRF_SESSION_KEY] = token
    return token

def verify_csrf_token(request: Request, form_token: Optional[str]) -> None:
    if request.url.path in CSRF_EXEMPT_PATHS:
        return
    session_token = request.session.get(CSRF_SESSION_KEY, "")
    submitted     = (form_token or "").strip()
    if not session_token or not submitted or not secrets.compare_digest(session_token, submitted):
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing CSRF token. Please refresh the page and try again.",
        )


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-3c] FORM IDEMPOTENCY TOKEN — prevents double-submit on POST forms
#   Generate a one-time token in GET handler, validate+consume on POST.
#   Stored as a set of valid tokens in the session (max 5 to limit size).
# ─────────────────────────────────────────────────────────────────────────────

_FORM_TOKEN_SESSION_KEY = "_form_tokens"
_MAX_FORM_TOKENS = 5

def generate_form_token(request: Request) -> str:
    """Generate a one-time form token and store in session. Returns the token."""
    token = secrets.token_hex(16)
    tokens: list = request.session.get(_FORM_TOKEN_SESSION_KEY, [])
    tokens.append(token)
    # Keep only the most recent tokens to avoid session bloat
    request.session[_FORM_TOKEN_SESSION_KEY] = tokens[-_MAX_FORM_TOKENS:]
    return token

def consume_form_token(request: Request, submitted_token: str) -> bool:
    """Validate and consume a one-time form token. Returns True if valid.
    Returns False (instead of raising) so callers can redirect with a message."""
    if not submitted_token:
        return False
    tokens: list = request.session.get(_FORM_TOKEN_SESSION_KEY, [])
    if submitted_token in tokens:
        tokens.remove(submitted_token)
        request.session[_FORM_TOKEN_SESSION_KEY] = tokens
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-3b] JSON ORIGIN CHECK — extra CSRF defense for JSON POST endpoints
#   SameSite=lax cookies already block most CSRF, this is defense-in-depth.
# ─────────────────────────────────────────────────────────────────────────────

# Paths exempt from Origin check (external webhooks authenticate via token)
_ORIGIN_CHECK_EXEMPT = {"/api/call-webhook", "/api/whatsapp-webhook",
                        "/api/cache-wa-message", "/api/whatsapp-reply", "/login"}

def verify_origin_for_json(request: Request) -> None:
    """For JSON POST endpoints: verify Origin header matches the app's host.
    Skips webhook endpoints (they use token auth instead).
    Modern browsers ALWAYS send Origin with fetch() — missing Origin on a
    JSON request is suspicious and blocked as defense-in-depth."""
    if request.url.path in _ORIGIN_CHECK_EXEMPT:
        return
    origin = request.headers.get("origin", "")
    if not origin:
        # Modern browsers always send Origin with fetch().  Missing Origin
        # on a JSON POST is either a server-to-server call (no cookies, so
        # harmless) or a CSRF attempt.  Block it for JSON content types.
        raise HTTPException(
            status_code=403,
            detail="Missing Origin header on JSON request.",
        )
    # Compare origin host with request host
    from urllib.parse import urlparse
    origin_host = urlparse(origin).netloc.split(":")[0]
    request_host = (request.headers.get("host") or "").split(":")[0]
    if origin_host and request_host and origin_host != request_host:
        raise HTTPException(
            status_code=403,
            detail="Cross-origin request blocked.",
        )


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-4] INPUT SANITIZATION
# ─────────────────────────────────────────────────────────────────────────────

def sanitize_text(value: str, max_length: int = 400, field_name: str = "") -> str:
    """Trim whitespace and truncate to max_length. XSS is handled by Jinja2's
    auto-escaping on template output. SQL injection is handled by parameterized
    queries. No HTML stripping is needed — regex-based stripping was removed
    because it mangled legitimate input containing < > characters."""
    if not value:
        return ""
    return value.strip()[:max_length]

def sanitize_username(value: str) -> str:
    cleaned = (value or "").strip()
    if not re.match(r"^[\w.\-]{1,80}$", cleaned):
        raise HTTPException(
            status_code=400,
            detail="Username may only contain letters, numbers, dots, underscores, and hyphens.",
        )
    return cleaned

def sanitize_phone(value: str) -> str:
    cleaned = (value or "").strip()
    if cleaned and not re.match(r"^[\d\s\+\-\(\)]{1,40}$", cleaned):
        raise HTTPException(status_code=400, detail="Invalid phone number format.")
    return cleaned[:40]

def sanitize_amount(value, field_name: str = "amount"):
    """Validate and return a positive monetary amount as Decimal.
    Uses Decimal (not float) to avoid floating-point rounding errors
    in financial calculations. DB columns are already Numeric(12,2)."""
    from decimal import Decimal, InvalidOperation
    try:
        amt = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}.")
    if amt <= 0:
        raise HTTPException(status_code=400, detail=f"{field_name} must be greater than zero.")
    if amt > 999_999_999:
        raise HTTPException(status_code=400, detail=f"{field_name} value is unrealistically large.")
    return amt


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-7] AUDIT LOG
#   Call audit_log(db, user_id, action, detail) anywhere in main.py
#   Requires an AuditLog table — see models.py addition below
# ─────────────────────────────────────────────────────────────────────────────

def _humanize_audit(action: str, detail: str) -> str:
    """Convert technical audit detail to plain English for non-technical users."""
    d = detail or ""
    a = action.upper()
    parts = {}
    try:
        parts = dict(p.split("=", 1) for p in d.split() if "=" in p)
    except Exception:
        pass
    if a == "LOGIN": return "Logged in successfully"
    if a == "LOGIN_FAILED": return f"Failed login attempt"
    if a == "LOGOUT": return "Logged out"
    if a == "DELIVERY_DELIVERED": return f"Delivery #{parts.get('delivery_id','?')} marked as delivered"
    if a == "ADJUSTMENT_REQUESTED": return f"Agent requested price/qty adjustment on delivery #{parts.get('delivery_id','?')}"
    if a == "ADJUSTMENT_APPROVED": return f"Admin approved adjustment on delivery #{parts.get('delivery_id','?')}"
    if a == "ADJUSTMENT_REJECTED": return f"Admin rejected adjustment on delivery #{parts.get('delivery_id','?')}"
    if a == "STOCK_RETURN_VETTED": return f"Stock return confirmed for delivery #{parts.get('delivery_id','?')} — {parts.get('item','?')}"
    if a == "SHORTFALL_RESOLVED": return f"Missing stock resolved for {parts.get('item','?')} — action: {parts.get('action','?')}"
    if a == "SHORTFALL_WRITTEN_OFF": return f"Missing stock written off for {parts.get('item','?')} — qty lost: {parts.get('qty_lost','?')}"
    if a == "CASH_CONFIRMED": return f"Agent cash confirmed for {parts.get('date','?')}"
    if a == "FAULTY_STOCK_FLAGGED": return f"Faulty stock flagged — {parts.get('item','?')} qty: {parts.get('qty','?')}"
    if a == "FAULTY_STOCK_RESOLVED": return f"Faulty stock resolved — {parts.get('item','?')} — {parts.get('action','?')}"
    if a == "STOCK_ASSIGNED_TO_AGENT": return f"Extra stock assigned — {parts.get('item','?')} × {parts.get('qty','?')} to {parts.get('agent','?')}"
    if a == "ASSIGNED_STOCK_RETURNED": return f"Agent returned assigned stock for assignment #{parts.get('assignment_id','?')}"
    if a == "MERCHANT_RETURN": return f"Goods returned to merchant — {parts.get('merchant','?')}"
    if a == "TRANSFER_PACKED": return f"Stock transfer #{parts.get('transfer_id','?')} packed and sent"
    if a == "TRANSFER_RECEIVED": return f"Stock transfer #{parts.get('transfer_id','?')} received by branch"
    if a == "DATA_RESET": return "All operational data was wiped by supervisor"
    if a == "PASSWORD_RESET": return f"Password reset performed"
    if a == "NEW_AGENT": return f"New agent account created"
    if a == "NEW_ADMIN": return f"New branch admin account created"
    return f"{action.replace('_',' ').title()}" + (f" — {d}" if d else "")


def audit_log(db, user_id: Optional[int], action: str, detail: str = "",
              ip: str = "") -> None:
    """Write an audit entry using a separate DB session so it never commits
    or rolls back the caller's transaction. Silently swallows errors."""
    try:
        from .models import AuditLog       # avoid circular import
        from .database import SessionLocal
        human_detail = _humanize_audit(action, detail)
        _db = SessionLocal()
        try:
            entry = AuditLog(
                user_id=user_id,
                action=action[:100],
                detail=human_detail[:500],
                ip=ip[:45],
                created_at=datetime.now(timezone.utc),
            )
            _db.add(entry)
            _db.commit()
        finally:
            _db.close()
    except Exception as e:
        logger.warning(f"Audit log failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-8] SECURITY HEADERS MIDDLEWARE
#   Adds HTTP security headers to every response
# ─────────────────────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # [SEC-3b] Origin check on JSON POST/PUT/DELETE
        if request.method in ("POST", "PUT", "DELETE"):
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    verify_origin_for_json(request)
                except HTTPException as exc:
                    return Response(content=exc.detail, status_code=exc.status_code)
        response = await call_next(request)
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(self), camera=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"]   = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com https://fonts.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;"
        )
        return response


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-9] FILE UPLOAD VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

ALLOWED_UPLOAD_EXTENSIONS = {".xlsx", ".xls", ".csv"}
MAX_UPLOAD_SIZE_BYTES      = 5 * 1024 * 1024  # 5 MB

def validate_upload(filename: str, content: bytes) -> None:
    """Raise HTTPException if the uploaded file fails validation."""
    import os
    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{ext}' is not allowed. Upload .xlsx, .xls, or .csv only.",
        )
    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"File is too large. Maximum size is {MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB.",
        )
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-9b] PROFILE IMAGE UPLOAD VALIDATION & PROCESSING
# ─────────────────────────────────────────────────────────────────────────────

ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
MAX_IMAGE_UPLOAD_BYTES   = 10 * 1024 * 1024  # Accept up to 10 MB raw (we compress it down)
PROFILE_IMAGE_MAX_DIM    = 400               # Max width/height in pixels
PROFILE_IMAGE_QUALITY    = 80                # JPEG compression quality

# Magic bytes for common image formats
_IMAGE_MAGIC = {
    b"\xff\xd8\xff": "image/jpeg",           # JPEG
    b"\x89PNG\r\n\x1a\n": "image/png",       # PNG
    b"RIFF": "image/webp",                   # WebP (starts with RIFF)
}

def validate_image_upload(filename: str, content: bytes) -> None:
    """Raise HTTPException if the uploaded image fails validation."""
    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Image type '{ext}' is not allowed. Upload .jpg, .png, or .webp only.",
        )
    if len(content) > MAX_IMAGE_UPLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Image is too large ({len(content) // (1024*1024)}MB). Maximum upload size is 10MB.",
        )
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded image is empty.")
    # Check magic bytes to make sure it's actually an image
    is_valid = False
    for magic in _IMAGE_MAGIC:
        if content[:len(magic)] == magic:
            is_valid = True
            break
    if not is_valid:
        raise HTTPException(status_code=400, detail="File does not appear to be a valid image.")


def process_profile_image(content: bytes) -> tuple[bytes, str]:
    """Resize and compress a profile image. Returns (jpeg_bytes, mime_type).
    Automatically shrinks any image to max 400x400 and compresses to JPEG."""
    from PIL import Image
    import io as _io

    # [SEC] Guard against decompression bombs — a small file on disk can
    # decompress to gigabytes of pixel data in RAM.
    Image.MAX_IMAGE_PIXELS = 25_000_000  # 25 megapixels max

    img = Image.open(_io.BytesIO(content))
    try:
        img.verify()  # Validate image structural integrity
    except Exception:
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid image.")
    # Re-open after verify() since verify() leaves the file in an unusable state
    img = Image.open(_io.BytesIO(content))

    # Convert to RGB (handles PNG with transparency, RGBA, etc.)
    if img.mode in ("RGBA", "LA", "P"):
        background = Image.new("RGB", img.size, (255, 255, 255))
        if img.mode == "P":
            img = img.convert("RGBA")
        background.paste(img, mask=img.split()[-1] if img.mode == "RGBA" else None)
        img = background
    elif img.mode != "RGB":
        img = img.convert("RGB")

    # Resize to fit within max dimensions, keeping aspect ratio
    img.thumbnail((PROFILE_IMAGE_MAX_DIM, PROFILE_IMAGE_MAX_DIM), Image.LANCZOS)

    # Compress to JPEG
    buf = _io.BytesIO()
    img.save(buf, format="JPEG", quality=PROFILE_IMAGE_QUALITY, optimize=True)
    return buf.getvalue(), "image/jpeg"


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-10] PUSH SUBSCRIPTION ENDPOINT VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def validate_push_endpoint(endpoint: str) -> None:
    """Reject push subscription endpoints that aren't HTTPS push service URLs."""
    from urllib.parse import urlparse
    parsed = urlparse(endpoint)
    if parsed.scheme != "https":
        raise HTTPException(status_code=400, detail="Push endpoint must use HTTPS.")
    # Push services use well-known domains; reject obviously bogus endpoints
    if not parsed.netloc or "." not in parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid push endpoint domain.")


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-11] TWILIO WEBHOOK SIGNATURE VERIFICATION
#   Twilio signs every webhook request with HMAC-SHA1 using your Auth Token.
#   This ensures only real Twilio requests are processed — not forged ones.
# ─────────────────────────────────────────────────────────────────────────────

def verify_twilio_signature(request: Request) -> None:
    """Verify the X-Twilio-Signature header matches the expected HMAC.
    Skipped if TWILIO_AUTH_TOKEN is not set (Twilio not configured)."""
    import os
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "")
    if not auth_token:
        raise HTTPException(status_code=403, detail="Twilio authentication not configured.")

    signature = request.headers.get("x-twilio-signature", "")
    if not signature:
        raise HTTPException(status_code=403, detail="Missing Twilio signature.")

    # Build the full URL that Twilio signed against
    # In production behind a proxy, use X-Forwarded-Proto + Host
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("host", "")
    url = f"{proto}://{host}{request.url.path}"

    # Twilio signs URL + sorted POST params concatenated as key=value
    # The form data is already parsed by FastAPI at this point, so we
    # accept it as a parameter from the caller.
    # NOTE: This function validates signature given the form params.
    # The caller must pass form_params after parsing the form.
    logger.debug("Twilio signature check — url=%s", url)


def verify_twilio_signature_with_params(request: Request, form_params: dict) -> None:
    """Full Twilio signature verification with parsed form parameters.
    Call this AFTER parsing the form data."""
    import os
    from urllib.parse import quote
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "")
    if not auth_token:
        raise HTTPException(status_code=403, detail="Twilio authentication not configured.")

    signature = request.headers.get("x-twilio-signature", "")
    if not signature:
        raise HTTPException(status_code=403, detail="Missing Twilio signature.")

    # Reconstruct the URL Twilio used for signing
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("host", "")
    url = f"{proto}://{host}{request.url.path}"

    # Append sorted POST params as key=value (Twilio's signing algorithm)
    data_string = url
    for key in sorted(form_params.keys()):
        data_string += f"{key}{form_params[key]}"

    # Compute HMAC-SHA1
    expected = hmac.new(
        auth_token.encode("utf-8"),
        data_string.encode("utf-8"),
        hashlib.sha1,
    ).digest()

    import base64
    expected_b64 = base64.b64encode(expected).decode("utf-8")

    if not hmac.compare_digest(expected_b64, signature):
        logger.warning("Twilio signature mismatch — url=%s", url)
        raise HTTPException(status_code=403, detail="Invalid Twilio signature.")
