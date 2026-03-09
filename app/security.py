# security.py
# Drop this file into your app folder alongside main.py
# It provides: CSRF protection, input sanitization, rate limiting helpers

import os
import re
import secrets
import html
from datetime import datetime, timedelta
from collections import defaultdict
from threading import Lock
from typing import Optional

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse


# ─────────────────────────────────────────────────────────────────────────────
# 1. SESSION SECRET — Hard fail if missing (never fall back to a default)
# ─────────────────────────────────────────────────────────────────────────────

def get_session_secret() -> str:
    """
    Reads SESSION_SECRET from environment.
    Raises RuntimeError immediately at startup if it is missing or too short.
    Never use a hardcoded fallback — that silently exposes all sessions.
    """
    secret = os.getenv("SESSION_SECRET", "").strip()
    if not secret:
        raise RuntimeError(
            "SESSION_SECRET environment variable is not set. "
            "Add it to your Railway Variables tab with a long random value. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    if len(secret) < 32:
        raise RuntimeError(
            "SESSION_SECRET is too short (minimum 32 characters). "
            "Generate a secure one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return secret


# ─────────────────────────────────────────────────────────────────────────────
# 2. IN-MEMORY RATE LIMITER
#    Works without Redis. Suitable for single-instance Railway deployments.
#    For multi-instance, swap the store for Upstash Redis.
# ─────────────────────────────────────────────────────────────────────────────

class InMemoryRateLimiter:
    """
    Token-bucket style rate limiter keyed by IP address.
    Thread-safe for single-process deployments (Railway default).
    """

    def __init__(self):
        # { ip: [(timestamp, count), ...] }
        self._store: dict[str, list[datetime]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, ip: str, max_requests: int, window_seconds: int) -> bool:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)

        with self._lock:
            # Purge old entries
            self._store[ip] = [t for t in self._store[ip] if t > cutoff]

            if len(self._store[ip]) >= max_requests:
                return False

            self._store[ip].append(now)
            return True

    def check(self, request: Request, max_requests: int = 10, window_seconds: int = 60) -> None:
        """
        Call this at the top of any sensitive endpoint.
        Raises HTTP 429 if the IP has exceeded the limit.

        Railway passes the real client IP in X-Forwarded-For.
        ProxyHeadersMiddleware (see main.py) makes request.client.host correct.
        """
        ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )

        if not self.is_allowed(ip, max_requests, window_seconds):
            raise HTTPException(
                status_code=429,
                detail="You are moving a bit too fast! Please try again in a few minutes.",
            )


# Global limiter instance — import and reuse this in main.py
limiter = InMemoryRateLimiter()


# ─────────────────────────────────────────────────────────────────────────────
# 3. CSRF PROTECTION
#    Double-submit cookie pattern — no database required.
#    Works with Jinja2 templates and standard HTML forms.
# ─────────────────────────────────────────────────────────────────────────────

CSRF_TOKEN_LENGTH = 32
CSRF_SESSION_KEY  = "_csrf_token"
CSRF_FORM_FIELD   = "csrf_token"

# These paths are exempt from CSRF checks (GET, HEAD, OPTIONS are always exempt)
CSRF_EXEMPT_PATHS = {"/login"}  # login has its own rate limiting; add others if needed


def get_csrf_token(request: Request) -> str:
    """
    Returns the CSRF token for the current session, creating one if absent.
    Call this in every GET handler that renders a form, and pass the result
    to the template context as 'csrf_token'.
    """
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_hex(CSRF_TOKEN_LENGTH)
        request.session[CSRF_SESSION_KEY] = token
    return token


def verify_csrf_token(request: Request, form_token: Optional[str]) -> None:
    """
    Verifies that the CSRF token submitted in the form matches the session token.
    Call this at the top of every POST/PUT/DELETE handler.

    Raises HTTP 403 if the token is missing or invalid.
    """
    # Skip exempt paths
    if request.url.path in CSRF_EXEMPT_PATHS:
        return

    session_token = request.session.get(CSRF_SESSION_KEY, "")
    submitted     = (form_token or "").strip()

    # Use secrets.compare_digest to prevent timing attacks
    if not session_token or not submitted or not secrets.compare_digest(session_token, submitted):
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing CSRF token. Please refresh the page and try again.",
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. INPUT SANITIZATION
#    Strips HTML tags, control characters, and obvious SQL patterns from
#    all free-text user inputs before they are stored or used.
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that suggest SQL injection attempts — log/reject these
_SQL_PATTERNS = re.compile(
    r"(--|;|/\*|\*/|xp_|UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|"
    r"SELECT\s+\*|ALTER\s+TABLE|EXEC\s*\(|EXECUTE\s*\()",
    re.IGNORECASE,
)

# HTML/script injection patterns
_SCRIPT_PATTERN = re.compile(r"<[^>]+>", re.IGNORECASE)


def sanitize_text(value: str, max_length: int = 400, field_name: str = "") -> str:
    """
    Sanitizes a free-text string:
      1. Strips leading/trailing whitespace
      2. Removes HTML tags (prevents XSS in templates that render raw HTML)
      3. Escapes remaining HTML entities
      4. Rejects obvious SQL injection patterns (raises 400)
      5. Truncates to max_length

    For fields rendered with Jinja2's auto-escaping ({{ value }}), step 2-3
    are defence-in-depth. They are critical if you ever use {{ value | safe }}.
    """
    if not value:
        return ""

    cleaned = value.strip()

    # Remove HTML tags
    cleaned = _SCRIPT_PATTERN.sub("", cleaned)

    # Escape any remaining HTML entities
    cleaned = html.escape(cleaned, quote=True)

    # Reject SQL injection patterns
    if _SQL_PATTERNS.search(cleaned):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid characters detected in {'field: ' + field_name if field_name else 'input'}.",
        )

    # Enforce length limit
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]

    return cleaned


def sanitize_username(value: str) -> str:
    """
    Usernames: alphanumeric, dots, underscores, hyphens only.
    Max 80 characters (matches DB column length).
    """
    cleaned = (value or "").strip()
    if not re.match(r"^[\w.\-]{1,80}$", cleaned):
        raise HTTPException(
            status_code=400,
            detail="Username may only contain letters, numbers, dots, underscores, and hyphens.",
        )
    return cleaned


def sanitize_phone(value: str) -> str:
    """
    Phone numbers: digits, spaces, +, -, (, ) only.
    """
    cleaned = (value or "").strip()
    if cleaned and not re.match(r"^[\d\s\+\-\(\)]{1,40}$", cleaned):
        raise HTTPException(
            status_code=400,
            detail="Invalid phone number format.",
        )
    return cleaned[:40]


def sanitize_amount(value: float, field_name: str = "amount") -> float:
    """
    Validates a monetary amount is positive and within a sane range.
    """
    try:
        amt = float(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}.")
    if amt <= 0:
        raise HTTPException(status_code=400, detail=f"{field_name} must be greater than zero.")
    if amt > 999_999_999:
        raise HTTPException(status_code=400, detail=f"{field_name} value is unrealistically large.")
    return amt
