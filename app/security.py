# security.py — Full security module for Inventory Keeper
# Fixes applied:
#   [SEC-1]  SESSION_SECRET hard-fail at startup
#   [SEC-2]  In-memory rate limiter (IP-based)
#   [SEC-3]  CSRF double-submit pattern
#   [SEC-4]  Input sanitization
#   [SEC-5]  Per-account login lockout (5 failures → 15 min lock)
#   [SEC-6]  Password reset token expiry (1 hour)
#   [SEC-7]  Audit log helpers
#   [SEC-8]  Security headers middleware
#   [SEC-9]  File upload validation

import os
import re
import secrets
import html
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from threading import Lock
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
# [SEC-2] IP-BASED RATE LIMITER
# ─────────────────────────────────────────────────────────────────────────────

class InMemoryRateLimiter:
    def __init__(self):
        self._store: dict[str, list[datetime]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, ip: str, max_requests: int, window_seconds: int) -> bool:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        with self._lock:
            self._store[ip] = [t for t in self._store[ip] if t > cutoff]
            if len(self._store[ip]) >= max_requests:
                return False
            self._store[ip].append(now)
            return True

    def check(self, request: Request, max_requests: int = 10, window_seconds: int = 60) -> None:
        ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
        if not self.is_allowed(ip, max_requests, window_seconds):
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please wait a minute and try again.",
            )

limiter = InMemoryRateLimiter()


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-5] PER-ACCOUNT LOGIN LOCKOUT
#   5 failed attempts → locked for 15 minutes
#   Stored in-memory (resets on dyno restart — acceptable for single instance)
# ─────────────────────────────────────────────────────────────────────────────

_LOCKOUT_MAX_ATTEMPTS = 5
_LOCKOUT_WINDOW_SECONDS = 900  # 15 minutes

class AccountLockout:
    def __init__(self):
        self._failures: dict[str, list[datetime]] = defaultdict(list)
        self._lock = Lock()

    def record_failure(self, username: str) -> None:
        now = datetime.utcnow()
        with self._lock:
            self._failures[username].append(now)

    def is_locked(self, username: str) -> bool:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=_LOCKOUT_WINDOW_SECONDS)
        with self._lock:
            self._failures[username] = [t for t in self._failures[username] if t > cutoff]
            return len(self._failures[username]) >= _LOCKOUT_MAX_ATTEMPTS

    def clear(self, username: str) -> None:
        with self._lock:
            self._failures.pop(username, None)

    def remaining_attempts(self, username: str) -> int:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=_LOCKOUT_WINDOW_SECONDS)
        with self._lock:
            recent = [t for t in self._failures[username] if t > cutoff]
            return max(0, _LOCKOUT_MAX_ATTEMPTS - len(recent))

account_lockout = AccountLockout()


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-6] PASSWORD RESET TOKEN STORE (1-hour expiry)
# ─────────────────────────────────────────────────────────────────────────────

_RESET_TOKEN_EXPIRY = 3600  # 1 hour

class PasswordResetTokenStore:
    def __init__(self):
        self._tokens: dict[str, tuple[int, datetime]] = {}  # token -> (user_id, expires_at)
        self._lock = Lock()

    def create(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(seconds=_RESET_TOKEN_EXPIRY)
        with self._lock:
            # Revoke any existing tokens for this user
            self._tokens = {t: (uid, exp) for t, (uid, exp) in self._tokens.items() if uid != user_id}
            self._tokens[token] = (user_id, expires_at)
        return token

    def verify(self, token: str) -> Optional[int]:
        """Returns user_id if token is valid and not expired, else None."""
        with self._lock:
            entry = self._tokens.get(token)
            if not entry:
                return None
            user_id, expires_at = entry
            if datetime.utcnow() > expires_at:
                del self._tokens[token]
                return None
            return user_id

    def consume(self, token: str) -> Optional[int]:
        """Verify and immediately invalidate the token (single-use)."""
        user_id = self.verify(token)
        if user_id:
            with self._lock:
                self._tokens.pop(token, None)
        return user_id

reset_token_store = PasswordResetTokenStore()


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-3] CSRF PROTECTION
# ─────────────────────────────────────────────────────────────────────────────

CSRF_TOKEN_LENGTH = 32
CSRF_SESSION_KEY  = "_csrf_token"
CSRF_EXEMPT_PATHS = {"/login"}

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
# [SEC-4] INPUT SANITIZATION
# ─────────────────────────────────────────────────────────────────────────────

_SQL_PATTERNS = re.compile(
    r"(--|;|/\*|\*/|xp_|UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|"
    r"SELECT\s+\*|ALTER\s+TABLE|EXEC\s*\(|EXECUTE\s*\()",
    re.IGNORECASE,
)
_SCRIPT_PATTERN = re.compile(r"<[^>]+>", re.IGNORECASE)

def sanitize_text(value: str, max_length: int = 400, field_name: str = "") -> str:
    if not value:
        return ""
    cleaned = value.strip()
    cleaned = _SCRIPT_PATTERN.sub("", cleaned)
    cleaned = html.escape(cleaned, quote=True)
    if _SQL_PATTERNS.search(cleaned):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid characters detected in {'field: ' + field_name if field_name else 'input'}.",
        )
    return cleaned[:max_length]

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

def sanitize_amount(value: float, field_name: str = "amount") -> float:
    try:
        amt = float(value)
    except (TypeError, ValueError):
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
    """Write an audit entry. Silently swallows errors so it never breaks the main flow."""
    try:
        from .models import AuditLog  # imported here to avoid circular import
        human_detail = _humanize_audit(action, detail)
        entry = AuditLog(
            user_id=user_id,
            action=action[:100],
            detail=human_detail[:500],
            ip=ip[:45],
            created_at=datetime.utcnow(),
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        logger.warning(f"Audit log failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-8] SECURITY HEADERS MIDDLEWARE
#   Adds HTTP security headers to every response
# ─────────────────────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"]   = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com https://fonts.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self';"
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
