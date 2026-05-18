"""Idempotency for state-changing /api/* POST endpoints.

Clients send an `Idempotency-Key` header (UUID, generated once per logical
event, reused on retries). The server:

1. Looks up (endpoint_path, idempotency_key) in `idempotency_keys`.
2. If found: returns the cached response body + status code. The handler
   body is SKIPPED entirely — no duplicate side-effects.
3. If not found: runs the handler, then stores the response under that key
   before returning it.

Two helpers:

- `require_idempotency_key(request)` — pulls the header. Raises 400 if missing
  (or returns None when `optional=True`).
- `lookup_or_replay(db, path, key)` → cached JSONResponse or None.
- `store_response(db, path, key, status_code, body)` — persist after a fresh
  handler run.

A 24-hour TTL is enforced lazily on every read: rows older than 24h are
treated as cache misses (and a cleanup runs occasionally to remove them).
"""

import json
import logging
import random
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

_log = logging.getLogger("idempotency")

# Same TTL Stripe uses. Configurable via env if you ever want a different value.
TTL_SECONDS = 24 * 60 * 60


def require_idempotency_key(request: Request, *, optional: bool = False) -> str | None:
    """Return the Idempotency-Key header, validated. Raises 400 if missing
    (unless optional=True, in which case returns None on absence)."""
    key = (request.headers.get("Idempotency-Key") or request.headers.get("idempotency-key") or "").strip()
    if not key:
        if optional:
            return None
        raise HTTPException(
            status_code=400,
            detail="Missing required header: Idempotency-Key. Send a unique UUID per logical event.",
        )
    if len(key) > 100:
        raise HTTPException(status_code=400, detail="Idempotency-Key too long (max 100 chars).")
    # Reject obvious garbage early; UUID-ish or any reasonable client-generated id is fine.
    if not all(c.isalnum() or c in "-_" for c in key):
        raise HTTPException(status_code=400, detail="Idempotency-Key contains invalid characters.")
    return key


def lookup_or_replay(db: Session, path: str, key: str) -> JSONResponse | None:
    """Return a cached JSONResponse for this (path, key) if one exists and is
    within TTL. Returns None on cache miss."""
    if not key:
        return None
    try:
        row = db.execute(text(
            "SELECT status_code, response_body, created_at FROM idempotency_keys "
            "WHERE endpoint_path = :p AND idempotency_key = :k"
        ), {"p": path, "k": key}).first()
    except Exception as e:
        # If the table doesn't exist yet (first deploy before migration runs),
        # behave as cache-miss rather than crashing the request.
        _log.warning("idempotency lookup failed (table missing?): %s", e)
        return None
    if not row:
        return None
    status_code, response_body, created_at = row[0], row[1], row[2]
    # Lazy TTL: ignore rows older than 24h
    try:
        import datetime as _dt
        now = _dt.datetime.utcnow() if not getattr(created_at, "tzinfo", None) else _dt.datetime.now(_dt.timezone.utc)
        age = (now - created_at).total_seconds() if hasattr(created_at, "tzinfo") else (now - created_at).total_seconds()
        if age > TTL_SECONDS:
            return None
    except Exception:
        pass
    # Occasionally garbage-collect expired rows (1% of requests trigger it).
    if random.random() < 0.01:
        try:
            db.execute(text(
                "DELETE FROM idempotency_keys WHERE created_at < "
                + ("datetime('now', '-1 day')" if db.bind.dialect.name == "sqlite" else "NOW() - INTERVAL '24 hours'")
            ))
            db.commit()
        except Exception:
            db.rollback()
    _log.info("idempotency HIT path=%s key=%s (replaying cached response)", path, key[:16])
    try:
        body = json.loads(response_body) if response_body else None
    except Exception:
        body = {"replay_error": "stored response was not valid JSON"}
    return JSONResponse(body, status_code=status_code)


def store_response(db: Session, path: str, key: str, status_code: int, body: Any) -> None:
    """Persist a fresh handler's response keyed by (path, key). Best-effort:
    failures here are logged, never raised — we don't want idempotency
    bookkeeping to break a successful write."""
    if not key:
        return
    try:
        body_json = json.dumps(body) if body is not None else ""
    except Exception:
        body_json = json.dumps({"non_serializable": True})
    try:
        is_sqlite = db.bind.dialect.name == "sqlite"
        if is_sqlite:
            sql = (
                "INSERT OR IGNORE INTO idempotency_keys "
                "(endpoint_path, idempotency_key, status_code, response_body) "
                "VALUES (:p, :k, :sc, :b)"
            )
        else:
            sql = (
                "INSERT INTO idempotency_keys "
                "(endpoint_path, idempotency_key, status_code, response_body) "
                "VALUES (:p, :k, :sc, :b) "
                "ON CONFLICT (endpoint_path, idempotency_key) DO NOTHING"
            )
        db.execute(text(sql), {"p": path, "k": key, "sc": status_code, "b": body_json})
        db.commit()
        _log.debug("idempotency STORED path=%s key=%s status=%s", path, key[:16], status_code)
    except Exception as e:
        _log.warning("idempotency store failed path=%s key=%s err=%s", path, key[:16], e)
        try:
            db.rollback()
        except Exception:
            pass
