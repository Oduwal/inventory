"""Hybrid Gemini client: tries Vertex AI first, falls back to AI Studio.

Vertex AI is used when:
  - GCP_PROJECT_ID is set, AND
  - GOOGLE_APPLICATION_CREDENTIALS_JSON is set (the service-account JSON),
  - AND a valid access token can be obtained.

Otherwise (or when the Vertex call fails for any reason) we fall back to the
existing AI Studio endpoint using GEMINI_API_KEY.

Both endpoints accept the same request/response shape, so callers pass the
same payload dict regardless of backend.
"""

import os
import json
import time
import logging
import threading
from typing import Any

import httpx

_log = logging.getLogger("gemini")

# Cached creds + token (so we don't re-parse JSON or re-mint a token on every call)
_cred_lock = threading.Lock()
_credentials = None
_token: str | None = None
_token_exp: float = 0.0
_credentials_load_failed: bool = False

# Default model — both backends accept the same model id family
DEFAULT_MODEL = "gemini-2.5-flash"


def _vertex_enabled() -> bool:
    return bool(
        os.getenv("GCP_PROJECT_ID")
        and os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")
        and not _credentials_load_failed
    )


def _load_credentials():
    """Parse the service-account JSON from env and build google-auth credentials."""
    global _credentials, _credentials_load_failed
    if _credentials is not None or _credentials_load_failed:
        return _credentials
    raw = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")
    if not raw:
        _credentials_load_failed = True
        return None
    try:
        info = json.loads(raw)
        from google.oauth2 import service_account
        _credentials = service_account.Credentials.from_service_account_info(
            info, scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        return _credentials
    except Exception as e:
        _log.error("gemini: failed to load Vertex service-account JSON: %s", e)
        _credentials_load_failed = True
        return None


def _get_vertex_token() -> str | None:
    """Return a valid OAuth bearer token, refreshing if expired."""
    global _token, _token_exp
    with _cred_lock:
        now = time.time()
        if _token and now < _token_exp - 60:
            return _token
        creds = _load_credentials()
        if creds is None:
            return None
        try:
            from google.auth.transport.requests import Request as GAuthRequest
            creds.refresh(GAuthRequest())
            _token = creds.token
            # google-auth sets `.expiry` to a UTC datetime
            if creds.expiry:
                _token_exp = creds.expiry.timestamp()
            else:
                _token_exp = now + 3000  # ~50 min default
            return _token
        except Exception as e:
            _log.error("gemini: vertex token refresh failed: %s", e)
            return None


def _vertex_url(model: str) -> str:
    project = os.getenv("GCP_PROJECT_ID", "")
    location = os.getenv("VERTEX_LOCATION", "us-central1")
    return (
        f"https://{location}-aiplatform.googleapis.com/v1/projects/{project}"
        f"/locations/{location}/publishers/google/models/{model}:generateContent"
    )


def _ai_studio_url(model: str) -> str:
    return f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def _log_usage(backend: str, data: dict) -> None:
    """Log token usage from a Gemini response (best-effort)."""
    try:
        meta = data.get("usageMetadata") or {}
        _log.info(
            "gemini: %s OK — prompt_tokens=%s, output_tokens=%s, total=%s",
            backend,
            meta.get("promptTokenCount"),
            meta.get("candidatesTokenCount"),
            meta.get("totalTokenCount"),
        )
    except Exception:
        pass


def _is_retryable_error(data: Any) -> bool:
    """Vertex/AIStudio sometimes return 200 with an embedded error."""
    if isinstance(data, dict) and "error" in data:
        return True
    return False


async def call_gemini_async(payload: dict, *, model: str = DEFAULT_MODEL, timeout: float = 60.0) -> dict | None:
    """Async POST to Vertex first, then AI Studio on failure. Returns the
    response JSON dict, or None if both backends failed."""
    # 1) Try Vertex
    if _vertex_enabled():
        token = _get_vertex_token()
        if token:
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    resp = await client.post(
                        _vertex_url(model),
                        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                        json=payload,
                    )
                if resp.status_code == 200:
                    data = resp.json()
                    if not _is_retryable_error(data):
                        _log_usage("vertex", data)
                        return data
                    _log.warning("gemini: vertex returned 200+error → AI Studio fallback. err=%s", data.get("error"))
                else:
                    _log.warning("gemini: vertex HTTP %s → AI Studio fallback. body=%s",
                                 resp.status_code, resp.text[:300])
            except Exception as e:
                _log.warning("gemini: vertex call raised %s → AI Studio fallback", e)
        else:
            _log.warning("gemini: no vertex token → AI Studio fallback")

    # 2) Fall back to AI Studio
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        _log.error("gemini: AI Studio fallback unavailable (GEMINI_API_KEY not set)")
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{_ai_studio_url(model)}?key={api_key}",
                headers={"Content-Type": "application/json"},
                json=payload,
            )
        data = resp.json()
        if _is_retryable_error(data):
            _log.warning("gemini: AI Studio returned error: %s", data.get("error"))
            return data  # caller decides what to do; we already logged
        _log_usage("ai_studio", data)
        return data
    except Exception as e:
        _log.error("gemini: AI Studio call raised %s", e)
        return None


def call_gemini_sync(payload: dict, *, model: str = DEFAULT_MODEL, timeout: float = 10.0) -> dict | None:
    """Sync POST — same hybrid behavior. Used by the whatsapp classifier which
    runs in a thread-pool, not the event loop."""
    if _vertex_enabled():
        token = _get_vertex_token()
        if token:
            try:
                resp = httpx.post(
                    _vertex_url(model),
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    json=payload,
                    timeout=timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if not _is_retryable_error(data):
                        _log_usage("vertex", data)
                        return data
                    _log.warning("gemini: vertex returned 200+error → AI Studio fallback. err=%s", data.get("error"))
                else:
                    _log.warning("gemini: vertex HTTP %s → AI Studio fallback. body=%s",
                                 resp.status_code, resp.text[:300])
            except Exception as e:
                _log.warning("gemini: vertex call raised %s → AI Studio fallback", e)
        else:
            _log.warning("gemini: no vertex token → AI Studio fallback")

    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        _log.error("gemini: AI Studio fallback unavailable (GEMINI_API_KEY not set)")
        return None
    try:
        resp = httpx.post(
            f"{_ai_studio_url(model)}?key={api_key}",
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=timeout,
        )
        data = resp.json()
        if _is_retryable_error(data):
            _log.warning("gemini: AI Studio returned error: %s", data.get("error"))
            return data
        _log_usage("ai_studio", data)
        return data
    except Exception as e:
        _log.error("gemini: AI Studio call raised %s", e)
        return None
