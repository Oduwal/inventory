"""
Cross-worker SSE bridge using PostgreSQL LISTEN/NOTIFY.

Problem: With --workers 4, each uvicorn worker has its own _sse_queues dict.
A webhook landing on worker A can't push to a browser connected on worker B.

Solution: Use PostgreSQL's built-in pub/sub. When broadcasting, we pg_notify()
through PostgreSQL. Each worker runs a listener thread that picks up the
notification and dispatches to its local asyncio queues.

No new dependencies — uses psycopg2-binary already in requirements.txt.
"""

import os
import json
import asyncio
import logging
import threading
import select

_log = logging.getLogger("sse_bridge")

# ── Local SSE queue registry (per-worker, same as before) ───────────
_sse_queues: dict[int, list[asyncio.Queue]] = {}   # delivery_id → [queue, ...]
_loop: asyncio.AbstractEventLoop | None = None      # set during startup

PG_CHANNEL = "sse_delivery_chat"


def _local_dispatch(delivery_id: int, html_fragment: str):
    """Push to all local asyncio queues for this delivery_id."""
    for q in _sse_queues.get(delivery_id, []):
        try:
            q.put_nowait(html_fragment)
        except asyncio.QueueFull:
            pass


def _listener_thread():
    """Background thread: LISTEN on PG channel, dispatch to local queues."""
    import psycopg2
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url or db_url.startswith("sqlite"):
        _log.warning("SSE bridge: no PostgreSQL URL — falling back to local-only mode")
        return

    while True:
        conn = None
        try:
            conn = psycopg2.connect(db_url)
            conn.set_isolation_level(0)  # autocommit required for LISTEN
            cur = conn.cursor()
            cur.execute(f"LISTEN {PG_CHANNEL};")
            _log.info("SSE bridge: listening on channel '%s'", PG_CHANNEL)

            while True:
                # Block up to 5 seconds waiting for a notification
                if select.select([conn], [], [], 5.0) == ([], [], []):
                    continue  # timeout, loop back to check again
                conn.poll()
                while conn.notifies:
                    notify = conn.notifies.pop(0)
                    try:
                        payload = json.loads(notify.payload)
                        did = payload["d"]
                        frag = payload["h"]
                        if _loop and not _loop.is_closed():
                            _loop.call_soon_threadsafe(_local_dispatch, did, frag)
                    except Exception as e:
                        _log.warning("SSE bridge: bad payload: %s", e)

        except Exception as e:
            _log.error("SSE bridge: listener error: %s — reconnecting in 3s", e)
            import time
            time.sleep(3)
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass


def start(loop: asyncio.AbstractEventLoop):
    """Call once during app startup to start the PG listener thread."""
    global _loop
    _loop = loop
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url or db_url.startswith("sqlite"):
        _log.info("SSE bridge: SQLite mode — using local-only dispatch")
        return
    t = threading.Thread(target=_listener_thread, daemon=True, name="sse-pg-listener")
    t.start()
    _log.info("SSE bridge: started listener thread")


def broadcast(delivery_id: int, html_fragment: str):
    """Broadcast an SSE event to ALL workers via pg_notify."""
    from .database import SessionLocal
    db_url = os.getenv("DATABASE_URL", "")

    if not db_url or db_url.startswith("sqlite"):
        # No PG — fall back to local-only dispatch (single worker / dev mode)
        _local_dispatch(delivery_id, html_fragment)
        return

    payload = json.dumps({"d": delivery_id, "h": html_fragment}, ensure_ascii=False)

    # pg_notify has an 8000-byte limit; HTML fragments are typically 300-600 bytes
    if len(payload.encode("utf-8")) > 7900:
        _log.warning("SSE bridge: payload too large (%d bytes), falling back to local", len(payload))
        _local_dispatch(delivery_id, html_fragment)
        return

    db = SessionLocal()
    try:
        from sqlalchemy import text
        db.execute(text(f"SELECT pg_notify('{PG_CHANNEL}', :payload)"), {"payload": payload})
        db.commit()
    except Exception as e:
        _log.error("SSE bridge: pg_notify failed: %s — falling back to local", e)
        _local_dispatch(delivery_id, html_fragment)
    finally:
        db.close()


def register_queue(delivery_id: int) -> asyncio.Queue:
    """Create and register a new SSE queue for a delivery."""
    q: asyncio.Queue = asyncio.Queue(maxsize=50)
    _sse_queues.setdefault(delivery_id, []).append(q)
    return q


def unregister_queue(delivery_id: int, q: asyncio.Queue):
    """Remove a queue when the SSE client disconnects."""
    lst = _sse_queues.get(delivery_id, [])
    if q in lst:
        lst.remove(q)
