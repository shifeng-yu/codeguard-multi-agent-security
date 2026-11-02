"""Server-Sent Events endpoint for the live agent chain.

Two sources, in this order:

1. **Replay** — every event is also written to ``agent_events``, so a client that
   connects late (or reloads the page) still receives the full timeline, and a
   ``Last-Event-ID`` header lets it resume exactly where it stopped.
2. **Live** — the Celery worker publishes each event to
   ``scan:{scan_id}:events`` on Redis; this endpoint forwards them.

If Redis is down the generator falls back to polling SQLite once per second, so
the demo keeps working in single-process mode.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import Request
from fastapi.responses import StreamingResponse

from src.monitoring.scan_recorder import CHANNEL_TEMPLATE
from src.utils.logging import get_logger

logger = get_logger(__name__)

TERMINAL_STATUS = {"completed", "failed"}
HEARTBEAT_SECONDS = 15
MAX_STREAM_SECONDS = 900


def _frame(event: dict[str, Any]) -> str:
    data = _to_wire(event)
    seq = data.get("seq") or 0
    payload = json.dumps(data, ensure_ascii=False, default=str)
    return f"id: {seq}\ndata: {payload}\n\n"


def _to_wire(event: dict[str, Any]) -> dict[str, Any]:
    """Normalise a stored row and a live publish into one wire shape.

    Live events already carry ``event``; rows replayed from ``agent_events`` do
    not. Without this both branches the client would need two parsers.
    """
    data = dict(event)
    data["seq"] = data.get("seq") or data.get("id") or 0

    if not data.get("event"):
        agent = str(data.get("agent", ""))
        status = str(data.get("status", ""))
        if agent == "scan" and status == "finished":
            data["event"] = "scan.finished"
        elif status == "started":
            data["event"] = "agent.started"
        else:
            data["event"] = "agent.finished"

    data.pop("id", None)
    return data


def _is_terminal(event: dict[str, Any]) -> bool:
    """True for the closing event, whichever branch produced it.

    Stored rows are identified by agent/status, live publishes by ``event``.
    """
    if event.get("event") == "scan.finished":
        return True
    return event.get("agent") == "scan" and event.get("status") == "finished"


def _synthetic_terminal(scan: dict[str, Any], seq: int) -> dict[str, Any]:
    return {
        "event": "scan.finished",
        "seq": seq + 1,
        "scan_id": scan.get("scan_id", ""),
        "agent": "scan",
        "status": "finished",
        "verdict": scan.get("verdict"),
        "status_detail": scan.get("status"),
        "blocker_count": scan.get("blocker_count", 0),
        "cve_count": scan.get("cve_count", 0),
        "duration_ms": scan.get("duration_ms"),
    }


def sse_response(
    *,
    request: Request,
    scan_id: str,
    store: Any,
    last_event_id: int = 0,
) -> StreamingResponse:
    """Build the ``text/event-stream`` response for one scan."""
    return StreamingResponse(
        _generator(request, scan_id, store, last_event_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _generator(
    request: Request, scan_id: str, store: Any, last_event_id: int
) -> AsyncIterator[str]:
    seq = max(0, last_event_id)

    # --- 1. Replay from SQLite ---
    try:
        for event in store.list_events(scan_id, after_id=seq):
            seq = event["id"]
            yield _frame(event)
            if _is_terminal(event):
                return
    except Exception as exc:  # noqa: BLE001 - stream must not crash the client
        logger.warning("sse_replay_failed", scan_id=scan_id, error=str(exc)[:150])

    # --- 2. Already finished? close immediately ---
    scan = _safe_scan(store, scan_id)
    if scan and scan.get("status") in TERMINAL_STATUS:
        yield _frame(_synthetic_terminal(scan, seq))
        return

    # --- 3. Live tail ---
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        async for chunk in _poll(store, scan_id, seq):
            yield chunk
        return

    async for chunk in _tail_redis(redis, request, scan_id, seq):
        yield chunk


async def _tail_redis(
    redis: Any, request: Request, scan_id: str, seq: int
) -> AsyncIterator[str]:
    channel = CHANNEL_TEMPLATE.format(scan_id=scan_id)
    pubsub = redis.pubsub()
    deadline = time.monotonic() + MAX_STREAM_SECONDS
    idle = 0.0

    try:
        await pubsub.subscribe(channel)
        while time.monotonic() < deadline:
            if await request.is_disconnected():
                return

            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=1.0
            )
            if message is None:
                idle += 1.0
                if idle >= HEARTBEAT_SECONDS:
                    idle = 0.0
                    yield ": ping\n\n"
                continue

            idle = 0.0
            event = _decode(message.get("data"))
            if not event:
                continue
            event_seq = int(event.get("seq") or 0)
            if event_seq and event_seq <= seq:
                continue
            seq = event_seq or seq
            yield _frame(event)
            if _is_terminal(event):
                return
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.warning("sse_tail_failed", scan_id=scan_id, error=str(exc)[:150])
    finally:
        try:
            await pubsub.unsubscribe(channel)
            await pubsub.close()
        except Exception:  # noqa: BLE001
            pass


async def _poll(store: Any, scan_id: str, seq: int) -> AsyncIterator[str]:
    """Degraded mode: poll SQLite when Redis is unavailable."""
    deadline = time.monotonic() + MAX_STREAM_SECONDS
    ticks = 0
    while time.monotonic() < deadline:
        try:
            events = store.list_events(scan_id, after_id=seq)
        except Exception:  # noqa: BLE001
            events = []
        for event in events:
            seq = event["id"]
            yield _frame(event)
            if _is_terminal(event):
                return

        scan = _safe_scan(store, scan_id)
        if scan and scan.get("status") in TERMINAL_STATUS:
            yield _frame(_synthetic_terminal(scan, seq))
            return

        ticks += 1
        if ticks % HEARTBEAT_SECONDS == 0:
            yield ": ping\n\n"
        await asyncio.sleep(1.0)


def _safe_scan(store: Any, scan_id: str) -> dict[str, Any] | None:
    try:
        return store.get_scan(scan_id)
    except Exception:  # noqa: BLE001
        return None


def _decode(raw: Any) -> dict[str, Any] | None:
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except (TypeError, ValueError):
        return None
