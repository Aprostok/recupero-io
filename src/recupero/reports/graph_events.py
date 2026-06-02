"""Real-time graph events (Phase 4.13).

Lets an open operator graph receive live node/edge deltas — e.g. when the
worker's nightly ``watch_tick`` detects movement on a watched address, or
when another operator expands a shared investigation.

Two transports, by who is producing the event:

  * **Same process (API):** an in-process asyncio pub/sub. The SSE endpoint
    ``subscribe()``s; an in-API producer (e.g. the expand route) ``publish()``es.
  * **Cross process (worker → API):** Postgres ``LISTEN/NOTIFY`` — the worker
    calls :func:`notify_pg` (``pg_notify('graph_events', …)``); a small bridge
    task in the API ``LISTEN``s and re-``publish()``es into the in-process bus.
    LISTEN/NOTIFY is the natural cross-process bus for this Postgres stack.

This module is pure plumbing (no FastAPI import) so the pub/sub + payload
shaping are unit-testable without a server. The SSE endpoint + the LISTEN
bridge (which need a running ASGI server + Postgres to exercise) live in the
API layer.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

log = logging.getLogger(__name__)

PG_CHANNEL = "graph_events"
_MAX_QUEUE = 100

# investigation_id -> set of subscriber queues
_subscribers: dict[str, set[asyncio.Queue]] = {}


def subscribe(investigation_id: str) -> asyncio.Queue:
    """Register a subscriber queue for an investigation's live events."""
    q: asyncio.Queue = asyncio.Queue(maxsize=_MAX_QUEUE)
    _subscribers.setdefault(str(investigation_id), set()).add(q)
    return q


def unsubscribe(investigation_id: str, q: asyncio.Queue) -> None:
    s = _subscribers.get(str(investigation_id))
    if not s:
        return
    s.discard(q)
    if not s:
        _subscribers.pop(str(investigation_id), None)


def subscriber_count(investigation_id: str) -> int:
    return len(_subscribers.get(str(investigation_id), ()))


async def publish(investigation_id: str, event: dict[str, Any]) -> int:
    """Fan ``event`` out to every live subscriber of the investigation.
    Drops the event for any full queue (a stalled client must not block
    others). Returns how many subscribers received it."""
    delivered = 0
    for q in list(_subscribers.get(str(investigation_id), ())):
        try:
            q.put_nowait(event)
            delivered += 1
        except asyncio.QueueFull:
            log.debug("graph_events: dropping event for full subscriber queue")
    return delivered


def build_delta_event(
    *,
    reason: str,
    nodes: list[dict[str, Any]] | None = None,
    edges: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Shape a live delta the operator graph knows how to merge."""
    return {
        "type": "delta",
        "reason": reason,
        "nodes": nodes or [],
        "edges": edges or [],
    }


def sse_frame(event: dict[str, Any]) -> str:
    """Serialize an event as a Server-Sent-Events ``data:`` frame."""
    return "data: " + json.dumps(event, separators=(",", ":")) + "\n\n"


def notify_pg(dsn: str, investigation_id: str, event: dict[str, Any]) -> bool:
    """Cross-process publish via ``pg_notify`` — used by the worker so an
    open operator graph (in the API process) gets the event through the
    LISTEN bridge. Payload carries the investigation id so the bridge can
    route it. Best-effort: returns False on any failure.

    NOTE: Postgres NOTIFY payloads are capped at 8000 bytes — keep deltas
    small (a watch hit is a handful of nodes/edges)."""
    try:
        from recupero._common import db_connect
        payload = json.dumps(
            {"investigation_id": str(investigation_id), "event": event},
            separators=(",", ":"),
        )
        if len(payload.encode("utf-8")) > 7900:
            log.warning("graph_events: NOTIFY payload too large; skipping")
            return False
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_notify(%s, %s)", (PG_CHANNEL, payload))
        return True
    except Exception as exc:  # noqa: BLE001
        log.debug("graph_events: notify_pg failed inv=%s: %s", investigation_id, exc)
        return False


__all__ = (
    "PG_CHANNEL",
    "subscribe",
    "unsubscribe",
    "subscriber_count",
    "publish",
    "build_delta_event",
    "sse_frame",
    "notify_pg",
)
