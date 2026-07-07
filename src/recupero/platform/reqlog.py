"""Structured per-request logging for the /v2 SaaS surface.

Emits ONE JSON line per ``/v2`` request keyed by the resolving tenant
(``org_id``) so multi-tenant traffic can be sliced by org in a log aggregator
(Datadog / Loki / CloudWatch) — the observability gap the summary flagged as the
last SaaS-layer residual. Opt-in via ``RECUPERO_PLATFORM_REQUEST_LOG=1`` (default
off preserves the current uvicorn access-log-only behavior).

The ``org_id`` / ``plan`` / ``role`` are read from ``request.state`` where
``platform.deps.current_principal`` records them after auth; an unauthenticated
or rejected request logs ``org_id=null``.

Split so the async surface stays contained: the *pure* record builder + the
enable check live here (sync, unit-tested), and the tiny pure-ASGI middleware
that calls them lives in ``api/app.py`` alongside the body-size guard (the
already-audited async module).
"""

from __future__ import annotations

import json
import logging
import os

# Dedicated logger so an operator can route request lines to their own handler /
# level without touching the rest of recupero's logging.
log = logging.getLogger("recupero.platform.request")


def request_log_enabled() -> bool:
    """True only when ``RECUPERO_PLATFORM_REQUEST_LOG=1``. Default off, so the
    middleware is not even installed on an unconfigured deploy."""
    return (os.environ.get("RECUPERO_PLATFORM_REQUEST_LOG", "") or "").strip() == "1"


def build_log_record(
    *,
    method: str | None,
    path: str | None,
    status: int,
    duration_ms: float,
    org_id: str | None,
    plan: str | None,
    role: str | None,
) -> str:
    """Serialize one request's structured fields to a compact JSON line.

    Deterministic key order (``sort_keys``) so downstream parsers + tests see a
    stable shape, and ``duration_ms`` is rounded to keep lines small.
    """
    return json.dumps(
        {
            "event": "http_request",
            "method": method,
            "path": path,
            "status": int(status),
            "duration_ms": round(float(duration_ms), 2),
            "org_id": org_id,
            "plan": plan,
            "role": role,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def emit(record_json: str) -> None:
    """Log a pre-built record line at INFO. Kept separate from ``build_log_record``
    so the ASGI middleware stays trivial and both halves are unit-testable."""
    log.info(record_json)


__all__ = ("request_log_enabled", "build_log_record", "emit")
