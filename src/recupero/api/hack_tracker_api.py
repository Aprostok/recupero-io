"""Hack-tracker feed — live crypto-incident intelligence for the operator.

Exposes the existing ``recupero.hack_tracker`` engine (dedupe + rank by
severity x source-credibility x recency) over HTTP. Until now that engine was
only reachable from a CLI digest, so nothing surfaced in the product.

  * ``GET /v1/hack-tracker``          — admin-gated JSON (ranked events)
  * ``GET /v1/hack-tracker/console``  — unauthenticated HTML shell, no data

Same secure-shell pattern as the other consoles: the HTML carries NO data and
fetches the admin-gated JSON client-side with the key in a request header.

Source reality (see ``sources/defillama_hacks.py`` for the full probe log):
DefiLlama is the live workhorse; IC3's RSS contributes rarely; OFAC, rekt and
CISA have no usable live source; X needs a paid token AND its fetcher is still
a stub. The response reports per-source counts so an operator can see exactly
which sources produced the feed rather than assuming all of them did.

Results are cached in-process for ``_CACHE_TTL_S`` because every console load
would otherwise hit third-party APIs.
"""

from __future__ import annotations

import hmac
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/hack-tracker", tags=["hack-tracker"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "hack_tracker_console.html"
)

# Third-party fetches are slow and rate-limited; serve repeat console loads
# from memory. Short enough that a fresh hack shows up within the hour.
_CACHE_TTL_S = 900

_MAX_WINDOW_DAYS = 365
_DEFAULT_WINDOW_DAYS = 30

_cache_lock = threading.Lock()
# (window_days) -> (monotonic_expiry, payload)
_cache: dict[int, tuple[float, dict[str, Any]]] = {}


def _require_admin_auth(provided: str | None) -> None:
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="admin key not configured on this deployment",
        )
    if not provided or not provided.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing X-Recupero-Admin-Key",
        )
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid X-Recupero-Admin-Key",
        )


@router.get(
    "",
    summary=(
        "Ranked live hack feed (severity x source-credibility x recency), "
        "deduped across sources. Admin-gated; cached in-process for 15 min."
    ),
)
def get_hack_feed(
    window_days: int = Query(
        _DEFAULT_WINDOW_DAYS, ge=1, le=_MAX_WINDOW_DAYS,
        description="How far back to look, in days.",
    ),
    refresh: bool = Query(
        False, description="Bypass the in-process cache and refetch.",
    ),
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)

    # Normalize the query params. Over HTTP, FastAPI resolves these to real
    # values; called DIRECTLY (tests, internal callers) an unset param is still
    # the `Query(...)` object -- which is truthy, so a bare `if not refresh:`
    # silently bypassed the cache and re-hit third-party APIs every call.
    if not isinstance(window_days, int) or isinstance(window_days, bool):
        window_days = _DEFAULT_WINDOW_DAYS
    window_days = max(1, min(_MAX_WINDOW_DAYS, window_days))
    refresh = refresh is True

    now = time.monotonic()
    if not refresh:
        with _cache_lock:
            hit = _cache.get(window_days)
            if hit and hit[0] > now:
                cached = dict(hit[1])
                cached["cached"] = True
                return cached

    from recupero._common import env_truthy

    # The aggregator refuses live fetches without an explicit opt-in so a stray
    # cron can't burn API quota. Surface that as a clear, actionable message
    # instead of a 500.
    if not (
        env_truthy("RECUPERO_HACK_TRACKER_ENABLED")
        or env_truthy("RECUPERO_HACK_TRACKER_OFFLINE")
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "hack tracker is off — set RECUPERO_HACK_TRACKER_ENABLED=1 for "
                "live sources, or RECUPERO_HACK_TRACKER_OFFLINE=1 for fixtures"
            ),
        )

    from datetime import UTC, datetime, timedelta

    from recupero.hack_tracker.aggregator import run_daily_digest

    since = datetime.now(UTC) - timedelta(days=window_days)
    try:
        digest = run_daily_digest(since=since)
    except RuntimeError as exc:
        # Feature-flag guard inside the aggregator (belt-and-braces).
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc),
        ) from exc
    except Exception as exc:  # noqa: BLE001 — never 500 an operator console
        log.warning("get_hack_feed: digest failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="hack feed unavailable",
        ) from exc

    payload: dict[str, Any] = {
        "generated_at": digest.generated_at.isoformat(),
        "window_start": digest.window_start.isoformat(),
        "window_end": digest.window_end.isoformat(),
        "window_days": window_days,
        "events_total": digest.events_total,
        "events_by_source": digest.events_by_source,
        "events_by_severity": digest.events_by_severity,
        "events": [_event_json(e) for e in digest.all_events],
        # Be explicit that a source contributing 0 is normal for some sources,
        # so an empty section never reads as a bug in the feed.
        "source_notes": _SOURCE_NOTES,
        "cached": False,
    }

    with _cache_lock:
        _cache[window_days] = (now + _CACHE_TTL_S, payload)
    return payload


# Why a source may show zero. Kept beside the endpoint so the console can
# explain itself without the operator reading source code.
_SOURCE_NOTES: dict[str, str] = {
    "defillama": "Live. Curated hack dataset with a USD figure per incident.",
    "ic3_alert": "Live, but IC3 publishes crypto-relevant PSAs only rarely.",
    "cisa_alert": (
        "No data: CISA returns HTTP 403 to server-side clients (CDN "
        "fingerprint block) even though the feed is public."
    ),
    "rekt": "No data: rekt.news' feed returns HTTP 500 upstream.",
    "ofac_sdn": (
        "No data here: OFAC's recent-actions page is HTML-only. Sanctions are "
        "ingested authoritatively elsewhere in the pipeline."
    ),
    "x_peckshield": (
        "Needs a paid X API token (RECUPERO_X_BEARER_TOKEN) AND the X fetcher "
        "is still a stub — no tweets will appear until both are done."
    ),
}


def _event_json(ev: Any) -> dict[str, Any]:
    """Serialize one HackEvent for the console (Decimal -> str, enums -> str)."""
    loss = ev.estimated_loss_usd
    return {
        "content_hash": ev.content_hash,
        "source": ev.source.value,
        "source_url": ev.source_url,
        "observed_at": ev.observed_at.isoformat(),
        "incident_time": ev.incident_time.isoformat() if ev.incident_time else None,
        "title": ev.title,
        "summary": ev.summary,
        "severity": ev.severity.value,
        "chains_mentioned": list(ev.chains_mentioned or []),
        "addresses": list(ev.addresses or []),
        "tx_hashes": list(ev.tx_hashes or []),
        # str, not float: a float would silently lose precision on large USD
        # figures and JSON has no Decimal.
        "estimated_loss_usd": str(loss) if loss is not None else None,
        "attributed_actor": ev.attributed_actor,
        "has_identifiable_victim": bool(ev.has_identifiable_victim),
        "victim_hint": ev.victim_hint,
        "tags": list(ev.tags or []),
    }


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/hack-tracker client-side with the admin key."
    ),
)
def hack_tracker_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("hack_tracker_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Hack Tracker console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
