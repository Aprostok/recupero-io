"""Live Watchlist / Watcher API + operator console (v0.35.1).

A live, authenticated operator surface for everything under monitoring — the
in-browser equivalent of the rendered ``watchlist-dashboard`` HTML, so an analyst
can open it, see what has MOVED since the last re-check, and trigger a fresh
check, without running a CLI.

Security model (mirrors ``/review-gate``): the CONSOLE shell at
``/v1/watchlist/console`` is served unauthenticated and contains NO data — every
dynamic value is fetched client-side from the admin-gated JSON endpoint with the
operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a custom
auth header, so server-gating the HTML itself would force the key into the URL
(leaks into logs/history); the shell+client-fetch pattern keeps the key in a
header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/watchlist``           — admin-gated JSON overview (cards, rollups, rows)
  * ``POST /v1/watchlist/run``       — admin-gated: trigger a watch_tick re-check now
  * ``GET  /v1/watchlist/console``   — unauthenticated shell (HTML+JS); no data
"""

from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import HTMLResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/watchlist", tags=["watchlist"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "watchlist_console.html"
)


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as cron_admin_api / review_api — duplicated to keep this module
    standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="watchlist API disabled — set RECUPERO_ADMIN_KEY to enable",
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


def _dsn() -> str:
    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="watchlist API requires SUPABASE_DB_URL",
        )
    return dsn


@router.get(
    "",
    summary=(
        "Live watchlist overview JSON — every monitored address, where it sits, "
        "and whether it has MOVED since the last re-check. Admin-gated."
    ),
)
def get_watchlist(
    x_recupero_admin_key: str | None = Header(default=None),
    investigation_id: str | None = None,
    stale_after_hours: int = 24,
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    dsn = _dsn()
    # Clamp the staleness knob to a sane range (1h .. 1yr) — operator-supplied.
    try:
        stale = max(1, min(int(stale_after_hours), 24 * 366))
    except (TypeError, ValueError):
        stale = 24
    from recupero.monitoring.watchlist_dashboard import build_watchlist_overview
    from recupero.reports.watchlist_dashboard import overview_to_dict
    overview = build_watchlist_overview(
        dsn=dsn,
        investigation_id=(investigation_id or None),
        stale_after_hours=stale,
    )
    return overview_to_dict(overview)


@router.post(
    "/run",
    summary=(
        "Trigger a watchlist re-check tick now: snapshot on-chain balance / "
        "tx-count for eligible watched addresses and record movement. "
        "Admin-gated. Per-row cooldowns make repeated calls safe."
    ),
)
def run_watchlist_check(
    x_recupero_admin_key: str | None = Header(default=None),
    limit: int | None = None,
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    dsn = _dsn()
    try:
        from recupero.config import load_config
        from recupero.worker.watch_tick import run_watch_tick
        cfg, env = load_config()
        capped = None
        if limit is not None:
            capped = max(1, min(int(limit), 5000))
        report = run_watch_tick(dsn=dsn, config=cfg, env=env, limit=capped)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning("watchlist run failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="watchlist re-check unavailable",
        ) from None
    return {
        "candidates": report.candidates,
        "snapshotted": report.snapshotted,
        "moved": len(report.material_changes),
        "skipped_cooldown": report.skipped_cooldown,
        "errors": len(report.errors),
    }


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/watchlist client-side with the admin key."
    ),
)
def watchlist_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("watchlist_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Watchlist console unavailable</h1>"
                "<p>Template could not be read; use "
                "<code>recupero-ops watchlist-dashboard</code>.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
