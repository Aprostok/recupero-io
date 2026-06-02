"""Label-Freshness operator console + admin JSON endpoint (v0.35.15).

A live, authenticated operator surface for label-source freshness — which
attribution feeds (OFAC, intl sanctions, bridges, CEX deposits, mixers, …) are
fresh vs overdue against their per-class SLA, with the OFAC feed as the headline
alarm. Stale attribution is silently-wrong attribution, so this makes feed age
loud rather than implicit.

Security model (mirrors ``/v1/watchlist``): the CONSOLE shell at
``/v1/freshness/console`` is served unauthenticated and contains NO data — every
dynamic value is fetched client-side from the admin-gated JSON endpoint with the
operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a custom
auth header, so server-gating the HTML itself would force the key into the URL
(leaks into logs/history); the shell+client-fetch pattern keeps the key in a
header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/freshness``           — admin-gated JSON (sources + summary)
  * ``GET  /v1/freshness/console``   — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/freshness", tags=["freshness"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "freshness_console.html"
)


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as cron_admin_api / review_api — duplicated to keep this module
    standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="freshness API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Label-freshness report JSON — per-source age vs SLA (fresh/stale/"
        "critical/unknown) with the OFAC feed as the headline alarm. "
        "Admin-gated."
    ),
)
def get_freshness(
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    from datetime import UTC, datetime

    from recupero.labels.freshness import build_freshness_report
    return build_freshness_report(now=datetime.now(UTC))


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/freshness client-side with the admin key."
    ),
)
def freshness_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("freshness_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Label Freshness console unavailable</h1>"
                "<p>Template could not be read; use "
                "<code>recupero-ops label-freshness</code>.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
