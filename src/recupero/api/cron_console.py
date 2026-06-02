"""Cron / Scheduled-job Health operator console (HTML shell).

A live, in-browser operator surface for background-job health — the visual
equivalent of polling ``GET /v1/cron/jobs`` by hand. An analyst opens it,
pastes the operator key, hits Load, and sees every scheduled job's last
status / last successful run / last error message at a glance, with failed
or stale rows flagged red.

Security model (mirrors ``/v1/watchlist/console`` and ``/review-gate``): the
CONSOLE shell at ``/v1/ops/cron-console`` is served UNAUTHENTICATED and
contains NO data — every dynamic value is fetched client-side from the
admin-gated ``GET /v1/cron/jobs`` endpoint with the operator's
``X-Recupero-Admin-Key``. A browser navigation cannot send a custom auth
header, so server-gating the HTML itself would force the key into the URL
(leaks into logs/history); the shell + client-fetch pattern keeps the key in
a request header and leaks nothing to an unauthenticated visitor.

  * ``GET /v1/ops/cron-console`` — unauthenticated shell (HTML+JS); no data.

This module adds NO JSON endpoint: the console reuses the EXISTING admin-gated
``GET /v1/cron/jobs`` (see ``recupero.api.cron_admin_api``).
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, status
from fastapi.responses import HTMLResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/ops", tags=["ops-console"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "cron_console.html"
)


@router.get(
    "/cron-console",
    response_class=HTMLResponse,
    summary=(
        "Cron / Job Health operator console (HTML shell). Unauthenticated by "
        "design — contains NO data; fetches /v1/cron/jobs client-side with the "
        "admin key."
    ),
)
def cron_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("cron_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Cron console unavailable</h1>"
                "<p>Template could not be read; query "
                "<code>GET /v1/cron/jobs</code> directly with your admin "
                "key.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
