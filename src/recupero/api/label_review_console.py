"""Label-candidate Review operator console (HTML shell).

A self-contained operator surface for the auto-ingest label queue — the
in-browser equivalent of inspecting ``GET /v1/labels/candidates`` by hand.
An analyst opens it, pastes their operator key, and sees the pending /
promoted / rejected candidate queue, without running a CLI.

Security model (mirrors ``watchlist_api`` / ``/review-gate``): the CONSOLE
shell at ``/v1/label-review/console`` is served unauthenticated and contains
NO data — every dynamic value is fetched client-side from the admin-gated
``/v1/labels/candidates`` endpoint with the operator's
``X-Recupero-Admin-Key``. A browser navigation cannot send a custom auth
header, so server-gating the HTML itself would force the key into the URL
(leaks into logs/history); the shell+client-fetch pattern keeps the key in a
header and leaks nothing to an unauthenticated visitor.

This console is READ-ONLY — it displays the queue. Promote / reject are
mutating actions that require the candidate-row confirm hash and are done
via the API (``POST /v1/labels/candidates/{id}/promote|reject``), not here.

  * ``GET  /v1/label-review/console``  — unauthenticated shell (HTML+JS); no data
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, status
from fastapi.responses import HTMLResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/label-review", tags=["label-review"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "label_review_console.html"
)


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Label-candidate review console (HTML shell). Unauthenticated by "
        "design — contains NO data; fetches /v1/labels/candidates "
        "client-side with the admin key."
    ),
)
def label_review_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("label_review_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Label-candidate Review unavailable</h1>"
                "<p>Template could not be read; query "
                "<code>/v1/labels/candidates</code> directly with the "
                "admin key.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
