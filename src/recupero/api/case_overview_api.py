"""Case-Overview operator console + admin JSON endpoint (v0.35.x).

A per-case "overview / launcher": the operator enters a single ``case_id`` and
sees which deliverables that case has produced on disk, each with a deep link to
its existing per-case console. It is the connective tissue tying the
case-centric consoles into one workflow.

This is READ-ONLY and FILESYSTEM-ONLY — like ``case_index_api`` it detects
deliverables purely by file presence (``.exists()``) and deliberately does NOT
parse ``case.json`` or any artifact, so it stays robust against a single
corrupted case. It never writes, never touches the DB, and never 500s.

Security model (mirrors ``/v1/ai-triage`` / ``/v1/cases``): the CONSOLE shell at
``/v1/case-overview/console`` is served unauthenticated and contains NO data —
every dynamic value is fetched client-side from the admin-gated JSON endpoint
with the operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a
custom auth header, so server-gating the HTML itself would force the key into the
URL (leaks into logs/history); the shell+client-fetch pattern keeps the key in a
header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/case-overview``          — admin-gated JSON (deliverable flags)
  * ``GET  /v1/case-overview/console``  — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/case-overview", tags=["case-overview"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "case_overview_console.html"
)

# Bound the case_id at the API edge before any storage lookup. The storage
# layer enforces its own (stricter) cap; this is a cheap reject for blank /
# pathological input so we never hand garbage to CaseStore.
_MAX_CASE_ID_LEN = 128


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as cron_admin_api / review_api — duplicated to keep this module
    standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="case-overview API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Case overview JSON for a single case — which deliverables (freeze "
        "brief, AI triage, exhibit pack, interactive graph) the case has on "
        "disk. File-presence only; does NOT parse case.json. Admin-gated."
    ),
)
def get_case_overview(
    case_id: str,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)

    # Validate at the edge: blank or oversized case_id is a 400, not a 404
    # (the lookup never even runs). FastAPI returns 422 if the param is
    # entirely missing; this covers the present-but-invalid case.
    cid = (case_id or "").strip()
    if not cid or len(case_id) > _MAX_CASE_ID_LEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="case_id must be 1..128 non-blank characters",
        )

    from recupero.config import load_config
    from recupero.storage.case_store import CaseStore

    cfg, _ = load_config()
    store = CaseStore(cfg)

    # Validate existence the same way ai_triage_api / exhibit_pack_api do:
    # read_case is path-traversal-guarded and raises FileNotFoundError/ValueError
    # for a missing or malformed case. We derive the case dir from cases_root
    # only AFTER that validation succeeds (CaseStore.case_dir would CREATE the
    # directory as a side effect, so it cannot be used to test existence).
    try:
        store.read_case(case_id)
    except (FileNotFoundError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case not found",
        ) from None

    case_dir = store.cases_root / case_id

    # File-presence-only deliverable detection (matching case_index_api
    # conventions — no JSON parsing). Anything unexpected maps to 404 (never
    # 500): a permission glitch or vanished directory all surface to the
    # operator as "not there".
    try:
        deliverables = {
            "freeze_brief": (case_dir / "freeze_brief.json").exists(),
            "ai_triage": (case_dir / "ai_triage.json").exists(),
            "exhibit_pack": (case_dir / "exhibit_pack").exists(),
            "graph_ui": (case_dir / "graph_ui.html").exists(),
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — never 500; map any blowup to 404
        log.warning(
            "get_case_overview: scan failed for %r: %s", case_id, exc
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case overview unavailable",
        ) from None

    return {"case_id": case_id, "deliverables": deliverables}


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/case-overview client-side with the admin key."
    ),
)
def case_overview_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("case_overview_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Case Overview console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
