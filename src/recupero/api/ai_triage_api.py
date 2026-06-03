"""AI-triage operator console + admin JSON endpoint (v0.35.x — roadmap G1).

A live, authenticated operator surface for the G1 AI-triage artifact of a
produced case — the short plain-English triage (case summary, recommended next
steps, completeness gaps) a non-crypto investigator relies on. This is
READ-ONLY over an ALREADY-produced artifact: the backend
(``recupero.reports.ai_triage.run_ai_triage``) writes a STORED
``<case_dir>/ai_triage.json`` and this console merely reads + displays it. There
is NO live model call from this endpoint — it never regenerates, never touches
the LLM, and costs nothing. If the artifact is absent the operator is told to
run ``recupero ai-triage <case>`` first.

Security model (mirrors ``/v1/exhibit-pack``): the CONSOLE shell at
``/v1/ai-triage/console`` is served unauthenticated and contains NO data —
every dynamic value is fetched client-side from the admin-gated JSON endpoint
with the operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a
custom auth header, so server-gating the HTML itself would force the key into the
URL (leaks into logs/history); the shell+client-fetch pattern keeps the key in a
header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/ai-triage``          — admin-gated JSON (the stored triage dict)
  * ``GET  /v1/ai-triage/console``  — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/ai-triage", tags=["ai-triage"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "ai_triage_console.html"
)

# Bound the case_id at the API edge before any storage lookup. The storage
# layer enforces its own (stricter) cap; this is a cheap reject for blank /
# pathological input so we never hand garbage to CaseStore.
_MAX_CASE_ID_LEN = 128

# Refuse to parse an implausibly large artifact (garbage / wrong file): the
# triage JSON is a handful of short capped strings + two small lists.
_MAX_TRIAGE_BYTES = 5_000_000


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as cron_admin_api / review_api — duplicated to keep this module
    standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI-triage API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "AI-triage artifact for a case — the stored plain-English triage "
        "(case summary, recommended next steps, completeness gaps) produced by "
        "the G1 phase. Read-only; admin-gated. NO live model call."
    ),
)
def get_ai_triage(
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

    # Validate existence the same way exhibit_pack_api does: read_case is
    # path-traversal-guarded and raises FileNotFoundError/ValueError for a
    # missing or malformed case. We derive the case dir from cases_root only
    # AFTER that validation succeeds (CaseStore.case_dir would CREATE the
    # directory as a side effect, so it cannot be used to test existence).
    try:
        store.read_case(case_id)
    except (FileNotFoundError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case not found",
        ) from None

    case_dir = store.cases_root / case_id

    # READ-ONLY load of the already-produced artifact. Anything unexpected maps
    # to 404 (never 500): a missing file, an oversized/garbage file, a parse
    # error, or a permission glitch all surface to the operator as "not there —
    # run ai-triage first".
    try:
        triage_path = case_dir / "ai_triage.json"
        if not triage_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    "no ai_triage.json — run `recupero ai-triage "
                    "<case_id>` first"
                ),
            )
        if triage_path.stat().st_size > _MAX_TRIAGE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="ai_triage.json unavailable",
            )
        import json

        data = json.loads(triage_path.read_text(encoding="utf-8"))
    except HTTPException:
        raise
    except (json.JSONDecodeError, OSError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="ai_triage.json unavailable",
        ) from None
    except Exception as exc:  # noqa: BLE001 — never 500; map any blowup to 404
        log.warning("get_ai_triage: read failed for %r: %s", case_id, exc)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="ai_triage.json unavailable",
        ) from None

    return data


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/ai-triage client-side with the admin key."
    ),
)
def ai_triage_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("ai_triage_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>AI Triage console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
