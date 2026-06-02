"""Graph-Analysis operator console + admin JSON endpoint (v0.35.16).

A live, authenticated operator surface for structural fund-flow graph analysis
of a traced case — the layer TRM / Chainalysis surface as "this is a
consolidation point", "funds cycle here". Two structural findings that point at
the actor's own infrastructure:

  * **Consolidation hubs** — where split funds re-merge (the actor's hub).
  * **Value cycles** — wash / loop obfuscation (funds looping through a set of
    addresses).

Security model (mirrors ``/v1/freshness``): the CONSOLE shell at
``/v1/graph-analysis/console`` is served unauthenticated and contains NO data —
every dynamic value is fetched client-side from the admin-gated JSON endpoint
with the operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a
custom auth header, so server-gating the HTML itself would force the key into
the URL (leaks into logs/history); the shell+client-fetch pattern keeps the key
in a header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/graph-analysis``          — admin-gated JSON (graph analysis)
  * ``GET  /v1/graph-analysis/console``  — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/graph-analysis", tags=["graph-analysis"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "graph_analysis_console.html"
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
            detail="graph-analysis API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Structural fund-flow graph analysis for a case — consolidation hubs "
        "(where split funds re-merge) + value cycles (wash/loop obfuscation), "
        "plus node/edge counts and max depth from seed. Admin-gated."
    ),
)
def get_graph_analysis(
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
    from recupero.trace.graph_analysis import analyze_case_graph

    cfg, _ = load_config()
    store = CaseStore(cfg)
    try:
        case = store.read_case(case_id)
    except (FileNotFoundError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case not found",
        ) from None

    try:
        return analyze_case_graph(case).to_dict()
    except Exception as exc:  # noqa: BLE001 — turn any analysis blowup into 503
        log.warning("get_graph_analysis: analysis failed for %r: %s", case_id, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="analysis unavailable",
        ) from exc


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/graph-analysis client-side with the admin key."
    ),
)
def graph_analysis_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("graph_analysis_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Graph Analysis console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
