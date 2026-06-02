"""Case-Index operator console + admin JSON endpoint (v0.35.16).

The casework home: a live, authenticated listing of every locally-traced case
plus which deliverables each one has on disk (freeze brief, AI triage, exhibit
pack, interactive graph). It is a fast directory scan — it deliberately does NOT
parse ``case.json`` — so it stays robust against a single corrupted case and
loads instantly even with hundreds of cases. From here the operator copies a
``case_id`` into the per-case views (e.g. the Graph Analysis console).

Security model (mirrors ``/v1/freshness`` / ``/v1/graph-analysis``): the CONSOLE
shell at ``/v1/cases/console`` is served unauthenticated and contains NO data —
every dynamic value is fetched client-side from the admin-gated JSON endpoint
with the operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a
custom auth header, so server-gating the HTML itself would force the key into the
URL (leaks into logs/history); the shell+client-fetch pattern keeps the key in a
header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/cases``           — admin-gated JSON (cases + deliverable flags)
  * ``GET  /v1/cases/console``   — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/cases", tags=["cases"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "case_index_console.html"
)

# Cap the directory scan so a runaway cases_root (thousands of dirs) can't turn
# the index into a slow, memory-heavy response. 500 is a generous ceiling for a
# single operator's local case load.
_MAX_CASES = 500


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as cron_admin_api / review_api — duplicated to keep this module
    standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="case-index API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Case index JSON — every locally-traced case plus which deliverables "
        "(freeze brief, AI triage, exhibit pack, graph) each has on disk. Fast "
        "directory scan; does NOT parse case.json. Admin-gated."
    ),
)
def get_cases(
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    from recupero.config import load_config
    from recupero.storage.case_store import CaseStore, _validate_case_id

    try:
        cfg, _ = load_config()
        store = CaseStore(cfg)
        root = store.cases_root
        if not root.exists():
            return {"cases": [], "count": 0}

        cases: list[dict[str, Any]] = []
        for child in sorted(root.iterdir()):
            if len(cases) >= _MAX_CASES:
                break
            if not child.is_dir():
                continue
            # Defense-in-depth: skip any subdirectory name that wouldn't pass
            # case_id validation (control chars, traversal patterns, reserved
            # device names) — we never want to surface such an entry as a
            # clickable/copyable case_id.
            try:
                _validate_case_id(child.name)
            except ValueError:
                continue
            if not (child / "case.json").is_file():
                continue
            cases.append(
                {
                    "case_id": child.name,
                    "has_brief": (child / "freeze_brief.json").exists(),
                    "has_ai_triage": (child / "ai_triage.json").exists(),
                    "has_exhibit_pack": (child / "exhibit_pack").exists(),
                    "has_graph": (child / "graph_ui.html").exists(),
                }
            )
        return {"cases": cases, "count": len(cases)}
    except Exception as exc:  # noqa: BLE001 — never 500 the operator console
        log.warning("get_cases: scan failed: %s", exc)
        return {"cases": [], "count": 0, "error": str(exc)}


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/cases client-side with the admin key."
    ),
)
def case_index_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("case_index_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Case Index console unavailable</h1>"
                "<p>Template could not be read; inspect the cases directory "
                "directly under <code>data/cases/</code>.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
