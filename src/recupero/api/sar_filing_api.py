"""SAR / STR regulatory-filing-draft operator console + admin JSON endpoint.

A live, authenticated operator surface for the E3 SAR/STR regulatory-filing
phase — it renders the suspicious-activity-report DRAFT context assembled from
a case's ``freeze_brief.json`` (subjects, normalized amounts, narrative,
jurisdiction metadata). The heavy lifting lives in
``recupero.reports.regulatory_filing``; this module is a thin, read-only
surface over ``build_sar_context``.

**Drafts only — Recupero is NOT a filer.** A SAR/STR is filed by an obligated
financial institution (or, in the UK, a POCA-2002 reporter). The console
keeps that framing front-and-center and never fabricates subjects/amounts.

Security model (mirrors ``/v1/graph-analysis``): the CONSOLE shell at
``/v1/sar-filing/console`` is served unauthenticated and contains NO data —
every dynamic value is fetched client-side from the admin-gated JSON endpoint
with the operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send
a custom auth header, so server-gating the HTML itself would force the key into
the URL (leaks into logs/history); the shell+client-fetch pattern keeps the key
in a header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/sar-filing``          — admin-gated JSON (SAR/STR draft context)
  * ``GET  /v1/sar-filing/console``  — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/sar-filing", tags=["sar-filing"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "sar_filing_console.html"
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
            detail="SAR/STR filing API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "SAR / STR regulatory-filing DRAFT context for a case — subjects, "
        "normalized amounts, fact-derived narrative, and the jurisdiction's "
        "regulator labels (us | uk | eu). DRAFT only; Recupero is not the "
        "filer. Read-only over the case's freeze_brief.json. Admin-gated."
    ),
)
def get_sar_filing(
    case_id: str,
    jurisdiction: str = "us",
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
    from recupero.reports.regulatory_filing import (
        SAR_JURISDICTIONS,
        build_sar_context,
        load_brief,
    )
    from recupero.storage.case_store import CaseStore

    # Validate the jurisdiction against the canonical set BEFORE touching
    # storage. build_sar_context accepts operator-friendly aliases (us/uk/eu)
    # that resolve INTO SAR_JURISDICTIONS, so accept either the alias or the
    # canonical key; reject anything that doesn't resolve with a clean 400.
    jur = (jurisdiction or "").strip().lower()
    canonical = {k.split("_", 1)[0]: k for k in SAR_JURISDICTIONS}  # us/uk/eu → key
    if jur not in SAR_JURISDICTIONS and jur not in canonical:
        allowed = ", ".join(sorted(canonical) + sorted(SAR_JURISDICTIONS))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"jurisdiction {jurisdiction!r} not recognized; allowed: {allowed}",
        )

    cfg, _ = load_config()
    store = CaseStore(cfg)

    # Validate existence WITHOUT creating anything: read_case is
    # path-traversal-guarded and raises FileNotFoundError/ValueError for a
    # missing or malformed case. We derive the case dir from cases_root only
    # AFTER that validation succeeds — CaseStore.case_dir would CREATE the
    # directory as a side effect (mkdir(exist_ok=True)), so an operator typo'ing
    # a case_id must not litter an empty case folder. Mirrors /v1/exhibit-pack
    # and /v1/graph-analysis exactly.
    try:
        store.read_case(case_id)
    except (FileNotFoundError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case not found",
        ) from None

    case_dir = store.cases_root / case_id

    try:
        brief = load_brief(case_dir)
        ctx = build_sar_context(brief, jurisdiction=jurisdiction)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case not found (no freeze_brief.json — run emit-brief first)",
        ) from None
    except ValueError as exc:
        # build_sar_context raises ValueError for an unrecognized jurisdiction;
        # any other bad-id ValueError lands here too. Map to a clean 400.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from None
    except Exception as exc:  # noqa: BLE001 — never 500; degrade to 503
        log.warning("get_sar_filing: render failed for %r: %s", case_id, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SAR/STR draft unavailable",
        ) from exc

    return ctx


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/sar-filing client-side with the admin key."
    ),
)
def sar_filing_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("sar_filing_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>SAR / STR Filing console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
