"""Recovery-Snapshot operator console + admin JSON endpoint (v0.22 phase).

A live, authenticated operator surface for the v0.22 Recovery Snapshot phase —
the pre-engagement recovery estimate for a case (expected net-to-victim,
per-issuer recovery breakdown, drivers / ROI) that the victim and their counsel
see BEFORE the engagement fee is paid. This is READ-ONLY over an
ALREADY-COMPUTED estimate: the backend stores the estimate inside the case's
freeze brief under the key ``RECOVERY_ESTIMATE`` (the deliverables worker reads
``freeze_brief["RECOVERY_ESTIMATE"]`` to render the snapshot). This console
merely reads ``<case_dir>/freeze_brief.json`` and surfaces that stored dict. It
does NOT recompute, never calls the trace/estimator, and costs nothing. If the
brief or the estimate is absent the operator is told to run emit-brief first.

Security model (mirrors ``/v1/ai-triage``): the CONSOLE shell at
``/v1/recovery-snapshot/console`` is served unauthenticated and contains NO data
— every dynamic value is fetched client-side from the admin-gated JSON endpoint
with the operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a
custom auth header, so server-gating the HTML itself would force the key into the
URL (leaks into logs/history); the shell+client-fetch pattern keeps the key in a
header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/recovery-snapshot``          — admin-gated JSON (the stored estimate)
  * ``GET  /v1/recovery-snapshot/console``  — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/recovery-snapshot", tags=["recovery-snapshot"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "recovery_snapshot_console.html"
)

# Bound the case_id at the API edge before any storage lookup. The storage
# layer enforces its own (stricter) cap; this is a cheap reject for blank /
# pathological input so we never hand garbage to CaseStore.
_MAX_CASE_ID_LEN = 128

# Refuse to parse an implausibly large file (garbage / wrong file): the freeze
# brief can carry a lot more than the triage artifact (full trace context), so
# the cap is higher here than for ai_triage.json.
_MAX_BRIEF_BYTES = 20_000_000


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as cron_admin_api / review_api — duplicated to keep this module
    standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="recovery-snapshot API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Recovery estimate for a case — the stored pre-engagement estimate "
        "(expected net-to-victim, per-issuer recovery breakdown, drivers/ROI) "
        "from the v0.22 Recovery Snapshot phase. Read-only; admin-gated. Reads "
        "the RECOVERY_ESTIMATE stored in the freeze brief; never recomputes."
    ),
)
def get_recovery_snapshot(
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
    except (OSError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case not found",
        ) from None

    case_dir = store.cases_root / case_id

    # READ-ONLY load of the already-produced freeze brief, surfacing only the
    # stored RECOVERY_ESTIMATE. Anything unexpected maps to 404 (never 500): a
    # missing file, an oversized/garbage file, a parse error, or a permission
    # glitch all surface to the operator as "not there — run emit-brief first".
    try:
        brief_path = case_dir / "freeze_brief.json"
        if not brief_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="no freeze_brief.json — run emit-brief first",
            )
        if brief_path.stat().st_size > _MAX_BRIEF_BYTES:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="freeze_brief.json unavailable",
            )
        import json

        brief = json.loads(brief_path.read_text(encoding="utf-8"))
        estimate = brief.get("RECOVERY_ESTIMATE") if isinstance(brief, dict) else None
        if not estimate:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="no RECOVERY_ESTIMATE in brief for this case",
            )
    except HTTPException:
        raise
    except (json.JSONDecodeError, OSError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="freeze_brief.json unavailable",
        ) from None
    except Exception as exc:  # noqa: BLE001 — never 500; map any blowup to 404
        log.warning("get_recovery_snapshot: read failed for %r: %s", case_id, exc)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="freeze_brief.json unavailable",
        ) from None

    return {"case_id": case_id, "recovery_estimate": estimate}


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/recovery-snapshot client-side with the admin key."
    ),
)
def recovery_snapshot_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("recovery_snapshot_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Recovery Snapshot console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
