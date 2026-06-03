"""Trace-accuracy benchmark operator console + admin JSON endpoint (J1 phase).

A live, authenticated operator surface for the J1 trace-accuracy benchmark — the
company's "prove our tracer is accurate" capability. Given a case whose trace has
already been produced AND an operator-supplied, INDEPENDENTLY-VERIFIED ground-truth
endpoint list, it scores the trace against that truth and yields
recall / endpoint-precision / F1, plus which truth endpoints were missed and which
flagged endpoints were spurious.

This console is READ-ONLY over already-produced artifacts: it reads the case's
``case.json`` + ``freeze_brief.json`` (reached / flagged endpoints) and a stored
``<case_dir>/ground_truth.json`` (the verified expected endpoints), then scores.
The ground truth is INPUT DATA the operator supplies from an independent, verified
source (a published incident report, an indictment, a recovered-funds record). It
is NEVER derived from the trace itself — that would be circular. Most cases will
not have a ground_truth.json; that is expected (→ 404).

Security model (mirrors ``/v1/recovery-snapshot``): the CONSOLE shell at
``/v1/benchmark/console`` is served unauthenticated and contains NO data — every
dynamic value is fetched client-side from the admin-gated JSON endpoint with the
operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a custom
auth header, so server-gating the HTML itself would force the key into the URL
(leaks into logs/history); the shell+client-fetch pattern keeps the key in a
header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/benchmark``          — admin-gated JSON (the trace-accuracy score)
  * ``GET  /v1/benchmark/console``  — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/benchmark", tags=["benchmark"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "benchmark_console.html"
)

# Bound the case_id at the API edge before any storage lookup. The storage
# layer enforces its own (stricter) cap; this is a cheap reject for blank /
# pathological input so we never hand garbage to CaseStore.
_MAX_CASE_ID_LEN = 128

# Refuse to parse an implausibly large ground-truth file (garbage / wrong file):
# an endpoint list is small; a multi-megabyte file is almost certainly not one.
_MAX_TRUTH_BYTES = 5_000_000


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as cron_admin_api / review_api — duplicated to keep this module
    standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="benchmark API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Trace-accuracy benchmark for a case — scores the case's already-produced "
        "trace against an operator-supplied, INDEPENDENTLY-VERIFIED ground-truth "
        "endpoint list (recall / endpoint-precision / F1 + missed / spurious). "
        "Read-only; admin-gated. The ground truth is never derived from the trace."
    ),
)
def get_benchmark(
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
    from recupero.trace.benchmark import load_ground_truth, score_case_dir

    cfg, _ = load_config()
    store = CaseStore(cfg)

    # Validate existence the same way recovery_snapshot_api / ai_triage_api do:
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

    # READ-ONLY scoring against a STORED, independently-verified ground truth.
    # A missing ground_truth.json is the common, expected case (most cases lack
    # one) → a 404 that tells the operator how to add one. A malformed truth file
    # is a 400 (their input is wrong). Anything else maps to 404 (never 500).
    try:
        gt_path = case_dir / "ground_truth.json"
        if not gt_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    "no ground_truth.json for this case — add an "
                    "independently-verified ground-truth file (a JSON object with "
                    "an 'endpoints' list) to benchmark trace accuracy"
                ),
            )
        if gt_path.stat().st_size > _MAX_TRUTH_BYTES:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="ground_truth.json unavailable",
            )
        truth = load_ground_truth(gt_path)  # may raise ValueError on malformed
        score = score_case_dir(case_dir, truth)
    except HTTPException:
        raise
    except ValueError as exc:
        # Malformed ground truth — the operator's input is wrong, not us.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from None
    except Exception as exc:  # noqa: BLE001 — never 500; map any blowup to 404
        log.warning("get_benchmark: scoring failed for %r: %s", case_id, exc)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="ground_truth.json unavailable",
        ) from None

    return score.to_dict()


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/benchmark client-side with the admin key."
    ),
)
def benchmark_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("benchmark_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Trace Benchmark console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
