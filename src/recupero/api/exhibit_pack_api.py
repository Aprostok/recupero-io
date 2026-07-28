"""Court-Exhibit-Pack operator console + admin JSON endpoint (v0.35.x — roadmap H1).

A live, authenticated operator surface for the court-admissible exhibit pack of a
produced case — the exhibit index every testifying expert / opposing counsel
relies on: each case artifact listed as Exhibit A, B, C… with its SHA-256 hash
and byte size, so a court can confirm the file introduced into evidence is
byte-identical to what was produced. This is READ-ONLY over already-produced case
artifacts — no new computation, no network.

Security model (mirrors ``/v1/graph-analysis``): the CONSOLE shell at
``/v1/exhibit-pack/console`` is served unauthenticated and contains NO data —
every dynamic value is fetched client-side from the admin-gated JSON endpoint
with the operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a
custom auth header, so server-gating the HTML itself would force the key into the
URL (leaks into logs/history); the shell+client-fetch pattern keeps the key in a
header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/exhibit-pack``          — admin-gated JSON (exhibit manifest)
  * ``GET  /v1/exhibit-pack/console``  — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/exhibit-pack", tags=["exhibit-pack"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "exhibit_pack_console.html"
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
            detail="exhibit-pack API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Court-exhibit-pack manifest for a case — every produced artifact as "
        "Exhibit A, B, C… with its SHA-256 hash and human byte size, plus the "
        "exhibit count and case metadata. Read-only; admin-gated."
    ),
)
def get_exhibit_pack(
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

    from recupero.api._case_workdir import (
        CaseNotFound,
        CaseStoreUnavailable,
        case_workdir,
    )
    from recupero.reports.exhibit_pack import build_exhibit_manifest

    # case_workdir yields the case's real directory on a filesystem deploy and
    # a temp directory of downloaded artifacts on a Supabase deploy, so the
    # manifest builder below is unchanged. want=None because the exhibit pack
    # hashes EVERY artifact — it genuinely needs the whole tree.
    try:
        with case_workdir(case_id, want=None) as case_dir:
            try:
                manifest = build_exhibit_manifest(case_dir)
            except (OSError, ValueError):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="case not found",
                ) from None
            except Exception as exc:  # noqa: BLE001 — never 500
                log.warning(
                    "get_exhibit_pack: manifest build failed for %r: %s",
                    case_id, exc,
                )
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="exhibit pack unavailable",
                ) from None
    except CaseNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case not found",
        ) from None
    except CaseStoreUnavailable as exc:
        log.warning("get_exhibit_pack: case store unavailable for %r: %s", case_id, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="case store unavailable",
        ) from None

    return manifest.to_dict()


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/exhibit-pack client-side with the admin key."
    ),
)
def exhibit_pack_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("exhibit_pack_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Exhibit Pack console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
