"""Fund-Endpoints operator console — "where the money is sitting now" (v0.42).

Pull up a case and see, at a glance, WHERE the stolen funds ended up, how much is
still REACHABLE (freeze / monitor / subpoena) vs. GONE (mixer / burned /
bridged-out), and whether any endpoint has MOVED since the last watch tick.

This is a thin READ-ONLY view over a case's already-computed
``freeze_brief.json`` — it runs no trace, calls no chain adapter, and infers
nothing new. It reads the brief (local ``CaseStore`` or, when configured, the
Supabase bucket), optionally annotates each endpoint with the watchlist's
movement verdict (best-effort; degrades to "never checked" without a DB), and
hands both to the pure ``reports.fund_endpoints.build_fund_endpoints`` view model.

Security model mirrors ``case_overview_api`` (the established secure-shell
pattern): the CONSOLE at ``/v1/fund-endpoints/console`` is unauthenticated and
carries NO data; every value is fetched client-side from the admin-gated JSON
endpoint with the operator's ``X-Recupero-Admin-Key`` (a browser navigation can't
send a custom header, so gating the HTML would force the key into the URL/logs).

  * ``GET /v1/fund-endpoints?case_id=`` — admin-gated endpoint-rollup JSON
  * ``GET /v1/fund-endpoints/console``  — unauthenticated shell (no data)
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import HTMLResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/fund-endpoints", tags=["fund-endpoints"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "fund_endpoints.html"
)

# Bound the case_id at the API edge before any storage lookup (matches
# case_overview_api). The storage layer enforces its own stricter cap.
_MAX_CASE_ID_LEN = 128
# A freeze brief is small (holdings + editorial), but cap the local read so a
# pathological file can't be slurped into memory. 16 MiB is generous headroom.
_MAX_BRIEF_BYTES = 16 * 1024 * 1024


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Duplicated from the other admin modules to stay standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="fund-endpoints API disabled — set RECUPERO_ADMIN_KEY to enable",
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


def _read_brief(case_id: str) -> dict[str, Any] | None:
    """Return the parsed ``freeze_brief.json`` for a case, or None if absent.

    Prefers the Supabase bucket when the deploy is switched to it (same rule as
    the case index); otherwise reads the local case store. Any read/parse failure
    returns None (the caller maps that to 404) — this never 500s."""
    # Supabase-backed deploy (opt-in): read the artifact from the bucket.
    try:
        from recupero.api import _supabase_case_source as _sup

        if _sup.enabled():
            try:
                raw = _sup.read_artifact(case_id, "freeze_brief.json")
            except Exception:  # noqa: BLE001 — missing/oversize/malformed → None
                return None
            if not raw:
                return None
            return json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return None
    except Exception as exc:  # noqa: BLE001
        log.warning("fund-endpoints: supabase brief read failed for %r: %s", case_id, exc)
        return None

    # Local case store (default).
    try:
        from recupero.config import load_config
        from recupero.storage.case_store import CaseStore

        cfg, _ = load_config()
        store = CaseStore(cfg)
        # read_case is path-traversal-guarded; it raises for a missing/malformed
        # case. Only after it validates do we derive the case dir (case_dir would
        # CREATE the directory as a side effect, so it can't test existence).
        store.read_case(case_id)
        brief_path = store.cases_root / case_id / "freeze_brief.json"
        if not brief_path.is_file():
            return None
        if brief_path.stat().st_size > _MAX_BRIEF_BYTES:
            log.warning("fund-endpoints: brief too large for %r; refusing", case_id)
            return None
        return json.loads(brief_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    except Exception as exc:  # noqa: BLE001
        log.warning("fund-endpoints: local brief read failed for %r: %s", case_id, exc)
        return None


def _watchlist_index(case_id: str) -> dict[str, dict[str, Any]] | None:
    """Best-effort ``{canonical_address: {movement,...}}`` for movement badges.

    Returns None when there's no DB (SUPABASE_DB_URL unset) or any read fails —
    the builder then reports every endpoint as ``never_checked`` (the honest
    default). Scoped to this case's investigation so it's a cheap read."""
    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        return None
    try:
        from recupero._common import canonical_address_key as _ck
        from recupero.monitoring.watchlist_dashboard import build_watchlist_overview

        overview = build_watchlist_overview(dsn=dsn, investigation_id=case_id)
        index: dict[str, dict[str, Any]] = {}
        for it in overview.items:
            if not it.address:
                continue
            index[_ck(it.address)] = {
                "movement": it.movement,
                "last_delta_usd": (
                    str(it.last_delta_usd) if it.last_delta_usd is not None else None
                ),
                "last_checked_at": (
                    it.last_checked_at.isoformat() if it.last_checked_at else None
                ),
            }
        return index or None
    except Exception as exc:  # noqa: BLE001 — movement is a nicety, never fatal
        log.warning("fund-endpoints: watchlist index failed for %r: %s", case_id, exc)
        return None


@router.get(
    "",
    summary=(
        "Fund-endpoint rollup for a case — every terminal resting place of the "
        "stolen funds, classified by recoverability (FREEZABLE / TRACKED / "
        "EXCHANGE / UNRECOVERABLE), with movement verdicts. Admin-gated."
    ),
)
def get_fund_endpoints(
    case_id: str,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)

    cid = (case_id or "").strip()
    if not cid or len(case_id) > _MAX_CASE_ID_LEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="case_id must be 1..128 non-blank characters",
        )

    brief = _read_brief(cid)
    if brief is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case not found or has no freeze brief",
        )

    from recupero.reports.fund_endpoints import build_fund_endpoints

    watchlist_index = _watchlist_index(cid)
    try:
        view = build_fund_endpoints(brief, watchlist_index=watchlist_index)
    except Exception as exc:  # noqa: BLE001 — never 500 on a malformed brief
        log.warning("fund-endpoints: build failed for %r: %s", cid, exc)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="fund-endpoint view unavailable",
        ) from None

    view["case_id"] = cid
    view["generated_at"] = datetime.now(UTC).isoformat()
    view["watchlist_linked"] = watchlist_index is not None
    return view


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Fund-endpoints operator console (HTML shell). Unauthenticated by "
        "design — contains NO data; fetches /v1/fund-endpoints client-side."
    ),
)
def fund_endpoints_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("fund_endpoints_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Fund Endpoints console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
