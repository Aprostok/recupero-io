"""Law-firm portfolio operator console + admin JSON endpoint (v0.26 surface).

A live, authenticated operator surface for the v0.26 Law Firm Dashboard
phase: per-law-firm portfolio views aggregated across every referred case —
how many cases were referred, how many traces completed / sit in queue, the
total loss / money frozen / returned to victims, intake→letter and
letter→freeze throughput medians, and the top issuers seen across the firm's
caseload. This is a DEPLOYMENT-WIDE dashboard sourced from the Postgres
``law_firms`` / ``case_referrals`` / ``freeze_*`` tables (NOT case-scoped); it
degrades gracefully to an empty result when no DB is configured, exactly like
the operator hub's ``/v1/console/stats``.

Security model (mirrors ``/v1/cooperation`` and ``/v1/watchlist``): the CONSOLE
shell at ``/v1/law-firm/console`` is served unauthenticated and contains NO
data — every dynamic value is fetched client-side from the admin-gated JSON
endpoint with the operator's ``X-Recupero-Admin-Key``. A browser navigation
cannot send a custom auth header, so server-gating the HTML itself would force
the key into the URL (leaks into logs/history); the shell+client-fetch pattern
keeps the key in a header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/law-firm``           — admin-gated JSON (firm portfolios)
  * ``GET  /v1/law-firm/console``   — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/law-firm", tags=["law-firm"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "law_firm_console.html"
)


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as freshness_api / cron_admin_api / review_api — duplicated to
    keep this module standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="law-firm API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Law-firm portfolio report JSON — per-firm cross-case portfolio "
        "rollups (cases referred / completed / in queue, total loss, money "
        "frozen / returned, intake→letter and letter→freeze throughput "
        "medians, top issuers). Deployment-wide, sourced from the DB. "
        "Degrades to an empty result when no DB is configured. Admin-gated."
    ),
)
def get_law_firm_portfolios(
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)

    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        # DSN-gated degrade-to-empty (mirrors operator_console._collect_stats):
        # no DB configured → empty 200, never a 500.
        return {"firms": [], "count": 0, "db_configured": False}

    try:
        # Deferred imports: the no-DB path above must not require the DB /
        # psycopg-touching modules to import, so keep these inside the
        # DSN-guarded branch.
        from recupero.monitoring.law_firm_dashboard import (
            build_all_firm_portfolios,
        )
        from recupero.reports.law_firm_dashboard import (
            _portfolio_to_template_dict,
        )

        portfolios = build_all_firm_portfolios(dsn=dsn)

        # Reuse the dashboard's portfolio->dict presenter verbatim so the
        # JSON matches the HTML dashboard (money/percentages formatted
        # identically). Sort deterministically by the firm slug so the JSON
        # is stable across requests.
        rows = [_portfolio_to_template_dict(p) for p in portfolios]
        rows.sort(key=lambda r: (r.get("firm_slug") or "", r.get("firm_name") or ""))

        return {"firms": rows, "count": len(rows), "db_configured": True}
    except Exception as exc:  # noqa: BLE001 — never 500 the operator console
        log.warning("get_law_firm_portfolios: portfolio build failed: %s", exc)
        return {
            "firms": [],
            "count": 0,
            "db_configured": True,
            "error": "law-firm portfolios unavailable",
        }


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/law-firm client-side with the admin key."
    ),
)
def law_firm_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("law_firm_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Law Firm Dashboard console unavailable</h1>"
                "<p>Template could not be read; use "
                "<code>recupero-ops law-firm-dashboard</code>.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
