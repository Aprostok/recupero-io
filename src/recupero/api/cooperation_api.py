"""Cooperation-intelligence operator console + admin JSON endpoint (v0.24 surface).

A live, authenticated operator surface for the v0.24 cooperation-intelligence
phase: per-issuer (exchange / token issuer) cooperation profiles aggregated
across every case — how many freeze letters were sent, response/freeze rates,
response times, the recommended legal instrument, and a "black hole"
(never-cooperates) flag. This is a DEPLOYMENT-WIDE dashboard sourced from the
Postgres ``freeze_letters_sent`` / ``freeze_outcomes`` tables (NOT case-scoped);
it degrades gracefully to an empty result when no DB is configured, exactly like
the operator hub's ``/v1/console/stats``.

Security model (mirrors ``/v1/freshness`` and ``/v1/watchlist``): the CONSOLE
shell at ``/v1/cooperation/console`` is served unauthenticated and contains NO
data — every dynamic value is fetched client-side from the admin-gated JSON
endpoint with the operator's ``X-Recupero-Admin-Key``. A browser navigation
cannot send a custom auth header, so server-gating the HTML itself would force
the key into the URL (leaks into logs/history); the shell+client-fetch pattern
keeps the key in a header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/cooperation``           — admin-gated JSON (issuer profiles)
  * ``GET  /v1/cooperation/console``   — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/cooperation", tags=["cooperation"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "cooperation_console.html"
)


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as freshness_api / cron_admin_api / review_api — duplicated to
    keep this module standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="cooperation API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Cooperation-intelligence report JSON — per-issuer cross-case "
        "cooperation profiles (letters sent, response/freeze rates, response "
        "times, recommended legal instrument, black-hole flag). Deployment-wide, "
        "sourced from the DB. Degrades to an empty result when no DB is "
        "configured. Admin-gated."
    ),
)
def get_cooperation(
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)

    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        # DSN-gated degrade-to-empty (mirrors operator_console._collect_stats):
        # no DB configured → empty 200, never a 500.
        return {"profiles": [], "count": 0, "db_configured": False}

    try:
        # Deferred imports: the no-DB path above must not require the DB /
        # psycopg-touching modules to import, so keep these inside the
        # DSN-guarded branch.
        from recupero.monitoring.cooperation_intelligence import (
            build_all_profiles,
            recommend_legal_instrument,
        )
        from recupero.reports.cooperation_dashboard import (
            _profile_to_template_dict,
        )

        profiles_by_issuer = build_all_profiles(dsn)

        # Match render_cooperation_dashboard's profile->dict transformation
        # exactly: the dashboard doesn't know the next case's jurisdiction or
        # OFAC posture, so the recommendation is computed with neutral inputs
        # (the per-case LE Section 5.7 layer applies case-specific signals on
        # top). Sort deterministically by issuer so the JSON is stable.
        rows: list[dict[str, Any]] = []
        for prof in sorted(
            profiles_by_issuer.values(), key=lambda p: p.issuer
        ):
            rec = recommend_legal_instrument(
                prof, jurisdiction=None, ofac_exposed=False, ic3_case_id=None,
            )
            rows.append(
                _profile_to_template_dict(prof, rec.instrument, rec.reason)
            )

        return {"profiles": rows, "count": len(rows), "db_configured": True}
    except Exception as exc:  # noqa: BLE001 — never 500 the operator console
        log.warning("get_cooperation: profile build failed: %s", exc)
        return {
            "profiles": [],
            "count": 0,
            "db_configured": True,
            "error": "cooperation profiles unavailable",
        }


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/cooperation client-side with the admin key."
    ),
)
def cooperation_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("cooperation_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Cooperation Intelligence console unavailable</h1>"
                "<p>Template could not be read; use "
                "<code>recupero-ops cooperation-dashboard</code>.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
