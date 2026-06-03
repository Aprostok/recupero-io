"""D4 incident-response plans operator console + admin JSON endpoint.

D6 (``recovery_alerts``) fires when watched funds move — "act now". D4
(``incident_response.build_incident_plans``) turns each persisted D6 alert into
a concrete, ordered response plan an operator executes: re-trace the moved
address → venue-conditional freeze/subpoena → notify LE / investigator → set a
follow-up. This surface reads the persisted recovery alerts back and derives the
plans on the fly — a DEPLOYMENT-WIDE dashboard (NOT case-scoped), sourced from
the Postgres ``recovery_alerts`` table. It degrades gracefully to an empty
result when no DB is configured, exactly like the recovery-alerts console.

Security model (mirrors ``/v1/recovery-alerts``): the CONSOLE shell at
``/v1/incident-plans/console`` is served unauthenticated and contains NO data —
every dynamic value is fetched client-side from the admin-gated JSON endpoint
with the operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a
custom auth header, so server-gating the HTML itself would force the key into
the URL (leaks into logs/history); the shell+client-fetch pattern keeps the key
in a header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/incident-plans``           — admin-gated JSON (plans from alerts)
  * ``GET  /v1/incident-plans/console``   — unauthenticated shell (HTML+JS); no data
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

router = APIRouter(prefix="/v1/incident-plans", tags=["incident-plans"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "incident_plans_console.html"
)


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as recovery_alerts_api / freshness_api — duplicated to keep this
    module standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="incident-plans API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Incident-plans JSON — ordered D4 response playbooks derived from the "
        "recent persisted D6 recovery alerts (re-trace → venue-conditional "
        "freeze/subpoena → notify → follow-up), highest-severity first, "
        "optionally filtered by severity. Deployment-wide, sourced from the DB. "
        "Degrades to an empty result when no DB is configured. Admin-gated."
    ),
)
def get_incident_plans(
    severity: str | None = None,
    limit: int = 200,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)

    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        # DSN-gated degrade-to-empty: no DB configured → empty 200, never a 500.
        return {"plans": [], "count": 0, "db_configured": False}

    try:
        # Deferred import: the no-DB path above must not require the DB /
        # psycopg-touching modules to import, so keep these inside the
        # DSN-guarded branch.
        from recupero.monitoring.incident_response import build_incident_plans
        from recupero.monitoring.recovery_alerts_store import list_recent_alerts

        # list_recent_alerts clamps limit to [1, 1000] and ignores an invalid
        # severity, so pass the query params straight through. The stored alert
        # dicts are consumed directly by build_incident_plans (its _f helper does
        # dict.get OR getattr) — no reconstruction needed.
        rows = list_recent_alerts(dsn, limit=limit, severity=severity)
        plans = build_incident_plans(rows)
        return {"plans": plans, "count": len(plans), "db_configured": True}
    except Exception as exc:  # noqa: BLE001 — never 500 the operator console
        log.warning("get_incident_plans: plan build failed: %s", exc)
        return {
            "plans": [],
            "count": 0,
            "db_configured": True,
            "error": "incident plans unavailable",
        }


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/incident-plans client-side with the admin key."
    ),
)
def incident_plans_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("incident_plans_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Incident Plans console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
