"""D6 proactive recovery-alerts operator console + admin JSON endpoint.

The live "act-now / freeze-NOW" queue. D6
(``recovery_alerts.evaluate_recovery_alerts``) derives a prioritized
``RecoveryAlert`` per material on-chain movement from each watch tick; those
alerts are now PERSISTED to ``public.recovery_alerts`` (see migrations/033).
This surface reads them back — a DEPLOYMENT-WIDE dashboard (NOT case-scoped)
sourced from the Postgres ``recovery_alerts`` table. It degrades gracefully to
an empty result when no DB is configured, exactly like the cooperation console.

Security model (mirrors ``/v1/cooperation``): the CONSOLE shell at
``/v1/recovery-alerts/console`` is served unauthenticated and contains NO data —
every dynamic value is fetched client-side from the admin-gated JSON endpoint
with the operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a
custom auth header, so server-gating the HTML itself would force the key into
the URL (leaks into logs/history); the shell+client-fetch pattern keeps the key
in a header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/recovery-alerts``           — admin-gated JSON (recent alerts)
  * ``GET  /v1/recovery-alerts/console``   — unauthenticated shell (HTML+JS); no data
"""

from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/recovery-alerts", tags=["recovery-alerts"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "recovery_alerts_console.html"
)


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as freshness_api / cron_admin_api / review_api — duplicated to
    keep this module standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="recovery-alerts API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Recovery-alerts queue JSON — recent D6 proactive recovery alerts "
        "(act-now / freeze-NOW), newest first, optionally filtered by severity. "
        "Deployment-wide, sourced from the DB. Degrades to an empty result when "
        "no DB is configured. Admin-gated."
    ),
)
def get_recovery_alerts(
    severity: str | None = None,
    limit: int = 200,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)

    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        # DSN-gated degrade-to-empty: no DB configured → empty 200, never a 500.
        return {"alerts": [], "count": 0, "db_configured": False}

    try:
        # Deferred import: the no-DB path above must not require the DB /
        # psycopg-touching modules to import, so keep this inside the
        # DSN-guarded branch.
        from recupero.monitoring.recovery_alerts_store import list_recent_alerts

        # list_recent_alerts clamps limit to [1, 1000] and ignores an invalid
        # severity, so pass the query params straight through.
        rows = list_recent_alerts(dsn, limit=limit, severity=severity)
        summary = {
            "critical": sum(1 for r in rows if r.get("severity") == "critical"),
            "high": sum(1 for r in rows if r.get("severity") == "high"),
        }
        return {
            "alerts": rows,
            "count": len(rows),
            "summary": summary,
            "db_configured": True,
        }
    except Exception as exc:  # noqa: BLE001 — never 500 the operator console
        log.warning("get_recovery_alerts: alert read failed: %s", exc)
        return {
            "alerts": [],
            "count": 0,
            "db_configured": True,
            "error": "recovery alerts unavailable",
        }


class AlertCaseUpdate(BaseModel):
    """Case-management transition (#10). Any subset of fields; unspecified
    fields are left unchanged."""
    status: str | None = Field(
        None, description="open | acknowledged | in_progress | resolved | dismissed",
    )
    assignee: str | None = Field(None, max_length=200)
    note: str | None = Field(None, max_length=4000)


@router.patch(
    "/{alert_id}",
    summary=(
        "Case-management update for one recovery alert — assign an owner, "
        "transition status (open→acknowledged→in_progress→resolved/dismissed), "
        "and/or attach a note. Admin-gated; audit-logged."
    ),
)
def update_recovery_alert(
    alert_id: int,
    body: AlertCaseUpdate,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="case-management requires a database (SUPABASE_DB_URL)",
        )
    if body.status is None and body.assignee is None and body.note is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="no fields to update (provide status, assignee, and/or note)",
        )

    from recupero.monitoring.recovery_alerts_store import update_alert_case
    try:
        updated = update_alert_case(
            dsn, alert_id,
            status=body.status, assignee=body.assignee, note=body.note,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        log.warning("update_recovery_alert: case update failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="case update failed",
        ) from exc
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"recovery alert {alert_id} not found",
        )

    # SOC 2 audit (best-effort): record who changed the alert and how.
    try:
        from recupero.audit import record_audit_event
        record_audit_event(
            dsn, actor="admin", action="alert.update",
            target=str(alert_id), target_kind="recovery_alert",
            metadata={
                "status": body.status, "assignee": body.assignee,
                "note_set": body.note is not None,
            },
        )
    except Exception:  # noqa: BLE001
        pass

    return {"alert": updated, "updated": True}


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/recovery-alerts client-side with the admin key."
    ),
)
def recovery_alerts_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("recovery_alerts_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Recovery Alerts console unavailable</h1>"
                "<p>Template could not be read.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
