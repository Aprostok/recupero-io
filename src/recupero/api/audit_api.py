"""Audit-log read endpoint (SOC 2 CC6/CC7 visibility).

Admin-gated JSON of the append-only audit trail (migration 034) — who did what,
when, to which target, and the outcome. Sourced from the DB; degrades to an
empty result when no DSN is configured. Writes happen guarded at the action
sites (label promote/reject, …), never here.

  * GET /v1/audit — recent audit events, newest first, optional actor/action
    filter. Admin-gated.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/audit", tags=["audit"])


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as recovery_alerts_api / freshness_api — duplicated to keep this
    module standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="audit API disabled — set RECUPERO_ADMIN_KEY to enable",
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
        "Audit-log JSON — recent security-sensitive actions (label promote/"
        "reject, …), newest first, optional actor/action filter. Sourced from "
        "the DB; degrades to empty when no DB is configured. Admin-gated."
    ),
)
def get_audit_log(
    actor: str | None = None,
    action: str | None = None,
    limit: int = 200,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)

    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        return {"events": [], "count": 0, "db_configured": False}

    try:
        from recupero.audit import list_audit_events
        rows = list_audit_events(dsn, limit=limit, actor=actor, action=action)
        return {
            "events": [e.to_json_safe() for e in rows],
            "count": len(rows),
            "db_configured": True,
        }
    except Exception as exc:  # noqa: BLE001 — never 500 the console
        log.warning("get_audit_log: read failed: %s", exc)
        return {"events": [], "count": 0, "db_configured": True, "error": "audit read failed"}
