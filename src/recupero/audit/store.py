"""Audit-log persistence (migration 034). Append-only; never raises.

SOC 2 CC6/CC7: an immutable trail of who did what, when, to which target, and
the outcome. ``record_audit_event`` is called best-effort at action sites
(trusted-data mutations such as label promote/reject); ``list_audit_events``
backs the read endpoint. NEVER stores secrets / API keys — only the actor's
NAME (never the key), the action, target, outcome, source IP, and non-secret
metadata.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# Bound metadata size so an oversized payload can't bloat the row / log.
_MAX_METADATA_CHARS = 4000


@dataclass
class AuditEvent:
    """One audit-log row (read shape)."""

    id: int
    occurred_at: str | None
    actor: str
    action: str
    target: str | None
    target_kind: str | None
    outcome: str
    source_ip: str | None
    metadata: dict[str, Any]

    def to_json_safe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "target_kind": self.target_kind,
            "outcome": self.outcome,
            "source_ip": self.source_ip,
            "metadata": self.metadata,
        }


def _safe_metadata(metadata: dict[str, Any] | None) -> str:
    """JSON-encode metadata defensively, capped. Never raises."""
    if not metadata:
        return "{}"
    try:
        encoded = json.dumps(metadata, default=str, ensure_ascii=False)
    except Exception:  # noqa: BLE001
        return "{}"
    if len(encoded) > _MAX_METADATA_CHARS:
        return json.dumps({"_truncated": True})
    return encoded


def record_audit_event(
    dsn: str | None,
    *,
    actor: str,
    action: str,
    target: str | None = None,
    target_kind: str | None = None,
    outcome: str = "success",
    source_ip: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> bool:
    """Append one audit row. Best-effort: returns True on insert, False on any
    failure (no DSN, missing table, DB error). NEVER raises — an audit-write
    failure must not break the action being audited."""
    if not dsn:
        return False
    try:
        from recupero._common import db_connect
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.audit_log
                    (actor, action, target, target_kind, outcome, source_ip, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    str(actor)[:200], str(action)[:200],
                    (str(target)[:400] if target is not None else None),
                    (str(target_kind)[:100] if target_kind is not None else None),
                    str(outcome)[:50],
                    (str(source_ip)[:100] if source_ip is not None else None),
                    _safe_metadata(metadata),
                ),
            )
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("audit: record failed (action=%s actor=%s): %s",
                    action, actor, exc)
        return False


def list_audit_events(
    dsn: str | None,
    *,
    limit: int = 200,
    actor: str | None = None,
    action: str | None = None,
) -> list[AuditEvent]:
    """Recent-first audit rows. Degrades to [] when DSN/table absent."""
    if not dsn:
        return []
    limit = max(1, min(int(limit or 200), 1000))

    # Inline-SQL-audit safe: every WHERE clause is a FIXED literal assigned to a
    # `_sql`-suffixed var; values are always bound %s params (never interpolated).
    params: list[Any] = []
    if actor and action:
        where_sql = " WHERE actor = %s AND action = %s"
        params.extend([actor, action])
    elif actor:
        where_sql = " WHERE actor = %s"
        params.append(actor)
    elif action:
        where_sql = " WHERE action = %s"
        params.append(action)
    else:
        where_sql = ""
    params.append(limit)

    query_sql = (
        "SELECT id, occurred_at, actor, action, target, target_kind, "
        "outcome, source_ip, metadata FROM public.audit_log"
        + where_sql
        + " ORDER BY occurred_at DESC LIMIT %s"
    )

    try:
        from recupero._common import db_connect
        out: list[AuditEvent] = []
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(query_sql, tuple(params))
            for r in cur.fetchall():
                md = r[8]
                if isinstance(md, str):
                    try:
                        md = json.loads(md)
                    except Exception:  # noqa: BLE001
                        md = {}
                out.append(AuditEvent(
                    id=r[0],
                    occurred_at=(r[1].isoformat() if hasattr(r[1], "isoformat") else r[1]),
                    actor=r[2], action=r[3], target=r[4], target_kind=r[5],
                    outcome=r[6], source_ip=r[7],
                    metadata=md if isinstance(md, dict) else {},
                ))
        return out
    except Exception as exc:  # noqa: BLE001
        log.warning("audit: list failed: %s", exc)
        return []
