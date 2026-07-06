"""Per-org audit trail for the ``/v2`` SaaS layer (SOC 2 CC6/CC7).

Writes into the shared append-only ``public.audit_log`` (migration 034 + the
``org_id`` from 040) using the caller's REQUEST connection, so an event commits
atomically with the action it records and is unit-testable without a live DB.

Best-effort: a write failure is swallowed + logged so it NEVER breaks the action
being audited (the same posture as ``recupero.audit.store``). NEVER stores
secrets — only the actor (user id / api-key NAME, never the key), the action, a
target, and non-secret metadata.
"""

from __future__ import annotations

import json
import logging
from typing import Any

log = logging.getLogger(__name__)

_MAX_METADATA_CHARS = 4000


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


def record(
    conn: Any, *, org_id: str | None, actor: str, action: str,
    target: str | None = None, target_kind: str | None = None,
    outcome: str = "success", source_ip: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> bool:
    """Append one org-scoped audit row in the caller's transaction. Returns True
    on insert, False on any failure. NEVER raises."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO public.audit_log "
                "(org_id, actor, action, target, target_kind, outcome, source_ip, metadata) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)",
                (
                    org_id,
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
        log.warning("platform audit: record failed (action=%s org=%s): %s",
                    action, org_id, exc)
        return False


def list_events(conn: Any, *, org_id: str, limit: int = 100) -> list[dict[str, Any]]:
    """Recent-first audit rows for one org. Degrades to [] on any error."""
    limit = max(1, min(int(limit or 100), 500))
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, occurred_at, actor, action, target, target_kind, outcome, metadata "
                "FROM public.audit_log WHERE org_id = %s "
                "ORDER BY occurred_at DESC LIMIT %s",
                (org_id, limit),
            )
            rows = cur.fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            md = r[7]
            if isinstance(md, str):
                try:
                    md = json.loads(md)
                except Exception:  # noqa: BLE001
                    md = {}
            out.append({
                "id": r[0],
                "occurred_at": r[1].isoformat() if hasattr(r[1], "isoformat") else r[1],
                "actor": r[2], "action": r[3], "target": r[4], "target_kind": r[5],
                "outcome": r[6], "metadata": md if isinstance(md, dict) else {},
            })
        return out
    except Exception as exc:  # noqa: BLE001
        log.warning("platform audit: list failed: %s", exc)
        return []


__all__ = ("record", "list_events")
