"""Persistence for D6 proactive recovery alerts (see migrations/033).

D6 (``recovery_alerts.evaluate_recovery_alerts``) derives a prioritized
``RecoveryAlert`` per material change from each watch tick. Previously those
were ephemeral — only present in the in-memory ``WatchTickReport``. This module
persists them to ``public.recovery_alerts`` so the operator console
(``/v1/recovery-alerts``) can surface the live "act-now / freeze-NOW" queue
between ticks.

All functions use the shared :func:`recupero._common.db_connect` and RAISE on
DB error — callers decide whether to degrade (the API read) or swallow (the
watch-tick write is guarded so persistence can never break a tick). Writing the
code before migration 033 is applied is non-fatal: the watch-tick persist is
wrapped in try/except (table-missing is logged, not raised) and the API read
degrades to an empty list.
"""

from __future__ import annotations

import logging
from typing import Any

from recupero._common import db_connect

log = logging.getLogger(__name__)

_ALLOWED_SEVERITY = ("critical", "high")
_ALLOWED_STATUS = ("open", "acknowledged")


def _alert_to_row(alert: Any) -> dict[str, Any]:
    """Normalize a RecoveryAlert (or an already-serialized dict) to a flat dict."""
    if hasattr(alert, "to_dict"):
        return alert.to_dict()
    return dict(alert)


def persist_alerts(
    dsn: str, alerts: list[Any], *, tick_started_at: Any = None
) -> int:
    """Persist the RecoveryAlerts a watch tick produced. Returns the number of
    rows actually inserted (dedup-skipped rows don't count).

    Idempotent per ``(address, chain, kind, tick)`` via a UNIQUE ``dedup_key``
    with ``ON CONFLICT DO NOTHING`` — replaying the same tick won't duplicate
    alerts, but a NEW tick re-alerts a still-moving address (each tick is a
    point-in-time snapshot of what an operator should act on).

    Empty input returns 0 WITHOUT opening a DB connection (so a no-DB caller
    that produced no alerts never touches the DB).
    """
    if not alerts:
        return 0
    tick_iso = (
        tick_started_at.isoformat()
        if tick_started_at is not None and hasattr(tick_started_at, "isoformat")
        else str(tick_started_at or "")
    )
    inserted = 0
    with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
        for idx, alert in enumerate(alerts):
            d = _alert_to_row(alert)
            address = str(d.get("address") or "")
            chain = str(d.get("chain") or "")
            kind = str(d.get("kind") or "")
            # Include the per-tick ORDINAL (idx) in the dedup key. evaluate_
            # recovery_alerts is deterministic (severity-then-|Δ| sorted), so a
            # genuine replay of the same tick reproduces the same order → same
            # idx → still idempotent. But two DISTINCT alerts that share
            # (address, chain, kind) within one tick — e.g. the same wallet
            # watched under two investigations — get different idx, so neither
            # is silently dropped by ON CONFLICT (the bug the ordinal fixes).
            dedup_key = f"{address}|{chain}|{kind}|{tick_iso}|{idx}"
            cur.execute(
                """
                INSERT INTO public.recovery_alerts
                    (tick_started_at, address, chain, severity, kind, delta_usd,
                     dormant_days, role, label_name, message, recommended_action,
                     dedup_key)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (dedup_key) DO NOTHING
                """,
                (
                    tick_started_at, address, chain, d.get("severity"), kind,
                    d.get("delta_usd"), d.get("dormant_days"), d.get("role"),
                    d.get("label_name"), d.get("message"),
                    d.get("recommended_action"), dedup_key,
                ),
            )
            if cur.rowcount and cur.rowcount > 0:
                inserted += cur.rowcount
    return inserted


def list_recent_alerts(
    dsn: str, *, limit: int = 200, severity: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Return recent alerts (newest first), optionally filtered by severity /
    status. ``limit`` is clamped to [1, 1000]. Timestamps are ISO strings."""
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 200
    limit = max(1, min(limit, 1000))

    # Build the optional WHERE from a FIXED set of literal fragments (NOT a
    # runtime str-join / ternary) so the inline-SQL audit can statically prove
    # the query is injection-free: filter VALUES are always bound %s params,
    # and ``where_sql`` is one of four constant string literals. The ``_sql``
    # suffix is the shape tests/test_inline_sql_audit.py recognizes as safe.
    sev_ok = severity in _ALLOWED_SEVERITY
    status_ok = status in _ALLOWED_STATUS
    if sev_ok and status_ok:
        where_sql = " WHERE severity = %s AND status = %s"
        params: list[Any] = [severity, status]
    elif sev_ok:
        where_sql = " WHERE severity = %s"
        params = [severity]
    elif status_ok:
        where_sql = " WHERE status = %s"
        params = [status]
    else:
        where_sql = ""
        params = []

    with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
        sql = (
            "SELECT id, created_at, tick_started_at, address, chain, severity, "
            "kind, delta_usd, dormant_days, role, label_name, message, "
            "recommended_action, status FROM public.recovery_alerts"
            + where_sql
            + " ORDER BY created_at DESC, id DESC LIMIT %s"
        )
        cur.execute(sql, (*params, limit))
        cols = [c[0] for c in cur.description]
        out: list[dict[str, Any]] = []
        for row in cur.fetchall():
            d = dict(zip(cols, row, strict=False))
            for k in ("created_at", "tick_started_at"):
                v = d.get(k)
                if v is not None and hasattr(v, "isoformat"):
                    d[k] = v.isoformat()
            out.append(d)
        return out


__all__ = ("persist_alerts", "list_recent_alerts")
