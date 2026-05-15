"""Aggregated counters for the admin-UI's investigator dashboard.

Pure read-only: composes top-level numbers from public.cases /
public.investigations / public.watchlist / public.watchlist_snapshots
that Jacob's UI surfaces on the homepage (total cases, freezable USD
under monitoring, last digest timestamp, etc.).

Designed to be called by either:

  * The worker's HTTP healthz pod, on a new ``/dashboard.json``
    endpoint that the admin UI polls every 60s.
  * A standalone CLI: ``recupero-worker --dashboard-summary`` for
    one-shot inspection.

Either path returns the same JSON shape; the schema is stable so
the UI can build against a fixed contract.

Schema:

  {
    "generated_at":     "2026-05-14T22:14:00+00:00",
    "cases": {
        "total":         123,
        "intake":        45,
        "investigating": 60,
        "ready_for_le":  10,
        "closed":        8
    },
    "investigations": {
        "pending":          2,
        "active":           1,
        "awaiting_review":  3,
        "complete":         100,
        "failed":           5,
        "total_api_costs_usd": "12.34"
    },
    "watchlist": {
        "active":      1227,
        "hot":         3,
        "paused":      45,
        "freezeable":  220,
        "total_balance_usd": "1234567.89"
    },
    "snapshots": {
        "in_last_24h":      245,
        "material_changes_24h": 7,
        "freezeable_changes_24h": 2
    },
    "digest": {
        "last_run_at":     "2026-05-14T03:00:00+00:00",
        "latest_digest_id": "DIGEST-20260514T030042-a1b2c3",
        "latest_path":     "watchlist-digest/2026-05-14/DIGEST-...json"
    }
  }
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import psycopg
from psycopg.rows import dict_row

log = logging.getLogger(__name__)


def build_dashboard_summary(*, dsn: str) -> dict[str, Any]:
    """Compose the dashboard summary JSON.

    Resilient: any sub-query failure logs a warning and the
    corresponding section is filled with zeros / nulls so the
    response always parses cleanly on the UI side.
    """
    generated_at = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "generated_at": generated_at.isoformat(),
        "cases": _empty_cases(),
        "investigations": _empty_investigations(),
        "watchlist": _empty_watchlist(),
        "snapshots": _empty_snapshots(),
        "digest": _empty_digest(),
    }

    pooled = _pooled_dsn(dsn)
    try:
        with psycopg.connect(pooled, autocommit=True, row_factory=dict_row,
                             prepare_threshold=None, connect_timeout=10) as conn:
            payload["cases"]          = _query_cases(conn) or payload["cases"]
            payload["investigations"] = _query_investigations(conn) or payload["investigations"]
            payload["watchlist"]      = _query_watchlist(conn) or payload["watchlist"]
            payload["snapshots"]      = _query_snapshots(conn) or payload["snapshots"]
    except Exception as exc:  # noqa: BLE001
        log.warning("dashboard summary: DB connection failed: %s", exc)
    return payload


# ----- sub-queries ----- #


def _query_cases(conn) -> dict[str, Any]:
    out = _empty_cases()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT status, COUNT(*) AS n FROM public.cases GROUP BY status;")
            for r in cur.fetchall():
                status = (r["status"] or "").lower()
                out["total"] += int(r["n"])
                if status in out:
                    out[status] = int(r["n"])
    except Exception as exc:  # noqa: BLE001
        log.warning("cases summary: %s", exc)
    return out


def _query_investigations(conn) -> dict[str, Any]:
    out = _empty_investigations()
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT status, COUNT(*) AS n,
                                  COALESCE(SUM(api_costs_usd), 0) AS cost
                             FROM public.investigations GROUP BY status;""")
            total_cost = Decimal(0)
            for r in cur.fetchall():
                status = (r["status"] or "").lower()
                n = int(r["n"])
                total_cost += Decimal(r["cost"] or 0)
                # Roll up working states into 'active' for the UI.
                if status in {"claimed", "tracing", "listing_freeze_targets",
                              "editorial_drafting", "emitting", "building_package"}:
                    out["active"] += n
                elif status == "pending":
                    out["pending"] = n
                elif status == "awaiting_review":
                    out["awaiting_review"] = n
                elif status == "complete":
                    out["complete"] = n
                elif status == "failed":
                    out["failed"] = n
            out["total_api_costs_usd"] = str(total_cost.quantize(Decimal("0.0001")))
    except Exception as exc:  # noqa: BLE001
        log.warning("investigations summary: %s", exc)
    return out


def _query_watchlist(conn) -> dict[str, Any]:
    out = _empty_watchlist()
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT status, COUNT(*) AS n,
                                  COALESCE(SUM(last_balance_usd), 0) AS bal
                             FROM public.watchlist GROUP BY status;""")
            total_bal = Decimal(0)
            for r in cur.fetchall():
                status = (r["status"] or "").lower()
                n = int(r["n"])
                if status == "active":
                    out["active"] = n
                    total_bal += Decimal(r["bal"] or 0)
            out["total_balance_usd"] = str(total_bal.quantize(Decimal("0.01")))

            # Freezeable count (a tag inside active rows).
            cur.execute("""SELECT COUNT(*) AS n FROM public.watchlist
                            WHERE status='active' AND is_freezeable;""")
            row = cur.fetchone()
            out["freezeable"] = int(row["n"]) if row else 0

            # Priority tier counts — only valid after migration 004 lands.
            try:
                cur.execute("""SELECT priority, COUNT(*) AS n
                                 FROM public.watchlist
                                WHERE status='active'
                                GROUP BY priority;""")
                for r in cur.fetchall():
                    p = (r["priority"] or "").lower()
                    if p in out:
                        out[p] = int(r["n"])
            except psycopg.errors.UndefinedColumn:
                pass  # migration 004 not applied yet
    except Exception as exc:  # noqa: BLE001
        log.warning("watchlist summary: %s", exc)
    return out


def _query_snapshots(conn) -> dict[str, Any]:
    out = _empty_snapshots()
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT COUNT(*) AS n
                             FROM public.watchlist_snapshots
                            WHERE taken_at > NOW() - INTERVAL '24 hours';""")
            row = cur.fetchone()
            out["in_last_24h"] = int(row["n"]) if row else 0

            # Material changes = snapshots where |delta_usd| >= 100
            # OR where tx_count increased vs the prior snapshot.
            # For the dashboard summary, just count significant delta_usd.
            cur.execute("""SELECT COUNT(*) AS n
                             FROM public.watchlist_snapshots
                            WHERE taken_at > NOW() - INTERVAL '24 hours'
                              AND ABS(COALESCE(delta_usd, 0)) >= 100;""")
            row = cur.fetchone()
            out["material_changes_24h"] = int(row["n"]) if row else 0

            cur.execute("""SELECT COUNT(*) AS n
                             FROM public.watchlist_snapshots s
                             JOIN public.watchlist w
                               ON w.id = s.watchlist_id
                            WHERE s.taken_at > NOW() - INTERVAL '24 hours'
                              AND ABS(COALESCE(s.delta_usd, 0)) >= 100
                              AND w.is_freezeable = TRUE;""")
            row = cur.fetchone()
            out["freezeable_changes_24h"] = int(row["n"]) if row else 0
    except Exception as exc:  # noqa: BLE001
        log.warning("snapshots summary: %s", exc)
    return out


# ----- empty payloads ----- #


def _empty_cases() -> dict[str, Any]:
    return {
        "total": 0, "intake": 0, "investigating": 0,
        "ready_for_le": 0, "closed": 0,
    }


def _empty_investigations() -> dict[str, Any]:
    return {
        "pending": 0, "active": 0, "awaiting_review": 0,
        "complete": 0, "failed": 0, "total_api_costs_usd": "0.0000",
    }


def _empty_watchlist() -> dict[str, Any]:
    return {
        "active": 0, "standard": 0, "hot": 0, "paused": 0,
        "freezeable": 0, "total_balance_usd": "0.00",
    }


def _empty_snapshots() -> dict[str, Any]:
    return {
        "in_last_24h": 0,
        "material_changes_24h": 0,
        "freezeable_changes_24h": 0,
    }


def _empty_digest() -> dict[str, Any]:
    return {
        "last_run_at": None,
        "latest_digest_id": None,
        "latest_path": None,
    }


# ----- DSN pooler rewrite (mirrors watch_tick._pooled_dsn) ----- #


def _pooled_dsn(dsn: str) -> str:
    if "db." in dsn and ".supabase.co" in dsn:
        m = re.search(
            r"postgres(?:ql)?://([^:]+):([^@]+)@db\.([^.]+)\.supabase\.co",
            dsn,
        )
        if m:
            user, pwd, ref = m.group(1), m.group(2), m.group(3)
            return (
                f"postgresql://{user}.{ref}:{pwd}"
                f"@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
            )
    return dsn


__all__ = ("build_dashboard_summary",)
