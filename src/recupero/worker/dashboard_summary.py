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
    },
    "stale_review": {
        "count":           2,
        "threshold_hours": 24,
        "rows": [
            {
                "investigation_id":   "...",
                "case_id":            "...",
                "case_number":        "...",
                "client_name":        "...",
                "chain":              "ethereum",
                "seed_address":       "0x...",
                "label":              null,
                "review_required_at": "2026-05-09T18:54:33+00:00",
                "hours_stale":        140.7
            }
        ]
    },
    "stale_engagements": {
        "count":          1,
        "threshold_days": 30,
        "rows": [
            {
                "investigation_id":      "...",
                "case_id":               "...",
                "case_number":           "...",
                "client_name":           "...",
                "chain":                 "ethereum",
                "seed_address":          "0x...",
                "engagement_started_at": "2026-04-10T12:00:00+00:00",
                "last_followup_sent_at": "2026-05-04T03:00:00+00:00",
                "days_since_start":      35,
                "days_overdue":          5
            }
        ]
    }
  }
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
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
    generated_at = datetime.now(UTC)
    payload: dict[str, Any] = {
        "generated_at": generated_at.isoformat(),
        "cases": _empty_cases(),
        "investigations": _empty_investigations(),
        "watchlist": _empty_watchlist(),
        "snapshots": _empty_snapshots(),
        "digest": _empty_digest(),
        "stale_review": _empty_stale_review(),
        "stale_engagements": _empty_stale_engagements(),
        "payments": _empty_payments(),
    }

    pooled = _pooled_dsn(dsn)
    try:
        with psycopg.connect(pooled, autocommit=True, row_factory=dict_row,
                             prepare_threshold=None, connect_timeout=10) as conn:
            payload["cases"]             = _query_cases(conn) or payload["cases"]
            payload["investigations"]    = _query_investigations(conn) or payload["investigations"]
            payload["watchlist"]         = _query_watchlist(conn) or payload["watchlist"]
            payload["snapshots"]         = _query_snapshots(conn) or payload["snapshots"]
            payload["stale_review"]      = _query_stale_review(conn) or payload["stale_review"]
            payload["stale_engagements"] = (
                _query_stale_engagements(conn) or payload["stale_engagements"]
            )
            payload["payments"] = _query_payments(conn) or payload["payments"]
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
                # v0.18.1 (round-11 worker-CRIT-001): pre-v0.18.1 used
                # `"listing_freeze_targets"` and `"editorial_drafting"`
                # but state.py declares the wire values as
                # `"finding_freeze_targets"` and `"drafting_editorial"`.
                # Active rows in those statuses fell through every
                # elif branch and never incremented `out["active"]`.
                # `total_api_costs_usd` still accumulated from them,
                # producing inconsistent counts. Sourcing from
                # state.ACTIVE_STATUSES so this can't drift again.
                from recupero.worker.state import ACTIVE_STATUSES
                if status in ACTIVE_STATUSES:
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


def _empty_stale_review() -> dict[str, Any]:
    """Default shape for the stale_review section. Comes back zero-
    filled when no rows match or the query fails — the UI shows a
    green "all caught up" widget on the homepage when count is 0."""
    return {
        "count": 0,
        # Threshold in hours used for this snapshot. Surfaced so the
        # UI can render "X rows stuck in review for > 24h" without
        # hard-coding the value.
        "threshold_hours": 24,
        "rows": [],
    }


def _empty_stale_engagements() -> dict[str, Any]:
    """Default shape for the stale_engagements section. Same UI-
    contract reasoning as _empty_stale_review — zero-filled means
    "no engagements past the 30-day window without a close marker",
    which is the green/healthy steady state.

    The Tier-2 engagement model commits us to 30 days of monitoring
    + freeze-letter follow-ups. After that window the operator should
    either renew (rare) or run ``recupero-ops mark-closed`` to wrap
    the engagement. This widget surfaces engagements that have aged
    out without being explicitly closed, so the operator sees them
    on the homepage instead of having to remember to check."""
    return {
        "count": 0,
        # Threshold in days used for this snapshot. 30 matches the
        # standard engagement commitment. Surfaced so the UI can
        # render "X engagements past the 30-day window" without
        # hard-coding the value.
        "threshold_days": 30,
        "rows": [],
    }


# ----- Stale review query ----- #
#
# The Hekla case (real intake, Phase-4 wallet-trace push) surfaced a
# 6-day stale awaiting_review row. The pipeline correctly paused for
# operator review, but nothing surfaced the wait to the operator.
# This section adds proactive visibility: any row in awaiting_review
# older than the threshold (default 24h) appears in the dashboard
# summary so the admin UI homepage can show a "needs attention"
# badge. Threshold is overridable via the
# RECUPERO_STALE_REVIEW_THRESHOLD_HOURS env var for ops who want a
# tighter or looser window.

_DEFAULT_STALE_REVIEW_THRESHOLD_HOURS = 24
_MAX_STALE_ROWS_RETURNED = 10  # cap payload size — UI links to full list


def _query_stale_review(conn) -> dict[str, Any]:
    """List investigations stuck in ``awaiting_review`` past the
    staleness threshold. Returns the count + up to N row summaries
    so the admin UI can render a "needs attention" widget without
    a second fetch.

    Threshold defaults to 24 hours. Override via env var. Rows are
    ordered oldest-first so the worst-stale appears at the top.
    """
    import os
    try:
        threshold_hours = int(
            os.environ.get(
                "RECUPERO_STALE_REVIEW_THRESHOLD_HOURS",
                str(_DEFAULT_STALE_REVIEW_THRESHOLD_HOURS),
            )
        )
    except ValueError:
        threshold_hours = _DEFAULT_STALE_REVIEW_THRESHOLD_HOURS
    out = _empty_stale_review()
    out["threshold_hours"] = threshold_hours
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT i.id, i.case_id, i.chain, i.seed_address,
                       i.label, i.review_required_at,
                       c.case_number, c.client_name,
                       EXTRACT(EPOCH FROM (NOW() - i.review_required_at))
                           / 3600.0 AS hours_stale
                  FROM public.investigations i
                  LEFT JOIN public.cases c ON c.id = i.case_id
                 WHERE i.status = 'awaiting_review'
                   AND i.review_required_at IS NOT NULL
                   AND i.review_required_at
                       < NOW() - make_interval(hours => %(threshold)s)
                 ORDER BY i.review_required_at ASC
                 LIMIT %(limit)s
                """,
                {"threshold": threshold_hours,
                 "limit": _MAX_STALE_ROWS_RETURNED + 1},
            )
            rows = cur.fetchall()
            # Get the true count separately so the UI knows if there
            # are more than _MAX_STALE_ROWS_RETURNED (display "+3 more").
            cur.execute(
                """
                SELECT COUNT(*) AS n
                  FROM public.investigations
                 WHERE status = 'awaiting_review'
                   AND review_required_at IS NOT NULL
                   AND review_required_at
                       < NOW() - make_interval(hours => %(threshold)s)
                """,
                {"threshold": threshold_hours},
            )
            total_row = cur.fetchone()
            out["count"] = int(total_row["n"]) if total_row else 0
            # Truncate rows array to the display cap.
            out["rows"] = [
                {
                    "investigation_id": str(r["id"]),
                    "case_id": str(r["case_id"]) if r["case_id"] else None,
                    "case_number": r["case_number"],
                    "client_name": r["client_name"],
                    "chain": r["chain"],
                    "seed_address": r["seed_address"],
                    "label": r.get("label"),
                    "review_required_at": (
                        r["review_required_at"].isoformat()
                        if r["review_required_at"] else None
                    ),
                    "hours_stale": round(float(r["hours_stale"]), 1),
                }
                for r in rows[:_MAX_STALE_ROWS_RETURNED]
            ]
    except Exception as exc:  # noqa: BLE001
        log.warning("stale_review summary: %s", exc)
    return out


# ----- Stale engagements query ----- #
#
# The Tier-2 engagement model (migration 006) commits the service to
# 30 days of follow-ups + monitoring. Beyond that window an
# engagement is either renewed or wrapped via
# ``recupero-ops mark-closed``. The follow-up cron correctly skips
# expired-but-unmarked engagements (its WHERE clause excludes them),
# but nothing else surfaces them — they just sit in the DB looking
# like active engagements until the operator notices. This widget
# closes that gap: any investigation with
# ``engagement_started_at + threshold < NOW() AND
#   engagement_closed_at IS NULL``
# shows up here so the operator sees it on the dashboard homepage
# and can run mark-closed.

_DEFAULT_STALE_ENGAGEMENT_THRESHOLD_DAYS = 30
_MAX_STALE_ENGAGEMENT_ROWS_RETURNED = 10  # cap payload size — UI links to full list


def _query_stale_engagements(conn) -> dict[str, Any]:
    """List investigations whose engagement has aged past the
    threshold (default 30 days) without being marked closed. Returns
    the count + up to N row summaries so the admin UI can render a
    "needs closing" widget without a second fetch.

    Defensive against the engagement_* columns not existing yet —
    catches UndefinedColumn and returns the empty shape so this
    works on deployments where migration 006 hasn't been applied.

    Rows are ordered oldest-first so the most-overdue engagement
    appears at the top.
    """
    import os
    try:
        threshold_days = int(
            os.environ.get(
                "RECUPERO_STALE_ENGAGEMENT_THRESHOLD_DAYS",
                str(_DEFAULT_STALE_ENGAGEMENT_THRESHOLD_DAYS),
            )
        )
    except ValueError:
        threshold_days = _DEFAULT_STALE_ENGAGEMENT_THRESHOLD_DAYS
    out = _empty_stale_engagements()
    out["threshold_days"] = threshold_days
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT i.id, i.case_id, i.chain, i.seed_address,
                       i.engagement_started_at, i.last_followup_sent_at,
                       c.case_number, c.client_name,
                       EXTRACT(EPOCH FROM (NOW() - i.engagement_started_at))
                           / 86400.0 AS days_since_start
                  FROM public.investigations i
                  LEFT JOIN public.cases c ON c.id = i.case_id
                 WHERE i.engagement_started_at IS NOT NULL
                   AND i.engagement_closed_at IS NULL
                   AND i.engagement_started_at
                       < NOW() - make_interval(days => %(threshold)s)
                 ORDER BY i.engagement_started_at ASC
                 LIMIT %(limit)s
                """,
                {"threshold": threshold_days,
                 "limit": _MAX_STALE_ENGAGEMENT_ROWS_RETURNED + 1},
            )
            rows = cur.fetchall()
            # Get the true count separately so the UI can show
            # "+N more" if rows are truncated.
            cur.execute(
                """
                SELECT COUNT(*) AS n
                  FROM public.investigations
                 WHERE engagement_started_at IS NOT NULL
                   AND engagement_closed_at IS NULL
                   AND engagement_started_at
                       < NOW() - make_interval(days => %(threshold)s)
                """,
                {"threshold": threshold_days},
            )
            total_row = cur.fetchone()
            out["count"] = int(total_row["n"]) if total_row else 0
            out["rows"] = [
                {
                    "investigation_id": str(r["id"]),
                    "case_id": str(r["case_id"]) if r["case_id"] else None,
                    "case_number": r["case_number"],
                    "client_name": r["client_name"],
                    "chain": r["chain"],
                    "seed_address": r["seed_address"],
                    "engagement_started_at": (
                        r["engagement_started_at"].isoformat()
                        if r["engagement_started_at"] else None
                    ),
                    "last_followup_sent_at": (
                        r["last_followup_sent_at"].isoformat()
                        if r["last_followup_sent_at"] else None
                    ),
                    "days_since_start": int(float(r["days_since_start"])),
                    "days_overdue": max(
                        0, int(float(r["days_since_start"])) - threshold_days
                    ),
                }
                for r in rows[:_MAX_STALE_ENGAGEMENT_ROWS_RETURNED]
            ]
    except psycopg.errors.UndefinedColumn:
        # Migration 006 not applied yet — return empty shape so the
        # response is still well-formed on older deployments.
        log.info("stale_engagements summary: engagement_* columns not present")
    except Exception as exc:  # noqa: BLE001
        log.warning("stale_engagements summary: %s", exc)
    return out


# ----- Payments query (Stripe webhook audit) ----- #
#
# Operator visibility on payment-event flow. Surfaces 24h + 7d
# counts + totals so the homepage can answer "did money move
# yesterday?" without a CLI roundtrip. The list-payments CLI
# command covers the per-row drilldown; this widget is the
# aggregated overview.


def _empty_payments() -> dict[str, Any]:
    """Default shape for the payments section. Comes back zero-
    filled on DBs without the public.payments table (pre-v0.6.0
    deployments) so the response always parses cleanly.

    Schema is locked by the UI; adding a key is intentional, removing
    one is a breaking change."""
    return {
        # Last 24h rollup
        "count_24h": 0,
        "paid_count_24h": 0,
        "amount_paid_cents_24h": 0,
        "refunded_count_24h": 0,
        "disputed_count_24h": 0,
        # Last 7d rollup
        "count_7d": 0,
        "paid_count_7d": 0,
        "amount_paid_cents_7d": 0,
        # Pending operator triage — payments with status='paid'
        # AND a notes column flagged for triage (the dispatcher
        # writes 'audit_only' notes when metadata is missing or
        # malformed; these are the rows that need operator action).
        "needs_triage_count": 0,
        # Recent refunds + disputes that need operator attention.
        # Surface the actual row IDs so the UI can deep-link to
        # `list-payments --case-id <uuid>` or the Stripe Dashboard.
        # Limited to 5 most-recent per category — the rollup
        # counts above carry the totals.
        "recent_refunds": [],
        "recent_disputes": [],
    }


def _query_payments(conn) -> dict[str, Any]:
    """Aggregated payment counters from public.payments.

    Resilient to the table not existing (UndefinedTable) — pre-
    v0.6.0 deployments and freshly-cloned dev DBs return the
    empty shape rather than erroring.
    """
    out = _empty_payments()
    try:
        with conn.cursor() as cur:
            # 24h + 7d rollups in one query for efficiency. Stripe
            # webhook traffic is low enough that no index is strictly
            # required, but payments_received_at_idx (DESC) makes
            # the COUNT predicates index-only.
            cur.execute(
                """
                SELECT
                  COUNT(*) FILTER (
                    WHERE received_at > NOW() - INTERVAL '24 hours'
                  ) AS count_24h,
                  COUNT(*) FILTER (
                    WHERE received_at > NOW() - INTERVAL '24 hours'
                      AND status = 'paid'
                  ) AS paid_count_24h,
                  COALESCE(SUM(amount_cents) FILTER (
                    WHERE received_at > NOW() - INTERVAL '24 hours'
                      AND status = 'paid'
                  ), 0) AS amount_paid_cents_24h,
                  COUNT(*) FILTER (
                    WHERE received_at > NOW() - INTERVAL '24 hours'
                      AND status = 'refunded'
                  ) AS refunded_count_24h,
                  COUNT(*) FILTER (
                    WHERE received_at > NOW() - INTERVAL '24 hours'
                      AND status = 'disputed'
                  ) AS disputed_count_24h,
                  COUNT(*) FILTER (
                    WHERE received_at > NOW() - INTERVAL '7 days'
                  ) AS count_7d,
                  COUNT(*) FILTER (
                    WHERE received_at > NOW() - INTERVAL '7 days'
                      AND status = 'paid'
                  ) AS paid_count_7d,
                  COALESCE(SUM(amount_cents) FILTER (
                    WHERE received_at > NOW() - INTERVAL '7 days'
                      AND status = 'paid'
                  ), 0) AS amount_paid_cents_7d
                  FROM public.payments
                """,
            )
            row = cur.fetchone()
            if row:
                for k in (
                    "count_24h", "paid_count_24h", "amount_paid_cents_24h",
                    "refunded_count_24h", "disputed_count_24h",
                    "count_7d", "paid_count_7d",
                    "amount_paid_cents_7d",
                ):
                    out[k] = int(row.get(k, 0) or 0)

            # Recent refunds + disputes for the homepage widget. Cap
            # at 5 per category; the rollup counts above carry the
            # totals so the UI can show "+N more" when truncated.
            for status_value, target_key in (
                ("refunded", "recent_refunds"),
                ("disputed", "recent_disputes"),
            ):
                cur.execute(
                    """
                    SELECT p.id, p.received_at, p.amount_cents,
                           p.amount_type, p.case_id, p.investigation_id,
                           p.notes, c.case_number, c.client_name
                      FROM public.payments p
                      LEFT JOIN public.cases c ON c.id = p.case_id
                     WHERE p.status = %s
                       AND p.received_at > NOW() - INTERVAL '30 days'
                     ORDER BY p.received_at DESC
                     LIMIT 5
                    """,
                    (status_value,),
                )
                out[target_key] = [
                    {
                        "payment_id": str(r["id"]),
                        "received_at": (
                            r["received_at"].isoformat()
                            if r["received_at"] else None
                        ),
                        "amount_cents": int(r["amount_cents"] or 0),
                        "amount_type": r.get("amount_type"),
                        "case_id": (
                            str(r["case_id"]) if r["case_id"] else None
                        ),
                        "case_number": r.get("case_number"),
                        "client_name": r.get("client_name"),
                        "investigation_id": (
                            str(r["investigation_id"])
                            if r["investigation_id"] else None
                        ),
                        "notes": r.get("notes"),
                    }
                    for r in cur.fetchall()
                ]

            # Triage queue: paid events where the dispatcher wrote
            # an audit_only outcome (typically due to missing
            # metadata.case_id or unknown amount_type). Operators
            # need to manually link these to the right workflow row.
            cur.execute(
                """
                SELECT COUNT(*) AS n
                  FROM public.payments
                 WHERE status = 'paid'
                   AND processed_at IS NOT NULL
                   AND notes IS NOT NULL
                   AND (
                     notes ILIKE '%audit_only%' OR
                     notes ILIKE '%operator triage%' OR
                     notes ILIKE '%missing%case_id%' OR
                     notes ILIKE '%missing%investigation_id%' OR
                     notes ILIKE '%seed_address%'
                   )
                """,
            )
            triage_row = cur.fetchone()
            if triage_row:
                out["needs_triage_count"] = int(triage_row.get("n", 0) or 0)
    except psycopg.errors.UndefinedTable:
        # public.payments doesn't exist yet (pre-v0.6.0 deployment
        # or freshly-cloned dev DB). Return the empty shape.
        log.info("payments summary: public.payments not present")
    except Exception as exc:  # noqa: BLE001
        log.warning("payments summary: %s", exc)
    return out


# ----- DSN pooler rewrite ----- #
#
# v0.19.0: single source moved to recupero._common.pooled_dsn (pre-v0.19.0
# this was duplicated verbatim in 4 worker modules).
from recupero._common import pooled_dsn as _pooled_dsn  # noqa: E402


__all__ = ("build_dashboard_summary",)
