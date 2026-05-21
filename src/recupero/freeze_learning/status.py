"""Live filing status — what's the current state of every freeze
letter for a case? (v0.21.0).

The LE handoff's pre-v0.21.0 "Section 5: Requests / Asks" was a
snapshot of intent: "we plan to ask Tether, Circle, Coinbase to
freeze these wallets." It said nothing about whether the requests
had actually gone out, been acknowledged, or resulted in a freeze
— even though that data was already in ``freeze_letters_sent`` +
``freeze_outcomes`` from v0.14.x onward.

This module bridges that gap. ``fetch_live_filing_status(case_id,
dsn)`` joins both tables and returns a single ``LiveFilingStatus``
dataclass that the LE handoff template renders as Section 5.5
"Live Filing Status":

  Tether     ✅ CONFIRMED FROZEN $1.2M as of 2026-05-15
  Circle     ⏳ ACKNOWLEDGED 14h ago
  Coinbase   ⚠️ NO RESPONSE for 5 days — recommend grand jury subpoena

The dataclass also carries an aggregate roll-up ("$X of $Y stolen
confirmed frozen") and a monitoring snapshot ("Active monitoring on
N wallets; M alerts fired") so the LE filing reads as a current
operational artifact, not a static document.

On the first render (immediately after emit_brief, before any
freeze letters have been mailed) the dataclass is empty-shape and
the template renders the "Pending issuer outreach" branch.

Failure mode: every DB op is wrapped — a Supabase outage causes
``fetch_live_filing_status`` to return an empty status (which the
template renders as the pending-state branch), so the LE handoff
generation never breaks because of a monitoring-side outage.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

log = logging.getLogger(__name__)


# Mapping from freeze_outcomes.outcome_type to the badge string the
# LE template renders. Order matters: when multiple outcomes have
# been recorded for one letter (acknowledged → partial_freeze →
# full_freeze), the LATEST one wins per the
# `observed_at DESC LIMIT 1` query, and the badge reflects the
# current state.
_OUTCOME_TO_BADGE: dict[str, str] = {
    "acknowledged":         "ACKNOWLEDGED",
    "request_more_info":    "INFO REQUESTED",
    "declined":             "DECLINED",
    "partial_freeze":       "PARTIAL FREEZE",
    "full_freeze":          "FROZEN",
    "released":             "RELEASED (FUNDS GONE)",
    "returned_to_victim":   "RETURNED",
    "silence_14d":          "NO RESPONSE (14d)",
    "silence_30d":          "NO RESPONSE (30d)",
    "silence_90d":          "NO RESPONSE (90d)",
}

# Outcomes that count as a positive "frozen / returned" for the
# aggregate roll-up. Used to compute the percent-frozen figure.
_POSITIVE_OUTCOMES = frozenset([
    "partial_freeze",
    "full_freeze",
    "returned_to_victim",
])


@dataclass
class LetterStatus:
    """One row in the LE handoff Section 5.5 letters table."""
    letter_id: UUID
    issuer: str
    target_address: str
    chain: str
    asset_symbol: str
    requested_freeze_usd: Decimal
    requested_freeze_usd_human: str
    sent_at: datetime
    sent_at_human: str
    days_since_sent: int
    status_badge: str           # PENDING / ACKNOWLEDGED / FROZEN / DECLINED / NO RESPONSE
    outcome_type: str | None    # raw outcome_type or None if no outcome yet
    frozen_usd: Decimal | None
    frozen_usd_human: str
    last_followup_sent_at: datetime | None
    followup_stage: str
    # v0.21.1 (audit-fix A2 HIGH): peak frozen USD across all positive
    # outcomes for this letter. Used by the aggregate roll-up so a later
    # request_more_info / acknowledged row doesn't zero out a confirmed
    # partial_freeze. frozen_usd is the LATEST row's value (may be NULL
    # when the latest is a non-financial outcome); peak_frozen_usd is the
    # MAX across rows whose outcome_type is in _POSITIVE_OUTCOMES.
    peak_frozen_usd: Decimal | None = None


@dataclass
class AggregateStatus:
    """Roll-up across all letters for the case."""
    total_letters: int = 0
    letters_with_response: int = 0
    letters_silent: int = 0
    total_requested_usd: Decimal = field(default_factory=lambda: Decimal(0))
    total_confirmed_frozen_usd: Decimal = field(default_factory=lambda: Decimal(0))
    total_requested_usd_human: str = "$0"
    total_confirmed_frozen_usd_human: str = "$0"
    freeze_percentage: int = 0    # 0..100, computed from totals


@dataclass
class MonitoringSnapshot:
    """Counters for the LE handoff monitoring block."""
    active_subscriptions: int = 0
    alerts_fired_since_brief: int = 0
    last_alert_at: datetime | None = None


@dataclass
class LiveFilingStatus:
    """Composite returned by fetch_live_filing_status."""
    letters: list[LetterStatus] = field(default_factory=list)
    aggregate: AggregateStatus = field(default_factory=AggregateStatus)
    monitoring: MonitoringSnapshot = field(default_factory=MonitoringSnapshot)
    # True when there are no letters yet — the template renders the
    # "Pending issuer outreach — re-render after send-freeze-letters"
    # empty-state branch.
    is_empty: bool = True


def _fmt_usd(value: Decimal | float | int | None) -> str:
    """Format a Decimal amount as $X,XXX.XX. NULL → '—' (em dash)."""
    if value is None:
        return "—"
    try:
        d = Decimal(str(value))
    except Exception:  # noqa: BLE001
        return "—"
    if d == d.to_integral_value():
        return f"${int(d):,}"
    return f"${d:,.2f}"


def _badge_for_letter(
    outcome_type: str | None,
    days_since_sent: int,
    followup_stage: str,
) -> str:
    """Compute the per-letter status badge.

    Priority:
      1. If we have a freeze_outcomes row, map the outcome_type via
         _OUTCOME_TO_BADGE.
      2. Else if the cron has progressed past silence_14d, badge
         reflects the longest silence we've observed.
      3. Else: PENDING / NO RESPONSE based on days_since_sent.
    """
    if outcome_type:
        return _OUTCOME_TO_BADGE.get(outcome_type, "RESPONSE")
    if followup_stage == "silence_14d":
        return "NO RESPONSE (14d)"
    if days_since_sent >= 14:
        return "NO RESPONSE"
    if days_since_sent >= 7:
        return "ESCALATING"
    if days_since_sent >= 3:
        return "NUDGED"
    return "PENDING"


def fetch_live_filing_status(
    case_id: UUID | str | None = None,
    *,
    dsn: str | None,
    investigation_id: UUID | str | None = None,
) -> LiveFilingStatus:
    """Join freeze_letters_sent + freeze_outcomes (latest per letter)
    + monitoring_subscriptions + monitoring_alerts.

    v0.21.1 (audit-fix A1 CRITICAL): pre-v0.21.1 this function filtered
    only by ``case_id``, but the worker pipeline path passes
    ``case.case_id`` which is a string brief identifier (e.g.
    ``"V-CFI01-BRIEF-2026-04-19"``), NOT the ``cases.id`` UUID that
    ``freeze_letters_sent.case_id`` references as an FK. The query
    matched zero rows in production; Section 5.5 silently rendered the
    "Pending issuer outreach" branch even after letters were sent and
    outcomes recorded.

    Fix: filter by ``investigation_id`` when provided (always the case
    in the worker pipeline path — see _deliverables.py) and FALL BACK
    to ``case_id`` for callers that have the cases.id UUID in hand
    (e.g. operator CLI tooling that joined to cases first). Filtering
    on either column is OK: the (investigation_id, case_id) tuple on
    freeze_letters_sent is co-determined per the migration 016
    partial-UNIQUE constraint.

    Returns an empty-shape ``LiveFilingStatus`` (``is_empty=True``)
    when:
      * No DSN configured (local CLI emit_brief path) — template
        renders the pending branch.
      * DSN configured but no letters yet — same template branch.
      * No filter key provided — same.
      * DB error during the join — logged at WARN, template renders
        the pending branch (graceful degradation, never breaks the
        deliverable).
    """
    if not dsn:
        return LiveFilingStatus()
    if not investigation_id and not case_id:
        # Misuse: caller didn't supply any key. Don't risk a full-table
        # SELECT — return empty.
        log.warning(
            "fetch_live_filing_status called without case_id or "
            "investigation_id — returning empty status"
        )
        return LiveFilingStatus()

    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return LiveFilingStatus()

    from recupero._common import db_connect

    # v0.21.1: prefer investigation_id (always available on the
    # worker pipeline path) and fall back to case_id (operator CLI
    # tooling that has the cases.id UUID).
    if investigation_id:
        letter_filter_clause = "WHERE fl.investigation_id = %s"
        letter_filter_value = str(investigation_id)
    else:
        letter_filter_clause = "WHERE fl.case_id = %s"
        letter_filter_value = str(case_id)

    # The latest outcome per letter via LATERAL — preserves the
    # "multiple outcomes per letter" time series while giving the
    # template the current state for the badge.
    letters_sql = f"""
        SELECT fl.id                       AS letter_id,
               fl.issuer                   AS issuer,
               fl.target_address           AS target_address,
               fl.chain                    AS chain,
               fl.asset_symbol             AS asset_symbol,
               fl.requested_freeze_usd     AS requested_freeze_usd,
               fl.sent_at                  AS sent_at,
               fl.last_followup_sent_at    AS last_followup_sent_at,
               fl.followup_stage           AS followup_stage,
               latest.outcome_type         AS outcome_type,
               latest.frozen_usd           AS frozen_usd,
               latest.observed_at          AS observed_at,
               -- v0.21.1 (audit-fix A2 HIGH): pull the MAX frozen_usd
               -- across all positive-outcome rows for this letter, so
               -- a partial_freeze of $500K followed by a later
               -- request_more_info (frozen_usd=NULL) doesn't zero out
               -- the aggregate.
               -- PUNISH-B F-6: COALESCE(frozen_usd, returned_usd).
               -- When a letter's progression is
               -- partial_freeze($X) → full_freeze($Y) → returned_to_victim
               -- (returned_usd=$Y, frozen_usd=NULL by operator convention),
               -- MAX(frozen_usd) over the chain returns $Y (the full_freeze
               -- step). But for a letter that went STRAIGHT to
               -- returned_to_victim with frozen_usd=NULL, MAX returned NULL
               -- and the LE handoff Section 5.5 reported "$0 confirmed
               -- frozen" for a fully-successful case. COALESCE picks the
               -- non-null money column on each row before the MAX.
               (SELECT MAX(COALESCE(fo2.frozen_usd, fo2.returned_usd))
                  FROM public.freeze_outcomes fo2
                 WHERE fo2.letter_id = fl.id
                   AND fo2.outcome_type IN
                       ('partial_freeze','full_freeze','returned_to_victim')
               )                            AS peak_frozen_usd
          FROM public.freeze_letters_sent fl
          LEFT JOIN LATERAL (
              SELECT fo.outcome_type, fo.frozen_usd, fo.observed_at
                FROM public.freeze_outcomes fo
               WHERE fo.letter_id = fl.id
               ORDER BY fo.observed_at DESC
               LIMIT 1
          ) latest ON TRUE
         {letter_filter_clause}
         ORDER BY fl.sent_at ASC
    """
    # Monitoring counters keyed by created_by — used only when caller
    # passes case_id (string brief identifier, matches the
    # 'emit_brief:<case_id>' created_by sentinel from subscriber.py).
    # When invoked with only investigation_id, the monitoring snapshot
    # stays at zeros.
    monitoring_sql = """
        SELECT
            (SELECT COUNT(*) FROM public.monitoring_subscriptions
              WHERE status = 'active'
                AND created_by = %(created_by)s) AS active_subs,
            (SELECT COUNT(*) FROM public.monitoring_alerts a
              JOIN public.monitoring_subscriptions s ON s.id = a.subscription_id
              WHERE s.created_by = %(created_by)s) AS alerts_fired,
            (SELECT MAX(a.fired_at) FROM public.monitoring_alerts a
              JOIN public.monitoring_subscriptions s ON s.id = a.subscription_id
              WHERE s.created_by = %(created_by)s) AS last_alert_at
    """

    from psycopg.rows import dict_row
    status = LiveFilingStatus()
    now = datetime.now(UTC)

    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            # Letters table
            cur.execute(letters_sql, (letter_filter_value,))
            for row in cur.fetchall():
                sent_at = row["sent_at"]
                days_since = max(0, (now - sent_at).days)
                requested = row["requested_freeze_usd"] or Decimal(0)
                if not isinstance(requested, Decimal):
                    requested = Decimal(str(requested))
                frozen = row.get("frozen_usd")
                if frozen is not None and not isinstance(frozen, Decimal):
                    frozen = Decimal(str(frozen))
                peak = row.get("peak_frozen_usd")
                if peak is not None and not isinstance(peak, Decimal):
                    peak = Decimal(str(peak))
                outcome_type = row.get("outcome_type")
                followup_stage = row.get("followup_stage") or "initial"
                # Display the PEAK frozen amount in the per-letter
                # cell so the table tells the truth even when the
                # latest outcome is non-financial (acknowledged etc.)
                display_frozen = peak if peak is not None else frozen
                status.letters.append(LetterStatus(
                    letter_id=row["letter_id"],
                    issuer=row["issuer"],
                    target_address=row["target_address"],
                    chain=row["chain"],
                    asset_symbol=row["asset_symbol"],
                    requested_freeze_usd=requested,
                    requested_freeze_usd_human=_fmt_usd(requested),
                    sent_at=sent_at,
                    sent_at_human=sent_at.strftime("%Y-%m-%d"),
                    days_since_sent=days_since,
                    status_badge=_badge_for_letter(
                        outcome_type=outcome_type,
                        days_since_sent=days_since,
                        followup_stage=followup_stage,
                    ),
                    outcome_type=outcome_type,
                    frozen_usd=display_frozen,
                    frozen_usd_human=_fmt_usd(display_frozen),
                    last_followup_sent_at=row.get("last_followup_sent_at"),
                    followup_stage=followup_stage,
                    peak_frozen_usd=peak,
                ))

            # Monitoring snapshot — the subscriber.py auto-subscribe
            # writes created_by = f"emit_brief:<case_id>", where
            # <case_id> is the string brief identifier (NOT the
            # investigations.id UUID). When the caller only supplied
            # investigation_id, the monitoring snapshot stays at
            # zeros — a future revision can resolve the case_id
            # from the investigation row.
            if case_id:
                created_by = f"emit_brief:{case_id}"
                cur.execute(monitoring_sql, {"created_by": created_by})
                mon_row = cur.fetchone()
                if mon_row:
                    status.monitoring = MonitoringSnapshot(
                        active_subscriptions=mon_row.get("active_subs") or 0,
                        alerts_fired_since_brief=mon_row.get("alerts_fired") or 0,
                        last_alert_at=mon_row.get("last_alert_at"),
                    )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "fetch_live_filing_status failed for case %s — "
            "returning empty (template falls back to pending branch): %s",
            case_id, exc,
        )
        return LiveFilingStatus()

    # Aggregate roll-up
    if status.letters:
        status.is_empty = False
        agg = status.aggregate
        agg.total_letters = len(status.letters)
        agg.letters_with_response = sum(
            1 for L in status.letters if L.outcome_type is not None
        )
        agg.letters_silent = agg.total_letters - agg.letters_with_response
        agg.total_requested_usd = sum(
            (L.requested_freeze_usd for L in status.letters),
            start=Decimal(0),
        )
        # v0.21.1 (audit-fix A2 HIGH): aggregate the PEAK frozen across
        # positive-outcome rows per letter, not the latest-row tuple.
        # A later request_more_info / acknowledged row used to zero out
        # a previously-confirmed partial_freeze.
        agg.total_confirmed_frozen_usd = sum(
            (L.peak_frozen_usd for L in status.letters
             if L.peak_frozen_usd is not None),
            start=Decimal(0),
        )
        agg.total_requested_usd_human = _fmt_usd(agg.total_requested_usd)
        agg.total_confirmed_frozen_usd_human = _fmt_usd(agg.total_confirmed_frozen_usd)
        if agg.total_requested_usd > 0:
            ratio = (agg.total_confirmed_frozen_usd / agg.total_requested_usd) * 100
            # v0.21.1 (audit-fix A4 MEDIUM): round to nearest int rather
            # than truncating, so a 99.6% freeze ratio renders as "100%"
            # not "99%". Previously systematically under-reported.
            agg.freeze_percentage = int(round(min(Decimal(100), max(Decimal(0), ratio))))

    return status


__all__ = (
    "LetterStatus",
    "AggregateStatus",
    "MonitoringSnapshot",
    "LiveFilingStatus",
    "fetch_live_filing_status",
)
