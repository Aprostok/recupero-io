"""Partner law-firm portfolio dashboard (v0.26.0).

Recovery counsel that refers clients to Recupero wants a periodic
statement showing the aggregate state of their referred caseload:

  * Volume — N cases referred, N completed traces, N in queue.
  * Money — total loss across referred cases, total $ frozen so
    far, total $ returned to victims.
  * Throughput — median time from intake → first freeze letter,
    median time from letter → first freeze response.
  * Cooperation context — top 5 issuers seen across the firm's
    cases, with cross-case cooperation profile rates pulled from
    the v0.24.0 cooperation_intelligence layer.

The dashboard is *aggregate per firm* — no per-case PII leaks into
it. The firm's own case-tracking happens in their CMS / matter
management; Recupero only shows portfolio-level rollups.

Public surface:

  * ``LawFirmPortfolio`` — dataclass holding the per-firm rollup.
  * ``build_firm_portfolio(firm_slug_or_id, dsn)`` — aggregator.
    Pure function except for the DB read.
  * ``build_all_firm_portfolios(dsn)`` — bulk for ops snapshots.

All DB ops are wrapped — Supabase outage returns an empty-shape
portfolio so the renderer never crashes mid-pdf-build.
"""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any
from uuid import UUID

log = logging.getLogger(__name__)


# Minimum referred-case count before we publish throughput medians
# (sub-3 samples make medians wobble between cases). Below this the
# dashboard hides the throughput card and shows "insufficient data."
_MIN_CASES_FOR_THROUGHPUT_MEDIANS = 3


@dataclass
class FirmIssuerSummary:
    """Per-issuer rollup within one firm's caseload."""
    issuer: str
    n_letters_sent: int = 0
    n_freezes_observed: int = 0
    total_frozen_usd: Decimal = field(default_factory=lambda: Decimal(0))
    # Pulled from cooperation_intelligence when available — None
    # when the issuer hasn't been seen enough times overall to
    # have a confident cross-firm profile.
    cross_firm_response_rate: float | None = None
    cross_firm_full_freeze_rate: float | None = None


@dataclass
class LawFirmPortfolio:
    """Aggregate per-firm view across all referred cases.

    All money figures are Decimal so the firm-facing statement is
    accountant-grade rather than IEEE-float-rounded.
    """
    firm_id: UUID | None = None
    firm_slug: str = ""
    firm_name: str = ""
    firm_status: str = "active"

    # Volume.
    n_referred_cases: int = 0
    n_completed_traces: int = 0
    n_in_queue: int = 0
    n_with_letters_sent: int = 0

    # Money.
    total_loss_usd: Decimal = field(default_factory=lambda: Decimal(0))
    total_frozen_usd: Decimal = field(default_factory=lambda: Decimal(0))
    total_returned_to_victim_usd: Decimal = field(default_factory=lambda: Decimal(0))

    # Throughput — only published when n_referred_cases is high
    # enough to make medians meaningful.
    median_hours_intake_to_first_letter: float | None = None
    median_hours_letter_to_first_freeze: float | None = None
    has_confident_throughput: bool = False

    # Top issuers seen across the firm's caseload. Sorted by
    # n_letters_sent DESC; capped to 5 in the dashboard render.
    top_issuers: list[FirmIssuerSummary] = field(default_factory=list)

    # Latest activity timestamps for the "as of" footer.
    latest_referral_at: str | None = None
    latest_letter_sent_at: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Public builders
# ─────────────────────────────────────────────────────────────────────────────


def build_firm_portfolio(
    firm_key: str,
    *,
    dsn: str | None,
) -> LawFirmPortfolio:
    """Aggregate the portfolio for one firm.

    ``firm_key`` may be either a UUID string (firm.id) or a slug
    (firm.slug). The function resolves whichever matches first.

    Returns an empty-shape portfolio when:
      * dsn is None
      * DB error — logged at WARN
      * No matching law_firms row
    """
    portfolio = LawFirmPortfolio()
    if not dsn:
        return portfolio

    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return portfolio

    from recupero._common import db_connect
    from psycopg.rows import dict_row

    try:
        with db_connect(dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                firm_row = _resolve_firm_row(cur, firm_key)
                if not firm_row:
                    log.info(
                        "build_firm_portfolio: no law_firms row "
                        "matches key=%r", firm_key,
                    )
                    return portfolio

                portfolio.firm_id = _as_uuid(firm_row["id"])
                portfolio.firm_slug = firm_row["slug"]
                portfolio.firm_name = firm_row["name"]
                portfolio.firm_status = firm_row.get("status") or "active"

                _populate_volume_and_money(cur, portfolio)
                _populate_throughput(cur, portfolio)
                _populate_top_issuers(cur, portfolio, dsn=dsn)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "build_firm_portfolio(%r) failed: %s", firm_key, exc,
        )

    return portfolio


def build_all_firm_portfolios(*, dsn: str | None) -> list[LawFirmPortfolio]:
    """Build portfolios for every active firm. Used by the nightly
    snapshot job and the ``recupero-ops law-firm-dashboard --all``
    flag."""
    if not dsn:
        return []
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return []

    from recupero._common import db_connect
    from psycopg.rows import dict_row

    portfolios: list[LawFirmPortfolio] = []
    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id::text AS id, slug
                  FROM public.law_firms
                 WHERE status = 'active'
                 ORDER BY slug ASC
                """
            )
            firm_keys = [r["slug"] for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        log.warning("build_all_firm_portfolios: list failed: %s", exc)
        return []

    for slug in firm_keys:
        portfolios.append(build_firm_portfolio(slug, dsn=dsn))
    return portfolios


# ─────────────────────────────────────────────────────────────────────────────
# Internal builder helpers
# ─────────────────────────────────────────────────────────────────────────────


def _resolve_firm_row(cur: Any, firm_key: str) -> dict[str, Any] | None:
    """Look up law_firms by UUID first (if firm_key parses as one)
    else by slug. Returns the row dict or None."""
    # Try UUID branch.
    try:
        firm_uuid = UUID(firm_key)
    except (ValueError, TypeError):
        firm_uuid = None

    if firm_uuid is not None:
        cur.execute(
            "SELECT id, slug, name, status FROM public.law_firms WHERE id = %s",
            (str(firm_uuid),),
        )
        row = cur.fetchone()
        if row:
            return row

    # Fall through to slug.
    cur.execute(
        "SELECT id, slug, name, status FROM public.law_firms WHERE slug = %s",
        (firm_key,),
    )
    return cur.fetchone()


def _populate_volume_and_money(cur: Any, portfolio: LawFirmPortfolio) -> None:
    """Volume + money rollup. Reads from case_referrals JOIN cases."""
    cur.execute(
        """
        SELECT
            COUNT(*)                                     AS n_referred,
            COUNT(*) FILTER (WHERE c.status IN
                ('completed', 'closed', 'archived'))     AS n_completed,
            COUNT(*) FILTER (WHERE c.status IN
                ('intake', 'tracing', 'pending', 'in_progress')) AS n_in_queue,
            MAX(cr.referred_at)::text                    AS latest_referral_at
          FROM public.case_referrals cr
          JOIN public.cases c ON c.id = cr.case_id
         WHERE cr.law_firm_id = %s
        """,
        (str(portfolio.firm_id),),
    )
    row = cur.fetchone()
    if row:
        portfolio.n_referred_cases = int(row["n_referred"] or 0)
        portfolio.n_completed_traces = int(row["n_completed"] or 0)
        portfolio.n_in_queue = int(row["n_in_queue"] or 0)
        portfolio.latest_referral_at = row.get("latest_referral_at")

    # Total loss across referred cases — pull from cases.total_loss_usd
    # if the column exists, else from the latest brief's TOTAL_LOSS_USD
    # via brief_synthesis (more work, deferred until v0.26.1+). For now
    # fall back to a simple SUM(cases.total_loss_usd) when present.
    try:
        cur.execute(
            """
            SELECT COALESCE(SUM(c.total_loss_usd), 0)::numeric AS sum_loss
              FROM public.case_referrals cr
              JOIN public.cases c ON c.id = cr.case_id
             WHERE cr.law_firm_id = %s
            """,
            (str(portfolio.firm_id),),
        )
        sum_row = cur.fetchone()
        if sum_row and sum_row.get("sum_loss") is not None:
            portfolio.total_loss_usd = Decimal(str(sum_row["sum_loss"]))
    except Exception as exc:  # noqa: BLE001
        log.info(
            "law_firm_dashboard: cases.total_loss_usd not present "
            "(skipping loss aggregate): %s", exc,
        )

    # Total frozen + returned across all freeze_outcomes for letters
    # tied to investigations on this firm's cases. We pick the
    # strongest outcome per letter (the v0.24.1 audit-fix CRIT-3
    # pattern) to avoid double-counting partial→full→returned
    # chains.
    cur.execute(
        """
        WITH firm_cases AS (
            SELECT case_id FROM public.case_referrals
             WHERE law_firm_id = %s
        ),
        firm_letters AS (
            SELECT fl.id AS letter_id
              FROM public.freeze_letters_sent fl
              JOIN public.investigations i ON i.id = fl.investigation_id
              JOIN firm_cases fc ON fc.case_id = i.case_id
        ),
        strongest_outcomes AS (
            SELECT fo.letter_id,
                   fo.outcome_type,
                   fo.frozen_usd,
                   ROW_NUMBER() OVER (
                       PARTITION BY fo.letter_id
                       ORDER BY
                           CASE fo.outcome_type
                               WHEN 'returned_to_victim' THEN 3
                               WHEN 'full_freeze'         THEN 2
                               WHEN 'partial_freeze'      THEN 1
                               ELSE 0
                           END DESC,
                           fo.observed_at DESC
                   ) AS rn
              FROM public.freeze_outcomes fo
              JOIN firm_letters fl ON fl.letter_id = fo.letter_id
             WHERE fo.outcome_type IN
                ('partial_freeze', 'full_freeze', 'returned_to_victim')
        )
        SELECT
            COALESCE(SUM(frozen_usd) FILTER (WHERE
                outcome_type IN ('partial_freeze', 'full_freeze',
                                 'returned_to_victim')), 0)::numeric AS frozen,
            COALESCE(SUM(frozen_usd) FILTER (WHERE
                outcome_type = 'returned_to_victim'), 0)::numeric    AS returned
          FROM strongest_outcomes
         WHERE rn = 1
        """,
        (str(portfolio.firm_id),),
    )
    row = cur.fetchone()
    if row:
        portfolio.total_frozen_usd = Decimal(str(row.get("frozen") or 0))
        portfolio.total_returned_to_victim_usd = Decimal(
            str(row.get("returned") or 0)
        )

    # n_with_letters_sent — distinct case count that has at least
    # one letter sent.
    cur.execute(
        """
        SELECT COUNT(DISTINCT cr.case_id) AS n_with_letters
          FROM public.case_referrals cr
          JOIN public.investigations i ON i.case_id = cr.case_id
          JOIN public.freeze_letters_sent fl ON fl.investigation_id = i.id
         WHERE cr.law_firm_id = %s
        """,
        (str(portfolio.firm_id),),
    )
    row = cur.fetchone()
    if row:
        portfolio.n_with_letters_sent = int(row["n_with_letters"] or 0)


def _populate_throughput(cur: Any, portfolio: LawFirmPortfolio) -> None:
    """Throughput medians. Only published when sample size is high
    enough."""
    if portfolio.n_referred_cases < _MIN_CASES_FOR_THROUGHPUT_MEDIANS:
        return

    # Intake → first letter hours. The earliest freeze_letters_sent
    # row per case, minus case.created_at.
    cur.execute(
        """
        WITH firm_cases AS (
            SELECT c.id AS case_id, c.created_at AS intake_at
              FROM public.case_referrals cr
              JOIN public.cases c ON c.id = cr.case_id
             WHERE cr.law_firm_id = %s
        ),
        first_letters AS (
            SELECT fc.case_id,
                   fc.intake_at,
                   MIN(fl.sent_at) AS first_letter_at,
                   MAX(fl.sent_at) AS latest_letter_at
              FROM firm_cases fc
              JOIN public.investigations i ON i.case_id = fc.case_id
              JOIN public.freeze_letters_sent fl ON fl.investigation_id = i.id
             GROUP BY fc.case_id, fc.intake_at
        )
        SELECT first_letter_at,
               intake_at,
               EXTRACT(EPOCH FROM (first_letter_at - intake_at)) / 3600.0
                    AS hours_intake_to_first_letter,
               MAX(latest_letter_at) OVER () AS latest_letter_overall
          FROM first_letters
         WHERE first_letter_at IS NOT NULL
        """,
        (str(portfolio.firm_id),),
    )
    rows = cur.fetchall()
    if rows:
        portfolio.latest_letter_sent_at = (
            str(rows[0]["latest_letter_overall"])
            if rows[0].get("latest_letter_overall") else None
        )
        hours_to_letter = [
            float(r["hours_intake_to_first_letter"]) for r in rows
            if r.get("hours_intake_to_first_letter") is not None
        ]
        if len(hours_to_letter) >= _MIN_CASES_FOR_THROUGHPUT_MEDIANS:
            portfolio.median_hours_intake_to_first_letter = (
                statistics.median(hours_to_letter)
            )
            portfolio.has_confident_throughput = True

    # Letter → first freeze (any outcome in
    # partial_freeze / full_freeze / returned_to_victim).
    cur.execute(
        """
        WITH firm_cases AS (
            SELECT case_id FROM public.case_referrals
             WHERE law_firm_id = %s
        ),
        firm_letters AS (
            SELECT fl.id AS letter_id, fl.sent_at
              FROM public.freeze_letters_sent fl
              JOIN public.investigations i ON i.id = fl.investigation_id
              JOIN firm_cases fc ON fc.case_id = i.case_id
        ),
        first_freezes AS (
            SELECT fl.letter_id,
                   fl.sent_at,
                   MIN(fo.observed_at) AS first_freeze_at
              FROM firm_letters fl
              JOIN public.freeze_outcomes fo ON fo.letter_id = fl.letter_id
             WHERE fo.outcome_type IN
                ('partial_freeze', 'full_freeze', 'returned_to_victim')
             GROUP BY fl.letter_id, fl.sent_at
        )
        SELECT EXTRACT(EPOCH FROM (first_freeze_at - sent_at)) / 3600.0
                    AS hours_letter_to_first_freeze
          FROM first_freezes
         WHERE first_freeze_at IS NOT NULL
        """,
        (str(portfolio.firm_id),),
    )
    rows = cur.fetchall()
    if rows:
        hours_to_freeze = [
            float(r["hours_letter_to_first_freeze"]) for r in rows
            if r.get("hours_letter_to_first_freeze") is not None
        ]
        if len(hours_to_freeze) >= _MIN_CASES_FOR_THROUGHPUT_MEDIANS:
            portfolio.median_hours_letter_to_first_freeze = (
                statistics.median(hours_to_freeze)
            )


def _populate_top_issuers(
    cur: Any,
    portfolio: LawFirmPortfolio,
    *,
    dsn: str,
) -> None:
    """Top 5 issuers across the firm's caseload, sorted by letter
    volume. Each row optionally enriched with cross-firm cooperation
    rates from cooperation_intelligence."""
    cur.execute(
        """
        WITH firm_cases AS (
            SELECT case_id FROM public.case_referrals
             WHERE law_firm_id = %s
        ),
        firm_letters AS (
            SELECT fl.id AS letter_id, fl.issuer
              FROM public.freeze_letters_sent fl
              JOIN public.investigations i ON i.id = fl.investigation_id
              JOIN firm_cases fc ON fc.case_id = i.case_id
        ),
        strongest_per_letter AS (
            SELECT fl.issuer,
                   fl.letter_id,
                   COALESCE(SUM(fo.frozen_usd) FILTER (WHERE
                       fo.outcome_type IN
                           ('partial_freeze', 'full_freeze',
                            'returned_to_victim')), 0) AS frozen
              FROM firm_letters fl
              LEFT JOIN public.freeze_outcomes fo
                     ON fo.letter_id = fl.letter_id
             GROUP BY fl.issuer, fl.letter_id
        )
        SELECT issuer,
               COUNT(*)                          AS n_letters,
               COUNT(*) FILTER (WHERE frozen > 0) AS n_freezes,
               COALESCE(SUM(frozen), 0)::numeric AS total_frozen
          FROM strongest_per_letter
         GROUP BY issuer
         ORDER BY n_letters DESC, issuer ASC
         LIMIT 5
        """,
        (str(portfolio.firm_id),),
    )
    rows = cur.fetchall()
    if not rows:
        return

    # Optionally enrich with cross-firm cooperation rates from
    # cooperation_intelligence — best-effort, the dashboard works
    # without it.
    try:
        from recupero.monitoring.cooperation_intelligence import (
            build_cooperation_profile,
        )
        enrich = True
    except Exception:  # noqa: BLE001
        enrich = False
        build_cooperation_profile = None  # type: ignore

    for r in rows:
        summary = FirmIssuerSummary(
            issuer=r["issuer"],
            n_letters_sent=int(r["n_letters"] or 0),
            n_freezes_observed=int(r["n_freezes"] or 0),
            total_frozen_usd=Decimal(str(r.get("total_frozen") or 0)),
        )
        if enrich and build_cooperation_profile is not None:
            try:
                coop = build_cooperation_profile(r["issuer"], dsn=dsn)
                if coop.has_confident_profile:
                    summary.cross_firm_response_rate = coop.response_rate
                    summary.cross_firm_full_freeze_rate = coop.full_freeze_rate
            except Exception as exc:  # noqa: BLE001
                log.info(
                    "law_firm_dashboard: cooperation enrich failed for "
                    "issuer=%s: %s", r["issuer"], exc,
                )
        portfolio.top_issuers.append(summary)


def _as_uuid(v: Any) -> UUID | None:
    """Best-effort UUID coercion — handles psycopg returning either
    UUID directly (if a UUID column) or str (most other paths)."""
    if v is None:
        return None
    if isinstance(v, UUID):
        return v
    try:
        return UUID(str(v))
    except (ValueError, TypeError):
        return None


__all__ = (
    "FirmIssuerSummary",
    "LawFirmPortfolio",
    "build_firm_portfolio",
    "build_all_firm_portfolios",
)
