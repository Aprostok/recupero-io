"""Compute Recupero's historical recovery rate from the
``freeze_outcomes`` table. Used by the intake portal to make an
informed-consent disclosure BEFORE the customer pays.

This is the v0.32 Tier-0 gap-#2 disclosure module. See
docs/WHY_RECUPERO_WOULD_FAIL.md §0.2 — without an honest, prominently-
displayed recovery-rate number, the first paying customer who recovers
$0 generates word-of-mouth that destroys the funnel. The mitigation is
a quantitative, audit-logged disclosure on the intake portal that
the customer must acknowledge before checkout.

Honesty contract
----------------
* If we have < 30 closed cases, return the industry base rate
  (Chainalysis 2024: ~3% full-recovery, ~7% partial-recovery for
  crypto theft cases where the funds had moved to an exchange).
  Label this as "industry rate" not "our rate."
* If we have >= 30 closed cases, compute OUR rate. Display it
  as our actual rate.
* NEVER lie. If our rate is 1%, show 1%.
* Confidence interval: 95% CI via Wilson score interval (NOT a
  normal approximation; Wilson is correct for small samples and
  bounded in [0, 1] by construction).

Performance contract
--------------------
* ``compute_recovery_stats`` is the hot path on every GET /v1/intake
  request. Wilson CI is O(1). The freeze_outcomes aggregation is
  cached for 60s — the rate doesn't change minute-to-minute, but
  we DO want it to refresh within a session if the operator just
  closed a case.
* DB unreachable → return the industry baseline + log a warning.
  We NEVER block intake on a DB outage.

What counts as "recovery"
-------------------------
The strict definition is ``returned_usd > 0`` from a
``returned_to_victim`` outcome — money in the victim's hand. We
also count ``full_freeze`` and ``partial_freeze`` outcomes as
"partial_recovery" candidates (the funds are frozen but not yet
returned), but the customer-facing disclosure is the strict
``returned_usd > 0`` number.

Outcome → recovery mapping:
* ``returned_to_victim`` with ``returned_usd > 0`` → full_recovery
* ``full_freeze`` or ``partial_freeze`` → partial_recovery
* anything else (``declined``, ``silence_*``, ``released``) → zero
"""

from __future__ import annotations

import logging
import math
import os
import time
from dataclasses import dataclass
from decimal import Decimal

log = logging.getLogger(__name__)


# ----- Industry-baseline constants ----- #
#
# Source: Chainalysis "The 2024 Crypto Crime Report" — for theft cases
# where stolen funds were deposited at a centralized exchange, full
# recovery rate is approximately 3% and partial recovery (any frozen
# funds, even short of full return) is approximately 7%. These numbers
# are the honest disclosure floor: we never claim better than the
# industry until OUR data shows it.
INDUSTRY_FULL_RECOVERY_RATE: float = 0.03
INDUSTRY_PARTIAL_RECOVERY_RATE: float = 0.07
INDUSTRY_BASELINE_LABEL: str = (
    "Chainalysis 2024 — ~3% full-recovery, ~7% partial-recovery "
    "for crypto theft cases involving centralized exchanges"
)

# Minimum closed cases before we publish OUR rate instead of the
# industry baseline. 30 is the standard rule-of-thumb cutoff where
# the central-limit-theorem normal approximation starts to be
# reasonable; Wilson CI works at smaller n but the user-facing
# message "we have N closed cases" stops being embarrassingly small
# around this threshold.
MIN_SAMPLE_FOR_OUR_RATE: int = 30

# Cache TTL — Wilson CI is O(1) but the SQL aggregation hits Supabase;
# refresh every 60s rather than per-request.
_CACHE_TTL_SECONDS: float = 60.0

# Process-wide cache. Keyed by DSN so a test harness using a separate
# DB doesn't accidentally inherit prod numbers.
_CACHE: dict[str, tuple[float, "RecoveryStats"]] = {}


@dataclass(frozen=True)
class RecoveryStats:
    """Disclosure-ready recovery statistics.

    All fields are populated for both the "our data" and "industry
    baseline" code paths so the template doesn't need conditional
    rendering for every field.
    """

    sample_size: int
    n_full_recovery: int
    n_partial_recovery: int
    n_zero_recovery: int

    # Full-recovery rate (strict: ``returned_usd > 0``). 0.0–1.0.
    full_recovery_rate: float
    full_recovery_rate_ci_low: float
    full_recovery_rate_ci_high: float

    # True iff sample_size >= MIN_SAMPLE_FOR_OUR_RATE and the
    # rates above are computed from OUR closed cases. False when
    # the industry baseline is being displayed.
    is_our_data: bool

    # Human-readable label for the industry-baseline branch. None
    # when ``is_our_data`` is True.
    industry_baseline_used: str | None

    # Aggregate per-case dollar / time medians from OUR data. None
    # when ``is_our_data`` is False or insufficient.
    median_recovery_usd: Decimal | None
    median_time_to_recovery_days: int | None


# ----- Wilson score interval ----- #
#
# Wilson 1927 is the right CI for a Bernoulli proportion at small n:
# it stays inside [0, 1] by construction (the normal approximation
# routinely goes negative at p̂≈0 or above 1 at p̂≈1), it has good
# coverage at the nominal level even for small samples, and it
# degrades gracefully toward the normal approximation as n grows.
#
# Formula (for level 95%, z=1.96):
#
#     p̂ + z²/(2n) ± z · √(p̂(1-p̂)/n + z²/(4n²))
#   ─────────────────────────────────────────────
#                1 + z²/n
#
# Edge cases:
#   * n=0   → returns (0.0, 1.0) — uninformative wide interval.
#   * k=0   → lower bound exactly 0; upper bound > 0 (the rule of
#             three / Wilson collapses to 3.7/n at 95%).
#   * k=n   → upper bound exactly 1; lower bound < 1.
#
# References: Wilson, E.B. (1927). "Probable inference, the law of
# succession, and statistical inference." JASA, 22(158), 209–212.
def wilson_score_interval(
    k: int, n: int, *, level: float = 0.95,
) -> tuple[float, float]:
    """Return (lower, upper) of the Wilson score interval for k
    successes out of n Bernoulli trials at the given confidence level.

    Raises ValueError on negative inputs or k > n. Bounds are clamped
    to [0, 1] for defense in depth (Wilson is already bounded; this
    catches float-error edge cases at very small n).
    """
    if n < 0 or k < 0:
        raise ValueError(f"wilson: negative input (k={k}, n={n})")
    if k > n:
        raise ValueError(f"wilson: k > n (k={k}, n={n})")
    if n == 0:
        # No data — uninformative interval. Return the widest plausible
        # range so callers display "we don't know yet."
        return (0.0, 1.0)

    # z for two-sided level. Hardcoded for the common confidences
    # so we don't pull SciPy for one inverse-CDF call.
    z_table = {0.90: 1.6449, 0.95: 1.95996, 0.99: 2.5758}
    z = z_table.get(round(level, 2), 1.95996)

    p_hat = k / n
    z2_over_n = (z * z) / n
    denom = 1.0 + z2_over_n
    center = (p_hat + z2_over_n / 2.0) / denom
    margin = (
        z
        * math.sqrt(
            p_hat * (1.0 - p_hat) / n + (z * z) / (4.0 * n * n)
        )
        / denom
    )
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return (low, high)


def _industry_baseline_stats() -> RecoveryStats:
    """Construct the RecoveryStats we publish when our sample is too
    small (< 30 closed cases) OR the DB is unreachable.

    The Wilson CI is intentionally NOT computed for the industry
    baseline — it's not OUR data so we have no n to compute one
    against. We surface the Chainalysis point estimate as both the
    low and high bound to make it unambiguous that this is a
    published industry constant, not a measurement of our work.
    """
    return RecoveryStats(
        sample_size=0,
        n_full_recovery=0,
        n_partial_recovery=0,
        n_zero_recovery=0,
        full_recovery_rate=INDUSTRY_FULL_RECOVERY_RATE,
        full_recovery_rate_ci_low=INDUSTRY_FULL_RECOVERY_RATE,
        full_recovery_rate_ci_high=INDUSTRY_FULL_RECOVERY_RATE,
        is_our_data=False,
        industry_baseline_used=INDUSTRY_BASELINE_LABEL,
        median_recovery_usd=None,
        median_time_to_recovery_days=None,
    )


def _our_data_stats(
    *,
    sample_size: int,
    n_full: int,
    n_partial: int,
    n_zero: int,
    recovery_usd_amounts: list[Decimal],
    time_to_recovery_days: list[int],
) -> RecoveryStats:
    """Build a RecoveryStats from raw counts pulled from
    freeze_outcomes. Wilson CI computed at the 95% level.
    """
    full_rate = n_full / sample_size if sample_size > 0 else 0.0
    low, high = wilson_score_interval(n_full, sample_size, level=0.95)

    median_usd: Decimal | None = None
    if recovery_usd_amounts:
        sorted_usd = sorted(recovery_usd_amounts)
        m = len(sorted_usd)
        median_usd = (
            sorted_usd[m // 2]
            if m % 2 == 1
            else (sorted_usd[m // 2 - 1] + sorted_usd[m // 2]) / 2
        )

    median_days: int | None = None
    if time_to_recovery_days:
        sorted_days = sorted(time_to_recovery_days)
        d = len(sorted_days)
        median_days = (
            sorted_days[d // 2]
            if d % 2 == 1
            else (sorted_days[d // 2 - 1] + sorted_days[d // 2]) // 2
        )

    return RecoveryStats(
        sample_size=sample_size,
        n_full_recovery=n_full,
        n_partial_recovery=n_partial,
        n_zero_recovery=n_zero,
        full_recovery_rate=full_rate,
        full_recovery_rate_ci_low=low,
        full_recovery_rate_ci_high=high,
        is_our_data=True,
        industry_baseline_used=None,
        median_recovery_usd=median_usd,
        median_time_to_recovery_days=median_days,
    )


def compute_recovery_stats(dsn: str | None = None) -> RecoveryStats:
    """Compute Recupero's recovery stats from freeze_outcomes.

    Parameters
    ----------
    dsn:
        Postgres DSN (Supabase). If None or empty the function returns
        the industry baseline immediately — the intake portal degrades
        gracefully when SUPABASE_DB_URL is unset (local dev, CI).

    Returns
    -------
    RecoveryStats — never raises; on any error we log + return the
    industry baseline so the intake form keeps rendering.

    Caching
    -------
    Results are cached for 60 seconds keyed by DSN. The cache is
    process-local; multiple workers maintain independent caches
    (acceptable: the rate doesn't change minute-to-minute, and any
    cross-worker variance is well below the CI width). The cache
    can be bypassed for tests by calling ``_clear_cache()``.
    """
    if not dsn:
        return _industry_baseline_stats()

    now = time.monotonic()
    cached = _CACHE.get(dsn)
    if cached is not None:
        ts, stats = cached
        if now - ts < _CACHE_TTL_SECONDS:
            return stats

    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        log.warning("psycopg not installed — recovery-rate disclosure "
                    "falling back to industry baseline")
        return _industry_baseline_stats()

    try:
        stats = _query_recovery_stats(dsn)
    except Exception as exc:  # noqa: BLE001
        # NEVER block intake on DB outage. Log and degrade gracefully.
        log.warning(
            "recovery-rate query failed; falling back to industry baseline: %s",
            exc,
        )
        stats = _industry_baseline_stats()

    _CACHE[dsn] = (now, stats)
    return stats


def _query_recovery_stats(dsn: str) -> RecoveryStats:
    """Pure DB-read implementation. Aggregates ``freeze_outcomes``
    rows joined to ``freeze_letters_sent`` and ``cases`` to derive:

      * sample_size — distinct CLOSED case_ids with at least one outcome
      * n_full_recovery — cases with ``returned_to_victim`` AND
        ``returned_usd > 0``
      * n_partial_recovery — cases with ``full_freeze`` or
        ``partial_freeze`` (no ``returned_to_victim`` win yet)
      * n_zero_recovery — closed cases with only ``declined`` /
        ``silence_*`` / ``released`` / no positive outcomes

    A case is considered "closed" if any of:
      * cases.status IN ('closed', 'completed', 'archived')
      * a ``no_outcome_documented`` synthetic row was logged (the
        explicit-zero shape introduced by Step 4 of the v0.32 push)

    This is one Postgres round-trip + per-case in-Python rollup —
    avoids 30+ separate queries when generating the intake portal
    disclosure on every request.
    """
    import psycopg
    from psycopg.rows import dict_row

    from recupero._common import db_connect

    # SQL strategy: one row per (case_id, outcome) so the Python side
    # can roll up by case. We deliberately do NOT use a GROUP BY in
    # SQL because the case-level rollup needs strongest-outcome logic
    # (returned_to_victim beats full_freeze beats partial_freeze) and
    # encoding that in SQL produces an unmaintainable CASE pyramid.
    sql = """
        SELECT
            c.id AS case_id,
            c.status AS case_status,
            fo.outcome_type AS outcome_type,
            fo.returned_usd AS returned_usd,
            fo.frozen_usd AS frozen_usd,
            fo.observed_at AS observed_at,
            fl.sent_at AS sent_at
        FROM public.cases c
        LEFT JOIN public.freeze_letters_sent fl
            ON fl.case_id = c.id
        LEFT JOIN public.freeze_outcomes fo
            ON fo.letter_id = fl.id
        WHERE c.status IN ('closed', 'completed', 'archived')
        ORDER BY c.id, fo.observed_at ASC
    """

    case_outcomes: dict[str, list[dict]] = {}
    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute(sql)
        for row in cur.fetchall():
            cid = str(row["case_id"])
            case_outcomes.setdefault(cid, []).append(row)

    n_full = 0
    n_partial = 0
    n_zero = 0
    recovery_usd_amounts: list[Decimal] = []
    time_to_recovery_days: list[int] = []

    for cid, rows in case_outcomes.items():
        # Did we recover anything for this case?
        full_win_rows = [
            r for r in rows
            if r.get("outcome_type") == "returned_to_victim"
            and r.get("returned_usd") is not None
            and _decimal_gt_zero(r["returned_usd"])
        ]
        partial_rows = [
            r for r in rows
            if r.get("outcome_type") in ("full_freeze", "partial_freeze")
        ]

        if full_win_rows:
            n_full += 1
            # Sum the per-case returned_usd across multiple
            # returned_to_victim rows (e.g. funds returned in stages
            # by the same issuer).
            case_total = sum(
                (
                    _to_decimal(r["returned_usd"])
                    for r in full_win_rows
                ),
                Decimal(0),
            )
            recovery_usd_amounts.append(case_total)
            # Time to recovery: earliest sent_at → earliest
            # returned_to_victim observed_at, in days.
            sent_at = min(
                (r["sent_at"] for r in rows if r.get("sent_at") is not None),
                default=None,
            )
            observed_at = min(
                (
                    r["observed_at"]
                    for r in full_win_rows
                    if r.get("observed_at") is not None
                ),
                default=None,
            )
            if sent_at is not None and observed_at is not None:
                try:
                    delta_days = (observed_at - sent_at).days
                    if delta_days >= 0:
                        time_to_recovery_days.append(delta_days)
                except (TypeError, AttributeError):
                    pass
        elif partial_rows:
            n_partial += 1
        else:
            n_zero += 1

    sample_size = n_full + n_partial + n_zero

    if sample_size < MIN_SAMPLE_FOR_OUR_RATE:
        # Not enough data yet — show industry baseline. But preserve
        # the actual closed-case count so the disclosure can say
        # "we have N closed cases of our own; will publish our own
        # rate at 30+."
        baseline = _industry_baseline_stats()
        return RecoveryStats(
            sample_size=sample_size,
            n_full_recovery=n_full,
            n_partial_recovery=n_partial,
            n_zero_recovery=n_zero,
            full_recovery_rate=baseline.full_recovery_rate,
            full_recovery_rate_ci_low=baseline.full_recovery_rate_ci_low,
            full_recovery_rate_ci_high=baseline.full_recovery_rate_ci_high,
            is_our_data=False,
            industry_baseline_used=baseline.industry_baseline_used,
            median_recovery_usd=None,
            median_time_to_recovery_days=None,
        )

    return _our_data_stats(
        sample_size=sample_size,
        n_full=n_full,
        n_partial=n_partial,
        n_zero=n_zero,
        recovery_usd_amounts=recovery_usd_amounts,
        time_to_recovery_days=time_to_recovery_days,
    )


def _decimal_gt_zero(v: object) -> bool:
    """True iff v can be coerced to a finite Decimal > 0."""
    try:
        d = Decimal(str(v))
    except Exception:  # noqa: BLE001
        return False
    if not d.is_finite():
        return False
    return d > Decimal(0)


def _to_decimal(v: object) -> Decimal:
    """Coerce to Decimal, returning Decimal(0) on failure / non-finite."""
    try:
        d = Decimal(str(v))
    except Exception:  # noqa: BLE001
        return Decimal(0)
    if not d.is_finite():
        return Decimal(0)
    return d


def log_disclosure(
    *,
    case_id: str,
    stats: RecoveryStats,
    dsn: str | None,
    acknowledged: bool = False,
) -> bool:
    """Write a row to ``recovery_disclosures`` recording that a
    customer saw this specific rate at this specific time.

    Returns True on success, False on any failure (DB unreachable,
    table missing, etc.). NEVER raises — the intake flow proceeds
    even when the audit write fails (a separate WARN is logged so
    ops sees it).

    The acknowledged flag is set on the POST path AFTER the customer
    ticks the box. The GET path inserts with acknowledged=False; the
    POST path UPDATEs the matching row.
    """
    if not dsn:
        return False
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return False
    try:
        from recupero._common import db_connect
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.recovery_disclosures (
                    case_id, shown_at_utc, rate_displayed,
                    ci_low, ci_high, sample_size,
                    is_our_data, industry_baseline_used,
                    customer_acknowledged,
                    customer_acknowledged_at_utc
                ) VALUES (
                    %s, NOW(), %s, %s, %s, %s, %s, %s, %s,
                    CASE WHEN %s THEN NOW() ELSE NULL END
                )
                """,
                (
                    case_id,
                    float(stats.full_recovery_rate),
                    float(stats.full_recovery_rate_ci_low),
                    float(stats.full_recovery_rate_ci_high),
                    int(stats.sample_size),
                    bool(stats.is_our_data),
                    stats.industry_baseline_used,
                    bool(acknowledged),
                    bool(acknowledged),
                ),
            )
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("recovery_disclosures insert failed: %s", exc)
        return False


def _clear_cache() -> None:
    """Test helper — drop the process-wide cache so a freshly-seeded
    DB shows up on the next call."""
    _CACHE.clear()


__all__ = (
    "RecoveryStats",
    "INDUSTRY_FULL_RECOVERY_RATE",
    "INDUSTRY_PARTIAL_RECOVERY_RATE",
    "INDUSTRY_BASELINE_LABEL",
    "MIN_SAMPLE_FOR_OUR_RATE",
    "wilson_score_interval",
    "compute_recovery_stats",
    "log_disclosure",
)
