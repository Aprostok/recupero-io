"""Dust-attack pattern detection (v0.31.2).

Detects perpetrators flooding many distinct addresses with sub-cent
transfers to pollute Section 5 of the brief. The intent of such an
attack is to bury the real laundering path under a forest of
innocent-looking destinations — operators eyeballing the counterparty
table see hundreds of $0.001 rows and lose signal in the noise.

Why a separate detector (vs. the existing `policy.dust_threshold_usd`)
---------------------------------------------------------------------

The amount-based dust filter in `TracePolicy.should_include` is a
*per-transfer* gate: any transfer below $X USD is dropped. That's the
right behavior for legitimate change-back patterns (refund of leftover
fee, fractional token sweep at the end of a swap), but it has two
weaknesses against a sophisticated dust SHOWER:

  1. A perpetrator can stay just under the threshold (e.g. $9.99 each
     to 50 addresses) — at $50 dust threshold that wouldn't fire, but
     50 tiny transfers from one source to 50 distinct destinations is
     unmistakably a shower pattern.
  2. Even when the threshold catches each individual transfer, the
     drained funds themselves *aren't* counted — but the destination
     ADDRESSES still land in `unlabeled_counterparties`, because the
     filter runs BEFORE counterparty aggregation. The brief renderer
     iterates `unlabeled_counterparties` to build Section 5, so the
     shower addresses pollute the table even when the transfers are
     dust-filtered out.

This module addresses both: it identifies destination *addresses* that
participate in a fan-out shower from a single source, regardless of
whether the individual transfers passed or failed `should_include`.
The returned set is intended to filter `case.unlabeled_counterparties`
AFTER the BFS completes — the transfers themselves stay in
`case.transfers` for the audit trail.

Algorithm
---------

For each source address that appears in `transfer.from_address`:

  1. Partition that source's transfers into "dust" and "non-dust" buckets
     by USD value (Decimal-strict — non-finite values are ignored, never
     treated as dust signal).
  2. Count DISTINCT destination addresses in each bucket.
  3. Fire ONLY when:
       a. distinct dust destinations >= `min_fanout` (default 10)
       b. distinct dust destinations >= 2x distinct non-dust destinations
          (confidence guard: a legitimate big-payment-plus-tiny-refunds
          pattern shouldn't be suppressed)

The 2x guard matters because a real consolidation hub might receive
ONE big payment plus 30 fractional change-backs from sub-routing — we
don't want to filter the consolidation hub itself, only the shower
destinations. If most of a source's outflows are dust to distinct
addresses, that's a shower; if most are real payments, it isn't.

Pure function — no DB, no I/O. Operates on the in-memory transfer list.
"""

from __future__ import annotations

import logging
import math
from decimal import Decimal
from typing import Iterable

from recupero.models import Transfer

log = logging.getLogger(__name__)


def _is_finite_decimal(value: Decimal | None) -> bool:
    """True if `value` is a real, finite Decimal (not None, not NaN/Inf).

    Decimal can carry NaN/Infinity sentinels just like float — `is_nan()`
    catches both quiet and signaling NaN. We bounce-check via float
    conversion as a belt-and-braces guard for any path that smuggled
    a Decimal('NaN') through earlier ingest hardening.
    """
    if value is None:
        return False
    try:
        if value.is_nan() or value.is_infinite():
            return False
        # Float conversion is the canonical "is this a real number"
        # check — Decimal('NaN').is_nan() is True but some pathological
        # constructions slip; isfinite is total.
        return math.isfinite(float(value))
    except (ValueError, ArithmeticError, OverflowError):
        return False


def identify_dust_attack_destinations(
    transfers: list[Transfer],
    *,
    dust_threshold_usd: Decimal = Decimal("1.00"),
    min_fanout: int = 10,
    case_id: str | None = None,
) -> set[str]:
    """Return the set of destination addresses that received only
    dust-shower transfers (<$1 USD, part of a fan-out of >=10 distinct
    destinations from a single source). These addresses should be
    OMITTED from the counterparty list in the brief.

    Args:
        transfers: All transfers in the case (post-BFS).
        dust_threshold_usd: Below this USD amount a transfer counts as
            "dust" for shower-detection purposes. Default $1.00 — chosen
            so the detector catches sub-cent showers AND just-over-cent
            ones. Independent of `TracePolicy.dust_threshold_usd`, which
            governs the per-transfer include gate.
        min_fanout: Minimum number of distinct dust destinations from
            a single source for the pattern to fire. Default 10 — well
            above any legitimate change-back behavior (which fans out
            to at most 2-3 addresses per swap) and below the smallest
            published dust-shower attacks (50-200 destinations). This
            is a heuristic CUTOFF, NOT a depth limit — v0.32.1+
            industry-best mode keeps it bounded at 10 (rather than
            relaxing it) and instead defeats the "set fanout-1" adversary
            via per-case HMAC randomization (see case_id param + the
            ``recupero.security.per_case_randomization`` module).
        case_id: Optional case identifier. When provided, the
            ``min_fanout`` is per-case randomized via HMAC under a
            server-held secret (``RECUPERO_RANDOMIZATION_SECRET``).
            Defeats the audit's M-5 adversary who picks ``fanout-1``
            after reading the source.

    Returns:
        Set of `to_address` strings that should be filtered from the
        brief's counterparty list. Empty set if no shower pattern is
        detected.

    Algorithm:
      1. Group transfers by `from_address`.
      2. For each source, count distinct `to_addresses` where
         `usd_value_at_tx` is non-None, finite, AND below
         `dust_threshold_usd`.
      3. If that count >= `min_fanout`, mark ALL those `to_addresses`
         as dust-attack victims.
      4. Confidence guard: only return the addresses if the source has
         at least 2x more dust destinations than non-dust destinations
         (so a legitimate single big-payment + dust-noise pattern isn't
         suppressed).

    Pure function — no DB, no I/O. Operates on the in-memory transfer list.
    """
    if not transfers:
        return set()

    # Defensive: clamp threshold + min_fanout to sane bounds even when
    # callers pass weird values. The env-var path in tracer.py also
    # clamps, but this is the public API surface and a unit test or
    # ad-hoc analysis script might pass arbitrary inputs.
    try:
        threshold = Decimal(str(dust_threshold_usd))
        if threshold.is_nan() or threshold.is_infinite() or threshold < 0:
            log.debug(
                "identify_dust_attack_destinations: invalid threshold %r; "
                "falling back to default $1.00",
                dust_threshold_usd,
            )
            threshold = Decimal("1.00")
    except (ArithmeticError, ValueError, TypeError):
        threshold = Decimal("1.00")

    try:
        fanout = int(min_fanout)
        if fanout < 1:
            fanout = 10
    except (TypeError, ValueError):
        fanout = 10

    # v0.32.1 W1 (round-2 adversary audit M-5): per-case randomized
    # min_fanout. When a case_id is provided, the fixed default above
    # is perturbed by ±30% via HMAC(case_id, "dust_min_fanout", secret).
    # An adversary reading the source still knows the BASE value but
    # cannot predict the actual per-case threshold without the
    # server-held secret — picking fanout=9 no longer reliably evades.
    # Caller chain: tracer.py → _apply_dust_attack_filter(case) →
    # identify_dust_attack_destinations(case_id=case.case_id). The
    # default kwarg is None to preserve backwards compat: tests and
    # ad-hoc analysis scripts that don't pass case_id get the same
    # behavior as v0.32.0. The dust_threshold_usd value is intentionally
    # NOT randomized — its $1 base would degenerate under integer jitter
    # (the bounded ±30% jitter on base=1 maps to {1,1,1,1}). Adversary
    # cost is concentrated in the fanout dimension.
    if case_id:
        try:
            from recupero.security.per_case_randomization import case_threshold
            fanout = case_threshold(case_id, "dust_min_fanout", base_value=fanout)
        except Exception as exc:  # noqa: BLE001 — never break the trace
            log.debug(
                "per-case threshold randomization failed for case %r: %s; "
                "falling back to fixed default fanout=%d",
                case_id, exc, fanout,
            )

    # source_address -> {"dust": set[to_addr], "non_dust": set[to_addr]}
    by_source: dict[str, dict[str, set[str]]] = {}

    for t in transfers:
        src = t.from_address
        dst = t.to_address
        if not src or not dst:
            continue
        bucket = by_source.setdefault(src, {"dust": set(), "non_dust": set()})

        usd = t.usd_value_at_tx
        if not _is_finite_decimal(usd):
            # Unpriced / NaN-priced transfers carry no dust signal —
            # we can't tell whether they're dust without USD. They DON'T
            # count as either dust OR non-dust for the per-source ratio.
            # (Treating them as non-dust would let an attacker bypass
            # the filter by stripping USD prices; treating them as dust
            # would falsely incriminate any unpriced legitimate flow.)
            continue
        assert usd is not None  # narrow for mypy after _is_finite_decimal
        if usd < threshold:
            bucket["dust"].add(dst)
        else:
            bucket["non_dust"].add(dst)

    flagged: set[str] = set()
    for src, buckets in by_source.items():
        dust_dests = buckets["dust"]
        non_dust_dests = buckets["non_dust"]
        if len(dust_dests) < fanout:
            continue
        # Confidence guard: dust fan-out must dominate non-dust fan-out
        # by at least 2x. A source that sends ONE big payment + 30 tiny
        # change-backs is suspicious but might be legitimate; a source
        # that sends 30 dust to distinct addresses and NOTHING else (or
        # a few non-dust) is unmistakably a shower.
        if len(dust_dests) < 2 * len(non_dust_dests):
            log.debug(
                "dust-attack: source %s has %d dust dests vs %d non-dust; "
                "ratio guard not met, skipping",
                src, len(dust_dests), len(non_dust_dests),
            )
            continue
        log.info(
            "dust-attack pattern detected: source=%s dust_destinations=%d "
            "non_dust_destinations=%d (filtering %d addresses from brief)",
            src, len(dust_dests), len(non_dust_dests), len(dust_dests),
        )
        flagged.update(dust_dests)

    return flagged


__all__ = ["identify_dust_attack_destinations"]
