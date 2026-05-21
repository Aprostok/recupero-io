"""Tests for the v0.7.4 perpetrator-holdings headline computation.

The strategic context (from Jacob's V-CFI01 validation):

  Law firms won't engage on stolen-crypto cases below ~$500K.
  When the worker's brief leads with "$153 attributable inflow"
  even though the perpetrator hub holds $655K + downstream
  destinations hold $3M+ in freezable Maple, the brief gets
  dismissed at the lawyer's desk.

  The fix: lead with GROSS perpetrator-controlled holdings as the
  headline; keep attribution-share as a secondary scoping figure.

This file pins the new computation against three case shapes:

  1. Zigha-like — small attribution ($150), large perpetrator
     position ($24M across hub + downstream). The classic
     multi-victim consolidation pattern.
  2. Chen-like — single-chain, all victim funds at one issuer,
     attribution ~= perpetrator position. Headline numbers
     should converge.
  3. Empty — no destinations identified. Both numbers are 0.

We also verify the brief's `_compute_totals()` returns the new
field with the right value and the brief assembly threads it
through to the rendered output.
"""

from __future__ import annotations

from datetime import UTC
from decimal import Decimal

from recupero.reports.emit_brief import (
    _compute_perpetrator_holdings,
    _compute_totals,
)

# ---- _compute_perpetrator_holdings ---- #


def test_perpetrator_holdings_zigha_shape_sums_freezable_and_unrecoverable() -> None:
    """The Zigha case shape: hub + downstream destinations holding
    a mix of freezable and unrecoverable assets. The headline
    should sum the GROSS at every perpetrator-controlled address,
    not just the attribution share.

    v0.18.0 (round-11 forensic CRIT): the prior version of this test
    had ``total_usd`` and ``total_suspected_usd`` set to the SAME value
    per issuer, because the original implementation comment claimed
    ``total_suspected_usd = FREEZABLE + INVESTIGATE`` and the test
    pinned that semantics with ``max()``. The actual emit_brief loop
    routes each holding into EXACTLY ONE bucket (FREEZABLE-status
    holdings → total_usd, INVESTIGATE-status holdings →
    total_suspected_usd) — the two are mutually exclusive. Test data
    now reflects realistic emit_brief output and the assertion uses
    the corrected sum semantics.
    """
    freezable = [
        # Maple destination — $3.27M FREEZABLE-status holdings.
        # total_suspected_usd = 0 because no INVESTIGATE-status rows
        # at Maple in the real case.
        {"issuer": "Maple Finance", "token": "mSyrupUSDp",
         "total_usd": "$3,270,000.00",
         "total_suspected_usd": "$0.00"},
        # Hub — $655K INVESTIGATE-status (pending KYC verification),
        # $0 FREEZABLE.
        {"issuer": "(unknown)", "token": "DAI",
         "total_usd": "$0.00",
         "total_suspected_usd": "$655,000.00"},
    ]
    unrecoverable = [
        # Three dormant DAI destinations.
        {"asset": "approximately 10.08M DAI (~$10,080,000)",
         "reason": "Dormant since Oct 2025; DAI permissionless"},
        {"asset": "approximately 6.91M DAI (~$6,910,000)",
         "reason": "Dormant"},
        {"asset": "approximately 1.14M mixed DAI/sUSDS (~$1,140,000)",
         "reason": "Dormant"},
    ]
    total = _compute_perpetrator_holdings(freezable, unrecoverable)
    # Expected = $3.27M (Maple FREEZABLE) + $655K (Hub INVESTIGATE)
    #           + $10.08M + $6.91M + $1.14M (Unrecoverable)
    #         = $22,055,000 exactly.
    assert total == Decimal("22055000"), (
        f"Zigha-shape headline should be $22.055M (3.27M FREEZABLE + "
        f"655K INVESTIGATE + 18.13M Unrecoverable), got {total}"
    )


def test_perpetrator_holdings_chen_shape_matches_attribution() -> None:
    """Chen-like single-issuer case: $50K stolen, all went to one
    Circle USDC address that holds $50K of FREEZABLE-status.
    Gross == attribution. Headline = $50K (FREEZABLE only; no
    INVESTIGATE bucket on this case)."""
    freezable = [
        {"issuer": "Circle", "token": "USDC",
         "total_usd": "$50,000.00",
         "total_suspected_usd": "$0.00"},
    ]
    unrecoverable: list[dict] = []
    total = _compute_perpetrator_holdings(freezable, unrecoverable)
    assert total == Decimal("50000.00")


def test_perpetrator_holdings_sums_both_buckets_when_mixed() -> None:
    """v0.18.0 (round-11 forensic CRIT): when an issuer has BOTH
    FREEZABLE and INVESTIGATE holdings, the perpetrator-holdings
    total must SUM them, not take max(). Pre-v0.18.0 the page-1
    headline understated perpetrator exposure by the INVESTIGATE
    bucket whenever both buckets were non-empty — typically 20-40%
    too low on multi-bucket issuers."""
    freezable = [
        # An issuer with BOTH FREEZABLE and INVESTIGATE positions.
        # Pre-v0.18.0 max() would report $500K; correct answer is $700K.
        {"issuer": "Circle", "token": "USDC",
         "total_usd": "$500,000.00",
         "total_suspected_usd": "$200,000.00"},
    ]
    total = _compute_perpetrator_holdings(freezable, [])
    assert total == Decimal("700000.00"), (
        f"Mixed-bucket issuer must sum FREEZABLE + INVESTIGATE, got {total}"
    )


def test_perpetrator_holdings_empty_returns_zero() -> None:
    """No destinations → 0. Sane default for the empty brief."""
    assert _compute_perpetrator_holdings([], []) == Decimal("0")


def test_perpetrator_holdings_sums_freezable_and_investigate_buckets() -> None:
    """v0.18.0 (round-11 forensic CRIT, renamed from
    `uses_max_of_total_and_suspected`): the OLD assumption was that
    `total_suspected_usd` = FREEZABLE + INVESTIGATE cumulative — so
    `max(suspected, freezable)` would give the gross perpetrator
    position. The actual emit_brief loop (emit_brief.py:596-601)
    routes EACH holding into EXACTLY ONE bucket: FREEZABLE → total_usd,
    INVESTIGATE → total_suspected_usd. So the gross is the SUM, not
    the max.

    Common shape: address holds $1M, of which $200K is USDC under
    Circle (FREEZABLE, capability=high) and $800K is other tokens
    pending KYC verification (INVESTIGATE). Gross perpetrator
    position = $200K + $800K = $1M.
    """
    freezable = [
        {"issuer": "X", "token": "Y",
         "total_usd": "$200,000.00",          # FREEZABLE-status
         "total_suspected_usd": "$800,000.00"},  # INVESTIGATE-status
    ]
    total = _compute_perpetrator_holdings(freezable, [])
    assert total == Decimal("1_000_000.00")


def test_perpetrator_holdings_unrecoverable_amount_extraction() -> None:
    """UNRECOVERABLE entries have a free-form `asset` string with a
    dollar amount we regex-extract. Verify the extraction handles
    the patterns the AI editorial actually emits."""
    unrec_entries = [
        {"asset": "approximately 6.4 ETH (~$15,200)",
         "reason": "Wrapped to WETH"},
        {"asset": "300,000 DAI (~$300,000.00)",
         "reason": "Dormant; DAI permissionless"},
        {"asset": "$1.5M USDT",
         "reason": "Sent to mixer"},
    ]
    total = _compute_perpetrator_holdings([], unrec_entries)
    # Regex picks the FIRST dollar amount in each string.
    # First entry: $15,200. Second: $300,000.00. Third: $1.5 (since
    # the regex matches digits/comma/decimal — it picks "1.5" before
    # the M suffix). So total is 15200 + 300000 + 1.5 = 315201.5.
    # Locking the current behavior so a future "parse M/K/B suffixes"
    # change is intentional.
    assert total > Decimal("315_000")
    assert total < Decimal("316_000")


# ---- _compute_totals (integration) ---- #


def _stub_case():
    """Build a minimal Case stub for _compute_totals."""
    from datetime import datetime

    from recupero.models import Case, Chain
    return Case(
        case_id="test-case",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=[],
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test",
        config_used={},
    )


def test_totals_includes_perpetrator_holdings_key() -> None:
    """The TOTAL_PERPETRATOR_HOLDINGS_USD key is present in the
    return dict so emit_brief can wire it through to the
    rendered output. UI contract.

    v0.18.0 (round-11 forensic CRIT): fixture data now reflects
    realistic emit_brief output (each holding in EXACTLY ONE bucket).
    Pre-v0.18.0 the test had FREEZABLE and INVESTIGATE buckets both
    set to $50K, which made sense under the old max() implementation
    but doesn't match the actual data shape emit_brief writes.
    """
    case = _stub_case()
    freezable = [{
        "issuer": "Circle", "token": "USDC",
        # $50K FREEZABLE, no INVESTIGATE positions on this issuer.
        "total_usd": "$50,000.00", "total_suspected_usd": "$0.00",
        "total_excluded_usd": "$0.00",
    }]
    totals = _compute_totals(case, freezable, [])
    assert "TOTAL_PERPETRATOR_HOLDINGS_USD" in totals
    assert "$50,000" in totals["TOTAL_PERPETRATOR_HOLDINGS_USD"]


def test_totals_preserves_existing_keys() -> None:
    """Adding the new key shouldn't break any existing consumer.
    The previous shape (TOTAL_LOSS_USD, TOTAL_FREEZABLE_USD,
    MAX_RECOVERABLE_USD, FREEZABLE_PERCENT, RECOVERABLE_PERCENT)
    must all still be present."""
    case = _stub_case()
    totals = _compute_totals(case, [], [])
    for key in (
        "TOTAL_LOSS_USD", "TOTAL_FREEZABLE_USD", "TOTAL_SUSPECTED_USD",
        "TOTAL_EXCLUDED_USD", "TOTAL_UNRECOVERABLE_USD",
        "MAX_RECOVERABLE_USD", "FREEZABLE_PERCENT", "RECOVERABLE_PERCENT",
    ):
        assert key in totals, f"existing key {key} was dropped"
