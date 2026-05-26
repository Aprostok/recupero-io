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

    History (three revisions):
      * Pre-v0.18.0: total_suspected_usd was wrongly believed to be
        FREEZABLE+INVESTIGATE cumulative; max() was used.
      * v0.18.0: actual emit_brief loop confirmed buckets MUTUALLY
        EXCLUSIVE. Sum of FREEZABLE + INVESTIGATE was adopted (this
        was the prior version of this test).
      * v0.27.2 (Jacob Zigha review, item 1): summing INVESTIGATE
        inflated the trace-report headline by 21.6× on Zigha because
        1inch/Uniswap reflective-liquidity contracts ($145M) were
        tagged INVESTIGATE — not perpetrator-controlled. Reverted to
        the original docstring semantic: FREEZABLE + UNRECOVERABLE
        only. INVESTIGATE has its own TOTAL_SUSPECTED_USD field for
        operator visibility but does NOT count toward the
        "perpetrator-controlled" headline.
    """
    freezable = [
        # Maple destination — $3.27M FREEZABLE-status holdings.
        # total_suspected_usd = 0 because no INVESTIGATE-status rows
        # at Maple in the real case.
        {"issuer": "Maple Finance", "token": "mSyrupUSDp",
         "total_usd": "$3,270,000.00",
         "total_suspected_usd": "$0.00"},
        # Hub — $655K INVESTIGATE-status (pending KYC verification),
        # $0 FREEZABLE. Under v0.27.2 this is NO LONGER counted in
        # perpetrator holdings — INVESTIGATE is a lead, not a
        # confirmed-controlled position.
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
    # v0.27.2: $3.27M (Maple FREEZABLE) + $18.13M Unrecoverable
    #         = $21,400,000. The $655K Hub INVESTIGATE is dropped
    # because INVESTIGATE-tagged positions are not confirmed
    # perpetrator-controlled.
    assert total == Decimal("21400000"), (
        f"Zigha-shape headline should be $21.4M (3.27M FREEZABLE + "
        f"18.13M Unrecoverable; INVESTIGATE excluded per v0.27.2), "
        f"got {total}"
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


def test_perpetrator_holdings_mixed_bucket_issuer_counts_freezable_only() -> None:
    """v0.27.2 (Jacob Zigha review, item 1): when an issuer has both
    FREEZABLE and INVESTIGATE holdings, the perpetrator-holdings
    headline counts ONLY the FREEZABLE bucket. INVESTIGATE is a lead
    — worth asking about, not confirmed-controlled.

    History: v0.18.0 changed this from max() to sum() believing
    INVESTIGATE was perpetrator-controlled-but-needs-KYC. Jacob's
    v0.27.1 Zigha review showed that this assumption breaks when
    the INVESTIGATE bucket includes smart-contract reflective
    liquidity ($145M on Zigha, NOT perpetrator-controlled) — the
    trace report headline ballooned to 21.6× the real number. The
    rule now is: only confirmed FREEZABLE + UNRECOVERABLE count.
    """
    freezable = [
        {"issuer": "Circle", "token": "USDC",
         "total_usd": "$500,000.00",
         "total_suspected_usd": "$200,000.00"},  # excluded post-v0.27.2
    ]
    total = _compute_perpetrator_holdings(freezable, [])
    assert total == Decimal("500000.00"), (
        f"Mixed-bucket issuer counts FREEZABLE only post-v0.27.2; "
        f"got {total}"
    )


def test_perpetrator_holdings_empty_returns_zero() -> None:
    """No destinations → 0. Sane default for the empty brief."""
    assert _compute_perpetrator_holdings([], []) == Decimal("0")


def test_perpetrator_holdings_excludes_investigate_only_entry() -> None:
    """v0.27.2 (Jacob Zigha review, item 1): an entry whose entire
    holding is INVESTIGATE contributes ZERO to perpetrator holdings.
    This is the BitGo / Threshold Zigha shape: 0x52Aa smart-contract
    bleed, $46M of INVESTIGATE-tagged 1inch/Uniswap liquidity, no
    FREEZABLE rows.

    History: this was previously `test_..._sums_freezable_and_
    investigate_buckets` and pinned a SUM semantic that v0.27.2
    rejects (see test_perpetrator_holdings_mixed_bucket_issuer_
    counts_freezable_only for the rationale).
    """
    freezable = [
        # Pure INVESTIGATE entry — 0x52Aa bleed pattern.
        {"issuer": "BitGo", "token": "WBTC",
         "total_usd": "$0.00",
         "total_suspected_usd": "$46,762,084.33"},
    ]
    total = _compute_perpetrator_holdings(freezable, [])
    assert total == Decimal("0"), (
        f"INVESTIGATE-only entry must contribute $0 to perpetrator "
        f"holdings post-v0.27.2; got {total}"
    )


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
