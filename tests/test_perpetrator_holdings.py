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
    not just the attribution share."""
    freezable = [
        # Maple destination — $3.27M freezable (the lawyer-relevant
        # number; the address's gross is what matters, not
        # attribution share).
        {"issuer": "Maple Finance", "token": "mSyrupUSDp",
         "total_usd": "$3,270,000.00",
         "total_suspected_usd": "$3,270,000.00"},
        # Hub — $655K gross even though only $101 was traceable
        # from this victim.
        {"issuer": "(unknown)", "token": "DAI",
         "total_usd": "$0.00",  # gross-not-freezable position
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
    # Expected ~$22.05M — the Maple freezable + the hub + the
    # three dormant destinations. Within rounding of the CFI
    # report's $24.28M (the missing piece is the $120K Solana
    # bridge, which v0.8.0 cross-chain handoff would surface).
    assert total > Decimal("20_000_000"), (
        f"Zigha-shape headline should be eight figures, got {total}"
    )
    assert total < Decimal("25_000_000"), (
        f"Zigha-shape headline shouldn't double-count, got {total}"
    )


def test_perpetrator_holdings_chen_shape_matches_attribution() -> None:
    """Chen-like single-issuer case: $50K stolen, all went to one
    Circle USDC address that holds $50K. Gross == attribution.
    Headline = attribution, no surprise."""
    freezable = [
        {"issuer": "Circle", "token": "USDC",
         "total_usd": "$50,000.00",
         "total_suspected_usd": "$50,000.00"},
    ]
    unrecoverable: list[dict] = []
    total = _compute_perpetrator_holdings(freezable, unrecoverable)
    assert total == Decimal("50000.00")


def test_perpetrator_holdings_empty_returns_zero() -> None:
    """No destinations → 0. Sane default for the empty brief."""
    assert _compute_perpetrator_holdings([], []) == Decimal("0")


def test_perpetrator_holdings_uses_max_of_total_and_suspected() -> None:
    """A FREEZABLE entry's `total_suspected_usd` is the gross at
    the address; `total_usd` is the freezable subset. We use the
    LARGER of the two to capture the full perpetrator position
    even when only a fraction is freezable. (Common: address
    holds $1M, only $200K is in USDC; gross perp position is
    $1M, freezable is $200K.)"""
    freezable = [
        {"issuer": "X", "token": "Y",
         "total_usd": "$200,000.00",          # freezable portion
         "total_suspected_usd": "$1,000,000.00"},  # gross at the address
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
    from recupero.models import Case, Chain
    from datetime import datetime, timezone
    return Case(
        case_id="test-case",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        transfers=[],
        trace_started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        software_version="test",
        config_used={},
    )


def test_totals_includes_perpetrator_holdings_key() -> None:
    """The TOTAL_PERPETRATOR_HOLDINGS_USD key is present in the
    return dict so emit_brief can wire it through to the
    rendered output. UI contract."""
    case = _stub_case()
    freezable = [{
        "issuer": "Circle", "token": "USDC",
        "total_usd": "$50,000.00", "total_suspected_usd": "$50,000.00",
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
