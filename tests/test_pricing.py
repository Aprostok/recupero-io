"""Lock the published pricing constants in recupero._pricing.

This file is the explicit reminder that pricing is a commercial
contract, not an implementation detail. If you change any of
these values you are doing so deliberately AND you need to:

  1. Update the Stripe Payment Link in the Dashboard for the
     same amount.
  2. Update the engagement_letter template if the structure
     changes (e.g., re-introducing diagnostic-credits-toward-
     engagement).
  3. Re-deploy the worker so the new dispatcher defaults +
     CLI defaults +  email banner text are all in sync.

The test deliberately uses literal expected values rather than
re-importing from _pricing — re-importing would make the test
auto-pass on any change. The whole point is to make a price
change visible in the diff.
"""

from __future__ import annotations

from decimal import Decimal

from recupero._pricing import (
    CONTINGENCY_PCT,
    DIAGNOSTIC_FEE_CENTS,
    DIAGNOSTIC_FEE_USD,
    ENGAGEMENT_FEE_CENTS,
    ENGAGEMENT_FEE_USD,
    RECOVERABLE_FLOOR_USD,
    fmt_usd,
    fmt_usd_short,
)


def test_diagnostic_fee_is_499_usd() -> None:
    """Diagnostic fee = $499. Changing this requires updating the
    Stripe diagnostic Payment Link in the Dashboard + every piece
    of customer-facing copy that references the $499 figure."""
    assert Decimal("499") == DIAGNOSTIC_FEE_USD
    assert DIAGNOSTIC_FEE_CENTS == 49900


def test_engagement_fee_is_10000_usd() -> None:
    """Engagement fee = $10,000 (v0.7.0, decoupled from
    diagnostic). Changing this requires updating the Stripe
    engagement Payment Link in the Dashboard + the engagement
    letter copy + the Pay-Now banner copy."""
    assert Decimal("10000") == ENGAGEMENT_FEE_USD
    assert ENGAGEMENT_FEE_CENTS == 1_000_000


def test_contingency_is_15_percent() -> None:
    """Contingency rate = 15% of recovered funds. Changing this
    requires updating the engagement letter Section 4 and the
    fee-explanation paragraph in victim_summary_recoverable.j2."""
    assert CONTINGENCY_PCT == 15


def test_recoverable_floor_is_4x_engagement() -> None:
    """Recoverable floor = 4× engagement fee. At less than 4× the
    fee, recommending Tier 2 means the engagement consumes >25%
    of the recoverable amount — predatory. The 4x ratio is the
    threshold we picked; it's locked here so an accidental
    'let's lower the floor to drive engagements' change is loud."""
    assert RECOVERABLE_FLOOR_USD == ENGAGEMENT_FEE_USD * 4


def test_cents_match_usd() -> None:
    """The cents constants must equal int(usd * 100). Catches
    accidentally setting one without the other."""
    assert int(DIAGNOSTIC_FEE_USD * 100) == DIAGNOSTIC_FEE_CENTS
    assert int(ENGAGEMENT_FEE_USD * 100) == ENGAGEMENT_FEE_CENTS


# ---- Formatters ---- #


def test_fmt_usd_thousands_separator() -> None:
    """fmt_usd always renders comma thousands + two decimals.
    Used in legal documents (engagement letter) where consistency
    matters."""
    assert fmt_usd(Decimal("10000")) == "$10,000.00"
    assert fmt_usd(499) == "$499.00"
    assert fmt_usd(1234567.89) == "$1,234,567.89"


def test_fmt_usd_short_drops_cents_on_round_dollars() -> None:
    """fmt_usd_short used in marketing copy where '.00' reads as
    visual noise."""
    assert fmt_usd_short(Decimal("10000")) == "$10,000"
    assert fmt_usd_short(499) == "$499"
    assert fmt_usd_short(Decimal("499.50")) == "$499.50"
    assert fmt_usd_short(Decimal("10000.99")) == "$10,000.99"
