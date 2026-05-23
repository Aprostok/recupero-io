"""RIGOR-Jacob T: Stripe amount cap.

``_resolve_amount_cents`` accepts any positive int from a verified
Stripe webhook. Stripe normally caps charges at ~$2M but a
compromised STRIPE_WEBHOOK_SECRET or a payload-mangling proxy could
inject ``amount_total = 10**18`` (10 quintillion cents = $10^16).

The amount lands in ``public.payments.amount_cents`` (BIGINT). It
also drives:
  * ``engagement_fee_paid_usd`` (decimal) — used in P&L reports
  * The notes column "$X.XX received" — rendered in operator UI

Cap at 10**11 cents = $1 billion. Real diagnostic = $499, real
engagement = ~$10K, real freeze recovery = ~$3B BTC (history),
which is the realistic ceiling. Anything above $1B in a SINGLE
payment is implausible.
"""

from __future__ import annotations

import pytest


def test_resolve_amount_cents_caps_extreme_values() -> None:
    """A Stripe object with amount_total = 10**18 (10 quintillion
    cents) must not propagate. Either return the typed default OR
    raise — but the extreme value MUST NOT land in the payments
    row unmodified."""
    from recupero.payments.dispatcher import _resolve_amount_cents

    obj = {"amount_total": 10**18}
    result = _resolve_amount_cents(obj, "diagnostic")

    # Either capped, raised, or fallen back to typed default.
    # The cap value depends on the implementation; just ensure
    # we don't return the raw 10**18.
    assert result != 10**18, (
        f"_resolve_amount_cents returned 10**18 directly — extreme "
        f"values pass through to payments.amount_cents. Cap or "
        f"fallback to default."
    )
    # Sanity: result should be a reasonable cents value.
    assert 0 <= result <= 10**11, (
        f"_resolve_amount_cents returned {result}, expected <= $1B"
    )


def test_resolve_amount_cents_caps_negative_via_unrelated_field() -> None:
    """An overlap between Stripe's amount + amount_total fields could
    surface a value of any shape (e.g., None, 0, negative). The
    function already filters val > 0 — confirm that contract."""
    from recupero.payments.dispatcher import _resolve_amount_cents

    obj = {"amount_total": -100, "amount": -50}
    result = _resolve_amount_cents(obj, "diagnostic")
    # Negative values fall through to the default.
    assert result >= 0


def test_resolve_amount_cents_real_diagnostic_passes() -> None:
    """Sanity: a real $499 diagnostic amount passes through."""
    from recupero.payments.dispatcher import _resolve_amount_cents

    obj = {"amount_total": 49900}
    assert _resolve_amount_cents(obj, "diagnostic") == 49900


def test_resolve_amount_cents_real_engagement_passes() -> None:
    """Sanity: a real $10K engagement amount passes through."""
    from recupero.payments.dispatcher import _resolve_amount_cents

    obj = {"amount_total": 1_000_000}
    assert _resolve_amount_cents(obj, "engagement") == 1_000_000
