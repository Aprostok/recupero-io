"""Centralized pricing constants for the Recupero Tier-2 service.

Single source of truth for every dollar amount + percentage that
appears in customer-facing copy, the Stripe dispatcher's defaults,
the engagement letter, the victim-summary email, the portal sign
form, and the operator CLI's --fee defaults.

Why centralize:
Pre-v0.7.0 the $1,500 figure was scattered across 11 files. A
price change required hunting every reference and risked drift
between the engagement letter (the legal contract) and the
Stripe Payment Link (what the customer actually pays). One
constant module forces every consumer to import the same number;
the test suite then locks the value so an accidental edit shows
up loudly.

Pricing model (v0.7.0, decoupled)
---------------------------------

  * Diagnostic fee: $499 (one-time, non-refundable on commencement
    of the forensic trace; partially refunded if recovery is
    structurally infeasible).
  * Engagement fee: $10,000 (one-time, due at signing of the
    Tier-2 engagement letter). NOT credited against any prior
    payment — the diagnostic and the engagement are separate
    products with separate prices.
  * Contingency fee: 15% of any funds actually recovered to the
    customer's wallet or bank. Paid only on successful recovery.

Anti-goal: per-case price overrides. We have ONE price for
each product. Operators who feel a case warrants a different
price should escalate, not eyeball-adjust mid-stream — that's a
real-money divergence between the contract PDF and the Stripe
Payment Link that we don't want to enable casually.
"""

from __future__ import annotations

from decimal import Decimal

# ----- Public constants ----- #

#: USD price of the $499 diagnostic. Charged via the diagnostic
#: Payment Link before any trace work begins. Includes the
#: forensic trace + victim-summary letter + (if recoverable) a
#: pre-built engagement letter the customer can choose to sign.
DIAGNOSTIC_FEE_USD: Decimal = Decimal("499")

#: USD price of the Tier-2 engagement. Charged via the engagement
#: Payment Link when the customer signs the engagement letter.
#: Unlocks 30 days of compliance freeze requests, LE coordination,
#: and weekly status emails.
ENGAGEMENT_FEE_USD: Decimal = Decimal("10000")

#: Contingency rate (percent integer) on recovered funds. Paid
#: only on successful recovery of value to the customer's wallet
#: or bank account.
CONTINGENCY_PCT: int = 15

#: Recoverable-floor: minimum confirmed FREEZABLE total below
#: which we route the case as "unrecoverable" rather than pitching
#: the engagement. At a $10,000 engagement fee, recommending
#: engagement on cases with $1,000 of recoverable funds would be
#: predatory; the floor raises the bar to a sensible multiple.
#:
#: Set to 4x the engagement fee — broad-stroke heuristic: a case
#: where the engagement covers ~25% of the recoverable amount is
#: worth pitching. At smaller recoverable totals, the customer is
#: better off with the diagnostic + DIY-LE-filing path.
RECOVERABLE_FLOOR_USD: Decimal = ENGAGEMENT_FEE_USD * 4


# ----- Derived / convenience values ----- #

#: USD amounts in CENTS for Stripe API integration. Stripe stores
#: all monetary amounts as cents (integer) to avoid floating-point
#: rounding; we mirror that internally so the dispatcher's
#: defaults match what Stripe will report.
DIAGNOSTIC_FEE_CENTS: int = int(DIAGNOSTIC_FEE_USD * 100)
ENGAGEMENT_FEE_CENTS: int = int(ENGAGEMENT_FEE_USD * 100)


def fmt_usd(amount: Decimal | int | float) -> str:
    """Customer-facing USD formatter. Always two decimals + comma
    thousands separator + leading $.

    Centralized so the engagement letter, the victim-summary
    email banner, the portal page, and the CLI all produce
    identical text — '$10,000.00' everywhere, not '$10000' on
    one surface and '$10,000.00' on another.
    """
    return f"${Decimal(amount):,.2f}"


def fmt_usd_short(amount: Decimal | int | float) -> str:
    """Compact USD formatter for inline copy where the .00 reads
    as visual noise (e.g., 'pay $10,000 to begin' vs 'pay
    $10,000.00 to begin'). Drops the cents component if exact
    dollars; keeps two decimals otherwise.
    """
    d = Decimal(amount)
    if d == d.to_integral_value():
        return f"${int(d):,}"
    return f"${d:,.2f}"


def fmt_usd_or(amount: Decimal | int | float | None, fallback: str = "(unknown)") -> str:
    """USD formatter that accepts None.

    v0.18.7 (round-11 arch-HIGH-003): the canonical None-handler.
    Pre-v0.18.7 six modules each had their own `_fmt_usd` with
    different None semantics (`"—"` in mini_freeze, `"(unknown)"` in
    brief, `"$0"` in trace_report) — the same Decimal(None) rendered
    differently across artifacts in the same case folder. Now one
    source of truth; consumers pick the fallback string.
    """
    if amount is None:
        return fallback
    return fmt_usd(amount)


__all__ = (
    "DIAGNOSTIC_FEE_USD",
    "ENGAGEMENT_FEE_USD",
    "CONTINGENCY_PCT",
    "RECOVERABLE_FLOOR_USD",
    "DIAGNOSTIC_FEE_CENTS",
    "ENGAGEMENT_FEE_CENTS",
    "fmt_usd",
    "fmt_usd_short",
)
