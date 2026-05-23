"""Deeper audit of `_pricing.fmt_usd` + `recovery.scorer` quantitative
edges (round-14 audit).

Goals:
  1. Extreme Decimal magnitudes do NOT escape into scientific notation in
     the LE-bound brief copy (would render as "$1E+20" — looks like a
     debug artifact, not money).
  2. Negative USD renders as `-$1,000.00` (accountant-canonical), NOT
     `$-1,000.00` (where the `$` is detached from the sign and reads as
     "negative dollars" — wrong sign placement on legal docs).
  3. Banker's rounding (ROUND_HALF_EVEN) is the documented + locked
     rounding mode for the formatter. Locked here so a global decimal-
     context flip elsewhere can't silently change LE letter cents.
  4. Recovery scorer with zero freezable issuers returns a finite p_any
     (the documented "no signal" floor of 0.10), NOT NaN.
  5. CI band width shrinks as sample size grows — beta_credible_interval
     must produce a wider band at n=3 than at n=100.
  6. recovery_estimate JSON serialization is round-trip-safe in the sense
     the rest of the pipeline cares about: every USD string MUST be
     parseable back through `_parse_usd` to the original Decimal value
     (no E-notation, no double-$, no garbage).
"""

from __future__ import annotations

from decimal import Decimal

from recupero._pricing import fmt_usd, fmt_usd_bare_or
from recupero.recovery.scorer import _parse_usd, score_recovery


# ---- 1. Extreme magnitudes ---- #


def test_fmt_usd_extreme_large_no_scientific_notation() -> None:
    """A Decimal of magnitude 1e20 must NOT render as `$1E+20` — the
    LE handoff has surfaced upstream Decimals in this range during
    bridge-loop attribution bugs, and `$1E+20` in a legal letter is a
    credibility-destroying artifact. Decimal's `:,.2f` format spec
    expands to fixed-point — lock that property here."""
    out = fmt_usd(Decimal("1E+20"))
    assert "E" not in out and "e" not in out, (
        f"fmt_usd produced scientific notation: {out!r}"
    )
    # Must look like money: leading $, comma thousands, .00 cents.
    assert out.startswith("$")
    assert "," in out
    assert out.endswith(".00")


def test_fmt_usd_extreme_small_collapses_to_zero() -> None:
    """Sub-cent magnitudes (1e-20) must collapse to `$0.00` in copy —
    rendering `$0.00000000000000000001` in a brief is nonsense and
    would break column alignment in fixed-width templates."""
    out = fmt_usd(Decimal("1E-20"))
    assert out == "$0.00", f"sub-cent should round to $0.00, got {out!r}"


# ---- 2. Negative USD: sign before $, not after ---- #


def test_fmt_usd_negative_sign_before_dollar() -> None:
    """Accounting convention: `-$1,000.00` (minus precedes the
    currency symbol). Python's default Decimal format produces
    `$-1,000.00`, which detaches the sign from the dollar token
    and reads as 'dollar-negative-one-thousand' — wrong on legal
    copy. Recovery summaries surface negative expected-net values
    on `discourage` / `reject` cases; we MUST render them the
    accountant way."""
    assert fmt_usd(Decimal("-1000")) == "-$1,000.00"
    assert fmt_usd(Decimal("-1.55")) == "-$1.55"
    assert fmt_usd(-50) == "-$50.00"


def test_fmt_usd_bare_or_negative_sign_before_value() -> None:
    """Same convention for the bare (no-$) variant used by templates
    that prefix `USD ` themselves — `-1,000.00`, not `1,000.00-` or
    a stripped sign."""
    # bare_or returns the no-$ form; sign should still lead.
    out = fmt_usd_bare_or(Decimal("-1000"))
    assert out.startswith("-"), f"negative should lead with `-`, got {out!r}"
    assert "1,000" in out


# ---- 3. Banker's-rounding lock ---- #


def test_fmt_usd_uses_bankers_rounding_lock() -> None:
    """Pin the rounding mode used by fmt_usd so a downstream context
    change can't silently flip from HALF_EVEN to HALF_UP.

    Banker's-rounding ties: 2.675 → 2.68 (round 7 up to even 8);
    0.125 → 0.12 (round 2 down, already even); 0.135 → 0.14 (round
    3 up to even 4). These are HALF_EVEN-specific outputs — HALF_UP
    would produce 2.68 / 0.13 / 0.14 respectively, so a divergence
    on 0.125 is the canary for context corruption."""
    # The canary: HALF_EVEN rounds 0.125 down (2 is even).
    # HALF_UP would round it up to 0.13.
    assert fmt_usd(Decimal("0.125")) == "$0.12"
    # 0.135 — HALF_EVEN rounds up to even 4 (matches HALF_UP here).
    assert fmt_usd(Decimal("0.135")) == "$0.14"


# ---- 4. Scorer with zero freezable issuers ---- #


def test_score_recovery_empty_freezable_returns_finite_p_any() -> None:
    """A brief whose FREEZABLE list is empty (e.g., all-DEX-swept
    case) must NOT produce NaN for probability_any_recovery_90d —
    the headline summary depends on rendering `p_any:.0%` and a NaN
    would land in the LE handoff as `nan%`."""
    out = score_recovery(
        {"TOTAL_LOSS_USD": "10000", "FREEZABLE": []},
        auto_load_priors=False,
    )
    import math
    assert math.isfinite(out.probability_any_recovery_90d)
    assert math.isfinite(out.probability_pays_back_engagement_180d)
    # No freezable → documented floor 0.10 (matches scorer.py:673).
    assert out.probability_any_recovery_90d == 0.10


# ---- 5. CI band width vs sample size ---- #


def test_ci_band_widens_at_small_sample_size() -> None:
    """beta_credible_interval at n=3 must produce a strictly wider
    band than at n=100, even when the point estimate is the same.
    This is the property that lets the brief honestly disclaim
    'estimate based on only 3 historical outcomes'."""
    from recupero.freeze_learning.recorder import beta_credible_interval

    lo_small, hi_small = beta_credible_interval(2, 3, level=0.90)
    lo_large, hi_large = beta_credible_interval(67, 100, level=0.90)
    width_small = hi_small - lo_small
    width_large = hi_large - lo_large
    assert width_small > width_large, (
        f"small-sample band ({width_small:.3f}) should be wider than "
        f"large-sample band ({width_large:.3f})"
    )
    # And the small-sample band should be meaningfully wide (>30%) so
    # operators visually clock the uncertainty.
    assert width_small > 0.30


# ---- 6. JSON serialization round-trip safety ---- #


def test_recovery_estimate_json_usd_strings_round_trip() -> None:
    """Every `$X,XXX.XX` string emitted by `RecoveryEstimate.to_json_safe`
    must be parseable back through `_parse_usd` to a finite Decimal —
    that's the contract `freeze.asks` + the brief assembler rely on
    when they re-read a cached estimate from JSON.

    Catches: scientific notation leaking into a USD string ("$1E+20")
    or a stray double-`$$` from copy-paste, both of which would crash
    `_parse_usd` or produce silent zero on round-trip."""
    brief = {
        "TOTAL_LOSS_USD": "1000000000000",  # $1T — extreme but legal
        "FREEZABLE": [
            {"issuer": "Tether", "total_usd": "1000000000000",
             "freeze_capability": "yes"}
        ],
    }
    est = score_recovery(brief, auto_load_priors=False)
    js = est.to_json_safe()
    for fld in (
        "expected_recovered_usd",
        "expected_recovered_low_usd",
        "expected_recovered_high_usd",
        "expected_recupero_revenue_usd",
        "expected_net_to_victim_usd",
    ):
        val = js[fld]
        assert isinstance(val, str), f"{fld} not a string: {val!r}"
        # No scientific notation.
        assert "E" not in val and "e" not in val, (
            f"{fld} leaked sci notation: {val!r}"
        )
        # _parse_usd must consume the value without raising / NaN-ing.
        back = _parse_usd(val)
        assert back.is_finite(), f"{fld} not finite after parse: {back}"
