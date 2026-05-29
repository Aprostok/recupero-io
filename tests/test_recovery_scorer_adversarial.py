"""Adversarial-input tests for recovery/scorer.

Patterns covered:
  * _parse_usd: rejects NaN / Infinity / "-1" / non-numeric strings
  * score_recovery: non-dict brief degrades to zero-recovery
  * _load_p_any_calibration: rejects NaN / Inf JSON, falls back to defaults
  * Learned-prior table containing NaN / out-of-range falls back to
    heuristic for that issuer rather than poisoning recovery math
"""

from __future__ import annotations

import math
import os
from decimal import Decimal
from unittest.mock import patch

# ---- _parse_usd ---- #


def test_parse_usd_rejects_nan_string() -> None:
    from recupero.recovery.scorer import _parse_usd
    out = _parse_usd("NaN")
    assert out == Decimal("0")


def test_parse_usd_rejects_infinity_string() -> None:
    from recupero.recovery.scorer import _parse_usd
    assert _parse_usd("Infinity") == Decimal("0")
    assert _parse_usd("-Infinity") == Decimal("0")


def test_parse_usd_rejects_nan_float() -> None:
    from recupero.recovery.scorer import _parse_usd
    assert _parse_usd(float("nan")) == Decimal("0")


def test_parse_usd_rejects_inf_float() -> None:
    from recupero.recovery.scorer import _parse_usd
    assert _parse_usd(float("inf")) == Decimal("0")


def test_parse_usd_rejects_negative_value() -> None:
    """Recovery scorer treats negative USD as the zero floor —
    no on-chain mechanism produces negative dollars; a negative
    Decimal would silently subtract from totals."""
    from recupero.recovery.scorer import _parse_usd
    assert _parse_usd("-1000") == Decimal("0")
    assert _parse_usd(-50.0) == Decimal("0")


def test_parse_usd_accepts_normal_values() -> None:
    """Regression: positive values still parse cleanly."""
    from recupero.recovery.scorer import _parse_usd
    assert _parse_usd("$1,234.56") == Decimal("1234.56")
    assert _parse_usd("0") == Decimal("0")
    assert _parse_usd("") == Decimal("0")


def test_parse_usd_rejects_garbage_string() -> None:
    from recupero.recovery.scorer import _parse_usd
    assert _parse_usd("not a number") == Decimal("0")


# ---- score_recovery: non-dict brief ---- #


def test_score_recovery_handles_none_brief() -> None:
    from recupero.recovery.scorer import score_recovery
    out = score_recovery(None, auto_load_priors=False)  # type: ignore[arg-type]
    assert out.expected_recovered_usd == Decimal("0.00")
    assert out.recommendation == "reject"


def test_score_recovery_handles_string_brief() -> None:
    from recupero.recovery.scorer import score_recovery
    out = score_recovery("not a brief", auto_load_priors=False)  # type: ignore[arg-type]
    assert out.expected_recovered_usd == Decimal("0.00")


def test_score_recovery_handles_brief_with_nan_loss() -> None:
    """A brief with TOTAL_LOSS_USD='NaN' must NOT propagate NaN
    through the recovery math."""
    from recupero.recovery.scorer import score_recovery
    out = score_recovery({"TOTAL_LOSS_USD": "NaN"}, auto_load_priors=False)
    assert out.expected_recovered_usd == Decimal("0.00")
    # All Decimal fields must be finite.
    for fld in (
        "expected_recovered_usd", "expected_recovered_low_usd",
        "expected_recovered_high_usd",
        "expected_recupero_revenue_usd", "expected_net_to_victim_usd",
    ):
        v = getattr(out, fld)
        assert v.is_finite(), f"{fld} is non-finite: {v}"


def test_score_recovery_handles_freezable_entry_with_inf_usd() -> None:
    """A FREEZABLE entry whose total_usd is 'Infinity' should be
    treated as zero — not propagated into the per-issuer math."""
    from recupero.recovery.scorer import score_recovery
    brief = {
        "TOTAL_LOSS_USD": "10000",
        "FREEZABLE": [
            {"issuer": "Tether", "total_usd": "Infinity",
             "freeze_capability": "yes"}
        ],
    }
    out = score_recovery(brief, auto_load_priors=False)
    for fld in (
        "expected_recovered_usd", "expected_recovered_low_usd",
        "expected_recovered_high_usd",
        "expected_recupero_revenue_usd", "expected_net_to_victim_usd",
    ):
        v = getattr(out, fld)
        assert v.is_finite(), f"{fld} not finite: {v}"


# ---- _load_p_any_calibration ---- #


def test_load_p_any_calibration_rejects_nan() -> None:
    """If RECUPERO_P_ANY_CALIBRATION_JSON contains NaN, the loader
    must fall back to the documented defaults rather than poisoning
    the model."""
    from recupero.recovery.scorer import (
        _P_ANY_DEFAULT_CALIBRATION,
        _load_p_any_calibration,
    )
    with patch.dict(os.environ, {
        "RECUPERO_P_ANY_CALIBRATION_JSON": '{"floor": NaN}',
    }, clear=False):
        # The JSON itself is invalid (bare NaN); should fall through
        # to defaults via the parse exception path.
        out = _load_p_any_calibration()
    assert math.isfinite(out["floor"])
    assert out["floor"] == _P_ANY_DEFAULT_CALIBRATION["floor"]


def test_load_p_any_calibration_handles_inf_via_string() -> None:
    """Python's json module accepts the JS-style `Infinity` literal
    by default. Make sure the resulting +Inf is replaced with the
    default floor value rather than propagating."""
    from recupero.recovery.scorer import (
        _P_ANY_DEFAULT_CALIBRATION,
        _load_p_any_calibration,
    )
    # Use Python json's Infinity literal acceptance.
    with patch.dict(os.environ, {
        "RECUPERO_P_ANY_CALIBRATION_JSON": '{"floor": Infinity, "cap": 0.9}',
    }, clear=False):
        out = _load_p_any_calibration()
    assert math.isfinite(out["floor"])
    assert out["floor"] == _P_ANY_DEFAULT_CALIBRATION["floor"]
    # The valid cap value should still apply.
    assert out["cap"] == 0.9


def test_load_p_any_calibration_handles_string_value() -> None:
    """If one of the calibration fields is a string instead of a
    number, skip it rather than crashing."""
    from recupero.recovery.scorer import (
        _P_ANY_DEFAULT_CALIBRATION,
        _load_p_any_calibration,
    )
    with patch.dict(os.environ, {
        "RECUPERO_P_ANY_CALIBRATION_JSON": '{"floor": "bogus"}',
    }, clear=False):
        out = _load_p_any_calibration()
    assert out["floor"] == _P_ANY_DEFAULT_CALIBRATION["floor"]


# ---- Learned-prior table NaN handling ---- #


def test_learned_prior_with_nan_falls_back_to_heuristic() -> None:
    """If the learned_priors map carries a NaN p_any_freeze, the
    scorer should fall back to the heuristic issuer prior instead
    of multiplying NaN through the math."""
    from recupero.recovery.scorer import score_recovery

    class _BadPrior:
        p_any_freeze = float("nan")
        sample_size = 100

    brief = {
        "TOTAL_LOSS_USD": "10000",
        "FREEZABLE": [
            {"issuer": "Tether", "total_usd": "10000",
             "freeze_capability": "yes"}
        ],
    }
    out = score_recovery(
        brief,
        learned_priors={"Tether": _BadPrior()},
        auto_load_priors=False,
    )
    assert out.expected_recovered_usd.is_finite()
    # Should still produce a non-trivial recovery from heuristic prior.
    assert out.expected_recovered_usd > Decimal("0")


def test_learned_prior_with_out_of_range_falls_back_to_heuristic() -> None:
    """A learned p_any_freeze=1.5 would push the effective prior
    above the 0..1 invariant the rest of the scorer assumes."""
    from recupero.recovery.scorer import score_recovery

    class _BadPrior:
        p_any_freeze = 1.5
        sample_size = 100

    brief = {
        "TOTAL_LOSS_USD": "10000",
        "FREEZABLE": [
            {"issuer": "Tether", "total_usd": "10000",
             "freeze_capability": "yes"}
        ],
    }
    out = score_recovery(
        brief,
        learned_priors={"Tether": _BadPrior()},
        auto_load_priors=False,
    )
    assert out.expected_recovered_usd.is_finite()
    # No issuer's effective prior should exceed 1.0; expected recovery
    # cannot exceed total_loss × 1.0 × jur (default 0.7 unknown jur).
    assert out.expected_recovered_usd <= Decimal("10000")
