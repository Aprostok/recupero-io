"""format_usd_cents must never crash a court-facing brief on a stray float.

format_usd_cents is typed Decimal|None, but a bare `.is_finite()` raises
AttributeError on a float NaN/Inf — which would surface as a Jinja TemplateError
mid-render instead of a graceful "$0.00". It now coerces first (matching its
sibling format_usd_trim).
"""
from __future__ import annotations

from decimal import Decimal

from recupero.reports._money import format_usd_cents


def test_format_usd_cents_survives_float_nan_and_inf() -> None:
    assert format_usd_cents(float("nan")) == "$0.00"
    assert format_usd_cents(float("inf")) == "$0.00"
    assert format_usd_cents(Decimal("NaN")) == "$0.00"
    assert format_usd_cents(None) == "$0.00"


def test_format_usd_cents_basic() -> None:
    assert format_usd_cents(Decimal("47840")) == "$47,840.00"
    assert format_usd_cents(Decimal("47840.12")) == "$47,840.12"
    assert format_usd_cents(47840.0) == "$47,840.00"  # float coerced, not crashed
