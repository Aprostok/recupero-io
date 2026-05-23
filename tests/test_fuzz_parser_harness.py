"""Hypothesis-based fuzzing harness against key parsers.

Goal: surface ANY input that crashes a parser uncaught. Each parser
has a documented contract exception (or none); the invariant is
"no other exception ever escapes."

Targets (8):
  1. _common.canonical_address_key   -> str   (never raises)
  2. _pricing.fmt_usd                -> str   (never raises)
  3. portal.intake._reject_unicode_trojans -> None | IntakeValidationError
  4. freeze_learning.status._is_uuid_filter (nested closure; reproduced
     locally to fuzz the same contract)               -> bool (never raises)
  5. hack_tracker.models.HackEvent ctor -> instance | ValidationError
  6. screen.screener._safe_int / _safe_decimal -> int/Decimal (never raises)
  7. pricing.coingecko._safe_finite_nonneg_decimal -> Decimal | None
  8. trace.ofac_sync._sanitize_sdn_name -> str (never raises)

These are NOT correctness tests (other property tests already do that).
This file's role is the crash-resistance floor: regardless of what
adversarial bytes the upstream surfaces (CoinGecko proxy, OFAC XML,
operator paste, Supabase column), the parser must degrade gracefully,
not blow up the worker.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from recupero._common import canonical_address_key
from recupero._pricing import fmt_usd
from recupero.hack_tracker.models import HackEvent, HackEventSeverity, HackEventSource
from recupero.pricing.coingecko import _safe_finite_nonneg_decimal
from recupero.portal.intake import IntakeValidationError, _reject_unicode_trojans
from recupero.screen.screener import _safe_decimal, _safe_int
from recupero.trace.ofac_sync import _sanitize_sdn_name


_FUZZ = settings(
    max_examples=200,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)


# ----------------------------------------------------------------------
# 1) canonical_address_key
# ----------------------------------------------------------------------

@given(s=st.one_of(st.text(), st.binary().map(lambda b: b.decode("latin-1"))))
@_FUZZ
def test_fuzz_canonical_address_key_text(s: str) -> None:
    out = canonical_address_key(s)
    # Contract: always str; never raises.
    assert isinstance(out, str)


@given(s=st.one_of(st.none(), st.integers(), st.floats(allow_nan=True), st.lists(st.text())))
@_FUZZ
def test_fuzz_canonical_address_key_nonstr(s: Any) -> None:
    out = canonical_address_key(s)
    assert out == ""


# ----------------------------------------------------------------------
# 2) fmt_usd
# ----------------------------------------------------------------------

# We restrict to Decimal/int/float per the declared signature. Even
# garbage Decimals (NaN/Infinity) and overflowing floats must not raise.
_usd_inputs = st.one_of(
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.decimals(allow_nan=True, allow_infinity=True),
    st.from_regex(r"-?[0-9]{0,12}(\.[0-9]{0,6})?", fullmatch=True),
)


@given(amount=_usd_inputs)
@_FUZZ
def test_fuzz_fmt_usd(amount: Any) -> None:
    out = fmt_usd(amount)
    assert isinstance(out, str)
    # Contract: starts with "$" or "-$" (sign before currency symbol).
    assert out.startswith("$") or out.startswith("-$")
    # Contract: never literal "NaN" / "Infinity" leaking into the cover banner.
    assert "NaN" not in out
    assert "Infinity" not in out


# ----------------------------------------------------------------------
# 3) _reject_unicode_trojans
# ----------------------------------------------------------------------

@given(value=st.text())
@_FUZZ
def test_fuzz_reject_unicode_trojans(value: str) -> None:
    try:
        out = _reject_unicode_trojans(value, field="probe")
        # Returns None on success.
        assert out is None
    except IntakeValidationError:
        # Documented contract exception.
        pass


# ----------------------------------------------------------------------
# 4) _is_uuid_filter — closure inside fetch_live_filing_status.
#
# Reproduced verbatim here so hypothesis can drive it directly. If
# the production closure ever diverges, the duplication is intentional:
# this test pins the contract independently.
# ----------------------------------------------------------------------

def _is_uuid_filter(v: UUID | str | None) -> bool:
    if v is None:
        return False
    if isinstance(v, UUID):
        return True
    try:
        UUID(str(v))
        return True
    except (TypeError, ValueError):
        return False


@given(v=st.one_of(
    st.none(),
    st.uuids(),
    st.text(),
    st.binary().map(lambda b: b.decode("latin-1")),
    st.integers(),
))
@_FUZZ
def test_fuzz_is_uuid_filter(v: Any) -> None:
    out = _is_uuid_filter(v)
    assert isinstance(out, bool)


# ----------------------------------------------------------------------
# 5) HackEvent ctor
# ----------------------------------------------------------------------

_hack_event_field = st.one_of(
    st.none(),
    st.text(max_size=50),
    st.integers(),
    st.floats(allow_nan=True),
    st.lists(st.text(max_size=10), max_size=3),
    st.booleans(),
)


@given(payload=st.dictionaries(
    keys=st.sampled_from([
        "content_hash", "source", "source_url",
        "observed_at", "incident_time",
        "title", "summary", "severity",
        "chains_mentioned", "addresses", "tx_hashes",
        "estimated_loss_usd", "attributed_actor",
        "has_identifiable_victim", "victim_hint", "tags",
        # Also probe an unknown field — model_config extra="forbid"
        # must surface as ValidationError, never as a sneakier crash.
        "unknown_extra_field",
    ]),
    values=_hack_event_field,
    max_size=8,
))
@_FUZZ
def test_fuzz_hack_event_ctor(payload: dict) -> None:
    try:
        HackEvent(**payload)
    except ValidationError:
        # Documented contract exception.
        pass


def test_hack_event_well_formed_smoke() -> None:
    """Sanity: a known-good payload still constructs. Pins that the
    fuzzer's invariant ("ValidationError or success") isn't trivially
    true because the ctor always raises."""
    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.manual,
        source_url="https://x.com/h/1",  # W9-02 host allowlist
        observed_at=datetime.now(UTC),
        title="t",
        summary="s",
        severity=HackEventSeverity.low,
    )
    assert ev.title == "t"


# ----------------------------------------------------------------------
# 6) _safe_int / _safe_decimal
# ----------------------------------------------------------------------

_any_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.decimals(allow_nan=True, allow_infinity=True),
    st.text(),
    st.lists(st.integers(), max_size=3),  # type-mismatched garbage
)


@given(val=_any_scalar)
@_FUZZ
def test_fuzz_safe_int(val: Any) -> None:
    out = _safe_int(val)
    assert isinstance(out, int)


@given(val=_any_scalar)
@_FUZZ
def test_fuzz_safe_decimal(val: Any) -> None:
    out = _safe_decimal(val)
    assert isinstance(out, Decimal)
    assert out.is_finite()
    assert out >= 0


# ----------------------------------------------------------------------
# 7) coingecko._safe_finite_nonneg_decimal
# ----------------------------------------------------------------------

@given(raw=st.one_of(
    st.none(),
    st.text(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.decimals(allow_nan=True, allow_infinity=True),
    st.binary().map(lambda b: b.decode("latin-1")),
    st.lists(st.integers(), max_size=2),  # unexpected JSON shape
    st.dictionaries(st.text(max_size=4), st.integers(), max_size=2),
))
@_FUZZ
def test_fuzz_coingecko_price_parser(raw: Any) -> None:
    out = _safe_finite_nonneg_decimal(raw)
    assert out is None or (isinstance(out, Decimal) and out.is_finite() and out >= 0)


# ----------------------------------------------------------------------
# 8) ofac_sync._sanitize_sdn_name
# ----------------------------------------------------------------------

@given(name=st.text())
@_FUZZ
def test_fuzz_sanitize_sdn_name(name: str) -> None:
    out = _sanitize_sdn_name(name)
    assert isinstance(out, str)
    # Contract: NUL + bidi overrides removed.
    for forbidden in ("\x00", "‪", "‫", "‬", "‭", "‮",
                      "⁦", "⁧", "⁨", "⁩"):
        assert forbidden not in out


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
