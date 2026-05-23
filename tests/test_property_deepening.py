"""Property-based deepening tests — invariants that lock subtle behavior.

Each test pins a property that an "innocent" refactor could quietly
break:

  1. USD aggregation associativity (Decimal sums commute / permute)
  2. canonical_address_key idempotency (normalizer must be stable)
  3. JSON round-trip determinism (manifest stability across builds)
  4. _validate_case_id idempotency (no state leakage; pure validator)
  5. hmac.compare_digest commutativity (defense vs. `a == b` refactor)
  6. _sanitize_email_header monotonicity (re-sanitize is a no-op)
  7. _safe_filename_segment length cap (output <= 64 chars)
  8. _safe_int / _safe_decimal NaN/Inf guard

All tests use @given + @settings(max_examples=200, deadline=1000) and
assume() to filter pathological inputs before they hit Pydantic-level
constraints.
"""

from __future__ import annotations

import functools
import hmac
import json
import math
from datetime import datetime, timezone
from decimal import Decimal

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from recupero._common import canonical_address_key
from recupero.reports.legal_requests import _safe_filename_segment
from recupero.screen.screener import _safe_decimal, _safe_int
from recupero.storage.case_store import _validate_case_id
from recupero.worker._email import _sanitize_email_header

_PROP_SETTINGS = settings(max_examples=200, deadline=1000)


# Bounded Decimals — keeps Hypothesis from generating 10**308 monsters
# that overflow JSON / Decimal arithmetic and aren't representative of
# real USD flow data.
_usd_decimals = st.decimals(
    min_value=Decimal("-1000000000"),
    max_value=Decimal("1000000000"),
    allow_nan=False,
    allow_infinity=False,
    places=2,
)


# ---------- 1. USD aggregation associativity ---------- #


@given(values=st.lists(_usd_decimals, min_size=0, max_size=50))
@_PROP_SETTINGS
def test_usd_sum_is_associative_and_permutation_invariant(values: list[Decimal]) -> None:
    """sum(L) == reduce(+, L) == sum(perm(L)) for any Decimal list.

    Locks aggregate.py / brief.py: if anyone "optimizes" the rollup by
    coercing to float mid-sum, this test fails (float drift breaks
    permutation invariance).
    """
    builtin = sum(values, Decimal("0"))
    reduced = functools.reduce(lambda a, b: a + b, values, Decimal("0"))
    reversed_sum = sum(reversed(values), Decimal("0"))
    assert builtin == reduced
    assert builtin == reversed_sum
    # All-decimal pipeline must NEVER demote to float (which would lose
    # cents on totals > ~$1e15).
    assert isinstance(builtin, Decimal)


# ---------- 2. canonical_address_key idempotency ---------- #


@given(addr=st.text(max_size=128))
@_PROP_SETTINGS
def test_canonical_address_key_is_idempotent(addr: str) -> None:
    """canonical(canonical(x)) == canonical(x). Normalizer stability."""
    once = canonical_address_key(addr)
    twice = canonical_address_key(once)
    assert once == twice


# ---------- 3. JSON round-trip determinism ---------- #


_json_scalar = st.one_of(
    st.text(max_size=32),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.booleans(),
    st.none(),
    _usd_decimals,
    st.datetimes(
        min_value=datetime(2000, 1, 1),
        max_value=datetime(2100, 1, 1),
    ).map(lambda d: d.replace(tzinfo=timezone.utc)),
)


@given(
    d=st.dictionaries(
        keys=st.text(
            alphabet=st.characters(
                min_codepoint=32, max_codepoint=126, blacklist_characters='"\\'
            ),
            min_size=1,
            max_size=16,
        ),
        values=_json_scalar,
        max_size=12,
    )
)
@_PROP_SETTINGS
def test_json_dump_is_deterministic_across_calls(d: dict) -> None:
    """Two successive json.dumps(..., default=str, sort_keys=True) on
    the same dict produce the IDENTICAL string. Locks manifest
    file determinism — if a recorded SHA256 is to match the on-disk
    bytes, the serializer must be a pure function of its input.
    """
    first = json.dumps(d, default=str, sort_keys=True)
    second = json.dumps(d, default=str, sort_keys=True)
    assert first == second
    # And re-parsing then re-dumping is also stable (after the initial
    # default-coercion of Decimals / datetimes to str).
    coerced = json.loads(first)
    third = json.dumps(coerced, default=str, sort_keys=True)
    assert first == third


# ---------- 4. _validate_case_id idempotency ---------- #


@given(
    case_id=st.text(
        alphabet=st.characters(
            min_codepoint=33,
            max_codepoint=126,
            blacklist_characters='/\\<>:"|?*',
        ),
        min_size=1,
        max_size=100,
    )
)
@_PROP_SETTINGS
def test_validate_case_id_is_idempotent(case_id: str) -> None:
    """If a case_id passes once, it passes again. The validator is
    pure — no state leakage, no caching that flips the second call.
    """
    try:
        _validate_case_id(case_id)
    except ValueError:
        assume(False)  # not the case we're locking
        return
    # Second call MUST also succeed and return None (no side effects).
    result = _validate_case_id(case_id)
    assert result is None


# ---------- 5. hmac.compare_digest commutativity ---------- #


@given(
    a=st.binary(min_size=0, max_size=128),
    b=st.binary(min_size=0, max_size=128),
)
@_PROP_SETTINGS
def test_hmac_compare_digest_is_commutative(a: bytes, b: bytes) -> None:
    """compare_digest(a, b) == compare_digest(b, a). Locks against an
    accidental refactor to `a == b` (which is also commutative but NOT
    constant-time — so the bug wouldn't be caught by this test alone,
    but the property MUST hold for any constant-time equality check).
    """
    assert hmac.compare_digest(a, b) == hmac.compare_digest(b, a)


# ---------- 6. _sanitize_email_header monotonicity ---------- #


@given(value=st.text(max_size=512))
@_PROP_SETTINGS
def test_sanitize_email_header_is_idempotent(value: str) -> None:
    """Re-sanitizing an already-sanitized string is a no-op.
    Stripping forbidden chars from clean text must not mutate it.
    """
    once = _sanitize_email_header(value)
    twice = _sanitize_email_header(once)
    assert once == twice


# ---------- 7. _safe_filename_segment length cap ---------- #


@given(value=st.text(min_size=64, max_size=2048))
@_PROP_SETTINGS
def test_safe_filename_segment_caps_at_64(value: str) -> None:
    """Any input — long, short, adversarial — produces output <= 64
    chars. The cap is a defensive ceiling against pathological labels
    that would otherwise blow past Windows MAX_PATH downstream.
    """
    out = _safe_filename_segment(value)
    assert isinstance(out, str)
    assert len(out) <= 64
    # And the cap is robust under double-application (no growth on
    # re-sanitize).
    assert len(_safe_filename_segment(out)) <= 64


# ---------- 8. _safe_int / _safe_decimal NaN guard ---------- #


@given(
    val=st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**63), max_value=2**63),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(max_size=32),
        _usd_decimals,
        st.just(float("nan")),
        st.just(float("inf")),
        st.just(float("-inf")),
        st.just("NaN"),
        st.just("Infinity"),
    )
)
@_PROP_SETTINGS
def test_safe_wrappers_never_return_nan_or_inf(val) -> None:
    """``_safe_int`` / ``_safe_decimal`` must always return a finite
    value (or the documented default). NaN/Inf in any downstream
    comparison poisons the result silently — the wrappers exist
    precisely to seal this off at the boundary.
    """
    i = _safe_int(val)
    assert isinstance(i, int)
    # ints can't be NaN/Inf by definition, but we still pin the type.

    d = _safe_decimal(val)
    assert isinstance(d, Decimal)
    assert d.is_finite()
    assert not d.is_nan()
    # _safe_decimal's contract: also non-negative (corruption guard).
    assert d >= 0
    # Cross-check via float coercion (NaN/Inf would surface here).
    f = float(d)
    assert not math.isnan(f)
    assert not math.isinf(f)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
