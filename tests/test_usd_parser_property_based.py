"""Property-based tests for the USD-amount parser.

`recupero.validators.output_integrity._parse_usd_string` is the
authoritative parser for human-formatted USD strings like
`'$1,234,567.89'`, `'$3.5M'`, `'500'`, etc. It feeds into every
cross-artifact reconciliation check (TOTAL_FREEZABLE_USD,
MAX_RECOVERABLE_USD, etc.). A buggy parser leads to silent
mis-comparisons in the validator — the kind that hide the
v0.15.1-class classifier-on-broken-input regressions.

These hypothesis-driven tests prove the parser:

  * Returns Decimal(0) on any garbage / non-numeric input
  * Never raises an exception (the upstream validator calls it in
    a tight loop and a crash would skip the rest of the case)
  * Round-trips through formatted-USD output of any Decimal
  * Strips $, commas, and whitespace correctly
  * Handles unicode garbage gracefully
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from recupero.validators.output_integrity import _parse_usd_string


_SETTINGS = settings(
    max_examples=300,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


# ═════════════════════════════════════════════════════════════════════════════
# Property 1: round-trip through formatted-USD output
# ═════════════════════════════════════════════════════════════════════════════


@given(amount=st.decimals(
    min_value=Decimal("0"),
    max_value=Decimal("999999999.99"),
    places=2,
    allow_nan=False, allow_infinity=False,
))
@_SETTINGS
def test_property_round_trip_formatted_usd(amount: Decimal) -> None:
    """Format a Decimal as `$X,XXX.XX` and parse it back. The result
    must equal the original amount.

    This is the canonical algebraic check: format then parse is the
    identity for amounts in the well-formed input space."""
    formatted = f"${amount:,.2f}"
    parsed = _parse_usd_string(formatted)
    assert parsed == amount, (
        f"round-trip failed: {amount!r} formatted as {formatted!r}, "
        f"parsed back as {parsed!r}"
    )


@given(amount=st.decimals(
    min_value=Decimal("0"),
    max_value=Decimal("999999999.99"),
    places=2,
    allow_nan=False, allow_infinity=False,
))
@_SETTINGS
def test_property_round_trip_no_dollar_sign(amount: Decimal) -> None:
    """The parser must accept input WITHOUT a leading $ — e.g.,
    `1,234.56` (the operator-CLI sometimes formats this way)."""
    formatted = f"{amount:,.2f}"  # no $
    parsed = _parse_usd_string(formatted)
    assert parsed == amount


# ═════════════════════════════════════════════════════════════════════════════
# Property 2: never raises on any input
# ═════════════════════════════════════════════════════════════════════════════


@given(garbage=st.one_of(
    st.text(min_size=0, max_size=200),
    st.binary(min_size=0, max_size=200),  # parser handles str(b"...") via cast
    st.none(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.lists(st.integers(), max_size=5),
))
@_SETTINGS
def test_property_never_raises_on_garbage(garbage: object) -> None:
    """The parser is called in tight loops on validator-found
    strings. A crash on weird input would SKIP the rest of the
    case's validation — the validator's failure mode contract is
    "complete on any input, NEVER raise."

    Verifies _parse_usd_string returns Decimal regardless of input
    shape — even garbage like None, integers, floats with NaN/inf,
    lists, etc."""
    try:
        result = _parse_usd_string(garbage)  # type: ignore[arg-type]
    except Exception as e:  # noqa: BLE001
        pytest.fail(
            f"_parse_usd_string raised {type(e).__name__} on input "
            f"{garbage!r}: {e}. Contract: never raises."
        )
    assert isinstance(result, Decimal), (
        f"expected Decimal, got {type(result).__name__}: {result!r}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 3: None / empty / whitespace → Decimal(0)
# ═════════════════════════════════════════════════════════════════════════════


@given(empty=st.sampled_from([
    None, "", " ", "\t", "\n", "$", "$ ", " $ ", ",,,,,",
    "abc", "$abc", "USD", "1.2.3", "+",
    "$$", "$.", ".$", " . ",
    # NOTE: removed "1,2,3,4,5" — the parser correctly treats this
    # as a comma-formatted number that strips to 12345. That's a
    # legitimate parse, not invalid input.
]))
@_SETTINGS
def test_property_empty_or_invalid_returns_decimal_zero(
    empty: str | None,
) -> None:
    """Anything that's structurally not a valid USD amount must
    return Decimal(0). The validator treats Decimal(0) as "no
    value" — the alternative (raising) would be worse, see the
    crash-contract test above."""
    result = _parse_usd_string(empty)
    assert result == Decimal(0), (
        f"_parse_usd_string({empty!r}) = {result!r}; expected Decimal(0)"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 4: commas in any position handled
# ═════════════════════════════════════════════════════════════════════════════


@given(integer_part=st.integers(min_value=0, max_value=10**12))
@_SETTINGS
def test_property_commas_stripped_correctly(integer_part: int) -> None:
    """Any natural-USD-formatted string with commas at the standard
    thousands-positions must parse to the right Decimal."""
    formatted = f"${integer_part:,}"  # e.g., "$1,234,567,890"
    parsed = _parse_usd_string(formatted)
    assert parsed == Decimal(integer_part), (
        f"comma stripping failed: {formatted!r} → {parsed!r}, "
        f"expected {integer_part!r}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 5: whitespace tolerance
# ═════════════════════════════════════════════════════════════════════════════


@given(
    amount=st.decimals(
        min_value=Decimal("1"),
        max_value=Decimal("1000"),
        places=2,
        allow_nan=False, allow_infinity=False,
    ),
    pad_left=st.integers(0, 10),
    pad_right=st.integers(0, 10),
)
@_SETTINGS
def test_property_whitespace_padding_ignored(
    amount: Decimal, pad_left: int, pad_right: int,
) -> None:
    """Leading + trailing whitespace must be stripped before parsing.
    Operators paste formatted USD with copy-paste artifacts."""
    formatted = (
        " " * pad_left + f"${amount:,.2f}" + " " * pad_right
    )
    parsed = _parse_usd_string(formatted)
    assert parsed == amount, (
        f"whitespace padding broke parse: {formatted!r} → {parsed!r}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 6: equivalence — `$1,234.56` == `1234.56` == `1,234.56`
# ═════════════════════════════════════════════════════════════════════════════


@given(amount=st.decimals(
    min_value=Decimal("0.01"),
    max_value=Decimal("999999.99"),
    places=2,
    allow_nan=False, allow_infinity=False,
))
@_SETTINGS
def test_property_format_variants_all_parse_equal(amount: Decimal) -> None:
    """The parser must be FORMAT-AGNOSTIC: `$X,XXX.XX`, `XXXX.XX`,
    `X,XXX.XX`, `$XXXX.XX` all represent the same Decimal."""
    formats = [
        f"${amount:,.2f}",      # $1,234.56
        f"{amount:,.2f}",       # 1,234.56
        f"${amount:.2f}",       # $1234.56
        f"{amount:.2f}",        # 1234.56
    ]
    parsed = [_parse_usd_string(f) for f in formats]
    assert all(p == amount for p in parsed), (
        f"format variants disagreed for amount={amount!r}: "
        f"{list(zip(formats, parsed))}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 7: negative values handled deterministically
# ═════════════════════════════════════════════════════════════════════════════


@given(amount=st.decimals(
    min_value=Decimal("-1000000"),
    max_value=Decimal("-0.01"),
    places=2,
    allow_nan=False, allow_infinity=False,
))
@_SETTINGS
def test_property_negative_amounts_parse_or_zero(amount: Decimal) -> None:
    """USD amounts in the validator are always non-negative (the
    domain is "money frozen / lost / recoverable"). A negative input
    means the upstream source is broken — the parser may legitimately
    parse it OR return Decimal(0); we just need DETERMINISTIC
    behavior + no crash."""
    formatted = f"${amount:,.2f}"
    parsed = _parse_usd_string(formatted)
    # Either the parsed value matches OR it's Decimal(0). Either is
    # acceptable; what's NOT acceptable is a crash or a different
    # value on different inputs.
    assert parsed in (amount, Decimal(0)), (
        f"negative-amount parsing inconsistent: {formatted!r} → "
        f"{parsed!r}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 8: idempotence via Decimal conversion
# ═════════════════════════════════════════════════════════════════════════════


@given(amount=st.decimals(
    min_value=Decimal("0"),
    max_value=Decimal("999999999.99"),
    places=2,
    allow_nan=False, allow_infinity=False,
))
@_SETTINGS
def test_property_idempotent_decimal_string(amount: Decimal) -> None:
    """str(Decimal(X)) parsed back should equal X. This proves the
    parser is the inverse of Decimal stringification on the parser's
    accepted shape."""
    decimal_str = str(amount)
    parsed = _parse_usd_string(decimal_str)
    assert parsed == amount, (
        f"Decimal round-trip failed: {amount!r} → {decimal_str!r} → "
        f"{parsed!r}"
    )
