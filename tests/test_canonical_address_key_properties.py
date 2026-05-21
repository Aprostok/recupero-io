"""Property-based tests for canonical_address_key.

``canonical_address_key`` is used everywhere address dedup matters:
trace.risk_scoring, screen.screener, trace.correlation, dormant.finder,
brief.py, _flow_diagram.py, etc. A bug here causes silent
under-counting: two views of the same wallet (different case forms,
checksum variants) hash to different keys and the dedup misses the
collision.

These tests probe ALGEBRAIC properties:

  * Idempotence: canonical(canonical(x)) == canonical(x). The function
    is a normalizer — applying it twice must be a no-op.
  * Case-insensitive for EVM: any case mutation of `0x{40 hex}` is
    canonicalized to the same lowercase form. EIP-55 checksum
    addresses MUST dedupe with their lowercase counterparts.
  * Case-PRESERVING for base58 / bech32 / anything else: lowercasing
    a Solana / Tron address SILENTLY CORRUPTS the address because
    base58 IS case-sensitive on-chain.
  * Empty / None safety: None / non-str / whitespace-only → "".
  * No crash on adversarial unicode / control chars.
"""

from __future__ import annotations

import string

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recupero._common import canonical_address_key


_SETTINGS = settings(
    max_examples=300,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


# ═════════════════════════════════════════════════════════════════════════════
# Strategies
# ═════════════════════════════════════════════════════════════════════════════


def _hex_char_strategy(want_upper: bool = False) -> st.SearchStrategy[str]:
    """Single hex char (0-9, a-f or A-F)."""
    if want_upper:
        return st.sampled_from(list("0123456789ABCDEF"))
    return st.sampled_from(list("0123456789abcdef"))


def _evm_address_lower_strategy() -> st.SearchStrategy[str]:
    """A well-formed EVM address (0x + 40 lowercase hex)."""
    return st.builds(
        lambda chars: "0x" + "".join(chars),
        st.lists(_hex_char_strategy(False), min_size=40, max_size=40),
    )


def _evm_address_mixed_case_strategy() -> st.SearchStrategy[str]:
    """A well-formed EVM address with arbitrary case mix (EIP-55-shaped
    but not validated against the checksum). Mix of upper + lower hex."""
    return st.builds(
        lambda chars: "0x" + "".join(chars),
        st.lists(
            st.sampled_from(list("0123456789abcdefABCDEF")),
            min_size=40, max_size=40,
        ),
    )


def _base58_address_strategy() -> st.SearchStrategy[str]:
    """A base58-shaped string (Bitcoin/Solana/Tron). Base58 alphabet
    excludes 0, O, I, l. Case is significant — uppercase and lowercase
    glyphs encode different bytes."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return st.builds(
        lambda chars: "".join(chars),
        st.lists(st.sampled_from(list(alphabet)),
                 min_size=32, max_size=44),
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 1: idempotence
# ═════════════════════════════════════════════════════════════════════════════


@given(addr=st.one_of(
    _evm_address_lower_strategy(),
    _evm_address_mixed_case_strategy(),
    _base58_address_strategy(),
    st.text(min_size=0, max_size=64),
))
@_SETTINGS
def test_property_canonical_address_key_is_idempotent(addr: str) -> None:
    """canonical(canonical(x)) == canonical(x) for any input.

    This is the most fundamental property of a normalizer. If it
    fails, the function is doing something other than normalization
    — likely producing intermediate forms that drift on repeated
    application, which would cause non-determinism downstream.
    """
    once = canonical_address_key(addr)
    twice = canonical_address_key(once)
    assert once == twice, (
        f"NOT idempotent: canonical({addr!r}) = {once!r}, "
        f"canonical({once!r}) = {twice!r}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 2: EVM addresses are case-insensitive
# ═════════════════════════════════════════════════════════════════════════════


@given(lower=_evm_address_lower_strategy())
@_SETTINGS
def test_property_evm_lowercase_and_uppercase_dedup(lower: str) -> None:
    """An EVM address in EIP-55 (mixed-case) or fully-upper form must
    canonicalize to the same key as the fully-lower form. Otherwise
    a checksum-cased Etherscan paste and a raw-hex paste of the same
    wallet are seen as different addresses → dedup breaks."""
    upper = "0x" + lower[2:].upper()
    # Sprinkle case-mix variant: ah-ha-half-half.
    mid_chars = list(lower[2:])
    for i in range(0, len(mid_chars), 2):
        mid_chars[i] = mid_chars[i].upper()
    mixed = "0x" + "".join(mid_chars)

    k_lower = canonical_address_key(lower)
    k_upper = canonical_address_key(upper)
    k_mixed = canonical_address_key(mixed)

    assert k_lower == k_upper == k_mixed, (
        f"EVM address dedup broken:\n"
        f"  lower {lower!r} → {k_lower!r}\n"
        f"  upper {upper!r} → {k_upper!r}\n"
        f"  mixed {mixed!r} → {k_mixed!r}"
    )
    # And the canonical form should be the all-lowercase variant.
    assert k_lower == lower.lower()


# ═════════════════════════════════════════════════════════════════════════════
# Property 3: non-EVM addresses preserve case
# ═════════════════════════════════════════════════════════════════════════════


@given(addr=_base58_address_strategy())
@_SETTINGS
def test_property_base58_addresses_preserve_case(addr: str) -> None:
    """Base58 encodings (Bitcoin, Solana, Tron) are case-sensitive on-
    chain — uppercase and lowercase glyphs encode different bytes.
    canonical_address_key MUST NOT lowercase a base58 string.

    The function distinguishes "EVM" by the shape (0x + exactly 40
    hex chars). Anything else, including 32-44-char base58 strings,
    must pass through verbatim (after whitespace strip).
    """
    # Filter: skip strings that happen to look like a valid EVM
    # address (starts with "0x" + 40 hex). Base58 doesn't usually
    # start with "0x" so this is rare but worth assuming away.
    if addr.startswith("0x") and len(addr) == 42:
        from hypothesis import assume
        assume(False)
        return
    result = canonical_address_key(addr)
    assert result == addr.strip(), (
        f"base58 address case mutated: {addr!r} → {result!r}. "
        "Base58 IS case-sensitive on-chain; lowercasing changes the "
        "underlying bytes."
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 4: malformed "0x"-prefixed strings DON'T silently get
# lowercased
# ═════════════════════════════════════════════════════════════════════════════


@given(non_hex_chars=st.lists(
    st.sampled_from(list("ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ_-+@")),
    min_size=1, max_size=40,
))
@_SETTINGS
def test_property_malformed_0x_string_is_not_lowercased(
    non_hex_chars: list[str],
) -> None:
    """A 42-char string starting with `0x` but containing non-hex
    characters should NOT be silently lowercased and treated as a
    valid EVM canonical key.

    Pre-v0.20.10 the function would `.lower()` any 42-char-0x-prefix
    string. A malformed paste like `0xGGGG...` would be returned
    lowercased as if valid → silent corruption of dedup state.
    Fix asserts on actual hex content.
    """
    # Build a 42-char "0x" + 40-char string that contains AT LEAST
    # ONE non-hex character.
    rest = list("a" * (40 - len(non_hex_chars))) + non_hex_chars
    rest = rest[:40]
    # Make sure we still have at least 1 non-hex char in there.
    has_nonhex = any(
        c.lower() not in "0123456789abcdef" for c in rest
    )
    if not has_nonhex:
        from hypothesis import assume
        assume(False)
        return
    addr = "0x" + "".join(rest)
    # Make sure there's a SPECIFICALLY uppercase non-hex char so we
    # can verify case preservation.
    if not any(c.isupper() and c.lower() not in "0123456789abcdef"
               for c in rest):
        # Force at least one uppercase non-hex
        addr = "0x" + "Z" + "".join(rest[1:])

    result = canonical_address_key(addr)
    # If the function correctly recognized this as malformed and
    # passed-through verbatim, the uppercase letter survives.
    # If the function incorrectly lowercased it, we've found a bug.
    assert result == addr.strip(), (
        f"malformed 0x-string was silently lowercased: {addr!r} → "
        f"{result!r}. Dedup state can be corrupted by feeding it "
        "an attacker-controlled (or operator-typo'd) string."
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 5: None / non-str inputs return ""
# ═════════════════════════════════════════════════════════════════════════════


@given(non_string=st.one_of(
    st.none(),
    st.integers(),
    st.floats(),
    st.binary(),
    st.lists(st.integers(), max_size=5),
    st.tuples(st.integers(), st.integers()),
))
@_SETTINGS
def test_property_non_string_input_returns_empty(non_string: object) -> None:
    """Anything that isn't a `str` must canonicalize to "". Defensive
    against accidental dict-key uses where the upstream value type
    drifts (e.g., bytes from a stream, None from a missing column)."""
    result = canonical_address_key(non_string)  # type: ignore[arg-type]
    assert result == "", (
        f"canonical_address_key({non_string!r}) returned {result!r}; "
        "expected ''. Non-string input is a defensive-shape failure "
        "if not handled."
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 6: leading / trailing whitespace stripped without affecting
# the canonical form
# ═════════════════════════════════════════════════════════════════════════════


@given(addr=_evm_address_lower_strategy(),
       padding=st.text(
           alphabet=" \t\n\r",
           min_size=0, max_size=8,
       ))
@_SETTINGS
def test_property_whitespace_padding_stripped(
    addr: str, padding: str,
) -> None:
    """Whitespace around the input must not change the canonical
    form. Operators paste addresses with copy-paste artifacts."""
    padded_addr = f"{padding}{addr}{padding}"
    assert canonical_address_key(padded_addr) == \
        canonical_address_key(addr), (
        f"whitespace padding changed canonical key: "
        f"{padded_addr!r} → {canonical_address_key(padded_addr)!r}, "
        f"{addr!r} → {canonical_address_key(addr)!r}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 7: garbage unicode never crashes
# ═════════════════════════════════════════════════════════════════════════════


@given(garbage=st.text(
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd", "Pc", "Sm", "Cc",
                              "Po", "Sk"),
        max_codepoint=0x10FFFF,
    ),
    min_size=0, max_size=200,
))
@_SETTINGS
def test_property_garbage_input_never_raises(garbage: str) -> None:
    """No adversarial unicode / control char / homoglyph can cause
    canonical_address_key to raise. It's a normalizer; "garbage in,
    garbage out" is the contract — but it must NEVER throw."""
    try:
        canonical_address_key(garbage)
    except Exception as e:  # noqa: BLE001
        pytest.fail(
            f"canonical_address_key raised {type(e).__name__} on "
            f"input {garbage!r}: {e}"
        )
