"""Tests for the canonical address-truncation helper.

v0.32.1 cross-cutting polish pass (Jacob audit §3.1). The audit found
17 sites in src/recupero/ each using a slightly different truncation
convention (6+4, 10+6, 10+ellipsis, prefix-only). This module unifies
the rule and these tests pin the contract.
"""

from __future__ import annotations

import pytest

from recupero.util.addr_format import short_address


# ----- Canonical EVM (0x + 40 hex) ----- #


def test_ethereum_canonical_6_4():
    """Default 6+4 truncation, EVM checksum address."""
    addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
    assert short_address(addr) == "0x742d…bEb1"


def test_ethereum_lowercase():
    """Lowercase EVM address truncates identically — case preserved."""
    addr = "0x742d35cc6634c0532925a3b844bc9e7595f0beb1"
    out = short_address(addr)
    assert out == "0x742d…beb1"
    # The truncation is presentation only; no normalization happens.
    assert out.startswith("0x742d")
    assert out.endswith("beb1")


def test_ethereum_zero_address():
    """0x0000…0000 — the canonical EVM null-address."""
    addr = "0x0000000000000000000000000000000000000000"
    assert short_address(addr) == "0x0000…0000"


# ----- Tron (T + 33 base58) ----- #


def test_tron_address():
    """Tron addresses start with 'T' followed by base58 chars."""
    addr = "TXYZopqrSTUVwxyz1234567890abcdefGHIJ"
    assert short_address(addr) == "TXYZop…GHIJ"


# ----- Solana (32+ base58, no prefix) ----- #


def test_solana_address():
    """Solana addresses are base58-encoded 32-byte pubkeys, ~44 chars."""
    addr = "9ARngHhVaCtH5JFieRdSS5Y8cdZk2TMF4tfGSWFB9iSK"
    out = short_address(addr)
    assert out == "9ARngH…9iSK"
    # No 0x prefix to worry about.
    assert not out.startswith("0x")


# ----- Bitcoin (1 / 3 / bc1 prefixes) ----- #


def test_bitcoin_legacy_p2pkh():
    """Legacy P2PKH addresses start with '1'."""
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # Genesis coinbase
    assert short_address(addr) == "1A1zP1…vfNa"


def test_bitcoin_p2sh():
    """P2SH addresses start with '3'."""
    addr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    assert short_address(addr) == "3J98t1…WNLy"


def test_bitcoin_bech32_segwit():
    """Bech32 / SegWit addresses start with 'bc1'."""
    addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    assert short_address(addr) == "bc1qar…5mdq"


# ----- Edge cases ----- #


def test_none_returns_empty_string():
    """None is the legitimate "address unknown" sentinel; it must not crash."""
    assert short_address(None) == ""


def test_empty_string_returns_empty():
    """Empty string short-circuits to empty (template-friendly)."""
    assert short_address("") == ""


def test_already_short_returns_unchanged():
    """Strings below the truncation threshold come back untouched."""
    # prefix(6) + suffix(4) + 1 ellipsis = 11 chars min for a useful trim.
    assert short_address("0xabc") == "0xabc"
    assert short_address("12345") == "12345"
    # Exactly 10 chars — strictly less than 11 → unchanged.
    assert short_address("0x12345678") == "0x12345678"


def test_exactly_at_threshold_truncates():
    """At prefix+suffix+1 (=11), truncation kicks in."""
    # 11 chars: prefix=6, suffix=4 → 6+ellipsis+4 = 11 chars rendered, same
    # length as the input. Helper still truncates here (it's defined as
    # "len >= prefix+suffix+1") to keep the rule predictable; the
    # rendered form simply has the same length as the source for the
    # edge case.
    addr = "0x12345abcde"
    assert short_address(addr) == "0x1234…bcde"


def test_long_string_truncates_normally():
    """A pathologically long string (>>40 chars) still truncates to 6+4."""
    addr = "0x" + "deadbeef" * 20  # 162 chars
    out = short_address(addr)
    assert out == "0xdead…beef"
    assert len(out) == 6 + 1 + 4  # prefix + 1 ellipsis char + suffix


# ----- Custom prefix/suffix (presentation flexibility) ----- #


def test_custom_prefix_suffix():
    """Caller can request a different prefix/suffix size."""
    addr = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
    # Slice semantics: addr[:8] + … + addr[-6:]. The "0x" is counted
    # in the prefix slice, so prefix=8 => "0xABCDEF" and suffix=6 =>
    # the last 6 chars "CDEF12".
    assert short_address(addr, prefix=8, suffix=6) == "0xABCDEF…CDEF12"


def test_zero_suffix():
    """suffix=0 yields prefix-only output (no tail)."""
    addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
    out = short_address(addr, prefix=10, suffix=0)
    # Slice semantics: addr[:10] (the "0x" is counted in the prefix) +
    # … + no tail. addr[:10] == "0x742d35Cc".
    assert out == "0x742d35Cc…"


def test_negative_prefix_raises():
    """Defensive: negative prefix/suffix is a programmer error."""
    with pytest.raises(ValueError):
        short_address("0xdeadbeef", prefix=-1)
    with pytest.raises(ValueError):
        short_address("0xdeadbeef", suffix=-1)


# ----- ASCII-safe ellipsis ----- #


def test_ascii_safe_uses_three_dots():
    """ascii_safe=True replaces unicode … with three ASCII dots.

    Used by environments whose font lacks U+2026 (some legacy PDF
    renderers). _pdf_links.py registers BOTH the unicode and ASCII
    forms as link-text matching candidates.
    """
    addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
    out = short_address(addr, ascii_safe=True)
    assert out == "0x742d...bEb1"
    assert "…" not in out


# ----- Cross-artifact consistency (the audit's headline complaint) ----- #


def test_cross_artifact_consistency():
    """The same address must truncate identically everywhere.

    Brief, LE handoff, freeze letter, log emitter, operator alert email:
    if short_address(X) returned different values in any two of them,
    operators could not cross-reference the artifacts. Pin the rule.
    """
    addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
    a = short_address(addr)
    b = short_address(addr)
    c = short_address(addr)
    assert a == b == c
    # And the canonical _common.short_addr delegates to us — so the
    # legacy callers are wired through too.
    from recupero._common import short_addr
    assert short_addr(addr) == short_address(addr)


def test_jinja_filter_registration():
    """The Jinja filter wrapper renders identically to the function."""
    from jinja2 import Environment
    from recupero.reports._jinja_filters import register_safe_filters

    env = Environment(autoescape=True)
    register_safe_filters(env)
    tmpl = env.from_string("{{ addr | short_address }}")
    addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
    rendered = tmpl.render(addr=addr)
    assert rendered == short_address(addr)


def test_jinja_filter_none_renders_empty():
    """Filter must not crash on None (template-safe)."""
    from jinja2 import Environment
    from recupero.reports._jinja_filters import register_safe_filters

    env = Environment(autoescape=True)
    register_safe_filters(env)
    tmpl = env.from_string("{{ addr | short_address }}")
    assert tmpl.render(addr=None) == ""
