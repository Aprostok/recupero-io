"""Tests for v0.12.0 Tron address utilities.

The single externally-verifiable fixture is the USDT-TRC20 contract:

  base58:  TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
  hex:     41a614f803b6fd780986a42c78ec9c7f77e6ded13c

(Verifiable on tronscan.org — this is the canonical Tron stablecoin
address that traces through ~half of all Tron USDT cases.)

Everything else is round-trip-tested: the algorithm is locked by
the USDT fixture, then we synthesize additional payload bytes and
verify ``base58_to_hex(hex_to_base58(payload)) == payload`` to
catch any byte-distribution-specific bugs.
"""

from __future__ import annotations

import pytest

from recupero.chains.tron.address import (
    TronAddressError,
    base58_to_hex,
    hex_to_base58,
    is_tron_base58_address,
    is_tron_hex_address,
    normalize_tron_address,
)


# ---- hex_to_base58 ---- #


def test_usdt_contract_round_trips() -> None:
    """USDT-TRC20 contract — the most-traced Tron address in the
    entire stack. If this round-trip breaks, USDT laundering
    cases break."""
    hex_addr = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
    b58 = hex_to_base58(hex_addr)
    assert b58 == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    assert base58_to_hex(b58) == hex_addr


def test_synthesized_hex_round_trip() -> None:
    """For a variety of synthetic 20-byte payloads, encoding
    then decoding must return the original hex. The USDT
    fixture above proves the encoder is right; this proves it
    handles arbitrary byte distributions (leading zeros,
    leading 0xff, all-zero except checksum, etc.)."""
    payloads_hex = [
        # All zeros (after prefix). Edge case: leading-zero encoding
        # uses repeated '1' chars in base58.
        "41" + "00" * 20,
        # All 0xff (after prefix).
        "41" + "ff" * 20,
        # Random byte pattern 1.
        "41" + "deadbeefcafebabe0011223344556677889900aa",
        # Random byte pattern 2.
        "41" + "0102030405060708090a0b0c0d0e0f1011121314",
    ]
    for hex_addr in payloads_hex:
        b58 = hex_to_base58(hex_addr)
        assert len(b58) == 34, f"encoded {hex_addr} → wrong length {len(b58)}"
        assert b58.startswith("T"), f"mainnet payload should encode to T... ({b58})"
        recovered = base58_to_hex(b58)
        assert recovered == hex_addr, (
            f"round-trip failed: {hex_addr} → {b58} → {recovered}"
        )


def test_hex_to_base58_accepts_0x_prefix() -> None:
    """TronGrid sometimes returns hex with the ``0x`` prefix; we
    should strip it transparently."""
    with_prefix = "0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
    without = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
    assert hex_to_base58(with_prefix) == hex_to_base58(without)


def test_hex_to_base58_rejects_wrong_length() -> None:
    with pytest.raises(TronAddressError, match="42 chars"):
        hex_to_base58("41a614f803")  # too short
    with pytest.raises(TronAddressError, match="42 chars"):
        hex_to_base58("41a614f803b6fd780986a42c78ec9c7f77e6ded13cdeadbeef")


def test_hex_to_base58_rejects_non_hex() -> None:
    with pytest.raises(TronAddressError, match="hex-decodable"):
        # 42 chars but contains 'z'
        hex_to_base58("4" + "z" * 41)


# ---- base58_to_hex ---- #


def test_base58_to_hex_round_trip() -> None:
    """Encode → decode → encode is identity."""
    hex_addr = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
    encoded = hex_to_base58(hex_addr)
    re_decoded = base58_to_hex(encoded)
    assert re_decoded == hex_addr


def test_base58_to_hex_rejects_wrong_length() -> None:
    with pytest.raises(TronAddressError, match="34 chars"):
        base58_to_hex("TR7NH")  # truncated
    with pytest.raises(TronAddressError, match="34 chars"):
        base58_to_hex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6tEXTRA")


def test_base58_to_hex_rejects_bad_checksum() -> None:
    """Flipping the last character of a valid address breaks the
    checksum. The decoder catches it (this is what protects
    investigators from typos)."""
    # USDT address with the trailing 't' mutated to a different
    # base58 character — should fail checksum.
    bad = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6Z"
    with pytest.raises(TronAddressError, match="checksum mismatch"):
        base58_to_hex(bad)


def test_base58_to_hex_rejects_invalid_char() -> None:
    """Tron base58 alphabet excludes 0, O, I, l. Any of those in
    an address should be flagged."""
    # 'O' (uppercase) is not in the alphabet
    bad = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6O"
    with pytest.raises(TronAddressError):
        base58_to_hex(bad)


# ---- is_tron_*_address ---- #


def test_is_tron_base58_address_valid() -> None:
    assert is_tron_base58_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t") is True
    assert is_tron_base58_address("TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9") is True


def test_is_tron_base58_address_rejects_non_strings_and_wrong_shapes() -> None:
    assert is_tron_base58_address("") is False
    assert is_tron_base58_address("0xa614f803b6fd780986a42c78ec9c7f77e6ded13c") is False
    # EVM-shaped — different length, no 'T' prefix.
    assert is_tron_base58_address("0x" + "a" * 40) is False
    # Right shape but bad checksum.
    assert is_tron_base58_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6Z") is False
    # Not a string at all.
    assert is_tron_base58_address(None) is False  # type: ignore[arg-type]
    assert is_tron_base58_address(12345) is False  # type: ignore[arg-type]


def test_is_tron_hex_address_valid() -> None:
    assert is_tron_hex_address("41a614f803b6fd780986a42c78ec9c7f77e6ded13c") is True
    assert is_tron_hex_address("0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c") is True


def test_is_tron_hex_address_rejects_wrong_length() -> None:
    # EVM-shaped (40 hex chars) — NOT a Tron hex address.
    assert is_tron_hex_address("0x" + "a" * 40) is False
    assert is_tron_hex_address("") is False
    assert is_tron_hex_address("41") is False


# ---- normalize_tron_address ---- #


def test_normalize_passes_through_base58_unchanged() -> None:
    addr = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    assert normalize_tron_address(addr) == addr


def test_normalize_converts_hex_to_base58() -> None:
    assert (
        normalize_tron_address("41a614f803b6fd780986a42c78ec9c7f77e6ded13c")
        == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    )


def test_normalize_rejects_evm_shaped_addresses() -> None:
    """EVM addresses are 40-hex / no Tron prefix — explicitly
    not a Tron address. This prevents accidental cross-chain
    lookups."""
    with pytest.raises(TronAddressError, match="not a Tron"):
        normalize_tron_address("0x" + "a" * 40)
    with pytest.raises(TronAddressError, match="not a Tron"):
        normalize_tron_address("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")


def test_normalize_rejects_bogus_inputs() -> None:
    with pytest.raises(TronAddressError):
        normalize_tron_address("")
    with pytest.raises(TronAddressError):
        normalize_tron_address("hello-world")
