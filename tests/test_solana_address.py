"""Tests for v0.13.5 Solana address validation.

Real Solana mainnet addresses (verifiable on solscan.io):

  USDC mint (most-traced SPL address):
    EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v

  Wrapped SOL mint:
    So11111111111111111111111111111111111111112

  JitoSOL stake pool:
    J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn
"""

from __future__ import annotations

import pytest

from recupero.chains.solana.address import (
    SolanaAddressError,
    is_solana_address,
    normalize_solana_address,
)


USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
WSOL_MINT = "So11111111111111111111111111111111111111112"
JITOSOL_MINT = "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn"


# ---- is_solana_address ---- #


def test_known_real_addresses_validate() -> None:
    """Three real mainnet addresses. If these fail, the validator
    is broken for normal Solana use."""
    assert is_solana_address(USDC_MINT) is True
    assert is_solana_address(WSOL_MINT) is True
    assert is_solana_address(JITOSOL_MINT) is True


def test_rejects_too_short() -> None:
    assert is_solana_address("abc") is False
    assert is_solana_address("") is False


def test_rejects_too_long() -> None:
    """44 chars is the practical cap; 45+ shouldn't decode to 32 bytes."""
    too_long = "Z" * 50
    assert is_solana_address(too_long) is False


def test_rejects_evm_address() -> None:
    """An EVM address (0x + 40 hex) is the wrong shape, contains
    characters outside base58 alphabet ('0' is not in base58)."""
    evm = "0x" + "a" * 40
    assert is_solana_address(evm) is False


def test_rejects_bitcoin_address() -> None:
    """BTC P2PKH (1...) is base58 but decodes to a different byte
    length (25 vs 32)."""
    btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert is_solana_address(btc) is False


def test_rejects_tron_address() -> None:
    """Tron base58check is 34 chars and decodes to 25 bytes — wrong
    length for a Solana 32-byte pubkey."""
    tron = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    assert is_solana_address(tron) is False


def test_rejects_invalid_base58_char() -> None:
    """0/O/I/l are not in base58 alphabet."""
    # USDC-shape but with an 'O' substituted in
    bad = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTOt1v"
    assert is_solana_address(bad) is False


def test_rejects_non_string() -> None:
    assert is_solana_address(None) is False  # type: ignore[arg-type]
    assert is_solana_address(123) is False  # type: ignore[arg-type]
    assert is_solana_address(b"bytes") is False  # type: ignore[arg-type]


def test_accepts_address_with_leading_ones() -> None:
    """WSOL has many leading '1' characters (corresponding to
    leading zero bytes in the pubkey). This is the edge case that
    tripped up early implementations of base58 decoders."""
    assert is_solana_address(WSOL_MINT) is True


# ---- normalize_solana_address ---- #


def test_normalize_preserves_case() -> None:
    """Base58 is case-sensitive."""
    assert normalize_solana_address(USDC_MINT) == USDC_MINT


def test_normalize_strips_whitespace() -> None:
    """Operators paste from emails — whitespace tolerated."""
    assert normalize_solana_address(f"  {USDC_MINT}  ") == USDC_MINT


def test_normalize_rejects_invalid() -> None:
    with pytest.raises(SolanaAddressError, match="not a valid Solana"):
        normalize_solana_address("not-an-address")
    with pytest.raises(SolanaAddressError, match="not a valid Solana"):
        normalize_solana_address("0x" + "a" * 40)


def test_normalize_rejects_non_string() -> None:
    with pytest.raises(SolanaAddressError, match="must be str"):
        normalize_solana_address(12345)  # type: ignore[arg-type]


def test_normalize_rejects_empty() -> None:
    with pytest.raises(SolanaAddressError):
        normalize_solana_address("")


# ---- Cross-chain disambiguation ---- #


def test_solana_address_distinguishable_from_other_chains() -> None:
    """At the routing boundary, the validators should give clean
    yes/no answers — exactly one chain accepts each address (with
    a few unavoidable overlaps for very short addresses)."""
    # Solana → Tron should reject (length / decoded-byte mismatch)
    from recupero.chains.tron.address import is_tron_base58_address
    assert is_tron_base58_address(USDC_MINT) is False
    # Solana → Bitcoin should reject (decoded-byte mismatch)
    from recupero.chains.bitcoin.address import is_bitcoin_address
    assert is_bitcoin_address(USDC_MINT) is False
    # Bitcoin → Solana should reject
    btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert is_solana_address(btc) is False
