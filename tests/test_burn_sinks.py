"""Tests for burn-sink classification (v0.32.1 trace gap E)."""

from __future__ import annotations

from recupero.trace.burn_sinks import (
    BURN_SINKS,
    classify_outflow,
    is_burn_sink,
)


# ---- EVM zero / dead addresses ---- #


def test_ethereum_zero_address_is_burn() -> None:
    assert is_burn_sink(
        "0x0000000000000000000000000000000000000000", "ethereum"
    ) is True


def test_ethereum_dead_address_is_burn() -> None:
    assert is_burn_sink(
        "0x000000000000000000000000000000000000dead", "ethereum"
    ) is True


def test_ethereum_dead_address_case_insensitive() -> None:
    """EVM lookup is case-insensitive."""
    assert is_burn_sink(
        "0x000000000000000000000000000000000000DEAD", "ethereum"
    ) is True
    assert is_burn_sink(
        "0x000000000000000000000000000000000000DeAd", "ethereum"
    ) is True


def test_eth2_deposit_contract_is_burn() -> None:
    """Pre-Pectra eth2 deposit contract → burn."""
    assert is_burn_sink(
        "0x00000000219ab540356cBB839Cbe05303d7705Fa", "ethereum"
    ) is True


def test_polygon_inherits_evm_burn_set() -> None:
    """Same EVM burn set on Polygon."""
    assert is_burn_sink(
        "0x000000000000000000000000000000000000dead", "polygon"
    ) is True


# ---- Solana / Tron / Bitcoin ---- #


def test_solana_incinerator_is_burn() -> None:
    assert is_burn_sink(
        "1nc1nerator11111111111111111111111111111111", "solana"
    ) is True


def test_solana_incinerator_case_sensitive() -> None:
    """Solana is case-sensitive — wrong case → not a burn."""
    assert is_burn_sink(
        "1NC1NERATOR11111111111111111111111111111111", "solana"
    ) is False


def test_tron_burn_address_is_burn() -> None:
    assert is_burn_sink(
        "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb", "tron"
    ) is True


def test_tron_burn_case_sensitive() -> None:
    """Lowercased Tron address → not a match."""
    assert is_burn_sink(
        "t9yd14nj9j7xab4dbgeix9h8unkkhxuwwb", "tron"
    ) is False


def test_bitcoin_eater_is_burn() -> None:
    assert is_burn_sink(
        "1BitcoinEaterAddressDontSendf59kuE", "bitcoin"
    ) is True


# ---- Cross-chain mismatch rejection ---- #


def test_tron_burn_on_ethereum_chain_is_not_burn() -> None:
    """Tron base58 string on chain='ethereum' → not a burn (cross-chain
    type confusion guard)."""
    assert is_burn_sink(
        "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb", "ethereum"
    ) is False


def test_evm_zero_on_solana_is_not_burn() -> None:
    """EVM hex string on chain='solana' → not a burn."""
    assert is_burn_sink(
        "0x0000000000000000000000000000000000000000", "solana"
    ) is False


# ---- classify_outflow ---- #


def test_classify_outflow_burn() -> None:
    t = {
        "to": "0x000000000000000000000000000000000000dead",
        "chain": "ethereum",
    }
    assert classify_outflow(t) == "burn"


def test_classify_outflow_normal() -> None:
    t = {
        "to": "0x1234567890abcdef1234567890abcdef12345678",
        "chain": "ethereum",
    }
    assert classify_outflow(t) == "normal"


def test_classify_outflow_to_address_field() -> None:
    """Accepts 'to_address' alias."""
    t = {
        "to_address": "0x0000000000000000000000000000000000000000",
        "chain": "ethereum",
    }
    assert classify_outflow(t) == "burn"


def test_classify_outflow_missing_chain() -> None:
    """No chain → normal (no crash)."""
    assert classify_outflow({"to": "0x0"}) == "normal"


def test_classify_outflow_garbage_input() -> None:
    """None / non-dict → normal."""
    assert classify_outflow(None) == "normal"
    assert classify_outflow("not a dict") == "normal"  # type: ignore[arg-type]
    assert classify_outflow({}) == "normal"


# ---- Registry sanity ---- #


def test_burn_sinks_dict_exposes_canonical_chains() -> None:
    """Public BURN_SINKS dict has entries for the chains we ship."""
    for chain in ("ethereum", "solana", "tron", "bitcoin"):
        assert chain in BURN_SINKS
        assert len(BURN_SINKS[chain]) >= 1


def test_evm_burn_set_has_at_least_six_entries() -> None:
    """Sanity: we've enumerated zero + dead + variants + eth2 + tornado100 + ..."""
    assert len(BURN_SINKS["ethereum"]) >= 6
