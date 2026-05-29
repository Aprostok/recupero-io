"""Tests for wrap/unwrap pair recognition (v0.32.1 trace gap F)."""

from __future__ import annotations

from recupero.trace.wrap_unwrap import (
    WRAPPER_CONTRACTS,
    is_wrap_unwrap,
)

# Helpers


def _u256_hex(n: int) -> str:
    """32-byte big-endian hex (no 0x prefix)."""
    return n.to_bytes(32, "big").hex()


# ---- Wrap cases ---- #


def test_weth_deposit_recognized() -> None:
    """ETH → WETH via deposit() with 1 ETH value."""
    tx = {
        "to": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "input": "0xd0e30db0",
        "value": 10**18,  # 1 ETH
        "chain": "ethereum",
    }
    ev = is_wrap_unwrap(tx)
    assert ev is not None
    assert ev.direction == "wrap"
    assert ev.input_asset == "ETH"
    assert ev.output_asset == "WETH"
    assert ev.amount == 10**18


def test_weth_withdraw_recognized() -> None:
    """WETH → ETH via withdraw(amount)."""
    amount = 5 * 10**17  # 0.5 ETH
    tx = {
        "to": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "input": "0x2e1a7d4d" + _u256_hex(amount),
        "value": 0,
        "chain": "ethereum",
    }
    ev = is_wrap_unwrap(tx)
    assert ev is not None
    assert ev.direction == "unwrap"
    assert ev.input_asset == "WETH"
    assert ev.output_asset == "ETH"
    assert ev.amount == amount


def test_wmatic_wrap_recognized() -> None:
    """Polygon native MATIC → WMATIC."""
    tx = {
        "to": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
        "input": "0xd0e30db0",
        "value": 2 * 10**18,
        "chain": "polygon",
    }
    ev = is_wrap_unwrap(tx)
    assert ev is not None
    assert ev.input_asset == "MATIC"
    assert ev.output_asset == "WMATIC"


def test_wbnb_wrap_recognized() -> None:
    tx = {
        "to": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
        "input": "0xd0e30db0",
        "value": 10**18,
        "chain": "bsc",
    }
    ev = is_wrap_unwrap(tx)
    assert ev is not None
    assert ev.output_asset == "WBNB"


def test_steth_submit_recognized() -> None:
    """ETH → stETH via Lido submit(address)."""
    tx = {
        "to": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
        "input": "0xa1903eab" + "00" * 32,  # submit(referral=0)
        "value": 10**18,
        "chain": "ethereum",
    }
    ev = is_wrap_unwrap(tx)
    assert ev is not None
    assert ev.output_asset == "stETH"
    assert ev.direction == "wrap"


def test_wsteth_wrap_recognized() -> None:
    """stETH → wstETH (amount from calldata, no native value)."""
    amount = 3 * 10**18
    tx = {
        "to": "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0",
        "input": "0xea598cb0" + _u256_hex(amount),
        "value": 0,
        "chain": "ethereum",
    }
    ev = is_wrap_unwrap(tx)
    assert ev is not None
    assert ev.input_asset == "stETH"
    assert ev.output_asset == "wstETH"
    assert ev.amount == amount


# ---- Negative / defensive cases ---- #


def test_unknown_contract_returns_none() -> None:
    """to address is not a wrapper → None."""
    tx = {
        "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "input": "0xd0e30db0",
        "value": 10**18,
        "chain": "ethereum",
    }
    assert is_wrap_unwrap(tx) is None


def test_unknown_selector_returns_none() -> None:
    """Wrapper contract but unknown selector → None."""
    tx = {
        "to": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "input": "0xdeadbeef",
        "value": 0,
        "chain": "ethereum",
    }
    assert is_wrap_unwrap(tx) is None


def test_unknown_chain_returns_none() -> None:
    tx = {
        "to": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "input": "0xd0e30db0",
        "value": 10**18,
        "chain": "moonbeam",
    }
    assert is_wrap_unwrap(tx) is None


def test_malformed_input_returns_none() -> None:
    """Garbage shapes → None, no crash."""
    assert is_wrap_unwrap(None) is None
    assert is_wrap_unwrap({}) is None
    assert is_wrap_unwrap({"to": None, "chain": None}) is None
    # Truncated calldata for withdraw → no amount → None
    tx = {
        "to": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "input": "0x2e1a7d4d",  # no amount arg
        "value": 0,
        "chain": "ethereum",
    }
    assert is_wrap_unwrap(tx) is None


def test_zero_value_wrap_returns_none() -> None:
    """deposit() with value=0 and no fallback calldata amount → None."""
    tx = {
        "to": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "input": "0xd0e30db0",
        "value": 0,
        "chain": "ethereum",
    }
    assert is_wrap_unwrap(tx) is None


def test_wrapper_table_coverage() -> None:
    """Sanity: every documented chain has at least one wrapper."""
    for chain in ("ethereum", "polygon", "bsc", "avalanche", "fantom"):
        assert chain in WRAPPER_CONTRACTS
        assert len(WRAPPER_CONTRACTS[chain]) >= 1
