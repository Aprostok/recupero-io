"""Tests for v0.13.0 BitcoinAdapter.

EsploraClient is mocked at the method level — these tests verify
the UTXO peel-chain heuristic in isolation. The fixtures are
real-shape Esplora responses synthesized from blockstream.info /
mempool.space schemas.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from recupero.chains.bitcoin.adapter import BitcoinAdapter
from recupero.chains.bitcoin.esplora import EsploraError
from recupero.models import Chain


VICTIM = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
PERP = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
CHANGE_TO_VICTIM = VICTIM  # change goes back to sender
THIRD_PARTY = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"


def _mk_tx(
    *,
    txid: str = "tx_001",
    inputs: list[tuple[str, int]] | None = None,
    outputs: list[tuple[str, int]] | None = None,
    confirmed: bool = True,
    block_height: int = 800_000,
    block_time: int = 1700_000_000,
) -> dict:
    """Build a minimal Esplora-shaped tx.

    inputs/outputs as ``(address, value_satoshi)`` tuples.
    """
    inputs = inputs or [(VICTIM, 100_000)]
    outputs = outputs or [(PERP, 90_000)]
    return {
        "txid": txid,
        "version": 1,
        "vin": [
            {
                "prevout": {
                    "scriptpubkey_address": addr,
                    "value": value,
                },
            }
            for addr, value in inputs
        ],
        "vout": [
            {
                "scriptpubkey_address": addr,
                "value": value,
            }
            for addr, value in outputs
        ],
        "status": {
            "confirmed": confirmed,
            "block_height": block_height,
            "block_time": block_time,
            "block_hash": "abcdef" * 10,
        },
    }


def _mk_adapter(txs: list[dict] | None = None) -> BitcoinAdapter:
    client = MagicMock()
    client.get_address_txs.return_value = txs or []
    return BitcoinAdapter(client=client)


# ---- fetch_native_outflows (peel-chain) ---- #


def test_simple_one_to_one_payment() -> None:
    """VICTIM → PERP, no change. One Transfer record."""
    tx = _mk_tx(
        inputs=[(VICTIM, 100_000)],
        outputs=[(PERP, 90_000)],  # 10k = fee
    )
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    rec = out[0]
    assert rec["chain"] == Chain.bitcoin
    assert rec["from"] == VICTIM
    assert rec["to"] == PERP
    assert rec["amount_raw"] == 90_000
    assert rec["token"].symbol == "BTC"
    assert rec["token"].decimals == 8
    assert "mempool.space" in rec["explorer_url"]


def test_payment_with_change_excludes_change_output() -> None:
    """VICTIM → PERP + change back to VICTIM. Only the PERP send
    becomes a Transfer; the change output is filtered."""
    tx = _mk_tx(
        inputs=[(VICTIM, 1_000_000)],
        outputs=[
            (PERP, 250_000),         # send
            (CHANGE_TO_VICTIM, 740_000),  # change
        ],
    )
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["to"] == PERP
    assert out[0]["amount_raw"] == 250_000


def test_payment_with_two_recipients_both_sends() -> None:
    """VICTIM → PERP1 + PERP2 (no overlap with inputs). Both
    outputs are sends → 2 Transfer records."""
    tx = _mk_tx(
        inputs=[(VICTIM, 1_000_000)],
        outputs=[
            (PERP, 400_000),
            (THIRD_PARTY, 590_000),
        ],
    )
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    addrs = {r["to"] for r in out}
    assert addrs == {PERP, THIRD_PARTY}
    assert len(out) == 2


def test_multi_input_uses_first_input_as_canonical_from() -> None:
    """If victim consolidates 2 UTXOs (both their own), the
    Transfer uses the FIRST input address as the canonical from.
    Important: even though multiple inputs were spent, only one
    Transfer per send-output is emitted to match the from→to data
    model."""
    other_victim_addr = "1HysioKHnUMzVNquWUL3yiKpcW1pPLnMSp"  # synthetic
    tx = _mk_tx(
        inputs=[(VICTIM, 500_000), (other_victim_addr, 500_000)],
        outputs=[(PERP, 990_000)],
    )
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["from"] == VICTIM  # first input wins


def test_address_not_in_inputs_returns_no_transfers() -> None:
    """If a tx's inputs don't include the queried address, no
    Transfers are produced for it (defensive — Esplora might
    return a tx where the address only appears as an output)."""
    tx = _mk_tx(
        inputs=[(THIRD_PARTY, 1_000_000)],
        outputs=[(VICTIM, 990_000)],  # victim is RECEIVING, not sending
    )
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert out == []


def test_unconfirmed_tx_skipped() -> None:
    """Mempool / unconfirmed txs are not traceable until they
    confirm — skip without producing Transfers."""
    tx = _mk_tx(confirmed=False)
    tx["status"]["block_height"] = None
    tx["status"]["block_time"] = None
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert out == []


def test_op_return_outputs_skipped() -> None:
    """OP_RETURN data carriers have no scriptpubkey_address. They
    should be silently dropped rather than producing bogus
    Transfers."""
    tx = _mk_tx(
        inputs=[(VICTIM, 100_000)],
        outputs=[(PERP, 50_000)],
    )
    # Inject an OP_RETURN output (no scriptpubkey_address).
    tx["vout"].append({"value": 0, "scriptpubkey_type": "op_return"})
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["to"] == PERP


def test_block_filter_drops_older_txs() -> None:
    """start_block=900_000 should drop txs confirmed at height
    800_000. Esplora has no block-window param on the address
    endpoint, so the adapter filters client-side."""
    old = _mk_tx(txid="old", block_height=800_000)
    new = _mk_tx(txid="new", block_height=900_001)
    adapter = _mk_adapter([old, new])
    out = adapter.fetch_native_outflows(VICTIM, start_block=900_000)
    assert len(out) == 1
    assert out[0]["tx_hash"] == "new"


# ---- CoinJoin detection ---- #


def test_coinjoin_pattern_dropped() -> None:
    """4+ inputs with 3+ outputs at identical values = CoinJoin.
    Skip — peel-chain heuristic doesn't work."""
    # 4 inputs from different addresses, 4 outputs all 1 BTC.
    coinjoin = {
        "txid": "coinjoin1",
        "vin": [
            {"prevout": {"scriptpubkey_address": VICTIM, "value": 110_000_000}},
            {"prevout": {"scriptpubkey_address": "1A2", "value": 105_000_000}},
            {"prevout": {"scriptpubkey_address": "1A3", "value": 108_000_000}},
            {"prevout": {"scriptpubkey_address": "1A4", "value": 102_000_000}},
        ],
        "vout": [
            {"scriptpubkey_address": "1B1", "value": 100_000_000},
            {"scriptpubkey_address": "1B2", "value": 100_000_000},
            {"scriptpubkey_address": "1B3", "value": 100_000_000},
            {"scriptpubkey_address": "1B4", "value": 100_000_000},
        ],
        "status": {
            "confirmed": True,
            "block_height": 800_000,
            "block_time": 1700_000_000,
            "block_hash": "x" * 64,
        },
    }
    adapter = _mk_adapter([coinjoin])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert out == []  # CoinJoin → drop


# ---- Error degradation ---- #


def test_esplora_error_returns_empty_list() -> None:
    client = MagicMock()
    client.get_address_txs.side_effect = EsploraError("upstream down")
    adapter = BitcoinAdapter(client=client)
    assert adapter.fetch_native_outflows(VICTIM, start_block=0) == []


def test_invalid_address_returns_empty_list() -> None:
    """An address that doesn't validate as Bitcoin → empty list
    (don't blow up the tracer)."""
    adapter = _mk_adapter()
    assert adapter.fetch_native_outflows("not-a-bitcoin-address", start_block=0) == []


# ---- Always-empty endpoints ---- #


def test_fetch_erc20_returns_empty() -> None:
    """Bitcoin has no ERC-20 equivalent. Empty list, always."""
    adapter = _mk_adapter()
    assert adapter.fetch_erc20_outflows(VICTIM, start_block=0) == []


def test_is_contract_always_false() -> None:
    """Bitcoin has no smart contracts. Even P2SH multisig addresses
    are treated as wallets for trace purposes."""
    adapter = _mk_adapter()
    assert adapter.is_contract(VICTIM) is False
    assert adapter.is_contract(THIRD_PARTY) is False  # P2SH


# ---- Explorer URLs ---- #


def test_explorer_tx_url() -> None:
    adapter = _mk_adapter()
    assert adapter.explorer_tx_url("abc123") == "https://mempool.space/tx/abc123"


def test_explorer_address_url() -> None:
    adapter = _mk_adapter()
    url = adapter.explorer_address_url(VICTIM)
    assert url == f"https://mempool.space/address/{VICTIM}"


def test_explorer_address_url_normalizes_bech32_case() -> None:
    """Uppercase bech32 input → lowercase URL."""
    adapter = _mk_adapter()
    upper = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
    url = adapter.explorer_address_url(upper)
    assert url == f"https://mempool.space/address/{upper.lower()}"


# ---- ChainAdapter factory ---- #


def test_for_chain_dispatches_bitcoin() -> None:
    from recupero.chains.base import ChainAdapter
    adapter = ChainAdapter.for_chain(Chain.bitcoin, config=None)
    assert isinstance(adapter, BitcoinAdapter)
