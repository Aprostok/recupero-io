"""Tests for v0.32.1 CRIT-2: Tron native TRX outflows.

Pre-v0.32.1 ``TronAdapter.fetch_native_outflows`` returned ``[]``
unconditionally — any case where the perpetrator held / moved
native TRX (gas reserves, SunSwap stake, JustLend collateral,
native swaps) silently appeared inactive. The TRX laundering
surface is the largest USDT-stablecoin laundering channel in
crypto (Chainalysis 2024), so this was a CRIT-tier silent-coverage
gap.

v0.32.1 wires ``fetch_native_outflows`` to TronGrid's
``/v1/accounts/{addr}/transactions`` endpoint, filters to
``raw_data.contract[0].type == "TransferContract"``, and decodes
``parameter.value.{owner_address, to_address, amount}`` (amount
in SUN; 1 TRX = 1,000,000 SUN).

These tests cover:
  * 0-transaction response → empty list (no crash).
  * Single TRX TransferContract → normalized dict matching the
    TRC-20 shape (chain=tron, decimals=6, symbol="TRX").
  * Pagination via fingerprint cursor.
  * Malformed responses (missing fields, wrong type tag, bad
    amount values) → log + skip the row, don't crash the BFS.
  * Direction filter (only_from on server, defensive client-side
    re-check).
  * SUN → TRX amount conversion correctness.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from recupero.chains.tron.adapter import (
    TRX_COINGECKO_ID,
    TRX_DECIMALS,
    TRX_SYMBOL,
    TronAdapter,
)
from recupero.chains.tron.address import base58_to_hex
from recupero.chains.tron.client import TronGridError
from recupero.models import Chain


# Real Tron mainnet addresses (base58check + their hex form).
PERP = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"
VICTIM = "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX"
THIRD = "TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn"
PERP_HEX = base58_to_hex(PERP)
VICTIM_HEX = base58_to_hex(VICTIM)
THIRD_HEX = base58_to_hex(THIRD)


def _native_tx(
    *,
    tx_id: str = "tx_native_001",
    owner_hex: str = VICTIM_HEX,
    to_hex: str = PERP_HEX,
    amount_sun: int = 1_500_000_000,   # 1500 TRX
    block_ts_ms: int = 1_750_000_000_000,
    contract_type: str = "TransferContract",
) -> dict:
    """Build a TronGrid native-tx envelope (TransferContract shape)."""
    return {
        "txID": tx_id,
        "block_timestamp": block_ts_ms,
        "raw_data": {
            "contract": [
                {
                    "type": contract_type,
                    "parameter": {
                        "value": {
                            "owner_address": owner_hex,
                            "to_address": to_hex,
                            "amount": amount_sun,
                        },
                        "type_url": "type.googleapis.com/protocol.TransferContract",
                    },
                },
            ],
            "ref_block_bytes": "0001",
            "ref_block_hash": "ff" * 8,
            "expiration": block_ts_ms + 60_000,
        },
    }


def _mk_adapter(native_txs: list[dict] | None = None) -> TronAdapter:
    """Build a TronAdapter with a mocked client.

    The mocked client exposes ``get_native_transactions`` returning
    whatever the test passes. ``get_account`` is also mocked because
    is_contract probes might be triggered downstream.
    """
    client = MagicMock()
    client.get_native_transactions.return_value = native_txs or []
    client.get_account.return_value = {"data": []}
    return TronAdapter(client=client)


# ---- 1: 0-tx response ---- #


def test_zero_tx_response_returns_empty_list() -> None:
    """An account with zero native TRX transactions → []. No crash,
    no spurious row, no log.error."""
    adapter = _mk_adapter([])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert out == []


# ---- 2: Single TransferContract normalization ---- #


def test_single_transfer_normalizes_to_standard_shape() -> None:
    """One TransferContract from VICTIM → PERP becomes one row
    matching the tracer's normalized-dict shape: chain=tron,
    token=TRX-native-pseudo, decimals=6, amount_raw in SUN."""
    adapter = _mk_adapter([_native_tx(amount_sun=1_500_000_000)])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    rec = out[0]
    assert rec["chain"] == Chain.tron
    assert rec["from"] == VICTIM
    assert rec["to"] == PERP
    assert rec["amount_raw"] == 1_500_000_000   # SUN, not TRX
    assert rec["token"].chain == Chain.tron
    assert rec["token"].contract is None         # native — no contract
    assert rec["token"].symbol == TRX_SYMBOL
    assert rec["token"].decimals == TRX_DECIMALS
    assert rec["token"].coingecko_id == TRX_COINGECKO_ID
    assert "tronscan.org" in rec["explorer_url"]
    assert rec["tx_hash"] == "tx_native_001"


def test_sun_to_trx_amount_parsing_for_various_magnitudes() -> None:
    """Verify SUN amounts parse correctly for the typical magnitudes
    seen in real Tron laundering volumes (dust → multi-million TRX).
    """
    cases = [
        1,                       # 0.000001 TRX (dust)
        1_000_000,               # 1 TRX
        1_500_000_000,           # 1,500 TRX
        50_000_000_000,          # 50,000 TRX (typical mid-cycle hub)
        10_000_000_000_000,      # 10,000,000 TRX (a whale-tier hub)
    ]
    for amt in cases:
        adapter = _mk_adapter([_native_tx(
            tx_id=f"tx_{amt}", amount_sun=amt,
        )])
        out = adapter.fetch_native_outflows(VICTIM, start_block=0)
        assert len(out) == 1, f"failed for amount {amt}"
        assert out[0]["amount_raw"] == amt


# ---- 3: Pagination (fingerprint cursor) ---- #


def test_pagination_threads_fingerprint_through_client() -> None:
    """The adapter delegates pagination to TronGridClient.
    get_native_transactions which internally loops on fingerprint.
    Verify the adapter calls get_native_transactions ONCE per
    fetch_native_outflows call (the client is responsible for the
    per-fingerprint loop) and passes through every page's rows.
    """
    txns = [
        _native_tx(tx_id=f"tx_page_{i}", amount_sun=1_000_000 * (i + 1))
        for i in range(75)  # spanning ≥ 3 pages of 25 each
    ]
    adapter = _mk_adapter(txns)
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 75
    # First and last row IDs preserved.
    assert out[0]["tx_hash"] == "tx_page_0"
    assert out[-1]["tx_hash"] == "tx_page_74"
    # Adapter called the client exactly once (pagination is the
    # client's responsibility, not the adapter's).
    assert adapter.client.get_native_transactions.call_count == 1


def test_pagination_passes_only_from_and_min_timestamp() -> None:
    """The adapter must pass ``only_from=True`` (server-side direction
    filter to halve bandwidth) AND convert start_block (unix seconds)
    to min_timestamp (unix milliseconds). Mirrors the TRC-20 path."""
    adapter = _mk_adapter([])
    adapter.fetch_native_outflows(VICTIM, start_block=1_700_000_000)
    call_kwargs = adapter.client.get_native_transactions.call_args.kwargs
    assert call_kwargs["only_from"] is True
    assert call_kwargs["min_timestamp"] == 1_700_000_000 * 1000


# ---- 4: Malformed responses ---- #


def test_missing_raw_data_skips_row_doesnt_crash() -> None:
    """A row with no ``raw_data`` envelope shouldn't kill the BFS.
    Skip with a warning, return any rows that DID normalize."""
    good = _native_tx(tx_id="good")
    bad = {"txID": "bad", "block_timestamp": 1_750_000_000_000}  # no raw_data
    adapter = _mk_adapter([bad, good])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["tx_hash"] == "good"


def test_non_transfer_contract_filtered_silently() -> None:
    """TRC-20 calls (TriggerSmartContract), staking
    (FreezeBalanceContract), votes — all filtered out at the
    type-tag check. The native endpoint returns these mixed-in
    with TransferContracts because /v1/accounts/{addr}/transactions
    is broad."""
    txns = [
        _native_tx(tx_id="trc20",
                   contract_type="TriggerSmartContract"),
        _native_tx(tx_id="stake",
                   contract_type="FreezeBalanceContract"),
        _native_tx(tx_id="vote", contract_type="VoteWitnessContract"),
        _native_tx(tx_id="real_native"),
    ]
    adapter = _mk_adapter(txns)
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["tx_hash"] == "real_native"


def test_malformed_amount_returns_partial_list() -> None:
    """A row with a non-integer amount (TronGrid corruption / mirror
    bug) shouldn't crash. Skip + log; the rest of the page still
    yields rows. Mirrors RIGOR-Jacob I hardening for TRC-20."""
    bad = _native_tx(tx_id="bad_amount")
    bad["raw_data"]["contract"][0]["parameter"]["value"]["amount"] = "not-a-number"
    good = _native_tx(tx_id="good")
    adapter = _mk_adapter([bad, good])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["tx_hash"] == "good"


def test_missing_block_timestamp_skips_row() -> None:
    """A row missing block_timestamp — we can't time-window it,
    skip silently rather than fabricate."""
    bad = _native_tx(tx_id="bad_ts")
    del bad["block_timestamp"]
    good = _native_tx(tx_id="good")
    adapter = _mk_adapter([bad, good])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["tx_hash"] == "good"


# ---- 5: Direction + self-transfer filtering ---- #


def test_wrong_direction_filtered_defensively() -> None:
    """only_from=True is a server-side hint but TronGrid can leak
    inbound events on newly-confirmed rows. The adapter re-checks
    direction client-side and filters mismatched rows. PERP → VICTIM
    must be dropped when querying VICTIM."""
    wrong_dir = _native_tx(
        tx_id="wrong_dir", owner_hex=PERP_HEX, to_hex=VICTIM_HEX,
    )
    adapter = _mk_adapter([wrong_dir])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert out == []


def test_self_transfer_filtered() -> None:
    """A native transfer where owner == to is not a laundering signal
    (it's just an internal balance shuffle). Drop it."""
    self_tx = _native_tx(
        tx_id="self", owner_hex=VICTIM_HEX, to_hex=VICTIM_HEX,
    )
    adapter = _mk_adapter([self_tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert out == []


def test_zero_amount_filtered() -> None:
    """A native TransferContract with amount=0 (rare, but seen on
    test-net + some mainnet probes) is not a real outflow."""
    zero_tx = _native_tx(tx_id="zero", amount_sun=0)
    adapter = _mk_adapter([zero_tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert out == []


# ---- 6: Network-error degradation ---- #


def test_trongrid_error_returns_empty_list() -> None:
    """When the underlying TronGrid client raises (network error,
    auth failure, 5xx that exhausted retries), the adapter must
    NOT propagate to the tracer — return empty list with a
    warning log. Mirrors the existing TRC-20 path."""
    client = MagicMock()
    client.get_native_transactions.side_effect = TronGridError("rate limit")
    adapter = TronAdapter(client=client)
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert out == []


def test_invalid_tron_address_returns_empty_list() -> None:
    """A non-Tron address (e.g., EVM-style 0x...) shouldn't crash
    the adapter — return empty list."""
    adapter = _mk_adapter([])
    out = adapter.fetch_native_outflows("not-a-tron-address", start_block=0)
    assert out == []
