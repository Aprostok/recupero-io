"""Tests for v0.32.1 CRIT-1: Bitcoin multi-input pro-rata + co-spending registry.

Pre-v0.32.1 the BitcoinAdapter dropped all but the FIRST input
address per tx — multi-input UTXO consolidations (the normal shape
for any wallet with >1 UTXO) silently under-reported outflows from
N-1 input addresses, AND the H1 (co-spending) clustering heuristic
in trace/clustering.py almost never fired because the multi-input
set was no longer visible anywhere in the case.

v0.32.1 fix:
  1. ``_normalize_utxo_tx`` emits one Transfer per send-output with
     ``from = expected_from`` and ``amount_raw`` = the queried
     address's pro-rata share of the output value (based on its
     contribution to total inputs).
  2. The FULL input-address set is registered in
     ``bitcoin.inputs_registry`` so ``trace/clustering.py`` H1 sees
     the actual common-input edges rather than only the random-first.

These tests verify pro-rata math, the registry, and that 1-input
behavior is byte-identical to pre-v0.32.1 (no regression for the
common case).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from recupero.chains.bitcoin.adapter import BitcoinAdapter
from recupero.chains.bitcoin.inputs_registry import (
    clear_for_case,
    lookup,
    size,
)

VICTIM = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
ADDR_B = "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"
ADDR_C = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
ADDR_D = "1LoveRPzn7VLDpFY4VKqcDPHmHv9rUKuvi"
ADDR_E = "1FfmbHfnpaZjKFvyi1okTjJJusN455paPH"
PERP = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"


def _mk_tx(
    *,
    txid: str = "tx_001",
    inputs: list[tuple[str, int]] | None = None,
    outputs: list[tuple[str, int]] | None = None,
    block_height: int = 800_000,
    block_time: int = 1_700_000_000,
) -> dict:
    """Build a minimal Esplora-shaped tx with (addr, value) inputs/outputs."""
    inputs = inputs or [(VICTIM, 100_000)]
    outputs = outputs or [(PERP, 90_000)]
    return {
        "txid": txid,
        "vin": [
            {"prevout": {"scriptpubkey_address": addr, "value": value}}
            for addr, value in inputs
        ],
        "vout": [
            {"scriptpubkey_address": addr, "value": value}
            for addr, value in outputs
        ],
        "status": {
            "confirmed": True,
            "block_height": block_height,
            "block_time": block_time,
            "block_hash": "x" * 64,
        },
    }


def _mk_adapter(txs: list[dict] | None = None) -> BitcoinAdapter:
    client = MagicMock()
    client.get_address_txs.return_value = txs or []
    return BitcoinAdapter(client=client)


@pytest.fixture(autouse=True)
def _clear_registry():
    """Each test gets a fresh registry — tests are otherwise stateful."""
    clear_for_case()
    yield
    clear_for_case()


# ---- 1: Single-input back-compat ---- #


def test_single_input_amount_unchanged_no_pro_rata() -> None:
    """v0.32.1 must preserve byte-identical behavior for the common
    single-input case: amount_raw equals the full output value, NOT
    a pro-rata fraction. Locks the back-compat with every pre-v0.32.1
    BTC test fixture."""
    tx = _mk_tx(
        inputs=[(VICTIM, 1_000_000)],
        outputs=[(PERP, 950_000)],
    )
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["from"] == VICTIM
    assert out[0]["to"] == PERP
    # Full output value — NO pro-rata for single-input.
    assert out[0]["amount_raw"] == 950_000
    # Registry still records the one input.
    assert lookup(tx["txid"]) == frozenset({VICTIM})


# ---- 2: Two-input pro-rata accounting ---- #


def test_two_input_pro_rata_equal_share_emits_half() -> None:
    """Victim contributes 50% of inputs → gets 50% of the output as
    its attributed outflow. The OTHER 50% is attributed to ADDR_B
    when the BFS visits B (separate hop)."""
    tx = _mk_tx(
        inputs=[(VICTIM, 500_000), (ADDR_B, 500_000)],
        outputs=[(PERP, 990_000)],
    )
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["from"] == VICTIM
    assert out[0]["to"] == PERP
    # 50% of 990_000 = 495_000
    assert out[0]["amount_raw"] == 495_000


def test_two_input_pro_rata_skewed_shares() -> None:
    """Victim contributes 90% of inputs → 90% of output attributed."""
    tx = _mk_tx(
        inputs=[(VICTIM, 900_000), (ADDR_B, 100_000)],
        outputs=[(PERP, 990_000)],
    )
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    # 990_000 * 900_000 // 1_000_000 = 891_000
    assert out[0]["amount_raw"] == 891_000


# ---- 3: Five-input fragmented UTXO consolidation ---- #


def test_five_input_pro_rata_and_registry() -> None:
    """The canonical multi-UTXO consolidation: 5 distinct input
    addresses, all controlled by the same actor (a co-spending
    cluster). Pro-rata attributes the right share to each; the
    registry captures the full input set for H1 clustering."""
    tx = _mk_tx(
        inputs=[
            (VICTIM, 200_000),
            (ADDR_B, 200_000),
            (ADDR_C, 200_000),
            (ADDR_D, 200_000),
            (ADDR_E, 200_000),
        ],
        outputs=[(PERP, 999_500)],
    )
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["from"] == VICTIM
    # 999_500 / 5 = 199_900
    assert out[0]["amount_raw"] == 199_900
    # Registry has all 5 inputs captured (the whole point of CRIT-1).
    inputs = lookup(tx["txid"])
    assert inputs == frozenset({VICTIM, ADDR_B, ADDR_C, ADDR_D, ADDR_E})


# ---- 4: CoinJoin path doesn't pollute the simple peel-chain logic ---- #


def test_coinjoin_10_plus_inputs_from_same_controller_uses_unwrap() -> None:
    """A 10+ input + 10-equal-output CoinJoin (Wasabi 1.0 / Whirlpool
    pattern) shouldn't fall through the pro-rata peel-chain logic —
    the CoinJoin detector fires first and routes to
    ``_record_coinjoin_lead``. Per the HIGH-1 fix the trace TERMINATES
    at the mixing boundary: it injects ZERO followable transfers (the
    returned list is empty) and records the post-mix outputs as leads
    only — never fabricating peel-chain Transfers."""
    # Whirlpool-shape: 10 inputs at exactly 10.1M sats, 10 outputs at
    # exactly 10M sats. VICTIM is one of the input addresses.
    addrs_in = [VICTIM] + [f"1Coinjoin{i:030d}" for i in range(9)]
    addrs_out = [f"1Out{i:032d}" for i in range(10)]
    cj_tx = {
        "txid": "cj_10",
        "vin": [
            {"prevout": {"scriptpubkey_address": a, "value": 10_100_000}}
            for a in addrs_in
        ],
        "vout": [
            {"scriptpubkey_address": a, "value": 10_000_000}
            for a in addrs_out
        ],
        "status": {
            "confirmed": True,
            "block_height": 800_000,
            "block_time": 1_700_000_000,
            "block_hash": "x" * 64,
        },
    }
    adapter = _mk_adapter([cj_tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    # HIGH-1 fix: the trace terminates at the CoinJoin boundary — no
    # followable transfers at all (and certainly not 10 pro-rata
    # peel-chain Transfers, which would be totally wrong for a CoinJoin).
    assert out == []


# ---- 5: Pro-rata math sums to the output value (round-trip) ---- #


def test_pro_rata_shares_sum_to_output_value_within_drift() -> None:
    """Calling fetch_native_outflows for EACH input address should
    return rows whose pro-rata amount sums to ~= the output value
    (modulo integer floor-division drift, which is at most n-1 sats
    per output for n inputs). This is the accounting correctness
    invariant: forensic totals must match on-chain reality."""
    tx = _mk_tx(
        inputs=[
            (VICTIM, 300_000),
            (ADDR_B, 200_000),
            (ADDR_C, 500_000),
        ],
        outputs=[(PERP, 990_000)],
    )
    adapter = _mk_adapter([tx])
    total = 0
    for input_addr in (VICTIM, ADDR_B, ADDR_C):
        out = adapter.fetch_native_outflows(input_addr, start_block=0)
        # Each input address gets one Transfer.
        assert len(out) == 1
        total += out[0]["amount_raw"]
    # Drift is at most n_inputs - 1 = 2 sats below the true 990_000.
    assert 990_000 - 2 <= total <= 990_000


# ---- 6: Registry records inputs even for 1-input txs ---- #


def test_registry_populated_for_every_tx_including_singletons() -> None:
    """The registry must record inputs for every tx we normalize,
    not just multi-input ones. Otherwise downstream clustering
    that lookup()s by tx_hash silently sees empty for the 1-input
    case (correctness for the legacy single-input H1 path)."""
    tx_a = _mk_tx(txid="single", inputs=[(VICTIM, 100_000)],
                   outputs=[(PERP, 90_000)])
    tx_b = _mk_tx(txid="multi",
                   inputs=[(VICTIM, 50_000), (ADDR_B, 50_000)],
                   outputs=[(PERP, 90_000)])
    adapter = _mk_adapter([tx_a, tx_b])
    adapter.fetch_native_outflows(VICTIM, start_block=0)
    assert lookup("single") == frozenset({VICTIM})
    assert lookup("multi") == frozenset({VICTIM, ADDR_B})
    assert size() >= 2


# ---- 7: Change output exclusion still works with multi-input ---- #


def test_multi_input_change_output_still_excluded() -> None:
    """The peel-chain rule (outputs to ANY input address are
    treated as change, not sends) must still apply with multi-
    input pro-rata. Tests that a 2-input → 1-send + 1-change tx
    yields only the send leg."""
    tx = _mk_tx(
        inputs=[(VICTIM, 500_000), (ADDR_B, 500_000)],
        outputs=[
            (PERP, 600_000),     # send
            (VICTIM, 390_000),   # change (back to one of the inputs)
        ],
    )
    adapter = _mk_adapter([tx])
    out = adapter.fetch_native_outflows(VICTIM, start_block=0)
    # Only the PERP send leg; the change leg to VICTIM is filtered.
    assert len(out) == 1
    assert out[0]["to"] == PERP
    # 50% of 600_000 = 300_000
    assert out[0]["amount_raw"] == 300_000
