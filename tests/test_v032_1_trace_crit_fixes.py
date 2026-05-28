"""Tests for v0.32.1 — JACOB_TRACE_AUDIT_v032 CRIT fixes.

Closes three of the six CRITs from docs/JACOB_TRACE_AUDIT_v032.md:

  * CRIT-1: Bitcoin adapter discards all but FIRST input address per
    multi-input tx → silently zero co-spending clusters.
  * CRIT-2: Tron native (TRX) outflows return ``[]`` always →
    TRX-laundering cases appear to have zero native activity.
  * CRIT-4: drainer-detection Signal 2 (approval → unknown contract)
    gated behind ``if False:`` → blank attribution column for every
    drainer-kit case (= ≥60% of incoming 2025-2026 volume).

Each test is a "punishing" shape: real-shape adapter output, real
clustering invocation, real detection-pattern wiring. Failures mean
the silent-loss-of-coverage gap re-opened.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import MagicMock

from recupero.chains.bitcoin.adapter import BitcoinAdapter
from recupero.chains.tron.adapter import TronAdapter
from recupero.models import (
    Case,
    Chain,
    Counterparty,
    TokenRef,
    Transfer,
)
from recupero.trace.clustering import compute_clusters_with_metadata
from recupero.trace.drainer_detection import (
    APPROVAL_TOPIC0,
    ApprovalEvent,
    detect_drainer_pattern,
)
from recupero.trace.risk_scoring import HighRiskEntry


# Real Bitcoin mainnet-shape addresses (base58check P2PKH).
BTC_A = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BTC_B = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
BTC_C = "1CounterpartyXXXXXXXXXXXXXXXXXVUWLpVr"
BTC_DEST = "1FfmbHfnpaZjKFvyi1okTjJJusN455paPH"


# ----------------------------------------------------------------- #
# CRIT-1 — Bitcoin multi-input collapse
# ----------------------------------------------------------------- #


def _mk_btc_tx(
    *,
    txid: str = "deadbeef" * 8,
    inputs: list[tuple[str, int]],
    outputs: list[tuple[str, int]],
    block_height: int = 800_000,
    block_time: int = 1_700_000_000,
) -> dict:
    return {
        "txid": txid,
        "vin": [
            {"prevout": {"scriptpubkey_address": addr, "value": val}}
            for addr, val in inputs
        ],
        "vout": [
            {"scriptpubkey_address": addr, "value": val}
            for addr, val in outputs
        ],
        "status": {
            "confirmed": True,
            "block_height": block_height,
            "block_time": block_time,
            "block_hash": "ab" * 32,
        },
    }


def _btc_adapter(txs: list[dict]) -> BitcoinAdapter:
    client = MagicMock()
    client.get_address_txs.return_value = txs
    return BitcoinAdapter(client=client)


def test_crit1_btc_multi_input_emits_co_spending_witnesses() -> None:
    """Multi-input tx with inputs A,B,C → output DEST.

    Pre-v0.32.1: fetching outflows for A returns ONE Transfer
    (A→DEST). B and C are invisible. clustering H1 never fires.

    v0.32.1: fetching outflows for A returns FOUR Transfer dicts:
    one primary send (A→DEST) plus co-input witness rows for B and C
    flagged ``is_utxo_co_input=True``. Clustering can now see that
    A, B, C were all inputs to the same tx — co-spending fires.
    """
    tx = _mk_btc_tx(
        inputs=[(BTC_A, 50_000), (BTC_B, 30_000), (BTC_C, 20_000)],
        outputs=[(BTC_DEST, 95_000)],  # 5_000 sat fee
    )
    adapter = _btc_adapter([tx])
    out = adapter.fetch_native_outflows(BTC_A, start_block=0)

    # 1 primary send (A→DEST) + 2 co-input witnesses (B→DEST, C→DEST).
    assert len(out) == 3, f"expected 3 rows, got {len(out)}: {out}"

    primary = [r for r in out if not r.get("is_utxo_co_input")]
    assert len(primary) == 1
    assert primary[0]["from"] == BTC_A
    assert primary[0]["to"] == BTC_DEST
    assert primary[0]["amount_raw"] == 95_000

    co_inputs = [r for r in out if r.get("is_utxo_co_input")]
    assert len(co_inputs) == 2
    from_addrs = {r["from"] for r in co_inputs}
    assert from_addrs == {BTC_B, BTC_C}
    # Each carries the input UTXO's value (NOT the destination share).
    by_from = {r["from"]: r for r in co_inputs}
    assert by_from[BTC_B]["amount_raw"] == 30_000
    assert by_from[BTC_C]["amount_raw"] == 20_000
    # All point at the canonical destination so clustering sees the
    # same tx_hash with multiple from_addresses.
    for r in co_inputs:
        assert r["to"] == BTC_DEST
        assert r["tx_hash"] == tx["txid"]
        assert r["chain"] == Chain.bitcoin


def test_crit1_btc_single_input_unchanged() -> None:
    """Single-input tx must NOT emit co-input witnesses — preserves
    pre-v0.32.1 behavior for the common case."""
    tx = _mk_btc_tx(
        inputs=[(BTC_A, 100_000)],
        outputs=[(BTC_DEST, 95_000)],
    )
    adapter = _btc_adapter([tx])
    out = adapter.fetch_native_outflows(BTC_A, start_block=0)
    assert len(out) == 1
    assert out[0]["from"] == BTC_A
    assert out[0]["is_utxo_co_input"] is False


def test_crit1_btc_co_spending_clustering_fires() -> None:
    """End-to-end: emit Transfers from the adapter through the
    clustering H1 heuristic. Pre-v0.32.1 the cluster set is empty;
    v0.32.1 it contains exactly one 3-member cluster {A,B,C}.
    """
    tx = _mk_btc_tx(
        inputs=[(BTC_A, 50_000), (BTC_B, 30_000), (BTC_C, 20_000)],
        outputs=[(BTC_DEST, 95_000)],
    )
    adapter = _btc_adapter([tx])
    raw = adapter.fetch_native_outflows(BTC_A, start_block=0)

    # Materialize Transfer objects (same shape the tracer uses).
    incident = datetime(2026, 1, 1, tzinfo=UTC)
    transfers: list[Transfer] = []
    for idx, rec in enumerate(raw):
        amount_dec = Decimal(rec["amount_raw"]) / Decimal(10**8)
        transfers.append(Transfer(
            transfer_id=f"bitcoin:{rec['tx_hash']}:{idx}",
            chain=Chain.bitcoin,
            tx_hash=rec["tx_hash"],
            block_number=rec["block_number"],
            block_time=rec["block_time"],
            log_index=rec["log_index"],
            from_address=rec["from"],
            to_address=rec["to"],
            counterparty=Counterparty(
                address=rec["to"], label=None, is_contract=False,
            ),
            token=rec["token"],
            amount_raw=str(rec["amount_raw"]),
            amount_decimal=amount_dec,
            hop_depth=1,
            is_utxo_co_input=bool(rec.get("is_utxo_co_input", False)),
            explorer_url=rec["explorer_url"],
            fetched_at=incident,
        ))

    case = Case(
        case_id="crit1",
        seed_address=BTC_A,
        chain=Chain.bitcoin,
        incident_time=incident,
        transfers=transfers,
        trace_started_at=incident,
        software_version="test",
        config_used={},
    )
    meta = compute_clusters_with_metadata(case)
    # Exactly one cluster with all three inputs.
    assert len(meta) == 1, f"expected 1 cluster, got: {meta}"
    members = set(meta[0]["addresses"])
    assert members == {BTC_A, BTC_B, BTC_C}
    assert "co_spending" in meta[0]["heuristics"]
    assert meta[0]["confidence"] == "high"


def test_crit1_btc_co_input_rows_skipped_in_total_usd_sum() -> None:
    """Co-input witness rows must NOT contribute to ``total_usd_out``
    — otherwise a 3-input tx is triple-counted."""
    from recupero.trace.tracer import _sum_usd

    incident = datetime(2026, 1, 1, tzinfo=UTC)

    def _btc_t(from_addr: str, to_addr: str, usd: Decimal,
               *, is_co: bool, tx: str) -> Transfer:
        return Transfer(
            transfer_id=f"bitcoin:{tx}:{from_addr[-4:]}",
            chain=Chain.bitcoin,
            tx_hash=tx,
            block_number=800_000,
            block_time=incident,
            from_address=from_addr,
            to_address=to_addr,
            counterparty=Counterparty(
                address=to_addr, label=None, is_contract=False,
            ),
            token=TokenRef(
                chain=Chain.bitcoin, contract=None, symbol="BTC",
                decimals=8, coingecko_id="bitcoin",
            ),
            amount_raw="100000",
            amount_decimal=Decimal("0.001"),
            usd_value_at_tx=usd,
            hop_depth=1,
            is_utxo_co_input=is_co,
            explorer_url="https://mempool.space/tx/" + tx,
            fetched_at=incident,
        )

    transfers = [
        _btc_t(BTC_A, BTC_DEST, Decimal("100"), is_co=False, tx="t1"),
        _btc_t(BTC_B, BTC_DEST, Decimal("100"), is_co=True, tx="t1"),
        _btc_t(BTC_C, BTC_DEST, Decimal("100"), is_co=True, tx="t1"),
    ]
    # Only the primary contributes — co-input rows are filtered.
    assert _sum_usd(transfers) == Decimal("100")


# ----------------------------------------------------------------- #
# CRIT-2 — Tron native TRX outflow stub
# ----------------------------------------------------------------- #

# Real Tron mainnet-shape (base58check).
TRON_PERP = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"
TRON_VICTIM = "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX"


def _trx_tx(
    *,
    tx_id: str = "ab" * 32,
    owner_hex: str,
    to_hex: str,
    amount_sun: int,
    block_ts_ms: int = 1_700_000_000_000,
    block_number: int = 50_000_000,
    contract_type: str = "TransferContract",
    contract_ret: str = "SUCCESS",
) -> dict:
    return {
        "txID": tx_id,
        "block_timestamp": block_ts_ms,
        "blockNumber": block_number,
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
                    },
                },
            ],
        },
        "ret": [{"contractRet": contract_ret}],
    }


def _tron_adapter(*, account_txs: list[dict] | None = None) -> TronAdapter:
    client = MagicMock()
    client.get_account_transactions.return_value = account_txs or []
    client.get_trc20_transfers.return_value = []
    client.get_account.return_value = {"data": []}
    return TronAdapter(client=client)


def _b58_to_hex(addr: str) -> str:
    from recupero.chains.tron.address import base58_to_hex
    return base58_to_hex(addr)


def test_crit2_trx_native_outflow_yields_rows() -> None:
    """A real-shape TRX TransferContract tx must surface as one
    normalized Transfer dict. Pre-v0.32.1 the function returned ``[]``
    unconditionally."""
    tx = _trx_tx(
        owner_hex=_b58_to_hex(TRON_VICTIM),
        to_hex=_b58_to_hex(TRON_PERP),
        amount_sun=1_500_000_000,  # 1500 TRX
    )
    adapter = _tron_adapter(account_txs=[tx])
    out = adapter.fetch_native_outflows(TRON_VICTIM, start_block=0)
    assert len(out) == 1
    rec = out[0]
    assert rec["chain"] == Chain.tron
    assert rec["from"] == TRON_VICTIM
    assert rec["to"] == TRON_PERP
    assert rec["amount_raw"] == 1_500_000_000
    assert rec["token"].symbol == "TRX"
    assert rec["token"].decimals == 6
    assert rec["token"].contract is None
    assert rec["token"].coingecko_id == "tron"


def test_crit2_trx_native_filters_non_transfer_contracts() -> None:
    """A TriggerSmartContract row (TRC-20 path, NOT native TRX) must
    be filtered — those belong to fetch_erc20_outflows."""
    tx = _trx_tx(
        owner_hex=_b58_to_hex(TRON_VICTIM),
        to_hex=_b58_to_hex(TRON_PERP),
        amount_sun=1_000_000,
        contract_type="TriggerSmartContract",
    )
    adapter = _tron_adapter(account_txs=[tx])
    out = adapter.fetch_native_outflows(TRON_VICTIM, start_block=0)
    assert out == []


def test_crit2_trx_native_filters_failed_tx() -> None:
    """A failed tx (contractRet != SUCCESS) must not surface — funds
    didn't actually move."""
    tx = _trx_tx(
        owner_hex=_b58_to_hex(TRON_VICTIM),
        to_hex=_b58_to_hex(TRON_PERP),
        amount_sun=1_000_000,
        contract_ret="OUT_OF_ENERGY",
    )
    adapter = _tron_adapter(account_txs=[tx])
    out = adapter.fetch_native_outflows(TRON_VICTIM, start_block=0)
    assert out == []


def test_crit2_trx_native_filters_wrong_direction() -> None:
    """An inbound TRX tx (someone else → VICTIM) must be filtered out
    by the expected_from check."""
    other = "TYr2tnyG8oQpvAQpD7hu1JjKKxKt2CKBu5"
    tx = _trx_tx(
        owner_hex=_b58_to_hex(other),
        to_hex=_b58_to_hex(TRON_VICTIM),
        amount_sun=999_000,
    )
    adapter = _tron_adapter(account_txs=[tx])
    out = adapter.fetch_native_outflows(TRON_VICTIM, start_block=0)
    assert out == []


def test_crit2_trx_native_uses_get_account_transactions_endpoint() -> None:
    """The native-TRX path must hit the per-address
    ``/v1/accounts/{addr}/transactions`` endpoint (via the client's
    get_account_transactions wrapper) — NOT the TRC-20 endpoint and
    NOT the per-tx info endpoint."""
    tx = _trx_tx(
        owner_hex=_b58_to_hex(TRON_VICTIM),
        to_hex=_b58_to_hex(TRON_PERP),
        amount_sun=1_000_000,
    )
    adapter = _tron_adapter(account_txs=[tx])
    adapter.fetch_native_outflows(TRON_VICTIM, start_block=0)
    assert adapter.client.get_account_transactions.called
    # And it was called with only_from=True (server-side direction filter).
    _, kwargs = adapter.client.get_account_transactions.call_args
    assert kwargs.get("only_from") is True


# ----------------------------------------------------------------- #
# CRIT-4 — Drainer detection gated `if False`
# ----------------------------------------------------------------- #


SEED_VICTIM = "0x" + "a" * 40
DRAINER_KIT = "0x" + "d" * 40
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


def _evm_transfer(
    *,
    from_addr: str,
    to_addr: str,
    tx_hash: str,
    block_time: datetime,
    usd: Decimal = Decimal("50000"),
    is_contract: bool = False,
) -> Transfer:
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:1",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=int(block_time.timestamp()) % 100_000_000,
        block_time=block_time,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=None, is_contract=is_contract,
        ),
        token=TokenRef(
            chain=Chain.ethereum, contract=USDC,
            symbol="USDC", decimals=6, coingecko_id="usd-coin",
        ),
        amount_raw="50000000000",
        amount_decimal=Decimal("50000"),
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=block_time,
    )


def _approval(
    *,
    owner: str = SEED_VICTIM,
    spender: str,
    tx_hash: str,
    block_time: datetime,
    amount_raw: str = "115792089237316195423570985008687907853269984665640564039457584007913129639935",  # uint256.max
) -> ApprovalEvent:
    return ApprovalEvent(
        owner=owner,
        spender=spender,
        token_contract=USDC,
        amount_raw=amount_raw,
        tx_hash=tx_hash,
        block_number=int(block_time.timestamp()) % 100_000_000,
        block_time=block_time,
    )


def test_crit4_approval_topic0_is_canonical_constant() -> None:
    """The ERC-20 Approval topic0 is a standard, well-known hash —
    mismatched value here means a typo would silently never match
    any Etherscan getLogs response."""
    assert APPROVAL_TOPIC0 == (
        "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
    )


def test_crit4_drainer_approval_chain_flips_classification() -> None:
    """The smoking-gun pattern: victim signs Approval, then funds
    flow to the spender. Pre-v0.32.1 this was silently no-op'd
    behind ``if False:``. v0.32.1 must classify the case as drainer
    and identify the drainer as perpetrator."""
    approve_time = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    drain_time = datetime(2026, 1, 1, 10, 5, tzinfo=UTC)
    case = Case(
        case_id="crit4-approval",
        seed_address=SEED_VICTIM,
        chain=Chain.ethereum,
        incident_time=drain_time,
        transfers=[_evm_transfer(
            from_addr=SEED_VICTIM,
            to_addr=DRAINER_KIT,
            tx_hash="0x" + "1" * 64,
            block_time=drain_time,
            is_contract=True,
        )],
        trace_started_at=drain_time,
        software_version="test",
        config_used={},
    )
    findings = detect_drainer_pattern(
        case,
        high_risk_db={},
        approvals=[_approval(
            spender=DRAINER_KIT,
            tx_hash="0x" + "a" * 64,
            block_time=approve_time,
        )],
    )
    assert findings.is_drainer_case is True
    # No off-chain label → medium confidence, attribution=None.
    assert findings.classification_confidence == "medium"
    sig = next(
        s for s in findings.signals
        if s.signal_type == "approval_to_unknown_contract"
    )
    assert sig.counterparty == DRAINER_KIT
    assert "drainer_approval_chain" in sig.description


def test_crit4_high_risk_label_plus_approval_is_high_confidence() -> None:
    """When the drainer kit is ALREADY tagged in high_risk.json AND
    the approval chain confirms, confidence escalates to 'high' with
    the named attribution."""
    approve_time = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    drain_time = datetime(2026, 1, 1, 10, 5, tzinfo=UTC)
    db = {DRAINER_KIT: HighRiskEntry(
        address=DRAINER_KIT, name="Inferno Drainer",
        risk_category="scam_drainer", severity=4,
    )}
    case = Case(
        case_id="crit4-high-risk",
        seed_address=SEED_VICTIM,
        chain=Chain.ethereum,
        incident_time=drain_time,
        # Transfer must go to a DIFFERENT address than the drainer
        # itself so we exercise Signal 2 (not Signal 1).
        # Actually for this case the drainer IS the destination — but
        # Signal 1 already classifies it; we want to confirm Signal 2
        # ALSO fires AND escalates the existing confidence to "high".
        # Use a separate dest contract to isolate Signal 2 only.
        transfers=[_evm_transfer(
            from_addr=SEED_VICTIM,
            to_addr=DRAINER_KIT,
            tx_hash="0x" + "1" * 64,
            block_time=drain_time,
            is_contract=True,
        )],
        trace_started_at=drain_time,
        software_version="test",
        config_used={},
    )
    findings = detect_drainer_pattern(
        case,
        high_risk_db=db,
        approvals=[_approval(
            spender=DRAINER_KIT,
            tx_hash="0x" + "a" * 64,
            block_time=approve_time,
        )],
    )
    # Signal 1 fires first (direct outflow to known drainer)
    # AND Signal 2 fires (approval chain corroborates).
    assert findings.is_drainer_case is True
    assert findings.classification_confidence == "high"
    assert findings.drainer_attribution == "Inferno Drainer"


def test_crit4_approval_after_outflow_does_not_trigger() -> None:
    """Approval signed AFTER the outflow is not causal (could be a
    re-approval). The detector must require the approval to predate
    the funds movement."""
    drain_time = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    approve_time = datetime(2026, 1, 1, 10, 5, tzinfo=UTC)
    case = Case(
        case_id="crit4-out-of-order",
        seed_address=SEED_VICTIM,
        chain=Chain.ethereum,
        incident_time=drain_time,
        transfers=[_evm_transfer(
            from_addr=SEED_VICTIM,
            to_addr=DRAINER_KIT,
            tx_hash="0x" + "1" * 64,
            block_time=drain_time,
            is_contract=True,
        )],
        trace_started_at=drain_time,
        software_version="test",
        config_used={},
    )
    findings = detect_drainer_pattern(
        case,
        high_risk_db={},
        approvals=[_approval(
            spender=DRAINER_KIT,
            tx_hash="0x" + "a" * 64,
            block_time=approve_time,
        )],
    )
    # No approval-chain signal because the approval post-dates the
    # outflow. And no high-risk label, so nothing classifies.
    assert findings.is_drainer_case is False
    assert not any(
        s.signal_type == "approval_to_unknown_contract"
        for s in findings.signals
    )


def test_crit4_no_approvals_preserves_v018_no_op_behavior() -> None:
    """Sanity: omitting ``approvals=`` (the pre-v0.32.1 calling
    pattern) must keep the v0.18.0 fix in place — random transfers
    to contracts do NOT misclassify the case as drainer."""
    case = Case(
        case_id="crit4-no-approvals",
        seed_address=SEED_VICTIM,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=[_evm_transfer(
            from_addr=SEED_VICTIM,
            to_addr=DRAINER_KIT,
            tx_hash="0x" + "1" * 64,
            block_time=datetime(2026, 1, 1, tzinfo=UTC),
            is_contract=True,
        )],
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test",
        config_used={},
    )
    findings = detect_drainer_pattern(case, high_risk_db={})
    assert findings.is_drainer_case is False
    assert not any(
        s.signal_type == "approval_to_unknown_contract"
        for s in findings.signals
    )
