"""v0.34 — bridge source↔destination pairing engine.

The correctness oracle: a cross-chain hop is CONFIRMED iff the protocol's own
order-id appears on BOTH chains. These tests use the VERIFIED on-chain shapes
from the Zigha deBridge DLN pair (Arbitrum CreatedOrder → Ethereum
FulfilledOrder, order-id 0x57825e7d…1f9b) and assert:
  * the source order-id is extracted at the verified offset,
  * an exact order-id match on the destination yields `high` + recipient/amount,
  * a TAMPERED (different) order-id yields None — no false-positive pairing,
  * unknown protocol / missing source event yield None (never guess).
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from recupero.trace.bridge_pairings import (
    confirm_bridge_destination,
    extract_source_order_id,
    get_pair_spec,
)

ORDER_ID = "0x57825e7d05231475614b6156ca01b74c8743fd70fb73210da95f7413f4871f9b"
OTHER_ID = "0x" + "ab" * 32
DLN_SOURCE = "0xef4fb24ad0916217251f553c0596f8edc630eb66"
DLN_DEST = "0xe7351fd770a37282b91d153ee690b63579d6dd7f"
CREATED_TOPIC = "0xfc8703fd57380f9dd234a89dce51333782d49c5902f307b02f03e014d18fe471"
FULFILLED_TOPIC = "0xd281ee92bab1446041582480d2c0a9dc91f855386bb27ea295faac1e992f7fe4"
ERC20_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
RECEIVER = "0xc1ee32fac1d9a0ce63021467e34164df3078289b"
DAI = "0x6b175474e89094c44da98b954eedeac495271d0f"
TAKE_AMOUNT = 2_919_869_135947824800000000


def _word(hexval: str) -> str:
    return hexval[2:].lower().rjust(64, "0")


def _topic_addr(a: str) -> str:
    return "0x" + "0" * 24 + a.removeprefix("0x").lower()


def _source_receipt(order_id: str = ORDER_ID) -> dict[str, Any]:
    # CreatedOrder data: word0 = order-tuple offset pointer, word1 = orderId.
    data = "0x" + _word("0xe0") + _word(order_id) + _word("0x4a0")
    return {"logs": [{
        "address": DLN_SOURCE,
        "topics": [CREATED_TOPIC],
        "data": data,
    }]}


def _fulfilled_log(order_id: str = ORDER_ID, tx: str = "0xfill") -> dict[str, Any]:
    # FulfilledOrder data: word0 = order offset, word1 = orderId (n_topics=1).
    data = "0x" + _word("0xe0") + _word(order_id)
    return {
        "address": DLN_DEST,
        "topics": [FULFILLED_TOPIC],
        "data": data,
        "transactionHash": tx,
    }


def _fill_receipt() -> dict[str, Any]:
    # The fill tx pays takeAmount DAI from the DLN destination to the receiver.
    return {"logs": [{
        "address": DAI,
        "topics": [ERC20_TRANSFER, _topic_addr(DLN_DEST), _topic_addr(RECEIVER)],
        "data": hex(TAKE_AMOUNT),
    }]}


class _FakeDstAdapter:
    def __init__(self, logs: list[dict[str, Any]]) -> None:
        self._logs = logs

    def block_at_or_before(self, ts: datetime) -> int:
        return 100

    def fetch_logs(self, address, topic0, *, from_block, to_block, topics=None):
        if address.lower() == DLN_DEST and topic0.lower() == FULFILLED_TOPIC:
            return list(self._logs)
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> Any:
        return SimpleNamespace(raw_receipt=_fill_receipt())


# ----------------------------- registry / extract ---------------------------


def test_registry_resolves_debridge_by_label_substring() -> None:
    assert get_pair_spec("deBridge DLN Source") is not None
    assert get_pair_spec("DeBridge") is not None
    assert get_pair_spec("Wormhole") is None        # not in verified core yet
    assert get_pair_spec(None) is None


def test_extract_source_order_id_at_verified_offset() -> None:
    spec = get_pair_spec("DeBridge")
    assert extract_source_order_id(spec, _source_receipt()) == ORDER_ID
    # wrong emitter / wrong topic → not found
    assert extract_source_order_id(spec, {"logs": [{
        "address": "0x" + "1" * 40, "topics": [CREATED_TOPIC],
        "data": "0x" + _word("0xe0") + _word(ORDER_ID),
    }]}) is None
    assert extract_source_order_id(spec, {"logs": []}) is None
    assert extract_source_order_id(spec, None) is None


# ----------------------------- confirmation ---------------------------------


def test_confirm_matches_orderid_both_sides_high_confidence() -> None:
    adapter = _FakeDstAdapter([_fulfilled_log(ORDER_ID)])
    out = confirm_bridge_destination(
        protocol="deBridge DLN Source",
        destination_chain="ethereum",
        source_receipt=_source_receipt(ORDER_ID),
        dst_adapter=adapter,
        src_block_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    assert out is not None
    assert out.confidence == "high"
    assert out.order_id == ORDER_ID
    assert out.dst_tx == "0xfill"
    assert (out.recipient or "").lower() == RECEIVER
    assert out.raw_amount == TAKE_AMOUNT
    assert out.dst_chain == "ethereum"


def test_confirm_tampered_orderid_returns_none() -> None:
    """The destination fill references a DIFFERENT order-id → NO pairing. This
    is the false-positive guard: matching is exact-id, not amount/time."""
    adapter = _FakeDstAdapter([_fulfilled_log(OTHER_ID)])
    out = confirm_bridge_destination(
        protocol="DeBridge",
        destination_chain="ethereum",
        source_receipt=_source_receipt(ORDER_ID),
        dst_adapter=adapter,
        src_block_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    assert out is None


def test_confirm_no_dest_logs_returns_none() -> None:
    adapter = _FakeDstAdapter([])   # destination chain has no matching fill
    out = confirm_bridge_destination(
        protocol="DeBridge", destination_chain="ethereum",
        source_receipt=_source_receipt(ORDER_ID), dst_adapter=adapter,
        src_block_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    assert out is None


def test_confirm_unknown_protocol_returns_none() -> None:
    adapter = _FakeDstAdapter([_fulfilled_log(ORDER_ID)])
    out = confirm_bridge_destination(
        protocol="SomeUnknownBridge", destination_chain="ethereum",
        source_receipt=_source_receipt(ORDER_ID), dst_adapter=adapter,
        src_block_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    assert out is None


def test_confirm_no_source_orderid_returns_none() -> None:
    """No CreatedOrder event in the source receipt → nothing to match → None."""
    adapter = _FakeDstAdapter([_fulfilled_log(ORDER_ID)])
    out = confirm_bridge_destination(
        protocol="DeBridge", destination_chain="ethereum",
        source_receipt={"logs": []}, dst_adapter=adapter,
        src_block_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    assert out is None


def test_confirm_explicit_order_id_overrides_source_parse() -> None:
    """Caller may pass a known order-id directly (e.g. already extracted)."""
    adapter = _FakeDstAdapter([_fulfilled_log(ORDER_ID)])
    out = confirm_bridge_destination(
        protocol="DeBridge", destination_chain="ethereum",
        source_receipt=None, dst_adapter=adapter,
        src_block_time=datetime(2025, 10, 9, tzinfo=UTC),
        order_id=ORDER_ID,
    )
    assert out is not None and out.order_id == ORDER_ID


# ===================== Across (indexed composite-key shape) =================
# Verified real pair: Base deposit 0x91f8874e (FundsDeposited 0x32ed1a40,
# destChainId=1, depositId=5729990) → Ethereum fill 0xdd8c3fd0 (FilledRelay
# 0x44b559f1, originChainId=8453, depositId=5729990).

ACROSS_DEPOSIT_T0 = "0x32ed1a409ef04c7b0227189c3a103dc5ac10e775a15b785dcc510201f7c25ad3"
ACROSS_FILL_T0 = "0x44b559f101f8fbcc8a0ea43fa91a05a729a5ea6e14a7c75aa750374690137208"
SPOKE_BASE = "0x09aea4b2242abc8bb4bb78d537a67a245a7bec64"
SPOKE_ETH = "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5"
DEPOSIT_ID = 5729990
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
ACROSS_RECIPIENT = "0x" + "ce" * 20
ACROSS_AMOUNT = 1_000_000_000


def _padint(n: int) -> str:
    return "0x" + f"{n:064x}"


def _across_source_receipt(deposit_id: int = DEPOSIT_ID, dest_chain_id: int = 1) -> dict[str, Any]:
    return {"logs": [{
        "address": SPOKE_BASE,
        "topics": [
            ACROSS_DEPOSIT_T0, _padint(dest_chain_id), _padint(deposit_id),
            _topic_addr("0x" + "d0" * 20),
        ],
        "data": "0x" + _word("0x0"),
    }]}


def _across_fill_log(deposit_id: int = DEPOSIT_ID, origin_chain_id: int = 8453,
                     tx: str = "0xafill") -> dict[str, Any]:
    return {
        "address": SPOKE_ETH,
        "topics": [
            ACROSS_FILL_T0, _padint(origin_chain_id), _padint(deposit_id),
            _topic_addr("0x" + "d0" * 20),
        ],
        "data": "0x",
        "transactionHash": tx,
    }


class _FakeAcrossAdapter:
    def __init__(self, logs: list[dict[str, Any]]) -> None:
        self._logs = logs

    def block_at_or_before(self, ts: datetime) -> int:
        return 100

    def fetch_logs(self, address, topic0, *, from_block, to_block, topics=None):
        if address.lower() == SPOKE_ETH and topic0.lower() == ACROSS_FILL_T0:
            return list(self._logs)
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> Any:
        return SimpleNamespace(raw_receipt={"logs": [{
            "address": USDC,
            "topics": [ERC20_TRANSFER, _topic_addr(SPOKE_ETH), _topic_addr(ACROSS_RECIPIENT)],
            "data": hex(ACROSS_AMOUNT),
        }]})


def test_across_registry_and_per_chain_dest_contract() -> None:
    spec = get_pair_spec("Across")
    assert spec is not None
    assert spec.dest_contract_for("ethereum") == SPOKE_ETH
    assert spec.dest_contract_for("base") == SPOKE_BASE
    assert spec.dest_contract_for("zzznotachain") is None


def test_across_extract_depositid_from_indexed_topic() -> None:
    spec = get_pair_spec("Across")
    assert extract_source_order_id(spec, _across_source_receipt()) == _padint(DEPOSIT_ID)


def test_across_confirm_composite_key_match_high() -> None:
    adapter = _FakeAcrossAdapter([_across_fill_log()])
    out = confirm_bridge_destination(
        protocol="Across", destination_chain="ethereum",
        source_receipt=_across_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 10, 9, tzinfo=UTC), source_chain="base",
    )
    assert out is not None
    assert out.confidence == "high"
    assert out.order_id == _padint(DEPOSIT_ID)
    assert out.dst_tx == "0xafill"
    assert (out.recipient or "").lower() == ACROSS_RECIPIENT
    assert out.raw_amount == ACROSS_AMOUNT


def test_across_wrong_origin_chain_returns_none() -> None:
    """The fill carries the right depositId but a DIFFERENT originChainId than
    the source chain → NOT our deposit (depositId is unique only per origin
    chain). The composite-key check rejects it — no false positive."""
    adapter = _FakeAcrossAdapter([_across_fill_log(origin_chain_id=42161)])  # arbitrum, not base
    out = confirm_bridge_destination(
        protocol="Across", destination_chain="ethereum",
        source_receipt=_across_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 10, 9, tzinfo=UTC), source_chain="base",
    )
    assert out is None


def test_across_wrong_depositid_returns_none() -> None:
    adapter = _FakeAcrossAdapter([_across_fill_log(deposit_id=999999)])
    out = confirm_bridge_destination(
        protocol="Across", destination_chain="ethereum",
        source_receipt=_across_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 10, 9, tzinfo=UTC), source_chain="base",
    )
    assert out is None


# ===================== Celer cBridge (scan shape, srcTransferId @ word 6) ====
# Verified real pair: BSC Send 0xc31bb378 (transferId word0 0x00c9ad07…) →
# Ethereum Relay 0x05e78067 (srcTransferId word6 == 0x00c9ad07…; Relay's OWN
# transferId at word0 is a DIFFERENT value).

CELER_SEND_T0 = "0x89d8051e597ab4178a863a5190407b98abfeff406aa8db90c59af76612e58f01"
CELER_RELAY_T0 = "0x79fa08de5149d912dce8e5e8da7a7c17ccdf23dd5d3bfe196802e6eb86347c7c"
CELER_ETH = "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820"
CELER_BSC = "0xdd90e5e87a2081dcf0391920868ebc2ffb81a1af"
CELER_XFER_ID = "0x00c9ad0717db05159a0972b87406d58516a1dc0f05196e864ff0dc4db5e94823"
CELER_DEST_OWN_ID = "0xe0fbdda0000000000000000000000000000000000000000000000000deadbeef"
CELER_RECIP = "0x647b320cab32125725a0142570af2dfe91212f99"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
CELER_AMOUNT = 187331216712


def _celer_source_receipt(xfer_id: str = CELER_XFER_ID) -> dict[str, Any]:
    # Send: data word0=transferId, then sender/receiver/token/amount/dstChainId/nonce.
    data = "0x" + _word(xfer_id) + _word("0x0") * 6
    return {"logs": [{"address": CELER_BSC, "topics": [CELER_SEND_T0], "data": data}]}


def _celer_relay_log(src_xfer_id: str = CELER_XFER_ID, tx: str = "0xrelaytx") -> dict[str, Any]:
    # Relay: word0=dest's OWN transferId (different), w1 sender, w2 receiver,
    # w3 token, w4 amount, w5 srcChainId, w6=srcTransferId (the pairing key).
    data = "0x" + (
        _word(CELER_DEST_OWN_ID) + _word("0x0") + _word("0x0") + _word("0x0")
        + _word("0x0") + _word("0x38") + _word(src_xfer_id)
    )
    return {"address": CELER_ETH, "topics": [CELER_RELAY_T0], "data": data,
            "transactionHash": tx}


class _FakeCelerAdapter:
    def __init__(self, logs: list[dict[str, Any]]) -> None:
        self._logs = logs

    def block_at_or_before(self, ts: datetime) -> int:
        return 100

    def fetch_logs(self, address, topic0, *, from_block, to_block, topics=None):
        if address.lower() == CELER_ETH and topic0.lower() == CELER_RELAY_T0:
            return list(self._logs)
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> Any:
        return SimpleNamespace(raw_receipt={"logs": [{
            "address": USDT,
            "topics": [ERC20_TRANSFER, _topic_addr(CELER_ETH), _topic_addr(CELER_RECIP)],
            "data": hex(CELER_AMOUNT),
        }]})


def test_celer_confirm_srctransferid_at_word6_high() -> None:
    """The cross-chain key is Relay.srcTransferId (word 6) — the scan-the-payload
    match must land on it, NOT on Relay's own word-0 transferId."""
    adapter = _FakeCelerAdapter([_celer_relay_log()])
    out = confirm_bridge_destination(
        protocol="Celer", destination_chain="ethereum",
        source_receipt=_celer_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 1, 1, tzinfo=UTC), source_chain="bsc",
    )
    assert out is not None
    assert out.confidence == "high"
    assert out.order_id == CELER_XFER_ID
    assert out.dst_tx == "0xrelaytx"
    assert (out.recipient or "").lower() == CELER_RECIP
    assert out.raw_amount == CELER_AMOUNT


def test_celer_tampered_srctransferid_returns_none() -> None:
    adapter = _FakeCelerAdapter([_celer_relay_log(src_xfer_id="0x" + "ab" * 32)])
    out = confirm_bridge_destination(
        protocol="Celer", destination_chain="ethereum",
        source_receipt=_celer_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 1, 1, tzinfo=UTC), source_chain="bsc",
    )
    assert out is None


def test_celer_registry_resolves() -> None:
    spec = get_pair_spec("Celer cBridge")
    assert spec is not None and spec.protocol == "Celer"
    assert spec.dest_contract_for("bsc") == CELER_BSC
