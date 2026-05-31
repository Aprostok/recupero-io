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
