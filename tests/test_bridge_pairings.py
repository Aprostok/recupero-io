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
    identify_source,
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

    def close(self) -> None:
        pass


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


# ===================== Hop (indexed transferId, address-less dest) ==========
# Verified real pair: Base TransferSent 0x3ba95375 → Optimism WithdrawalBonded
# 0x1942dd58, transferId 0x2a9767e8…, both indexed topic1.

HOP_SENT_T0 = "0xe35dddd4ea75d7e9b3fe93af4f4e40e778c3da4074c9d93e7c6536f1e803c1eb"
HOP_BOND_T0 = "0x0c3d250c7831051e78aa6a56679e590374c7c424415ffe4aa474491def2fe705"
HOP_SRC_EMITTER = "0x3666f603cc164936c1b87e207f36beba4ac5f18a"  # Hop ETH L2 Bridge (Base)
HOP_DEST_EMITTER = "0x83f6244bd87662118d96d9a6d44f09dfff14b30e"  # Hop ETH L2 Bridge (Optimism)
HOP_XFER = "0x2a9767e8a94802c4b86df8c0bfa9e03a2b8c29dc6f419e1321cb4fc47290cdfd"
HOP_RECIP = "0xf8284721424e03b07056c3809f25eea780d8473e"


def _hop_source_receipt(xfer: str = HOP_XFER, dest_chain_id: int = 10) -> dict[str, Any]:
    # TransferSent: topic1=transferId, topic2=destChainId, topic3=recipient.
    return {"logs": [{
        "address": HOP_SRC_EMITTER,
        "topics": [HOP_SENT_T0, xfer, _padint(dest_chain_id), _topic_addr(HOP_RECIP)],
        "data": "0x" + _word("0x2d79883d2000"),  # amount
    }]}


def _hop_bond_log(xfer: str = HOP_XFER, tx: str = "0xhopbond") -> dict[str, Any]:
    return {"address": HOP_DEST_EMITTER, "topics": [HOP_BOND_T0, xfer],
            "data": "0x" + _word("0x2d79883d2000"), "transactionHash": tx}


class _FakeHopAdapter:
    def __init__(self, logs: list[dict[str, Any]]) -> None:
        self._logs = logs

    def block_at_or_before(self, ts: datetime) -> int:
        return 100

    def fetch_logs(self, address, topic0, *, from_block, to_block, topics=None):
        # address-less (wildcard) query → address is "" for Hop.
        if topic0.lower() == HOP_BOND_T0:
            return list(self._logs)
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> Any:
        return SimpleNamespace(raw_receipt={"logs": [{
            "address": USDC,
            "topics": [ERC20_TRANSFER, _topic_addr(HOP_DEST_EMITTER), _topic_addr(HOP_RECIP)],
            "data": hex(50000000000000),
        }]})


def test_hop_source_emitters_loaded_from_bridges_json() -> None:
    spec = get_pair_spec("Hop")
    assert spec is not None and spec.dest_wildcard is True
    assert HOP_SRC_EMITTER in spec.source_contracts, (
        "Hop source emitters must load from bridges.json"
    )


def test_hop_confirm_indexed_transferid_high() -> None:
    adapter = _FakeHopAdapter([_hop_bond_log()])
    out = confirm_bridge_destination(
        protocol="Hop", destination_chain="optimism",
        source_receipt=_hop_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 1, 1, tzinfo=UTC), source_chain="base",
    )
    assert out is not None
    assert out.confidence == "high"
    assert out.order_id == HOP_XFER
    assert out.dst_tx == "0xhopbond"
    assert (out.recipient or "").lower() == HOP_RECIP


def test_hop_tampered_transferid_returns_none() -> None:
    adapter = _FakeHopAdapter([_hop_bond_log(xfer="0x" + "ab" * 32)])
    out = confirm_bridge_destination(
        protocol="Hop", destination_chain="optimism",
        source_receipt=_hop_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 1, 1, tzinfo=UTC), source_chain="base",
    )
    assert out is None


def test_hop_identify_source_reads_dest_chain_from_topic() -> None:
    ident = identify_source(_hop_source_receipt(dest_chain_id=10))
    assert ident is not None
    spec, oid, dest_chain = ident
    assert spec.protocol == "Hop"
    assert oid == HOP_XFER
    assert dest_chain == "optimism"


# ===================== Synapse (derived kappa = keccak(ascii(srcTxHash))) ====
# Verified vs 5 real Eth→BSC pairs: src TokenDeposit 0x1deca897… → derived kappa
# 0x867be90c… == dest BSC TokenMint topics[2].

SYN_SRC_TX = "0x1deca8979d670d04eec269502cc5435aeaabb0354f72615514ede521419f0282"
SYN_KAPPA = "0x867be90cef9605d157d3f2cb76101c03e53bffb3af0386a69afe80ba32de8483"
SYN_ETH = "0x2796317b0ff8538f253012862c06787adfb8ceb6"
SYN_BSC = "0xd123f70ae324d34a9e76b67a27bf77593ba8749f"
SYN_DEPOSIT_T0 = "0xda5273705dbef4bf1b902a131c2eac086b7e1476a8ab0cb4da08af1fe1bd8e3b"
SYN_MINT_T0 = "0xbf14b9fde87f6e1c29a7e0787ad1d0d64b4648d8ae63da21524d9fd0f283dd38"
SYN_RECIP = "0xfdff0b5600000000000000000000000000000000"


def _syn_source_receipt(src_tx: str = SYN_SRC_TX, dest_chain_id: int = 56) -> dict[str, Any]:
    # TokenDeposit(to indexed, chainId, token, amount): chainId = data word 0.
    return {
        "transactionHash": src_tx,
        "logs": [{
            "address": SYN_ETH,
            "topics": [SYN_DEPOSIT_T0, _topic_addr("0x" + "ab" * 20)],
            "data": "0x" + _word(_padint(dest_chain_id)) + _word("0x0") + _word("0x0"),
        }],
    }


def _syn_mint_log(kappa: str = SYN_KAPPA, tx: str = "0xsynmint") -> dict[str, Any]:
    return {"address": SYN_BSC,
            "topics": [SYN_MINT_T0, _topic_addr(SYN_RECIP), kappa],
            "data": "0x", "transactionHash": tx}


class _FakeSynapseAdapter:
    def __init__(self, logs: list[dict[str, Any]]) -> None:
        self._logs = logs

    def block_at_or_before(self, ts: datetime) -> int:
        return 100

    def fetch_logs(self, address, topic0, *, from_block, to_block, topics=None):
        if address.lower() == SYN_BSC and topic0.lower() == SYN_MINT_T0:
            return list(self._logs)
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> Any:
        return SimpleNamespace(raw_receipt={"logs": [{
            "address": USDT,
            "topics": [ERC20_TRANSFER, _topic_addr(SYN_BSC), _topic_addr(SYN_RECIP)],
            "data": hex(5000000),
        }]})


def test_synapse_extract_derives_kappa_from_txhash() -> None:
    spec = get_pair_spec("Synapse")
    # The derived id must equal the real on-chain kappa for the verified tx.
    assert extract_source_order_id(spec, _syn_source_receipt()) == SYN_KAPPA


def test_synapse_derive_requires_a_recognized_source_event() -> None:
    """No Synapse source event in the receipt → don't derive a kappa for an
    unrelated tx."""
    spec = get_pair_spec("Synapse")
    assert extract_source_order_id(spec, {"transactionHash": SYN_SRC_TX, "logs": []}) is None


def test_synapse_confirm_derived_kappa_match_high() -> None:
    adapter = _FakeSynapseAdapter([_syn_mint_log()])
    out = confirm_bridge_destination(
        protocol="Synapse", destination_chain="bsc",
        source_receipt=_syn_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 1, 1, tzinfo=UTC), source_chain="ethereum",
    )
    assert out is not None
    assert out.confidence == "high"
    assert out.order_id == SYN_KAPPA
    assert out.dst_tx == "0xsynmint"
    assert (out.recipient or "").lower() == SYN_RECIP


def test_synapse_tampered_kappa_returns_none() -> None:
    adapter = _FakeSynapseAdapter([_syn_mint_log(kappa="0x" + "cd" * 32)])
    out = confirm_bridge_destination(
        protocol="Synapse", destination_chain="bsc",
        source_receipt=_syn_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 1, 1, tzinfo=UTC), source_chain="ethereum",
    )
    assert out is None


def test_synapse_identify_source_derives_and_reads_dest_chain_word() -> None:
    ident = identify_source(_syn_source_receipt(dest_chain_id=56))
    assert ident is not None
    spec, oid, dest_chain = ident
    assert spec.protocol == "Synapse"
    assert oid == SYN_KAPPA
    assert dest_chain == "bsc"


# ===================== CCIP (topic0-only source, success-gated dest) ========
# Verified: Eth CCIPSendRequested (messageId data word 13) → BSC
# ExecutionStateChanged (messageId topic2, state word0==2). msgId 0x602d8eaa….

CCIP_SEND_T0 = "0xd0c3c799bf9e2639de44391e7f524d229b2b55f5b1ea94b2bf7da42f7243dddd"
CCIP_EXEC_T0 = "0xd4f851956a5d67c3997d1c9205045fef79bae2947fdee7e9e2641abc7391ef65"
CCIP_MSGID = "0x602d8eaa51ed66c06613521e0ddadfd29f56c94ad495b1e62d43f5cfa21b7088"
CCIP_ONRAMP = "0x948306c220ac325fa9392a6e601042a3cd0b480d"  # per-lane; not in any set
CCIP_OFFRAMP = "0xf616733641d420207b8f30db9c4ce39684768991"
CCIP_RECIP = "0xf5c299316699131d29adcb7ef87af8e97bbc7ead"


def _ccip_source_receipt(msgid: str = CCIP_MSGID) -> dict[str, Any]:
    # CCIPSendRequested: 1 struct arg; word0=outer offset, …, word13=messageId.
    data = "0x" + _word("0x20") + _word("0x0") * 12 + _word(msgid)
    return {"logs": [{
        "address": CCIP_ONRAMP, "topics": [CCIP_SEND_T0], "data": data,
    }]}


def _ccip_exec_log(msgid: str = CCIP_MSGID, state: int = 2, tx: str = "0xccipexec") -> dict[str, Any]:
    # ExecutionStateChanged: topic1=seq, topic2=messageId; data word0=state.
    return {
        "address": CCIP_OFFRAMP,
        "topics": [CCIP_EXEC_T0, _padint(21239), msgid],
        "data": "0x" + _word(hex(state)) + _word("0x40"),
        "transactionHash": tx,
    }


class _FakeCCIPAdapter:
    def __init__(self, logs: list[dict[str, Any]]) -> None:
        self._logs = logs

    def block_at_or_before(self, ts: datetime) -> int:
        return 100

    def fetch_logs(self, address, topic0, *, from_block, to_block, topics=None):
        if topic0.lower() == CCIP_EXEC_T0:  # address-less wildcard
            return list(self._logs)
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> Any:
        return SimpleNamespace(raw_receipt={"logs": [{
            "address": USDC,
            "topics": [ERC20_TRANSFER, _topic_addr(CCIP_OFFRAMP), _topic_addr(CCIP_RECIP)],
            "data": hex(13326686183618000138270),
        }]})


def test_ccip_extract_messageid_from_data_word13() -> None:
    spec = get_pair_spec("CCIP")
    assert spec is not None and spec.source_match_topic0_only is True
    # topic0-only recognition: the per-lane OnRamp is NOT in any address set.
    assert extract_source_order_id(spec, _ccip_source_receipt()) == CCIP_MSGID


def test_ccip_confirm_messageid_state_success_high() -> None:
    adapter = _FakeCCIPAdapter([_ccip_exec_log(state=2)])
    out = confirm_bridge_destination(
        protocol="CCIP", destination_chain="bsc",
        source_receipt=_ccip_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 1, 1, tzinfo=UTC), source_chain="ethereum",
    )
    assert out is not None
    assert out.confidence == "high"
    assert out.order_id == CCIP_MSGID
    assert out.dst_tx == "0xccipexec"
    assert (out.recipient or "").lower() == CCIP_RECIP


def test_ccip_failed_execution_state_not_confirmed() -> None:
    """A FAILED CCIP execution (state != 2) with the matching messageId must NOT
    be reported as a delivered destination."""
    adapter = _FakeCCIPAdapter([_ccip_exec_log(state=3)])  # 3 = FAILURE
    out = confirm_bridge_destination(
        protocol="CCIP", destination_chain="bsc",
        source_receipt=_ccip_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 1, 1, tzinfo=UTC), source_chain="ethereum",
    )
    assert out is None


def test_ccip_tampered_messageid_returns_none() -> None:
    adapter = _FakeCCIPAdapter([_ccip_exec_log(msgid="0x" + "ab" * 32)])
    out = confirm_bridge_destination(
        protocol="CCIP", destination_chain="bsc",
        source_receipt=_ccip_source_receipt(), dst_adapter=adapter,
        src_block_time=datetime(2025, 1, 1, tzinfo=UTC), source_chain="ethereum",
    )
    assert out is None


def test_ccip_identify_source_topic0_only() -> None:
    ident = identify_source(_ccip_source_receipt())
    assert ident is not None
    spec, oid, dest_chain = ident
    assert spec.protocol == "CCIP"
    assert oid == CCIP_MSGID
    assert dest_chain is None  # CCIP dest chain comes from the Router calldata


# ===================== live-trace wiring (_confirm_bridge_handoffs) ==========
# tracer._confirm_bridge_handoffs is the bridge between the heuristic cross-chain
# continuation and the cryptographic oracle: for each handoff with a verified
# pairing spec it confirms the destination on-chain and returns it for seeding +
# the Phase-2 report. These lock in the contract the live wiring depends on.


def _wiring_handoff(
    protocol: str = "deBridge DLN Source",
    dest_chain: str | None = "ethereum",
) -> Any:
    return SimpleNamespace(
        bridge_protocol=protocol,
        source_tx_hash="0xsrc",
        source_chain=SimpleNamespace(value="arbitrum"),
        block_time_iso="2025-10-09T00:00:00Z",
        decoded_destination_chain=dest_chain,
    )


def _wiring_src_adapter(receipt: dict[str, Any]) -> Any:
    return SimpleNamespace(
        fetch_evidence_receipt=lambda tx: SimpleNamespace(
            raw_receipt=receipt, block_time=datetime(2025, 10, 9, tzinfo=UTC),
        ),
    )


def test_confirm_bridge_handoffs_records_confirmed_destination(monkeypatch) -> None:
    """A handoff with a verified spec is cryptographically confirmed via the
    oracle and returned with its ConfirmedDestination + parsed source time."""
    from recupero.trace import tracer

    fake_dst = _FakeDstAdapter([_fulfilled_log(ORDER_ID)])
    monkeypatch.setattr(tracer.ChainAdapter, "for_chain", lambda *a, **k: fake_dst)

    out = tracer._confirm_bridge_handoffs(
        [_wiring_handoff()],
        src_adapter=_wiring_src_adapter(_source_receipt(ORDER_ID)),
        config=object(),
        env=object(),
        window_hours=24.0,
        incident_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    assert len(out) == 1
    _h, confirmed, sbt = out[0]
    assert confirmed.order_id == ORDER_ID
    assert (confirmed.recipient or "").lower() == RECEIVER
    assert confirmed.dst_chain == "ethereum"
    assert confirmed.confidence == "high"
    assert sbt == datetime(2025, 10, 9, tzinfo=UTC)  # parsed from block_time_iso


def test_confirm_bridge_handoffs_skips_unknown_protocol(monkeypatch) -> None:
    """A handoff whose protocol has no verified pairing spec is skipped without
    even instantiating a destination adapter — no fabricated confirmation."""
    from recupero.trace import tracer

    def _boom(*a, **k):
        raise AssertionError("must not instantiate dst adapter for unknown bridge")

    monkeypatch.setattr(tracer.ChainAdapter, "for_chain", _boom)
    out = tracer._confirm_bridge_handoffs(
        [_wiring_handoff(protocol="TotallyUnknownBridge")],
        src_adapter=_wiring_src_adapter({"logs": []}),
        config=object(),
        env=object(),
        window_hours=24.0,
        incident_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    assert out == []


def test_confirm_bridge_handoffs_tampered_dest_not_confirmed(monkeypatch) -> None:
    """If the destination fill references a DIFFERENT order-id, the handoff is
    NOT confirmed — the wiring never seeds a false-positive destination."""
    from recupero.trace import tracer

    fake_dst = _FakeDstAdapter([_fulfilled_log(OTHER_ID)])
    monkeypatch.setattr(tracer.ChainAdapter, "for_chain", lambda *a, **k: fake_dst)
    out = tracer._confirm_bridge_handoffs(
        [_wiring_handoff(protocol="DeBridge")],
        src_adapter=_wiring_src_adapter(_source_receipt(ORDER_ID)),
        config=object(),
        env=object(),
        window_hours=24.0,
        incident_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    assert out == []


def test_confirm_bridge_handoffs_source_fetch_failure_skips(monkeypatch) -> None:
    """A source-receipt fetch error degrades to skip (best-effort, never raises)."""
    from recupero.trace import tracer

    monkeypatch.setattr(
        tracer.ChainAdapter, "for_chain",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("unreachable")),
    )

    def _raise(tx):
        raise RuntimeError("rpc down")

    src = SimpleNamespace(fetch_evidence_receipt=_raise)
    out = tracer._confirm_bridge_handoffs(
        [_wiring_handoff()],
        src_adapter=src,
        config=object(),
        env=object(),
        window_hours=24.0,
        incident_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    assert out == []
