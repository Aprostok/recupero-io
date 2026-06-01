"""Bridge source↔destination pairing by the protocol's own cross-chain order /
message ID — the answer-key-free correctness oracle (v0.34).

A bridge stamps a unique cross-chain identifier on the SOURCE chain (in an
order-creation event) and the DESTINATION chain references the SAME id in its
fill / mint event. Matching the two by that id is CRYPTOGRAPHIC proof of the hop
— it needs no human ground truth, and it is the ONLY basis on which a
cross-chain edge may be assigned ``high`` confidence (protocol identity, not
amount/time inference). Everything else (the existing ``bridge_matching``
amount+time correlation) stays capped at ``medium``/``low``.

Two verified pairing SHAPES are supported:

  * **32-byte data id** (deBridge DLN): the order-id is an unforgeable bytes32
    in the source order event's data; the destination fill event carries the
    same bytes32. Matched by scanning the fill event payload for the exact id —
    a 32-byte collision is impossible, so the match alone is proof.
  * **indexed composite key** (Across): the id is a small ``depositId`` in an
    INDEXED topic, unique only PER origin chain, so it is paired together with
    the ``originChainId`` topic. Matched by a server-side topic filter
    (depositId) plus an origin-chain-id check — the pair is unique.

Each ``BridgePairSpec`` MUST be verified against a REAL on-chain source+dest
pair before it is trusted (see docs/BRIDGE_PAIRING.md). Guessing an event
signature is exactly the wrong-selector class of bug this module prevents.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

log = logging.getLogger(__name__)

_ZERO_ADDR = "0x0000000000000000000000000000000000000000"

#: chain value → real EVM chain id (Across encodes origin/destination as the
#: real chain id in indexed topics).
_REAL_CHAIN_ID: dict[str, int] = {
    "ethereum": 1,
    "optimism": 10,
    "polygon": 137,
    "arbitrum": 42161,
    "base": 8453,
    "bsc": 56,
    "avalanche": 43114,
    "zksync": 324,
}
_CHAIN_BY_REAL_ID: dict[int, str] = {v: k for k, v in _REAL_CHAIN_ID.items()}


@dataclass(frozen=True)
class BridgePairSpec:
    """How to pair a bridge's source order with its destination fill, verified
    against real on-chain data. Addresses are lowercased.

    Source id location: exactly one of ``source_order_id_word`` (a 32-byte data
    word index) or ``source_order_id_topic`` (an indexed-topic index).

    Destination match: when ``dest_id_topic`` is set, the id is matched as an
    indexed topic (server-side filter) and — if ``dest_origin_chain_topic`` is
    set — the origin-chain-id topic must equal the source chain's real chain id
    (the Across composite-key shape). Otherwise the id is a 32-byte value scanned
    for anywhere in the fill event payload (the DLN shape).

    Destination contract: ``dest_contract`` (a single deterministic-deploy
    address used on every chain) OR ``dest_contracts`` (a per-chain map).
    """

    protocol: str
    source_contracts: frozenset[str]
    source_event_topic0: str
    dest_event_topic0: str
    max_fee_pct: Decimal
    # source id location (exactly one)
    source_order_id_word: int | None = None
    source_order_id_topic: int | None = None
    # destination contract (one of)
    dest_contract: str | None = None
    dest_contracts: dict[str, str] | None = None
    # destination match shape
    dest_id_topic: int | None = None            # topic index of id on the fill (composite shape)
    dest_origin_chain_topic: int | None = None  # topic index of originChainId on the fill
    # topic index of destinationChainId (real chain id) on the SOURCE event, when
    # the destination chain can be read straight from the source event rather
    # than decoded from calldata (robust to periphery/multicall entrypoints).
    source_dest_chain_topic: int | None = None
    notes: str = ""

    def dest_contract_for(self, chain: str | None) -> str | None:
        if self.dest_contracts is not None:
            return self.dest_contracts.get((chain or "").lower())
        return self.dest_contract


@dataclass(frozen=True)
class ConfirmedDestination:
    """A cryptographically-confirmed cross-chain destination."""

    protocol: str
    order_id: str
    dst_chain: str
    dst_tx: str
    dst_contract: str
    recipient: str | None
    raw_amount: int | None
    confidence: str  # always "high" — order-id matched on both chains
    basis: str


# ── verified-core registry ──────────────────────────────────────────────────
# Only protocols whose source order-id offset AND destination fill event have
# been confirmed against a real on-chain source+dest pair belong here.

_DLN = BridgePairSpec(
    protocol="DeBridge",
    # DlnSource — deterministic deploy across EVM chains.
    source_contracts=frozenset({"0xef4fb24ad0916217251f553c0596f8edc630eb66"}),
    # CreatedOrder(Order order, bytes32 orderId, ...) — orderId at data word 1
    # (word 0 is the dynamic `order` tuple offset pointer). VERIFIED on Arbitrum
    # tx 0xd4bf228f… (Zigha): word 1 == 0x57825e7d…1f9b == the Ethereum
    # FulfilledOrder's orderId.
    source_event_topic0=(
        "0xfc8703fd57380f9dd234a89dce51333782d49c5902f307b02f03e014d18fe471"
    ),
    source_order_id_word=1,
    # DlnDestination — deterministic deploy across EVM chains.
    dest_contract="0xe7351fd770a37282b91d153ee690b63579d6dd7f",
    dest_event_topic0=(
        "0xd281ee92bab1446041582480d2c0a9dc91f855386bb27ea295faac1e992f7fe4"
    ),
    # 32-byte id scanned in the fill payload (no composite key needed).
    max_fee_pct=Decimal("1.0"),
    notes="deBridge DLN createSaltedOrder→FulfilledOrder; verified vs Zigha pair.",
)

# Across V3 SpokePool — per-chain contracts; id is the small uint depositId in
# an indexed topic, paired with originChainId. VERIFIED real pair: Base deposit
# 0x91f8874e… (FundsDeposited topic0 0x32ed1a40, destChainId=1, depositId=
# 5729990) → Ethereum fill 0xdd8c3fd0… (FilledRelay topic0 0x44b559f1,
# originChainId=8453, depositId=5729990).
_ACROSS_SPOKEPOOLS: dict[str, str] = {
    "ethereum": "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5",
    "arbitrum": "0xe35e9842fceaca1f60ef4db1a48a9c12d9c2db5e",
    "optimism": "0x6f26bf09b1c792e3228e5467807a900a503c0281",
    "base": "0x09aea4b2242abc8bb4bb78d537a67a245a7bec64",
    "polygon": "0x9295ee1d8c5b022be115a2ad3c30c72e34e7f096",
}
_ACROSS = BridgePairSpec(
    protocol="Across",
    source_contracts=frozenset(_ACROSS_SPOKEPOOLS.values()),
    # FundsDeposited: topic1=destinationChainId, topic2=depositId, topic3=depositor.
    source_event_topic0=(
        "0x32ed1a409ef04c7b0227189c3a103dc5ac10e775a15b785dcc510201f7c25ad3"
    ),
    source_order_id_topic=2,            # depositId
    dest_contracts=_ACROSS_SPOKEPOOLS,
    # FilledRelay: topic1=originChainId, topic2=depositId, topic3=relayer.
    dest_event_topic0=(
        "0x44b559f101f8fbcc8a0ea43fa91a05a729a5ea6e14a7c75aa750374690137208"
    ),
    dest_id_topic=2,                    # depositId (server-filtered)
    dest_origin_chain_topic=1,          # originChainId must == source chain id
    source_dest_chain_topic=1,          # destinationChainId on FundsDeposited
    max_fee_pct=Decimal("1.0"),
    notes="Across V3 FundsDeposited→FilledRelay; verified Base→Ethereum pair.",
)

# Celer cBridge — per-chain pool bridges. The source `Send` event carries the
# 32-byte transferId in DATA word 0; the destination `Relay` event carries it
# again as `srcTransferId` in DATA word 6 (Relay word 0 is the dest's OWN
# transferId — NOT the cross-chain key). A 32-byte id is unforgeable, so the
# scan-the-payload match (dest_id_topic=None) lands on word 6 unambiguously.
# VERIFIED real pair: BSC Send 0xc31bb378 (transferId 0x00c9ad07…) → Ethereum
# Relay 0x05e78067 (srcTransferId 0x00c9ad07…), USDT 187,331.
_CELER_CBRIDGES: dict[str, str] = {
    "ethereum": "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820",
    "bsc": "0xdd90e5e87a2081dcf0391920868ebc2ffb81a1af",
    "arbitrum": "0x1619de6b6b20ed217a58d00f37b9d47c7663feca",
    "optimism": "0x9d39fc627a6d9d9f8c831c16995b209548cc3401",
    "polygon": "0x88dcdc47d2f83a99cf0000fdf667a468bb958a78",
}
_CELER = BridgePairSpec(
    protocol="Celer",
    source_contracts=frozenset(_CELER_CBRIDGES.values()),
    source_event_topic0=(
        "0x89d8051e597ab4178a863a5190407b98abfeff406aa8db90c59af76612e58f01"
    ),
    source_order_id_word=0,             # Send.transferId
    dest_contracts=_CELER_CBRIDGES,
    dest_event_topic0=(
        "0x79fa08de5149d912dce8e5e8da7a7c17ccdf23dd5d3bfe196802e6eb86347c7c"
    ),
    # 32-byte id scanned in the Relay payload → finds srcTransferId at word 6.
    max_fee_pct=Decimal("1.0"),
    notes="Celer cBridge Send.transferId(w0)==Relay.srcTransferId(w6); verified BSC→Eth.",
)

_REGISTRY: tuple[BridgePairSpec, ...] = (_DLN, _ACROSS, _CELER)


def get_pair_spec(protocol: str | None) -> BridgePairSpec | None:
    """Resolve a ``BridgePairSpec`` by bridge protocol/label substring (the same
    permissive matching the calldata-decoder dispatch uses)."""
    if not protocol:
        return None
    p = protocol.lower()
    for spec in _REGISTRY:
        if spec.protocol.lower() in p:
            return spec
    return None


def _norm_word(w: str | None) -> str:
    if not w:
        return ""
    w = w.strip().lower()
    if not w.startswith("0x"):
        w = "0x" + w
    return w


def _data_word(data_hex: str | None, idx: int) -> str | None:
    if not data_hex:
        return None
    d = data_hex[2:] if data_hex.startswith("0x") else data_hex
    start, end = idx * 64, idx * 64 + 64
    if end > len(d):
        return None
    return "0x" + d[start:end].lower()


def _all_words(data_hex: str | None) -> set[str]:
    if not data_hex:
        return set()
    d = data_hex[2:] if data_hex.startswith("0x") else data_hex
    return {"0x" + d[i:i + 64].lower() for i in range(0, len(d) - len(d) % 64, 64)}


def _topic(topics: list[str] | None, idx: int) -> str | None:
    if not topics or idx >= len(topics):
        return None
    return _norm_word(topics[idx])


def extract_source_order_id(
    spec: BridgePairSpec, raw_source_receipt: dict[str, Any] | None
) -> str | None:
    """Pull the cross-chain order-id out of the source tx receipt's
    order-creation event, from the spec's verified location (a topic for the
    composite shape, a data word for the 32-byte shape). Defensive — never raises.
    """
    if not isinstance(raw_source_receipt, dict):
        return None
    logs = raw_source_receipt.get("logs")
    if not isinstance(logs, list):
        return None
    for lg in logs:
        if not isinstance(lg, dict):
            continue
        if (lg.get("address") or "").lower() not in spec.source_contracts:
            continue
        topics = lg.get("topics") or []
        if _topic(topics, 0) != spec.source_event_topic0:
            continue
        if spec.source_order_id_topic is not None:
            oid = _topic(topics, spec.source_order_id_topic)
        else:
            oid = _data_word(lg.get("data"), spec.source_order_id_word or 0)
        if oid and oid != "0x" + "0" * 64:
            return oid
    return None


def identify_source(
    raw_source_receipt: dict[str, Any] | None,
) -> tuple[BridgePairSpec, str, str | None] | None:
    """Resolve ``(spec, order_id, destination_chain)`` from a source tx receipt
    by scanning its EVENT LOGS for a known source order event.

    Robust to periphery / multicall entrypoints: the tx ``to`` is often a router
    or periphery contract, but the bridge contract still emits its order event in
    the receipt, so we identify the protocol from the emitted event — not the tx
    target. ``destination_chain`` is read from the source event's
    destinationChainId topic when the spec declares one (Across); otherwise None
    (the caller decodes it from calldata, e.g. DLN's takeChainId). Returns None
    when no known source order event is present.
    """
    if not isinstance(raw_source_receipt, dict):
        return None
    logs = raw_source_receipt.get("logs")
    if not isinstance(logs, list):
        return None
    for lg in logs:
        if not isinstance(lg, dict):
            continue
        emitter = (lg.get("address") or "").lower()
        topics = lg.get("topics") or []
        t0 = _topic(topics, 0)
        for spec in _REGISTRY:
            if emitter not in spec.source_contracts or t0 != spec.source_event_topic0:
                continue
            if spec.source_order_id_topic is not None:
                oid = _topic(topics, spec.source_order_id_topic)
            else:
                oid = _data_word(lg.get("data"), spec.source_order_id_word or 0)
            if not oid or oid == "0x" + "0" * 64:
                continue
            dest_chain: str | None = None
            if spec.source_dest_chain_topic is not None:
                cid_word = _topic(topics, spec.source_dest_chain_topic)
                if cid_word:
                    try:
                        dest_chain = _CHAIN_BY_REAL_ID.get(int(cid_word, 16))
                    except ValueError:
                        dest_chain = None
            return spec, oid, dest_chain
    return None


def _fill_recipient_amount(
    dst_adapter: Any, dst_tx: str, *, infra: set[str]
) -> tuple[str | None, int | None]:
    """From the destination fill tx, return (recipient, raw_amount) of the
    largest ERC-20 payout to a TERMINAL non-infra recipient (one that doesn't
    itself re-send within the tx — so we land on the resting receiver, not a
    solver's internal swap leg). Best-effort; the id match is the proof."""
    from recupero.trace.swap_output import parse_erc20_transfers

    try:
        receipt = dst_adapter.fetch_evidence_receipt(dst_tx)
        raw = getattr(receipt, "raw_receipt", None)
    except Exception as exc:  # noqa: BLE001
        log.debug("fill recipient fetch failed tx=%s: %s", dst_tx, exc)
        return None, None
    transfers = parse_erc20_transfers(raw)
    infra_lc = {a.lower() for a in infra} | {_ZERO_ADDR}
    senders_in_tx = {t.frm for t in transfers}
    best_to: str | None = None
    best_amt = 0
    for t in transfers:
        if t.to in infra_lc or t.amount <= 0 or t.to in senders_in_tx:
            continue
        if t.amount > best_amt:
            best_amt = t.amount
            best_to = t.to
    return best_to, (best_amt or None)


def confirm_bridge_destination(
    *,
    protocol: str | None,
    destination_chain: str | None,
    source_receipt: dict[str, Any] | None,
    dst_adapter: Any,
    src_block_time: datetime,
    source_chain: str | None = None,
    window_hours: float = 24.0,
    order_id: str | None = None,
) -> ConfirmedDestination | None:
    """Confirm a bridge handoff's destination by matching the protocol id on the
    destination chain. Returns a ``high``-confidence ``ConfirmedDestination`` on
    an exact match, or ``None`` (never a guess).

    ``dst_adapter`` is the adapter for ``destination_chain`` and must expose
    ``fetch_logs`` + ``block_at_or_before`` + ``fetch_evidence_receipt``.
    ``source_chain`` is required for the composite-key (Across) shape so the
    origin-chain-id topic can be checked.
    """
    spec = get_pair_spec(protocol)
    if spec is None:
        return None

    oid = _norm_word(order_id) if order_id else extract_source_order_id(
        spec, source_receipt
    )
    if not oid or oid == "0x" + "0" * 64:
        return None

    dst_contract = spec.dest_contract_for(destination_chain)
    if not dst_contract:
        return None

    try:
        from_block = dst_adapter.block_at_or_before(src_block_time)
    except Exception as exc:  # noqa: BLE001
        log.warning("confirm: from-block lookup failed: %s", exc)
        return None
    try:
        to_block: int | str = dst_adapter.block_at_or_before(
            src_block_time + timedelta(hours=window_hours)
        )
    except Exception:  # noqa: BLE001
        to_block = "latest"

    # Build the destination log query. Composite shape filters the id server-side
    # at its topic; 32-byte shape scans the payload.
    topics_filter: list[str | None] | None = None
    if spec.dest_id_topic is not None:
        topics_filter = [None, None, None]
        if 1 <= spec.dest_id_topic <= 3:
            topics_filter[spec.dest_id_topic - 1] = oid

    try:
        logs = dst_adapter.fetch_logs(
            dst_contract, spec.dest_event_topic0,
            from_block=from_block, to_block=to_block, topics=topics_filter,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("confirm: dest fetch_logs failed: %s", exc)
        return None

    # Expected origin-chain-id topic value for the composite shape.
    want_origin = None
    if spec.dest_origin_chain_topic is not None and source_chain:
        cid = _REAL_CHAIN_ID.get(source_chain.lower())
        if cid is not None:
            want_origin = "0x" + f"{cid:064x}"

    for lg in logs or []:
        if not isinstance(lg, dict):
            continue
        if spec.dest_id_topic is not None:
            # composite shape: confirm the id topic + (origin chain id topic)
            if _topic(lg.get("topics"), spec.dest_id_topic) != oid:
                continue
            if want_origin is not None and _topic(
                lg.get("topics"), spec.dest_origin_chain_topic
            ) != want_origin:
                continue
        else:
            # 32-byte shape: scan the payload (+ topics) for the exact id.
            words = _all_words(lg.get("data")) | {
                _norm_word(t) for t in (lg.get("topics") or [])
            }
            if oid not in words:
                continue
        dst_tx = lg.get("transactionHash") or lg.get("transaction_hash") or ""
        recipient, raw_amount = _fill_recipient_amount(
            dst_adapter, dst_tx,
            infra={dst_contract, *spec.source_contracts},
        )
        log.info(
            "bridge destination CONFIRMED (id match): protocol=%s id=%s "
            "dst_chain=%s dst_tx=%s recipient=%s",
            spec.protocol, oid[:14] + "…", destination_chain, dst_tx, recipient,
        )
        return ConfirmedDestination(
            protocol=spec.protocol,
            order_id=oid,
            dst_chain=destination_chain or "",
            dst_tx=dst_tx,
            dst_contract=dst_contract,
            recipient=recipient,
            raw_amount=raw_amount,
            confidence="high",
            basis=(
                f"protocol id {oid} matched on both the {spec.protocol} source "
                f"event ({spec.source_event_topic0[:10]}…) and the destination "
                f"fill ({spec.dest_event_topic0[:10]}…)"
                + (
                    f" with origin-chain-id == {source_chain}"
                    if spec.dest_origin_chain_topic is not None else ""
                )
                + " — cryptographic match"
            ),
        )
    return None


__all__ = (
    "BridgePairSpec",
    "ConfirmedDestination",
    "get_pair_spec",
    "extract_source_order_id",
    "identify_source",
    "confirm_bridge_destination",
)
