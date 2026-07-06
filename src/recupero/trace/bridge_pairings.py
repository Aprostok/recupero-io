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
from decimal import Decimal, InvalidOperation
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

#: chain value → Wormhole INTERNAL chain id (NOT the EVM chain id). Wormhole
#: stamps the source chain as this id in the destination TransferRedeemed's
#: emitterChainId topic. Source: https://wormhole.com/docs/products/reference/chain-ids/
_WH_CHAIN_ID: dict[str, int] = {
    "ethereum": 2,
    "bsc": 4,
    "polygon": 5,
    "avalanche": 6,
    "arbitrum": 23,
    "optimism": 24,
    "base": 30,
}

#: chain value → LayerZero V2 ENDPOINT id (NOT the EVM chain id). Stargate (and
#: every LayerZero OFT) stamps the destination as this eid in OFTSent.dstEid and
#: the source as srcEid in OFTReceived. Source: LayerZero deployed-endpoints docs.
_LZ_EID: dict[str, int] = {
    "ethereum": 30101,
    "bsc": 30102,
    "avalanche": 30106,
    "polygon": 30109,
    "arbitrum": 30110,
    "optimism": 30111,
    "base": 30184,
}
_CHAIN_BY_LZ_EID: dict[int, str] = {v: k for k, v in _LZ_EID.items()}


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
    # when True, the destination fill is queried address-LESS (Etherscan getLogs
    # by topic0 + the id topic, across ALL emitters) — for protocols with many
    # per-token/per-pool contracts (Hop) where the id is a globally-unique
    # indexed bytes32 so no address is needed to disambiguate.
    dest_wildcard: bool = False
    # v0.34 Synapse shape: the cross-chain id is NOT emitted on the source — it
    # is DERIVED from the source tx hash. "event" (default) reads it from the
    # source event; "keccak_ascii_txhash" computes keccak256(ascii("0x"+txHash)).
    source_id_kind: str = "event"
    # extra source-event topic0s for protocol RECOGNITION (a protocol with
    # several source event variants, e.g. Synapse TokenDeposit/TokenRedeem/…).
    source_event_topics: tuple[str, ...] = ()
    # destinationChainId in a source-event DATA word (real chain id), when not a
    # topic (Synapse TokenRedeem.chainId is data word 0).
    source_dest_chain_word: int | None = None
    # extra destination fill topic0s (Synapse TokenMint/TokenWithdraw/…AndSwap).
    dest_event_topics: tuple[str, ...] = ()
    # recognize the source event by topic0 ALONE (skip the emitter-membership
    # check) — for protocols whose source emitter is per-lane and not
    # enumerable (CCIP OnRamps). Safe only for a distinctive event signature.
    source_match_topic0_only: bool = False
    # require a destination data word to equal a value, e.g. CCIP
    # ExecutionStateChanged.state (word 0) == 2 (SUCCESS) so a FAILED execution
    # is never reported as a delivered destination.
    dest_state_word: int | None = None
    dest_state_ok: int | None = None
    # v0.34.3 — read the recipient/amount straight off the MATCHED fill event
    # rather than scanning the dest tx for ERC-20 Transfers. Needed for protocols
    # that deliver NATIVE value (Synapse RFQ BridgeRelayed pays ETH to `to`, which
    # emits no ERC-20 Transfer, so the generic scanner finds nothing). When
    # ``dest_recipient_topic`` is set, recipient = the address in that fill topic;
    # when ``dest_amount_word`` is set, raw_amount = that fill data word. Both fall
    # back to the ERC-20 scan when absent/zero — never fabricated.
    dest_recipient_topic: int | None = None
    dest_amount_word: int | None = None
    # v0.34.3 Axelar — a SECOND cryptographic tiebreak on the dest fill: the data
    # word at this index must equal the SOURCE tx hash (Axelar ContractCallApproved
    # carries sourceTxHash at data word 2). Pairs with a payloadHash topic match so
    # a colliding payloadHash (identical payloads) can never produce a false pair.
    dest_source_txhash_word: int | None = None
    # v0.34 Phase 2 — conservation: True when the protocol delivers the SAME
    # asset on both chains (canonical/liquidity bridge), so the raw deposit and
    # fill amounts are directly comparable and must satisfy the fee bound
    # (dst ∈ [src·(1−maxFee), src]). False when the protocol can deliver a
    # DIFFERENT asset (DLN give≠take; Synapse …AndSwap; CCIP arbitrary token) —
    # raw-amount conservation is then meaningless and is NOT checked (we never
    # fabricate a violation from an apples-to-oranges comparison).
    same_asset: bool = True
    # v0.34 Wormhole composite shape — the cross-chain key is the VAA identity
    # (emitterChainId, emitterAddress, sequence). ``source_order_id_word`` holds
    # the sequence (source LogMessagePublished data word 0); ``dest_id_topic``
    # holds the sequence on the dest fill; ``dest_origin_chain_topic`` holds the
    # emitterChainId; and these two pin the emitter address:
    #   * ``source_emitter_topic`` — topic index of the emitter on the SOURCE
    #     event (Wormhole LogMessagePublished.sender = topic 1),
    #   * ``dest_emitter_topic`` — topic index of emitterAddress on the dest fill
    #     (Wormhole TransferRedeemed.emitterAddress = topic 2),
    # matched so a colliding sequence on a different emitter is rejected.
    source_emitter_topic: int | None = None
    dest_emitter_topic: int | None = None
    # which chain-id namespace the origin-chain match uses: "evm" (real chain id,
    # Across) or "wormhole" (Wormhole internal chain id, via _WH_CHAIN_ID).
    chain_id_scheme: str = "evm"
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
    # v0.34 Phase 2 — the raw amount DEPOSITED into the source bridge contract
    # (largest ERC-20 Transfer into a source emitter), for the conservation
    # check on same-asset protocols. None when not determinable / not same-asset.
    src_raw_amount: int | None = None
    same_asset: bool = True


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
    # v0.34.3 STALENESS FIX: the original FulfilledOrder topic0 (above, verified
    # vs the Oct-2025 Zigha fill) is NO LONGER EMITTED — DLN changed its fill
    # event signature at the SAME DlnDestination contract sometime after. The
    # fresh-input generalization test (Jun-2026 DLN orders) confirmed 0/3 + zero
    # FulfilledOrder events on-chain. The current fill events at 0xe7351fd7 are
    # the two below (the order-id bytes32 sits in the event payload, which the
    # 32-byte-shape engine scans). Keeping the old topic0 confirms historical
    # (Zigha-era) cases; the new ones confirm current orders. This is exactly the
    # spec-drift the staleness monitor (scripts/_v034_bridge_staleness.py) now
    # guards against going forward.
    dest_event_topics=(
        "0xc164aca37b9805a1c9027b6f32260a069723a82926f6e9ece4926e4dd3ea8ecf",
        "0x37a01d7dc38e924008cf4f2fa3d2ec1f45e7ae3c8292eb3e7d9314b7ad10e2fc",
    ),
    # 32-byte id scanned in the fill payload (no composite key needed).
    max_fee_pct=Decimal("1.0"),
    # DLN give≠take asset (the maker quotes an arbitrary take token), so raw
    # deposit/fill amounts are NOT comparable — skip conservation.
    same_asset=False,
    notes="deBridge DLN createSaltedOrder→fill; verified vs Zigha (old event) + Jun-2026 fresh orders (new events).",
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

def _load_addresses_by_name(substr: str) -> frozenset[str]:
    """Load bridge contract addresses whose label name/protocol contains
    ``substr`` (case-insensitive) from bridges.json — for protocols with many
    per-token contracts (Hop). Best-effort: returns empty on any load failure
    (the protocol then just isn't recognized, rather than raising)."""
    try:
        from recupero.trace.cross_chain import ingest_bridge_seeds
        db = ingest_bridge_seeds()
        s = substr.lower()
        out = {
            addr.lower()
            for (_chain, addr), info in db.items()
            if s in (info.name or "").lower() or s in (info.protocol or "").lower()
        }
        return frozenset(out)
    except Exception as exc:  # noqa: BLE001
        log.warning("bridge-pairing: failed to load %r addresses: %s", substr, exc)
        return frozenset()


# Hop — per-token L2 bridges. transferId is a globally-unique indexed bytes32 on
# BOTH the source `TransferSent` (topic1) and the destination `WithdrawalBonded`
# (topic1), so the destination is found address-LESS by (topic0, transferId).
# The source emitters (many per-token addresses) are loaded from bridges.json.
# VERIFIED real pair: Base TransferSent 0x3ba95375 → Optimism WithdrawalBonded
# 0x1942dd58, transferId 0x2a9767e8…, both indexed topic1.
_HOP = BridgePairSpec(
    protocol="Hop",
    source_contracts=_load_addresses_by_name("Hop:"),
    source_event_topic0=(
        "0xe35dddd4ea75d7e9b3fe93af4f4e40e778c3da4074c9d93e7c6536f1e803c1eb"
    ),
    source_order_id_topic=1,            # transferId (indexed)
    source_dest_chain_topic=2,          # destination chainId (indexed real id)
    dest_event_topic0=(
        "0x0c3d250c7831051e78aa6a56679e590374c7c424415ffe4aa474491def2fe705"
    ),
    dest_id_topic=1,                    # transferId (indexed)
    dest_wildcard=True,                 # WithdrawalBonded across any Hop bridge
    max_fee_pct=Decimal("1.0"),
    notes="Hop TransferSent.transferId(topic1)==WithdrawalBonded.transferId(topic1); verified Base→Optimism.",
)

# Synapse — kappa is NOT emitted on the source; it is derived
# keccak256(ascii("0x"+sourceTxHash)) and appears as the destination mint's
# indexed topic2. Source events (TokenDeposit/TokenRedeem) are used only to
# RECOGNIZE the tx as Synapse before deriving. VERIFIED vs 5 real Eth→BSC pairs.
# Legacy kappa-emitting bridges (the bridges.json "SynapseRouter" entries are
# the front-end routers, NOT these).
_SYNAPSE_BRIDGES: dict[str, str] = {
    "ethereum": "0x2796317b0ff8538f253012862c06787adfb8ceb6",
    "bsc": "0xd123f70ae324d34a9e76b67a27bf77593ba8749f",
    "polygon": "0x8f5bbb2bb8c2ee94639e55d5f41de9b4839c1280",
    "optimism": "0xaf41a65f786339e7911f4acdad6bd49426f2dc6b",
    "arbitrum": "0x6f4e8eba4d337f874ab57478acc2cb5bacdc19c9",
}
_SYNAPSE = BridgePairSpec(
    protocol="Synapse",
    source_contracts=frozenset(_SYNAPSE_BRIDGES.values()),
    source_event_topic0=(  # TokenDeposit
        "0xda5273705dbef4bf1b902a131c2eac086b7e1476a8ab0cb4da08af1fe1bd8e3b"
    ),
    source_event_topics=(  # TokenRedeem (other recognition variant)
        "0xdc5bad4651c5fbe9977a696aadc65996c468cde1448dd468ec0d83bf61c4b57c",
    ),
    source_id_kind="keccak_ascii_txhash",
    source_dest_chain_word=0,           # chainId is data word 0 of TokenDeposit/Redeem
    dest_contracts=_SYNAPSE_BRIDGES,
    dest_event_topic0=(  # TokenMint
        "0xbf14b9fde87f6e1c29a7e0787ad1d0d64b4648d8ae63da21524d9fd0f283dd38"
    ),
    dest_event_topics=(  # TokenWithdraw / TokenMintAndSwap / TokenWithdrawAndRemove
        "0x8b0afdc777af6946e53045a4a75212769075d30455a212ac51c9b16f9c5c9b26",
        "0x4f56ec39e98539920503fd54ee56ae0cbebe9eb15aa778f18de67701eeae7c65",
        "0xc1a608d0f8122d014d03cc915a91d98cef4ebaf31ea3552320430cba05211b6d",
    ),
    dest_id_topic=2,                    # kappa (indexed)
    max_fee_pct=Decimal("1.0"),
    # …AndSwap variants deliver a DIFFERENT token than deposited — not same-asset.
    same_asset=False,
    notes="Synapse (CLASSIC bridge) kappa=keccak256(ascii('0x'+srcTxHash))==dest mint topic2; verified vs 5 pairs. "
          "v0.34.3: the CLASSIC TokenDeposit/TokenRedeem source events are SILENT on-chain now — Synapse's "
          "current volume MOVED to the RFQ/FastBridge rail (see _SYNAPSE_RFQ below), which is covered "
          "separately and verified vs a real Optimism→Ethereum pair. This classic spec is retained for "
          "HISTORICAL Synapse cases (the dest TokenMint/TokenWithdraw contract is still live and confirms "
          "them). Tracked by scripts/_v034_bridge_staleness.py (acknowledged: historical rail).",
)

# Synapse RFQ / FastBridgeV2 — Synapse's CURRENT (intent-based) rail, deployed at
# the SAME deterministic CREATE2 address on every EVM chain. The cross-chain id is
# the `transactionId` (bytes32), emitted INDEXED as topic1 on BOTH the source
# `BridgeRequested` and the destination `BridgeRelayed` — a clean cryptographic
# pairing (no derivation needed, unlike the classic kappa). Recipient is `to`
# (BridgeRelayed topic3) and the delivered amount is destAmount (data word 4),
# read straight off the matched fill event (RFQ delivers NATIVE value, no ERC-20
# Transfer to scan). destChainId is a REAL chain id in BridgeRequested data word 1
# (word 0 is the dynamic `request` offset). Event sigs from synapsecns/sanguine
# IFastBridge.sol. VERIFIED vs a real pair: source Optimism tx 0xdf6da3c0… (txid
# 0xf88b22a5…, destChainId=1) → dest Ethereum tx 0x13b91389… (same txid topic1,
# recipient 0x77bde4b2…); source-committed destAmount == dest-delivered destAmount
# (951302461322824), originAmount ≥ destAmount (relayer fee = the difference).
_FASTBRIDGE_RFQ = "0x5523d3c98809dddb82c686e152f5c58b1b0fb59e"
_SYNAPSE_RFQ = BridgePairSpec(
    protocol="Synapse RFQ",
    source_contracts=frozenset({_FASTBRIDGE_RFQ}),
    source_event_topic0=(  # BridgeRequested(bytes32,address,bytes,uint32,address,address,uint256,uint256,bool)
        "0x120ea0364f36cdac7983bcfdd55270ca09d7f9b314a2ebc425a3b01ab1d6403a"
    ),
    source_order_id_topic=1,            # transactionId (indexed)
    source_dest_chain_word=1,           # destChainId (real id) — data word 1
    dest_contract=_FASTBRIDGE_RFQ,
    dest_event_topic0=(  # BridgeRelayed(bytes32,address,address,uint32,address,address,uint256,uint256,uint256)
        "0xf8ae392d784b1ea5e8881bfa586d81abf07ef4f1e2fc75f7fe51c90f05199a5c"
    ),
    dest_id_topic=1,                    # transactionId (indexed) on the fill
    dest_recipient_topic=3,             # `to` (indexed) on BridgeRelayed
    dest_amount_word=4,                 # destAmount — data word 4
    max_fee_pct=Decimal("1.0"),
    # RFQ is intent-based: originToken may differ from destToken (a swap), so raw
    # deposit/fill amounts are NOT comparable — skip same-asset conservation.
    same_asset=False,
    notes="Synapse RFQ/FastBridgeV2 transactionId(topic1) matched source BridgeRequested↔dest "
          "BridgeRelayed; deterministic CREATE2 0x5523…; verified vs real OP→ETH pair (txid 0xf88b22a5…).",
)

# Chainlink CCIP — messageId is a globally-unique bytes32 in the OnRamp
# `CCIPSendRequested` event DATA (word 13, the last static field of the
# EVM2EVMMessage struct) and INDEXED as topic2 on the OffRamp
# `ExecutionStateChanged`. OnRamps/OffRamps are per-lane (unenumerable), so the
# source is recognized by the distinctive CCIPSendRequested topic0 alone and the
# dest is queried address-less. The OffRamp's state (data word 0) must be 2
# (SUCCESS). Destination chain comes from the Router ccipSend calldata
# (decode_bridge_calldata, selector→chain via _CCIP_CHAIN_SELECTORS). VERIFIED:
# Eth→BSC (messageId 0x602d8eaa…, state 2) + Base→Polygon.
_CCIP = BridgePairSpec(
    protocol="CCIP",
    source_contracts=frozenset(),
    source_match_topic0_only=True,
    source_event_topic0=(
        "0xd0c3c799bf9e2639de44391e7f524d229b2b55f5b1ea94b2bf7da42f7243dddd"
    ),
    source_order_id_word=13,            # messageId (last static struct field)
    dest_wildcard=True,
    dest_event_topic0=(
        "0xd4f851956a5d67c3997d1c9205045fef79bae2947fdee7e9e2641abc7391ef65"
    ),
    dest_id_topic=2,                    # messageId (indexed)
    dest_state_word=0,                  # ExecutionStateChanged.state
    dest_state_ok=2,                    # 2 == SUCCESS
    max_fee_pct=Decimal("1.0"),
    # CCIP carries an arbitrary token+data payload; the dest amount isn't a
    # comparable same-asset transfer — skip conservation.
    same_asset=False,
    notes="Chainlink CCIP messageId: CCIPSendRequested data w13 == ExecutionStateChanged topic2 (state==2); verified Eth→BSC + Base→Polygon.",
)

# Connext (Amarok) — the transferId is a globally-unique INDEXED bytes32 on both
# the source `XCalled` (topic1) and the destination `Executed` (topic1). One
# diamond per chain. VERIFIED real pair: Optimism XCalled
# 0x32771f01… → Arbitrum Executed 0xdae39d21…, shared transferId
# 0x8956f897…dbbb7 (both topic1) — confirmed live on-chain.
_CONNEXT_DIAMONDS: dict[str, str] = {
    "ethereum": "0x8898b472c54c31894e3b9bb83cea802a5d0e63c6",
    "optimism": "0x8f7492de823025b4cfaab1d34c58963f2af5deda",
    "arbitrum": "0xee9dec2712cce65174b561151701bf54b99c24c8",
    "polygon": "0x11984dc4465481512eb5b777e44061c158cf2259",
    "base": "0xb8448c6f7f7887d36dca487370778e419e9ebe3f",
    "bsc": "0xcd401c10afa37d641d2f594852da94c700e4f2ce",
}
_CONNEXT = BridgePairSpec(
    protocol="Connext",
    source_contracts=frozenset(_CONNEXT_DIAMONDS.values()),
    source_event_topic0=(  # XCalled(bytes32 transferId, uint256 nonce, bytes32 messageHash, ...)
        "0xed8e6ba697dd65259e5ce532ac08ff06d1a3607bcec58f8f0937fe36a5666c54"
    ),
    source_order_id_topic=1,            # transferId (indexed)
    dest_contracts=_CONNEXT_DIAMONDS,
    dest_event_topic0=(  # Executed(bytes32 transferId, address to, address asset, ...)
        "0x0b07a8b0b083f8976b3c832b720632f49cb8ba1e7a99e1b145f51a47d3391cb7"
    ),
    dest_id_topic=1,                    # transferId (indexed) — globally unique, no composite key
    max_fee_pct=Decimal("1.0"),
    # Connext receiveLocal/swap can deliver a different (canonical vs nextAsset)
    # token + router fee — not reliably same-asset.
    same_asset=False,
    notes="Connext Amarok XCalled.transferId(topic1)==Executed.transferId(topic1); verified OP→ARB pair. "
          "v0.34.3 DORMANT: Amarok is deprecated (migrated to Everclear) — XCalled/Executed are SILENT "
          "and the diamonds emit nothing on-chain now. The spec stays correct for HISTORICAL Connext "
          "cases; current volume is ~nil. Tracked by scripts/_v034_bridge_staleness.py (acknowledged).",
)

# Wormhole token bridge — the cross-chain id is the VAA identity
# (emitterChainId, emitterAddress, sequence). SOURCE `LogMessagePublished` (Core
# Bridge) carries the emitter in topic1 (the Token Bridge `sender`) and the
# sequence in data word 0; DESTINATION `TransferRedeemed` (Token Bridge) carries
# emitterChainId(topic1), emitterAddress(topic2), sequence(topic3) — all indexed.
# The sequence is matched server-side; emitterChainId (Wormhole-id of the source
# chain) + emitterAddress (the source emitter) are checked client-side so a
# colliding sequence on a different emitter is rejected. VERIFIED real pair:
# Arbitrum LogMessagePublished 0xd60d0825… (emitter 0x…0b2402144…, seq 328729) →
# Ethereum TransferRedeemed 0xb4cec59b… (chainId 23, same emitter, seq 328729).
_WORMHOLE_CORE: dict[str, str] = {
    "ethereum": "0x98f3c9e6e3face36baad05fe09d375ef1464288b",
    "bsc": "0x98f3c9e6e3face36baad05fe09d375ef1464288b",
    "polygon": "0x7a4b5a56256163f07b2c80a7ca55abe66c4ec4d7",
    "arbitrum": "0xa5f208e072434bc67592e4c49c1b991ba79bca46",
    "optimism": "0xee91c335eab126df5fdb3797ea9d6ad93aec9722",
    "base": "0xbebdb6c8ddc678ffa9f8748f85c815c556dd8ac6",
}
_WORMHOLE_TOKEN: dict[str, str] = {
    "ethereum": "0x3ee18b2214aff97000d974cf647e7c347e8fa585",
    "bsc": "0xb6f6d86a8f9879a9c87f643768d9efc38c1da6e7",
    "polygon": "0x5a58505a96d1dbf8df91cb21b54419fc36e93fde",
    "arbitrum": "0x0b2402144bb366a632d14b83f244d2e0e21bd39c",
    "optimism": "0x1d68124e65fafc907325e3edbf8c4d84499daa8b",
    "base": "0x8d2de8d2f73f1f4cab472ac9a881c9b123c79627",
}
_WORMHOLE = BridgePairSpec(
    protocol="Wormhole",
    source_contracts=frozenset(_WORMHOLE_CORE.values()),
    source_event_topic0=(  # LogMessagePublished(address sender, uint64 sequence, ...)
        "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2"
    ),
    source_order_id_word=0,             # sequence (data word 0)
    source_emitter_topic=1,             # sender = the Token Bridge (VAA emitter)
    dest_contracts=_WORMHOLE_TOKEN,
    dest_event_topic0=(  # TransferRedeemed(uint16 emitterChainId, bytes32 emitterAddress, uint64 sequence)
        "0xcaf280c8cfeba144da67230d9b009c8f868a75bac9a528fa0474be1ba317c169"
    ),
    dest_id_topic=3,                    # sequence (indexed) — filtered server-side
    dest_origin_chain_topic=1,          # emitterChainId (Wormhole id), checked client-side
    dest_emitter_topic=2,               # emitterAddress, checked == source emitter
    chain_id_scheme="wormhole",
    max_fee_pct=Decimal("1.0"),
    # token bridge wraps/unwraps + normalizes to 8 decimals — amounts not
    # directly comparable; not same-asset for conservation.
    same_asset=False,
    notes="Wormhole VAA (emitterChainId,emitterAddress,sequence): LogMessagePublished→TransferRedeemed; verified ARB→ETH pair.",
)

# Stargate V2 — Stargate's pools are LayerZero OFTs; the cross-chain id is the
# LayerZero GUID (bytes32), emitted INDEXED as topic1 on BOTH the source OFTSent
# and the destination OFTReceived. dstEid/srcEid are LayerZero ENDPOINT ids
# (chain_id_scheme="layerzero", via _LZ_EID), NOT EVM chain ids. The source is
# pinned to the VERIFIED Stargate pool set — OFTSent is the generic OFT standard
# event, so matching topic0 alone would mislabel ANY OFT token as Stargate. The
# dest is queried address-LESS (dest_wildcard) since the guid is globally unique
# and the pools are per-token/per-chain. Recipient = toAddress (OFTReceived
# topic2); delivered amount = amountReceivedLD (data word1). VERIFIED real pair:
# source Ethereum StargatePoolNative 0x77b2…ce57931 tx 0xff3ab5d7… (guid
# 0xb7b985ee…, dstEid 30184=base) → dest Base 0xdc181b… tx 0xb0c2faf5… (same guid
# topic1, recipient 0xbc9a201c…, amountReceivedLD == source's, exactly).
_STARGATE_POOLS = frozenset({
    # ethereum: Native / USDC / USDT
    "0x77b2043768d28e9c9ab44e1abfc95944bce57931",
    "0xc026395860db2d07ee33e05fe50ed7bd583189c7",
    "0x933597a323eb81cae705c5bc29985172fd5a3973",
    # arbitrum (e8cd…/ce8c… are CREATE2-shared with optimism)
    "0xa45b5130f36cdca45667738e2a258ab09f4a5f7f",
    "0xe8cdf27acd73a434d661c84887215f7598e7d0d3",
    "0xce8cca271ebc0533920c83d39f417ed6a0abb7d0",
    # base
    "0xdc181bd607330aeebef6ea62e03e5e1fb4b6f7c7",
    "0x27a16dc786820b16e5c9028b75b99f6f604b5d26",
    # optimism
    "0x19cfce47ed54a88614648dc3f19a5980097007dd",
    # polygon
    "0x9aa02d4fae7f58b8e8f34c66e756cc734dac7fe4",
    "0xd47b03ee6d86cf251ee7860fb2acf9f91b9fd4d7",
    # bsc
    "0x962bd449e630b0d928f308ce63f1a21f02576057",
    "0x138eb30f73bc423c6455c53df6d89cb01d9ebc63",
})
_STARGATE = BridgePairSpec(
    protocol="Stargate",
    source_contracts=_STARGATE_POOLS,
    source_event_topic0=(  # OFTSent(bytes32,uint32,address,uint256,uint256)
        "0x85496b760a4b7f8d66384b9df21b381f5d1b1e79f229a47aaf4c232edc2fe59a"
    ),
    source_order_id_topic=1,            # guid (indexed)
    source_dest_chain_word=0,           # dstEid (LayerZero eid) — data word 0
    chain_id_scheme="layerzero",
    dest_wildcard=True,                 # guid is globally unique; pools are many
    dest_event_topic0=(  # OFTReceived(bytes32,uint32,address,uint256)
        "0xefed6d3500546b29533b128a29e3a94d70788727f0507505ac12eaf2e578fd9c"
    ),
    dest_id_topic=1,                    # guid (indexed) on the fill
    dest_recipient_topic=2,             # toAddress (indexed) on OFTReceived
    dest_amount_word=1,                 # amountReceivedLD — data word 1
    max_fee_pct=Decimal("1.0"),
    # OFT delivers the SAME token 1:1, but LD = LOCAL decimals can differ per
    # chain, so raw amounts aren't always comparable — skip same-asset
    # conservation to avoid a false violation on a legit decimals mismatch.
    same_asset=False,
    notes="Stargate V2 / LayerZero OFT guid(topic1) matched source OFTSent↔dest OFTReceived; "
          "dest wildcard (guid globally unique); source pinned to verified pools; eid namespace; "
          "verified vs real ETH→Base pair (guid 0xb7b985ee…).",
)

# Axelar GMP (the rail under Squid) — the source AxelarGateway emits ContractCall
# with the payloadHash INDEXED (topic2); the destination AxelarGateway emits
# ContractCallApproved with the SAME payloadHash INDEXED (topic3) AND the source
# tx hash at data word2. We pair on payloadHash (efficient indexed filter) and
# REQUIRE the dest's sourceTxHash word == the source tx hash — so even an
# (astronomically unlikely) identical-payload collision can't make a false pair.
# Destination chain is a STRING in the source event (not an int), so it isn't
# auto-resolved here — the caller supplies destination_chain (calldata decode),
# exactly like Wormhole. VERIFIED real pair: source Ethereum tx 0x16410393…
# (ContractCall @gateway 0x4f449524…, payloadHash 0x5ed87ed8…) → dest Arbitrum tx
# 0x2b70632b… (ContractCallApproved @gateway 0xe432150c…, same payloadHash topic3,
# sourceTxHash word2 == 0x16410393…).
_AXELAR_GATEWAYS = frozenset({
    "0x4f4495243837681061c4743b74b3eedf548d56a5",  # ethereum
    "0xe432150cce91c13a887f7d836923d5597add8e31",  # arbitrum / base / optimism (shared)
    "0x6f015f16de9fc8791b234ef68d486d2bf203fba8",  # polygon
    "0x5029c0eff6c34351a0cec334542cdb22c7928f78",  # avalanche
    "0x304acf330bbe08d1e512eefaa92f6a57871fd895",  # bsc
})
_AXELAR = BridgePairSpec(
    protocol="Axelar",
    source_contracts=_AXELAR_GATEWAYS,
    source_event_topic0=(  # ContractCall(address,string,string,bytes32,bytes)
        "0x30ae6cc78c27e651745bf2ad08a11de83910ac1e347a52f7ac898c0fbef94dae"
    ),
    source_order_id_topic=2,            # payloadHash (indexed)
    dest_wildcard=True,                 # dest gateway per chain; payloadHash filter
    dest_event_topic0=(  # ContractCallApproved(bytes32,string,string,address,bytes32,bytes32,uint256)
        "0x44e4f8f6bd682c5a3aeba93601ab07cb4d1f21b2aab1ae4880d9577919309aa4"
    ),
    dest_id_topic=3,                    # payloadHash (indexed) on the approval
    dest_source_txhash_word=2,          # sourceTxHash — MUST equal the source tx hash
    max_fee_pct=Decimal("1.0"),
    same_asset=False,                   # GMP carries arbitrary calldata/asset
    notes="Axelar GMP payloadHash(source topic2 == dest topic3) + dest sourceTxHash(word2) == "
          "source tx hash; dest wildcard; verified vs real ETH→ARB pair (payloadHash 0x5ed87ed8…).",
)

# Generic LayerZero OFT — the OFT standard (OFTSent/OFTReceived) is used by MANY
# bridges/omnichain tokens, not just Stargate. This spec catches ALL of them via
# the same globally-unique LayerZero GUID (topic1 on both sides), recognized by
# topic0 ALONE (source_match_topic0_only) since the emitter is unbounded (every
# OFT). It is registered AFTER _STARGATE so a Stargate pool keeps the precise
# "Stargate" label and every OTHER OFT gets the generic "LayerZero OFT" label.
# Same verified mechanism as Stargate (the verified ETH→Base pair is an OFT pair).
_LAYERZERO_OFT = BridgePairSpec(
    protocol="LayerZero OFT",
    source_contracts=frozenset(),
    source_match_topic0_only=True,
    source_event_topic0=(  # OFTSent(bytes32,uint32,address,uint256,uint256)
        "0x85496b760a4b7f8d66384b9df21b381f5d1b1e79f229a47aaf4c232edc2fe59a"
    ),
    source_order_id_topic=1,            # guid (indexed)
    source_dest_chain_word=0,           # dstEid (LayerZero eid)
    chain_id_scheme="layerzero",
    dest_wildcard=True,
    dest_event_topic0=(  # OFTReceived(bytes32,uint32,address,uint256)
        "0xefed6d3500546b29533b128a29e3a94d70788727f0507505ac12eaf2e578fd9c"
    ),
    dest_id_topic=1,                    # guid (indexed)
    dest_recipient_topic=2,             # toAddress (indexed)
    dest_amount_word=1,                 # amountReceivedLD
    max_fee_pct=Decimal("1.0"),
    same_asset=False,                   # LD decimals can differ per chain
    notes="Generic LayerZero OFT guid(topic1) matched OFTSent↔OFTReceived; topic0-only source "
          "recognition (unbounded OFT emitters); registered AFTER Stargate so pools stay 'Stargate'.",
)

_REGISTRY: tuple[BridgePairSpec, ...] = (
    # _SYNAPSE_RFQ MUST precede classic _SYNAPSE: get_pair_spec matches by
    # substring, so "Synapse RFQ" would otherwise resolve to classic "Synapse".
    # _STARGATE MUST precede _LAYERZERO_OFT: a Stargate pool source matches both,
    # and the more-specific (pinned) "Stargate" label must win over generic OFT.
    _DLN, _ACROSS, _CELER, _HOP, _SYNAPSE_RFQ, _SYNAPSE, _CCIP, _CONNEXT,
    _WORMHOLE, _STARGATE, _LAYERZERO_OFT, _AXELAR,
)


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


def _source_topic0s(spec: BridgePairSpec) -> tuple[str, ...]:
    return (spec.source_event_topic0, *spec.source_event_topics)


def _dest_topic0s(spec: BridgePairSpec) -> tuple[str, ...]:
    return (spec.dest_event_topic0, *spec.dest_event_topics)


def _source_event_matches(spec: BridgePairSpec, emitter: str, topic0: str | None) -> bool:
    """True if a log is this spec's source order event. Matches topic0 always;
    the emitter must be in source_contracts UNLESS source_match_topic0_only (a
    distinctive event whose emitter is per-lane / unenumerable, e.g. CCIP)."""
    if topic0 not in _source_topic0s(spec):
        return False
    if spec.source_match_topic0_only:
        return True
    return (emitter or "").lower() in spec.source_contracts


def _derive_keccak_ascii_txhash(raw_receipt: dict[str, Any] | None) -> str | None:
    """Synapse-style derived id: keccak256 of the lowercase ASCII STRING of the
    source tx hash (the form the Synapse validator uses for kappa). VERIFIED vs
    5 real Synapse pairs."""
    if not isinstance(raw_receipt, dict):
        return None
    txh = raw_receipt.get("transactionHash") or raw_receipt.get("transaction_hash")
    if not txh or not isinstance(txh, str):
        return None
    from eth_utils import keccak
    return "0x" + keccak(text=txh.lower()).hex()


def extract_source_order_id(
    spec: BridgePairSpec, raw_source_receipt: dict[str, Any] | None
) -> str | None:
    """Pull the cross-chain order-id out of the source tx receipt's
    order-creation event, from the spec's verified location (a topic for the
    composite shape, a data word for the 32-byte shape). Defensive — never raises.
    """
    if not isinstance(raw_source_receipt, dict):
        return None
    # Derived-id shape (Synapse): the id is not emitted — compute it from the
    # source tx hash. Only trust it when a source event from this protocol IS
    # present in the receipt (so we don't derive a kappa for a non-Synapse tx).
    if spec.source_id_kind == "keccak_ascii_txhash":
        if _has_source_event(spec, raw_source_receipt):
            return _derive_keccak_ascii_txhash(raw_source_receipt)
        return None
    logs = raw_source_receipt.get("logs")
    if not isinstance(logs, list):
        return None
    for lg in logs:
        if not isinstance(lg, dict):
            continue
        topics = lg.get("topics") or []
        if not _source_event_matches(
            spec, (lg.get("address") or "").lower(), _topic(topics, 0)
        ):
            continue
        if spec.source_order_id_topic is not None:
            oid = _topic(topics, spec.source_order_id_topic)
        else:
            oid = _data_word(lg.get("data"), spec.source_order_id_word or 0)
        if oid and oid != "0x" + "0" * 64:
            return oid
    return None


def _has_source_event(spec: BridgePairSpec, raw_receipt: dict[str, Any]) -> bool:
    """True if the receipt contains a recognized source event from this spec's
    emitter set — the gate that prevents deriving an id for an unrelated tx."""
    logs = raw_receipt.get("logs")
    if not isinstance(logs, list):
        return False
    for lg in logs:
        if not isinstance(lg, dict):
            continue
        if _source_event_matches(
            spec, (lg.get("address") or "").lower(),
            _topic(lg.get("topics") or [], 0),
        ):
            return True
    return False


def _source_event_topic(
    spec: BridgePairSpec, raw_receipt: dict[str, Any] | None, topic_index: int
) -> str | None:
    """Read a topic value off this spec's SOURCE event in the receipt (e.g. the
    Wormhole emitter on LogMessagePublished.topic1). None if not found."""
    if not isinstance(raw_receipt, dict):
        return None
    for lg in raw_receipt.get("logs") or []:
        if not isinstance(lg, dict):
            continue
        topics = lg.get("topics") or []
        if _source_event_matches(spec, (lg.get("address") or "").lower(), _topic(topics, 0)):
            return _topic(topics, topic_index)
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
            if not _source_event_matches(spec, emitter, t0):
                continue
            # order id: derived (Synapse) or read from the event topic/word.
            if spec.source_id_kind == "keccak_ascii_txhash":
                oid = _derive_keccak_ascii_txhash(raw_source_receipt)
            elif spec.source_order_id_topic is not None:
                oid = _topic(topics, spec.source_order_id_topic)
            else:
                oid = _data_word(lg.get("data"), spec.source_order_id_word or 0)
            if not oid or oid == "0x" + "0" * 64:
                continue
            # destination chain from a source-event topic OR data word (real id).
            dest_chain: str | None = None
            cid_word: str | None = None
            if spec.source_dest_chain_topic is not None:
                cid_word = _topic(topics, spec.source_dest_chain_topic)
            elif spec.source_dest_chain_word is not None:
                cid_word = _data_word(lg.get("data"), spec.source_dest_chain_word)
            if cid_word:
                # The chain-id namespace depends on the protocol: a real EVM
                # chain id (default) or a LayerZero endpoint id (Stargate/OFT).
                cid_by = (
                    _CHAIN_BY_LZ_EID if spec.chain_id_scheme == "layerzero"
                    else _CHAIN_BY_REAL_ID
                )
                try:
                    dest_chain = cid_by.get(int(cid_word, 16))
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


def _deposit_amount(
    source_receipt: dict[str, Any] | None, source_contracts: frozenset[str]
) -> int | None:
    """The raw amount DEPOSITED into the source bridge: the largest ERC-20
    Transfer in the source tx whose recipient is a known source bridge contract.
    Generic (no per-protocol offset to mis-verify) — and only meaningful for
    same-asset protocols, where the caller compares it to the fill amount.
    Returns None when no source contract is known (wildcard-source protocols) or
    no such transfer exists."""
    if not source_contracts or not source_receipt:
        return None
    from recupero.trace.swap_output import parse_erc20_transfers

    sinks = {a.lower() for a in source_contracts}
    best = 0
    for t in parse_erc20_transfers(source_receipt):
        if t.to in sinks and t.amount > best:
            best = t.amount
    return best or None


def bridge_conservation_ok(
    src_raw: int | None,
    dst_raw: int | None,
    max_fee_pct: Decimal,
) -> tuple[bool, str]:
    """Same-asset bridge value conservation: the destination amount must lie in
    ``[src·(1 − maxFee), src]`` — a bridge takes a fee, it never adds value. Used
    only for protocols that deliver the SAME asset on both chains; the caller
    must not call this for cross-asset bridges (the comparison is meaningless).

    Returns ``(ok, reason)``. When either amount is unknown / non-positive, or
    ``max_fee_pct`` is out of range, returns ``(True, "unknown")`` — we never
    fabricate a violation from missing or unusable data.
    """
    if src_raw is None or dst_raw is None or src_raw <= 0 or dst_raw <= 0:
        return True, "unknown (missing/non-positive amount)"
    try:
        fee = Decimal(max_fee_pct)
    except (InvalidOperation, TypeError, ValueError):
        return True, "unknown (bad max_fee_pct)"
    if not fee.is_finite() or fee < 0 or fee > 100:
        return True, "unknown (max_fee_pct out of range)"
    s = Decimal(src_raw)
    d = Decimal(dst_raw)
    floor = s * (Decimal(100) - fee) / Decimal(100)
    if d > s:
        return False, (
            f"destination amount {dst_raw} exceeds source deposit {src_raw} "
            f"— a bridge cannot pay out more than was deposited (possible "
            f"mispairing or different asset)"
        )
    if d < floor:
        return False, (
            f"destination amount {dst_raw} is below the conservation floor "
            f"{floor:.0f} = source {src_raw} × (1 − {fee}% max fee) — fee "
            f"exceeds protocol maximum (possible mispairing or skimming)"
        )
    return True, "conserved"


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

    # The source tx hash — the second cryptographic tiebreak for protocols that
    # echo it on the dest fill (Axelar ContractCallApproved.sourceTxHash).
    want_src_txhash: str | None = None
    if spec.dest_source_txhash_word is not None and isinstance(source_receipt, dict):
        want_src_txhash = _norm_word(
            source_receipt.get("transactionHash")
            or source_receipt.get("transaction_hash")
        )

    # Resolve the destination contract. dest_wildcard protocols (Hop) query
    # address-LESS (across all per-token emitters) since the id is globally
    # unique; others use the per-chain / deterministic contract.
    if spec.dest_wildcard:
        query_addr = ""  # omit address → Etherscan getLogs searches all emitters
    else:
        query_addr = spec.dest_contract_for(destination_chain) or ""
        if not query_addr:
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

    # Composite shape filters the id server-side at its topic; 32-byte shape
    # scans the payload.
    topics_filter: list[str | None] | None = None
    if spec.dest_id_topic is not None and 1 <= spec.dest_id_topic <= 3:
        topics_filter = [None, None, None]
        topics_filter[spec.dest_id_topic - 1] = oid

    # Expected origin-chain-id topic value for the composite shape. The chain-id
    # namespace is EVM (Across) or Wormhole-internal (Wormhole), per the spec.
    want_origin = None
    if spec.dest_origin_chain_topic is not None and source_chain:
        cid_map = _WH_CHAIN_ID if spec.chain_id_scheme == "wormhole" else _REAL_CHAIN_ID
        cid = cid_map.get(source_chain.lower())
        if cid is not None:
            want_origin = "0x" + f"{cid:064x}"

    # Expected emitter topic (Wormhole): the source event's emitter (the VAA
    # emitterAddress) must equal the dest fill's emitterAddress topic — so a
    # colliding sequence on a DIFFERENT emitter is rejected.
    want_emitter = None
    if spec.dest_emitter_topic is not None and spec.source_emitter_topic is not None:
        want_emitter = _source_event_topic(
            spec, source_receipt, spec.source_emitter_topic
        )

    # False-positive guard for the composite-key shape. A composite-key protocol's
    # id is a SMALL, non-globally-unique value (e.g. Across's ``depositId``) that is
    # only disambiguated by the origin-chain-id topic. If we cannot compute/verify
    # that qualifier (``source_chain`` missing or not in the chain-id map) AND the
    # spec carries no other unique tiebreak (emitter / source-tx-hash), an id-only
    # match could be a colliding deposit from a DIFFERENT source chain — so we
    # decline rather than emit a false 'high'. Protocols with a unique tiebreak
    # (Wormhole's emitter) or a globally-unique hash id (dest_id_topic is None)
    # are unaffected.
    if (
        spec.dest_origin_chain_topic is not None
        and want_origin is None
        and want_emitter is None
        and spec.dest_source_txhash_word is None
    ):
        log.info(
            "confirm: %s is a composite-key protocol but the origin-chain-id "
            "qualifier is unavailable (source_chain=%r) and there is no other "
            "unique tiebreak — declining id-only match to avoid a false 'high'.",
            spec.protocol, source_chain,
        )
        return None

    # A protocol may emit the fill under several event signatures (Synapse
    # TokenMint/TokenWithdraw/…). Query each; first id-match wins.
    for dest_t0 in _dest_topic0s(spec):
        try:
            logs = dst_adapter.fetch_logs(
                query_addr, dest_t0,
                from_block=from_block, to_block=to_block, topics=topics_filter,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("confirm: dest fetch_logs failed: %s", exc)
            continue
        for lg in logs or []:
            if not isinstance(lg, dict):
                continue
            if spec.dest_id_topic is not None:
                # composite/topic shape: confirm the id topic + (origin chain id)
                if _topic(lg.get("topics"), spec.dest_id_topic) != oid:
                    continue
                if want_origin is not None and _topic(
                    lg.get("topics"), spec.dest_origin_chain_topic
                ) != want_origin:
                    continue
                if want_emitter is not None and _topic(
                    lg.get("topics"), spec.dest_emitter_topic
                ) != want_emitter:
                    continue
            else:
                # 32-byte shape: scan the payload (+ topics) for the exact id.
                words = _all_words(lg.get("data")) | {
                    _norm_word(t) for t in (lg.get("topics") or [])
                }
                if oid not in words:
                    continue
            # second tiebreak: the dest fill must echo the SOURCE tx hash at the
            # declared data word (Axelar). Rejects a colliding-payloadHash pair.
            if want_src_txhash and spec.dest_source_txhash_word is not None:
                got = _data_word(lg.get("data"), spec.dest_source_txhash_word)
                if _norm_word(got) != want_src_txhash:
                    continue
            # success-state gate (CCIP: ExecutionStateChanged.state==2) so a
            # FAILED execution is never reported as a delivered destination.
            if spec.dest_state_word is not None and spec.dest_state_ok is not None:
                sw = _data_word(lg.get("data"), spec.dest_state_word)
                try:
                    if sw is None or int(sw, 16) != spec.dest_state_ok:
                        continue
                except ValueError:
                    continue
            dst_tx = lg.get("transactionHash") or lg.get("transaction_hash") or ""
            emitter = (lg.get("address") or query_addr or "").lower()
            recipient = None
            raw_amount = None
            # Prefer the recipient/amount carried by the matched fill event itself
            # (Synapse RFQ native-ETH fills emit no ERC-20 Transfer to scan).
            if spec.dest_recipient_topic is not None:
                rt = _topic(lg.get("topics"), spec.dest_recipient_topic)
                if rt and rt != "0x" + "0" * 64:
                    recipient = "0x" + rt[-40:]
                if spec.dest_amount_word is not None:
                    aw = _data_word(lg.get("data"), spec.dest_amount_word)
                    try:
                        raw_amount = int(aw, 16) if aw else None
                    except ValueError:
                        raw_amount = None
            # Fall back to the ERC-20 payout scan when the event didn't yield a
            # recipient (token fills, or a spec without the topic configured).
            if recipient is None:
                recipient, scanned_amt = _fill_recipient_amount(
                    dst_adapter, dst_tx,
                    infra={emitter, query_addr, *spec.source_contracts},
                )
                if raw_amount is None:
                    raw_amount = scanned_amt
            # raw amount deposited into the source bridge (same-asset only) for
            # the Phase-2 conservation check; None for cross-asset / wildcard.
            src_raw = (
                _deposit_amount(source_receipt, spec.source_contracts)
                if spec.same_asset else None
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
                dst_contract=emitter or query_addr,
                recipient=recipient,
                raw_amount=raw_amount,
                confidence="high",
                basis=(
                    f"protocol id {oid} matched on both the {spec.protocol} "
                    f"source event and the destination fill ({dest_t0[:10]}…)"
                    + (
                        f" with origin-chain-id == {source_chain}"
                        if want_origin is not None else ""
                    )
                    + " — cryptographic match"
                ),
                src_raw_amount=src_raw,
                same_asset=spec.same_asset,
            )
    return None


__all__ = (
    "BridgePairSpec",
    "ConfirmedDestination",
    "get_pair_spec",
    "extract_source_order_id",
    "identify_source",
    "confirm_bridge_destination",
    "bridge_conservation_ok",
)
