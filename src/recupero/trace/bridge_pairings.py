"""Bridge source↔destination pairing by the protocol's own cross-chain order /
message ID — the answer-key-free correctness oracle (v0.34).

A bridge stamps a unique cross-chain identifier on the SOURCE chain (in an
order-creation event) and the DESTINATION chain references the SAME id in its
fill / mint event. Matching the two by that id is CRYPTOGRAPHIC proof of the hop
— it needs no human ground truth, and it is the ONLY basis on which a
cross-chain edge may be assigned ``high`` confidence (protocol identity, not
amount/time inference). Everything else (the existing ``bridge_matching``
amount+time correlation) stays capped at ``medium``/``low``.

How it confirms (no answer key):
  1. Read the SOURCE order-creation event from the source tx receipt and extract
     the order-id at the protocol's verified data offset.
  2. Query the DESTINATION chain's fill-event logs (filter by the fill event's
     topic0 over a settlement-time block window) and find the one whose payload
     contains the SAME order-id. A 32-byte order-id is effectively unforgeable,
     so an exact match is proof — not correlation.
  3. The matched fill tx's largest ERC-20 payout identifies the recipient +
     amount on the destination chain. ``None`` is returned when nothing matches
     (the engine NEVER guesses a destination).

Each ``BridgePairSpec`` MUST be verified against a REAL on-chain source+dest
pair before it is trusted — see docs/BRIDGE_PAIRING.md and the
``tests/fixtures/zigha_dln_*`` fixtures. Guessing an event signature is exactly
the wrong-selector class of bug (cf. the v0.28 DeBridge ``createOrder`` selectors
that never matched a real order) this module exists to prevent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

log = logging.getLogger(__name__)

_ZERO_ADDR = "0x0000000000000000000000000000000000000000"


@dataclass(frozen=True)
class BridgePairSpec:
    """How to pair a bridge's source order with its destination fill, verified
    against real on-chain data. Addresses are lowercased.

    For deterministic-deploy protocols (DLN, canonical rollup bridges) the
    source/dest contracts are the SAME address on every chain, so a single
    address suffices; ``source_contracts`` is the set of source emitters and
    ``dest_contract`` the destination fill emitter.
    """

    protocol: str
    #: lowercased source-side emitter address(es) of the order-creation event
    source_contracts: frozenset[str]
    #: keccak topic0 of the source order-creation event
    source_event_topic0: str
    #: data-word index (32-byte words, 0-based) of the order-id in the source event
    source_order_id_word: int
    #: lowercased destination-side fill emitter (deterministic across chains)
    dest_contract: str
    #: keccak topic0 of the destination fill event
    dest_event_topic0: str
    #: max protocol fee as a percent — destination amount must be within
    #: [src*(1-maxfee), src]; used by the Phase-2 conservation check.
    max_fee_pct: Decimal
    #: human note / provenance
    notes: str = ""


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
    # tx 0xd4bf228f… (Zigha): word 1 == 0x57825e7d…1f9b.
    source_event_topic0=(
        "0xfc8703fd57380f9dd234a89dce51333782d49c5902f307b02f03e014d18fe471"
    ),
    source_order_id_word=1,
    # DlnDestination — deterministic deploy across EVM chains. VERIFIED on
    # Ethereum tx 0x221c6c62… emitting FulfilledOrder with the SAME orderId.
    dest_contract="0xe7351fd770a37282b91d153ee690b63579d6dd7f",
    dest_event_topic0=(
        "0xd281ee92bab1446041582480d2c0a9dc91f855386bb27ea295faac1e992f7fe4"
    ),
    max_fee_pct=Decimal("1.0"),
    notes="deBridge DLN createSaltedOrder→FulfilledOrder; verified vs Zigha pair.",
)

_REGISTRY: tuple[BridgePairSpec, ...] = (_DLN,)


def get_pair_spec(protocol: str | None) -> BridgePairSpec | None:
    """Resolve a ``BridgePairSpec`` by bridge protocol/label substring (the same
    permissive matching the calldata-decoder dispatch uses, e.g. 'deBridge DLN
    Source' → DeBridge)."""
    if not protocol:
        return None
    p = protocol.lower()
    for spec in _REGISTRY:
        if spec.protocol.lower() in p:
            return spec
    return None


def _norm_word(w: str | None) -> str:
    """Normalize a 32-byte hex word to lowercase 0x-prefixed."""
    if not w:
        return ""
    w = w.strip().lower()
    if not w.startswith("0x"):
        w = "0x" + w
    return w


def _data_word(data_hex: str | None, idx: int) -> str | None:
    """Return the ``idx``-th 32-byte word of event ``data`` as 0x-hex, or None."""
    if not data_hex:
        return None
    d = data_hex[2:] if data_hex.startswith("0x") else data_hex
    start = idx * 64
    end = start + 64
    if end > len(d):
        return None
    return "0x" + d[start:end].lower()


def _all_words(data_hex: str | None) -> set[str]:
    """Every 32-byte word in event ``data`` (for scanning for an order-id)."""
    if not data_hex:
        return set()
    d = data_hex[2:] if data_hex.startswith("0x") else data_hex
    return {"0x" + d[i:i + 64].lower() for i in range(0, len(d) - len(d) % 64, 64)}


def extract_source_order_id(
    spec: BridgePairSpec, raw_source_receipt: dict[str, Any] | None
) -> str | None:
    """Pull the cross-chain order-id out of the source tx receipt's
    order-creation event, at the spec's verified data offset. Returns None if
    the event isn't present (defensive — never raises)."""
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
        if not topics or _norm_word(topics[0]) != spec.source_event_topic0:
            continue
        oid = _data_word(lg.get("data"), spec.source_order_id_word)
        if oid and oid != "0x" + "0" * 64:
            return oid
    return None


def _fill_recipient_amount(
    dst_adapter: Any, dst_tx: str, *, infra: set[str]
) -> tuple[str | None, int | None]:
    """From the destination fill tx, return (recipient, raw_amount) of the
    largest ERC-20 payout to a non-infra recipient. Best-effort: the order-id
    match is the proof; this enriches it with the on-chain landing spot."""
    from recupero.trace.swap_output import parse_erc20_transfers

    try:
        receipt = dst_adapter.fetch_evidence_receipt(dst_tx)
        raw = getattr(receipt, "raw_receipt", None)
    except Exception as exc:  # noqa: BLE001
        log.debug("fill recipient fetch failed tx=%s: %s", dst_tx, exc)
        return None, None
    transfers = parse_erc20_transfers(raw)
    infra_lc = {a.lower() for a in infra} | {_ZERO_ADDR}
    # A bridge fill tx often contains the solver's own sourcing legs (e.g. a 0x
    # swap settler→proxy→…) before the final payout. Pick the largest transfer
    # to a TERMINAL recipient — one that does NOT itself re-send within this tx
    # — so we land on the resting receiver (the decoded receiverDst), not an
    # internal pass-through hop. Same terminal rule as swap_output.resolve_swap_output.
    senders_in_tx = {t.frm for t in transfers}
    best_to: str | None = None
    best_amt = 0
    for t in transfers:
        if (
            t.to in infra_lc
            or t.amount <= 0
            or t.to in senders_in_tx  # not terminal — it forwards onward in-tx
        ):
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
    window_hours: float = 24.0,
    order_id: str | None = None,
) -> ConfirmedDestination | None:
    """Confirm a bridge handoff's destination by matching the protocol order-id
    on the destination chain. Returns a ``high``-confidence ``ConfirmedDestination``
    on an exact order-id match, or ``None`` (never a guess).

    ``dst_adapter`` is the adapter for ``destination_chain`` and must expose
    ``fetch_logs`` + ``block_at_or_before`` + ``fetch_evidence_receipt``.
    """
    spec = get_pair_spec(protocol)
    if spec is None:
        return None

    oid = _norm_word(order_id) if order_id else extract_source_order_id(
        spec, source_receipt
    )
    if not oid or oid == "0x" + "0" * 64:
        return None

    # Destination block window: [src_time, src_time + window]. Fills settle in
    # seconds-to-minutes; the window just bounds the log scan.
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

    try:
        logs = dst_adapter.fetch_logs(
            spec.dest_contract, spec.dest_event_topic0,
            from_block=from_block, to_block=to_block,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("confirm: dest fetch_logs failed: %s", exc)
        return None

    for lg in logs or []:
        if not isinstance(lg, dict):
            continue
        words = _all_words(lg.get("data")) | {
            _norm_word(t) for t in (lg.get("topics") or [])
        }
        if oid not in words:
            continue
        dst_tx = lg.get("transactionHash") or lg.get("transaction_hash") or ""
        recipient, raw_amount = _fill_recipient_amount(
            dst_adapter, dst_tx,
            infra={spec.dest_contract, *spec.source_contracts},
        )
        log.info(
            "bridge destination CONFIRMED (order-id match): protocol=%s "
            "order_id=%s dst_chain=%s dst_tx=%s recipient=%s",
            spec.protocol, oid[:14] + "…", destination_chain, dst_tx, recipient,
        )
        return ConfirmedDestination(
            protocol=spec.protocol,
            order_id=oid,
            dst_chain=destination_chain or "",
            dst_tx=dst_tx,
            dst_contract=spec.dest_contract,
            recipient=recipient,
            raw_amount=raw_amount,
            confidence="high",
            basis=(
                f"order-id {oid} emitted by {spec.protocol} on both the source "
                f"order ({spec.source_event_topic0[:10]}…) and the destination "
                f"fill ({spec.dest_event_topic0[:10]}…) — cryptographic match"
            ),
        )
    return None


__all__ = (
    "BridgePairSpec",
    "ConfirmedDestination",
    "get_pair_spec",
    "extract_source_order_id",
    "confirm_bridge_destination",
)
