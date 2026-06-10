"""Uniswap V3 LP park-and-withdraw leads (roadmap-v4 Tier-2 #7, slice 1).

The laundering pattern: deposit stolen tokens into a Uniswap V3 position via
the NonfungiblePositionManager (NPM), wait, then remove liquidity to a fresh
wallet. The trace previously dead-ended at the NPM/pool contract — the value
"vanished" into the position.

The cryptographic rail this runner exploits: the NPM stamps every position
with a ``tokenId``, and ALL lifecycle events carry it as indexed topic 1:

  * ``IncreaseLiquidity(uint256 indexed tokenId, uint128 liquidity,
    uint256 amount0, uint256 amount1)``
  * ``DecreaseLiquidity(uint256 indexed tokenId, ...)``
  * ``Collect(uint256 indexed tokenId, address recipient,
    uint256 amount0, uint256 amount1)`` — the ONLY event that pays tokens
    out; ``recipient`` (where the funds actually exit) is DATA WORD 0.

All three topic0 hashes, the topic/data layout, and every per-chain NPM
address below are LIVE-VERIFIED against real mainnet logs (2026-06; e.g.
remove-liquidity tx 0x997f9235… emits DecreaseLiquidity + Collect for the
same tokenId, recipient in Collect data word 0).

Forensic posture: the POSITION-CONTINUITY claim (this exit came from the
same position the traced wallet funded) is protocol identity — reported
``high``. The ACTOR attribution is split: exit recipient == the parking
wallet → same-owner round-trip (``high``); a different recipient → the
position NFT may have been transferred/sold in between, so actor attribution
is ``medium`` pending the NFT ownership trail (which RECUPERO_NFT_FLOWS can
surface — the NPM position IS an ERC-721). Leads are an artifact for review,
never a followed destination, and never touch the recoverable total.

Gated by ``RECUPERO_LP_LEADS`` (default off) — adds a receipt fetch per
NPM deposit + one getLogs per discovered position.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from typing import Any

log = logging.getLogger(__name__)

# LIVE-VERIFIED topic0 hashes (keccak recomputed + matched to real logs).
NPM_INCREASE_LIQUIDITY_TOPIC0 = (
    "0x3067048beee31b25b2f1681f88dac838c8bba36af25bfb2b7cf7473a5847e35f"
)
NPM_DECREASE_LIQUIDITY_TOPIC0 = (
    "0x26f6a048ee9138f2c0ce266f322cb99228e8d619ae2bff30c67f8dcf9d2377b4"
)
NPM_COLLECT_TOPIC0 = (
    "0x40d0efd1a53d60ecbf40971b9daf7dc90178c3aadc7aab1765632738fa8b8f01"
)

# Per-chain Uniswap V3 NonfungiblePositionManager — every entry LIVE-VERIFIED
# (2026-06) to emit IncreaseLiquidity on its chain via the Etherscan v2
# multichain API. Do NOT add an entry without that verification.
UNISWAP_V3_NPM_BY_CHAIN: dict[str, str] = {
    "ethereum": "0xc36442b4a4522e871399cd717abdd847ab11fe88",
    "polygon": "0xc36442b4a4522e871399cd717abdd847ab11fe88",
    "arbitrum": "0xc36442b4a4522e871399cd717abdd847ab11fe88",
    "optimism": "0xc36442b4a4522e871399cd717abdd847ab11fe88",
    "base": "0x03a520b32c04bf3beef7beb72e919cf822ed34f1",
    "bsc": "0x7b8a01b39d58278b5de7e48c8449c9f4f5170613",
}

_MAX_PARKS = 25          # bound the per-case fan-out
_MAX_EXITS_PER_TOKEN = 50


def lp_leads_enabled() -> bool:
    """Opt-in gate (RECUPERO_LP_LEADS). Default off — adds a receipt fetch
    per NPM deposit + a getLogs per position."""
    return (os.environ.get("RECUPERO_LP_LEADS", "") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _chain_str(c: Any) -> str | None:
    if c is None:
        return None
    return getattr(c, "value", None) or (str(c) if c else None)


def find_lp_parks(
    transfers: Iterable[Any], *, default_chain: str = "ethereum"
) -> list[dict[str, Any]]:
    """Transfers from a traced wallet INTO the chain's verified NPM — the
    park candidates. One record per (parker, tx); works on Case.transfers or
    any objects exposing from/to_address, chain, tx_hash."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for t in transfers or []:
        to = getattr(t, "to_address", None)
        if not to:
            continue
        chain = _chain_str(getattr(t, "chain", None)) or default_chain
        npm = UNISWAP_V3_NPM_BY_CHAIN.get(chain)
        if not npm or str(to).lower() != npm:
            continue
        frm = str(getattr(t, "from_address", "") or "").lower()
        txh = str(getattr(t, "tx_hash", "") or "")
        if not frm or not txh:
            continue
        key = (frm, txh)
        if key in seen:
            continue
        seen.add(key)
        out.append({"parker": frm, "tx_hash": txh, "chain": chain, "npm": npm})
        if len(out) >= _MAX_PARKS:
            log.info("lp-leads: park cap (%d) reached", _MAX_PARKS)
            break
    return out


def _topic_token_id(topics: Any) -> int | None:
    """tokenId = indexed topic 1 on all three NPM lifecycle events."""
    if not isinstance(topics, list) or len(topics) < 2:
        return None
    t1 = topics[1]
    if not isinstance(t1, str):
        return None
    try:
        return int(t1, 16)
    except ValueError:
        return None


def position_ids_from_receipt_logs(
    logs: Iterable[Any], *, npm: str
) -> list[int]:
    """The position tokenIds an NPM deposit tx touched: IncreaseLiquidity
    logs emitted BY the NPM in that receipt. Malformed logs are skipped."""
    ids: list[int] = []
    for lg in logs or []:
        if not isinstance(lg, dict):
            continue
        if str(lg.get("address", "")).lower() != npm:
            continue
        topics = lg.get("topics")
        if (
            isinstance(topics, list)
            and topics
            and topics[0] == NPM_INCREASE_LIQUIDITY_TOPIC0
        ):
            tid = _topic_token_id(topics)
            if tid is not None and tid not in ids:
                ids.append(tid)
    return ids


def collect_exits_from_logs(logs: Iterable[Any]) -> list[dict[str, Any]]:
    """Parse NPM ``Collect`` logs → exit records. The recipient (where the
    position's funds actually left) is DATA WORD 0 (live-verified); amounts
    are words 1-2 (raw, per-pool-token units — reported verbatim, never
    priced here). Malformed logs are skipped, never repaired."""
    out: list[dict[str, Any]] = []
    for lg in logs or []:
        if not isinstance(lg, dict):
            continue
        data = lg.get("data") or ""
        data = data[2:] if data.startswith("0x") else data
        if len(data) < 192:  # 3 words
            continue
        recipient = "0x" + data[0:64][24:]
        # 20-byte address left-padded with 12 zero bytes — anything else is
        # not an address-shaped word (same guard as the bridge decoders).
        if data[0:24] != "0" * 24 or recipient == "0x" + "0" * 40:
            continue
        tid = _topic_token_id(lg.get("topics"))
        if tid is None:
            continue
        txh = lg.get("transactionHash") or lg.get("transaction_hash") or ""
        try:
            amount0 = str(int(data[64:128], 16))
            amount1 = str(int(data[128:192], 16))
        except ValueError:
            continue
        out.append({
            "token_id": tid,
            "recipient": recipient,
            "tx_hash": str(txh),
            "amount0_raw": amount0,
            "amount1_raw": amount1,
            "block_number": lg.get("blockNumber"),
        })
    return out


def run_lp_leads(
    *,
    transfers: Iterable[Any],
    adapter: Any,
    default_chain: str = "ethereum",
    force: bool = False,
) -> list[dict[str, Any]]:
    """For each NPM deposit by a traced wallet: recover the position tokenId
    from the deposit receipt, then find every later ``Collect`` on that SAME
    position — where the parked value actually exited. Opt-in: ``[]`` unless
    ``force`` or ``RECUPERO_LP_LEADS``. Best-effort per park."""
    if not (force or lp_leads_enabled()):
        return []
    parks = find_lp_parks(transfers, default_chain=default_chain)
    leads: list[dict[str, Any]] = []
    for park in parks:
        try:
            receipt = adapter.fetch_evidence_receipt(park["tx_hash"])
            raw_logs = (receipt.raw_receipt or {}).get("logs") or []
            token_ids = position_ids_from_receipt_logs(raw_logs, npm=park["npm"])
            park_block = int(getattr(receipt, "block_number", 0) or 0)
        except Exception as exc:  # noqa: BLE001 — best-effort per park
            log.warning("lp-leads: receipt fetch failed tx=%s: %s",
                        park["tx_hash"][:12], exc)
            continue
        for tid in token_ids:
            tid_topic = "0x" + format(tid, "064x")
            try:
                logs = adapter.fetch_logs(
                    park["npm"], NPM_COLLECT_TOPIC0,
                    topics=[tid_topic],
                    from_block=park_block, to_block="latest",
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("lp-leads: Collect fetch failed token=%d: %s",
                            tid, exc)
                continue
            exits = collect_exits_from_logs(logs)[:_MAX_EXITS_PER_TOKEN]
            for ex in exits:
                if ex["token_id"] != tid:
                    continue  # cross-token contamination guard
                same_owner = ex["recipient"] == park["parker"]
                leads.append({
                    "chain": park["chain"],
                    "parker": park["parker"],
                    "park_tx": park["tx_hash"],
                    "position_token_id": str(tid),
                    "exit_tx": ex["tx_hash"],
                    "exit_recipient": ex["recipient"],
                    "amount0_raw": ex["amount0_raw"],
                    "amount1_raw": ex["amount1_raw"],
                    "recipient_is_parker": same_owner,
                    # position-continuity is protocol identity (tokenId match
                    # on both sides) = high; actor attribution downgrades to
                    # medium when the recipient differs (the position NFT may
                    # have changed hands — check the NFT ownership trail).
                    "position_link_confidence": "high",
                    "actor_attribution_confidence": (
                        "high" if same_owner else "medium"
                    ),
                    "basis": (
                        f"Uniswap V3 position #{tid}: deposit "
                        "(IncreaseLiquidity) by the traced wallet and this "
                        "Collect exit carry the SAME indexed tokenId on the "
                        "verified NonfungiblePositionManager."
                    ),
                })
        if token_ids:
            log.info("lp-leads: park %s → %d position(s)",
                     park["tx_hash"][:12], len(token_ids))
    return leads


def leads_to_json(leads: list[dict[str, Any]]) -> dict[str, Any]:
    """Serialize run_lp_leads output to the lp_leads.json artifact."""
    return {
        "kind": "recupero_lp_leads",
        "disclaimer": (
            "Uniswap V3 park-and-withdraw LEADS. The position link (same "
            "tokenId on deposit and Collect exit) is protocol identity — "
            "high confidence. Actor attribution is high only when the exit "
            "recipient IS the parking wallet; otherwise medium (the position "
            "NFT may have been transferred — review the NFT ownership "
            "trail). Amounts are RAW per-pool-token units, never priced "
            "here; leads are for review, never a followed destination, and "
            "the recoverable total is unchanged."
        ),
        "lead_count": len(leads),
        "leads": leads,
    }


__all__ = (
    "NPM_INCREASE_LIQUIDITY_TOPIC0",
    "NPM_DECREASE_LIQUIDITY_TOPIC0",
    "NPM_COLLECT_TOPIC0",
    "UNISWAP_V3_NPM_BY_CHAIN",
    "lp_leads_enabled",
    "find_lp_parks",
    "position_ids_from_receipt_logs",
    "collect_exits_from_logs",
    "run_lp_leads",
    "leads_to_json",
)
