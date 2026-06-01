"""DEX swap unwrapping (v0.10.2).

When perpetrator funds pass through a DEX router (1inch,
Uniswap, CoW Protocol, ParaSwap), the trace today shows the
transfer to the router contract as a terminal point. The
actual swap counterparty (where the SWAPPED tokens end up)
is a different address — typically a perpetrator-controlled
wallet that received the output token.

This module detects DEX router involvement in the trace and
attempts to:

  1. Identify which DEX router was used.
  2. Identify the output address (where the swapped tokens
     went) — read from the OUTPUT side of the same tx's other
     transfers.
  3. Flag the swap as a "obfuscation pattern" rather than
     letting the trace dead-end at the router.

What this gives the investigator
---------------------------------

Pre-v0.10.2 brief for a case where the perpetrator used 1inch:
  "Funds traced from victim → 1inch Aggregation Router. The
   trace terminates here; funds swapped to a different asset
   and dispersed to swap counterparties not recoverable."

v0.10.2 brief:
  "Funds traced from victim → 1inch Router (SWAP DETECTED).
   In the same transaction, $48,200 worth of USDT was
   transferred from the router to 0xperp...wallet. The
   perpetrator received USDT at 0xperp...wallet; original
   USDC was burned in the swap. Continue tracing from
   0xperp...wallet."

Limitations
-----------

This is a *heuristic* — we identify swaps by matching tx_hash:
if the victim's outflow + the perpetrator's inflow both happen
in the same tx AND a DEX router is involved, it's likely a
swap. False positives possible (e.g., a multi-transfer batch
that happens to share a tx with a router call).

Confidence levels reflect this — 'high' when the swap pattern
is unambiguous, 'medium' when we infer based on co-occurrence.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from recupero.models import Case, Transfer

log = logging.getLogger(__name__)


# DEX router category labels we pre-loaded in defi_protocols.json.
# When a Transfer.to_address.lower() matches one of these
# subcategories on label lookup, we treat the transfer as
# "entered a DEX swap" rather than as a terminal destination.
_DEX_ROUTER_SUBCATEGORIES = frozenset([
    "dex_aggregator", "dex", "dex_pool", "aggregator_proxy",
])

_DEFI_PROTOCOLS_PATH = (
    Path(__file__).parent.parent / "labels" / "seeds" / "defi_protocols.json"
)


@dataclass(frozen=True)
class DEXSwap:
    """One detected DEX swap event."""
    tx_hash: str
    explorer_url: str
    block_time_iso: str
    swapper: str              # address that initiated the swap (perpetrator's hub typically)
    router_address: str       # the DEX router contract
    router_name: str          # display name from defi_protocols
    router_protocol: str      # 'Uniswap V3' / '1inch' / 'CoW Protocol' / etc.
    input_token_symbol: str | None
    input_amount_decimal: Decimal | None
    input_amount_usd: Decimal | None
    # Output side — what the swapper received post-swap.
    output_token_symbol: str | None
    output_amount_decimal: Decimal | None
    output_amount_usd: Decimal | None
    output_recipient: str | None  # where the output tokens landed
    confidence: str               # 'high' | 'medium' | 'low'
    # v0.34: how the output was found — "in_trace" (paired from case.transfers)
    # or "receipt_logs" (recovered from the swap tx's ERC-20 Transfer logs, for
    # settler-style aggregators like 0x where the output is the settler's own
    # outflow the BFS never traversed). The continuation follows BOTH so a 0x
    # token->DAI swap no longer dead-ends.
    output_source: str = "in_trace"


def load_dex_routers(
    defi_protocols_path: Path | None = None,
) -> dict[str, dict]:
    """Load DEX router metadata from defi_protocols.json.

    Returns ``{lowercased_address: protocol_info_dict}``.
    """
    src = defi_protocols_path or _DEFI_PROTOCOLS_PATH
    try:
        raw = json.loads(src.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # noqa: BLE001
        log.warning("dex routers seed load failed (%s)", exc)
        return {}

    # Name-pattern fallback for pre-v0.9.3 entries that lack
    # the `subcategory` field. Recognizes well-known DEX router
    # names so the original (1inch, Uniswap, 0x, Sushiswap)
    # entries still load.
    name_patterns_dex = (
        "1inch", "uniswap", "0x:", "sushiswap", "sushi",
        "curve", "balancer", "paraswap", "cow protocol",
        "kyber", "pancake",
    )

    out: dict[str, dict] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        addr = entry.get("address")
        if not isinstance(addr, str) or not addr.strip():
            continue
        subcategory = entry.get("subcategory", "")
        name_lower = (entry.get("name") or "").lower()

        # Match by subcategory (v0.9.3+) OR by name pattern
        # (pre-v0.9.3 entries that didn't carry subcategory).
        is_dex = (
            subcategory in _DEX_ROUTER_SUBCATEGORIES
            or any(p in name_lower for p in name_patterns_dex)
        )
        if not is_dex:
            continue
        out[addr.lower()] = entry
    return out


def _resolve_output_from_receipt(
    adapter: object,
    tx_hash: str,
    *,
    input_token_contract: str | None,
    swapper: str,
    infra_addresses: set[str],
):
    """Fetch a swap tx's receipt + recover its output from the ERC-20 Transfer
    logs. Returns a ``SwapOutput`` or None. Best-effort — any fetch/parse
    failure degrades to None (no output) rather than raising."""
    from recupero.trace.swap_output import (
        parse_erc20_transfers,
        resolve_swap_output,
    )
    try:
        receipt = adapter.fetch_evidence_receipt(tx_hash)
        raw = getattr(receipt, "raw_receipt", None)
    except Exception as exc:  # noqa: BLE001 — receipt fetch is best-effort
        log.debug("swap-output receipt fetch failed tx=%s: %s", tx_hash, exc)
        return None
    parsed = parse_erc20_transfers(raw)
    if not parsed:
        return None
    inputs = {input_token_contract.lower()} if input_token_contract else set()
    return resolve_swap_output(
        parsed,
        swapper=swapper,
        input_token_contracts=inputs,
        infra_addresses=infra_addresses,
    )


def detect_dex_swaps(
    case: Case,
    dex_router_db: dict[str, dict] | None = None,
    *,
    adapter: object | None = None,
) -> list[DEXSwap]:
    """Scan ``case.transfers`` for DEX swap events.

    Approach:
      1. Find transfers TO a DEX router contract — these are
         the input side of a swap.
      2. For each input transfer, find OTHER transfers in the
         same tx that go FROM the router to some other address
         — these are the output side.
      3. Pair input + output to produce DEXSwap records.

    v0.34: when no output can be paired from ``case.transfers`` AND an
    ``adapter`` is supplied, fetch the swap tx's RECEIPT and recover the output
    from its ERC-20 ``Transfer`` logs (``swap_output.resolve_swap_output``).
    This is what catches 0x Protocol / Matcha settler swaps, where the converted
    token (e.g. DAI) is paid out by the settler — an outflow the BFS never
    traversed, so it's absent from ``case.transfers``. Such outputs are marked
    ``output_source="receipt_logs"`` so the continuation still follows them.

    Returns swaps sorted by input_amount_usd descending.
    """
    routers = (
        dex_router_db if dex_router_db is not None else load_dex_routers()
    )
    if not routers or not case.transfers:
        return []

    # Group transfers by tx_hash for efficient pairing.
    by_tx: dict[str, list[Transfer]] = defaultdict(list)
    for t in case.transfers:
        by_tx[t.tx_hash].append(t)

    swaps: list[DEXSwap] = []
    for tx_hash, transfers_in_tx in by_tx.items():
        # Look for transfer(s) TO a router (input side)
        input_transfers = [
            t for t in transfers_in_tx
            if t.to_address.lower() in routers
        ]
        if not input_transfers:
            continue
        # Find output-side transfers in the same tx (router →
        # somewhere). Some DEXes (1inch) emit the output
        # transfer with from=router; some (CoW) use a settlement
        # contract pattern where from=settlement. We match on
        # tx_hash + (from is the router OR from is another
        # router in the same tx) and exclude any transfer that's
        # back to one of the swap inputs.
        input_router_addresses = {
            t.to_address.lower() for t in input_transfers
        }
        output_transfers = [
            t for t in transfers_in_tx
            if t.from_address.lower() in input_router_addresses
            and t.to_address.lower() not in input_router_addresses
        ]

        # Build a swap record per input transfer. If multiple
        # output transfers exist, we associate with the
        # largest-USD one (typical swap pattern: 1 input → 1
        # primary output + small fee outputs).
        for in_t in input_transfers:
            router_addr = in_t.to_address.lower()
            router_info = routers[router_addr]
            # Pick the largest matching output by USD
            best_output: Transfer | None = None
            best_usd = Decimal("0")
            for out_t in output_transfers:
                usd = out_t.usd_value_at_tx or Decimal("0")
                if usd > best_usd:
                    best_usd = usd
                    best_output = out_t

            # v0.32.1 (trace-depth #3): USD-only selection makes an UNPRICED
            # swap output INVISIBLE — `usd_value_at_tx or 0` defaults an
            # unpriced output to 0, which never beats best_usd=0, so
            # best_output stays None and the tracer (which only follows
            # confidence=='high' outputs with a recipient) DEAD-ENDS at the
            # router. A launderer swapping stolen funds into a token
            # CoinGecko can't price (new listing, low liquidity, self-issued)
            # thereby breaks the trail. Fall back to the on-chain output
            # transfer(s) when no priced winner exists — the router→address
            # transfer is an on-chain FACT (not an inference), so the
            # recipient is identified with structural certainty:
            #   * exactly one output transfer  → unambiguous, use it.
            #   * multiple, all same token     → largest amount is the main
            #                                     output (others are fee/dust).
            #   * multiple, mixed tokens, all  → cannot tell main from fee
            #     unpriced                       across tokens; leave None
            #                                     (confidence 'medium', the
            #                                     brief still surfaces the
            #                                     swap for manual follow-up).
            if best_output is None and output_transfers:
                if len(output_transfers) == 1:
                    best_output = output_transfers[0]
                elif len({ot.token.symbol for ot in output_transfers}) == 1:
                    best_output = max(
                        output_transfers,
                        key=lambda ot: ot.amount_decimal or Decimal("0"),
                    )

            # v0.34: still no in-trace output — a settler-style swap (0x /
            # Matcha) pays the converted token from the settler's own balance,
            # an outflow the BFS never traversed. Recover it from the swap tx's
            # receipt logs (an on-chain fact) so the trace doesn't dead-end.
            output_source = "in_trace"
            log_out = None
            if best_output is None and adapter is not None:
                log_out = _resolve_output_from_receipt(
                    adapter, tx_hash,
                    input_token_contract=getattr(in_t.token, "contract", None),
                    swapper=in_t.from_address,
                    infra_addresses=set(routers.keys()) | input_router_addresses,
                )
                if log_out is not None:
                    output_source = "receipt_logs"

            if best_output is not None:
                confidence = "high"
                out_symbol = best_output.token.symbol
                out_amount = best_output.amount_decimal
                out_usd = best_output.usd_value_at_tx
                out_recipient = best_output.to_address.lower()
            elif log_out is not None:
                # Structural (the Transfer event exists) but "which output is
                # ours" is a heuristic → medium, never high.
                confidence = "medium"
                out_symbol = None       # logs give the contract, not a symbol
                out_amount = None       # raw amount; decimals unknown here
                out_usd = None
                out_recipient = log_out.output_recipient
            else:
                confidence = "medium"
                out_symbol = out_amount = out_usd = out_recipient = None

            swaps.append(DEXSwap(
                tx_hash=tx_hash,
                explorer_url=in_t.explorer_url,
                block_time_iso=in_t.block_time.isoformat().replace("+00:00", "Z"),
                swapper=in_t.from_address.lower(),
                router_address=router_addr,
                router_name=router_info.get("name", "(unknown DEX)"),
                router_protocol=router_info.get("name", "").split(":")[0].strip()
                                or "(unknown)",
                input_token_symbol=in_t.token.symbol,
                input_amount_decimal=in_t.amount_decimal,
                input_amount_usd=in_t.usd_value_at_tx,
                output_token_symbol=out_symbol,
                output_amount_decimal=out_amount,
                output_amount_usd=out_usd,
                output_recipient=out_recipient,
                confidence=confidence,
                output_source=output_source,
            ))

    swaps.sort(
        key=lambda s: s.input_amount_usd or Decimal("0"),
        reverse=True,
    )
    return swaps


def dex_swaps_to_brief_section(swaps: list[DEXSwap]) -> list[dict]:
    """Serialize for the brief's DEX_SWAPS section."""
    out: list[dict] = []
    for s in swaps:
        out.append({
            "tx_hash": s.tx_hash,
            "explorer_url": s.explorer_url,
            "block_time": s.block_time_iso,
            "swapper": s.swapper,
            "router_address": s.router_address,
            "router_name": s.router_name,
            "router_protocol": s.router_protocol,
            "input_token": s.input_token_symbol,
            "input_amount": (
                f"{s.input_amount_decimal} {s.input_token_symbol}"
                if s.input_amount_decimal and s.input_token_symbol
                else None
            ),
            "input_amount_usd": (
                f"${s.input_amount_usd:,.2f}"
                if s.input_amount_usd is not None else None
            ),
            "output_token": s.output_token_symbol,
            "output_amount": (
                f"{s.output_amount_decimal} {s.output_token_symbol}"
                if s.output_amount_decimal and s.output_token_symbol
                else None
            ),
            "output_amount_usd": (
                f"${s.output_amount_usd:,.2f}"
                if s.output_amount_usd is not None else None
            ),
            "output_recipient": s.output_recipient,
            "confidence": s.confidence,
            "investigator_note": _build_swap_note(s),
        })
    return out


def _build_swap_note(s: DEXSwap) -> str:
    """One-line action item for the investigator."""
    input_str = (
        f"${s.input_amount_usd:,.2f} {s.input_token_symbol}"
        if s.input_amount_usd is not None and s.input_token_symbol
        else f"{s.input_amount_decimal} {s.input_token_symbol}"
        if s.input_token_symbol else "(unknown amount)"
    )
    output_str = (
        f"${s.output_amount_usd:,.2f} {s.output_token_symbol}"
        if s.output_amount_usd is not None and s.output_token_symbol
        else f"{s.output_amount_decimal} {s.output_token_symbol}"
        if s.output_token_symbol else None
    )
    if output_str and s.output_recipient:
        return (
            f"Swap via {s.router_name}: {input_str} → {output_str} "
            f"to {s.output_recipient}. Continue tracing from "
            f"the output address; the original token is no longer "
            "recoverable at this hop."
        )
    if s.output_recipient:
        return (
            f"Swap via {s.router_name}: {input_str} → "
            f"swapped tokens to {s.output_recipient}. "
            f"Continue tracing from the output address."
        )
    return (
        f"Swap via {s.router_name}: {input_str} → swap output "
        f"address not identified in trace. Continue tracing "
        "requires fetching the tx's full event log."
    )


__all__ = (
    "DEXSwap",
    "detect_dex_swaps",
    "dex_swaps_to_brief_section",
    "load_dex_routers",
)
