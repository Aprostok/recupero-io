"""Resolve a DEX-aggregator swap's OUTPUT from the transaction receipt logs
(v0.34 — 0x Protocol / Matcha and any settler-style aggregator).

The problem
-----------

``detect_dex_swaps`` pairs a swap's input (victim/perp → router) with its output
(router → recipient) using transfers ALREADY in ``case.transfers``. That works
when the output is a simple router→recipient transfer the BFS happened to fetch.
It does NOT work for 0x Protocol's Settler architecture (and similar), where the
funds convert token→DAI and the DAI is paid out by a SETTLER / pool contract the
BFS never traverses — so the output transfer is absent from ``case.transfers``
and the trace dead-ends at the router. The Zigha case proved this: the
perpetrator's bridged funds were swapped to DAI via 0x ``MainnetSettler``, and
the DAI flowed settler → proxy → intermediate EOA → dormant DAI.

The fix
-------

Fetch the swap tx's RECEIPT and parse its ERC-20 ``Transfer`` event logs — every
token movement in the tx, including the settler's DAI payout. Then identify the
swap OUTPUT: the largest transfer of a token DIFFERENT from the input, to a
recipient that is NOT the swapper and NOT swap infrastructure (router/settler/
pool) and is TERMINAL within the tx (doesn't forward the token onward in the
same tx). That recipient is where the swapped funds landed — the onward hop.

This is structural (the Transfer event is an on-chain FACT), but selecting "the
main output" among a tx's many token movements is a heuristic, so the result is
calibrated ``medium`` confidence — never ``high``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

#: keccak256("Transfer(address,address,uint256)")
ERC20_TRANSFER_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)
_ZERO = "0x0000000000000000000000000000000000000000"


@dataclass(frozen=True)
class RawTokenTransfer:
    token: str      # lowercased token contract
    frm: str        # lowercased sender
    to: str         # lowercased recipient
    amount: int     # raw integer amount


@dataclass(frozen=True)
class SwapOutput:
    output_token_contract: str
    output_recipient: str
    output_amount_raw: int
    confidence: str   # "medium" — structural fact + dominant-output heuristic


def _addr_from_topic(topic: str) -> str:
    """A 32-byte indexed-address topic → 0x-prefixed 20-byte address (lower)."""
    t = (topic or "").lower().removeprefix("0x")
    if len(t) < 40:
        return ""
    return "0x" + t[-40:]


def parse_erc20_transfers(raw_receipt: dict[str, Any] | None) -> list[RawTokenTransfer]:
    """Parse every ERC-20 ``Transfer`` event out of an eth receipt's ``logs``.

    Defensive: malformed / missing logs yield ``[]`` rather than raising.
    """
    if not isinstance(raw_receipt, dict):
        return []
    logs = raw_receipt.get("logs")
    if not isinstance(logs, list):
        return []
    out: list[RawTokenTransfer] = []
    for lg in logs:
        if not isinstance(lg, dict):
            continue
        topics = lg.get("topics")
        if not isinstance(topics, list) or len(topics) < 3:
            continue
        if (topics[0] or "").lower() != ERC20_TRANSFER_TOPIC:
            continue
        token = (lg.get("address") or "").lower()
        frm = _addr_from_topic(topics[1])
        to = _addr_from_topic(topics[2])
        if not token or not frm or not to:
            continue
        data = lg.get("data") or "0x0"
        try:
            amount = int(data, 16)
        except (TypeError, ValueError):
            continue
        out.append(RawTokenTransfer(token=token, frm=frm, to=to, amount=amount))
    return out


def resolve_swap_output(
    transfers: list[RawTokenTransfer],
    *,
    swapper: str,
    input_token_contracts: set[str],
    infra_addresses: set[str],
) -> SwapOutput | None:
    """Identify the swap's main OUTPUT among a tx's ERC-20 transfers.

    The output is the largest transfer where:
      * the token is NOT an input token (the swap changed the asset),
      * the recipient is NOT the swapper, NOT swap infrastructure, NOT zero,
      * the recipient is TERMINAL in this tx (it doesn't forward the token on
        within the same tx — i.e. it's the resting recipient, not an internal
        settler→proxy hop).

    Returns ``None`` when no qualifying output exists (the matcher never guesses
    a destination). Same-token comparison only — amounts across different output
    tokens are not comparable, so we rank within the single most-paid-out output
    token.
    """
    swapper = (swapper or "").lower()
    infra = {a.lower() for a in infra_addresses} | {_ZERO}
    inputs = {a.lower() for a in input_token_contracts}

    senders_in_tx = {t.frm for t in transfers}

    candidates = [
        t for t in transfers
        if t.token not in inputs
        and t.to != swapper
        and t.to not in infra
        and t.amount > 0
        # terminal: the recipient does NOT re-send within this tx (so it's the
        # resting destination, not a settler/proxy pass-through node).
        and t.to not in senders_in_tx
    ]
    if not candidates:
        return None

    # Choose the output TOKEN that had the most total value paid to terminal
    # recipients, then the single largest transfer of that token.
    by_token_total: dict[str, int] = {}
    for t in candidates:
        by_token_total[t.token] = by_token_total.get(t.token, 0) + t.amount
    best_token = max(by_token_total, key=lambda k: by_token_total[k])
    best = max(
        (t for t in candidates if t.token == best_token),
        key=lambda t: t.amount,
    )
    return SwapOutput(
        output_token_contract=best.token,
        output_recipient=best.to,
        output_amount_raw=best.amount,
        confidence="medium",
    )


__all__ = (
    "ERC20_TRANSFER_TOPIC",
    "RawTokenTransfer",
    "SwapOutput",
    "parse_erc20_transfers",
    "resolve_swap_output",
)
