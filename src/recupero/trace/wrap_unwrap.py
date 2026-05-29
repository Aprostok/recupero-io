"""Wrap/unwrap pair recognition (v0.32.1 trace gap F).

When a thief drops $X of ETH into WETH (deposit) and immediately
swaps WETH on Uniswap, naive trace pipelines render TWO hops:
"ETH → WETH contract" + "WETH → Uniswap". Reactor folds these into
a single semantic event ("wrapped X ETH, swapped to Y USDC").

Same for stETH, wstETH, rETH, frxETH (liquid staking variants) and
chain-native wraps (WMATIC, WBNB, WAVAX, WFTM, WSOL, WTRX, WCRO).

This module recognizes single-tx wrap/unwrap events from
transaction shape. Pure / no RPC.

# TODO(wave-4-integration): wire `is_wrap_unwrap` into
# trace.tracer to collapse adjacent ETH→WETH→DEX hops into one
# semantic event in the brief.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)


# Function selectors — all are well-known, easy to compute via
# keccak256(signature)[:4]. Kept here as the canonical reference for
# the brief renderer.
SELECTOR_WETH_DEPOSIT = "0xd0e30db0"  # deposit()
SELECTOR_WETH_WITHDRAW = "0x2e1a7d4d"  # withdraw(uint256)
SELECTOR_LIDO_SUBMIT = "0xa1903eab"  # submit(address) — stETH mint
SELECTOR_WSTETH_WRAP = "0xea598cb0"  # wrap(uint256)
SELECTOR_WSTETH_UNWRAP = "0xde0e9a3e"  # unwrap(uint256)
SELECTOR_RETH_DEPOSIT = "0x4dcd4547"  # deposit() (RocketDepositPool)
SELECTOR_FRXETH_SUBMIT = "0xa1903eab"  # submit() — frxETH mint (same shape as Lido)


# Wrapper contract addresses keyed by chain.
# EVM entries are stored lowercase (case-insensitive lookup).
# Non-EVM entries (Solana, Tron) are stored in canonical case
# (base58 distinguishes case as different addresses).
WRAPPER_CONTRACTS: dict[str, dict[str, tuple[str, str]]] = {
    # chain → { wrapper_address → (native_symbol, wrapped_symbol) }
    "ethereum": {
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ("ETH", "WETH"),
        # Lido staked ETH
        "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": ("ETH", "stETH"),
        # wstETH wrapper
        "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": ("stETH", "wstETH"),
        # Rocket Pool rETH
        "0xae78736cd615f374d3085123a210448e74fc6393": ("ETH", "rETH"),
        # Frax frxETH
        "0x5e8422345238f34275888049021821e8e08caa1f": ("ETH", "frxETH"),
    },
    "polygon": {
        "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270": ("MATIC", "WMATIC"),
    },
    "bsc": {
        "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": ("BNB", "WBNB"),
    },
    "avalanche": {
        "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7": ("AVAX", "WAVAX"),
    },
    "fantom": {
        "0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83": ("FTM", "WFTM"),
    },
    "solana": {
        # WSOL native mint (case-sensitive)
        "So11111111111111111111111111111111111111112": ("SOL", "WSOL"),
    },
    "tron": {
        # WTRX TRC-20 wrapper (case-sensitive base58)
        "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR": ("TRX", "WTRX"),
    },
    "cronos": {
        "0x5c7f8a570d578ed84e63fdfa7b1ee72deae1ae23": ("CRO", "WCRO"),
    },
}

# EVM chains where address comparison is case-insensitive.
_EVM_CHAINS = frozenset({
    "ethereum", "polygon", "bsc", "arbitrum", "optimism",
    "base", "avalanche", "fantom", "cronos",
})


# Selectors that indicate a wrap (native → wrapped).
WRAP_SELECTORS = frozenset({
    SELECTOR_WETH_DEPOSIT,
    SELECTOR_LIDO_SUBMIT,
    SELECTOR_WSTETH_WRAP,
    SELECTOR_RETH_DEPOSIT,
    SELECTOR_FRXETH_SUBMIT,
})

# Selectors that indicate an unwrap (wrapped → native).
UNWRAP_SELECTORS = frozenset({
    SELECTOR_WETH_WITHDRAW,
    SELECTOR_WSTETH_UNWRAP,
})


@dataclass(frozen=True)
class WrapUnwrapEvent:
    """One wrap or unwrap event detected on a single tx.

    `direction`: "wrap" (native→wrapped) or "unwrap" (wrapped→native).
    `amount` is the raw amount (in wei / lamports / sun) — caller
    formats with token decimals.
    """

    input_asset: str
    output_asset: str
    amount: int
    chain: str
    direction: str  # "wrap" | "unwrap"
    wrapper_contract: str


def _canon_addr(addr: Any) -> str:
    if not isinstance(addr, str):
        return ""
    return addr.strip().lower()


def _normalize_input(tx_input: Any) -> str:
    """Return the lowercase selector (0x + 8 hex chars) or empty string."""
    if not isinstance(tx_input, str):
        return ""
    s = tx_input.strip().lower()
    if not s.startswith("0x") or len(s) < 10:
        return ""
    return s[:10]


def _to_int(val: Any) -> int | None:
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return None
        try:
            if s.startswith("0x"):
                return int(s, 16)
            return int(s, 10)
        except ValueError:
            return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def is_wrap_unwrap(tx: dict[str, Any] | None) -> WrapUnwrapEvent | None:
    """Return a WrapUnwrapEvent if this tx is a wrap or unwrap; else None.

    Expected tx shape (duck-typed; matches the dict form used by
    trace.tracer):
        {
          "to": "<wrapper contract>",
          "input": "<hex-encoded calldata>",
          "value": <wei int or hex string>,
          "chain": "ethereum",
        }

    For wraps (deposit), `value` holds the native amount.
    For unwraps (withdraw), the amount is in the calldata arg.
    Solana wraps don't have calldata — we detect them by destination
    + amount alone.
    """
    if not isinstance(tx, dict):
        return None

    chain_raw = tx.get("chain") or tx.get("chain_id")
    if not isinstance(chain_raw, str):
        return None
    chain = chain_raw.strip().lower()

    chain_wrappers = WRAPPER_CONTRACTS.get(chain)
    if chain_wrappers is None:
        return None

    to_raw = tx.get("to") or tx.get("to_address")
    if not isinstance(to_raw, str) or not to_raw.strip():
        return None
    # EVM lookup is case-insensitive; Solana/Tron case-sensitive.
    if chain in _EVM_CHAINS:
        to = to_raw.strip().lower()
    else:
        to = to_raw.strip()
    if to not in chain_wrappers:
        return None

    native, wrapped = chain_wrappers[to]

    selector = _normalize_input(tx.get("input") or tx.get("data"))

    # Wrap case
    if selector in WRAP_SELECTORS:
        amount = _to_int(tx.get("value")) or 0
        if amount <= 0:
            # No native value attached — could be a malformed wrap call;
            # for stETH/rETH the value carries ETH, for wstETH the
            # amount comes from calldata. Try to recover from calldata.
            data = tx.get("input") or tx.get("data")
            if isinstance(data, str) and len(data) >= 10 + 64:
                amount = _to_int("0x" + data[10:74]) or 0
        if amount <= 0:
            return None
        return WrapUnwrapEvent(
            input_asset=native,
            output_asset=wrapped,
            amount=amount,
            chain=chain,
            direction="wrap",
            wrapper_contract=to,
        )

    # Unwrap case
    if selector in UNWRAP_SELECTORS:
        data = tx.get("input") or tx.get("data")
        amount = 0
        if isinstance(data, str) and len(data) >= 10 + 64:
            amount = _to_int("0x" + data[10:74]) or 0
        if amount <= 0:
            return None
        return WrapUnwrapEvent(
            input_asset=wrapped,
            output_asset=native,
            amount=amount,
            chain=chain,
            direction="unwrap",
            wrapper_contract=to,
        )

    return None
