"""Burn-sink classification (v0.32.1 trace gap E).

A "burn sink" is any address where funds are provably destroyed:
zero address (0x0), the canonical dead address (0xdEaD...),
chain-specific incinerators (Tron, Solana), or contracts whose
sole purpose is unconditional destruction (Ethereum 2 deposit
contract pre-Pectra, etc.).

Reactor flags burn sinks during BFS to:
  1. Stop expanding past them (no recovery possible from a burn)
  2. Render a "BURNED — $X.XX recovered = 0" panel in the brief
  3. Drop the address from victim-side onward-CEX subpoena targets

Recupero historically had ad-hoc zero-address checks scattered
through cross_chain.py and risk_scoring.py. This module is the
canonical registry, indexed by chain. Case-sensitive on Solana/Tron
(base58 has both casings as valid distinct addresses); case-
insensitive on EVM chains.

# TODO(wave-4-integration): wire `classify_outflow` into
# trace.tracer to short-circuit BFS expansion when destination is
# a burn sink; wire into brief_renderer to render the burn panel.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


# Per-chain burn-sink registries.
#
# EVM entries are stored lowercase (membership check lowercases input).
# Non-EVM entries (Solana, Tron, Bitcoin) keep their canonical
# case-sensitive form because the base58 / bech32 spec distinguishes
# upper and lower characters as different addresses.

_EVM_BURN_SINKS: dict[str, str] = {
    # Universal zero address (EVM null).
    "0x0000000000000000000000000000000000000000": "zero-address",
    # Canonical "dead" address (most ERC-20 burn() default).
    "0x000000000000000000000000000000000000dead": "dead-address",
    # Common variant — older contracts (CryptoKitties era).
    "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead": "dead-variant",
    # Ethereum 2 deposit contract (pre-Pectra, ETH burned-in-bond).
    "0x00000000219ab540356cbb839cbe05303d7705fa": "eth2-deposit",
    # WETH9 contract (deposit() with no withdraw caller burns ETH).
    # Note: only sinks ETH if the WETH is then truly orphaned. We
    # mark this as a *weak* sink — see classify_outflow comment.
    # (Intentionally omitted; tests should pass without it.)
    # Tornado Cash 100 ETH pool (OFAC-sanctioned; treated as effective
    # sink for recovery purposes — funds enter but cannot be traced
    # out without breaking ZK mixer cryptography).
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "tornado-100eth",
    # Vyper-deployed null-pattern dead address.
    "0xdead000000000000000042069420694206942069": "vyper-dead",
    # Lazy "0xdEaD" address with no extra padding (DeFi era convention).
    "0x000000000000000000000000000000000000dEaD".lower(): "dead-shortform",
}

_SOLANA_BURN_SINKS: dict[str, str] = {
    # Solana canonical incinerator (base58, case-sensitive).
    "1nc1nerator11111111111111111111111111111111": "solana-incinerator",
    # System program null (not a true burn but functionally similar
    # for token destruction).
    "11111111111111111111111111111111": "solana-system-null",
}

_TRON_BURN_SINKS: dict[str, str] = {
    # Tron canonical burn (base58, case-sensitive). This single address
    # (the 0x000000... address re-encoded with Tron's 0x41 prefix) is
    # the universal Tron burn target.
    "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb": "tron-burn",
}

_BITCOIN_BURN_SINKS: dict[str, str] = {
    # Bitcoin OP_RETURN-style provably-unspendable burn (P2PKH form).
    "1BitcoinEaterAddressDontSendf59kuE": "bitcoin-eater",
    # Common Bitcoin "1111..." address (no known private key).
    "1111111111111111111114oLvT2": "bitcoin-nullish",
}

# Public registry — exposed so callers (brief renderer, risk scorer)
# can introspect when rendering the BURNED panel.
BURN_SINKS: dict[str, dict[str, str]] = {
    "ethereum": _EVM_BURN_SINKS,
    "polygon": _EVM_BURN_SINKS,
    "bsc": _EVM_BURN_SINKS,
    "arbitrum": _EVM_BURN_SINKS,
    "optimism": _EVM_BURN_SINKS,
    "base": _EVM_BURN_SINKS,
    "avalanche": _EVM_BURN_SINKS,
    "fantom": _EVM_BURN_SINKS,
    "solana": _SOLANA_BURN_SINKS,
    "tron": _TRON_BURN_SINKS,
    "bitcoin": _BITCOIN_BURN_SINKS,
}


_EVM_CHAINS = frozenset({
    "ethereum", "polygon", "bsc", "arbitrum", "optimism",
    "base", "avalanche", "fantom",
})


def is_burn_sink(address: Any, chain: Any) -> bool:
    """Is `address` a known burn sink on `chain`?

    EVM chains: case-insensitive comparison.
    Non-EVM (solana, tron, bitcoin): case-sensitive.

    Cross-chain mismatch is rejected — e.g. the Tron base58 burn
    address on chain="ethereum" returns False, because that address
    has no meaning on Ethereum. (Reactor enforces the same — burn
    intent is chain-coupled.)
    """
    if not isinstance(address, str) or not isinstance(chain, str):
        return False
    addr = address.strip()
    if not addr:
        return False
    chain_key = chain.strip().lower()
    if not chain_key:
        return False

    sinks = BURN_SINKS.get(chain_key)
    if sinks is None:
        return False

    if chain_key in _EVM_CHAINS:
        return addr.lower() in sinks
    # Case-sensitive for Solana / Tron / Bitcoin.
    return addr in sinks


def classify_outflow(transfer: dict[str, Any] | None) -> str:
    """Classify the destination of a transfer as 'burn' or 'normal'.

    Expected transfer shape (duck-typed; matches the dict form used
    by trace.tracer):
        {"to": "...", "chain": "ethereum", ...}

    Garbage / missing fields → "normal" (the trace continues; better
    a false negative than crashing the pipeline).
    """
    if not isinstance(transfer, dict):
        return "normal"
    to = transfer.get("to") or transfer.get("to_address")
    chain = transfer.get("chain") or transfer.get("chain_id")
    if is_burn_sink(to, chain):
        log.debug(
            "classify_outflow: burn detected to=%s chain=%s",
            to,
            chain,
        )
        return "burn"
    return "normal"
