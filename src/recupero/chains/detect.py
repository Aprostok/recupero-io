"""Best-guess chain from an address SHAPE — the consumer "start a recovery"
convenience so a victim pastes the drained address without picking a chain.

Detection verifies the address with the SAME per-chain validators the adapters
use (base58check / bech32 / ed25519-length checksums, not loose prefixes), so it
never guesses from a bare prefix. The formats are mutually exclusive (a Tron
base58check decodes to 25 bytes and carries the 0x41 version byte; a Solana key
decodes to 32 bytes; a Bitcoin base58check has version 0x00/0x05 — none satisfy
another chain's validator), so order only affects readability.

EVM caveat: every EVM chain shares the identical 20-byte 0x address, so an
0x-address can only be resolved to the EVM FAMILY. We return ``"ethereum"`` (the
most common) as a default the caller MUST let the user override when the funds
were actually on Arbitrum / Base / BSC / Polygon / etc. Returns ``None`` when no
validator matches (the caller then asks the user to specify the chain).
"""

from __future__ import annotations

import re

from recupero.chains.bitcoin.address import (
    is_base58check_address,
    is_bech32_address,
)
from recupero.chains.solana.address import is_solana_address
from recupero.chains.tron.address import is_tron_base58_address

# 20-byte hex, 0x-prefixed. Any EVM chain; resolved to the family default below.
_EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# The concrete chain ids detection can return. EVM → the family default.
EVM_DEFAULT_CHAIN = "ethereum"


def detect_chain(address: str) -> str | None:
    """Return the best-guess chain id for ``address`` by verified format, or
    ``None`` if no chain validator matches. EVM addresses resolve to
    ``EVM_DEFAULT_CHAIN`` (family default — override for a non-Ethereum EVM chain)."""
    if not isinstance(address, str):
        return None
    a = address.strip()
    if not a:
        return None
    if _EVM_RE.match(a):
        return EVM_DEFAULT_CHAIN
    # Tron before Solana/Bitcoin: 'T...' base58check with the 0x41 version byte.
    if is_tron_base58_address(a):
        return "tron"
    # Bitcoin: bech32 (bc1…) or base58check (1…/3…).
    if is_bech32_address(a) or is_base58check_address(a):
        return "bitcoin"
    # Solana: 32-byte ed25519 public key, base58.
    if is_solana_address(a):
        return "solana"
    return None


def is_evm_family(address: str) -> bool:
    """True if ``address`` is an EVM 0x-address (the chain can't be narrowed from
    the address alone — the UI should offer the EVM chain choices)."""
    return isinstance(address, str) and bool(_EVM_RE.match(address.strip()))


__all__ = ("detect_chain", "is_evm_family", "EVM_DEFAULT_CHAIN")
