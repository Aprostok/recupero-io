"""Stellar address (StrKey) handling.

A Stellar account id is a StrKey ed25519 public key: the literal ``G`` followed
by 55 base32 (RFC 4648, no padding) characters — 56 total. StrKey encodes a
version byte + 32-byte key + a CRC16-XModem checksum, but addresses we handle
come FROM Horizon (authoritative), so we validate shape + the leading version
char rather than re-deriving the checksum. base32 is case-sensitive (upper); we
preserve case (lower-casing would corrupt it), matching the
``canonical_address_key`` convention for non-EVM chains.

Muxed accounts (``M...``) and contracts (``C...``, Soroban) are out of scope for
the classic-payments adapter.
"""

from __future__ import annotations

import re

# G + 55 base32 chars (A-Z, 2-7). 56 total.
_STELLAR_RE = re.compile(r"^G[A-Z2-7]{55}$")


def is_stellar_address(addr: str) -> bool:
    """True if ``addr`` is a well-formed Stellar account id (StrKey ``G...``)."""
    return isinstance(addr, str) and bool(_STELLAR_RE.match(addr.strip()))


def normalize_stellar_address(addr: str) -> str:
    """Canonicalize a Stellar account id (strip; preserve case). Raises
    ValueError when it is not a valid ``G...`` StrKey."""
    s = addr.strip()
    if not _STELLAR_RE.match(s):
        raise ValueError(f"not a Stellar account id: {addr!r}")
    return s
