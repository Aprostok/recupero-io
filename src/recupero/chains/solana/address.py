"""Solana address validation (v0.13.5).

Solana addresses are base58-encoded Ed25519 public keys (32 bytes
when decoded, which encodes to 32-44 characters in base58 — most
land in the 43-44 range, but leading-zero bytes shrink the string).
No checksum — base58 alone, with byte-length validation as the
guard against typos.

Used at the chain dispatch boundary so a Solana-shaped address
gets routed to SolanaAdapter (rather than mis-detected as a Tron
base58 or a Bitcoin base58check).
"""

from __future__ import annotations

# Bitcoin / Solana / Tron all share the same base58 alphabet.
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

# Solana public keys decode to exactly 32 bytes.
_SOLANA_PUBKEY_LEN_BYTES = 32

# Practical bounds on the encoded length. The theoretical range is
# wider (a 32-byte key with all zero leading bytes encodes to 32
# "1" chars + nothing else = 32 chars in pathological cases), but
# we use 32..44 as the realistic envelope. Solana itself's PublicKey
# validation accepts this range.
_MIN_ENCODED_LEN = 32
_MAX_ENCODED_LEN = 44


class SolanaAddressError(ValueError):
    """Raised on malformed Solana address input."""


def _b58decode(s: str) -> bytes:
    """Decode a base58 string to bytes (Bitcoin alphabet, same as Solana)."""
    n_leading_ones = 0
    for ch in s:
        if ch == "1":
            n_leading_ones += 1
        else:
            break
    num = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise SolanaAddressError(f"invalid base58 character: {ch!r}")
        num = num * 58 + _B58_INDEX[ch]
    n_bytes = (num.bit_length() + 7) // 8
    decoded = num.to_bytes(n_bytes, "big") if num > 0 else b""
    return (b"\x00" * n_leading_ones) + decoded


def is_solana_address(s: str) -> bool:
    """Return True iff ``s`` is a valid mainnet Solana address.

    The validation chain:
      1. String, length 32-44.
      2. Base58 alphabet (no 0/O/I/l).
      3. Decodes to exactly 32 bytes (the Ed25519 pubkey size).

    Note: this does NOT verify the bytes form a valid Ed25519
    curve point — Solana itself allows off-curve PDAs (program-
    derived addresses). Forensic tracing accepts both, so we don't
    restrict.
    """
    if not isinstance(s, str):
        return False
    if not (_MIN_ENCODED_LEN <= len(s) <= _MAX_ENCODED_LEN):
        return False
    try:
        raw = _b58decode(s)
    except SolanaAddressError:
        return False
    return len(raw) == _SOLANA_PUBKEY_LEN_BYTES


def normalize_solana_address(s: str) -> str:
    """Return the canonical form of a Solana address.

    Solana addresses are case-sensitive base58 — case is meaningful.
    Just strip whitespace and validate.

    Raises SolanaAddressError on unrecognized input.
    """
    if not isinstance(s, str):
        raise SolanaAddressError(f"address must be str, got {type(s)!r}")
    s = s.strip()
    if not is_solana_address(s):
        raise SolanaAddressError(f"not a valid Solana address: {s!r}")
    return s


__all__ = (
    "SolanaAddressError",
    "is_solana_address",
    "normalize_solana_address",
)
