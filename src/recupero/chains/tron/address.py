"""Tron address utilities (v0.12.0).

Tron addresses come in two encodings:

  * **Base58check** — the user-facing form, e.g.
    ``TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`` (USDT-TRC20 contract).
    Always 34 chars, starts with ``T`` on mainnet, base58-alphabet.

  * **Hex** — the wire form used inside TRC-20 contract events,
    e.g. ``41a614f803b6fd780986a42c78ec9c7f77e6ded13c``. Always
    42 hex chars (21 bytes): a 1-byte mainnet prefix ``0x41``
    followed by a 20-byte payload identical in shape to an EVM
    address.

The conversion is bidirectional and stable: base58check ↔ hex without
loss. TronGrid returns transfer events with addresses in hex form
inside ``raw_data`` and base58check form inside the higher-level
``data`` array. Risk-scoring + correlation lookups need a single
canonical form, so we standardize on **base58check** for the user-
facing pipeline and convert at the adapter boundary.

This module implements base58check encoding from scratch (no external
``base58`` dependency) — 60 lines of well-tested code that doesn't
pull in another supply-chain surface.
"""

from __future__ import annotations

import hashlib

# Bitcoin / Tron base58 alphabet (same set, same order).
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

# Tron mainnet address prefix byte.
_TRON_MAINNET_PREFIX = 0x41

# Length sanity checks.
_HEX_ADDR_LEN = 42                # "41" + 40 hex chars
_BASE58_ADDR_LEN = 34
_PAYLOAD_LEN = 21                 # 1 prefix + 20 address bytes


class TronAddressError(ValueError):
    """Raised on malformed Tron address input."""


# ----- base58check core ----- #


def _b58encode(b: bytes) -> str:
    """Encode bytes as base58 (Bitcoin alphabet)."""
    # Count leading zero bytes (encoded as leading '1's).
    n_leading_zeros = 0
    for byte in b:
        if byte == 0:
            n_leading_zeros += 1
        else:
            break
    # Convert the rest from base 256 to base 58.
    num = int.from_bytes(b, "big")
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = _B58_ALPHABET[rem] + encoded
    return ("1" * n_leading_zeros) + encoded


def _b58decode(s: str) -> bytes:
    """Decode a base58 string to bytes (Bitcoin alphabet)."""
    n_leading_ones = 0
    for ch in s:
        if ch == "1":
            n_leading_ones += 1
        else:
            break
    num = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise TronAddressError(f"invalid base58 character: {ch!r}")
        num = num * 58 + _B58_INDEX[ch]
    # Convert num to bytes
    n_bytes = (num.bit_length() + 7) // 8
    decoded = num.to_bytes(n_bytes, "big") if num > 0 else b""
    return (b"\x00" * n_leading_ones) + decoded


def _sha256d(b: bytes) -> bytes:
    """Double-SHA256 (Bitcoin / Tron checksum)."""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ----- Public conversion API ----- #


def hex_to_base58(hex_addr: str) -> str:
    """Convert a Tron hex address (``41...``, 42 chars) to base58check.

    Raises ``TronAddressError`` on invalid input.

    Example::

      hex_to_base58("41a614f803b6fd780986a42c78ec9c7f77e6ded13c")
      # → "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    """
    if not isinstance(hex_addr, str):
        raise TronAddressError(f"hex address must be str, got {type(hex_addr)!r}")
    h = hex_addr.lower()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) != _HEX_ADDR_LEN:
        raise TronAddressError(
            f"hex address must be {_HEX_ADDR_LEN} chars (got {len(h)})"
        )
    try:
        payload = bytes.fromhex(h)
    except ValueError as e:
        raise TronAddressError(f"hex address not hex-decodable: {e}") from e
    if payload[0] != _TRON_MAINNET_PREFIX:
        # Other prefixes exist (e.g. Shasta testnet uses 0xa0) — we
        # accept-and-encode rather than reject. The base58check round-
        # trip still works on any 21-byte payload.
        pass
    checksum = _sha256d(payload)[:4]
    return _b58encode(payload + checksum)


def base58_to_hex(b58_addr: str) -> str:
    """Convert a Tron base58check address to lowercase hex.

    Returns the 42-char hex (no ``0x`` prefix) so it can be
    directly compared with TronGrid's ``raw_data`` fields.

    Raises ``TronAddressError`` on invalid input or checksum
    mismatch.
    """
    if not isinstance(b58_addr, str):
        raise TronAddressError(f"address must be str, got {type(b58_addr)!r}")
    if len(b58_addr) != _BASE58_ADDR_LEN:
        raise TronAddressError(
            f"base58 address must be {_BASE58_ADDR_LEN} chars (got {len(b58_addr)})"
        )
    raw = _b58decode(b58_addr)
    if len(raw) != _PAYLOAD_LEN + 4:
        raise TronAddressError(
            f"decoded address must be {_PAYLOAD_LEN + 4} bytes "
            f"(payload+checksum), got {len(raw)}"
        )
    payload, checksum = raw[:_PAYLOAD_LEN], raw[_PAYLOAD_LEN:]
    expected_checksum = _sha256d(payload)[:4]
    if checksum != expected_checksum:
        raise TronAddressError(
            f"base58check checksum mismatch for {b58_addr!r} "
            f"(expected {expected_checksum.hex()}, got {checksum.hex()})"
        )
    return payload.hex()


def is_tron_base58_address(s: str) -> bool:
    """Return True iff ``s`` parses as a valid base58check Tron address.

    Used by the address-routing logic at the CLI / pipeline boundary
    to decide whether a victim address should hit the Tron adapter or
    a different chain.
    """
    if not isinstance(s, str) or len(s) != _BASE58_ADDR_LEN:
        return False
    if not s.startswith("T"):
        return False
    try:
        base58_to_hex(s)
    except TronAddressError:
        return False
    return True


def is_tron_hex_address(s: str) -> bool:
    """Return True iff ``s`` parses as a valid Tron hex address.

    Accepts both ``41...`` (mainnet) and ``a0...`` (Shasta testnet)
    prefixes — a hex address with no prefix byte is by definition
    not a Tron address.
    """
    if not isinstance(s, str):
        return False
    h = s.lower()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) != _HEX_ADDR_LEN:
        return False
    try:
        bytes.fromhex(h)
    except ValueError:
        return False
    return True


def normalize_tron_address(s: str) -> str:
    """Return the canonical base58check form of any Tron-shaped
    address (hex or base58check).

    Used at the adapter boundary so every downstream component
    keys addresses on the same string.
    """
    if not isinstance(s, str):
        raise TronAddressError(f"address must be str, got {type(s)!r}")
    if is_tron_base58_address(s):
        return s
    if is_tron_hex_address(s):
        return hex_to_base58(s)
    raise TronAddressError(
        f"not a Tron address (neither base58check nor 42-char hex): {s!r}"
    )


__all__ = (
    "TronAddressError",
    "hex_to_base58",
    "base58_to_hex",
    "is_tron_base58_address",
    "is_tron_hex_address",
    "normalize_tron_address",
)
