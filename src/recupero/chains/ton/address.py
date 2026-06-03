"""TON address codec.

A TON address identifies (workchain, 32-byte account hash). It has two textual
forms:

  * RAW:            ``<workchain>:<64-hex>``  e.g. ``0:b113a994…``  (also ``-1:`` for
                    the masterchain). Bounce-flag-agnostic.
  * USER-FRIENDLY:  48-char base64url of ``[tag, workchain, hash(32), crc16(2)]``,
                    e.g. ``EQCxE6mU…`` (bounceable, tag 0x11) or ``UQ…``
                    (non-bounceable, tag 0x51). The CRC16 (CCITT/XMODEM, poly
                    0x1021) covers the first 34 bytes.

TON Center v2 returns user-friendly addresses; v3 returns raw. The SAME wallet
therefore appears as raw ``0:hex``, ``EQ…`` (bounceable) and ``UQ…``
(non-bounceable). To make tracing match them, we canonicalize EVERYTHING to the
RAW lower-cased form ``<wc>:<hexlower>`` — the only form with no bounce-flag
ambiguity. The codec is verified against live raw↔friendly vector pairs from
toncenter.com (see tests/test_ton_address.py).
"""

from __future__ import annotations

import base64
import re

_RAW_RE = re.compile(r"^(-?\d+):([0-9a-fA-F]{64})$")
# User-friendly is base64url or base64 (the API uses url-safe -/_); 48 chars.
_FRIENDLY_RE = re.compile(r"^[A-Za-z0-9_\-+/]{48}$")

_TAG_BOUNCEABLE = 0x11
_TAG_NON_BOUNCEABLE = 0x51
_TAG_TEST_ONLY = 0x80  # OR'd into the tag for testnet-only addresses


def _crc16(data: bytes) -> int:
    """CRC16-CCITT/XMODEM (poly 0x1021, init 0x0000) — the checksum TON uses
    in the user-friendly address form."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (
                ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000)
                else (crc << 1) & 0xFFFF
            )
    return crc


def is_ton_address(addr: str) -> bool:
    """True if ``addr`` looks like a TON address in either form."""
    if not isinstance(addr, str):
        return False
    s = addr.strip()
    if _RAW_RE.match(s):
        return True
    if _FRIENDLY_RE.match(s):
        # Cheap structural check; full validation happens in friendly_to_raw.
        try:
            friendly_to_raw(s)
            return True
        except Exception:  # noqa: BLE001
            return False
    return False


def friendly_to_raw(friendly: str) -> str:
    """Decode a 48-char user-friendly TON address to canonical raw
    ``<wc>:<hexlower>``. Raises ValueError on malformed input or CRC mismatch."""
    s = friendly.strip()
    # Accept both url-safe (-/_) and standard (+//) base64 alphabets.
    norm = s.replace("+", "-").replace("/", "_")
    try:
        full = base64.urlsafe_b64decode(norm)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"not valid base64url: {friendly!r}") from exc
    if len(full) != 36:
        raise ValueError(f"TON friendly address must decode to 36 bytes, got {len(full)}")
    payload, crc_bytes = full[:34], full[34:]
    expected = (crc_bytes[0] << 8) | crc_bytes[1]
    if _crc16(payload) != expected:
        raise ValueError(f"TON address CRC16 mismatch: {friendly!r}")
    workchain_byte = payload[1]
    workchain = workchain_byte - 256 if workchain_byte == 0xFF else workchain_byte
    account_hash = payload[2:34]
    return f"{workchain}:{account_hash.hex()}"


def raw_to_friendly(raw: str, *, bounceable: bool = True, test_only: bool = False) -> str:
    """Encode a raw ``<wc>:<hex>`` address to the user-friendly base64url form.
    Bounceable (``EQ…``) is the convention for contract addresses (explorers)."""
    m = _RAW_RE.match(raw.strip())
    if not m:
        raise ValueError(f"not a raw TON address: {raw!r}")
    workchain = int(m.group(1))
    account_hash = bytes.fromhex(m.group(2))
    tag = _TAG_BOUNCEABLE if bounceable else _TAG_NON_BOUNCEABLE
    if test_only:
        tag |= _TAG_TEST_ONLY
    workchain_byte = workchain & 0xFF  # -1 → 0xFF
    payload = bytes([tag, workchain_byte]) + account_hash
    crc = _crc16(payload)
    full = payload + bytes([crc >> 8, crc & 0xFF])
    return base64.urlsafe_b64encode(full).decode("ascii")


def normalize_ton_address(addr: str) -> str:
    """Canonicalize ANY TON address form (raw / EQ / UQ / std-base64) to the
    bounce-flag-agnostic raw lower-cased form ``<wc>:<hexlower>``.

    This is the canonical key for tracing — so the same wallet seen via the v2
    native API (user-friendly) and the v3 Jetton API (raw) compares equal.
    Raises ValueError on input that is not a recognizable TON address.
    """
    s = addr.strip()
    m = _RAW_RE.match(s)
    if m:
        return f"{int(m.group(1))}:{m.group(2).lower()}"
    if _FRIENDLY_RE.match(s):
        return friendly_to_raw(s)
    raise ValueError(f"not a TON address: {addr!r}")
