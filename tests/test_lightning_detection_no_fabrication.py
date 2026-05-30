"""v0.34 anti-fabrication guard for the Lightning gateway registry.

12 of the 16 previously-hardcoded Lightning gateway addresses were fabricated
placeholders (invalid bech32/base58 checksums); the rest were unverified and
custodial sweep addresses rotate. The registry was emptied. These tests lock
in the honest state AND make it impossible to silently re-introduce a
fabricated address: any future entry MUST pass its real checksum.
"""

from __future__ import annotations

import hashlib

from recupero.trace.lightning_detection import (
    KNOWN_LIGHTNING_GATEWAYS,
    detect_lightning_exit,
    is_lightning_gateway,
)

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _bech32_valid(addr: str) -> bool:
    if addr.lower() != addr and addr.upper() != addr:
        return False
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False
    hrp, data = a[:pos], a[pos + 1:]
    if any(c not in _BECH32_CHARSET for c in data):
        return False
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    values += [_BECH32_CHARSET.find(c) for c in data]
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk in (1, 0x2BC830A3)


def _base58check_valid(s: str) -> bool:
    if any(c not in _B58 for c in s):
        return False
    num = 0
    for c in s:
        num = num * 58 + _B58.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        return False
    body, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == checksum


def _btc_address_valid(addr: str) -> bool:
    if addr.startswith(("bc1", "tb1", "BC1", "TB1")):
        return _bech32_valid(addr)
    return _base58check_valid(addr)


def test_registry_is_empty_pending_verified_source() -> None:
    """The hardcoded table was removed (fabricated + unverifiable + rotating).
    It stays empty until wave-7 wires a maintained, verifiable source."""
    assert KNOWN_LIGHTNING_GATEWAYS == {}


def test_detect_returns_none_for_former_fabricated_addresses() -> None:
    """The former fabricated gateway literals must no longer resolve."""
    for fake in (
        "bc1qsphinx7n8m9k2v5xc6h8a3g4f3d2s1n0pqwert9",  # ex-"Sphinx Chat"
        "bc1qcashapp5q3wn7p8m9k2v5xc6h8a3g4f3d2s1n0",   # ex-"Cash App"
        "bc1qblink9d4ywgfnd8h43da5tpcxcn6ajv590cg6d",   # ex-"Blink"
    ):
        assert detect_lightning_exit(fake) is None
        assert is_lightning_gateway(fake) is False


def test_no_fabricated_addresses_if_repopulated() -> None:
    """Forward guard: if the registry is ever re-populated, every key MUST be a
    checksum-valid BTC address (vacuously true while empty)."""
    bad = [a for a in KNOWN_LIGHTNING_GATEWAYS if not _btc_address_valid(a)]
    assert not bad, f"fabricated (checksum-invalid) Lightning addresses: {bad}"


def test_validator_self_check() -> None:
    """The inline validator accepts a real address and rejects a placeholder."""
    assert _btc_address_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert not _btc_address_valid("bc1qsphinx7n8m9k2v5xc6h8a3g4f3d2s1n0pqwert9")
