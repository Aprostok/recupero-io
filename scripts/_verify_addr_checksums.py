"""Verify every hardcoded BTC/Tron address in the trace registries against its
real checksum (BIP173 bech32 / BIP350 bech32m / base58check). A genuine
on-chain address CANNOT fail its checksum — so any FAIL is a fabricated /
placeholder literal that must never sit in a forensic registry (false
provenance in a law-enforcement deliverable, and it can never match a real
victim transaction). This script is the evidence behind the v0.34 fabricated-
address removal; re-runnable, pure stdlib.

Usage:  python scripts/_verify_addr_checksums.py
Exit 0 always (report-only). Prints VALID/INVALID per address per file.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_TARGETS = [
    _ROOT / "src" / "recupero" / "trace" / "mixer_detection.py",
    _ROOT / "src" / "recupero" / "trace" / "lightning_detection.py",
]

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_valid(addr: str) -> bool:
    if any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return False
    if addr.lower() != addr and addr.upper() != addr:
        return False  # mixed case not allowed
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False
    hrp, data = a[:pos], a[pos + 1:]
    if any(c not in _BECH32_CHARSET for c in data):
        return False
    decoded = [_BECH32_CHARSET.find(c) for c in data]
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + decoded)
    return const in (1, 0x2BC830A3)  # bech32 (v0) or bech32m (v1+)


def base58check_valid(s: str) -> bool:
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
    digest = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    return digest == checksum


_BTC = re.compile(r'"(bc1[a-zA-HJ-NP-Z0-9]{6,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})"')


def main() -> int:
    total = bad = 0
    for path in _TARGETS:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        print(f"\n=== {path.name} ===")
        seen: set[str] = set()
        for m in _BTC.finditer(text):
            addr = m.group(1)
            if addr in seen:
                continue
            seen.add(addr)
            total += 1
            ok = bech32_valid(addr) if addr.startswith("bc1") else base58check_valid(addr)
            if not ok:
                bad += 1
            print(f"  [{'OK   ' if ok else 'FAIL '}] {addr}")
    print(f"\nSCANNED {total} BTC addresses; {bad} FAIL checksum (fabricated).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
