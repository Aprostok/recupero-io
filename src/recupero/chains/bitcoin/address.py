"""Bitcoin address validation (v0.13.0).

Supported address formats (mainnet):

  * **P2PKH** — ``1...``, base58check, 26-35 chars. Original
    pay-to-pubkey-hash addresses. Version byte 0x00.
  * **P2SH** — ``3...``, base58check, 34 chars. Pay-to-script-hash
    (multisig, etc.). Version byte 0x05.
  * **Bech32 segwit v0** — ``bc1q...``, 42 chars typical (max 90).
    Native segwit P2WPKH (single-sig) and P2WSH (multi-sig).
  * **Bech32m segwit v1 (Taproot)** — ``bc1p...``, 62 chars typical.
    Pay-to-Taproot from BIP-341.

We implement validators-only (not creators) because the forensic
pipeline never needs to derive an address from a key — only to
recognize and route addresses found in transaction data.

The bech32 / bech32m polymod is implemented from scratch (BIP-173
/ BIP-350 reference algorithm, ~50 lines) so we don't pull in a
``bech32`` dependency.
"""

from __future__ import annotations

import hashlib

# Bitcoin base58 alphabet (same as Tron).
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

# Bech32 alphabet for segwit (lowercase).
_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_INDEX = {c: i for i, c in enumerate(_BECH32_ALPHABET)}

# Mainnet version bytes.
_P2PKH_VERSION = 0x00
_P2SH_VERSION = 0x05

# Bech32 mainnet HRP (human-readable prefix).
_BECH32_HRP_MAINNET = "bc"

# Bech32m constant from BIP-350 (different from BIP-173 bech32).
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


class BitcoinAddressError(ValueError):
    """Raised on malformed Bitcoin address input."""


# ----- base58check (P2PKH / P2SH) ----- #


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
            raise BitcoinAddressError(f"invalid base58 character: {ch!r}")
        num = num * 58 + _B58_INDEX[ch]
    n_bytes = (num.bit_length() + 7) // 8
    decoded = num.to_bytes(n_bytes, "big") if num > 0 else b""
    return (b"\x00" * n_leading_ones) + decoded


def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def is_base58check_address(s: str) -> bool:
    """Return True iff ``s`` parses as a valid P2PKH (``1...``) or
    P2SH (``3...``) mainnet address."""
    if not isinstance(s, str):
        return False
    if not (s.startswith("1") or s.startswith("3")):
        return False
    if not (26 <= len(s) <= 35):
        return False
    try:
        raw = _b58decode(s)
    except BitcoinAddressError:
        return False
    if len(raw) != 25:
        return False
    version = raw[0]
    if version not in (_P2PKH_VERSION, _P2SH_VERSION):
        return False
    payload, checksum = raw[:-4], raw[-4:]
    expected = _sha256d(payload)[:4]
    return checksum == expected


# ----- bech32 / bech32m (native segwit + Taproot) ----- #


def _bech32_polymod(values: list[int]) -> int:
    """BIP-173 polymod accumulator (also used by bech32m)."""
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_verify_checksum(hrp: str, data: list[int]) -> int | None:
    """Return the BIP-173/350 constant the address checksum validates
    against (1 for bech32, 0x2BC830A3 for bech32m), or None on
    failure."""
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if polymod == _BECH32_CONST:
        return _BECH32_CONST
    if polymod == _BECH32M_CONST:
        return _BECH32M_CONST
    return None


def is_bech32_address(s: str) -> bool:
    """Return True iff ``s`` is a valid mainnet segwit address
    (bech32 v0 OR bech32m v1+)."""
    if not isinstance(s, str):
        return False
    # Mixed case is forbidden (BIP-173 §5 — robust against shoulder
    # surfing and OCR errors).
    if s != s.lower() and s != s.upper():
        return False
    s_lower = s.lower()
    pos = s_lower.rfind("1")
    if pos < 1:
        return False
    hrp = s_lower[:pos]
    if hrp != _BECH32_HRP_MAINNET:
        return False
    # Bech32 max length: 90 chars total per BIP-173 §3.
    if len(s_lower) > 90 or len(s_lower) < 8:
        return False
    data_part = s_lower[pos + 1:]
    if len(data_part) < 6:
        return False
    try:
        data = [_BECH32_INDEX[c] for c in data_part]
    except KeyError:
        return False
    # First data char is the witness version (0..16).
    witness_version = data[0]
    if witness_version > 16:
        return False
    # Checksum validation — bech32 (v0) vs bech32m (v1+).
    spec = _bech32_verify_checksum(hrp, data)
    if spec is None:
        return False
    if witness_version == 0 and spec != _BECH32_CONST:
        return False
    if witness_version != 0 and spec != _BECH32M_CONST:
        return False
    # Witness program (data, after the 1-char version, dropping the
    # 6-char checksum) must be 2..40 5-bit elements which decode to
    # 2..40 bytes after conversion.
    program_5bit = data[1:-6]
    if len(program_5bit) < 2:
        return False
    # Convert 5-bit groups to bytes (BIP-173 §5 padding rules).
    try:
        program_bytes = _convertbits(program_5bit, 5, 8, pad=False)
    except BitcoinAddressError:
        return False
    if program_bytes is None or not (2 <= len(program_bytes) <= 40):
        return False
    # v0 must be P2WPKH (20 bytes) or P2WSH (32 bytes).
    if witness_version == 0 and len(program_bytes) not in (20, 32):
        return False
    return True


def _convertbits(
    data: list[int],
    frombits: int,
    tobits: int,
    pad: bool = True,
) -> list[int] | None:
    """BIP-173 reference bit-group conversion. Returns None on
    over-padding (invalid input)."""
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


# ----- Top-level dispatcher ----- #


def is_bitcoin_address(s: str) -> bool:
    """Return True iff ``s`` is a valid mainnet Bitcoin address
    in any supported encoding (P2PKH, P2SH, bech32, bech32m).

    Used by the address-routing layer to decide whether to dispatch
    to the Bitcoin adapter.
    """
    return is_base58check_address(s) or is_bech32_address(s)


def normalize_bitcoin_address(s: str) -> str:
    """Return the canonical form of a Bitcoin address.

    Canonical:
      * base58check addresses (1..., 3...): case-preserved (case is
        meaningful in base58).
      * bech32 / bech32m addresses (bc1...): lowercased (BIP-173
        forbids mixed case anyway, but we normalize to lower so DB
        keys are stable).

    Raises BitcoinAddressError on unrecognized input.
    """
    if not isinstance(s, str):
        raise BitcoinAddressError(f"address must be str, got {type(s)!r}")
    s = s.strip()
    if is_base58check_address(s):
        return s
    if is_bech32_address(s):
        return s.lower()
    raise BitcoinAddressError(f"not a recognized Bitcoin mainnet address: {s!r}")


def classify_bitcoin_address(s: str) -> str:
    """Return a string classifying the address type.

    Values: ``'p2pkh'`` | ``'p2sh'`` | ``'p2wpkh'`` | ``'p2wsh'``
    | ``'p2tr'`` | ``'unknown'``. Used by the adapter to enrich
    Transfer metadata so the brief can say "victim sent to a
    fresh P2TR Taproot address" rather than just "bc1p...".
    """
    if not isinstance(s, str):
        return "unknown"
    s_stripped = s.strip()
    if s_stripped.startswith("1") and is_base58check_address(s_stripped):
        return "p2pkh"
    if s_stripped.startswith("3") and is_base58check_address(s_stripped):
        return "p2sh"
    if is_bech32_address(s_stripped):
        s_lower = s_stripped.lower()
        # Read witness version from the data part to distinguish
        # v0 (P2WPKH/P2WSH) from v1 (P2TR).
        try:
            pos = s_lower.rfind("1")
            data_part = s_lower[pos + 1:]
            data = [_BECH32_INDEX[c] for c in data_part]
            witness_version = data[0]
            program_5bit = data[1:-6]
            program_bytes = _convertbits(program_5bit, 5, 8, pad=False)
            if witness_version == 0:
                if program_bytes and len(program_bytes) == 20:
                    return "p2wpkh"
                if program_bytes and len(program_bytes) == 32:
                    return "p2wsh"
            if witness_version == 1:
                return "p2tr"
        except (IndexError, KeyError, BitcoinAddressError):
            return "unknown"
    return "unknown"


__all__ = (
    "BitcoinAddressError",
    "is_base58check_address",
    "is_bech32_address",
    "is_bitcoin_address",
    "normalize_bitcoin_address",
    "classify_bitcoin_address",
)
