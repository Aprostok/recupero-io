"""Move-VM (Sui + Aptos) address codec — the verifiable foundation for #10.

Sui and Aptos addresses are BOTH a 32-byte value, hex-encoded with a ``0x``
prefix, case-insensitive, and WITHOUT a checksum (unlike Ethereum's EIP-55).
Short forms (leading zeros omitted, e.g. ``0x2`` / ``0x1``) are valid input and
canonicalise by LEFT-padding to 64 hex chars. This module normalises + validates
those addresses deterministically — no network, no unverified on-chain constants
— so the addresses that appear in cases can be screened / displayed / de-duped
consistently.

Scope note (forensic): this is intentionally JUST the address layer. The live
transfer-fetching adapters (Sui ``suix_queryTransactionBlocks`` + balanceChanges;
Aptos REST + coin ``Withdraw/DepositEvent`` AND fungible-asset events with their
store-object→owner resolution) require verifying decimals + event shapes against
real RPC responses before they can be trusted in evidence, and are tracked
separately. Address normalisation is the deterministic, fully-verifiable piece
every adapter builds on first.

Sources: docs.sui.io (SuiAddress = 32B hex, 66-char canonical, case-insensitive,
no checksum); aptos.dev (32-byte hex, left-pad to 64, AIP-40 LONG form).
"""

from __future__ import annotations

_HEX_DIGITS = frozenset("0123456789abcdef")
_ADDR_HEX_LEN = 64  # 32 bytes


def _normalize_move_address(addr: str, *, kind: str) -> str:
    """Normalise a Sui/Aptos address to the canonical ``0x`` + 64-hex LONG form.

    Accepts short forms (``0x1``) and mixed/upper case; left-pads to 64 hex.
    Raises ``TypeError`` for non-str, ``ValueError`` for empty / over-long /
    non-hex input (there is NO checksum to verify — only structural validity).
    """
    if not isinstance(addr, str):
        raise TypeError(f"{kind} address must be a string, got {type(addr).__name__}")
    s = addr.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if not s:
        raise ValueError(f"empty {kind} address")
    if len(s) > _ADDR_HEX_LEN:
        raise ValueError(
            f"{kind} address too long: {len(s)} hex chars (max {_ADDR_HEX_LEN})"
        )
    if any(c not in _HEX_DIGITS for c in s):
        raise ValueError(f"{kind} address has non-hex characters: {addr!r}")
    return "0x" + s.rjust(_ADDR_HEX_LEN, "0")


def normalize_sui_address(addr: str) -> str:
    """Canonical Sui address: ``0x`` + 64 lowercase hex (left-padded). Raises on
    invalid input."""
    return _normalize_move_address(addr, kind="Sui")


def normalize_aptos_address(addr: str) -> str:
    """Canonical Aptos address: ``0x`` + 64 lowercase hex (left-padded). Raises on
    invalid input."""
    return _normalize_move_address(addr, kind="Aptos")


def is_valid_sui_address(addr: object) -> bool:
    """True if ``addr`` is a structurally valid Sui address (never raises)."""
    try:
        normalize_sui_address(addr)  # type: ignore[arg-type]
        return True
    except (TypeError, ValueError):
        return False


def is_valid_aptos_address(addr: object) -> bool:
    """True if ``addr`` is a structurally valid Aptos address (never raises)."""
    try:
        normalize_aptos_address(addr)  # type: ignore[arg-type]
        return True
    except (TypeError, ValueError):
        return False


__all__ = (
    "normalize_sui_address",
    "normalize_aptos_address",
    "is_valid_sui_address",
    "is_valid_aptos_address",
)
