"""TON address codec — verified against live raw↔friendly vector pairs
captured from toncenter.com (v2 friendly / v3 raw + address_book)."""

from __future__ import annotations

import pytest

from recupero.chains.ton.address import (
    friendly_to_raw,
    is_ton_address,
    normalize_ton_address,
    raw_to_friendly,
)

# Live vector pairs (toncenter v3 address_book): raw 0:hex ↔ user-friendly.
A_RAW = "0:7b27ada438eeffc7a7eea02e44b966726f4e21322f35fda51dc6a2e0cd6a04d5"
A_EQ = "EQB7J62kOO7_x6fuoC5EuWZyb04hMi81_aUdxqLgzWoE1aKD"   # bounceable
B_RAW = "0:0b6073a6132acb17fed859a58ea651d6050d2fe751a7c76d30bb041302b8b772"
B_UQ = "UQALYHOmEyrLF_7YWaWOplHWBQ0v51Gnx20wuwQTAri3ckRZ"   # non-bounceable
USDT_RAW = "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe"
USDT_EQ = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"


def test_friendly_to_raw_matches_live_vectors() -> None:
    assert friendly_to_raw(A_EQ) == A_RAW
    assert friendly_to_raw(B_UQ) == B_RAW
    assert friendly_to_raw(USDT_EQ) == USDT_RAW


def test_raw_to_friendly_bounceable_and_non_bounceable() -> None:
    assert raw_to_friendly(A_RAW, bounceable=True) == A_EQ
    assert raw_to_friendly(B_RAW, bounceable=False) == B_UQ
    assert raw_to_friendly(USDT_RAW, bounceable=True) == USDT_EQ


def test_normalize_collapses_all_forms_to_canonical_raw() -> None:
    """The same wallet via v3 (raw), v2 bounceable (EQ) and non-bounceable (UQ)
    must all canonicalize to ONE key so the trace matches them."""
    eq = raw_to_friendly(A_RAW, bounceable=True)
    uq = raw_to_friendly(A_RAW, bounceable=False)
    assert normalize_ton_address(A_RAW) == A_RAW
    assert normalize_ton_address(A_RAW.upper().replace("0X", "0")) == A_RAW  # case-insensitive hex
    assert normalize_ton_address(eq) == A_RAW
    assert normalize_ton_address(uq) == A_RAW


def test_masterchain_workchain_roundtrip() -> None:
    raw = "-1:" + "ab" * 32
    friendly = raw_to_friendly(raw)
    assert friendly_to_raw(friendly) == raw


def test_crc16_mismatch_rejected() -> None:
    # Flip one char in a valid friendly address → CRC fails.
    bad = "X" + A_EQ[1:]
    with pytest.raises(ValueError):
        friendly_to_raw(bad)


def test_is_ton_address() -> None:
    assert is_ton_address(A_RAW)
    assert is_ton_address(A_EQ)
    assert is_ton_address(B_UQ)
    assert not is_ton_address("0xabc")
    assert not is_ton_address("not an address")
    assert not is_ton_address("")


def test_normalize_rejects_non_ton() -> None:
    with pytest.raises(ValueError):
        normalize_ton_address("0x1234")
