"""Roadmap-#1 v3 item #10 (foundation): Move-VM (Sui + Aptos) address codec.

Deterministic, network-free address normalisation/validation — the verifiable
piece the Sui/Aptos adapters build on. Vectors per docs.sui.io / aptos.dev:
32-byte hex, 0x-prefixed, case-insensitive, no checksum, short forms left-pad to
64 hex.
"""

from __future__ import annotations

import pytest

from recupero.chains.move_address import (
    is_valid_aptos_address,
    is_valid_sui_address,
    normalize_aptos_address,
    normalize_sui_address,
)

_PAD = "0x" + "0" * 63


def test_sui_short_form_left_pads_to_64() -> None:
    assert normalize_sui_address("0x2") == _PAD + "2"
    assert normalize_sui_address("0x2") == "0x" + "2".rjust(64, "0")
    assert len(normalize_sui_address("0x2")) == 66


def test_aptos_short_form_left_pads_to_64() -> None:
    assert normalize_aptos_address("0x1") == _PAD + "1"
    assert normalize_aptos_address("0xA") == _PAD + "a"   # case-insensitive


def test_full_address_roundtrips_and_lowercases() -> None:
    full_upper = "0x" + "AB" * 32          # 64 hex chars, uppercase
    norm = normalize_sui_address(full_upper)
    assert norm == "0x" + "ab" * 32
    assert normalize_sui_address(norm) == norm        # idempotent
    assert normalize_aptos_address(norm) == norm


def test_no_0x_prefix_accepted() -> None:
    assert normalize_sui_address("2") == _PAD + "2"
    assert normalize_aptos_address("dead") == "0x" + "0" * 60 + "dead"


def test_invalid_inputs_raise() -> None:
    with pytest.raises(ValueError):
        normalize_sui_address("0x" + "f" * 65)         # too long (>32 bytes)
    with pytest.raises(ValueError):
        normalize_sui_address("0xZZZ")                  # non-hex
    with pytest.raises(ValueError):
        normalize_sui_address("0x")                     # empty
    with pytest.raises(ValueError):
        normalize_aptos_address("   ")                  # blank
    with pytest.raises(TypeError):
        normalize_sui_address(None)                     # not a string


def test_is_valid_never_raises() -> None:
    assert is_valid_sui_address("0x2") is True
    assert is_valid_aptos_address("0x" + "1" * 64) is True
    assert is_valid_sui_address("0x" + "f" * 65) is False
    assert is_valid_sui_address(None) is False
    assert is_valid_aptos_address(12345) is False
    assert is_valid_aptos_address("0xnothex") is False
