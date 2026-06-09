"""Coverage-gap tests flagged by the v0.39 background audit sweep.

Each test locks the CURRENT behavior of a function that previously had no
direct unit coverage:
  * ``mev_detection._safe_int``      — bool/NaN/Inf/Decimal/garbage coercion;
  * ``mev_detection._detect_jit_lp`` — JIT-LP shape detection + sandwich reject;
  * ``erc4337`` array readers        — the ``_MAX_BATCH_CALLS`` DoS cap;
  * ``cosmos.adapter._resolve_max_pages`` — page-budget translation + clamps;
  * ``demix_runner.withdrawals_from_logs`` — zero-recipient / malformed skip.

These are behavior-locking tests (no production change), so a future
regression in any of these paths fails loudly instead of silently.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------------------
# mev_detection._safe_int — bool is NOT an int here (the subtle case)
# ---------------------------------------------------------------------------
def test_safe_int_rejects_bool() -> None:
    from recupero.trace.mev_detection import _safe_int

    # bool is a subclass of int in Python; _safe_int must reject it so a
    # stray True/False in tx metadata never becomes gas_price 1/0.
    assert _safe_int(True) is None
    assert _safe_int(False) is None


def test_safe_int_accepts_finite_numbers() -> None:
    from recupero.trace.mev_detection import _safe_int

    assert _safe_int(42) == 42
    assert _safe_int(-7) == -7
    assert _safe_int(3.0) == 3
    assert _safe_int(Decimal("100")) == 100
    # hex/decimal strings are still int-able via int()? No — non-numeric types
    # are rejected before the int() call.
    assert _safe_int("0x10") is None
    assert _safe_int("123") is None


def test_safe_int_rejects_nan_inf_none_garbage() -> None:
    from recupero.trace.mev_detection import _safe_int

    assert _safe_int(None) is None
    assert _safe_int(float("nan")) is None
    assert _safe_int(float("inf")) is None
    assert _safe_int(float("-inf")) is None
    assert _safe_int(Decimal("NaN")) is None
    assert _safe_int(object()) is None
    assert _safe_int([1, 2]) is None


# ---------------------------------------------------------------------------
# mev_detection._detect_jit_lp
# ---------------------------------------------------------------------------
_SEED = "0x" + "11" * 20
_POOL = "0x" + "cc" * 20
_A = "0x" + "aa" * 20
_B = "0x" + "bb" * 20


def _xfer(**kw):
    base = {
        "block_number": 100,
        "log_index": 0,
        "from_address": "",
        "to_address": "",
        "tx_hash": "0x" + "00" * 32,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_detect_jit_lp_positive() -> None:
    from recupero.trace.mev_detection import _detect_jit_lp

    # a (from A → POOL), b (victim, from SEED), c (from B → POOL):
    # distinct outer addresses target the same pool around the victim swap.
    txs = [
        _xfer(log_index=0, from_address=_A, to_address=_POOL, tx_hash="0xa"),
        _xfer(log_index=1, from_address=_SEED, to_address=_B, tx_hash="0xb"),
        _xfer(log_index=2, from_address=_B, to_address=_POOL, tx_hash="0xc"),
    ]
    out = _detect_jit_lp(txs, _SEED)
    assert len(out) == 1
    sig = out[0]
    assert sig.signal_type == "jit_lp"
    assert sig.confidence == 0.4
    assert sig.address == _POOL.lower()
    assert sig.tx_hash == "0xb"  # tagged on the victim (middle) tx


def test_detect_jit_lp_rejects_sandwich_shape() -> None:
    from recupero.trace.mev_detection import _detect_jit_lp

    # Outer pair shares the SAME from_address (A==A) → that's a sandwich,
    # not JIT-LP — must NOT be reported by the JIT detector.
    txs = [
        _xfer(log_index=0, from_address=_A, to_address=_POOL, tx_hash="0xa"),
        _xfer(log_index=1, from_address=_SEED, to_address=_B, tx_hash="0xb"),
        _xfer(log_index=2, from_address=_A, to_address=_POOL, tx_hash="0xc"),
    ]
    assert _detect_jit_lp(txs, _SEED) == []


def test_detect_jit_lp_needs_three_txs_and_seed() -> None:
    from recupero.trace.mev_detection import _detect_jit_lp

    txs = [
        _xfer(log_index=0, from_address=_A, to_address=_POOL, tx_hash="0xa"),
        _xfer(log_index=1, from_address=_SEED, to_address=_B, tx_hash="0xb"),
    ]
    assert _detect_jit_lp(txs, _SEED) == []  # only 2 in the block
    # empty seed short-circuits
    three = [
        _xfer(log_index=0, from_address=_A, to_address=_POOL, tx_hash="0xa"),
        _xfer(log_index=1, from_address=_SEED, to_address=_B, tx_hash="0xb"),
        _xfer(log_index=2, from_address=_B, to_address=_POOL, tx_hash="0xc"),
    ]
    assert _detect_jit_lp(three, "") == []


# ---------------------------------------------------------------------------
# erc4337 array readers — the _MAX_BATCH_CALLS DoS cap
# ---------------------------------------------------------------------------
def test_erc4337_uint_array_over_cap_raises() -> None:
    from recupero.trace.erc4337 import _MAX_BATCH_CALLS, _read_uint_array

    # A length word claiming > cap elements must raise rather than attempt a
    # multi-GB allocation from attacker-controlled calldata.
    data = (_MAX_BATCH_CALLS + 1).to_bytes(32, "big")
    with pytest.raises(ValueError, match="exceeds cap"):
        _read_uint_array(data, 0)


def test_erc4337_uint_array_valid_decode() -> None:
    from recupero.trace.erc4337 import _read_uint_array

    data = (2).to_bytes(32, "big") + (10).to_bytes(32, "big") + (20).to_bytes(32, "big")
    assert _read_uint_array(data, 0) == [10, 20]


def test_erc4337_address_array_over_cap_raises() -> None:
    from recupero.trace.erc4337 import _MAX_BATCH_CALLS, _read_address_array

    data = (_MAX_BATCH_CALLS + 99).to_bytes(32, "big")
    with pytest.raises(ValueError, match="exceeds cap"):
        _read_address_array(data, 0)


def test_erc4337_address_array_valid_decode() -> None:
    from recupero.trace.erc4337 import _read_address_array

    addr = b"\xaa" * 20
    slot = b"\x00" * 12 + addr  # left-padded into a 32-byte word
    data = (1).to_bytes(32, "big") + slot
    assert _read_address_array(data, 0) == ["0x" + "aa" * 20]


def test_erc4337_bytes_array_over_cap_raises() -> None:
    from recupero.trace.erc4337 import _MAX_BATCH_CALLS, _read_bytes_array

    data = (_MAX_BATCH_CALLS + 1).to_bytes(32, "big")
    with pytest.raises(ValueError, match="exceeds cap"):
        _read_bytes_array(data, 0)


# ---------------------------------------------------------------------------
# cosmos.adapter._resolve_max_pages — page-budget translation + clamps
# ---------------------------------------------------------------------------
def test_cosmos_resolve_max_pages_default_and_disabled() -> None:
    from recupero.chains.cosmos.adapter import (
        _DEFAULT_MAX_TRANSFERS_PER_ADDRESS,
        _HARD_PAGE_CEILING,
        _LCD_PAGE_SIZE,
        _resolve_max_pages,
    )

    # None → derive from the default transfer budget (ceil division).
    expected_default = -(-_DEFAULT_MAX_TRANSFERS_PER_ADDRESS // _LCD_PAGE_SIZE)
    assert _resolve_max_pages(None) == min(_HARD_PAGE_CEILING, expected_default)
    # 0 / negative == "unbounded" → hard ceiling.
    assert _resolve_max_pages(0) == _HARD_PAGE_CEILING
    assert _resolve_max_pages(-100) == _HARD_PAGE_CEILING


def test_cosmos_resolve_max_pages_ceil_and_clamp() -> None:
    from recupero.chains.cosmos.adapter import _HARD_PAGE_CEILING, _resolve_max_pages

    assert _resolve_max_pages(100) == 1   # exactly one page
    assert _resolve_max_pages(150) == 2   # ceil(150/100)
    assert _resolve_max_pages(250) == 3   # ceil(250/100)
    assert _resolve_max_pages(1) == 1     # min clamp
    # An enormous budget clamps to the hard ceiling.
    assert _resolve_max_pages(10_000_000) == _HARD_PAGE_CEILING


# ---------------------------------------------------------------------------
# demix_runner.withdrawals_from_logs — zero-recipient / malformed skip
# ---------------------------------------------------------------------------
def test_demix_withdrawals_skips_zero_recipient() -> None:
    from recupero.trace.demix_runner import withdrawals_from_logs

    # data word 0 = all zeros → recipient 0x000…0 → must be skipped, never
    # emitted as a (fabricated) lead.
    logs = [{"data": "0x" + "00" * 32, "topics": [], "transactionHash": "0xz"}]
    assert withdrawals_from_logs(logs, pool_name="tornado-100eth") == []


def test_demix_withdrawals_emits_real_recipient() -> None:
    from recupero.trace.demix_runner import withdrawals_from_logs

    recipient_word = "00" * 12 + "aa" * 20  # left-padded 20-byte address
    relayer_topic = "0x" + "00" * 12 + "bb" * 20
    logs = [{
        "data": "0x" + recipient_word,
        "topics": ["0x" + "ee" * 32, relayer_topic],
        "transactionHash": "0xdead",
        "timeStamp": "0x0",
    }]
    out = withdrawals_from_logs(logs, pool_name="tornado-100eth")
    assert len(out) == 1
    ev = out[0]
    assert ev.address == "0x" + "aa" * 20
    assert ev.pool == "tornado-100eth"
    assert ev.relayer == "0x" + "bb" * 20


def test_demix_withdrawals_skips_malformed() -> None:
    from recupero.trace.demix_runner import withdrawals_from_logs

    # non-dict, short data, missing data → all skipped, never raise.
    logs = ["not a dict", {"data": "0x1234"}, {"topics": []}, {}]
    assert withdrawals_from_logs(logs, pool_name="p") == []
    assert withdrawals_from_logs([], pool_name="p") == []
    assert withdrawals_from_logs(None, pool_name="p") == []
