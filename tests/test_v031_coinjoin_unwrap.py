"""Tests for v0.31.0 extended CoinJoin protocol detection.

v0.31.0 adds shape-only detection for three additional protocols
on top of the v0.14.0 round-amount enumerator:

  * Wasabi 1.0 (regression — must still be recognized)
  * Wasabi 2.0 / WabiSabi (10+ in / 10+ out, no dominant amount)
  * Samourai Whirlpool (strict 5x5 at a published pool denom)
  * Mercury Layer — DEFERRED, not testable on-chain (see docs)

These tests pin the new `detect_coinjoin()` entry point, which
returns a `CoinjoinDetection` (NOT the v0.14.0 `UnwrapResult`).
The detection's `most_likely_output` is always None — post-mix
output recovery is infeasible without off-chain coordinator data,
and these tests assert we do not pretend otherwise.

The math is pure: same inputs => same detection, no NaN
propagation, no floating-point drift across the dominant-output
fraction calculation.
"""

from __future__ import annotations

import math

from recupero.trace.coinjoin_unwrap import (
    PROTOCOL_WASABI_1,
    PROTOCOL_WASABI_2,
    PROTOCOL_WHIRLPOOL,
    CoinjoinDetection,
    UTXOInput,
    UTXOOutput,
    _dominant_output_fraction,
    _is_strict_whirlpool,
    _is_wasabi1_fixed_denom,
    _is_wasabi2_wabisabi,
    _is_whirlpool_pool_denomination,
    detect_coinjoin,
    detection_to_brief_section,
)

# ---- Wasabi 1.0 (regression — must still be recognized) ---- #


def test_detect_wasabi1_fixed_denomination() -> None:
    """Wasabi 1.0 shape: many inputs, 10+ equal-value outputs.

    This is the historic 0.1 BTC denomination pattern. Must still
    be recognized after v0.31.0 changes.
    """
    inputs = [UTXOInput(f"in{i}", 10_500_000) for i in range(20)]
    outputs = [UTXOOutput(f"out{i}", 10_000_000, i) for i in range(15)]
    # A handful of change outputs at varied amounts.
    for i in range(5):
        outputs.append(
            UTXOOutput(f"change{i}", 100_000 + i * 1_000, 15 + i),
        )
    detection = detect_coinjoin(
        tx_hash="0xwasabi1",
        input_address="in0",
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is not None
    assert detection.protocol == PROTOCOL_WASABI_1
    assert detection.input_address == "in0"
    assert detection.tx_hash == "0xwasabi1"
    assert detection.most_likely_output is None  # contract
    assert 0.0 <= detection.confidence <= 1.0
    assert "Wasabi 1.0" in detection.forensic_note


# ---- Wasabi 2.0 / WabiSabi ---- #


def test_detect_wasabi2_wabisabi_non_uniform_outputs() -> None:
    """10-in / 10-out with arbitrary denominations (no equal-output
    cluster, no dominant single amount) → Wasabi 2.0."""
    # All inputs distinct, roughly comparable size — avoids any
    # accidental dominant-output trigger.
    inputs = [UTXOInput(f"in{i}", 5_000_000 + i * 100_000) for i in range(12)]
    # Outputs at varied amounts, none dominant.
    # 12 outputs whose values are spread roughly evenly across the
    # 1M..5M sat range so no single output exceeds 20% of total.
    outputs = [
        UTXOOutput(f"out{i}", 2_000_000 + i * 137_000, i) for i in range(12)
    ]
    detection = detect_coinjoin(
        tx_hash="0xwabisabi",
        input_address="in0",
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is not None
    assert detection.protocol == PROTOCOL_WASABI_2
    assert detection.input_address == "in0"
    assert detection.tx_hash == "0xwabisabi"
    assert detection.most_likely_output is None
    # WabiSabi confidence is intentionally lower than the
    # fixed-denomination protocols.
    assert detection.confidence < 0.90
    assert "WabiSabi" in detection.forensic_note or "Wasabi 2.0" in detection.forensic_note


def test_wasabi2_rejected_when_one_output_dominates() -> None:
    """Many-in / many-out but one output carries >20% of total
    value → looks like a payout or sweep, NOT a WabiSabi mix."""
    inputs = [UTXOInput(f"in{i}", 5_000_000) for i in range(15)]
    # One huge output dwarfs the rest — definitely not a mix.
    outputs = [UTXOOutput("big", 60_000_000, 0)]
    for i in range(11):
        outputs.append(UTXOOutput(f"small{i}", 100_000 + i, i + 1))
    detection = detect_coinjoin(
        tx_hash="0xpayout",
        input_address="in0",
        inputs=inputs,
        outputs=outputs,
    )
    # Should NOT be classified as a coinjoin.
    assert detection is None


def test_wasabi2_rejected_below_input_threshold() -> None:
    """9 inputs is below the Wasabi 2.0 floor of 10."""
    inputs = [UTXOInput(f"in{i}", 5_000_000) for i in range(9)]
    outputs = [UTXOOutput(f"out{i}", 500_000 + i * 7_000, i) for i in range(12)]
    detection = detect_coinjoin(
        tx_hash="0xnope",
        input_address="in0",
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is None


# ---- Samourai Whirlpool (strict 5x5 at pool denom) ---- #


def test_detect_whirlpool_at_pool_001_btc() -> None:
    """5-in / 5-out all at 0.001 BTC (100,000 sats) → Whirlpool."""
    inputs = [UTXOInput(f"in{i}", 110_000) for i in range(5)]
    outputs = [UTXOOutput(f"out{i}", 100_000, i) for i in range(5)]
    detection = detect_coinjoin(
        tx_hash="0xwhirlpool",
        input_address="in0",
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is not None
    assert detection.protocol == PROTOCOL_WHIRLPOOL
    assert detection.most_likely_output is None
    assert detection.confidence >= 0.90


def test_detect_whirlpool_at_pool_05_btc() -> None:
    """5-in / 5-out at 0.5 BTC (50,000,000 sats) — top pool."""
    inputs = [UTXOInput(f"in{i}", 51_000_000) for i in range(5)]
    outputs = [UTXOOutput(f"out{i}", 50_000_000, i) for i in range(5)]
    detection = detect_coinjoin(
        tx_hash="0xwhirlpool_big",
        input_address="in0",
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is not None
    assert detection.protocol == PROTOCOL_WHIRLPOOL


def test_whirlpool_rejected_at_non_pool_denomination() -> None:
    """5-in / 5-out all at 0.1 BTC — NOT a Whirlpool pool, so the
    strict detector should reject it. The loose v0.14.0 classifier
    would have called this 'whirlpool', but v0.31.0 detection is
    pool-denomination-aware."""
    inputs = [UTXOInput(f"in{i}", 10_500_000) for i in range(5)]
    outputs = [UTXOOutput(f"out{i}", 10_000_000, i) for i in range(5)]
    matched, denom = _is_strict_whirlpool(inputs, outputs)
    assert matched is False
    assert denom is None
    # Top-level detect_coinjoin: should NOT return Whirlpool. It
    # might return None (no other protocol matches the 5/5 shape).
    detection = detect_coinjoin(
        tx_hash="0xnotwhirlpool",
        input_address="in0",
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is None or detection.protocol != PROTOCOL_WHIRLPOOL


def test_whirlpool_pool_denomination_set() -> None:
    """The four published Whirlpool pools must be recognized."""
    assert _is_whirlpool_pool_denomination(100_000)      # 0.001 BTC
    assert _is_whirlpool_pool_denomination(1_000_000)    # 0.01  BTC
    assert _is_whirlpool_pool_denomination(5_000_000)    # 0.05  BTC
    assert _is_whirlpool_pool_denomination(50_000_000)   # 0.5   BTC
    # Anything else is NOT a pool denomination.
    assert not _is_whirlpool_pool_denomination(10_000_000)  # 0.1 BTC
    assert not _is_whirlpool_pool_denomination(0)
    # The detector intentionally allows a 1-sat tolerance around each
    # pool denomination (see _WHIRLPOOL_DENOM_TOLERANCE_SATS) to absorb
    # rounding noise from upstream parsers. Use a value clearly outside
    # the cushion so the assertion is meaningful.
    assert not _is_whirlpool_pool_denomination(999_990)


# ---- Non-coinjoin shapes ---- #


def test_simple_2in_3out_is_not_coinjoin() -> None:
    """Plain 2-in / 3-out transfer (sender + change + recipient
    splits) should not trip any detector."""
    inputs = [
        UTXOInput("alice", 50_000_000),
        UTXOInput("alice_2", 10_000_000),
    ]
    outputs = [
        UTXOOutput("bob", 30_000_000, 0),
        UTXOOutput("carol", 20_000_000, 1),
        UTXOOutput("alice_change", 9_900_000, 2),
    ]
    assert detect_coinjoin(
        tx_hash="0xnormal",
        input_address="alice",
        inputs=inputs,
        outputs=outputs,
    ) is None


def test_single_input_single_output_is_not_coinjoin() -> None:
    inputs = [UTXOInput("alice", 1_000_000)]
    outputs = [UTXOOutput("bob", 950_000, 0)]
    assert detect_coinjoin(
        tx_hash="0xnormal",
        input_address="alice",
        inputs=inputs,
        outputs=outputs,
    ) is None


def test_empty_inputs_or_outputs() -> None:
    """Defensive: no crash on empty input/output lists."""
    assert detect_coinjoin(
        tx_hash="0xempty",
        input_address="alice",
        inputs=[],
        outputs=[UTXOOutput("bob", 1, 0)],
    ) is None
    assert detect_coinjoin(
        tx_hash="0xempty",
        input_address="alice",
        inputs=[UTXOInput("alice", 1)],
        outputs=[],
    ) is None


# ---- Pure-function math sanity ---- #


def test_dominant_output_fraction_uniform() -> None:
    """Outputs all of equal amount: dominant fraction = 1.0
    (the single amount-bucket holds all value)."""
    outputs = [UTXOOutput(f"o{i}", 1_000_000, i) for i in range(10)]
    frac = _dominant_output_fraction(outputs)
    assert frac == 1.0


def test_dominant_output_fraction_spread() -> None:
    """Outputs spread across distinct amounts: each amount-bucket
    holds exactly that amount's value, so the largest bucket equals
    the largest single output / total."""
    outputs = [
        UTXOOutput("o0", 100, 0),
        UTXOOutput("o1", 200, 1),
        UTXOOutput("o2", 700, 2),  # this is the largest single amount
    ]
    frac = _dominant_output_fraction(outputs)
    assert frac == 0.7


def test_dominant_output_fraction_no_nan() -> None:
    """Empty outputs and zero-total cases must NOT produce NaN."""
    assert _dominant_output_fraction([]) == 0.0
    assert not math.isnan(_dominant_output_fraction([]))
    # All-zero outputs.
    zeros = [UTXOOutput(f"z{i}", 0, i) for i in range(5)]
    val = _dominant_output_fraction(zeros)
    assert val == 0.0
    assert not math.isnan(val)


def test_detect_coinjoin_is_pure() -> None:
    """Same inputs → same detection. No hidden state."""
    inputs = [UTXOInput(f"in{i}", 110_000) for i in range(5)]
    outputs = [UTXOOutput(f"out{i}", 100_000, i) for i in range(5)]
    d1 = detect_coinjoin(
        tx_hash="0xtx", input_address="in0",
        inputs=inputs, outputs=outputs,
    )
    d2 = detect_coinjoin(
        tx_hash="0xtx", input_address="in0",
        inputs=inputs, outputs=outputs,
    )
    assert d1 == d2


# ---- Sub-detector unit tests (defensive) ---- #


def test_is_wasabi1_returns_metadata_on_match() -> None:
    inputs = [UTXOInput(f"in{i}", 10_500_000) for i in range(12)]
    outputs = [UTXOOutput(f"o{i}", 10_000_000, i) for i in range(11)]
    matched, amt, cnt = _is_wasabi1_fixed_denom(inputs, outputs)
    assert matched is True
    assert amt == 10_000_000
    assert cnt == 11


def test_is_wasabi1_misses_below_threshold() -> None:
    """9 inputs, 9 equal outputs — below the 10/10 floor."""
    inputs = [UTXOInput(f"in{i}", 10_500_000) for i in range(9)]
    outputs = [UTXOOutput(f"o{i}", 10_000_000, i) for i in range(9)]
    matched, amt, cnt = _is_wasabi1_fixed_denom(inputs, outputs)
    assert matched is False
    assert amt is None
    assert cnt is None


def test_is_wasabi2_excludes_wasabi1() -> None:
    """If the tx ALSO matches Wasabi 1.0, _is_wasabi2_wabisabi must
    decline so we don't get ambiguous double-classification."""
    inputs = [UTXOInput(f"in{i}", 10_500_000) for i in range(12)]
    outputs = [UTXOOutput(f"o{i}", 10_000_000, i) for i in range(11)]
    # This is a Wasabi 1.0 shape — _is_wasabi2_wabisabi must say no.
    assert _is_wasabi2_wabisabi(inputs, outputs) is False


# ---- Brief serialization ---- #


def test_detection_to_brief_section_none() -> None:
    section = detection_to_brief_section(None)
    assert section == {
        "detected": False,
        "protocol": None,
        "tx_hash": None,
    }


def test_detection_to_brief_section_shape() -> None:
    """The brief section format is locked — REST/PDF consumers
    parse on field name."""
    detection = CoinjoinDetection(
        protocol=PROTOCOL_WASABI_2,
        input_address="bc1q_victim",
        tx_hash="0xabc",
        all_outputs=(
            UTXOOutput("bc1q_out1", 1_000_000, 0),
            UTXOOutput("bc1q_out2", 2_000_000, 1),
        ),
        confidence=0.75,
        forensic_note="WabiSabi mix — see runbook.",
        most_likely_output=None,
    )
    section = detection_to_brief_section(detection)
    assert section["detected"] is True
    assert section["protocol"] == PROTOCOL_WASABI_2
    assert section["tx_hash"] == "0xabc"
    assert section["input_address"] == "bc1q_victim"
    assert section["all_output_addresses"] == ["bc1q_out1", "bc1q_out2"]
    assert section["output_count"] == 2
    assert section["confidence"] == 0.75
    assert section["most_likely_output"] is None
    assert "WabiSabi" in section["forensic_note"]
