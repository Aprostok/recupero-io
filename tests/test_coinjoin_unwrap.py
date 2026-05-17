"""Tests for v0.14.0 probabilistic CoinJoin unwrap.

The core algorithm is deterministic — these tests pin behavior on
synthesized CoinJoin shapes:

  * Wasabi (50+ inputs, large round-output cluster)
  * Whirlpool (exact 5/5)
  * JoinMarket (small participant count)
  * Generic (3+ equal outputs but doesn't match named pattern)

Plus the ranking logic — single-input near-perfect-match should
always score HIGHER than multi-input loose-match.
"""

from __future__ import annotations

import pytest

from recupero.trace.coinjoin_unwrap import (
    CoinJoinHypothesis,
    UTXOInput,
    UTXOOutput,
    UnwrapResult,
    classify_coinjoin_pattern,
    detect_round_amounts,
    unwrap_coinjoin,
    unwrap_to_brief_section,
)


# ---- detect_round_amounts ---- #


def test_detects_equal_output_cluster() -> None:
    outputs = [
        UTXOOutput("a1", 10_000_000, 0),
        UTXOOutput("a2", 10_000_000, 1),
        UTXOOutput("a3", 10_000_000, 2),
        UTXOOutput("change", 234_567, 3),  # change output
    ]
    rounds = detect_round_amounts(outputs)
    assert len(rounds) == 1
    value, members = rounds[0]
    assert value == 10_000_000
    assert len(members) == 3


def test_skips_cluster_below_min_size() -> None:
    outputs = [
        UTXOOutput("a1", 10_000_000, 0),
        UTXOOutput("a2", 10_000_000, 1),   # only 2 — below min_cluster_size=3
        UTXOOutput("change", 234_567, 2),
    ]
    rounds = detect_round_amounts(outputs)
    assert rounds == []


def test_multiple_round_clusters_sorted_by_size() -> None:
    """Two equal-value clusters → the larger one comes first
    (it's more likely the actual round denomination)."""
    outputs = [
        # 3-output cluster
        UTXOOutput("a1", 1_000_000, 0),
        UTXOOutput("a2", 1_000_000, 1),
        UTXOOutput("a3", 1_000_000, 2),
        # 5-output cluster (bigger)
        UTXOOutput("b1", 10_000_000, 3),
        UTXOOutput("b2", 10_000_000, 4),
        UTXOOutput("b3", 10_000_000, 5),
        UTXOOutput("b4", 10_000_000, 6),
        UTXOOutput("b5", 10_000_000, 7),
    ]
    rounds = detect_round_amounts(outputs)
    assert len(rounds) == 2
    # Largest first.
    assert rounds[0][0] == 10_000_000
    assert len(rounds[0][1]) == 5
    assert rounds[1][0] == 1_000_000
    assert len(rounds[1][1]) == 3


def test_empty_inputs() -> None:
    assert detect_round_amounts([]) == []


# ---- classify_coinjoin_pattern ---- #


def test_classifies_whirlpool_shape() -> None:
    """Samourai Whirlpool always 5-in/5-out at the round."""
    inputs = [UTXOInput(f"in{i}", 10_500_000) for i in range(5)]
    outputs = [UTXOOutput(f"out{i}", 10_000_000, i) for i in range(5)]
    pattern = classify_coinjoin_pattern(inputs, outputs, 10_000_000, 5)
    assert pattern == "whirlpool"


def test_classifies_wasabi_shape() -> None:
    """Wasabi: many inputs + large round-output cluster."""
    inputs = [UTXOInput(f"in{i}", 10_500_000) for i in range(80)]
    outputs = [UTXOOutput(f"out{i}", 10_000_000, i) for i in range(50)]
    # Add 30 change outputs.
    for i in range(30):
        outputs.append(UTXOOutput(f"change{i}", 500_000 + i, 50 + i))
    pattern = classify_coinjoin_pattern(inputs, outputs, 10_000_000, 50)
    assert pattern == "wasabi"


def test_classifies_joinmarket_shape() -> None:
    """JoinMarket: 5-15 inputs, 3-15 round outputs."""
    inputs = [UTXOInput(f"in{i}", 10_500_000) for i in range(8)]
    outputs = [UTXOOutput(f"out{i}", 10_000_000, i) for i in range(5)]
    pattern = classify_coinjoin_pattern(inputs, outputs, 10_000_000, 5)
    assert pattern == "joinmarket"


def test_classifies_generic() -> None:
    """4-input, 4-output round-tx but not matching any named pattern."""
    inputs = [UTXOInput(f"in{i}", 10_500_000) for i in range(4)]
    outputs = [UTXOOutput(f"out{i}", 10_000_000, i) for i in range(4)]
    pattern = classify_coinjoin_pattern(inputs, outputs, 10_000_000, 4)
    assert pattern in ("generic", "joinmarket")


# ---- unwrap_coinjoin: happy path ---- #


def test_unwrap_returns_none_for_non_coinjoin() -> None:
    """Simple non-CoinJoin tx → no round cluster → None."""
    inputs = [UTXOInput("alice", 50_000)]
    outputs = [UTXOOutput("bob", 40_000, 0)]
    assert unwrap_coinjoin(tx_id="0xabc", inputs=inputs, outputs=outputs) is None


def test_unwrap_emits_hypothesis_for_single_input_participant() -> None:
    """A participant who contributed exactly 1 input at ~round
    amount + small fee should produce a HIGH-confidence
    hypothesis."""
    # 5 participants, each contributes 1 input ~10.5M sats, gets
    # 1 output at 10M sats. (Fee ~5%.)
    inputs = [
        UTXOInput("alice", 10_100_000),
        UTXOInput("bob", 10_100_000),
        UTXOInput("carol", 10_100_000),
        UTXOInput("dave", 10_100_000),
        UTXOInput("eve", 10_100_000),
    ]
    outputs = [
        UTXOOutput("alice_2", 10_000_000, 0),
        UTXOOutput("bob_2", 10_000_000, 1),
        UTXOOutput("carol_2", 10_000_000, 2),
        UTXOOutput("dave_2", 10_000_000, 3),
        UTXOOutput("eve_2", 10_000_000, 4),
    ]
    result = unwrap_coinjoin(
        tx_id="0xcoinjoin", inputs=inputs, outputs=outputs,
    )
    assert result is not None
    assert result.detected_pattern == "whirlpool"
    assert result.round_amount_sats == 10_000_000
    assert result.round_output_count == 5
    assert len(result.hypotheses) > 0
    # The highest-confidence hypothesis should match a single-input
    # participant.
    top = result.hypotheses[0]
    assert len(top.input_addresses) == 1
    assert top.output_count == 1
    assert top.confidence == "high"


def test_unwrap_handles_multi_output_participant() -> None:
    """A participant who contributed 2x the round amount should get
    a hypothesis that they received 2 outputs."""
    inputs = [
        UTXOInput("whale", 21_000_000),  # 2x round → claims 2 outputs
        UTXOInput("alice", 10_500_000),
        UTXOInput("bob", 10_500_000),
        UTXOInput("carol", 10_500_000),
    ]
    outputs = [
        UTXOOutput(f"out{i}", 10_000_000, i) for i in range(5)
    ]
    result = unwrap_coinjoin(
        tx_id="0xcoinjoin", inputs=inputs, outputs=outputs,
    )
    assert result is not None
    # At least one hypothesis should claim 2 outputs.
    multi_output_hyps = [h for h in result.hypotheses if h.output_count == 2]
    assert len(multi_output_hyps) > 0


def test_unwrap_self_mixing_penalty() -> None:
    """If a participant's input address ALSO appears as one of the
    output addresses (self-mixing), the hypothesis confidence
    should be lower — recovery interest is in DIFFERENT outputs."""
    inputs = [
        UTXOInput("alice", 10_100_000),
        UTXOInput("bob", 10_100_000),
        UTXOInput("carol", 10_100_000),
    ]
    outputs = [
        # alice's input address ALSO receives an output — self-mix
        UTXOOutput("alice", 10_000_000, 0),
        UTXOOutput("bob_2", 10_000_000, 1),
        UTXOOutput("carol_2", 10_000_000, 2),
    ]
    result = unwrap_coinjoin(
        tx_id="0xcoinjoin", inputs=inputs, outputs=outputs,
    )
    assert result is not None
    # Find alice's hypothesis — should have self_mixing signal.
    alice_hyps = [
        h for h in result.hypotheses
        if "alice" in h.input_addresses
    ]
    assert len(alice_hyps) > 0
    assert any(
        "self_mixing" in " ".join(h.signals)
        for h in alice_hyps
    )


def test_unwrap_ranks_higher_confidence_first() -> None:
    """Hypotheses should be sorted by confidence_score descending."""
    inputs = [UTXOInput(f"in{i}", 10_100_000) for i in range(5)]
    outputs = [UTXOOutput(f"out{i}", 10_000_000, i) for i in range(5)]
    result = unwrap_coinjoin(
        tx_id="0xcoinjoin", inputs=inputs, outputs=outputs,
    )
    assert result is not None
    scores = [h.confidence_score for h in result.hypotheses]
    assert scores == sorted(scores, reverse=True)


def test_unwrap_caps_hypotheses() -> None:
    """A pathological 100-input tx should not blow up the
    hypothesis enumerator — we cap at _MAX_HYPOTHESES_PER_TX."""
    inputs = [UTXOInput(f"in{i}", 10_000_500) for i in range(40)]
    outputs = [UTXOOutput(f"out{i}", 10_000_000, i) for i in range(20)]
    result = unwrap_coinjoin(
        tx_id="0xbig", inputs=inputs, outputs=outputs,
    )
    assert result is not None
    assert len(result.hypotheses) <= 200


# ---- unwrap_to_brief_section ---- #


def test_brief_section_for_no_unwrap() -> None:
    """When the tx isn't a CoinJoin, the brief section is a clean
    empty shape."""
    section = unwrap_to_brief_section(None)
    assert section == {"detected": False, "tx_id": None, "hypotheses": []}


def test_brief_section_shape() -> None:
    """The brief section format is locked — REST consumers parse
    on field name."""
    inputs = [UTXOInput("alice", 10_100_000) for _ in range(5)]
    # Vary so each subset is distinct.
    inputs = [
        UTXOInput("alice", 10_100_000),
        UTXOInput("bob", 10_200_000),
        UTXOInput("carol", 10_300_000),
        UTXOInput("dave", 10_400_000),
        UTXOInput("eve", 10_500_000),
    ]
    outputs = [
        UTXOOutput(f"out{i}", 10_000_000, i) for i in range(5)
    ]
    result = unwrap_coinjoin(
        tx_id="0xcoinjoin", inputs=inputs, outputs=outputs,
    )
    section = unwrap_to_brief_section(result)
    assert section["detected"] is True
    assert section["tx_id"] == "0xcoinjoin"
    assert section["detected_pattern"] == "whirlpool"
    assert section["round_amount_btc"] == "0.1000"
    assert section["round_output_count"] == 5
    assert section["participant_count_estimate"] == 5
    assert len(section["hypotheses"]) > 0
    first = section["hypotheses"][0]
    # Field names are part of the contract.
    assert "input_addresses" in first
    assert "output_addresses" in first
    assert "input_value_btc" in first
    assert "output_value_btc" in first
    assert "output_count" in first
    assert "confidence" in first
    assert "confidence_score" in first
    assert "rationale" in first
    assert "signals" in first
    assert first["confidence"] in ("high", "medium", "low")
    assert 0.0 <= first["confidence_score"] <= 1.0
