"""Tests for v0.31.5 Mercury Layer (statechain) heuristic detection.

Mercury Layer is a Bitcoin statechain run by CommerceBlock. State
transitions happen OFF-CHAIN — the on-chain footprint is just a
``state_init`` / ``state_withdraw`` tx, both 1-input/1-output P2TR
with a small fee to the Statechain Entity (SE) operator.

We cannot fully UNWRAP Mercury (the SE's transition graph is
private), but we CAN detect the on-chain SHAPE with enough
specificity to flag the hop for the investigator and tell them to
query the SE operator directly. This is the same posture TRM Labs
documents for statechain detection: "shape-match alert, off-chain
follow-up."

These tests pin:

  * The happy path: 1-in/1-out P2TR with a 100-2000 sat fee fires
    with confidence 0.55.
  * Known-SE-address bonus: input.address ∈ _MERCURY_KNOWN_SE_INPUTS
    raises confidence to 0.85.
  * All the shape rejections: non-P2TR input, non-P2TR output,
    fee out of range, multiple inputs, multiple outputs.
  * Backward compat: pre-v0.31.5 callers that don't pass
    ``script_hex`` still get the Wasabi 1.0 / Wasabi 2.0 / Whirlpool
    detectors firing normally — the Mercury detector silently
    declines when ``script_hex`` is absent.
"""

from __future__ import annotations

import recupero.trace.coinjoin_unwrap as coinjoin_unwrap
from recupero.trace.coinjoin_unwrap import (
    PROTOCOL_MERCURY_LAYER,
    PROTOCOL_WASABI_1,
    PROTOCOL_WASABI_2,
    PROTOCOL_WHIRLPOOL,
    UTXOInput,
    UTXOOutput,
    _is_mercury_layer,
    _is_p2tr_script,
    detect_coinjoin,
)


# A valid-looking P2TR script: "5120" (OP_1 + push 32) + 64 hex chars
# = 32-byte x-only pubkey. The exact pubkey doesn't matter for shape
# detection; we just need the right length and prefix.
_VALID_P2TR_1 = "5120" + "a1" * 32
_VALID_P2TR_2 = "5120" + "b2" * 32

# A P2WPKH script (witness v0 + 20-byte program) — same family but
# NOT P2TR. Used to confirm the detector requires Taproot specifically.
_P2WPKH_SCRIPT = "0014" + "c3" * 20

# A P2PKH script: OP_DUP OP_HASH160 + push 20 + OP_EQUALVERIFY OP_CHECKSIG.
_P2PKH_SCRIPT = "76a914" + "d4" * 20 + "88ac"


# ---- _is_p2tr_script unit tests ---- #


def test_is_p2tr_script_valid() -> None:
    assert _is_p2tr_script(_VALID_P2TR_1) is True
    assert _is_p2tr_script(_VALID_P2TR_2) is True


def test_is_p2tr_script_uppercase_tolerated() -> None:
    """Some upstream parsers emit uppercase hex; the detector must
    not be case-sensitive."""
    assert _is_p2tr_script(_VALID_P2TR_1.upper()) is True


def test_is_p2tr_script_rejects_other_witness_versions() -> None:
    """P2WPKH (witness v0) must not be classified as P2TR."""
    assert _is_p2tr_script(_P2WPKH_SCRIPT) is False
    assert _is_p2tr_script(_P2PKH_SCRIPT) is False


def test_is_p2tr_script_wrong_length() -> None:
    # Correct prefix but only 31 bytes pushed (should be 32).
    too_short = "5120" + "ee" * 31
    too_long = "5120" + "ff" * 33
    assert _is_p2tr_script(too_short) is False
    assert _is_p2tr_script(too_long) is False


def test_is_p2tr_script_none_or_empty() -> None:
    """Callers that lack scriptPubKey data simply opt out — no
    exception, just a clean False."""
    assert _is_p2tr_script(None) is False
    assert _is_p2tr_script("") is False
    assert _is_p2tr_script("   ") is False


# ---- _is_mercury_layer happy path ---- #


def test_mercury_happy_path_1000_sat_fee() -> None:
    """1-in / 1-out, both P2TR, output = input - 1000 sats → match."""
    inputs = [
        UTXOInput("bc1p_alice", 5_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1p_bob", 4_999_000, 0, script_hex=_VALID_P2TR_2),
    ]
    matched, fee, known = _is_mercury_layer(inputs, outputs)
    assert matched is True
    assert fee == 1000
    assert known is False


def test_detect_coinjoin_mercury_shape_only() -> None:
    """End-to-end through detect_coinjoin(): shape match without
    known-SE confirmation → confidence=0.55."""
    inputs = [
        UTXOInput("bc1p_alice", 5_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1p_bob", 4_999_000, 0, script_hex=_VALID_P2TR_2),
    ]
    detection = detect_coinjoin(
        tx_hash="0xmercury_shape",
        input_address="bc1p_alice",
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is not None
    assert detection.protocol == PROTOCOL_MERCURY_LAYER
    assert detection.confidence == 0.55
    assert detection.most_likely_output is None
    assert "Mercury Layer" in detection.forensic_note
    assert "medium confidence" in detection.forensic_note
    assert "SE operator" in detection.forensic_note


def test_detect_coinjoin_mercury_with_known_se(monkeypatch) -> None:
    """When the input is a known SE address, confidence jumps to 0.85.

    We monkeypatch the module-level frozenset so the curated list
    stays empty in the shipped build while still being testable.
    """
    se_addr = "bc1p_known_se_xyz"
    monkeypatch.setattr(
        coinjoin_unwrap,
        "_MERCURY_KNOWN_SE_INPUTS",
        frozenset({se_addr}),
    )
    inputs = [
        UTXOInput(se_addr, 5_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1p_bob", 4_998_500, 0, script_hex=_VALID_P2TR_2),
    ]
    detection = detect_coinjoin(
        tx_hash="0xmercury_known_se",
        input_address=se_addr,
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is not None
    assert detection.protocol == PROTOCOL_MERCURY_LAYER
    assert detection.confidence == 0.85
    assert detection.most_likely_output is None
    assert "high confidence" in detection.forensic_note


# ---- Shape rejections ---- #


def test_mercury_rejects_non_p2tr_input() -> None:
    """Input is P2WPKH, output is P2TR — not a statechain op."""
    inputs = [
        UTXOInput("bc1q_alice", 5_000_000, script_hex=_P2WPKH_SCRIPT),
    ]
    outputs = [
        UTXOOutput("bc1p_bob", 4_999_000, 0, script_hex=_VALID_P2TR_2),
    ]
    matched, fee, known = _is_mercury_layer(inputs, outputs)
    assert matched is False
    assert fee is None
    assert known is False
    assert detect_coinjoin(
        tx_hash="0xnonp2tr_in",
        input_address="bc1q_alice",
        inputs=inputs,
        outputs=outputs,
    ) is None


def test_mercury_rejects_non_p2tr_output() -> None:
    """Input is P2TR, output is P2WPKH — also not a statechain op."""
    inputs = [
        UTXOInput("bc1p_alice", 5_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1q_bob", 4_999_000, 0, script_hex=_P2WPKH_SCRIPT),
    ]
    matched, _fee, _known = _is_mercury_layer(inputs, outputs)
    assert matched is False
    assert detect_coinjoin(
        tx_hash="0xnonp2tr_out",
        input_address="bc1p_alice",
        inputs=inputs,
        outputs=outputs,
    ) is None


def test_mercury_rejects_fee_too_small() -> None:
    """Fee = 50 sats is below the SE fee floor (100). That's plain
    miner-fee territory, not an SE charge."""
    inputs = [
        UTXOInput("bc1p_alice", 5_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1p_bob", 4_999_950, 0, script_hex=_VALID_P2TR_2),
    ]
    matched, _fee, _known = _is_mercury_layer(inputs, outputs)
    assert matched is False


def test_mercury_rejects_fee_too_large() -> None:
    """Fee = 5000 sats is above the SE fee ceiling. Looks like an
    ordinary P2TR send with a generous fee, not Mercury."""
    inputs = [
        UTXOInput("bc1p_alice", 5_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1p_bob", 4_995_000, 0, script_hex=_VALID_P2TR_2),
    ]
    matched, _fee, _known = _is_mercury_layer(inputs, outputs)
    assert matched is False


def test_mercury_rejects_fee_boundary_low_inclusive() -> None:
    """Fee == 100 sats is INSIDE the allowed range (range is
    [100, 2000] inclusive)."""
    inputs = [
        UTXOInput("bc1p_alice", 5_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1p_bob", 4_999_900, 0, script_hex=_VALID_P2TR_2),
    ]
    matched, fee, _known = _is_mercury_layer(inputs, outputs)
    assert matched is True
    assert fee == 100


def test_mercury_rejects_fee_boundary_high_inclusive() -> None:
    """Fee == 2000 sats is INSIDE the allowed range."""
    inputs = [
        UTXOInput("bc1p_alice", 5_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1p_bob", 4_998_000, 0, script_hex=_VALID_P2TR_2),
    ]
    matched, fee, _known = _is_mercury_layer(inputs, outputs)
    assert matched is True
    assert fee == 2000


def test_mercury_rejects_two_inputs() -> None:
    """Statechain init/withdraw is strictly 1-in/1-out. Two inputs
    invalidates the shape."""
    inputs = [
        UTXOInput("bc1p_a", 3_000_000, script_hex=_VALID_P2TR_1),
        UTXOInput("bc1p_b", 2_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1p_out", 4_999_000, 0, script_hex=_VALID_P2TR_2),
    ]
    matched, _fee, _known = _is_mercury_layer(inputs, outputs)
    assert matched is False


def test_mercury_rejects_two_outputs() -> None:
    """1-in / 2-out also invalidates — a real statechain operation
    is always 1/1."""
    inputs = [
        UTXOInput("bc1p_alice", 5_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1p_out1", 3_000_000, 0, script_hex=_VALID_P2TR_2),
        UTXOOutput("bc1p_out2", 1_999_000, 1, script_hex=_VALID_P2TR_2),
    ]
    matched, _fee, _known = _is_mercury_layer(inputs, outputs)
    assert matched is False


def test_mercury_returns_none_when_script_hex_absent() -> None:
    """Pre-v0.31.5 callers don't populate script_hex. The detector
    must silently decline rather than raise — the *other* detectors
    still get a chance to fire on this tx."""
    inputs = [UTXOInput("alice", 5_000_000)]  # no script_hex
    outputs = [UTXOOutput("bob", 4_999_000, 0)]  # no script_hex
    matched, _fee, _known = _is_mercury_layer(inputs, outputs)
    assert matched is False
    # And detect_coinjoin returns None on this 1/1 shape because no
    # other detector matches either.
    assert detect_coinjoin(
        tx_hash="0xplain",
        input_address="alice",
        inputs=inputs,
        outputs=outputs,
    ) is None


# ---- Backward compatibility: existing detectors still fire ---- #


def test_wasabi1_still_fires_without_script_hex() -> None:
    """The Wasabi 1.0 detector does NOT consult script_hex. Adding
    the new Mercury detector must not regress its happy path."""
    inputs = [UTXOInput(f"in{i}", 10_500_000) for i in range(15)]
    outputs = [UTXOOutput(f"out{i}", 10_000_000, i) for i in range(12)]
    detection = detect_coinjoin(
        tx_hash="0xwasabi1_compat",
        input_address="in0",
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is not None
    assert detection.protocol == PROTOCOL_WASABI_1


def test_whirlpool_still_fires_without_script_hex() -> None:
    """Whirlpool 5x5 detector likewise ignores script_hex."""
    inputs = [UTXOInput(f"in{i}", 110_000) for i in range(5)]
    outputs = [UTXOOutput(f"out{i}", 100_000, i) for i in range(5)]
    detection = detect_coinjoin(
        tx_hash="0xwhirlpool_compat",
        input_address="in0",
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is not None
    assert detection.protocol == PROTOCOL_WHIRLPOOL


def test_wasabi2_still_fires_without_script_hex() -> None:
    """Wasabi 2.0 / WabiSabi shape detection — script_hex irrelevant."""
    inputs = [UTXOInput(f"in{i}", 5_000_000 + i * 100_000) for i in range(12)]
    outputs = [
        UTXOOutput(f"out{i}", 2_000_000 + i * 137_000, i) for i in range(12)
    ]
    detection = detect_coinjoin(
        tx_hash="0xwabisabi_compat",
        input_address="in0",
        inputs=inputs,
        outputs=outputs,
    )
    assert detection is not None
    assert detection.protocol == PROTOCOL_WASABI_2


# ---- Defensive: empty inputs/outputs ---- #


def test_mercury_empty_inputs_outputs() -> None:
    """detect_coinjoin already guards against empty lists — Mercury
    detector must not change that contract."""
    assert detect_coinjoin(
        tx_hash="0xempty",
        input_address="alice",
        inputs=[],
        outputs=[UTXOOutput("bob", 1, 0, script_hex=_VALID_P2TR_2)],
    ) is None
    assert detect_coinjoin(
        tx_hash="0xempty",
        input_address="alice",
        inputs=[UTXOInput("alice", 1, script_hex=_VALID_P2TR_1)],
        outputs=[],
    ) is None
    # Direct call to _is_mercury_layer on empty lists also rejects.
    matched, _fee, _known = _is_mercury_layer([], [])
    assert matched is False


# ---- Purity ---- #


def test_mercury_detection_is_pure() -> None:
    """Same inputs → same detection. No hidden state, no caching
    that would make repeat calls drift."""
    inputs = [
        UTXOInput("bc1p_alice", 5_000_000, script_hex=_VALID_P2TR_1),
    ]
    outputs = [
        UTXOOutput("bc1p_bob", 4_999_000, 0, script_hex=_VALID_P2TR_2),
    ]
    d1 = detect_coinjoin(
        tx_hash="0xtx", input_address="bc1p_alice",
        inputs=inputs, outputs=outputs,
    )
    d2 = detect_coinjoin(
        tx_hash="0xtx", input_address="bc1p_alice",
        inputs=inputs, outputs=outputs,
    )
    assert d1 == d2
