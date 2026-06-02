"""v0.35.12 (J1) — ground-truth trace-quality benchmark.

Pins: recall/endpoint-precision/F1 math; canonical-key address matching;
missed/spurious lists; empty-truth + empty-flagged edge cases; per-category
recall; the case.json/brief extraction + score_case_dir entry point; the
ground-truth never being inferred from the trace (must be supplied).
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from recupero.trace.benchmark import (
    GroundTruth,
    extract_trace_addresses,
    load_ground_truth,
    score_case_dir,
    score_trace,
)

A = "0x" + "a" * 40
B = "0x" + "b" * 40
C = "0x" + "c" * 40
D = "0x" + "d" * 40


def test_perfect_trace_scores_one():
    truth = GroundTruth(case_id="X", endpoints=frozenset({A, B}))
    s = score_trace(reached={A, B, C}, flagged_endpoints={A, B}, truth=truth)
    assert s.recall == 1.0
    assert s.endpoint_precision == 1.0
    assert s.f1 == 1.0
    assert s.missed == ()
    assert s.spurious == ()


def test_partial_recall_and_precision():
    truth = GroundTruth(case_id="X", endpoints=frozenset({A, B, C}))
    # Reached A and B (not C). Flagged A (real) and D (spurious).
    s = score_trace(reached={A, B}, flagged_endpoints={A, D}, truth=truth)
    assert math.isclose(s.recall, 2 / 3, rel_tol=1e-9)
    assert s.endpoint_precision == 0.5      # 1 of 2 flagged were real
    assert s.missed == (C,)
    assert s.spurious == (D,)
    expected_f1 = 2 * (2 / 3) * 0.5 / ((2 / 3) + 0.5)
    assert math.isclose(s.f1, expected_f1, rel_tol=1e-9)


def test_canonical_key_matching():
    # Trace reached the mixed-case form; truth has lowercase. Must match.
    mixed = "0x" + "Ab" * 20
    truth = GroundTruth(case_id="X", endpoints=frozenset({mixed.lower()}))
    s = score_trace(reached={mixed}, flagged_endpoints={mixed}, truth=truth)
    assert s.recall == 1.0
    assert s.reached_truth_count == 1


def test_empty_truth_recall_zero():
    truth = GroundTruth(case_id="X", endpoints=frozenset())
    s = score_trace(reached={A}, flagged_endpoints={A}, truth=truth)
    assert s.recall == 0.0
    assert s.ground_truth_count == 0


def test_empty_flagged_precision_zero():
    truth = GroundTruth(case_id="X", endpoints=frozenset({A}))
    s = score_trace(reached={A}, flagged_endpoints=set(), truth=truth)
    assert s.recall == 1.0
    assert s.endpoint_precision == 0.0
    assert s.f1 == 0.0


def test_per_category_recall():
    truth = GroundTruth(
        case_id="X",
        endpoints=frozenset({A, B}),
        by_category={"exchange": frozenset({A}), "mixer": frozenset({B})},
    )
    s = score_trace(reached={A}, flagged_endpoints={A}, truth=truth)
    assert s.by_category_recall["exchange"] == 1.0
    assert s.by_category_recall["mixer"] == 0.0   # B not reached


def test_load_ground_truth(tmp_path: Path):
    p = tmp_path / "truth.json"
    p.write_text(json.dumps({
        "case_id": "RONIN",
        "endpoints": [A, B],
        "by_category": {"mixer": [B]},
        "notes": "from indictment",
    }), encoding="utf-8")
    gt = load_ground_truth(p)
    assert gt.case_id == "RONIN"
    assert gt.endpoints == frozenset({A, B})
    assert gt.by_category["mixer"] == frozenset({B})


def test_extract_handles_dict_transfers():
    case_json = {
        "transfers": [
            {"from_address": A, "to_address": B,
             "counterparty": {"address": C}},
        ],
    }
    brief = {"EXCHANGES": [{"address": B}], "DESTINATIONS": [{"address": C}]}
    reached, flagged = extract_trace_addresses(case_json, brief)
    assert reached == {A, B, C}
    assert flagged == {B, C}


def test_score_case_dir_reads_files(tmp_path: Path):
    case_dir = tmp_path / "CASE"
    case_dir.mkdir()
    (case_dir / "case.json").write_text(json.dumps({
        "transfers": [{"from_address": A, "to_address": B}],
    }), encoding="utf-8")
    (case_dir / "freeze_brief.json").write_text(json.dumps({
        "EXCHANGES": [{"address": B}],
    }), encoding="utf-8")
    truth = GroundTruth(case_id="CASE", endpoints=frozenset({B}))
    s = score_case_dir(case_dir, truth)
    assert s.recall == 1.0            # B reached
    assert s.endpoint_precision == 1.0  # B flagged + real


def test_score_case_dir_missing_files_no_crash(tmp_path: Path):
    case_dir = tmp_path / "EMPTY"
    case_dir.mkdir()
    truth = GroundTruth(case_id="EMPTY", endpoints=frozenset({A}))
    s = score_case_dir(case_dir, truth)   # no case.json / brief
    assert s.recall == 0.0
    assert s.missed == (A,)
