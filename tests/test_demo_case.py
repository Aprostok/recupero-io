"""DEMO/SAMPLE case seeding — content, idempotency, and the empty-store gate.

The seeder populates a fresh recupero-api deploy's console with a clearly-
labeled sample case. Tests pin: it writes the expected files, is idempotent,
is unmistakably a SAMPLE (banner + placeholder addresses + _demo markers),
never overwrites real cases, and honors RECUPERO_SEED_DEMO_CASE=0.
"""

from __future__ import annotations

import json

from recupero.demo_case import (
    DEMO_CASE_ID,
    maybe_seed_demo_case,
    seed_demo_case,
)
from recupero.storage.case_store import _validate_case_id


def test_demo_case_id_is_valid() -> None:
    _validate_case_id(DEMO_CASE_ID)  # must not raise


def test_seed_writes_expected_files_and_is_idempotent(tmp_path) -> None:
    cases = tmp_path / "cases"
    cases.mkdir()
    assert seed_demo_case(cases) is True
    d = cases / DEMO_CASE_ID
    for rel in [
        "case.json", "freeze_brief.json", "ai_triage.json", "transfers.csv",
        "graph_ui.html", "trace_report_demo.html",
        "briefs/le_handoff_demo.html", "briefs/freeze_request_circle_demo.html",
        "briefs/victim_summary_demo.html",
        "regulatory_filing/us_fincen_sar_demo.html",
        "exhibit_pack/exhibit_pack.html",
    ]:
        assert (d / rel).is_file(), f"missing demo artifact {rel}"
    # Idempotent: a second call doesn't rewrite.
    assert seed_demo_case(cases) is False


def test_demo_is_clearly_labeled_sample(tmp_path) -> None:
    cases = tmp_path / "cases"
    cases.mkdir()
    seed_demo_case(cases)
    d = cases / DEMO_CASE_ID
    le = (d / "briefs" / "le_handoff_demo.html").read_text(encoding="utf-8")
    assert "SAMPLE" in le and "not a real" in le.lower()
    case_meta = json.loads((d / "case.json").read_text(encoding="utf-8"))
    assert case_meta.get("_demo") is True
    brief = json.loads((d / "freeze_brief.json").read_text(encoding="utf-8"))
    assert brief.get("_demo") is True
    # Placeholder addresses only (the repeated-nibble demo pattern), never a
    # plausible real address.
    blob = (d / "freeze_brief.json").read_text(encoding="utf-8")
    assert "0x1111111111111111111111111111111111111111" in blob


def test_gate_seeds_when_empty(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("RECUPERO_SEED_DEMO_CASE", raising=False)
    assert maybe_seed_demo_case() is True
    assert (tmp_path / "cases" / DEMO_CASE_ID / "case.json").is_file()


def test_gate_disabled_by_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RECUPERO_SEED_DEMO_CASE", "0")
    assert maybe_seed_demo_case() is False
    assert not (tmp_path / "cases" / DEMO_CASE_ID).exists()


def test_gate_skips_when_real_case_present(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("RECUPERO_SEED_DEMO_CASE", raising=False)
    real = tmp_path / "cases" / "REAL-CASE-0001"
    real.mkdir(parents=True)
    (real / "case.json").write_text("{}", encoding="utf-8")
    assert maybe_seed_demo_case() is False
    assert not (tmp_path / "cases" / DEMO_CASE_ID).exists()
