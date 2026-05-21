"""Tests for v0.14.4 label-data validator + CI gate."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.labels.validator import (
    validate_seed_files,
)


def _write(tmp: Path, name: str, data) -> None:
    (tmp / name).write_text(json.dumps(data), encoding="utf-8")


# ---- Real seed files validate cleanly ---- #


def test_committed_seed_files_validate() -> None:
    """The seed files currently committed in the repo MUST validate.
    This is the CI gate that protects against drift."""
    report = validate_seed_files()
    errors = [i for i in report.issues if i.severity == "error"]
    if errors:
        msg = "Committed seed files have errors:\n" + "\n".join(
            f"  {i.file}[{i.entry_index}]: {i.message}"
            for i in errors
        )
        pytest.fail(msg)


# ---- Schema enforcement ---- #


def test_missing_required_field_flagged() -> None:
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "mixers.json", [
            {
                # missing 'address' (required)
                "name": "Test Mixer",
                "category": "mixer",
            },
        ])
        report = validate_seed_files(tmp_path)
        assert any(
            i.severity == "error" and i.field == "address"
            for i in report.issues
        )


def test_duplicate_address_in_file_warned() -> None:
    """The same address appearing twice in one file is a curation
    TODO. Surfaced as a WARNING so the operator sees it, but not
    an error (some pre-existing duplicates exist in the committed
    files and we don't want to block CI on those — separate
    cleanup task)."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "mixers.json", [
            {"address": "0xabc", "name": "First", "category": "mixer"},
            {"address": "0xabc", "name": "Dup", "category": "mixer"},
        ])
        report = validate_seed_files(tmp_path)
        dup_issues = [i for i in report.issues if "Duplicate address" in i.message]
        assert len(dup_issues) >= 1
        # WARNING severity, not ERROR.
        assert all(i.severity == "warning" for i in dup_issues)


def test_invalid_confidence_value_flagged() -> None:
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "mixers.json", [
            {
                "address": "0xabc", "name": "Test", "category": "mixer",
                "confidence": "unknown",  # not in {high, medium, low}
            },
        ])
        report = validate_seed_files(tmp_path)
        assert any(
            i.severity == "error" and i.field == "confidence"
            for i in report.issues
        )


def test_severity_out_of_range_flagged() -> None:
    """high_risk.json uses severity 1..4; 5+ should be flagged."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "high_risk.json", {
            "addresses": [
                {
                    "address": "0xabc", "name": "Test",
                    "risk_category": "ofac_sanctioned",
                    "severity": 7,  # out of range
                },
            ],
        })
        report = validate_seed_files(tmp_path)
        assert any(
            i.severity == "error" and i.field == "severity"
            for i in report.issues
        )


def test_unknown_field_is_warning_not_error() -> None:
    """Unknown fields should warn (forward-compat) but not error."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "mixers.json", [
            {
                "address": "0xabc", "name": "Test", "category": "mixer",
                "future_field_not_in_schema": "some value",
            },
        ])
        report = validate_seed_files(tmp_path)
        # Should have a warning about the unknown field.
        warnings = [i for i in report.issues if i.severity == "warning"]
        assert any("future_field_not_in_schema" in i.message for i in warnings)
        # But NO error.
        assert not any(i.severity == "error" for i in report.issues)


def test_malformed_json_flagged_as_error() -> None:
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "mixers.json").write_text("not-valid-json{", encoding="utf-8")
        report = validate_seed_files(tmp_path)
        assert any("JSON parse failed" in i.message for i in report.issues)
        assert not report.ok


def test_wrong_top_level_shape_flagged() -> None:
    """mixers.json expects a top-level list; an object should error."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "mixers.json", {"not": "a list"})
        report = validate_seed_files(tmp_path)
        assert any("Expected JSON array" in i.message for i in report.issues)


def test_high_risk_missing_addresses_key_flagged() -> None:
    """high_risk.json expects {"addresses": [...]} at top level."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "high_risk.json", [{"address": "0xabc", "name": "x"}])
        report = validate_seed_files(tmp_path)
        assert any(
            "Expected object with 'addresses' key" in i.message
            for i in report.issues
        )


def test_missing_file_is_warning_not_error() -> None:
    """If a known file is absent, that's a warning (some files are
    optional)."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # Don't write anything.
        report = validate_seed_files(tmp_path)
        assert report.ok is True  # warnings only, no errors
        warns = [i for i in report.issues if i.severity == "warning"]
        assert any("File not found" in i.message for i in warns)


def test_empty_seeds_dir_passes() -> None:
    """No seed files at all → all-warnings, ok=True."""
    with TemporaryDirectory() as tmp:
        report = validate_seed_files(Path(tmp))
        assert report.ok is True
        # entries_checked == 0
        assert report.entries_checked == 0
