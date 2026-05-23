"""RIGOR-Jacob Z20: adversarial-input regression for labels.validator.

Hardens the validator against four malformed-wrapping shapes that
previously crashed with an uncaught TypeError. A malicious or
mistyped seed PR could land a file with ``{"addresses": null}`` or
``{"tokens": 42}`` and explode the entire CI gate (rather than
flagging the single bad file).
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.labels.validator import validate_seed_files


def _write(tmp: Path, name: str, raw: str) -> None:
    (tmp / name).write_text(raw, encoding="utf-8")


def test_addresses_value_null_does_not_crash() -> None:
    """Z20: ``{"addresses": null}`` previously raised
    ``TypeError: 'NoneType' object is not iterable`` inside the
    inner entry loop. Must surface as a clean validation error."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "high_risk.json", json.dumps({"addresses": None}))
        report = validate_seed_files(tmp_path)
        assert not report.ok
        assert any(
            i.severity == "error"
            and "high_risk.json" == i.file
            and ("'addresses'" in i.message or "addresses" in (i.field or ""))
            for i in report.issues
        ), [i.message for i in report.issues]


def test_addresses_value_non_list_does_not_crash() -> None:
    """Z20: ``{"addresses": 42}`` (int) used to raise TypeError on
    enumerate(). Must produce an error issue, not a crash."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "high_risk.json", json.dumps({"addresses": 42}))
        report = validate_seed_files(tmp_path)
        # Must NOT raise; should report an error.
        assert not report.ok


def test_tokens_value_non_list_does_not_crash() -> None:
    """Z20: ``{"tokens": 42}`` in issuers.json used to raise
    TypeError on enumerate(). Must report as a validation error."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "issuers.json", json.dumps({"tokens": 42}))
        report = validate_seed_files(tmp_path)
        assert not report.ok


def test_tokens_value_null_does_not_crash() -> None:
    """Z20: ``{"tokens": null}`` in issuers.json — same root cause."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write(tmp_path, "issuers.json", json.dumps({"tokens": None}))
        report = validate_seed_files(tmp_path)
        assert not report.ok


def test_validator_caps_oversized_files() -> None:
    """Z20: a 60MB labels.json file must be rejected at read-time
    rather than slurped into memory + parsed. The seed files in the
    repo are all <300KB; a 60MB file in seeds/ is unambiguously an
    attack or an accident worth flagging."""
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # ~60MB of valid-looking JSON. Each entry is ~70 bytes so
        # 900_000 entries × 70 = ~63MB, comfortably over the 50MB cap.
        entry = '{"address":"0xabc","name":"oversized-attack","category":"mixer"}'
        huge = "[" + ",".join([entry] * 900_000) + "]"
        assert len(huge) > 55 * 1024 * 1024  # sanity: definitely above cap
        _write(tmp_path, "mixers.json", huge)
        report = validate_seed_files(tmp_path)
        # Should flag size or parse error rather than silently process
        # 60MB. The exact wording isn't pinned; what matters is that
        # the validator returns a report with an error and does NOT
        # consume gigabytes of memory or hang.
        assert not report.ok
        assert any(
            "exceeds" in (i.message or "").lower()
            or "size" in (i.message or "").lower()
            or "too large" in (i.message or "").lower()
            for i in report.issues
        ), [i.message for i in report.issues]
        # The size-cap path must short-circuit before
        # entries_checked is incremented (i.e. we did NOT walk 900k
        # entries — that's the whole point of the cap).
        assert report.entries_checked == 0
