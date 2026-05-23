"""RIGOR-Jacob S: _safe_load_json size cap.

The validator's ``_safe_load_json`` reads any-size JSON into memory
before parsing. A 100GB manifest_*.json (operator misconfig /
corrupted disk / hostile case dir) OOMs the validator process.
Same shape as the read_case bug closed in M-phase.

The realistic manifest_*.json is <100KB; cap at 50MB (500× margin)
to bound the worst case while leaving room for unusual but
legitimate cases.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_safe_load_json_rejects_oversized_file(tmp_path: Path) -> None:
    """A manifest > MAX_VALIDATOR_JSON_BYTES must be rejected BEFORE
    being read into memory."""
    from recupero.validators.output_integrity import _safe_load_json

    huge_path = tmp_path / "huge_manifest.json"
    huge_path.write_text('{"case_id":"X"}', encoding="utf-8")

    import os
    orig_stat = os.stat

    def fake_stat(p, *args, **kwargs):
        result = orig_stat(p, *args, **kwargs)
        if str(p).endswith(".json"):
            class FakeStat:
                st_size = 100_000_000  # 100MB
                def __getattr__(self, name):
                    return getattr(result, name)
            return FakeStat()
        return result

    with pytest.MonkeyPatch.context() as m:
        m.setattr(os, "stat", fake_stat)
        result = _safe_load_json(huge_path)

    # The hardened version returns None (the documented "any failure"
    # contract) without OOMing.
    assert result is None


def test_safe_load_json_normal_file_works(tmp_path: Path) -> None:
    """Sanity: a normal-sized manifest still parses."""
    from recupero.validators.output_integrity import _safe_load_json

    good = tmp_path / "ok.json"
    good.write_text(json.dumps({"case_id": "OK"}), encoding="utf-8")
    assert _safe_load_json(good) == {"case_id": "OK"}


def test_safe_load_json_returns_dict_or_none(tmp_path: Path) -> None:
    """RIGOR-Jacob S: even when JSON content is valid but the outer
    shape is a list/string/number, return None so downstream callers
    that do .get() don't crash AttributeError."""
    from recupero.validators.output_integrity import _safe_load_json

    list_path = tmp_path / "list.json"
    list_path.write_text("[1, 2, 3]", encoding="utf-8")
    assert _safe_load_json(list_path) is None or isinstance(
        _safe_load_json(list_path), dict,
    )

    str_path = tmp_path / "str.json"
    str_path.write_text('"just a string"', encoding="utf-8")
    assert _safe_load_json(str_path) is None or isinstance(
        _safe_load_json(str_path), dict,
    )

    num_path = tmp_path / "num.json"
    num_path.write_text("42", encoding="utf-8")
    assert _safe_load_json(num_path) is None or isinstance(
        _safe_load_json(num_path), dict,
    )
