"""v0.35.11 (H1) — court-admissible exhibit pack.

Pins: SHA-256 hashes match the on-disk bytes; the exhibit index is
deterministic + alphabetically labeled; non-evidentiary files are excluded; the
rendered HTML carries the hashes, the methodology appendix, and the 28 U.S.C.
§ 1746 declaration template; empty case dirs render gracefully.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from recupero.reports.exhibit_pack import (
    _exhibit_letter,
    _human_size,
    build_exhibit_manifest,
    render_exhibit_pack,
)


def _seed_case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "V-CFI01"
    case_dir.mkdir()
    (case_dir / "freeze_brief.json").write_text(
        json.dumps({
            "CASE_ID": "V-CFI01",
            "software_version": "0.35.11",
            "config_used": {"max_hops": 5, "chain": "ethereum"},
        }),
        encoding="utf-8",
    )
    (case_dir / "transfers.csv").write_text(
        "tx_hash,from,to,usd\n0xabc,0x1,0x2,100\n", encoding="utf-8",
    )
    (case_dir / "notes.png").write_bytes(b"\x89PNG not evidentiary")
    return case_dir


def test_manifest_hashes_match_disk(tmp_path: Path):
    case_dir = _seed_case(tmp_path)
    manifest = build_exhibit_manifest(case_dir)
    by_name = {e.filename: e for e in manifest.entries}
    # .png excluded; the two evidentiary files indexed.
    assert "notes.png" not in by_name
    assert set(by_name) == {"freeze_brief.json", "transfers.csv"}
    for name, entry in by_name.items():
        expected = hashlib.sha256((case_dir / name).read_bytes()).hexdigest()
        assert entry.sha256 == expected
        assert entry.size_bytes == (case_dir / name).stat().st_size
    # Deterministic alphabetical labels.
    labels = [e.exhibit_label for e in manifest.entries]
    assert labels == ["Exhibit A", "Exhibit B"]
    # Case meta pulled from the brief.
    assert manifest.software_version == "0.35.11"
    assert "max_hops=5" in manifest.config_summary


def test_manifest_deterministic_ordering(tmp_path: Path):
    case_dir = _seed_case(tmp_path)
    a = build_exhibit_manifest(case_dir)
    b = build_exhibit_manifest(case_dir)
    assert [e.filename for e in a.entries] == [e.filename for e in b.entries]
    assert [e.sha256 for e in a.entries] == [e.sha256 for e in b.entries]


def test_exhibit_letter_sequence():
    assert _exhibit_letter(0) == "A"
    assert _exhibit_letter(25) == "Z"
    assert _exhibit_letter(26) == "AA"
    assert _exhibit_letter(27) == "AB"


def test_human_size():
    assert _human_size(500) == "500 B"
    assert _human_size(1536) == "1.5 KB"


def test_render_writes_pack_with_hashes_and_sections(tmp_path: Path):
    case_dir = _seed_case(tmp_path)
    out_path = render_exhibit_pack(case_dir)
    assert out_path.exists()
    assert out_path == case_dir / "exhibit_pack" / "exhibit_pack.html"
    html = out_path.read_text(encoding="utf-8")
    assert "V-CFI01" in html
    assert "Methodology" in html
    assert "28 U.S.C. § 1746" in html
    assert "Exhibit A" in html
    # A real hash appears in the rendered index.
    brief_hash = hashlib.sha256(
        (case_dir / "freeze_brief.json").read_bytes()
    ).hexdigest()
    assert brief_hash in html


def test_own_output_excluded(tmp_path: Path):
    case_dir = _seed_case(tmp_path)
    # A stray top-level exhibit_pack.html must never index itself.
    (case_dir / "exhibit_pack.html").write_text("<html></html>", encoding="utf-8")
    manifest = build_exhibit_manifest(case_dir)
    assert "exhibit_pack.html" not in {e.filename for e in manifest.entries}


def test_empty_case_dir_renders(tmp_path: Path):
    case_dir = tmp_path / "EMPTY"
    case_dir.mkdir()
    manifest = build_exhibit_manifest(case_dir)
    assert manifest.entries == ()
    out_path = render_exhibit_pack(case_dir)
    html = out_path.read_text(encoding="utf-8")
    assert "No evidentiary artifacts" in html
