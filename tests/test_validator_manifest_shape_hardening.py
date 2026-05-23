"""RIGOR-Jacob Q: harden _check_manifest_sha_matches_disk against
malformed manifest shapes.

The validator is THE final integrity check before LE handoff. If a
corrupted / partially-written / wrong-shape manifest_*.json file
crashes the validator with AttributeError instead of producing a
clear violation, an operator running pre-flight checks gets a
500 instead of an audit log row.

Real adversarial inputs:
  * ``outputs: [...]`` — list instead of dict. ``.items()`` raises
    AttributeError.
  * ``output_sha256: "string"`` — string instead of dict. ``.get()``
    raises AttributeError.
  * ``outputs: {"file": null}`` — null value where path expected.
    ``Path(None).name`` raises TypeError.
  * ``outputs: {"file": "../../etc/passwd"}`` — path traversal
    attempt. The current code does ``Path(declared_path).name``
    which extracts only the basename — safe — but worth pinning
    that contract.

Lock: the validator MUST return either an empty list or a list of
Violations, never raise.
"""

from __future__ import annotations

import json
from pathlib import Path


def _write_manifest(tmp_path: Path, contents: dict) -> Path:
    """Lay down a briefs/ dir with one manifest_test.json."""
    briefs = tmp_path / "briefs"
    briefs.mkdir(parents=True, exist_ok=True)
    manifest_path = briefs / "manifest_test.json"
    manifest_path.write_text(json.dumps(contents), encoding="utf-8")
    return briefs


def test_outputs_as_list_does_not_crash(tmp_path: Path) -> None:
    """outputs being a list (instead of dict) must not raise."""
    from recupero.validators.output_integrity import (
        _check_manifest_sha_matches_disk,
    )

    briefs = _write_manifest(tmp_path, {
        "outputs": ["a.html", "b.pdf"],  # list instead of dict
        "output_sha256": {},
    })
    # Must return a list of Violations or empty, never raise.
    try:
        result = _check_manifest_sha_matches_disk(briefs)
    except (AttributeError, TypeError) as e:
        raise AssertionError(
            f"_check_manifest_sha_matches_disk crashed on list outputs: {e}"
        ) from e
    assert isinstance(result, list)


def test_output_sha256_as_string_does_not_crash(tmp_path: Path) -> None:
    """output_sha256 being a string (instead of dict) must not raise."""
    from recupero.validators.output_integrity import (
        _check_manifest_sha_matches_disk,
    )

    briefs = _write_manifest(tmp_path, {
        "outputs": {"file": "a.html"},
        "output_sha256": "abc123",  # string instead of dict
    })
    try:
        result = _check_manifest_sha_matches_disk(briefs)
    except (AttributeError, TypeError) as e:
        raise AssertionError(
            f"_check_manifest_sha_matches_disk crashed on string "
            f"output_sha256: {e}"
        ) from e
    assert isinstance(result, list)


def test_outputs_with_null_value_does_not_crash(tmp_path: Path) -> None:
    """A null path value must not raise TypeError on Path(None)."""
    from recupero.validators.output_integrity import (
        _check_manifest_sha_matches_disk,
    )

    briefs = _write_manifest(tmp_path, {
        "outputs": {"file": None},  # null path
        "output_sha256": {"file": "abc123"},
    })
    try:
        result = _check_manifest_sha_matches_disk(briefs)
    except (AttributeError, TypeError) as e:
        raise AssertionError(
            f"_check_manifest_sha_matches_disk crashed on null path: {e}"
        ) from e
    assert isinstance(result, list)


def test_outputs_with_path_traversal_extracts_basename_only(
    tmp_path: Path,
) -> None:
    """Path traversal in the declared_path must NOT escape briefs_dir
    (Path(...).name extracts only the basename). Lock this contract."""
    from recupero.validators.output_integrity import (
        _check_manifest_sha_matches_disk,
    )

    # Plant a sensitive file outside briefs/
    sensitive = tmp_path / "sensitive.txt"
    sensitive.write_text("secret", encoding="utf-8")

    briefs = _write_manifest(tmp_path, {
        "outputs": {"file": "../sensitive.txt"},
        "output_sha256": {"file": "deadbeef" * 8},
    })

    try:
        result = _check_manifest_sha_matches_disk(briefs)
    except Exception as e:
        raise AssertionError(
            f"_check_manifest_sha_matches_disk crashed on traversal "
            f"path: {e}"
        ) from e

    # The check should look for briefs/sensitive.txt (basename only),
    # find it missing, and emit a "file is missing on disk" violation.
    # Critically, it must NOT read the actual sensitive.txt at
    # tmp_path/sensitive.txt.
    for v in result:
        assert "sensitive.txt" not in str(v.detail) or "missing on disk" in v.detail, (
            f"Traversal extracted full path instead of basename: {v}"
        )


def test_outputs_with_extreme_path_does_not_crash(tmp_path: Path) -> None:
    """A pathologically long declared_path must not crash Path()."""
    from recupero.validators.output_integrity import (
        _check_manifest_sha_matches_disk,
    )

    huge_path = "x" * 10_000 + ".html"
    briefs = _write_manifest(tmp_path, {
        "outputs": {"file": huge_path},
        "output_sha256": {"file": "abc"},
    })
    try:
        result = _check_manifest_sha_matches_disk(briefs)
    except Exception as e:
        raise AssertionError(
            f"_check_manifest_sha_matches_disk crashed on long path: {e}"
        ) from e
    assert isinstance(result, list)


def test_outputs_with_non_string_path_does_not_crash(tmp_path: Path) -> None:
    """A non-string path value (int, list, dict) must not raise."""
    from recupero.validators.output_integrity import (
        _check_manifest_sha_matches_disk,
    )

    for bad_path in (42, [1, 2], {"nested": "dict"}, True):
        briefs_dir = tmp_path / f"briefs_{type(bad_path).__name__}"
        briefs_dir.mkdir(parents=True)
        manifest = briefs_dir / "manifest_test.json"
        manifest.write_text(json.dumps({
            "outputs": {"file": bad_path},
            "output_sha256": {"file": "abc"},
        }), encoding="utf-8")
        try:
            result = _check_manifest_sha_matches_disk(briefs_dir)
        except (AttributeError, TypeError) as e:
            raise AssertionError(
                f"crashed on path={bad_path!r}: {e}"
            ) from e
        assert isinstance(result, list)


def test_valid_manifest_still_validates(tmp_path: Path) -> None:
    """Sanity: a well-formed manifest still gets validated."""
    import hashlib

    from recupero.validators.output_integrity import (
        _check_manifest_sha_matches_disk,
    )

    briefs = tmp_path / "briefs"
    briefs.mkdir(parents=True)
    # Plant a file + its SHA.
    target = briefs / "real_output.html"
    content = b"<html>test</html>"
    target.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    manifest_path = briefs / "manifest_test.json"
    manifest_path.write_text(json.dumps({
        "outputs": {"file": "real_output.html"},
        "output_sha256": {"file": sha},
    }), encoding="utf-8")

    result = _check_manifest_sha_matches_disk(briefs)
    # No violations for a correctly-hashed file.
    assert result == [], (
        f"Valid manifest should produce no violations; got {result!r}"
    )
