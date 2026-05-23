"""Deeper audit of the output-integrity validator.

The validator runs after build_all_deliverables and enforces ~27
structural invariants. This file locks gaps discovered in the
Wave-1 + Q audit that fall outside the existing
``test_validator_manifest_shape_hardening`` and
``test_validator_safe_load_json_cap`` coverage.

Gaps targeted (RED → minimal fix):

  A. **Per-deliverable size invariant**. The Wave-1 cap
     (MAX_VALIDATOR_JSON_BYTES = 50MB) bounds the *validator's*
     own JSON intake. But a *rendered* artifact going pathological
     (e.g. brief.html ballooning to 25MB because of an unbounded
     loop in a template) silently passes — no violation. A real
     freeze_request.html is <300KB; a real manifest_*.json is
     <100KB. Cap each.

  B. **Constant-time SHA compare**. The manifest-SHA check uses
     ``actual_sha != declared_sha`` — Python ``!=`` on strings
     short-circuits. For a *correctness* validator this is fine,
     but if the same code path is reused on a signed manifest
     downstream, a timing-side-channel on the compare leaks the
     declared digest a nibble at a time. Use hmac.compare_digest.

  C. **Manifest required-keys schema lock**. The validator reads
     ``outputs`` / ``output_sha256`` but never asserts they (and
     ``case_id``) are PRESENT. A manifest missing ``case_id`` (a
     real bug we've seen on the freeze_brief side) passes the
     SHA check trivially because outputs={} → nothing to verify.
     Lock the required-key contract explicitly.

  D. **Disk→manifest reverse consistency**. Check 5 walks
     manifest entries and verifies each one exists on disk. The
     reverse direction (every HTML / JSON / CSV in briefs/ is
     declared in *some* manifest) is not checked. An orphan
     artifact — written by a stale build, leftover from a prior
     case ID, etc. — slips through.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _briefs(tmp_path: Path) -> Path:
    b = tmp_path / "briefs"
    b.mkdir(parents=True, exist_ok=True)
    return b


def _seed_real_file(briefs: Path, name: str, body: bytes) -> str:
    (briefs / name).write_bytes(body)
    return hashlib.sha256(body).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# A. Per-deliverable size invariant
# ─────────────────────────────────────────────────────────────────────────────


def test_html_artifact_over_size_cap_emits_violation(tmp_path: Path) -> None:
    """A freeze_request.html > the per-HTML cap should produce a
    'high' severity 'artifact_size_invariant' violation.

    Realistic freeze_request_*.html is ~50–300KB. A 30MB file means
    a template runaway (unbounded inventory loop, infinite recursion
    in a partial). The validator must flag it before LE sees the
    deliverable.
    """
    from recupero.validators.output_integrity import (
        _check_artifact_size_invariants,
    )

    briefs = _briefs(tmp_path)
    # Real-looking HTML prefix so HTML-content check (separate) passes.
    # ~30MB body, well above any realistic ceiling.
    head = b"<!DOCTYPE html><html><body>"
    payload = b"x" * (30 * 1024 * 1024)
    (briefs / "freeze_request_circle_BRIEF-X-aa.html").write_bytes(
        head + payload + b"</body></html>",
    )

    vs = _check_artifact_size_invariants(briefs)
    assert any(
        v.check == "artifact_size_invariants"
        and v.severity in ("high", "critical")
        and "freeze_request_circle" in (v.file or "")
        for v in vs
    ), (
        f"expected an artifact_size_invariants violation for the 30MB "
        f"HTML; got {vs!r}"
    )


def test_manifest_json_over_per_artifact_cap_emits_violation(
    tmp_path: Path,
) -> None:
    """A manifest_*.json that is structurally valid but unrealistically
    large (e.g. 8MB) should be flagged. The OOM cap is 50MB; the
    *per-artifact realism* cap is smaller (a real manifest is <100KB).
    """
    from recupero.validators.output_integrity import (
        _check_artifact_size_invariants,
    )

    briefs = _briefs(tmp_path)
    # 8MB of valid JSON: an array with millions of entries.
    huge = {"case_id": "X", "outputs": {}, "output_sha256": {},
            "_pad": "y" * (8 * 1024 * 1024)}
    (briefs / "manifest_BRIEF-X-aa.json").write_text(
        json.dumps(huge), encoding="utf-8",
    )

    vs = _check_artifact_size_invariants(briefs)
    assert any(
        v.check == "artifact_size_invariants"
        and "manifest_BRIEF" in (v.file or "")
        for v in vs
    ), (
        f"expected an artifact_size_invariants violation for the 8MB "
        f"manifest; got {vs!r}"
    )


def test_normal_sized_artifacts_no_size_violation(tmp_path: Path) -> None:
    """Sanity: realistic file sizes (a few hundred KB) do NOT fire."""
    from recupero.validators.output_integrity import (
        _check_artifact_size_invariants,
    )

    briefs = _briefs(tmp_path)
    (briefs / "freeze_request_circle_BRIEF-X-aa.html").write_bytes(
        b"<!DOCTYPE html><html>" + b"x" * (200 * 1024) + b"</html>",
    )
    (briefs / "manifest_BRIEF-X-aa.json").write_text(
        json.dumps({"case_id": "X", "outputs": {}, "output_sha256": {}}),
        encoding="utf-8",
    )
    assert _check_artifact_size_invariants(briefs) == []


# ─────────────────────────────────────────────────────────────────────────────
# B. Constant-time SHA compare
# ─────────────────────────────────────────────────────────────────────────────


def test_sha_compare_uses_constant_time(tmp_path: Path) -> None:
    """The manifest-SHA equality path must route through
    ``hmac.compare_digest``, not raw ``!=``. We assert by monkey-
    patching ``hmac.compare_digest`` and checking it was called
    during a mismatch.
    """
    import hmac

    from recupero.validators.output_integrity import (
        _check_manifest_sha_matches_disk,
    )

    briefs = _briefs(tmp_path)
    body = b"<html>real</html>"
    real_sha = _seed_real_file(briefs, "x.html", body)
    # Declared sha is WRONG → triggers the comparison branch.
    (briefs / "manifest_BRIEF-X-aa.json").write_text(json.dumps({
        "case_id": "X",
        "outputs": {"x": "x.html"},
        "output_sha256": {"x": "0" * 64},
    }), encoding="utf-8")

    called: list[tuple[str, str]] = []
    real_compare = hmac.compare_digest

    def spy(a, b):  # type: ignore[no-untyped-def]
        called.append((str(a)[:16], str(b)[:16]))
        return real_compare(a, b)

    import pytest as _pt
    with _pt.MonkeyPatch.context() as m:
        m.setattr(hmac, "compare_digest", spy)
        _check_manifest_sha_matches_disk(briefs)

    # Sanity reference the captured sha so the linter doesn't flag it.
    assert real_sha
    assert called, (
        "manifest SHA compare did not route through hmac.compare_digest; "
        "raw '!=' is timing-leaky."
    )


# ─────────────────────────────────────────────────────────────────────────────
# C. Manifest required-keys schema lock
# ─────────────────────────────────────────────────────────────────────────────


def test_manifest_missing_required_keys_emits_violation(
    tmp_path: Path,
) -> None:
    """A manifest_*.json missing ``case_id``, ``outputs``, or
    ``output_sha256`` should fire a 'manifest_schema_required_keys'
    violation. A manifest that lacks ``outputs`` passes the SHA loop
    trivially (no entries to check) — that's a silent-pass bug.
    """
    from recupero.validators.output_integrity import (
        _check_manifest_required_keys,
    )

    briefs = _briefs(tmp_path)
    (briefs / "manifest_BRIEF-X-aa.json").write_text(
        json.dumps({"case_id": "X"}),  # missing outputs + output_sha256
        encoding="utf-8",
    )
    vs = _check_manifest_required_keys(briefs)
    missing = " ".join(v.detail for v in vs)
    assert "outputs" in missing and "output_sha256" in missing, (
        f"expected the schema-lock violation to call out the missing "
        f"required keys; got {vs!r}"
    )


def test_manifest_complete_schema_no_violation(tmp_path: Path) -> None:
    """Sanity: a manifest with all required keys present fires nothing."""
    from recupero.validators.output_integrity import (
        _check_manifest_required_keys,
    )

    briefs = _briefs(tmp_path)
    (briefs / "manifest_BRIEF-X-aa.json").write_text(json.dumps({
        "case_id": "X",
        "outputs": {},
        "output_sha256": {},
    }), encoding="utf-8")
    assert _check_manifest_required_keys(briefs) == []


# ─────────────────────────────────────────────────────────────────────────────
# D. Disk→manifest orphan detection
# ─────────────────────────────────────────────────────────────────────────────


def test_orphan_artifact_on_disk_emits_violation(tmp_path: Path) -> None:
    """A freeze_request_*.html on disk that is NOT listed in any
    manifest_*.json's outputs should emit a 'high' severity
    'artifact_orphan_on_disk' violation.

    Realistic origin: a stale build left over from a prior case ID, a
    write to the wrong dir from a parallel pipeline. AUSA would
    download the orphan and attribute it to the current case.
    """
    from recupero.validators.output_integrity import (
        _check_orphan_artifacts_on_disk,
    )

    briefs = _briefs(tmp_path)
    body = b"<!DOCTYPE html><html>real</html>"
    sha = _seed_real_file(briefs, "freeze_request_circle_BRIEF-X-aa.html", body)
    # ORPHAN: not in manifest.
    _seed_real_file(briefs, "freeze_request_stale_BRIEF-OLD-zz.html",
                    b"<!DOCTYPE html>old")
    (briefs / "manifest_BRIEF-X-aa.json").write_text(json.dumps({
        "case_id": "X",
        "outputs": {"freeze_request_circle": "freeze_request_circle_BRIEF-X-aa.html"},
        "output_sha256": {"freeze_request_circle": sha},
    }), encoding="utf-8")

    vs = _check_orphan_artifacts_on_disk(briefs)
    assert any(
        v.check == "artifact_orphan_on_disk"
        and "stale" in (v.file or "")
        for v in vs
    ), f"expected an orphan violation for the stale freeze_request; got {vs!r}"


def test_no_orphan_when_every_file_declared(tmp_path: Path) -> None:
    """Sanity: when every freeze_request / le_handoff on disk is
    declared in the manifest, no orphan finding."""
    from recupero.validators.output_integrity import (
        _check_orphan_artifacts_on_disk,
    )

    briefs = _briefs(tmp_path)
    body = b"<!DOCTYPE html><html>real</html>"
    sha = _seed_real_file(briefs, "freeze_request_circle_BRIEF-X-aa.html", body)
    (briefs / "manifest_BRIEF-X-aa.json").write_text(json.dumps({
        "case_id": "X",
        "outputs": {
            "freeze_request_circle": "freeze_request_circle_BRIEF-X-aa.html",
        },
        "output_sha256": {"freeze_request_circle": sha},
    }), encoding="utf-8")

    assert _check_orphan_artifacts_on_disk(briefs) == []
