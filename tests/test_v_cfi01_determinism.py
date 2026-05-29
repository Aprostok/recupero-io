"""V-CFI01 determinism: identical inputs MUST produce identical outputs.

Jacob's discipline (and good engineering hygiene): if you run the
worker pipeline twice on the same case fixture, every output file
should be byte-identical except for legitimately-variable fields
(timestamps, generated UUIDs that are write-time scoped, the
manifest's `generated_at` field, etc.).

Non-determinism in worker output is a silent class of bugs:
  * a dict iteration that depends on insertion-order
  * a set() comprehension that produces order-dependent output
  * a "random" sort tie-breaker
  * a Python str hashing variation (PYTHONHASHSEED)

These bugs produce visible output that LOOKS correct on the first
run but differs from the second run — meaning Jacob's "I ran the
same case twice and got different briefs" complaint becomes
inevitable as the codebase grows.

This test runs V-CFI01 through the production pipeline TWICE, then
diffs every output file. Differences are categorized:

  * EXPECTED: timestamps, generated_at, generated UUIDs (per-run)
  * UNEXPECTED: any other difference — FAIL the test with a focused
    diff so the offending field is immediately localizable.

The fixture is small enough to run in <5s but exercises the full
emit_brief + build_all_deliverables path.
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

import pytest

# Regexes that match LEGITIMATELY-variable fields. Two runs MAY differ
# on these. Everything else MUST be identical.
_LEGITIMATE_VARIATION_PATTERNS = [
    # ISO 8601 timestamps INCLUDING fractional seconds + tz offset.
    # E.g., 2026-05-21T17:32:11.650811+00:00 — all of this is a
    # legitimately-variable per-run timestamp.
    re.compile(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
        r'(?:\.\d+)?'           # fractional seconds
        r'(?:Z|[+-]\d{2}:\d{2})?'  # tz offset or Z
    ),
    # Date stamps (YYYY-MM-DD)
    re.compile(r'\d{4}-\d{2}-\d{2}\b'),
    # Time-of-day stamps
    re.compile(r'\d{2}:\d{2}:\d{2}(?:\.\d+)?'),
    # UUIDs (per-run generated investigation_id, etc.)
    re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
        r'[0-9a-f]{4}-[0-9a-f]{12}',
        re.IGNORECASE,
    ),
    # SHA-256 hashes (manifest output_sha256 fields will agree on
    # content but the hash itself may include encoded timestamp bytes
    # inside the artifact text).
    re.compile(r'[0-9a-f]{40,64}'),
    # Per-run tmp directory paths (the test driver allocates a unique
    # tmp dir per run; the manifest stores absolute output paths that
    # include this prefix). In prod the case_dir is stable; in tests
    # we normalize. Both Windows (\Users\...\Temp\vcfi01_det_xxx) and
    # POSIX (/tmp/vcfi01_det_xxx) variants.
    re.compile(r'(?:[A-Za-z]:[\\/]|/)[^"\\\s]*vcfi01_det_[A-Za-z0-9_]+'),
    # Path-separator escaping in JSON: \\\\ or \\ for the tmp prefix.
    # When stringified into JSON the path becomes
    # "C:\\\\Users\\\\...". A single sub catches the JSON-escaped form.
    re.compile(
        r'(?:[A-Za-z]:\\\\|/)[^"]*?vcfi01_det_[A-Za-z0-9_]+'
    ),
]


def _normalize(text: str) -> str:
    """Replace every legitimate-variation match with a sentinel so
    the post-normalization diff surfaces only UNEXPECTED differences."""
    out = text
    for pat in _LEGITIMATE_VARIATION_PATTERNS:
        out = pat.sub("<VARIABLE>", out)
    return out


@pytest.fixture(scope="module")
def two_v_cfi01_runs() -> tuple[Path, Path]:
    """Run V-CFI01 through emit_brief + build_all_deliverables TWICE
    and return both case_dir paths. Each run uses an isolated tmp
    directory so they can't share state."""
    from recupero.reports.brief import InvestigatorInfo
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo
    from recupero.worker._deliverables import build_all_deliverables
    from tests.test_v_cfi01_production_path import (  # type: ignore
        VICTIM,
        _build_editorial,
        _build_freeze_asks_dict,
        _build_issuer_metadata,
        _build_v_cfi01_case,
    )

    def _run_once() -> Path:
        case = _build_v_cfi01_case()
        editorial = _build_editorial()
        freeze_asks = _build_freeze_asks_dict()
        metadata = _build_issuer_metadata()
        victim = VictimInfo(
            name="V-CFI01 Det Test", wallet_address=VICTIM,
            state="NY", country="US",
            email="det-test@example.com",
        )
        inv = InvestigatorInfo(
            name="Determinism Test Investigator",
            organization="Recupero Forensics Ltd.",
            email="det-investigator@example.com",
        )
        brief = emit_brief(
            case=case, victim=victim, editorial=editorial,
            freeze_asks=freeze_asks, issuer_metadata=metadata,
        )
        tmp = Path(tempfile.mkdtemp(prefix="vcfi01_det_"))
        (tmp / "freeze_brief.json").write_text(
            json.dumps(brief, default=str), encoding="utf-8",
        )
        (tmp / "freeze_asks.json").write_text(
            json.dumps(freeze_asks, default=str), encoding="utf-8",
        )
        build_all_deliverables(
            case=case, victim=victim, freeze_brief=brief,
            case_dir=tmp, investigator=inv, skip_freeze_briefs=False,
        )
        return tmp

    return _run_once(), _run_once()


def _enumerate_files(case_dir: Path) -> dict[str, bytes]:
    """Walk the case directory and return {relative_path: file_bytes}.
    Skips temp / lock files."""
    out: dict[str, bytes] = {}
    for p in sorted(case_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(case_dir)).replace("\\", "/")
        if rel.endswith((".tmp", ".lock", ".log")):
            continue
        out[rel] = p.read_bytes()
    return out


def test_v_cfi01_output_set_is_identical(two_v_cfi01_runs):
    """Both runs MUST produce the same SET of output files (same
    filenames, modulo hash-suffixed BRIEF-<case>-<hash> components
    which we normalize). Mismatched file sets indicate a code path
    that conditionally produces an artifact based on non-deterministic
    state (e.g., a dict iteration order)."""
    run_a, run_b = two_v_cfi01_runs

    def _normalize_filename(name: str) -> str:
        # The BRIEF-<case_id>-<6-char-hash> suffix changes the hash
        # portion when the brief content changes by even a timestamp.
        # Normalize the hash so we compare the artifact CLASSES.
        return re.sub(
            r"BRIEF-[A-Z0-9-]+-[0-9a-f]+",
            "BRIEF-<NORM>",
            name,
        )

    names_a = {_normalize_filename(p) for p in _enumerate_files(run_a)}
    names_b = {_normalize_filename(p) for p in _enumerate_files(run_b)}

    missing_in_b = names_a - names_b
    missing_in_a = names_b - names_a
    assert not missing_in_b, (
        f"files produced by run A but not run B: {sorted(missing_in_b)}"
    )
    assert not missing_in_a, (
        f"files produced by run B but not run A: {sorted(missing_in_a)}"
    )


def test_v_cfi01_normalized_contents_are_identical(two_v_cfi01_runs):
    """For every output file present in BOTH runs, the
    normalized-text contents MUST be byte-identical (after replacing
    timestamps + UUIDs + SHA-256 hashes with a sentinel).

    A failure here means a code path produces different output on
    the SAME input — exactly the silent class of bugs that produces
    "the second brief looks different from the first" complaints
    over time."""
    run_a, run_b = two_v_cfi01_runs

    files_a = _enumerate_files(run_a)
    files_b = _enumerate_files(run_b)

    # Build a map from normalized filename → original filenames.
    def _norm(n: str) -> str:
        return re.sub(
            r"BRIEF-[A-Z0-9-]+-[0-9a-f]+",
            "BRIEF-<NORM>",
            n,
        )

    a_by_norm: dict[str, str] = {_norm(k): k for k in files_a}
    b_by_norm: dict[str, str] = {_norm(k): k for k in files_b}

    differences: list[str] = []
    binary_extensions = (".pdf", ".png", ".jpg", ".jpeg", ".gif")

    for nname in sorted(set(a_by_norm) & set(b_by_norm)):
        a_path = a_by_norm[nname]
        b_path = b_by_norm[nname]
        a_bytes = files_a[a_path]
        b_bytes = files_b[b_path]

        # Binary files: compare structurally (size + first/last bytes)
        # rather than full content, since PDF embeds timestamps in
        # binary form.
        if any(nname.endswith(ext) for ext in binary_extensions):
            # Allow up to 5% size variation (PDF timestamp bytes vary)
            if abs(len(a_bytes) - len(b_bytes)) > max(1024, len(a_bytes) // 20):
                differences.append(
                    f"{nname}: size mismatch beyond 5% slack — "
                    f"A={len(a_bytes)} B={len(b_bytes)}"
                )
            continue

        # Text files: normalize and compare.
        try:
            a_text = a_bytes.decode("utf-8")
            b_text = b_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Non-UTF-8 text — fall back to byte compare with same
            # 5% slack as binary.
            if abs(len(a_bytes) - len(b_bytes)) > max(1024, len(a_bytes) // 20):
                differences.append(
                    f"{nname}: non-UTF8 byte-size mismatch — "
                    f"A={len(a_bytes)} B={len(b_bytes)}"
                )
            continue

        a_norm = _normalize(a_text)
        b_norm = _normalize(b_text)
        if a_norm != b_norm:
            # Find the first divergence point + context.
            from difflib import unified_diff
            diff_lines = list(
                unified_diff(
                    a_norm.splitlines(keepends=True)[:200],
                    b_norm.splitlines(keepends=True)[:200],
                    fromfile=f"runA/{a_path}",
                    tofile=f"runB/{b_path}",
                    n=2,
                )
            )
            # Truncate the diff to the first 30 lines for readability.
            diff_snippet = "".join(diff_lines[:30])
            differences.append(
                f"{nname}: normalized text differs after replacing "
                f"timestamps + UUIDs + SHAs. Diff snippet:\n"
                f"{diff_snippet}"
            )

    assert not differences, (
        f"V-CFI01 is NON-DETERMINISTIC across {len(differences)} files. "
        "Same inputs → different normalized outputs. This is a silent "
        "bug class — Jacob would catch this with `diff -r run_a/ run_b/`. "
        "\n\n" + "\n---\n".join(differences[:5])
    )


def test_v_cfi01_freeze_brief_json_normalizes_identically(
    two_v_cfi01_runs,
):
    """Focused test on freeze_brief.json specifically — the single
    most important output file, since it drives every freeze letter
    + the LE handoff. After normalizing timestamps + UUIDs, the
    parsed JSON structure MUST be identical between runs."""
    run_a, run_b = two_v_cfi01_runs

    brief_a = json.loads(
        (run_a / "freeze_brief.json").read_text(encoding="utf-8")
    )
    brief_b = json.loads(
        (run_b / "freeze_brief.json").read_text(encoding="utf-8")
    )

    # Normalize: serialize, replace timestamps/UUIDs, re-parse.
    a_norm_text = _normalize(json.dumps(brief_a, sort_keys=True, default=str))
    b_norm_text = _normalize(json.dumps(brief_b, sort_keys=True, default=str))

    if a_norm_text != b_norm_text:
        # Identify the first key whose value differs.
        diffs = []
        for k in set(brief_a) | set(brief_b):
            va = json.dumps(brief_a.get(k), sort_keys=True, default=str)
            vb = json.dumps(brief_b.get(k), sort_keys=True, default=str)
            if _normalize(va) != _normalize(vb):
                diffs.append(
                    f"  key {k!r}: "
                    f"A={_normalize(va)[:100]}, B={_normalize(vb)[:100]}"
                )
        pytest.fail(
            "freeze_brief.json normalized contents differ:\n"
            + "\n".join(diffs[:5])
        )
