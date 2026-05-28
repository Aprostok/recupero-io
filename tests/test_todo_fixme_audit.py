"""TODO / FIXME contract lock.

Every ``TODO``, ``FIXME``, ``XXX``, ``HACK``, ``KLUDGE``, and
``DEPRECATED`` marker in ``src/recupero/**/*.py`` is tracked. The
allowlist is keyed by ``(relative_path, marker_word) -> count`` so
it survives line-drift inside a file but still catches:

  * A new marker appearing in a file (count goes UP)         → fails.
  * A marker disappearing from a file (count goes DOWN)      → fails
    (advisory: the entry is stale; resolve OR lower the count).
  * A marker appearing in a brand-new file                   → fails.

v0.31.1 — was previously line-pinned and `xfail`'d because every
``wave-*`` edit drifted the line numbers. The line-pinned variant
made the audit advisory-only; the file-level count locks the
invariant ("known markers, known counts") without false positives
from unrelated source movement.

This test does NOT modify source. Each entry in :data:`_TODO_NOTES`
classifies the markers in a file:

  - ``tracked``  — references an issue/ticket/version (e.g. TODO(v0.12.x)).
                   Acceptable but should still have a target.
  - ``deferred`` — known unfinished feature or known-broken-but-deferred
                   work, with a documented reason for the defer. Acceptable.
  - ``domain``   — the marker word is *not* a developer note; it's a
                   reference to a domain concept (e.g. the "TODO:" prefix
                   the AI uses to flag missing victim address fields in
                   the editorial JSON, or the ``$X,XXX.XX`` currency format
                   string, or the product name "HACK-TRACKER"). These are
                   load-bearing user-visible text — renaming them would
                   break the user-facing contract.
  - ``legacy``   — the marker tags code retained for compatibility with
                   an older workflow. Removal requires a migration plan.

Goal: make adding a new TODO a deliberate act, not a drive-by.
"""

from __future__ import annotations

import re
from pathlib import Path


# --- Marker definition ----------------------------------------------------

_MARKER_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK|KLUDGE|DEPRECATED)\b")


# --- Source root ----------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_ROOT = _REPO_ROOT / "src" / "recupero"


# --- Allowlist ------------------------------------------------------------
#
# Format: dict[(relative_path_with_forward_slashes, marker_word)] -> count.
# Edits inside a file freely move the markers around without
# touching this dict; adding a NEW marker (or removing one) flips
# the count and trips the test until the developer acknowledges
# the change.

_KNOWN_MARKER_COUNTS: dict[tuple[str, str], int] = {
    ("src/recupero/chains/tron/adapter.py",          "TODO"): 2,
    ("src/recupero/cli.py",                          "TODO"): 4,
    ("src/recupero/freeze_learning/status.py",       "XXX"):  1,
    ("src/recupero/hack_tracker/digest_cli.py",      "HACK"): 1,
    ("src/recupero/ops/cli.py",                      "TODO"): 1,
    ("src/recupero/reports/ai_editorial.py",         "TODO"): 21,
    ("src/recupero/reports/emit_brief.py",           "TODO"): 27,
    ("src/recupero/reports/legal_requests.py",       "TODO"): 1,
    ("src/recupero/trace/drainer_detection.py",      "TODO"): 1,
    # v0.31.0: indirect_exposure.py MVP scorer has one TODO note
    # flagging the cycle-detection / per-category severity / inflow-
    # aware traversal as post-MVP follow-ups. Documented in the
    # commit message; deferred.
    ("src/recupero/trace/indirect_exposure.py",      "TODO"): 1,
    ("src/recupero/trace/perpetrator_trace.py",      "XXX"):  1,
    ("src/recupero/validators/output_integrity.py",  "XXX"):  2,
    ("src/recupero/worker/_engagement_letter.py",    "XXX"):  1,
    ("src/recupero/worker/_victim_summary.py",       "XXX"):  2,
    ("src/recupero/worker/db.py",                    "TODO"): 1,
    ("src/recupero/worker/pipeline.py",              "TODO"): 2,
    ("src/recupero/worker/watch_tick.py",            "TODO"): 1,
}


# --- Notes (audit trail) --------------------------------------------------

_TODO_NOTES: dict[tuple[str, str], str] = {
    ("src/recupero/cli.py", "TODO"): (
        "legacy/domain: 1× brief command retained for Midas/Zigha runbooks "
        "+ 3× docstring references to the AI-editorial 'TODO:' placeholder "
        "convention"
    ),
    ("src/recupero/chains/tron/adapter.py", "TODO"): (
        "deferred: 2× TRX native outflow ingestion (line 20 docstring + "
        "line 175 implementation), scheduled v0.12.x"
    ),
    ("src/recupero/worker/watch_tick.py", "TODO"): (
        "deferred: hyperliquid wallet-balance snapshot needs a new endpoint"
    ),
    ("src/recupero/trace/drainer_detection.py", "TODO"): (
        "deferred: detect_approval_signatures needs Approval-event ingestion"
    ),
    ("src/recupero/trace/indirect_exposure.py", "TODO"): (
        "deferred: v0.31.0 MVP scorer flags cycle-detection, per-category "
        "severity weights, inflow-aware traversal as post-MVP follow-ups"
    ),
    ("src/recupero/hack_tracker/digest_cli.py", "HACK"): (
        "domain: product name (HACK-TRACKER) — banner text, not a developer note"
    ),
    ("src/recupero/ops/cli.py", "TODO"): (
        "domain: 'TODO' is the public name of a lint check the ops CLI runs"
    ),
    ("src/recupero/reports/ai_editorial.py", "TODO"): (
        "domain: 'TODO:' placeholder convention in editorial JSON — flags "
        "fields needing operator review. Renaming breaks the placeholder-"
        "detection contract enforced by emit_brief._find_todos()"
    ),
    ("src/recupero/reports/emit_brief.py", "TODO"): (
        "domain: same 'TODO:' placeholder convention as ai_editorial.py — "
        "implementation side that emits / detects the placeholder strings"
    ),
    ("src/recupero/reports/legal_requests.py", "TODO"): (
        "domain: 'TODO' placeholder in legal-request templates"
    ),
    ("src/recupero/worker/db.py", "TODO"): (
        "domain: docstring documenting the TODO placeholder convention"
    ),
    ("src/recupero/worker/pipeline.py", "TODO"): (
        "domain: 2× docstring references to the TODO placeholder convention"
    ),
    ("src/recupero/worker/_victim_summary.py", "XXX"): (
        "domain: 2× $X,XXX.XX currency format documentation"
    ),
    ("src/recupero/worker/_engagement_letter.py", "XXX"): (
        "domain: $X,XXX.XX currency format documentation"
    ),
    ("src/recupero/freeze_learning/status.py", "XXX"): (
        "domain: $X,XXX.XX currency format documentation"
    ),
    ("src/recupero/validators/output_integrity.py", "XXX"): (
        "domain: 2× $X,XXX.XX currency format docstrings"
    ),
    ("src/recupero/trace/perpetrator_trace.py", "XXX"): (
        "domain: $X,XXX.XX currency format documentation"
    ),
}


# --- Scanner --------------------------------------------------------------


def _count_markers_per_file() -> dict[tuple[str, str], int]:
    """Scan ``src/recupero/**/*.py`` and return one count per
    ``(relative_path, marker_word)``. Multiple markers on the same line
    are counted independently (matches the user-visible behavior of "how
    many TODO occurrences live in this file").
    """
    counts: dict[tuple[str, str], int] = {}
    for py_path in sorted(_SRC_ROOT.rglob("*.py")):
        if "__pycache__" in py_path.parts:
            continue
        try:
            text = py_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:  # pragma: no cover
            continue
        rel = py_path.relative_to(_REPO_ROOT).as_posix()
        for line in text.splitlines():
            for match in _MARKER_RE.finditer(line):
                key = (rel, match.group(1))
                counts[key] = counts.get(key, 0) + 1
    return counts


# --- Tests ----------------------------------------------------------------


def test_no_unregistered_todo_markers() -> None:
    """Every (file, marker) pair in src/recupero/ that contains the
    pattern must appear in :data:`_KNOWN_MARKER_COUNTS` with the EXACT
    count seen on disk. New markers (or removed markers) trip this test
    until the developer acknowledges the change.
    """
    found = _count_markers_per_file()
    new_keys = set(found) - set(_KNOWN_MARKER_COUNTS)
    if new_keys:
        rendered = "\n".join(
            f"  {rel}: +{found[(rel, marker)]} new [{marker}] "
            f"(file not previously known to contain {marker})"
            for (rel, marker) in sorted(new_keys)
        )
        raise AssertionError(
            "New TODO/FIXME-style marker(s) in src/recupero. Resolve the "
            "work, or register the marker in _KNOWN_MARKER_COUNTS in "
            f"tests/test_todo_fixme_audit.py with a count.\n{rendered}"
        )
    drift: list[str] = []
    for key, expected in _KNOWN_MARKER_COUNTS.items():
        actual = found.get(key, 0)
        if actual > expected:
            drift.append(
                f"  {key[0]}: [{key[1]}] expected={expected} actual={actual} "
                f"(+{actual - expected} new occurrence(s))"
            )
    if drift:
        raise AssertionError(
            "Marker count INCREASED above the allowlisted value — a new "
            "marker was added to a file already known to contain that "
            "marker. Register the higher count in _KNOWN_MARKER_COUNTS.\n"
            + "\n".join(drift)
        )


def test_allowlist_has_no_stale_entries() -> None:
    """Every entry in :data:`_KNOWN_MARKER_COUNTS` must still match
    a count > 0 on disk; an entry whose markers were all deleted is
    stale and should be removed from the allowlist (good cleanup, not
    a regression).
    """
    found = _count_markers_per_file()
    stale: list[str] = []
    for key, expected in _KNOWN_MARKER_COUNTS.items():
        actual = found.get(key, 0)
        if actual < expected:
            stale.append(
                f"  {key[0]}: [{key[1]}] expected={expected} actual={actual} "
                f"(-{expected - actual} occurrence(s) removed)"
            )
    if stale:
        raise AssertionError(
            "Allowlist has stale entries — markers were removed from "
            "source but the allowlist count was not lowered. Lower the "
            "count in _KNOWN_MARKER_COUNTS (or delete the entry if it's "
            "now zero).\n" + "\n".join(stale)
        )


def test_todo_notes_keys_subset_of_allowlist() -> None:
    """Every (file, marker) note must reference a real allowlist entry.
    Catches typos in either structure."""
    orphan_notes = set(_TODO_NOTES) - set(_KNOWN_MARKER_COUNTS)
    assert not orphan_notes, (
        f"_TODO_NOTES has keys not in _KNOWN_MARKER_COUNTS: {sorted(orphan_notes)}"
    )
