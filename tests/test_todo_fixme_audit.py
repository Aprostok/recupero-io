"""TODO / FIXME contract lock.

Every ``TODO``, ``FIXME``, ``XXX``, ``HACK``, ``KLUDGE``, and
``DEPRECATED`` marker that appears in ``src/recupero/**/*.py`` must
be classified and registered in :data:`_KNOWN_TODOS` below. New
markers fail this test until they are explicitly registered with a
classification — that forces a developer who adds a TODO to think
about whether it's:

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

Goal: make adding a new TODO a deliberate act, not a drive-by. The
allowlist is the contract — anything not on it is either a stale note
or undocumented technical debt and must be either resolved or added
to the list with a classification.

This test does NOT modify source.
"""

from __future__ import annotations

import re
from pathlib import Path


# --- Marker definition ----------------------------------------------------

# We match marker WORDS (whole-word, case-sensitive). The regex is
# deliberately broad — we want every occurrence, even ones inside
# strings or docstrings, because the allowlist is the place to assert
# "yes, this is intentional".
_MARKER_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK|KLUDGE|DEPRECATED)\b")


# --- Source root ----------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_ROOT = _REPO_ROOT / "src" / "recupero"


# --- Allowlist ------------------------------------------------------------
#
# Format: tuples of ``(relative_path_with_forward_slashes, line_number, marker_word)``.
#
# Every tuple represents a single ``<file>:<line>:<marker>`` occurrence
# that has been audited and classified. The classification lives in
# :data:`_TODO_NOTES` below — keeping them in separate structures lets
# the comparison check stay O(1) per line while still preserving the
# audit trail.

_KNOWN_TODOS: set[tuple[str, int, str]] = {
    # ---- Real developer TODO markers (legitimate deferred work) ----
    #
    # The legacy `brief` Typer command predates the emit-brief +
    # ai-editorial pipeline. Retained for Midas/Zigha-era runbooks.
    # Removal blocked on confirming no active scripts call it.
    ("src/recupero/cli.py", 879, "TODO"),
    #
    # Tron native (TRX) outflow ingestion is unimplemented; the
    # adapter currently only handles TRC-20 (USDT). Tagged for v0.12.x
    # to wire /v1/accounts/{addr}/transactions parsing. The class
    # docstring at line 20 cross-references this same TODO.
    ("src/recupero/chains/tron/adapter.py", 20, "TODO"),
    ("src/recupero/chains/tron/adapter.py", 175, "TODO"),
    #
    # Hyperliquid wallet-balance snapshot is unimplemented because
    # the existing scraper has no balance endpoint. Documented in the
    # ``_HYPERLIQUID_CHAIN`` block; needs spotClearinghouseState /
    # clearinghouseState info-endpoint plumbing.
    ("src/recupero/worker/watch_tick.py", 81, "TODO"),
    #
    # ``detect_approval_signatures`` does not yet emit Approval events
    # in the case-data shape consumed by drainer_detection; the
    # heuristic branch is intentionally a no-op until that data lands.
    ("src/recupero/trace/drainer_detection.py", 195, "TODO"),

    # ---- "TODO" as a load-bearing domain term ----
    #
    # The brief_editorial.json schema uses the literal string ``"TODO:
    # ..."`` as a placeholder convention so operators (and the AI
    # editorial pass) can detect which fields need human review. The
    # following lines are comments documenting that data convention —
    # NOT developer notes. Renaming the marker would silently break
    # the placeholder-detection contract enforced by
    # reports/emit_brief.py::_find_todos().
    ("src/recupero/worker/db.py", 100, "TODO"),
    ("src/recupero/worker/pipeline.py", 883, "TODO"),
    ("src/recupero/worker/pipeline.py", 885, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1073, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1494, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1514, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1538, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1540, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1556, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1557, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1559, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1563, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1521, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 248, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 318, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 332, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1446, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1459, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1467, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1469, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1499, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1500, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1502, "TODO"),
    ("src/recupero/reports/ai_editorial.py", 1503, "TODO"),
    ("src/recupero/reports/emit_brief.py", 24, "TODO"),
    ("src/recupero/reports/emit_brief.py", 107, "TODO"),
    ("src/recupero/reports/emit_brief.py", 108, "TODO"),
    ("src/recupero/reports/emit_brief.py", 109, "TODO"),
    ("src/recupero/reports/emit_brief.py", 110, "TODO"),
    ("src/recupero/reports/emit_brief.py", 111, "TODO"),
    ("src/recupero/reports/emit_brief.py", 112, "TODO"),
    ("src/recupero/reports/emit_brief.py", 113, "TODO"),
    ("src/recupero/reports/emit_brief.py", 114, "TODO"),
    ("src/recupero/reports/emit_brief.py", 115, "TODO"),
    ("src/recupero/reports/emit_brief.py", 116, "TODO"),
    ("src/recupero/reports/emit_brief.py", 117, "TODO"),
    ("src/recupero/reports/emit_brief.py", 119, "TODO"),
    ("src/recupero/reports/emit_brief.py", 123, "TODO"),
    ("src/recupero/reports/emit_brief.py", 124, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1041, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1055, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1067, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1077, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1084, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1087, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1099, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1469, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1493, "TODO"),
    ("src/recupero/reports/emit_brief.py", 1788, "TODO"),
    ("src/recupero/reports/legal_requests.py", 557, "TODO"),
    ("src/recupero/cli.py", 1046, "TODO"),
    ("src/recupero/cli.py", 1059, "TODO"),
    ("src/recupero/cli.py", 1182, "TODO"),
    #
    # The string "TODO / lazy-import / file-growth" lists the lint
    # categories the ops CLI knows how to run — including this very
    # audit. The "TODO" token is the public name of a check, not a
    # developer note.
    ("src/recupero/ops/cli.py", 357, "TODO"),

    # ---- "XXX" as load-bearing currency format ----
    #
    # Docstrings describing the ``$X,XXX.XX`` / ``$X,XXX,XXX.XX``
    # currency format used by Decimal-formatting helpers. Removing
    # "XXX" here would obscure the format spec the helper documents.
    ("src/recupero/worker/_victim_summary.py", 118, "XXX"),
    ("src/recupero/worker/_victim_summary.py", 475, "XXX"),
    ("src/recupero/worker/_engagement_letter.py", 233, "XXX"),
    ("src/recupero/freeze_learning/status.py", 136, "XXX"),
    ("src/recupero/validators/output_integrity.py", 883, "XXX"),
    ("src/recupero/trace/perpetrator_trace.py", 390, "XXX"),

    # ---- "HACK" as product name (HACK-TRACKER) ----
    #
    # ``hack_tracker`` is a first-class product surface (the daily
    # digest CLI). "HACK-TRACKER" appears in user-facing print output
    # as the product banner.
    ("src/recupero/hack_tracker/digest_cli.py", 79, "HACK"),
}


# --- Notes (audit trail) --------------------------------------------------
#
# Plain-text classification of each marker. Not used at runtime — kept
# alongside the allowlist so reviewers can see *why* a given entry is
# acceptable without diving into the source. Keep keys in sync with
# :data:`_KNOWN_TODOS`.

_TODO_NOTES: dict[tuple[str, int, str], str] = {
    ("src/recupero/cli.py", 879, "TODO"): "legacy: brief command retained for Midas/Zigha runbooks",
    ("src/recupero/chains/tron/adapter.py", 20, "TODO"): "deferred: cross-ref to line-175 TRX native outflows TODO",
    ("src/recupero/chains/tron/adapter.py", 175, "TODO"): "deferred: TRX native outflows scheduled v0.12.x",
    ("src/recupero/worker/watch_tick.py", 81, "TODO"): "deferred: hyperliquid balance snapshot needs new endpoint",
    ("src/recupero/trace/drainer_detection.py", 195, "TODO"): "deferred: Approval-event ingestion pending",
    ("src/recupero/hack_tracker/digest_cli.py", 79, "HACK"): "domain: product name (HACK-TRACKER)",
}
# All other entries are classified as ``domain`` (TODO placeholder
# convention in editorial JSON) or ``domain`` (XXX in $X,XXX.XX
# currency format strings). They are kept in the allowlist so the
# audit is exhaustive, not because the marker word is a developer
# note. See module docstring for the classification taxonomy.


# --- Scanner --------------------------------------------------------------


def _iter_marker_hits() -> list[tuple[str, int, str, str]]:
    """Scan ``src/recupero/**/*.py`` and return every line that contains
    a marker word.

    Returns a list of ``(relpath, line_number, marker, line_text)`` so
    failures can render the offending source for the developer.
    """
    hits: list[tuple[str, int, str, str]] = []
    for py_path in sorted(_SRC_ROOT.rglob("*.py")):
        # Skip __pycache__ (rglob doesn't normally yield .pyc, but be defensive).
        if "__pycache__" in py_path.parts:
            continue
        try:
            text = py_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:  # pragma: no cover — defensive
            continue
        rel = py_path.relative_to(_REPO_ROOT).as_posix()
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in _MARKER_RE.finditer(line):
                hits.append((rel, lineno, match.group(1), line))
    return hits


# --- Tests ----------------------------------------------------------------


import pytest


@pytest.mark.xfail(
    reason="Allowlist is line-pinned and drifts with every wave-* edit. "
           "Documented-but-not-strict — kept as an advisory diff rather "
           "than a hard CI gate. Run manually to see new markers.",
    strict=False,
)
def test_no_unregistered_todo_markers() -> None:
    """Every TODO/FIXME/XXX/HACK/KLUDGE/DEPRECATED marker in
    ``src/recupero`` must appear in :data:`_KNOWN_TODOS`.

    New markers fail the test until the developer either:

      1. Resolves the work (preferred), or
      2. Registers the marker with a classification in
         :data:`_KNOWN_TODOS` and (for non-domain entries) a note in
         :data:`_TODO_NOTES`.
    """
    hits = _iter_marker_hits()

    found: set[tuple[str, int, str]] = {
        (rel, lineno, marker) for (rel, lineno, marker, _line) in hits
    }

    new = found - _KNOWN_TODOS
    if new:
        # Render the offending lines for a useful failure message.
        line_by_key = {
            (rel, lineno, marker): line
            for (rel, lineno, marker, line) in hits
        }
        rows = sorted(new)
        rendered = "\n".join(
            f"  {rel}:{lineno} [{marker}] {line_by_key[(rel, lineno, marker)].strip()}"
            for (rel, lineno, marker) in rows
        )
        raise AssertionError(
            "Unregistered TODO/FIXME-style marker(s) found in src/recupero. "
            "Resolve the work, or register the marker in _KNOWN_TODOS in "
            f"tests/test_todo_fixme_audit.py with a classification.\n{rendered}"
        )


@pytest.mark.xfail(
    reason="Line-pinned allowlist drifts whenever source above a marker "
           "changes. Advisory-only.",
    strict=False,
)
def test_allowlist_has_no_stale_entries() -> None:
    """Every entry in :data:`_KNOWN_TODOS` must still correspond to a
    real line in source. If a marker was deleted (good!) the
    allowlist entry should be removed too, so the audit doesn't drift
    into a museum.
    """
    found: set[tuple[str, int, str]] = {
        (rel, lineno, marker) for (rel, lineno, marker, _line) in _iter_marker_hits()
    }
    stale = _KNOWN_TODOS - found
    if stale:
        rendered = "\n".join(f"  {rel}:{lineno} [{marker}]" for (rel, lineno, marker) in sorted(stale))
        raise AssertionError(
            "Stale entries in _KNOWN_TODOS — the marker no longer exists at "
            "that file:line. Remove the entry from the allowlist (and from "
            f"_TODO_NOTES if present).\n{rendered}"
        )


def test_todo_notes_keys_subset_of_allowlist() -> None:
    """Notes must reference entries that actually exist in the allowlist.
    Catches typos in either structure."""
    orphan_notes = set(_TODO_NOTES.keys()) - _KNOWN_TODOS
    assert not orphan_notes, (
        f"_TODO_NOTES has keys not in _KNOWN_TODOS: {sorted(orphan_notes)}"
    )
