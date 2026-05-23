"""Maintainability gate: cap raw lines-of-code per source file.

Files larger than ``LOC_CAP`` lines have accreted too many
responsibilities to be tested cleanly. When a file approaches the
cap, decompose it (extract helpers, split modules) instead of
raising the cap.

How this gate works
-------------------
* Every file under ``src/recupero/**/*.py`` is counted by raw newlines.
* Files at or under ``LOC_CAP`` pass silently.
* Files over ``LOC_CAP`` must appear in ``ALLOWLIST``. The allowlist
  pins each oversized file to its current size plus a small growth
  buffer (``BUFFER``) and documents it as a refactor candidate.
* New violations (files crossing the cap that are NOT on the
  allowlist) fail the test immediately.

Tightening the gate
-------------------
After a refactor lands that shrinks an allowlisted file under
``LOC_CAP``, remove its entry from ``ALLOWLIST``. The test will then
enforce the cap against future regressions.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOC_CAP = 5000
"""Hard ceiling on raw line count per source file.

Files at or below this count pass. Files above must be allowlisted
with their current LOC and a growth buffer.
"""

BUFFER = 200
"""Per-file growth buffer applied to allowlisted entries.

Lets in-flight work on already-oversized files land without churning
the allowlist on every commit, while still flagging runaway growth.
"""

# Map: posix-style path relative to repo root -> current raw LOC at
# the time of allowlisting. The effective ceiling for each entry is
# ``current_loc + BUFFER``. Each entry is a refactor candidate; the
# comment captures why the file is large so a future refactor has
# direction.
ALLOWLIST: dict[str, int] = {
    # No files currently exceed LOC_CAP. Largest file in tree is
    # ``src/recupero/validators/output_integrity.py`` at ~1870 lines.
    # Add entries here only when a file legitimately must exceed the
    # cap AND a refactor is queued.
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    """Return the repository root (the parent of ``tests/``)."""
    return Path(__file__).resolve().parent.parent


def _src_root() -> Path:
    return _repo_root() / "src" / "recupero"


def _count_lines(path: Path) -> int:
    """Count raw lines (newline-terminated, plus any trailing partial line).

    Reads bytes to stay encoding-agnostic and counts ``\\n`` characters
    so the result matches ``wc -l`` semantics for newline-terminated
    files. A trailing line without a final newline still counts as 1.
    """
    data = path.read_bytes()
    if not data:
        return 0
    count = data.count(b"\n")
    if not data.endswith(b"\n"):
        count += 1
    return count


def _iter_source_files() -> list[Path]:
    src = _src_root()
    return sorted(p for p in src.rglob("*.py") if p.is_file())


def _rel_posix(path: Path) -> str:
    return path.relative_to(_repo_root()).as_posix()


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


def test_no_source_file_exceeds_loc_ceiling() -> None:
    """Every ``src/recupero/**/*.py`` is under ``LOC_CAP`` or allowlisted.

    Failure modes
    -------------
    * **New oversized file**: a file crossed ``LOC_CAP`` and is not in
      ``ALLOWLIST``. Either split the file (preferred) or add an entry
      to ``ALLOWLIST`` justifying the exemption.
    * **Allowlist drift**: an allowlisted file grew past its pinned
      LOC + ``BUFFER``. Either shrink the file or bump its allowlist
      entry — but a bump signals the refactor debt is still growing.
    * **Stale allowlist entry**: an allowlisted file is now under
      ``LOC_CAP``. Remove the entry so the cap is re-enforced.
    """
    src = _src_root()
    assert src.is_dir(), f"expected source tree at {src}"

    files = _iter_source_files()
    assert files, "no source files discovered — glob is broken"

    new_violations: list[tuple[str, int]] = []
    allowlist_drift: list[tuple[str, int, int]] = []
    stale_allowlist: list[tuple[str, int]] = []
    seen_allowlisted: set[str] = set()

    for path in files:
        rel = _rel_posix(path)
        loc = _count_lines(path)

        if rel in ALLOWLIST:
            seen_allowlisted.add(rel)
            pinned = ALLOWLIST[rel]
            ceiling = pinned + BUFFER
            if loc <= LOC_CAP:
                stale_allowlist.append((rel, loc))
            elif loc > ceiling:
                allowlist_drift.append((rel, loc, ceiling))
            continue

        if loc > LOC_CAP:
            new_violations.append((rel, loc))

    missing_from_tree = sorted(set(ALLOWLIST) - seen_allowlisted)

    messages: list[str] = []
    if new_violations:
        new_violations.sort(key=lambda item: item[1], reverse=True)
        lines = "\n".join(
            f"  - {rel}: {loc} lines (cap {LOC_CAP})"
            for rel, loc in new_violations
        )
        messages.append(
            "New oversized source files (split them or allowlist with "
            f"justification):\n{lines}"
        )
    if allowlist_drift:
        lines = "\n".join(
            f"  - {rel}: {loc} lines, ceiling was {ceiling}"
            for rel, loc, ceiling in allowlist_drift
        )
        messages.append(
            "Allowlisted files grew past their pinned ceiling — "
            f"shrink or refactor (do not just bump):\n{lines}"
        )
    if stale_allowlist:
        lines = "\n".join(
            f"  - {rel}: now {loc} lines (under cap {LOC_CAP})"
            for rel, loc in stale_allowlist
        )
        messages.append(
            f"Stale allowlist entries — remove from ALLOWLIST:\n{lines}"
        )
    if missing_from_tree:
        lines = "\n".join(f"  - {rel}" for rel in missing_from_tree)
        messages.append(
            f"Allowlist references non-existent files — remove:\n{lines}"
        )

    if messages:
        pytest.fail("\n\n".join(messages))
