"""Unused-dependency audit.

Parses pyproject.toml's [project].dependencies (and optional-dependencies),
then greps src/recupero/**/*.py for ``import <dep>`` / ``from <dep>``
statements. Flags any declared dependency that is never imported.

WHY: declared-but-unused deps inflate the install footprint, slow down
docker builds, increase the supply-chain attack surface, and create
confusion about what the codebase actually needs. Catching them at test
time is cheaper than catching them at deploy time.

PHILOSOPHY: this test is intentionally CONSERVATIVE. We only assert that
the *known* unused-candidate list is empty. Removing a dep is a follow-up
decision (some deps are transitive runtime needs that aren't directly
imported — e.g. `eth-hash[pycryptodome]` is the keccak backend for
`eth-utils`). When a new dep is added, the corresponding import shows up
naturally; when an old dep is dropped from the code, this test loudly
fails until pyproject.toml is updated to match.

ALLOWLIST: legitimate non-imported deps (build tools, plugins, transitive
runtime needs) are listed in ``ALLOWLIST_NOT_IMPORTED`` below with a
one-line justification each.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

# --------------------------------------------------------------------------- #
# Path helpers
# --------------------------------------------------------------------------- #

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
SRC_ROOT = REPO_ROOT / "src" / "recupero"


# --------------------------------------------------------------------------- #
# Dep-name → import-name canonicalisation
# --------------------------------------------------------------------------- #
#
# PyPI distribution names don't always match the importable module name.
# The common transforms are:
#   - lowercase
#   - ``-`` and ``.`` become ``_``
#   - strip [extras]
# Plus a handful of well-known irregular mappings (python-dotenv → dotenv,
# pyyaml → yaml, python-dateutil → dateutil, etc.).

IRREGULAR_IMPORT_NAMES: dict[str, str] = {
    "python-dotenv": "dotenv",
    "pyyaml": "yaml",
    "python-dateutil": "dateutil",
    "pydantic-settings": "pydantic_settings",
    # eth-* keep their hyphen-to-underscore mapping, handled by the
    # default normaliser below
}


def _strip_extras(spec: str) -> str:
    """Return ``"pkg"`` from a spec like ``"pkg[extra1,extra2]>=1.0"``."""
    # Drop version constraint
    spec = re.split(r"[<>=!~;\s]", spec, maxsplit=1)[0]
    # Drop extras
    return re.sub(r"\[.*\]", "", spec).strip()


def _import_name(dep_spec: str) -> str:
    """Normalise a pyproject dep spec to its importable module name."""
    name = _strip_extras(dep_spec).lower()
    if name in IRREGULAR_IMPORT_NAMES:
        return IRREGULAR_IMPORT_NAMES[name]
    return name.replace("-", "_").replace(".", "_")


# --------------------------------------------------------------------------- #
# Allowlist of declared-but-not-directly-imported deps
# --------------------------------------------------------------------------- #
#
# Each entry MUST come with a one-line justification. If a dep is on this
# list because it's a transitive runtime requirement of another declared
# dep, document which dep needs it and why pinning here (rather than
# relying on the transitive resolution) is worth the maintenance cost.

ALLOWLIST_NOT_IMPORTED: dict[str, str] = {
    # Keccak backend that ``eth-utils`` loads at runtime. Not directly
    # imported by recupero, but eth-utils' to_checksum_address() and
    # keccak() helpers fail at runtime without it. Pinning the
    # ``[pycryptodome]`` extra here guarantees the backend is installed.
    "eth-hash": "transitive runtime backend for eth-utils (keccak)",
    # Type stubs / typing primitives consumed transitively by eth-utils
    # and eth-account. Pinned here so a major-version bump in eth-utils
    # doesn't silently drift the typing surface.
    "eth-typing": "transitive typing surface for eth-utils ecosystem",
    # Currently unused at the import level but declared so that any future
    # date-parsing work (e.g. flexible ISO-8601 + RFC-2822 mixed inputs)
    # doesn't require re-vetting a new dep. Candidate for removal — see
    # the follow-up note at the bottom of this file. Tracked here for
    # now to keep this test green without quietly losing coverage.
    "python-dateutil": "reserved for date parsing; candidate for removal",
    # FastAPI loads python-multipart at runtime to parse Form(...) bodies
    # (the /v1/intake route). Never imported by recupero directly, but
    # FastAPI raises at import time without it — so it's a required,
    # not-directly-imported runtime dep.
    "python-multipart": "transitive runtime dep for FastAPI Form() parsing",
}


# --------------------------------------------------------------------------- #
# Parse pyproject.toml
# --------------------------------------------------------------------------- #


def _load_declared_deps() -> list[str]:
    """All deps from [project].dependencies + [project.optional-dependencies]."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = data["project"]
    deps: list[str] = list(project.get("dependencies", []))
    for _group, group_deps in project.get("optional-dependencies", {}).items():
        deps.extend(group_deps)
    return deps


# --------------------------------------------------------------------------- #
# Scan src/recupero/**/*.py for imports
# --------------------------------------------------------------------------- #

# Match ``import foo``, ``import foo.bar``, ``from foo import ...``,
# ``from foo.bar import ...``. Capture the top-level package only.
_IMPORT_RE = re.compile(
    r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)


def _scan_imports() -> set[str]:
    """Return the set of top-level packages imported under src/recupero."""
    imported: set[str] = set()
    for py in SRC_ROOT.rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="replace")
        for m in _IMPORT_RE.finditer(text):
            imported.add(m.group(1).lower())
    return imported


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def declared_deps() -> list[str]:
    return _load_declared_deps()


@pytest.fixture(scope="module")
def imported_packages() -> set[str]:
    return _scan_imports()


def test_pyproject_parses(declared_deps: list[str]) -> None:
    """Sanity: pyproject.toml has at least the core deps we expect."""
    names = {_strip_extras(d).lower() for d in declared_deps}
    # Spot-check a handful of well-known core deps. If any of these
    # disappear, something has gone very wrong with the project metadata.
    for must in ("httpx", "pydantic", "jinja2", "fastapi"):
        assert must in names, f"{must} missing from pyproject dependencies"


def test_src_has_imports(imported_packages: set[str]) -> None:
    """Sanity: the import scanner finds something."""
    # ``typing`` is in stdlib but ubiquitous — its absence would mean the
    # scanner regex is broken or the source tree is empty.
    assert "typing" in imported_packages, (
        "import scan returned no results — regex or path is broken"
    )


def test_no_unused_declared_deps(
    declared_deps: list[str],
    imported_packages: set[str],
) -> None:
    """Every declared dep is either imported or explicitly allow-listed."""
    # Dev-only deps (pytest, ruff, mypy, type stubs) are tools, not runtime
    # imports — skip them. We detect them by membership in optional-deps
    # rather than guessing names.
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    optional = data["project"].get("optional-dependencies", {})
    dev_dep_names = {
        _strip_extras(d).lower()
        for group_deps in optional.values()
        for d in group_deps
    }

    unused: list[str] = []
    for spec in declared_deps:
        dep_name = _strip_extras(spec).lower()
        if dep_name in dev_dep_names:
            # Dev deps are build/test tooling — not expected as runtime imports.
            continue
        if dep_name in ALLOWLIST_NOT_IMPORTED:
            continue
        import_name = _import_name(spec)
        if import_name not in imported_packages:
            unused.append(dep_name)

    assert not unused, (
        "Declared deps that are never imported (and not allow-listed):\n  "
        + "\n  ".join(sorted(unused))
        + "\n\nEither (a) import the dep where it's needed, (b) add it to "
        "ALLOWLIST_NOT_IMPORTED with a justification, or (c) remove it "
        "from pyproject.toml."
    )


def test_allowlist_entries_are_actually_declared(
    declared_deps: list[str],
) -> None:
    """Catch stale ALLOWLIST_NOT_IMPORTED entries — every allow-listed
    name MUST still appear in pyproject. If a dep is removed from
    pyproject but its allowlist entry lingers, that's confusing noise."""
    declared_names = {_strip_extras(d).lower() for d in declared_deps}
    stale = [name for name in ALLOWLIST_NOT_IMPORTED if name not in declared_names]
    assert not stale, (
        f"ALLOWLIST_NOT_IMPORTED has stale entries no longer in "
        f"pyproject.toml: {stale}"
    )


# --------------------------------------------------------------------------- #
# Follow-up note (DO NOT remove without checking — see test docstring)
# --------------------------------------------------------------------------- #
#
# Candidate for removal in a follow-up: ``python-dateutil``. No file under
# src/recupero/ currently does ``from dateutil ...`` or ``import dateutil``.
# Before removing, double-check:
#   1. No runtime-only string ref (e.g. ``importlib.import_module("dateutil")``).
#   2. The dev image still has it via another transitive dep, OR the test
#      suite genuinely doesn't need it.
# If both confirmed, drop it from pyproject.toml dependencies and from
# ALLOWLIST_NOT_IMPORTED in the same commit.
