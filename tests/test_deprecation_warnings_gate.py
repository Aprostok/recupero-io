"""Deprecation-warning gate (v0.27.x).

Imports every module under the ``recupero.*`` namespace and asserts that
no ``DeprecationWarning`` / ``PendingDeprecationWarning`` is raised by
*our* source during import.

Python 3.14 escalated several long-pending deprecations to hard removals
in 3.15+ (``datetime.utcnow``, ``pkg_resources``, several ``asyncio``
loop helpers, ``typing.io`` / ``typing.re``, etc.). We want to catch
those at CI time *for code we own*; third-party deprecations are out of
scope (operators can't fix them without an upstream release), so the
companion ``filterwarnings`` entry in ``pyproject.toml`` is scoped to
``recupero.*`` only.

Why import-time and not just rely on the pytest filter:
  - The ``filterwarnings = error::DeprecationWarning:recupero.*`` filter
    only fires on warnings emitted while some *other* test is running.
    Warnings emitted purely at module-import time (e.g. a module-level
    ``datetime.utcnow()`` call) fire during pytest's collection phase
    and can slip through depending on collection order.
  - This test imports every module under a ``warnings.catch_warnings()``
    block with ``simplefilter('always')`` so we positively *see* every
    warning, then filter to recupero-owned ones and fail loudly with
    the full list.
"""

from __future__ import annotations

import importlib
import pkgutil
import warnings
from pathlib import Path

import pytest

import recupero

# Modules that are expensive / have heavy side effects (DB connects,
# network probes, model loads) and should be skipped from the *import*
# sweep. Add sparingly — the point of this gate is broad coverage.
_IMPORT_SKIP: frozenset[str] = frozenset(
    {
        # `recupero.worker.main` registers a typer CLI at import time;
        # safe but noisy. Kept in for now — remove only if it ever
        # starts doing real work at import.
    }
)


def _all_recupero_modules() -> list[str]:
    """Walk the recupero package and return every importable dotted name."""
    out: list[str] = ["recupero"]
    for info in pkgutil.walk_packages(recupero.__path__, prefix="recupero."):
        out.append(info.name)
    return sorted(out)


def _is_recupero_source(filename: str | None) -> bool:
    """True iff the warning was raised from a file inside src/recupero."""
    if not filename:
        return False
    # Normalize path separators so the test works on both Windows and POSIX.
    norm = filename.replace("\\", "/").lower()
    # Match either an installed location (.../site-packages/recupero/...)
    # or the in-tree source layout (.../src/recupero/...). We deliberately
    # match BOTH `/recupero/` and `\recupero\` (already normalized above).
    return "/recupero/" in norm or norm.endswith("/recupero")


def test_no_deprecation_warnings_on_import() -> None:
    """No recupero module emits a DeprecationWarning on import.

    If this fails, the message lists every offending (module, warning,
    file:line) tuple — fix the source, don't add a per-warning suppression.
    """
    modules = _all_recupero_modules()

    caught: list[tuple[str, str, str, int]] = []

    with warnings.catch_warnings():
        # Bypass the project-level pytest filter so we see *everything*
        # and can classify ourselves.
        warnings.resetwarnings()
        warnings.simplefilter("always")

        # Capture into our list rather than letting pytest's recwarn /
        # the filterwarnings escalator turn them into immediate errors —
        # we want to report ALL of them at once, not the first one.
        original_showwarning = warnings.showwarning

        def _capture(message, category, filename, lineno, file=None, line=None):  # type: ignore[no-untyped-def]
            caught.append((str(message), category.__name__, filename or "", lineno or 0))

        warnings.showwarning = _capture
        try:
            for modname in modules:
                if modname in _IMPORT_SKIP:
                    continue
                try:
                    importlib.import_module(modname)
                except ImportError:
                    # Optional / lazy-imported deps (graphviz binary,
                    # weasyprint native libs, etc.) may legitimately
                    # be unavailable in the dev sandbox. Skipping the
                    # import is fine — the deprecation gate only cares
                    # about modules that *do* load.
                    continue
        finally:
            warnings.showwarning = original_showwarning

    offenders = [
        w
        for w in caught
        if w[1] in {"DeprecationWarning", "PendingDeprecationWarning"}
        and _is_recupero_source(w[2])
    ]

    if offenders:
        lines = [
            f"  - [{cat}] {msg}\n      at {fname}:{lineno}"
            for (msg, cat, fname, lineno) in offenders
        ]
        pytest.fail(
            "DeprecationWarning(s) raised by recupero source during import.\n"
            "Fix the underlying call site — do NOT add a per-warning ignore.\n"
            "Offending warnings:\n" + "\n".join(lines),
            pytrace=False,
        )


def test_filterwarnings_gate_configured() -> None:
    """pyproject.toml has the recupero-scoped DeprecationWarning gate wired up.

    Belt-and-braces check so a future refactor that drops the
    ``filterwarnings`` entry from ``[tool.pytest.ini_options]`` fails
    loudly here instead of silently disabling the call-time gate.
    """
    # Find pyproject.toml by walking up from this test file. The repo
    # root is several levels up when this lives in a worktree, so the
    # safest thing is to look for the marker file.
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        candidate = parent / "pyproject.toml"
        if candidate.is_file():
            text = candidate.read_text(encoding="utf-8")
            break
    else:
        pytest.fail("could not locate pyproject.toml from test file")

    # Cheap substring asserts — we don't want to pull in tomllib + parse
    # just to confirm two filter strings are present.
    assert (
        'error::DeprecationWarning:recupero' in text
    ), "pyproject.toml is missing the recupero-scoped DeprecationWarning gate"
    assert (
        'error::PendingDeprecationWarning:recupero' in text
    ), "pyproject.toml is missing the recupero-scoped PendingDeprecationWarning gate"
