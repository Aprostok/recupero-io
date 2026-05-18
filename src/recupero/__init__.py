"""Recupero — trace stolen crypto to law-enforcement-actionable endpoints."""

from __future__ import annotations


def _resolve_version() -> str:
    """Resolve the package version from installed metadata.

    Falls back to a placeholder if the package isn't installed (rare;
    happens in source-tree-only invocations before `pip install -e .`).
    """
    try:
        from importlib.metadata import version as _v
        return _v("recupero")
    except Exception:  # noqa: BLE001
        return "0.0.0+unknown"


__version__ = _resolve_version()
