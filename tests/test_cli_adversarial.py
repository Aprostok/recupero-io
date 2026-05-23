"""Adversarial-input tests for the recupero CLI.

Patterns covered:
  * --investigation-id rejects path-traversal payloads
  * --investigation-id accepts legitimate UUID-shaped tokens
  * --investigation-id rejects oversized inputs
  * _validate_investigation_id is callable directly
"""

from __future__ import annotations

import pytest
import typer


def test_validate_investigation_id_rejects_traversal() -> None:
    from recupero.cli import _validate_investigation_id
    with pytest.raises(typer.BadParameter):
        _validate_investigation_id("../../etc/passwd")


def test_validate_investigation_id_rejects_slash() -> None:
    from recupero.cli import _validate_investigation_id
    with pytest.raises(typer.BadParameter):
        _validate_investigation_id("foo/bar")


def test_validate_investigation_id_rejects_backslash() -> None:
    from recupero.cli import _validate_investigation_id
    with pytest.raises(typer.BadParameter):
        _validate_investigation_id("foo\\bar")


def test_validate_investigation_id_rejects_null_byte() -> None:
    from recupero.cli import _validate_investigation_id
    with pytest.raises(typer.BadParameter):
        _validate_investigation_id("ok\x00stuffed")


def test_validate_investigation_id_rejects_newline() -> None:
    from recupero.cli import _validate_investigation_id
    with pytest.raises(typer.BadParameter):
        _validate_investigation_id("ok\nfake")


def test_validate_investigation_id_rejects_oversized() -> None:
    from recupero.cli import _validate_investigation_id
    with pytest.raises(typer.BadParameter):
        _validate_investigation_id("a" * 65)


def test_validate_investigation_id_rejects_empty() -> None:
    """Empty string would be treated as a relative path component
    when concatenated; reject it."""
    from recupero.cli import _validate_investigation_id
    with pytest.raises(typer.BadParameter):
        _validate_investigation_id("")


def test_validate_investigation_id_accepts_uuid() -> None:
    """Valid UUIDv4 tokens must pass — preserves existing CLI behavior."""
    from recupero.cli import _validate_investigation_id
    _validate_investigation_id("550e8400-e29b-41d4-a716-446655440000")


def test_validate_investigation_id_accepts_short_token() -> None:
    """A 12-char hex investigation id (worker-generated correlation ids)
    must still pass."""
    from recupero.cli import _validate_investigation_id
    _validate_investigation_id("abc123def456")


def test_validate_investigation_id_none_is_noop() -> None:
    """None means --investigation-id wasn't passed — that's the default
    and must not crash."""
    from recupero.cli import _validate_investigation_id
    _validate_investigation_id(None)
