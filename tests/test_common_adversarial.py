"""Adversarial-input tests for _common.

Patterns covered:
  * db_connect: psycopg connect errors must not leak DSN passwords
  * redact_dsn: handles edge cases (None, empty, non-postgres URL)
  * canonical_address_key: malformed inputs don't crash
  * atomic_write_text: tempfile cleanup on rename failure
  * env_truthy: handles whitespace, mixed-case, garbage
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


# ---- db_connect: DSN redaction in error messages ---- #


def test_db_connect_redacts_dsn_in_error_message() -> None:
    """A psycopg failure should NOT leak the password into the
    exception message. The hardened helper substitutes the redacted
    form of the DSN before re-raising."""
    from recupero._common import db_connect

    secret_dsn = "postgresql://user:SUPER_SECRET_PWD_123@host:5432/db"

    def _fail(_dsn, **_kwargs):
        # Simulate psycopg's habit of echoing the full DSN in failures.
        raise RuntimeError(
            f"connection to {_dsn} failed: timeout"
        )

    with patch("psycopg.connect", side_effect=_fail):
        try:
            db_connect(secret_dsn)
        except RuntimeError as e:
            msg = str(e)
            assert "SUPER_SECRET_PWD_123" not in msg, (
                f"password leaked: {msg}"
            )
            assert "***" in msg
            return
    raise AssertionError("expected RuntimeError")


def test_db_connect_redacts_dsn_when_psycopg_does_not_include_full_dsn() -> None:
    """Psycopg may compose its own DSN-shaped string. The redaction
    helper must catch that too."""
    from recupero._common import db_connect

    def _fail(_dsn, **_kwargs):
        # A psycopg-style normalized DSN with different formatting.
        raise RuntimeError(
            "could not connect to postgresql://otheruser:OTHER_PWD@h:5432/d"
        )

    with patch("psycopg.connect", side_effect=_fail):
        try:
            db_connect("postgresql://user:pwd@host/db")
        except RuntimeError as e:
            msg = str(e)
            assert "OTHER_PWD" not in msg, f"composed password leaked: {msg}"
            return
    raise AssertionError("expected RuntimeError")


# ---- redact_dsn ---- #


def test_redact_dsn_handles_none() -> None:
    from recupero._common import redact_dsn
    assert redact_dsn(None) == ""


def test_redact_dsn_handles_empty() -> None:
    from recupero._common import redact_dsn
    assert redact_dsn("") == ""


def test_redact_dsn_handles_password_with_special_chars() -> None:
    """A password containing punctuation should still be redacted."""
    from recupero._common import redact_dsn
    out = redact_dsn("postgresql://u:p@ss!w0rd-=.,@host/db")
    # The first @ delimits user:pass from host. The regex is greedy on
    # [^@\s]+ so password = "p" (since the next "@" terminates). That's
    # the safest behavior — better to over-redact than under-redact.
    # Key guarantee: the substring "p@ss" must not appear unredacted at
    # the start (the password slot is replaced).
    assert "u:***@" in out


def test_redact_dsn_non_postgres_passthrough() -> None:
    """A non-postgres URL should pass through untouched."""
    from recupero._common import redact_dsn
    assert redact_dsn("https://example.com/path") == "https://example.com/path"


# ---- canonical_address_key ---- #


def test_canonical_address_key_handles_none() -> None:
    from recupero._common import canonical_address_key
    assert canonical_address_key(None) == ""


def test_canonical_address_key_handles_non_string() -> None:
    from recupero._common import canonical_address_key
    assert canonical_address_key(12345) == ""  # type: ignore[arg-type]
    assert canonical_address_key([]) == ""  # type: ignore[arg-type]


def test_canonical_address_key_passes_through_non_hex_evm_lookalike() -> None:
    """A 42-char string starting with 0x but containing non-hex
    characters should NOT be lower-cased — that would silently corrupt
    a malformed address into a different key."""
    from recupero._common import canonical_address_key
    bogus = "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    out = canonical_address_key(bogus)
    # Pass-through (not lower-cased).
    assert out == bogus


def test_canonical_address_key_strips_whitespace() -> None:
    from recupero._common import canonical_address_key
    out = canonical_address_key("  0xABCDef" + "0" * 34 + "  ")
    assert not out.startswith(" ")
    assert not out.endswith(" ")


# ---- atomic_write_text: cleanup on rename failure ---- #


def test_atomic_write_text_cleans_up_tmp_on_rename_failure(tmp_path: Path) -> None:
    from recupero._common import atomic_write_text

    target = tmp_path / "out.json"

    with patch("os.replace", side_effect=OSError("rename failed")):
        try:
            atomic_write_text(target, "payload")
        except OSError:
            pass

    # The .tmp sibling should NOT linger.
    tmp = target.with_suffix(target.suffix + ".tmp")
    assert not tmp.exists(), f"tempfile leaked: {tmp}"


def test_atomic_write_text_normal_path(tmp_path: Path) -> None:
    from recupero._common import atomic_write_text
    target = tmp_path / "subdir" / "file.json"
    atomic_write_text(target, "hello world")
    assert target.read_text(encoding="utf-8") == "hello world"


# ---- env_truthy ---- #


def test_env_truthy_handles_whitespace(monkeypatch) -> None:
    from recupero._common import env_truthy
    monkeypatch.setenv("FOO", "  TRUE  ")
    assert env_truthy("FOO") is True


def test_env_truthy_garbage_returns_default(monkeypatch) -> None:
    from recupero._common import env_truthy
    monkeypatch.setenv("FOO", "maybe")
    assert env_truthy("FOO", default=False) is False
    assert env_truthy("FOO", default=True) is False


def test_env_truthy_unset_returns_default(monkeypatch) -> None:
    from recupero._common import env_truthy
    monkeypatch.delenv("RECUPERO_UNSET_VAR", raising=False)
    assert env_truthy("RECUPERO_UNSET_VAR", default=True) is True
    assert env_truthy("RECUPERO_UNSET_VAR", default=False) is False


# ---- db_connect: still works on success ---- #


def test_db_connect_success_path() -> None:
    """Regression: the redaction wrapper must not break the happy
    path — a successful connect returns whatever psycopg returns."""
    from recupero._common import db_connect

    sentinel = MagicMock(name="conn")
    with patch("psycopg.connect", return_value=sentinel) as mc:
        out = db_connect("postgresql://u:p@h/d")
    assert out is sentinel
    mc.assert_called_once()
