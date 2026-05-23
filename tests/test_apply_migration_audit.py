"""Audit tests for scripts/apply_migration.py.

These are RED tests describing security/safety invariants the helper
should uphold when an operator hand-feeds it a .sql file:

  * Reject migration files outside the ``migrations/`` directory
    (operators should not be able to apply ``/tmp/whatever.sql`` or
    ``../../etc/passwd``).
  * Refuse pathologically large files (1 GB paste accidents).
  * Refuse migrations containing destructive DDL (``DROP TABLE``,
    ``DROP SCHEMA``, ``TRUNCATE``, ``ALTER USER ... PASSWORD``) unless
    the operator passes ``--yes-i-really-mean-it`` (confirmation).
  * Never echo the SQL body to stdout (an ``ALTER USER ... PASSWORD``
    would leak via trace logs).
  * Never echo the DSN to stdout/stderr when env var is missing or
    when the file path is bogus.

DB access is mocked at the ``psycopg.connect`` boundary. No real
network or DB calls happen in these tests.
"""

from __future__ import annotations

import importlib.util
import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import pytest

_REPO_ROOT = Path(__file__).parents[1]
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "apply_migration.py"
_spec = importlib.util.spec_from_file_location("apply_migration", _SCRIPT_PATH)
apply_migration = importlib.util.module_from_spec(_spec)
sys.modules["apply_migration"] = apply_migration
_spec.loader.exec_module(apply_migration)


_MIGRATIONS_DIR = _REPO_ROOT / "migrations"


def _run(argv: list[str]) -> tuple[int, str, str]:
    """Invoke ``apply_migration.main()`` with ``argv``; capture stdio."""
    out, err = io.StringIO(), io.StringIO()
    with patch.object(sys, "argv", ["apply_migration.py", *argv]):
        with redirect_stdout(out), redirect_stderr(err):
            rc = apply_migration.main()
    return rc, out.getvalue(), err.getvalue()


@pytest.fixture
def mock_psycopg(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace ``psycopg.connect`` with a no-op transactional mock."""
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    cur = MagicMock()
    cur.__enter__.return_value = cur
    cur.__exit__.return_value = False
    conn.cursor.return_value = cur
    factory = MagicMock(return_value=conn)
    monkeypatch.setattr(apply_migration.psycopg, "connect", factory)
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://u:p@127.0.0.1/test")
    return factory


# ---- 1. Path containment ---- #


def test_rejects_path_outside_migrations_dir(
    mock_psycopg: MagicMock, tmp_path: Path
) -> None:
    """An ad-hoc .sql sitting in /tmp must NOT be applicable."""
    stray = tmp_path / "ad_hoc.sql"
    stray.write_text("CREATE TABLE IF NOT EXISTS t (id int);")
    rc, _out, err = _run([str(stray)])
    assert rc != 0, "operator-supplied path outside migrations/ must be rejected"
    assert "migrations" in err.lower()
    mock_psycopg.assert_not_called()


def test_rejects_dotdot_traversal(mock_psycopg: MagicMock, tmp_path: Path) -> None:
    """A path that resolves outside ``migrations/`` via ``..`` is rejected."""
    target = _MIGRATIONS_DIR / ".." / "scripts" / "apply_migration.py"
    rc, _out, _err = _run([str(target)])
    assert rc != 0
    mock_psycopg.assert_not_called()


# ---- 2. Size cap ---- #


def test_rejects_oversized_file(
    mock_psycopg: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pathologically large file must be refused (paste-accident
    guard). We shrink the cap to a few bytes and feed the script a
    file that's an order of magnitude larger; the production-default
    1 GB-class behavior is the same code path with a different
    constant."""
    monkeypatch.setattr(apply_migration, "_MAX_SQL_BYTES", 64)
    big = _MIGRATIONS_DIR / "_oversized_audit_fixture.sql"
    big.write_text("-- " + ("x" * 4096) + "\n")
    try:
        rc, _out, err = _run([str(big)])
        assert rc != 0
        assert (
            "size" in err.lower()
            or "large" in err.lower()
            or "too big" in err.lower()
            or "exceed" in err.lower()
        )
        mock_psycopg.assert_not_called()
    finally:
        big.unlink(missing_ok=True)


# ---- 3. Destructive-DDL confirmation ---- #


@pytest.mark.parametrize(
    "stmt",
    [
        "DROP TABLE users;",
        "drop schema public cascade;",
        "TRUNCATE TABLE payments;",
        "ALTER USER postgres WITH PASSWORD 'hunter2';",
    ],
)
def test_destructive_ddl_requires_confirmation(
    mock_psycopg: MagicMock, stmt: str
) -> None:
    """Destructive DDL must NOT execute without --yes-i-really-mean-it."""
    fixture = _MIGRATIONS_DIR / "_destructive_audit_fixture.sql"
    fixture.write_text(stmt)
    try:
        rc, _out, err = _run([str(fixture)])
        assert rc != 0, f"destructive stmt slipped through unconfirmed: {stmt!r}"
        assert "confirm" in err.lower() or "destructive" in err.lower()
        mock_psycopg.assert_not_called()
    finally:
        fixture.unlink(missing_ok=True)


def test_destructive_ddl_runs_with_confirmation_flag(
    mock_psycopg: MagicMock,
) -> None:
    fixture = _MIGRATIONS_DIR / "_destructive_audit_fixture.sql"
    fixture.write_text("DROP TABLE legacy;")
    try:
        rc, _out, _err = _run([str(fixture), "--yes-i-really-mean-it"])
        assert rc == 0
        mock_psycopg.assert_called_once()
    finally:
        fixture.unlink(missing_ok=True)


# ---- 4. SQL body never logged ---- #


def test_sql_body_not_echoed_to_stdout(mock_psycopg: MagicMock) -> None:
    """The migration body must not appear on stdout (password-in-DDL leak)."""
    fixture = _MIGRATIONS_DIR / "_quiet_audit_fixture.sql"
    secret = "VERY_SECRET_TOKEN_DO_NOT_LOG_42"
    fixture.write_text(f"-- {secret}\nCREATE TABLE IF NOT EXISTS t (id int);\n")
    try:
        rc, out, err = _run([str(fixture)])
        assert rc == 0
        assert secret not in out
        assert secret not in err
    finally:
        fixture.unlink(missing_ok=True)


# ---- 5. DSN-leak hygiene ---- #


def test_dsn_not_echoed_when_env_missing(
    mock_psycopg: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Stub load_dotenv to a no-op so an upstream .env can't re-populate.
    monkeypatch.setattr(apply_migration, "load_dotenv", lambda *a, **k: None)
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    # Use a real migration file so we get past path validation.
    real = next(_MIGRATIONS_DIR.glob("[0-9]*.sql"))
    rc, out, err = _run([str(real)])
    assert rc != 0
    assert "postgresql://" not in out
    assert "postgresql://" not in err
