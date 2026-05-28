"""v0.30.2 regression tests for `scripts/_prod_dsn_guard.py`.

Pins the V030_2_SCRIPTS_AUDIT T1-A contract: any prod-shaped
SUPABASE_DB_URL refuses unless `RECUPERO_ALLOW_PROD_DSN=1` is set.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

# Add scripts/ to sys.path so the guard module is importable.
_SCRIPTS = Path(__file__).parent.parent / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

_prod_dsn_guard = importlib.import_module("_prod_dsn_guard")


# ──────────────────────────────────────────────────────────────────────
# _looks_like_prod_dsn
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("dsn", [
    "postgresql://postgres:p@aws-0-us-west-1.pooler.supabase.com:5432/postgres",
    "postgres://postgres.proj:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres",
    "postgresql://postgres:p@db.abcdefghij.supabase.co:5432/postgres",
    "postgresql://app:p@somehost.example.com:5432/postgres",  # bare 'postgres' DB
])
def test_prod_shaped_dsns_classified_correctly(dsn: str) -> None:
    """Supabase pooler / Supabase direct / bare 'postgres' DB =
    prod-shaped. The check is defensive — better to false-positive
    than false-negative on a destructive script."""
    assert _prod_dsn_guard._looks_like_prod_dsn(dsn), (
        f"DSN {dsn!r} should have been classified prod-shaped"
    )


@pytest.mark.parametrize("dsn", [
    "postgresql://test_user:t@127.0.0.1:5432/recupero_int_test",
    "postgresql://test_user:t@localhost:5432/recupero_test",
    "postgresql://app:p@somehost.example.com:5432/recupero_local",
    "postgresql://app:p@somehost.example.com:5432/something_test_thing",
    "postgresql://app:p@10.0.0.5:5432/postgres",  # private network
    "postgresql://app:p@192.168.1.10:5432/postgres",  # private LAN
    "",
    None,
])
def test_local_test_dsns_not_classified_prod(dsn: str | None) -> None:
    """Local/test DSNs (loopback, private network, _test suffix,
    explicit _int_test substring) must NOT be classified prod-shaped —
    otherwise dev ergonomics break."""
    assert not _prod_dsn_guard._looks_like_prod_dsn(dsn or ""), (
        f"DSN {dsn!r} was wrongly classified prod-shaped"
    )


# ──────────────────────────────────────────────────────────────────────
# assert_not_prod_dsn
# ──────────────────────────────────────────────────────────────────────


def test_assert_not_prod_dsn_raises_on_prod_shape(monkeypatch) -> None:
    monkeypatch.setenv(
        "SUPABASE_DB_URL",
        "postgresql://postgres:p@aws-0-us-east-1.pooler.supabase.com:5432/postgres",
    )
    monkeypatch.delenv("RECUPERO_ALLOW_PROD_DSN", raising=False)
    with pytest.raises(RuntimeError, match="REFUSING"):
        _prod_dsn_guard.assert_not_prod_dsn("test action")


def test_assert_not_prod_dsn_passes_on_local(monkeypatch) -> None:
    monkeypatch.setenv(
        "SUPABASE_DB_URL",
        "postgresql://test_user:t@127.0.0.1:5432/recupero_int_test",
    )
    monkeypatch.delenv("RECUPERO_ALLOW_PROD_DSN", raising=False)
    # Must NOT raise.
    _prod_dsn_guard.assert_not_prod_dsn("test action")


def test_assert_not_prod_dsn_opt_in_bypasses_check(monkeypatch) -> None:
    """RECUPERO_ALLOW_PROD_DSN=1 explicit opt-in lets the operator
    deliberately run a script against prod (e.g., an approved
    backfill). Without the explicit env var, prod DSNs refuse."""
    monkeypatch.setenv(
        "SUPABASE_DB_URL",
        "postgresql://postgres:p@aws-0-us-east-1.pooler.supabase.com:5432/postgres",
    )
    monkeypatch.setenv("RECUPERO_ALLOW_PROD_DSN", "1")
    # Must NOT raise.
    _prod_dsn_guard.assert_not_prod_dsn("intentional prod action")


def test_assert_not_prod_dsn_error_redacts_password(monkeypatch) -> None:
    """The error message must NOT include the password component of
    the DSN — pytest output / logs / Sentry might capture it."""
    monkeypatch.setenv(
        "SUPABASE_DB_URL",
        "postgresql://postgres:SECRET_PASSWORD_xyz123@aws-0-us-east-1.pooler.supabase.com:5432/postgres",
    )
    monkeypatch.delenv("RECUPERO_ALLOW_PROD_DSN", raising=False)
    try:
        _prod_dsn_guard.assert_not_prod_dsn("test")
        pytest.fail("expected RuntimeError")
    except RuntimeError as exc:
        msg = str(exc)
        assert "SECRET_PASSWORD_xyz123" not in msg, (
            "Prod DSN password leaked into error message — redact "
            "before raising."
        )
