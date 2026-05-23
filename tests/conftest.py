"""Test-suite prod-DB safety net.

This conftest is at ``tests/`` (NOT at repo root). The root conftest.py
loads ``.env`` into ``os.environ`` at import time — including any
operator-supplied ``SUPABASE_DB_URL`` that may point at the live
Recupero production database. Without this file, every test process
inherits a live-prod DSN that ``db_connect()`` would happily dial.

This module runs at TEST-PACKAGE import time (before any
``test_*.py`` is collected and before any fixture, autouse or not,
executes). It performs three actions:

  1. If ``SUPABASE_DB_URL`` looks prod-shaped (DB name == 'postgres',
     or hostname matches Supabase's pooler/db domains, or no 'test' /
     '_int' substring in the DB name), it is COPIED into
     ``RECUPERO_PROD_SUPABASE_DB_URL_DO_NOT_USE`` for forensics, then
     REPLACED with a local test DSN built from ``PGPASSWORD`` (or a
     dummy DSN if PGPASSWORD is unset — the unit tests don't need a
     real connection).
  2. A ``pytest_runtest_setup`` hook re-asserts the invariant before
     every test, so a fixture that tries to set ``SUPABASE_DB_URL``
     back to prod will trip a ``RuntimeError`` rather than reach the
     live DB.
  3. A ``_assert_no_prod_dsn_leak`` helper is exposed for tests that
     want to assert prod DSN never appears in caplog output.

Naming convention: the stash key
``RECUPERO_PROD_SUPABASE_DB_URL_DO_NOT_USE`` is the ONLY place the
original prod DSN lives during test execution. Any code that reads
that key is opting in to a forensic audit. No fixture, helper, or
test should re-export it under another name.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest

# Public constants — tests import these to assert behavior.
PROD_DSN_STASH_KEY = "RECUPERO_PROD_SUPABASE_DB_URL_DO_NOT_USE"
LOCAL_TEST_DB_NAME_DEFAULT = "recupero_int_test"

# Sentinel DSN used when no PGPASSWORD is available. Unit tests
# (the vast majority) don't open a connection; this just keeps
# ``os.environ["SUPABASE_DB_URL"]`` non-empty so code paths that
# branch on "is the URL configured?" don't surprise-skip.
_DUMMY_LOCAL_DSN = (
    "postgresql://test_user:test_password@127.0.0.1:5432/"
    f"{LOCAL_TEST_DB_NAME_DEFAULT}"
)


def _looks_like_prod_dsn(dsn: str) -> bool:
    """Heuristic: does this DSN point at production?

    The cheapest reliable signal is the DB name. Production Supabase
    DSNs always target ``postgres`` (the default DB). A DSN whose
    final path segment is not ``postgres`` AND contains ``test`` or
    ``_int`` is considered safe.

    Hostname heuristic backs that up: any hostname under
    ``supabase.co`` / ``supabase.com`` / ``pooler.supabase.com`` is
    treated as prod regardless of DB name. This catches operators
    who created a hosted test database but left the hostname pointing
    at the live pooler.
    """
    if not dsn:
        return False
    try:
        parsed = urlparse(dsn)
    except ValueError:
        # Malformed DSN — refuse to claim it's safe.
        return True
    host = (parsed.hostname or "").lower()
    db_name = (parsed.path or "").lstrip("/").lower()
    # Strip any ``?`` query string the path might still carry.
    if "?" in db_name:
        db_name = db_name.split("?", 1)[0]
    # Hostname signal — any Supabase-hosted DB is treated as prod.
    suspicious_host_suffixes = (
        ".supabase.co",
        ".supabase.com",
        ".pooler.supabase.com",
    )
    if any(host.endswith(s) for s in suspicious_host_suffixes):
        return True
    # DB-name signal — ``postgres`` (default DB) or any DB whose
    # name lacks the test/_int substring.
    if db_name == "postgres":
        return True
    if db_name and "test" not in db_name and "_int" not in db_name:
        return True
    return False


def _local_test_dsn() -> str:
    """Build the local-test DSN we redirect to.

    Prefers ``PGPASSWORD`` and only returns it AFTER successfully
    probing the local Postgres — production code paths that read
    ``SUPABASE_DB_URL`` and try to connect should see a DSN that
    works, OR an empty string. A non-empty unreachable DSN is the
    worst-of-both: triggers DB-attempt logic that then fails with
    WARNING-level connection errors and breaks tests like
    test_v_cfi01_production_path that assert "no warnings emitted".

    If PGPASSWORD is unset OR the local probe fails, return ``""``
    so callers consistently see "no DB available" and skip cleanly.
    """
    pgpassword = (os.environ.get("PGPASSWORD") or "").strip()
    if not pgpassword:
        return ""
    candidate = (
        f"postgresql://postgres:{pgpassword}@127.0.0.1:5432/"
        f"{LOCAL_TEST_DB_NAME_DEFAULT}"
    )
    # Probe before committing. Don't import psycopg at module-load
    # time — defer to avoid any import-time side-effects when psycopg
    # is absent (CI sometimes ships without it for static-analysis-
    # only test runs).
    try:
        import psycopg
        with psycopg.connect(candidate, connect_timeout=2):
            return candidate
    except Exception:  # noqa: BLE001
        return ""


def _redirect_supabase_db_url_if_prod_shaped() -> None:
    """Run at module import time. Idempotent.

    Order of operations is paranoid: we read once, stash once, write
    once. No logging of the DSN itself — leaking it to stdout would
    defeat the point.
    """
    current = os.environ.get("SUPABASE_DB_URL", "")
    if not current:
        # Nothing to do — code that needs a DSN will skip or use the
        # explicit ``integration_dsn`` fixture's checks.
        return
    if not _looks_like_prod_dsn(current):
        # Already pointing at a local/test DB — leave it alone.
        return
    # Prod-shaped. Stash for forensics (only if we haven't already —
    # don't overwrite a prior stash on re-import).
    if PROD_DSN_STASH_KEY not in os.environ:
        os.environ[PROD_DSN_STASH_KEY] = current
    # Redirect.
    os.environ["SUPABASE_DB_URL"] = _local_test_dsn()


# Side-effect: run at conftest import. pytest imports the closest
# conftest before collecting tests, which happens before any fixture
# (autouse or otherwise) is executed.
_redirect_supabase_db_url_if_prod_shaped()


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Re-assert the invariant before every test.

    If a fixture or earlier test mutated ``SUPABASE_DB_URL`` back to
    a prod-shaped value, we trip here with a clear error rather than
    silently letting the test reach prod.
    """
    current = os.environ.get("SUPABASE_DB_URL", "")
    if _looks_like_prod_dsn(current):
        # Don't include the DSN itself in the message — keep the
        # operator's prod creds out of pytest output.
        raise RuntimeError(
            "SUPABASE_DB_URL points at a production-shaped DSN at "
            "test setup time. Conftest auto-redirects prod DSNs to "
            "the local test DB; something restored it. Check fixtures "
            "and parent processes. The original prod DSN (if any) "
            f"is stashed under {PROD_DSN_STASH_KEY!r}."
        )


def assert_no_prod_dsn_leak(text: str) -> None:
    """Helper: raise AssertionError if the stashed prod DSN appears in ``text``.

    Tests pass caplog output (or any captured string) through this
    helper to verify nothing leaked the prod creds.
    """
    stashed = os.environ.get(PROD_DSN_STASH_KEY, "")
    if not stashed:
        return  # Nothing to leak — no prod DSN was ever loaded.
    # Compare against the whole DSN AND its password component
    # individually — a logger might mask the URL but still print
    # the password by itself.
    if stashed in text:
        raise AssertionError(
            "Captured text contains the stashed prod DSN. Conftest "
            "must NEVER allow the prod DSN to reach test stdout/"
            "stderr/logs."
        )
    try:
        parsed = urlparse(stashed)
    except ValueError:
        return
    password = parsed.password
    if password and password in text:
        raise AssertionError(
            "Captured text contains the prod DSN password component."
        )
