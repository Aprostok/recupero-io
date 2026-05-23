"""Prod-DB safety net for the test suite.

These tests pin the invariants documented in tests/conftest.py:

  1. The root conftest loads ``.env`` into ``os.environ``. If the
     operator's ``.env`` contains a live ``SUPABASE_DB_URL``, the
     tests/conftest.py must (a) stash it under
     ``RECUPERO_PROD_SUPABASE_DB_URL_DO_NOT_USE`` and (b) overwrite
     ``SUPABASE_DB_URL`` with a local test DSN BEFORE any test or
     fixture runs.
  2. No env var, marker, or fixture can re-enable the prod DSN
     mid-test — the conftest's ``pytest_runtest_setup`` hook raises
     before such a test could begin its body.
  3. The prod DSN string must never appear in caplog output during
     a benign test path.

If conftest regresses (operator drops a fresh ``.env`` with a live
DSN, someone refactors the redirect away), these tests go RED in
seconds.
"""

from __future__ import annotations

import logging
import os

import pytest

from tests.conftest import (
    LOCAL_TEST_DB_NAME_DEFAULT,
    PROD_DSN_STASH_KEY,
    _looks_like_prod_dsn,
    assert_no_prod_dsn_leak,
)

PROD_LIKE_DSN = (
    "postgresql://postgres.pooler:supersecretprodpw@aws-0-us-east-1."
    "pooler.supabase.com:6543/postgres"
)


def test_supabase_db_url_is_not_prod_at_test_time() -> None:
    """At test execution time, SUPABASE_DB_URL must NOT be prod-shaped.

    This pins the redirect at conftest import time. If a future
    refactor breaks the auto-redirect, this is the canary.
    """
    current = os.environ.get("SUPABASE_DB_URL", "")
    # Either empty (fine — code skips when unset) or a local/test DSN.
    assert not _looks_like_prod_dsn(current), (
        "SUPABASE_DB_URL looks prod-shaped at test time; conftest "
        "auto-redirect failed."
    )


def test_supabase_db_url_points_at_local_test_db_when_present() -> None:
    """If SUPABASE_DB_URL is set after conftest ran, it must target
    a local test DB (DB name contains 'test' or '_int')."""
    current = os.environ.get("SUPABASE_DB_URL", "")
    if not current:
        pytest.skip("SUPABASE_DB_URL unset — nothing to assert about.")
    # Cheapest check: the DB-name segment.
    from urllib.parse import urlparse
    db_name = (urlparse(current).path or "").lstrip("/").lower()
    assert (
        "test" in db_name
        or "_int" in db_name
        or db_name == LOCAL_TEST_DB_NAME_DEFAULT
    ), f"Redirected DSN's DB name is not test-shaped: {db_name!r}"


def test_prod_dsn_stash_key_is_the_only_alias() -> None:
    """If a prod DSN was loaded from .env, it lives ONLY under
    ``RECUPERO_PROD_SUPABASE_DB_URL_DO_NOT_USE`` — no second alias."""
    stashed = os.environ.get(PROD_DSN_STASH_KEY)
    if not stashed:
        pytest.skip("No prod DSN was stashed — operator has no .env DSN.")
    # Scan os.environ for any OTHER key whose value matches the
    # stashed DSN. SUPABASE_DB_URL itself must NOT match (the redirect
    # should have replaced it).
    for key, val in os.environ.items():
        if key == PROD_DSN_STASH_KEY:
            continue
        assert val != stashed, (
            f"Env var {key!r} duplicates the stashed prod DSN. Only "
            f"{PROD_DSN_STASH_KEY!r} may hold it."
        )


def test_bypass_via_monkeypatch_is_blocked_by_setup_hook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A test (or upstream fixture) that resets ``SUPABASE_DB_URL`` to
    a prod-shaped value must trigger the conftest's
    ``pytest_runtest_setup`` re-assertion on the NEXT test.

    We verify directly: invoke the hook on a fake item with prod-DSN
    in env and assert it raises.
    """
    from tests import conftest as ct

    monkeypatch.setenv("SUPABASE_DB_URL", PROD_LIKE_DSN)

    class _FakeItem:
        name = "fake"

    with pytest.raises(RuntimeError, match="production-shaped"):
        ct.pytest_runtest_setup(_FakeItem())  # type: ignore[arg-type]


def test_looks_like_prod_dsn_classification() -> None:
    """Pin the prod-DSN heuristic against known-good and known-bad
    inputs so a future loosening of the rules can't sneak past."""
    # Prod-shaped (must be flagged):
    assert _looks_like_prod_dsn(PROD_LIKE_DSN)
    assert _looks_like_prod_dsn(
        "postgresql://postgres:pw@db.abcdef.supabase.co:5432/postgres"
    )
    assert _looks_like_prod_dsn(
        "postgresql://u:p@host:5432/recupero_main"  # no test/_int substring
    )
    # Safe (must NOT be flagged):
    assert not _looks_like_prod_dsn(
        "postgresql://postgres:pw@127.0.0.1:5432/recupero_int_test"
    )
    assert not _looks_like_prod_dsn(
        "postgresql://u:p@localhost:5432/recupero_test_db"
    )
    assert not _looks_like_prod_dsn("")  # empty is a no-op


def test_conftest_does_not_log_prod_dsn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A benign test must produce zero caplog records containing the
    stashed prod DSN. Conftest must never print/log it."""
    stashed = os.environ.get(PROD_DSN_STASH_KEY, "")
    if not stashed:
        pytest.skip("No prod DSN stashed — nothing to leak.")
    with caplog.at_level(logging.DEBUG):
        # Benign work that uses the conftest module.
        from tests.conftest import _local_test_dsn  # noqa: PLC0415
        _ = _local_test_dsn()
    full_text = "\n".join(r.getMessage() for r in caplog.records)
    assert_no_prod_dsn_leak(full_text)


def test_assert_no_prod_dsn_leak_helper_catches_full_dsn() -> None:
    """The helper itself must catch a leaked DSN substring. If no
    prod DSN is stashed, the helper is a no-op (skip)."""
    stashed = os.environ.get(PROD_DSN_STASH_KEY, "")
    if not stashed:
        pytest.skip("No prod DSN stashed — helper is a no-op.")
    with pytest.raises(AssertionError, match="prod DSN"):
        assert_no_prod_dsn_leak(f"some log line containing {stashed}")
    # Negative control: benign text passes through.
    assert_no_prod_dsn_leak("nothing sensitive here")
