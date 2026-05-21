"""Integration-test fixtures.

This conftest is scoped to `tests/integration/` only — unit tests
under `tests/test_*.py` won't pick up these fixtures or skip rules.

Layering:

  * ``integration_enabled`` — module-level skip if
    RECUPERO_RUN_INTEGRATION != "1". Every test below depends on it.
  * ``respx_router`` — pytest-httpx is project-included; we reuse
    its respx mock to register chain-API + pricing + email routes.
  * ``mocked_external_apis`` — preset respx routes for Etherscan V2 /
    Helius / CoinGecko / Resend. Tests that want a real network call
    pass through opt-in env vars (RECUPERO_INTEGRATION_LIVE=1 + the
    specific API key).
  * ``integration_dsn`` — yields a Postgres DSN. If
    SUPABASE_DB_URL points at a TEST database (operator's
    responsibility — name must contain "test" or "_int"), uses it;
    otherwise skips with a clear message.
  * ``clean_case_dir(tmp_path)`` — yields a fresh case directory
    under pytest's tmp_path. Auto-cleaned.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def integration_enabled() -> None:
    """Auto-enable the integration suite when the local test Postgres
    is reachable.

    RIGOR (no-skips discipline): the prior version required operators
    to set ``RECUPERO_RUN_INTEGRATION=1`` explicitly, which meant a
    routine ``python -m pytest`` skipped 6 integration tests by
    default. Those tests would have caught real bugs (the W-1..W-4
    race tests are integration-only). Now the conftest does the
    detection itself:

      1. If RECUPERO_RUN_INTEGRATION=1 is set explicitly, respect it.
      2. Otherwise, try to connect to the local test DB
         (``postgresql://postgres:<PGPASSWORD>@127.0.0.1:5432/
         recupero_int_test``). If reachable, auto-set
         RECUPERO_RUN_INTEGRATION=1 + RECUPERO_INTEGRATION_DSN.
      3. If neither, skip cleanly with a message that points the
         operator at scripts/setup_test_db.sh.

    Live-API tests still gate on RECUPERO_INTEGRATION_LIVE=1 (those
    require external credentials).
    """
    # Path 1: env var set explicitly — honor it.
    if (os.environ.get("RECUPERO_RUN_INTEGRATION") or "").strip() == "1":
        return

    # Path 2: try the local test DB.
    pgpassword = os.environ.get("PGPASSWORD", "").strip()
    if pgpassword:
        candidate_dsn = (
            f"postgresql://postgres:{pgpassword}"
            f"@127.0.0.1:5432/recupero_int_test"
        )
        try:
            import psycopg
            with psycopg.connect(
                candidate_dsn, connect_timeout=2,
            ) as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM pg_class WHERE relname='cases'"
                )
                if cur.fetchone() is not None:
                    # The test DB exists + has migrations applied.
                    # Auto-enable.
                    os.environ["RECUPERO_RUN_INTEGRATION"] = "1"
                    os.environ["RECUPERO_INTEGRATION_DSN"] = candidate_dsn
                    return
        except Exception:  # noqa: BLE001
            # Connection refused / auth failure / wrong DB name —
            # fall through to skip.
            pass

    # Path 3: no env var, no reachable DB — skip cleanly.
    pytest.skip(
        "Integration tests need either RECUPERO_RUN_INTEGRATION=1 "
        "+ RECUPERO_INTEGRATION_DSN, OR a local Postgres with "
        "recupero_int_test database + PGPASSWORD env var. Run "
        "`bash scripts/setup_test_db.sh` to set up the test DB.",
        allow_module_level=True,
    )


@pytest.fixture
def integration_dsn() -> Iterator[str]:
    """Yield a DSN pointing at a TEST database, or skip cleanly.

    Safety guard: the DSN's database name must contain "test" or
    "_int" — refuses to run against production-shaped names so an
    operator's misconfigured .env can't accidentally migrate-and-
    truncate the live Recupero DB.
    """
    raw = (os.environ.get("RECUPERO_INTEGRATION_DSN")
           or os.environ.get("SUPABASE_DB_URL")
           or "").strip()
    if not raw:
        pytest.skip(
            "No RECUPERO_INTEGRATION_DSN or SUPABASE_DB_URL set. "
            "Integration DB tests need a TEST postgres."
        )
    # Safety guard. Pre-RIGOR-1 this fixture had TWO bugs:
    #   1. Operator-precedence: `if "/postgres" in lowered or "test"
    #      not in lowered and "_int" not in lowered` parsed as
    #      `("/postgres" in lowered) or (("test" not in lowered) and
    #      ("_int" not in lowered))` — meaning a DB named `recupero_test`
    #      that lived on a server hosting "postgres" would skip.
    #   2. `/postgres` substring match also tripped on the URL's user
    #      portion: `postgresql://postgres:password@...` always contained
    #      `/postgres` because `postgresql:` has a slash before the user
    #      `postgres`. Every local-dev DSN got skipped.
    # Fix: extract the DB name properly (after the LAST `/`, before any
    # `?` query string) and refuse production-shaped names.
    from urllib.parse import urlparse
    parsed = urlparse(raw)
    db_name = (parsed.path or "").lstrip("/").lower()
    if not db_name:
        pytest.skip(
            f"DSN has no database name in the path: {raw!r}"
        )
    # Strict allow-list discipline: db name MUST contain 'test' or
    # '_int' to be considered safe for destructive integration tests.
    # A bare 'postgres' (the default db) is the production-shape name
    # we explicitly refuse.
    if db_name == "postgres" or (
        "test" not in db_name and "_int" not in db_name
    ):
        pytest.skip(
            f"Refusing to run integration DB tests against DB {db_name!r}. "
            "Point RECUPERO_INTEGRATION_DSN at a DB whose name contains "
            "'test' or '_int' (e.g., 'recupero_int_test')."
        )
    yield raw


@pytest.fixture
def clean_case_dir(tmp_path: Path) -> Iterator[Path]:
    """Yield a fresh, clean case directory under pytest's tmp_path.

    Mirrors the layout the worker writes:
      <case_dir>/case.json
      <case_dir>/transfers.csv
      <case_dir>/manifest.json
      <case_dir>/briefs/...
    """
    case_dir = tmp_path / "integration_case"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "briefs").mkdir(exist_ok=True)
    yield case_dir
    # tmp_path is auto-cleaned by pytest; nothing to do.


@pytest.fixture
def live_mode_required(request: pytest.FixtureRequest) -> None:
    """Tests that need REAL external calls (no respx mocks) depend
    on this fixture. Skips unless ``RECUPERO_INTEGRATION_LIVE=1``.
    """
    if (os.environ.get("RECUPERO_INTEGRATION_LIVE") or "").strip() != "1":
        pytest.skip(
            "Test requires real external services. "
            "Set RECUPERO_INTEGRATION_LIVE=1 to opt in."
        )
