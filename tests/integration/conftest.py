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
from pathlib import Path
from typing import Iterator

import pytest


@pytest.fixture(scope="session", autouse=True)
def integration_enabled() -> None:
    """Skip the entire integration-test package unless opted in.

    Set ``RECUPERO_RUN_INTEGRATION=1`` to enable. We refuse to run if
    the variable is unset so a routine `pytest tests/` doesn't hit
    external services or burn API budget.
    """
    if (os.environ.get("RECUPERO_RUN_INTEGRATION") or "").strip() != "1":
        pytest.skip(
            "Integration tests require RECUPERO_RUN_INTEGRATION=1. "
            "See tests/integration/README.md for setup.",
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
    # Safety guard
    lowered = raw.lower()
    if "/postgres" in lowered or "test" not in lowered and "_int" not in lowered:
        pytest.skip(
            "Refusing to run integration DB tests against a DSN whose "
            "db name doesn't contain 'test' or '_int'. Point "
            "RECUPERO_INTEGRATION_DSN at a dedicated test DB."
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
