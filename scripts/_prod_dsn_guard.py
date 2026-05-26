"""v0.30.2 (V030_2_SCRIPTS_AUDIT T1-A) — prod-DSN guardrail for scripts.

`tests/conftest.py` already enforces this invariant for the test suite
(redirects prod-shaped SUPABASE_DB_URL to a local test DSN). The same
shape was MISSING from operational scripts — `insert_validation_row.py`,
`approve_validation_row.py`, and `e2e_smoke.py` all call
`load_dotenv(override=True)` and connect blind, meaning an operator who
runs them locally with a `.env` that contains a prod DSN gets a live
prod connection. In the `e2e_smoke.py` case, this is followed by
`DELETE FROM public.investigations` + `DELETE FROM public.cases` in a
`finally` block (keyed by UUID, not catastrophic — but a synthetic
record gets created and consumes a Stripe webhook).

This module exposes one function: `assert_not_prod_dsn(action)` that
inspects `os.environ["SUPABASE_DB_URL"]` and raises if it looks
production-shaped, unless the caller explicitly opts in via
`RECUPERO_ALLOW_PROD_DSN=1`. The check uses the same heuristics as
`tests/conftest.py::_looks_like_prod_dsn` so dev/test ergonomics are
consistent.

Usage:
    from _prod_dsn_guard import assert_not_prod_dsn
    assert_not_prod_dsn("running e2e_smoke insert+delete")
"""
from __future__ import annotations

import os
from urllib.parse import urlparse


def _looks_like_prod_dsn(dsn: str) -> bool:
    """Heuristic: does this DSN look like Supabase production?

    A prod-shaped DSN matches one of:
      - Supabase pooler host (`*.pooler.supabase.com`,
        `aws-*-pooler.supabase.com`)
      - Supabase direct host (`db.*.supabase.co`)
      - DB name "postgres" (Supabase default) AND no "_int" / "test"
        / "_local" substring anywhere in the URL
    Local-test DSNs typically have `_int_test` / `localhost` /
    `127.0.0.1` / a non-default DB name.
    """
    if not dsn:
        return False
    try:
        parsed = urlparse(dsn)
    except Exception:  # noqa: BLE001
        return False
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "/").lstrip("/")
    db_name = path.split("?", 1)[0]

    # Local hosts are NEVER prod, even if the DB happens to be called
    # "postgres".
    if host in ("localhost", "127.0.0.1", "::1") or host.startswith("192.168.") or host.startswith("10."):
        return False

    if "pooler.supabase.com" in host or host.startswith("db.") and host.endswith(".supabase.co"):
        return True

    if db_name == "postgres":
        lowered_url = dsn.lower()
        if "test" in lowered_url or "_int" in lowered_url or "_local" in lowered_url:
            return False
        return True

    return False


_OPT_IN_ENV_VAR = "RECUPERO_ALLOW_PROD_DSN"


def assert_not_prod_dsn(action: str) -> None:
    """Raise RuntimeError if the active SUPABASE_DB_URL looks
    production-shaped.

    Set `RECUPERO_ALLOW_PROD_DSN=1` to opt in (e.g. for a manual
    operator-confirmed prod-data operation). Without that env var,
    every script that calls this helper will refuse to talk to prod.

    Args:
      action: short string describing what the script is about to do,
        included in the error message so an operator knows why it
        bailed.
    """
    if os.environ.get(_OPT_IN_ENV_VAR, "").strip() in ("1", "true", "yes", "on"):
        return
    dsn = os.environ.get("SUPABASE_DB_URL", "")
    if _looks_like_prod_dsn(dsn):
        # Redact the password component before quoting in the error.
        try:
            parsed = urlparse(dsn)
            host = parsed.hostname or "(unknown host)"
        except Exception:  # noqa: BLE001
            host = "(unparseable)"
        raise RuntimeError(
            f"REFUSING: SUPABASE_DB_URL points at a production-shaped "
            f"host ({host}). The action {action!r} would run against "
            f"prod data. If this is genuinely intended (DB backfill, "
            f"approved migration, etc.), set "
            f"{_OPT_IN_ENV_VAR}=1 and re-run. Otherwise, point "
            f"SUPABASE_DB_URL at a local test DB before running this "
            f"script."
        )
