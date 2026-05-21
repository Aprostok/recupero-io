"""Unit tests for the pure helpers in worker/dashboard_summary.

The dashboard_summary builds the JSON payload the admin UI's
homepage polls. Most of it is read-only SQL but the pure-Python
helpers — the empty-payload shapes and the Supabase pooler DSN
rewrite — are worth locking down:

  * Empty shapes are the contract the UI binds to. If a sub-query
    silently fails we still return the same JSON keys with zeros,
    so the UI never breaks on a missing key.
  * The pooler DSN rewrite is what makes the worker not exhaust
    Supabase's direct-connection pool. Getting this wrong takes
    the worker offline under load.
"""

from __future__ import annotations

from recupero.worker.dashboard_summary import (
    _empty_cases,
    _empty_digest,
    _empty_investigations,
    _empty_snapshots,
    _empty_stale_engagements,
    _empty_stale_review,
    _empty_watchlist,
    _pooled_dsn,
)

# ---- empty shapes (UI contract) ---- #


def test_empty_cases_shape() -> None:
    """Locked schema for the ``cases`` section of dashboard.json.
    The UI keys against these field names — adding/removing one
    here is a breaking UI change."""
    out = _empty_cases()
    assert set(out.keys()) == {"total", "intake", "investigating",
                               "ready_for_le", "closed"}
    assert all(v == 0 for v in out.values())


def test_empty_investigations_shape() -> None:
    out = _empty_investigations()
    assert set(out.keys()) == {"pending", "active", "awaiting_review",
                               "complete", "failed", "total_api_costs_usd"}
    # Counters are int 0, total_api_costs_usd is a Decimal-stringified "0.0000".
    assert out["pending"] == 0
    assert out["active"] == 0
    assert out["total_api_costs_usd"] == "0.0000"


def test_empty_watchlist_shape() -> None:
    out = _empty_watchlist()
    assert set(out.keys()) == {"active", "standard", "hot", "paused",
                               "freezeable", "total_balance_usd"}
    assert out["active"] == 0
    assert out["total_balance_usd"] == "0.00"


def test_empty_snapshots_shape() -> None:
    out = _empty_snapshots()
    assert set(out.keys()) == {"in_last_24h", "material_changes_24h",
                               "freezeable_changes_24h"}
    assert all(v == 0 for v in out.values())


def test_empty_digest_shape() -> None:
    """Digest section has 3 nullable string fields (no last digest
    is a valid steady state for a freshly-deployed worker)."""
    out = _empty_digest()
    assert set(out.keys()) == {"last_run_at", "latest_digest_id", "latest_path"}
    assert all(v is None for v in out.values())


def test_empty_stale_review_shape() -> None:
    """stale_review section surfaces investigations stuck in
    awaiting_review past the staleness threshold. Empty shape means
    "no rows past the threshold" — the UI renders an "all caught up"
    state. Keys are locked so the UI's "needs attention" widget
    binds to a stable contract."""
    out = _empty_stale_review()
    assert set(out.keys()) == {"count", "threshold_hours", "rows"}
    assert out["count"] == 0
    assert out["threshold_hours"] == 24
    assert out["rows"] == []


def test_empty_stale_engagements_shape() -> None:
    """stale_engagements surfaces active engagements that have aged
    past the 30-day commitment window without being marked closed.
    Same UI-contract reasoning as stale_review — empty shape is the
    healthy steady state, keys are locked so the homepage's "needs
    closing" widget binds against a stable contract.

    Note: threshold is in DAYS (engagement cadence), not hours
    (review cadence). The two sections use different units on
    purpose — don't unify them."""
    out = _empty_stale_engagements()
    assert set(out.keys()) == {"count", "threshold_days", "rows"}
    assert out["count"] == 0
    assert out["threshold_days"] == 30
    assert out["rows"] == []


# ---- _pooled_dsn ---- #


def test_pooled_dsn_rewrites_supabase_direct() -> None:
    """A direct-connection Supabase DSN gets rewritten to the
    pooler form. This is what stops the worker from exhausting
    Supabase's direct-connection pool under load."""
    direct = (
        "postgresql://postgres:somepassword@db.abcdef12345.supabase.co:5432/postgres"
    )
    pooled = _pooled_dsn(direct)
    # Pooler host
    assert "pooler.supabase.com" in pooled
    assert "db." not in pooled or "db.abcdef" not in pooled
    # Pooler port is 6543, not 5432
    assert ":6543/" in pooled
    # Username gets the project ref appended (postgres.abcdef12345)
    assert "postgres.abcdef12345" in pooled


def test_pooled_dsn_preserves_password() -> None:
    """Password must survive the rewrite — getting this wrong locks
    the worker out of the DB entirely."""
    pwd = "s0me-r4ndom-p4ssw0rd"
    direct = f"postgresql://postgres:{pwd}@db.xyz789.supabase.co:5432/postgres"
    pooled = _pooled_dsn(direct)
    assert pwd in pooled


def test_pooled_dsn_passes_non_supabase_through() -> None:
    """A DSN that isn't a Supabase direct-connection URL passes
    through verbatim — local dev against a private Postgres, CI
    pointed at a test fixture, etc."""
    local = "postgresql://test:test@localhost:5432/recupero_test"
    assert _pooled_dsn(local) == local


def test_pooled_dsn_passes_already_pooled_through() -> None:
    """If the DSN is already on the pooler hostname, don't double-
    rewrite it. The regex specifically targets the direct ``db.<ref>
    .supabase.co`` form."""
    already_pooled = (
        "postgresql://postgres.abc123:pwd"
        "@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
    )
    assert _pooled_dsn(already_pooled) == already_pooled


def test_pooled_dsn_handles_postgres_scheme_variant() -> None:
    """Both ``postgresql://`` and ``postgres://`` are valid Postgres
    URL schemes. The rewrite must accept either."""
    direct_alt_scheme = (
        "postgres://postgres:pwd@db.xyz789.supabase.co:5432/postgres"
    )
    pooled = _pooled_dsn(direct_alt_scheme)
    assert "pooler.supabase.com" in pooled
    assert "postgres.xyz789" in pooled


def test_pooled_dsn_empty_string_returns_empty() -> None:
    """Empty input → empty output (defensive — caller is expected
    to handle the empty-config case at a higher level)."""
    assert _pooled_dsn("") == ""


def test_pooled_dsn_url_with_query_string() -> None:
    """A DSN with extra query params (sslmode=require, etc.) — the
    rewrite currently doesn't preserve query params after the
    transformation. Lock the current behavior so any future change
    is intentional."""
    direct_with_qs = (
        "postgresql://postgres:pwd@db.foo123.supabase.co:5432/postgres?sslmode=require"
    )
    pooled = _pooled_dsn(direct_with_qs)
    # The current implementation rewrites up to the path and drops
    # everything after the host:port/db section. If we ever need to
    # preserve query params, update the regex AND this test.
    assert "pooler.supabase.com" in pooled
    assert ":6543/postgres" in pooled
