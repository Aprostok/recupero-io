"""Unit tests for the tenant maintenance passes (completion metering + retention).

The pure retention-window policy is tested directly against ``tenancy.PLANS``.
The two SQL passes are exercised through a recording fake cursor so we lock the
important invariants (idempotency guard, org-scoping, one DELETE per plan)
without needing a live Postgres.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from recupero.platform import retention, tenancy


class _FakeCursor:
    def __init__(self, *, fetch_rows=None, rowcount=0):
        self.executed: list[tuple[str, object]] = []
        self._fetch_rows = fetch_rows or []
        self.rowcount = rowcount

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchall(self):
        return list(self._fetch_rows)


class _FakeConn:
    def __init__(self, cursor: _FakeCursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor


# ---- pure retention policy ---- #

def test_retention_cutoffs_match_plan_windows() -> None:
    now = datetime(2026, 7, 6, tzinfo=UTC)
    cutoffs = retention.retention_cutoffs(now=now)
    # Every plan is represented, and each cutoff is exactly retention_days back.
    assert set(cutoffs) == set(tenancy.PLANS)
    for name, plan in tenancy.PLANS.items():
        assert cutoffs[name] == now - timedelta(days=plan.retention_days)


def test_retention_free_shorter_than_enterprise() -> None:
    now = datetime(2026, 7, 6, tzinfo=UTC)
    cutoffs = retention.retention_cutoffs(now=now)
    # Free retains the least (most-recent cutoff), enterprise the most.
    assert cutoffs["free"] > cutoffs["pro"] > cutoffs["enterprise"]


def test_retention_cutoffs_default_now_is_utc_aware() -> None:
    cutoffs = retention.retention_cutoffs()
    assert cutoffs["free"].tzinfo is not None


# ---- completion metering ---- #

def test_reconcile_meters_completed_and_is_idempotent_by_construction() -> None:
    # Two finished jobs lacked a trace_completed event → two rows inserted.
    cur = _FakeCursor(fetch_rows=[(1,), (2,)])
    added = retention.reconcile_completed_traces(_FakeConn(cur))
    assert added == 2
    sql, params = cur.executed[0]
    # The idempotency guard + tenant-scoping + correct kind are all present.
    assert "NOT EXISTS" in sql
    assert "'trace_completed'" in sql
    assert "org_id IS NOT NULL" in sql
    assert params == ("complete",)


def test_reconcile_returns_zero_when_nothing_new() -> None:
    cur = _FakeCursor(fetch_rows=[])
    assert retention.reconcile_completed_traces(_FakeConn(cur)) == 0


# ---- retention purge ---- #

def test_purge_runs_one_delete_per_plan_and_sums_rowcounts() -> None:
    cur = _FakeCursor(rowcount=3)
    now = datetime(2026, 7, 6, tzinfo=UTC)
    deleted = retention.purge_expired_cases(_FakeConn(cur), now=now)
    # One DELETE per plan, each reporting rowcount=3.
    assert len(cur.executed) == len(tenancy.PLANS)
    assert deleted == 3 * len(tenancy.PLANS)
    plan_params = {p[1][0] for p in cur.executed}
    assert plan_params == set(tenancy.PLANS)
    for sql, params in cur.executed:
        assert "DELETE FROM public.investigations" in sql
        assert "i.status IN ('complete', 'failed')" in sql
        # cutoff is the second bound param, derived from the plan window.
        assert isinstance(params[1], datetime)


def test_run_maintenance_reports_both_passes() -> None:
    cur = _FakeCursor(fetch_rows=[(1,)], rowcount=0)
    summary = retention.run_maintenance(_FakeConn(cur))
    assert summary == {"metered": 1, "purged": 0}


# ---- cron registration ---- #

def test_platform_maintenance_job_registered() -> None:
    from recupero.worker import cron_scheduler

    names = {j.name for j in cron_scheduler._build_default_jobs()}
    assert "platform_maintenance" in names
