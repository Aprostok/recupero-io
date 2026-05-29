"""v0.32 — Tier-1 gap #3: cron scheduler HA + alerting + observability.

Pins the closures of `docs/WHY_RECUPERO_WOULD_FAIL.md` §1.3 ("single
instance cron"):

  * Postgres leader election — two scheduler instances race, only one
    acquires the lock (the other sees the row's lease is still valid
    and gets zero rows back from the ON CONFLICT UPDATE).
  * Lock expiry — a stale lock (past expires_at_utc) yields to the
    next replica that races to acquire.
  * Job success/failure tracking — last_success_utc + counters reset
    on success; last_error_* + bump on failure.
  * Webhook fires only at consecutive_failures >= 2 (one transient
    blip can't page on-call).
  * Webhook failure doesn't crash the scheduler.
  * /cron/healthz returns down / degraded / ok per the documented
    roll-up rules.
  * Local-dev (no DSN) — scheduler logs a WARN and runs without
    locking (so a developer working offline gets a working scheduler
    instead of a no-op).

The DB-touching tests use a fake in-memory cursor (no psycopg
required) to keep CI green on machines without a Postgres.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest

from recupero.worker import cron_scheduler

# ─────────────────────────────────────────────────────────────────────────────
# Fake in-memory cron_jobs_lock store
# ─────────────────────────────────────────────────────────────────────────────


class _FakeRow:
    """A minimal cron_jobs_lock row with mutable fields."""

    __slots__ = (
        "job_name", "leader_id", "acquired_at_utc", "expires_at_utc",
        "last_success_utc", "last_error_utc", "last_error_message",
        "consecutive_failures",
    )

    def __init__(self, job_name, leader_id, acquired_at_utc, expires_at_utc):
        self.job_name = job_name
        self.leader_id = leader_id
        self.acquired_at_utc = acquired_at_utc
        self.expires_at_utc = expires_at_utc
        self.last_success_utc = None
        self.last_error_utc = None
        self.last_error_message = None
        self.consecutive_failures = 0


class _FakeDB:
    """Module-state singleton storing the cron_jobs_lock table.

    Plugged in via a monkeypatched ``db_connect`` so the scheduler's
    real SQL paths exercise exactly the same code, while we sidestep
    the need for a live Postgres.
    """

    def __init__(self):
        self.rows: dict[str, _FakeRow] = {}

    def reset(self) -> None:
        self.rows.clear()


# Module-scoped singleton so tests share the same fake table when
# they want to verify two-instance races within one test.
_DB = _FakeDB()


class _FakeCursor:
    def __init__(self, db: _FakeDB):
        self._db = db
        self._result: list = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql: str, params=()):  # noqa: PLR0912 — fake SQL dispatcher
        sql = " ".join(sql.split())  # collapse whitespace
        self._result = []

        if sql.startswith("INSERT INTO public.cron_jobs_lock"):
            # _try_acquire_lock SQL.
            job_name, leader_id, acquired_at, expires_at = params
            existing = self._db.rows.get(job_name)
            now = datetime.now(UTC)
            if existing is None:
                # First insert — wins.
                row = _FakeRow(job_name, leader_id, acquired_at, expires_at)
                self._db.rows[job_name] = row
                self._result = [(leader_id,)]
            else:
                # ON CONFLICT path. WHERE: existing.expires_at_utc < NOW()
                #   OR existing.leader_id == EXCLUDED.leader_id
                expires_in_past = existing.expires_at_utc < now
                same_leader = existing.leader_id == leader_id
                if expires_in_past or same_leader:
                    existing.leader_id = leader_id
                    existing.acquired_at_utc = acquired_at
                    existing.expires_at_utc = expires_at
                    self._result = [(existing.leader_id,)]
                else:
                    # WHERE failed → no rows updated.
                    self._result = []
            return

        if sql.startswith("UPDATE public.cron_jobs_lock SET last_success_utc"):
            # _record_job_success.
            (job_name,) = params
            row = self._db.rows.get(job_name)
            if row is not None:
                row.last_success_utc = datetime.now(UTC)
                row.consecutive_failures = 0
                row.last_error_utc = None
                row.last_error_message = None
            return

        if sql.startswith("UPDATE public.cron_jobs_lock SET last_error_utc"):
            # _record_job_failure.
            msg, job_name = params
            row = self._db.rows.get(job_name)
            if row is None:
                self._result = []
                return
            row.last_error_utc = datetime.now(UTC)
            row.last_error_message = msg
            row.consecutive_failures += 1
            self._result = [(row.consecutive_failures,)]
            return

        if sql.startswith("SELECT job_name, last_success_utc"):
            # build_cron_healthz_payload.
            self._result = [
                (
                    r.job_name, r.last_success_utc, r.last_error_utc,
                    r.last_error_message, r.consecutive_failures,
                )
                for r in self._db.rows.values()
            ]
            return

        raise NotImplementedError(f"FakeCursor doesn't handle: {sql[:80]!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return list(self._result)


class _FakeConn:
    def __init__(self, db: _FakeDB):
        self._db = db

    def cursor(self):
        return _FakeCursor(self._db)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture(autouse=True)
def _patch_db_connect(monkeypatch):
    """Route ``recupero._common.db_connect`` to the in-memory fake.

    Also force ``SUPABASE_DB_URL`` to a non-empty placeholder so the
    scheduler's "local dev" branch doesn't trip — tests opt into the
    no-DSN path explicitly by clearing it.
    """
    _DB.reset()
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://test/test")
    monkeypatch.delenv("RECUPERO_CRON_ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("HOSTNAME", raising=False)
    monkeypatch.delenv("RAILWAY_REPLICA_ID", raising=False)
    monkeypatch.delenv("RECUPERO_CRON_LEASE_SECONDS", raising=False)
    monkeypatch.delenv("RECUPERO_CRON_HEALTHZ_STALE_HOURS", raising=False)

    def _fake_db_connect(dsn, **kwargs):
        return _FakeConn(_DB)

    # Patch via sys.modules so the import inside cron_scheduler picks
    # it up regardless of import order.
    monkeypatch.setattr(
        "recupero._common.db_connect", _fake_db_connect,
    )
    yield
    _DB.reset()


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────


def test_two_instances_race_only_one_acquires(monkeypatch):
    """Test 1: leader election — two replicas race, exactly one wins."""
    monkeypatch.setenv("HOSTNAME", "replica-A")
    ok_a = cron_scheduler._try_acquire_lock("ofac_sync")
    monkeypatch.setenv("HOSTNAME", "replica-B")
    ok_b = cron_scheduler._try_acquire_lock("ofac_sync")
    assert ok_a is True, "first replica must win the fresh row"
    assert ok_b is False, (
        "second replica must lose — the existing lease is still "
        "valid and the leader_id differs"
    )


def test_lock_expiry_lets_next_replica_acquire(monkeypatch):
    """Test 2: a stale lock (past expires_at_utc) is stealable."""
    monkeypatch.setenv("HOSTNAME", "replica-A")
    monkeypatch.setenv("RECUPERO_CRON_LEASE_SECONDS", "60")
    assert cron_scheduler._try_acquire_lock("ofac_sync") is True

    # Forcibly age the lease into the past.
    row = _DB.rows["ofac_sync"]
    row.expires_at_utc = datetime.now(UTC) - timedelta(seconds=10)

    monkeypatch.setenv("HOSTNAME", "replica-B")
    assert cron_scheduler._try_acquire_lock("ofac_sync") is True, (
        "a stale lease must be claimable by the next racing replica"
    )
    assert _DB.rows["ofac_sync"].leader_id.startswith("replica-B"), (
        "the row should now reflect replica-B as the leader"
    )


def test_same_leader_re_acquires_idempotently(monkeypatch):
    """Test 2b: the same replica re-acquiring its own valid lease is
    a no-op success. Pin this — without it, a single replica's normal
    next-tick acquire would think someone else stole the lock."""
    monkeypatch.setenv("HOSTNAME", "replica-A")
    assert cron_scheduler._try_acquire_lock("ofac_sync") is True
    # Same replica re-acquires before the lease expires — still wins.
    assert cron_scheduler._try_acquire_lock("ofac_sync") is True


def test_job_success_sets_last_success_and_resets_failures(monkeypatch):
    """Test 3: a clean run writes last_success_utc + zeroes failures."""
    monkeypatch.setenv("HOSTNAME", "replica-A")
    cron_scheduler._try_acquire_lock("ofac_sync")
    # Simulate two failures, then a success.
    _DB.rows["ofac_sync"].consecutive_failures = 2
    _DB.rows["ofac_sync"].last_error_message = "boom"

    cron_scheduler._record_job_success("ofac_sync")

    row = _DB.rows["ofac_sync"]
    assert row.last_success_utc is not None
    assert row.consecutive_failures == 0
    assert row.last_error_message is None
    assert row.last_error_utc is None


def test_job_failure_bumps_counters_and_sets_error(monkeypatch):
    """Test 4: a failure writes last_error_* and increments
    consecutive_failures."""
    monkeypatch.setenv("HOSTNAME", "replica-A")
    cron_scheduler._try_acquire_lock("ofac_sync")
    err = RuntimeError("OFAC SDN feed 502 Bad Gateway")
    failures = cron_scheduler._record_job_failure("ofac_sync", err)
    assert failures == 1

    failures = cron_scheduler._record_job_failure("ofac_sync", err)
    assert failures == 2

    row = _DB.rows["ofac_sync"]
    assert row.consecutive_failures == 2
    assert row.last_error_utc is not None
    assert "OFAC SDN feed 502" in row.last_error_message


def test_webhook_fires_at_threshold(monkeypatch):
    """Test 5: webhook fires only when consecutive_failures >= 2."""
    monkeypatch.setenv(
        "RECUPERO_CRON_ALERT_WEBHOOK_URL", "https://example.test/hook",
    )
    posted = []

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None):
            posted.append((url, json))

            class R:
                status_code = 200

            return R()

    monkeypatch.setattr("httpx.Client", _FakeClient)

    cron_scheduler._post_error_webhook(
        "ofac_sync", RuntimeError("boom"), consecutive_failures=2,
    )
    assert len(posted) == 1, "webhook must fire at threshold (2)"
    url, payload = posted[0]
    assert url == "https://example.test/hook"
    assert payload["text"].startswith("cron job ofac_sync failed")
    # Slack-style shape.
    assert "attachments" in payload
    assert payload["attachments"][0]["color"] == "danger"


def test_webhook_does_NOT_fire_on_first_failure(monkeypatch):
    """Test 6: one transient blip must not page."""
    monkeypatch.setenv(
        "RECUPERO_CRON_ALERT_WEBHOOK_URL", "https://example.test/hook",
    )
    posted = []

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None):
            posted.append((url, json))

            class R:
                status_code = 200

            return R()

    monkeypatch.setattr("httpx.Client", _FakeClient)

    cron_scheduler._post_error_webhook(
        "ofac_sync", RuntimeError("boom"), consecutive_failures=1,
    )
    assert posted == [], (
        "one-time failure must NOT fire the webhook — the threshold "
        "is 2 by design"
    )


def test_webhook_timeout_does_not_crash_scheduler(monkeypatch):
    """Test 7: a webhook delivery failure must NOT propagate.

    The alerting mechanism is best-effort. A bad URL or a hung
    receiver must log a WARN and return; raising would defeat the
    whole point.
    """
    monkeypatch.setenv(
        "RECUPERO_CRON_ALERT_WEBHOOK_URL", "https://example.test/hook",
    )

    class _BoomClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, *a, **kw):
            raise OSError("connection refused")

    monkeypatch.setattr("httpx.Client", _BoomClient)

    # Must not raise.
    cron_scheduler._post_error_webhook(
        "ofac_sync", RuntimeError("boom"), consecutive_failures=5,
    )


def test_webhook_url_unset_is_silent_no_call(monkeypatch):
    """Test 8: unset webhook URL → silent (no httpx.Client touch).

    Pin this so we don't accidentally page on an unset receiver.
    """
    monkeypatch.delenv("RECUPERO_CRON_ALERT_WEBHOOK_URL", raising=False)
    called = []

    class _ShouldNotBeCalled:
        def __init__(self, *a, **kw):
            called.append("instantiated")

    monkeypatch.setattr("httpx.Client", _ShouldNotBeCalled)

    cron_scheduler._post_error_webhook(
        "ofac_sync", RuntimeError("boom"), consecutive_failures=5,
    )
    assert called == [], (
        "with no webhook URL set, the alerter must not even "
        "construct an httpx.Client"
    )


def test_healthz_returns_down_when_job_never_succeeded():
    """Test 9: last_success_utc IS NULL → job status="down"."""
    # Don't insert any rows — every expected job is unseen.
    payload = cron_scheduler.build_cron_healthz_payload()
    assert payload["status"] == "down"
    for name, job in payload["jobs"].items():
        assert job["status"] == "down", (
            f"{name} has no row → must report 'down'"
        )
        assert job["last_success_utc"] is None


def test_healthz_returns_ok_when_all_jobs_fresh():
    """Test 10: every job < 25h old → top-level 'ok'."""
    fresh = datetime.now(UTC) - timedelta(hours=1)
    expected = {j.name for j in cron_scheduler._build_default_jobs()}
    for name in expected:
        row = _FakeRow(
            job_name=name, leader_id="x",
            acquired_at_utc=fresh, expires_at_utc=fresh + timedelta(minutes=5),
        )
        row.last_success_utc = fresh
        _DB.rows[name] = row

    payload = cron_scheduler.build_cron_healthz_payload()
    assert payload["status"] == "ok"
    for job in payload["jobs"].values():
        assert job["status"] == "ok"
        assert job["hours_since_last_success"] < 25


def test_healthz_degraded_when_one_job_stale():
    """Test 11: one stale job + others ok → top-level 'degraded'."""
    fresh = datetime.now(UTC) - timedelta(hours=1)
    stale = datetime.now(UTC) - timedelta(hours=30)  # > 25h, < 168h

    expected = [j.name for j in cron_scheduler._build_default_jobs()]
    for i, name in enumerate(expected):
        ts = stale if i == 0 else fresh
        row = _FakeRow(
            job_name=name, leader_id="x",
            acquired_at_utc=ts, expires_at_utc=ts + timedelta(minutes=5),
        )
        row.last_success_utc = ts
        _DB.rows[name] = row

    payload = cron_scheduler.build_cron_healthz_payload()
    assert payload["status"] == "degraded"
    assert payload["jobs"][expected[0]]["status"] == "stale"
    for n in expected[1:]:
        assert payload["jobs"][n]["status"] == "ok"


def test_healthz_down_when_any_job_past_one_week():
    """Test 12: any job > 168h → status='down' regardless of others."""
    fresh = datetime.now(UTC) - timedelta(hours=1)
    dead = datetime.now(UTC) - timedelta(hours=200)  # > 168h

    expected = [j.name for j in cron_scheduler._build_default_jobs()]
    for i, name in enumerate(expected):
        ts = dead if i == 0 else fresh
        row = _FakeRow(
            job_name=name, leader_id="x",
            acquired_at_utc=ts, expires_at_utc=ts + timedelta(minutes=5),
        )
        row.last_success_utc = ts
        _DB.rows[name] = row

    payload = cron_scheduler.build_cron_healthz_payload()
    assert payload["status"] == "down"
    assert payload["jobs"][expected[0]]["status"] == "down"


def test_local_dev_no_dsn_bypasses_locking(monkeypatch, caplog):
    """Test 13: SUPABASE_DB_URL unset → WARN + acquire returns True
    without hitting any DB.

    Without this, a developer on a laptop with no Postgres would see
    every job-fire skipped silently — terrible UX. We choose to run
    the job (with a loud WARN) so local-dev workflows keep working.
    """
    monkeypatch.setenv("SUPABASE_DB_URL", "")
    called = []

    def _should_not_be_called(*a, **kw):
        called.append("hit")
        raise AssertionError("db_connect must not be reached without a DSN")

    monkeypatch.setattr("recupero._common.db_connect", _should_not_be_called)
    with caplog.at_level(logging.WARNING):
        ok = cron_scheduler._try_acquire_lock("ofac_sync")
    assert ok is True, "no-DSN path must allow the job to run"
    assert called == []
    assert any(
        "bypassing leader election" in rec.message for rec in caplog.records
    ), "no-DSN path must log a loud WARN"


def test_db_error_during_acquire_fails_closed(monkeypatch, caplog):
    """Test 14: a DB error during acquire MUST return False so we
    don't fire the job — another replica might."""
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://test/test")

    def _boom(*a, **kw):
        raise RuntimeError("db is down")

    monkeypatch.setattr("recupero._common.db_connect", _boom)
    with caplog.at_level(logging.ERROR):
        ok = cron_scheduler._try_acquire_lock("ofac_sync")
    assert ok is False, (
        "fail-closed on DB error — firing the job here could let two "
        "replicas double-run if one of them can talk to the DB and one "
        "can't"
    )
    assert any("refusing to fire" in r.message for r in caplog.records)


def test_safe_error_text_redacts_dsn_credentials():
    """Test 15: an exception carrying a DSN with a password must NOT
    leak that password into the webhook payload or the
    last_error_message column."""
    err = RuntimeError(
        "connection failed: postgresql://user:hunter2@host:5432/db"
    )
    out = cron_scheduler._safe_error_text(err)
    assert "hunter2" not in out, "DSN password leaked"
    assert "***" in out


def test_safe_error_text_redacts_api_key_substring():
    """Test 15b: api_key=sk_live_... substrings get masked."""
    err = RuntimeError("auth failed: api_key=sk_live_deadbeefdeadbeef")
    out = cron_scheduler._safe_error_text(err)
    assert "sk_live_deadbeefdeadbeef" not in out
    assert "***" in out


def test_safe_error_text_truncates_long_messages():
    """Test 15c: a giant traceback string is truncated so it doesn't
    blow the row or the webhook payload."""
    err = RuntimeError("x" * 5000)
    out = cron_scheduler._safe_error_text(err)
    assert len(out) <= 1000


def test_fire_job_skips_when_lock_held_by_other(monkeypatch, caplog):
    """Test 16: _fire_job logs INFO + skips when another leader holds
    the lock — does not call the job function."""
    monkeypatch.setenv("HOSTNAME", "replica-A")
    cron_scheduler._try_acquire_lock("ofac_sync")  # A holds the lock

    monkeypatch.setenv("HOSTNAME", "replica-B")
    called = []

    def _job():
        called.append("ran")

    j = cron_scheduler.CronJob(
        name="ofac_sync",
        schedule_fn=lambda now: now,
        run_fn=_job,
    )
    with caplog.at_level(logging.INFO):
        cron_scheduler._fire_job(j)
    assert called == [], "must NOT run the job when another leader holds the lock"
    assert any(
        "held by another leader" in r.message for r in caplog.records
    )


def test_fire_job_full_failure_path_journals_and_alerts(monkeypatch):
    """Test 17: end-to-end — _fire_job catches the exception,
    journals the failure, and fires the webhook at threshold."""
    monkeypatch.setenv("HOSTNAME", "replica-A")
    monkeypatch.setenv(
        "RECUPERO_CRON_ALERT_WEBHOOK_URL", "https://example.test/hook",
    )
    posted = []

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None):
            posted.append(json)

            class R:
                status_code = 200

            return R()

    monkeypatch.setattr("httpx.Client", _FakeClient)

    def _flaky():
        raise RuntimeError("boom")

    j = cron_scheduler.CronJob(
        name="ofac_sync",
        schedule_fn=lambda now: now,
        run_fn=_flaky,
    )
    # First fire — failure 1 (no webhook yet).
    cron_scheduler._fire_job(j)
    assert _DB.rows["ofac_sync"].consecutive_failures == 1
    assert posted == [], "no page on first failure"

    # Second fire — failure 2 (webhook fires).
    cron_scheduler._fire_job(j)
    assert _DB.rows["ofac_sync"].consecutive_failures == 2
    assert len(posted) == 1
    assert posted[0]["text"].startswith("cron job ofac_sync failed")


def test_fire_job_success_path_resets_counters(monkeypatch):
    """Test 18: a successful run after failures clears the counters."""
    monkeypatch.setenv("HOSTNAME", "replica-A")

    # Seed the row with two failures.
    cron_scheduler._try_acquire_lock("ofac_sync")
    _DB.rows["ofac_sync"].consecutive_failures = 2
    _DB.rows["ofac_sync"].last_error_message = "old boom"

    j = cron_scheduler.CronJob(
        name="ofac_sync",
        schedule_fn=lambda now: now,
        run_fn=lambda: None,
    )
    cron_scheduler._fire_job(j)
    row = _DB.rows["ofac_sync"]
    assert row.consecutive_failures == 0
    assert row.last_success_utc is not None
    assert row.last_error_message is None


def test_leader_id_uses_hostname_when_set(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "scheduler-1")
    monkeypatch.delenv("RAILWAY_REPLICA_ID", raising=False)
    leader = cron_scheduler._resolve_leader_id()
    assert leader.startswith("scheduler-1:"), (
        f"expected HOSTNAME-prefixed leader id; got {leader!r}"
    )


def test_lease_seconds_env_clamping(monkeypatch):
    monkeypatch.setenv("RECUPERO_CRON_LEASE_SECONDS", "bad")
    assert cron_scheduler._lease_seconds_from_env() == 300

    monkeypatch.setenv("RECUPERO_CRON_LEASE_SECONDS", "0")
    assert cron_scheduler._lease_seconds_from_env() == 300

    monkeypatch.setenv("RECUPERO_CRON_LEASE_SECONDS", "-5")
    assert cron_scheduler._lease_seconds_from_env() == 300

    monkeypatch.setenv("RECUPERO_CRON_LEASE_SECONDS", "120")
    assert cron_scheduler._lease_seconds_from_env() == 120


def test_healthz_stale_hours_env_clamping(monkeypatch):
    monkeypatch.setenv("RECUPERO_CRON_HEALTHZ_STALE_HOURS", "nan")
    # 'nan' is parseable by float() but isfinite() rejects it.
    assert cron_scheduler._healthz_stale_hours_from_env() == 25.0

    monkeypatch.setenv("RECUPERO_CRON_HEALTHZ_STALE_HOURS", "inf")
    assert cron_scheduler._healthz_stale_hours_from_env() == 25.0

    monkeypatch.setenv("RECUPERO_CRON_HEALTHZ_STALE_HOURS", "0")
    assert cron_scheduler._healthz_stale_hours_from_env() == 25.0

    monkeypatch.setenv("RECUPERO_CRON_HEALTHZ_STALE_HOURS", "12.5")
    assert cron_scheduler._healthz_stale_hours_from_env() == 12.5


def test_healthz_endpoint_returns_503_on_down(monkeypatch):
    """Test 19: /cron/healthz HTTP route returns 503 when payload
    .status == 'down'. Pin so uptime monitors get a non-2xx response
    to alarm on."""
    import urllib.request

    from recupero.worker import _health_server

    # Force ephemeral port + loopback.
    monkeypatch.setattr(_health_server, "_resolve_health_port", lambda: 0)
    monkeypatch.delenv("HEALTH_BIND_HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)

    # Empty DB → all jobs missing → status=down.
    _DB.reset()

    srv = _health_server.start_health_server(lambda: (True, {"db": "ok"}))
    port = srv.server_address[1]
    try:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/cron/healthz", timeout=5,
            ) as resp:
                code = resp.status
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            code = e.code
            body = e.read().decode("utf-8")
        assert code == 503, (
            f"/cron/healthz must return 503 when any job is 'down' "
            f"(got {code}, body={body[:200]!r})"
        )
        import json as _j
        payload = _j.loads(body)
        assert payload["status"] == "down"
        assert "jobs" in payload
    finally:
        srv.shutdown()


def test_healthz_endpoint_returns_200_on_ok(monkeypatch):
    """Test 20: /cron/healthz returns 200 when all jobs fresh."""
    import urllib.request

    from recupero.worker import _health_server

    monkeypatch.setattr(_health_server, "_resolve_health_port", lambda: 0)
    monkeypatch.delenv("HEALTH_BIND_HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)

    # Seed every job with a fresh last_success_utc.
    fresh = datetime.now(UTC) - timedelta(minutes=30)
    for j in cron_scheduler._build_default_jobs():
        row = _FakeRow(
            job_name=j.name, leader_id="x",
            acquired_at_utc=fresh, expires_at_utc=fresh + timedelta(minutes=5),
        )
        row.last_success_utc = fresh
        _DB.rows[j.name] = row

    srv = _health_server.start_health_server(lambda: (True, {"db": "ok"}))
    port = srv.server_address[1]
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/cron/healthz", timeout=5,
        ) as resp:
            code = resp.status
            body = resp.read().decode("utf-8")
        assert code == 200
        import json as _j
        payload = _j.loads(body)
        assert payload["status"] == "ok"
    finally:
        srv.shutdown()


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v", "--tb=short"])
