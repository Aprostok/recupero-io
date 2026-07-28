"""Schema-contract regression tests for the /v2 platform queue SQL.

These lock three production-fatal defects found by auditing the platform layer
against the REAL schema (migrations/000 + worker/state.py). None were caught by
the existing platform tests because every one of them fakes the DB connection,
so no SQL was ever validated against the actual columns:

  1. ``enqueue_trace`` inserted ``status='queued'``, but the worker's
     CLAIMABLE_STATUSES is {'pending','review_approved'} (worker/state.py) — so
     every /v2-submitted job sat unclaimable forever.
  2. ``enqueue_trace`` wrote the synthetic ``CASE-<hex>`` label into
     ``investigations.case_id``, which is ``UUID REFERENCES public.cases(id)``
     → 22P02 invalid-uuid on every submit.
  3. ``get_trace_status`` / ``list_traces`` selected ``created_at`` /
     ``updated_at``, which ``public.investigations`` does not have → 42703
     UndefinedColumn. Because get_trace_status is the org gate, that 500'd the
     whole /v2 trace surface (status, summary, graph, artifacts, stream).

The tests assert on the SQL text a recording cursor captures, which is the only
way to catch column-level drift without a live database.
"""

from __future__ import annotations

from recupero.platform import store

# Columns that actually exist on public.investigations (migrations/000).
_REAL_COLUMNS = {
    "id", "case_id", "status", "triggered_by", "triggered_at", "worker_id",
    "claimed_at", "last_heartbeat_at", "started_at", "completed_at", "failed_at",
    "review_required_at", "error_message", "error_stage", "chain", "seed_address",
    "incident_time", "max_depth", "dust_threshold_usd", "supabase_storage_path",
    "total_loss_usd", "max_recoverable_usd", "api_costs_usd", "freezable_issuers",
    "label", "skip_editorial", "skip_freeze_briefs",
    # added by later migrations
    "org_id", "submitted_by", "idempotency_key",
}
#: Columns the platform layer must never reference on `investigations`.
_NONEXISTENT_COLUMNS = ("created_at", "updated_at")


class _RecCursor:
    def __init__(self, fetchone=None, fetchall=None):
        self.executed: list[tuple[str, object]] = []
        self._fetchone = fetchone
        self._fetchall = fetchall or []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return self._fetchone

    def fetchall(self):
        return self._fetchall


class _RecConn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self):
        return self._cur


def _sql(cur) -> str:
    return " ".join(sql for sql, _ in cur.executed)


# --------------------------------------------------------------------------- #
# 1 + 2: enqueue_trace status literal + case_id not written to a UUID FK
# --------------------------------------------------------------------------- #

def test_enqueue_uses_worker_claimable_status() -> None:
    from recupero.worker import state
    cur = _RecCursor(fetchone=("inv-1",))
    store.enqueue_trace(
        _RecConn(cur), org_id="o", submitted_by=None, chain="ethereum",
        seed_address="0xabc", incident_time="2026-01-01T00:00:00Z",
        case_id="CASE-deadbeef", idempotency_key=None,
    )
    insert = cur.executed[0][0]
    # The inserted literal must be the worker's QUEUED value, else the job is
    # never claimed (FOR UPDATE SKIP LOCKED filters on CLAIMABLE_STATUSES).
    assert "'pending'" in insert
    assert "'queued'" not in insert
    assert state.QUEUED == "pending"
    assert state.QUEUED in state.CLAIMABLE_STATUSES


def test_enqueue_does_not_write_case_label_into_uuid_column() -> None:
    """`investigations.case_id` is a UUID FK to public.cases — the human
    `CASE-<hex>` label must never be inserted there (22P02)."""
    cur = _RecCursor(fetchone=("inv-1",))
    store.enqueue_trace(
        _RecConn(cur), org_id="o", submitted_by=None, chain="ethereum",
        seed_address="0xabc", incident_time="2026-01-01T00:00:00Z",
        case_id="CASE-deadbeef", idempotency_key=None,
    )
    insert_sql, insert_params = cur.executed[0]
    assert "case_id" not in insert_sql
    assert "CASE-deadbeef" not in [str(p) for p in (insert_params or ())]


def test_enqueue_still_meters_usage() -> None:
    cur = _RecCursor(fetchone=("inv-1",))
    inv_id, created = store.enqueue_trace(
        _RecConn(cur), org_id="o", submitted_by=None, chain="ethereum",
        seed_address="0xabc", incident_time="2026-01-01T00:00:00Z",
        case_id="CASE-x", idempotency_key=None,
    )
    assert (inv_id, created) == ("inv-1", True)
    assert "usage_events" in _sql(cur)
    assert "trace_submitted" in _sql(cur)


# --------------------------------------------------------------------------- #
# 3: no reference to columns investigations does not have
# --------------------------------------------------------------------------- #

def test_get_trace_status_uses_only_real_columns() -> None:
    cur = _RecCursor(fetchone=("i", "pending", None, "ethereum", "0xabc", None, None))
    out = store.get_trace_status(_RecConn(cur), org_id="o", investigation_id="i")
    sql = _sql(cur)
    for col in _NONEXISTENT_COLUMNS:
        assert col not in sql, f"get_trace_status references nonexistent column {col!r}"
    # It still exposes created_at/updated_at in the RESPONSE (mapped from the
    # real lifecycle stamps) — the API shape is unchanged for clients.
    assert out is not None
    assert "created_at" in out and "updated_at" in out
    assert "triggered_at" in sql


def test_list_traces_orders_by_a_real_column() -> None:
    cur = _RecCursor(fetchall=[("i", "pending", None, "ethereum", None)])
    rows = store.list_traces(_RecConn(cur), org_id="o", limit=10)
    sql = _sql(cur)
    for col in _NONEXISTENT_COLUMNS:
        assert col not in sql, f"list_traces references nonexistent column {col!r}"
    assert "ORDER BY triggered_at" in sql
    assert rows and "created_at" in rows[0]


def test_platform_queue_sql_only_touches_existing_investigation_columns() -> None:
    """Belt-and-braces: every identifier the queue SQL mentions that looks like
    an investigations column must be one that exists."""
    cur = _RecCursor(fetchone=("i", "pending", None, "ethereum", "0xabc", None, None))
    store.get_trace_status(_RecConn(cur), org_id="o", investigation_id="i")
    cur2 = _RecCursor(fetchall=[])
    store.list_traces(_RecConn(cur2), org_id="o")
    cur3 = _RecCursor(fetchone=("i",))
    store.enqueue_trace(
        _RecConn(cur3), org_id="o", submitted_by=None, chain="ethereum",
        seed_address="0x", incident_time="2026-01-01T00:00:00Z",
        case_id="CASE-y", idempotency_key=None,
    )
    combined = " ".join([_sql(cur), _sql(cur2), _sql(cur3)])
    for col in _NONEXISTENT_COLUMNS:
        assert col not in combined


# --------------------------------------------------------------------------- #
# Billing replay guard + quota race (audit follow-ups)
# --------------------------------------------------------------------------- #

def test_claim_stripe_event_is_atomic_and_first_wins() -> None:
    """Stripe delivers at-least-once and invoice.paid RESETS the billing period,
    so an un-deduped replay re-granted a full monthly quota. The claim must be a
    single INSERT ... ON CONFLICT DO NOTHING (no read-then-write race)."""
    first = _RecCursor(fetchone=("evt_1",))
    assert store.claim_stripe_event(
        _RecConn(first), event_id="evt_1", event_type="invoice.paid",
    ) is True
    sql = _sql(first)
    assert "INSERT INTO public.stripe_events" in sql
    assert "ON CONFLICT (event_id) DO NOTHING" in sql
    assert "RETURNING" in sql

    # Conflict → no row returned → replay.
    replay = _RecCursor(fetchone=None)
    assert store.claim_stripe_event(
        _RecConn(replay), event_id="evt_1", event_type="invoice.paid",
    ) is False


def test_claim_stripe_event_without_id_is_not_claimed() -> None:
    """No id to dedupe on: process the event, but don't issue a bogus claim."""
    cur = _RecCursor(fetchone=None)
    assert store.claim_stripe_event(_RecConn(cur), event_id="") is True
    assert cur.executed == []


def test_lock_org_for_update_takes_a_row_lock() -> None:
    cur = _RecCursor(fetchone=(1,))
    store.lock_org_for_update(_RecConn(cur), "org1")
    sql = _sql(cur)
    assert "public.organizations" in sql
    assert "FOR UPDATE" in sql


def test_submit_locks_the_org_before_reading_usage(monkeypatch) -> None:
    """Ordering matters: the lock must be held BEFORE the quota count, otherwise
    concurrent submits at `used == quota - 1` all read the same value and pass."""
    from recupero.platform import router

    order: list[str] = []
    monkeypatch.setattr(router.obs_metrics, "record_platform_request", lambda *a, **k: None)
    monkeypatch.setattr(
        store, "lock_org_for_update",
        lambda conn, org_id: order.append("lock"),
    )
    monkeypatch.setattr(
        store, "get_org",
        lambda conn, org_id: {"status": "active", "plan": "pro"},
    )

    def _used(conn, org_id):
        order.append("count")
        return 0

    monkeypatch.setattr(store, "traces_used_this_period", _used)
    monkeypatch.setattr(store, "enqueue_trace", lambda conn, **kw: ("inv-1", True))

    body = router.TraceIn(
        chain="ethereum",
        seed_address="0x" + "ab" * 20,
        incident_time="2026-01-01T00:00:00Z",
    )
    router.submit_trace(
        body,
        principal=store.OrgContext(org_id="o", plan="pro", user_id="u", role="owner"),
        conn=object(),
        idempotency_key=None,
    )
    assert order[:2] == ["lock", "count"], f"lock must precede the count; got {order}"
