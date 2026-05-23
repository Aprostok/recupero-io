"""Queue-starvation regression locks for `recupero.worker.db.WorkerDB`.

Locks the AUDIT FINDINGS from the W10-01 follow-up audit. These tests
encode the documented design so a future refactor that breaks any of
the following silently is caught:

  1. **Strict FIFO ordering.** `investigations` has NO `priority`
     column (verified against Jacob's admin UI schema). `claim_one`
     uses `ORDER BY triggered_at ASC NULLS LAST`. Any change away
     from `triggered_at` ordering — for instance, a refactor that
     introduces `claimed_at` ordering — would mean a stuck row never
     gets retried. The reaper-then-reinsert flow is the only way a
     case retries.

  2. **No in-worker retry / dead-letter.** `mark_failed` is terminal.
     `CLAIMABLE_STATUSES = {pending, review_approved}`. A reaped or
     explicitly failed row CANNOT be re-claimed by the worker — the
     admin UI must insert a fresh investigation. This prevents the
     "fails 5 times then keeps getting picked" starvation pattern.

  3. **Single-claim-per-call.** `claim_one`'s inner SELECT carries
     `LIMIT 1` — the worker can never hold more than one
     investigation at a time. The main poll loop is serial.

  4. **Reaper cleans worker_id.** A crashed worker's row is reclaimed
     by inserting a NEW pending row, but the reaper clears worker_id
     so the old row can't be silently re-flipped to `complete` by a
     zombie heartbeat/mark_* call.

If a future refactor genuinely wants priority-aware claiming or
bounded retry-then-dead-letter semantics, that work needs a schema
migration on Jacob's side first AND deliberate edits to these tests.
Do not weaken them silently.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch
from uuid import uuid4

from recupero.worker import state as S
from recupero.worker.db import WorkerDB


def _make_db() -> WorkerDB:
    return WorkerDB(dsn="postgresql://u:p@h/d", worker_id="worker-test")


def _captured_sql(mock_connect: MagicMock) -> str:
    conn = mock_connect.return_value.__enter__.return_value
    cur = conn.cursor.return_value.__enter__.return_value
    assert cur.execute.called, "cursor.execute was never called"
    return cur.execute.call_args.args[0]


def test_claim_one_orders_by_triggered_at_fifo_not_claimed_at() -> None:
    """`claim_one` must order by `triggered_at ASC NULLS LAST`.

    Locks the documented FIFO behavior. If a refactor swaps in
    `claimed_at` (which is NULL for unclaimed rows!), pending rows
    would be ordered randomly and an unlucky old row could starve.
    If a refactor adds a `priority` column without coordinating with
    Jacob's admin UI schema, the SQL would reference a missing column
    and every claim would error.
    """
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
        m.return_value.__enter__.return_value.cursor.return_value.\
            __enter__.return_value.fetchone.return_value = None
        _make_db().claim_one()
        sql = _captured_sql(m)

    # ORDER BY clause uses triggered_at with NULLS LAST.
    assert re.search(
        r"ORDER\s+BY\s+triggered_at\s+ASC\s+NULLS\s+LAST",
        sql,
        re.IGNORECASE,
    ), (
        "claim_one no longer orders by triggered_at ASC NULLS LAST — "
        "this breaks the documented FIFO guarantee. If you want a "
        "priority queue, coordinate a schema change with Jacob first."
    )
    # Defensive: no priority column should be referenced.
    assert "priority" not in sql.lower(), (
        "claim_one references a `priority` column — investigations "
        "has no such column. See db.py module docstring."
    )
    # Defensive: must NOT order by claimed_at (NULL for unclaimed rows).
    assert not re.search(
        r"ORDER\s+BY\s+claimed_at",
        sql,
        re.IGNORECASE,
    ), "claim_one orders by claimed_at — NULL-sorts make ordering meaningless."


def test_claimable_statuses_excludes_failed_no_in_worker_retry() -> None:
    """Failed rows are TERMINAL — the worker cannot re-claim them.

    Locks the no-infinite-retry property. A row that fails 5 times in
    a row cannot starve the queue, because each failure is terminal:
    the admin UI must insert a brand-new pending investigation row
    for a retry. There is no `attempt_count`, no `max_retries`, no
    dead-letter state — by design.
    """
    assert S.FAILED not in S.CLAIMABLE_STATUSES, (
        "S.FAILED is claimable — would enable infinite-retry "
        "starvation. mark_failed must remain terminal."
    )
    assert S.COMPLETED not in S.CLAIMABLE_STATUSES
    # Only pending and review_approved are claimable.
    assert S.CLAIMABLE_STATUSES == frozenset({S.QUEUED, S.REVIEW_APPROVED}), (
        f"CLAIMABLE_STATUSES drifted: {S.CLAIMABLE_STATUSES!r}. "
        "Any addition risks reopening starvation/retry semantics."
    )


def test_claim_one_returns_at_most_one_row_no_per_worker_queue_depth() -> None:
    """`claim_one`'s inner SELECT must be `LIMIT 1`.

    A worker can never hold more than a single investigation at a
    time, and the main poll loop processes serially. This is the
    "per-worker queue depth limit" — implicit but firm.
    """
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
        m.return_value.__enter__.return_value.cursor.return_value.\
            __enter__.return_value.fetchone.return_value = None
        _make_db().claim_one()
        sql = _captured_sql(m)
    assert re.search(r"\bLIMIT\s+1\b", sql, re.IGNORECASE), (
        "claim_one no longer LIMIT 1 — a single call could claim "
        "multiple rows and exceed per-worker depth."
    )
    # Reinforce: must use SKIP LOCKED so concurrent workers don't queue.
    assert re.search(r"FOR\s+UPDATE\s+SKIP\s+LOCKED", sql, re.IGNORECASE), (
        "claim_one lost SKIP LOCKED — concurrent workers would serialize."
    )


def test_reap_stale_claims_clears_worker_id_for_clean_handoff() -> None:
    """Reaper must NULL out `worker_id` AND `last_heartbeat_at`.

    Locks v0.18.1 HIGH-005. Without this, a still-alive heartbeat
    thread on a zombie worker would keep the row's heartbeat fresh,
    so reap_stale_claims would never see it as stale on a subsequent
    pass; AND a subsequent mark_completed from the zombie could
    silently flip a reaped-failed row to `complete` via its stale
    `worker_id = me` filter.

    This is THE mechanism that prevents worker-affinity starvation:
    if the same worker repeatedly crashes on the same row, the
    reaper severs the affinity so any *other* worker can — once the
    admin UI inserts a fresh pending row — pick up the work.
    """
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
        m.return_value.__enter__.return_value.cursor.return_value.\
            __enter__.return_value.fetchall.return_value = []
        _make_db().reap_stale_claims(stale_after_sec=300)
        sql = _captured_sql(m)
    assert re.search(r"worker_id\s*=\s*NULL", sql, re.IGNORECASE), (
        "reap_stale_claims no longer clears worker_id — a zombie "
        "worker could resurrect a reaped row via stale worker_id."
    )
    assert re.search(r"last_heartbeat_at\s*=\s*NULL", sql, re.IGNORECASE), (
        "reap_stale_claims no longer clears last_heartbeat_at — a "
        "still-alive heartbeat thread would mask the staleness."
    )


def test_mark_failed_does_not_reset_to_claimable_state() -> None:
    """`mark_failed` writes `status = 'failed'` — never any claimable
    status. Locks the terminal-state invariant: there is no path
    inside the worker that returns a failed row to the queue.
    """
    fake_id = uuid4()
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
        _make_db().mark_failed(fake_id, stage="x", error="y")
        conn = m.return_value.__enter__.return_value
        cur = conn.cursor.return_value.__enter__.return_value
        params = cur.execute.call_args.args[1]
    assert params["status"] == S.FAILED
    # Cross-check: the value is exactly the wire string `failed`,
    # not any of the claimable statuses.
    assert params["status"] not in S.CLAIMABLE_STATUSES


def test_claim_one_filters_to_claimable_statuses_only() -> None:
    """`claim_one`'s WHERE clause must reference ONLY the claimable
    statuses — never `failed`, never an active state. Locks the
    "stale active-state rows are NOT silently re-claimed" contract
    from the claim_one docstring.
    """
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
        m.return_value.__enter__.return_value.cursor.return_value.\
            __enter__.return_value.fetchone.return_value = None
        _make_db().claim_one()
        sql = _captured_sql(m)

    # Both claimable wire-values appear.
    assert "'pending'" in sql
    assert "'review_approved'" in sql
    # Terminal and active states must NOT appear inline in the SQL
    # — they'd open the door to silently re-claiming a failed or
    # mid-pipeline row.
    for forbidden in ("'failed'", "'complete'", "'claimed'",
                      "'tracing'", "'emitting'", "'building_package'"):
        assert forbidden not in sql, (
            f"claim_one filter mentions {forbidden!r} — would "
            f"re-claim a terminal or active row, breaking the "
            f"reaper-then-reinsert recovery contract."
        )
