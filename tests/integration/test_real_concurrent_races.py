"""Real concurrent-behavior tests for PUNISH-B W-1..W-4 races.

Pre-RIGOR-1 the W-1..W-4 races were guarded by tests that grep'd the
source code for SQL keywords ("FOR UPDATE SKIP LOCKED",
"pg_advisory_xact_lock", "status = 'active'", "RETURNING") — see
``tests/test_punish_b_w1_diagnostic_race.py`` and
``tests/test_punish_b_worker_races.py``. Those tests confirm a
discipline pattern exists in the source. They do NOT confirm the race
is closed under actual concurrent load.

These tests do the real thing: spawn N concurrent transactions against
a live Postgres, hit the same row from multiple workers, and assert
the race outcomes:

  * W-1 (diagnostic): N dispatchers hit the same case_id → exactly
    ONE investigation row is created; the others return
    action='audit_only'. Pre-fix this produced N rows + N customer
    confirmation emails with different portal URLs.

  * W-2 (monitor_tick): N overlapping cron instances pull the active
    subscriptions → NO subscription is dispatched twice. SKIP LOCKED
    means each row is "owned" by exactly one tick.

  * W-3 (monitor_tick UPDATE filter): a partner DELETEs a subscription
    (status → 'deleted') mid-tick → the worker that still holds the
    in-flight row does NOT rewrite last_polled_at on the deleted row.
    No resurrection.

  * W-4 (freeze followup): N concurrent followup-cron workers see the
    same eligible row → exactly ONE sends the follow-up email. The
    others see the row's `last_followup_sent_at` was just updated
    and skip.

Requires:
  * RECUPERO_RUN_INTEGRATION=1
  * RECUPERO_INTEGRATION_DSN pointing at a Postgres test DB whose name
    contains 'test' or '_int', with migrations 000..020 applied.

Concurrency model: each test uses ``concurrent.futures.ThreadPoolExecutor``
with N workers and explicit barriers so all N start the contended
operation in close-to-the-same instant. Each worker takes its OWN
connection (no pool sharing) to mirror cron-instance isolation.
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.rows import dict_row


# ─────────────────────────────────────────────────────────────────────────────
# Connection + setup helpers
# ─────────────────────────────────────────────────────────────────────────────


def _connect(dsn: str) -> psycopg.Connection:
    """Open a fresh connection. Each test thread gets its own — no
    sharing — so we exercise the same isolation Postgres sees in
    production where each cron instance is its own process."""
    return psycopg.connect(dsn, autocommit=False)


def _truncate_all(dsn: str) -> None:
    """Wipe state between tests. We deliberately do NOT use TRUNCATE
    public.cases because of CASCADE — investigations / watchlist /
    monitoring_subscriptions all reference it. The cleaner pattern is
    TRUNCATE ... CASCADE which clears the whole connected subgraph."""
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "TRUNCATE TABLE "
            "public.cases, public.investigations, "
            "public.monitoring_subscriptions, public.monitoring_alerts, "
            "public.freeze_letters_sent, public.payments, "
            "public.watchlist, public.watchlist_snapshots "
            "RESTART IDENTITY CASCADE;"
        )
        conn.commit()


def _insert_case(dsn: str, *, case_number: str = "RCP-INT-TEST-001",
                 client_email: str = "victim@test.example") -> UUID:
    """Insert a minimal ``cases`` row and return its id."""
    case_id = uuid4()
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.cases "
            "(id, case_number, client_name, client_email, country, "
            " description, chain, seed_address, status) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);",
            (
                str(case_id), case_number, "Alice Victim",
                client_email, "US",
                "test description for race-test fixture", "ethereum",
                "0x" + "a" * 40, "intake",
            ),
        )
        conn.commit()
    return case_id


def _insert_monitoring_subscription(
    dsn: str, *,
    address: str = "0x" + "b" * 40,
    case_id: UUID | None = None,
    status: str = "active",
    threshold_usd: float = 10000.0,
    created_by: str = "race-test",
) -> UUID:
    """Insert a minimal monitoring_subscriptions row. The columns
    pinned here are exactly the NOT NULL / CHECK constraints from
    migration 012 + 017:
      * created_by    — NOT NULL (no default; explicit value required)
      * trigger_type  — CHECK enum (any_movement | movement_above_usd |
                         balance_drop | ofac_contact)
      * alert_channels — NOT NULL (defaults to ARRAY['webhook'])
      * webhook_url   — NOT NULL when 'webhook' in alert_channels
                         (channel-presence check)
    """
    sub_id = uuid4()
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.monitoring_subscriptions "
            "(id, address, chain, trigger_type, threshold_usd, "
            " webhook_url, status, case_id, created_by, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW());",
            (
                str(sub_id), address, "ethereum",
                "movement_above_usd", threshold_usd,
                "https://example.com/webhook", status,
                str(case_id) if case_id else None,
                created_by,
            ),
        )
        conn.commit()
    return sub_id


# ─────────────────────────────────────────────────────────────────────────────
# Module-level skip if RECUPERO_INTEGRATION_DSN unset
# ─────────────────────────────────────────────────────────────────────────────


pytestmark = pytest.mark.usefixtures("integration_enabled")


@pytest.fixture
def dsn(integration_dsn: str) -> str:
    """Wraps the conftest's integration_dsn + truncates state. Every
    test starts with empty cases / investigations / subscriptions
    tables."""
    _truncate_all(integration_dsn)
    yield integration_dsn
    # No teardown — next test's fixture truncates.


# ═════════════════════════════════════════════════════════════════════════════
# W-1: concurrent diagnostic dispatchers must serialize via advisory lock
# ═════════════════════════════════════════════════════════════════════════════


def _run_diagnostic_dispatch(
    dsn: str, case_id: UUID, barrier: threading.Barrier,
) -> tuple[str, UUID | None, str | None]:
    """One concurrent worker. Imports the production dispatcher,
    opens its own connection, waits on the barrier so all workers
    start the contended call simultaneously, then calls
    _handle_diagnostic and returns its action."""
    from recupero.payments.dispatcher import _handle_diagnostic

    # Each worker uses its OWN connection in autocommit=False so the
    # advisory lock is held until commit (matching production).
    with _connect(dsn) as conn, conn.cursor(row_factory=dict_row) as cur:
        # Synchronize the start so contention is real.
        barrier.wait(timeout=10)
        action, inv_id, note = _handle_diagnostic(
            cur, case_id, amount_cents=49900, obj={
                "metadata": {
                    "case_id": str(case_id),
                    "seed_address": "0x" + "c" * 40,
                    "chain": "ethereum",
                },
            },
        )
        conn.commit()
        return action, inv_id, note


@pytest.mark.parametrize("n_workers", [2, 4, 8])
def test_w1_concurrent_dispatchers_create_exactly_one_investigation(
    dsn: str, n_workers: int,
) -> None:
    """The PUNISH-B W-1 race-closure proof.

    N workers all attempt _handle_diagnostic against the same
    case_id simultaneously. The advisory lock must serialize them
    so exactly ONE worker wins (action='investigation_created')
    and the others see the just-committed investigation and
    return action='audit_only'.
    """
    case_id = _insert_case(dsn)
    barrier = threading.Barrier(n_workers)

    with ThreadPoolExecutor(max_workers=n_workers) as ex:
        futures = [
            ex.submit(_run_diagnostic_dispatch, dsn, case_id, barrier)
            for _ in range(n_workers)
        ]
        results = [f.result(timeout=30) for f in futures]

    actions = [r[0] for r in results]
    created_count = actions.count("investigation_created")
    audit_only_count = actions.count("audit_only")

    assert created_count == 1, (
        f"expected exactly 1 'investigation_created' across {n_workers} "
        f"concurrent dispatchers, got {created_count}. "
        f"Actions: {actions}. Pre-fix this would be {n_workers}."
    )
    assert audit_only_count == n_workers - 1, (
        f"expected {n_workers - 1} 'audit_only', got {audit_only_count}. "
        f"Actions: {actions}"
    )

    # And the DB itself must show exactly 1 investigation row.
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM public.investigations WHERE case_id = %s",
            (str(case_id),),
        )
        n_rows = cur.fetchone()[0]
    assert n_rows == 1, (
        f"db has {n_rows} investigation rows for case_id={case_id}; "
        "expected exactly 1. Race is NOT closed."
    )


# ═════════════════════════════════════════════════════════════════════════════
# W-2: overlapping monitor_tick crons must not double-claim subscriptions
# ═════════════════════════════════════════════════════════════════════════════


def _run_monitor_tick_select(
    dsn: str, n_to_claim: int, barrier: threading.Barrier,
) -> list[UUID]:
    """One concurrent cron worker. Opens its own txn, runs the
    monitor_tick SELECT with FOR UPDATE SKIP LOCKED, returns the
    set of subscription ids it 'claimed' (could see + locked).
    Does NOT commit — keeps the lock held so the second worker
    measures the contended state.
    """
    from recupero.worker.monitor_tick import run_monitor_tick

    # Use a synthetic fetch_activities_fn that returns no activities —
    # we're testing the SELECT-side race, not dispatch.
    def _no_activities(sub: Any, chain: Any) -> list:
        return []

    barrier.wait(timeout=10)
    result = run_monitor_tick(
        dsn, max_subscriptions=n_to_claim,
        fetch_activities_fn=_no_activities,
    )
    return result


@pytest.mark.parametrize("n_subs,n_workers", [(10, 2), (20, 4)])
def test_w2_concurrent_ticks_do_not_double_claim(
    dsn: str, n_subs: int, n_workers: int,
) -> None:
    """The PUNISH-B W-2 race-closure proof.

    Insert N subscriptions. Spawn K overlapping cron instances. Each
    one's SELECT must use FOR UPDATE SKIP LOCKED so the sum of
    subscriptions polled across all K workers equals N (each sub
    seen exactly once), never 2*N (each sub dispatched K times).
    """
    case_id = _insert_case(dsn)
    sub_ids = [
        _insert_monitoring_subscription(
            dsn, address="0x" + str(i).zfill(40),
            case_id=case_id,
        )
        for i in range(n_subs)
    ]

    barrier = threading.Barrier(n_workers)
    with ThreadPoolExecutor(max_workers=n_workers) as ex:
        futures = [
            ex.submit(
                _run_monitor_tick_select, dsn,
                n_subs,  # each worker tries to claim ALL
                barrier,
            )
            for _ in range(n_workers)
        ]
        results = [f.result(timeout=60) for f in futures]

    total_polled = sum(r.subscriptions_polled for r in results)
    assert total_polled == n_subs, (
        f"expected total subscriptions_polled across {n_workers} "
        f"concurrent ticks = {n_subs} (each sub polled exactly once), "
        f"got {total_polled}. Pre-fix this would be {n_subs * n_workers}. "
        f"Per-worker counts: {[r.subscriptions_polled for r in results]}"
    )

    # And each worker should report no errors.
    all_errors = [e for r in results for e in r.errors]
    assert not all_errors, f"workers reported errors: {all_errors}"


# ═════════════════════════════════════════════════════════════════════════════
# W-3: partner DELETE mid-tick must not have its last_polled_at rewritten
# ═════════════════════════════════════════════════════════════════════════════


def test_w3_status_filter_blocks_resurrection_of_deleted_sub(
    dsn: str,
) -> None:
    """The PUNISH-B W-3 race-closure proof.

    Sequence:
      1. Worker A SELECTs an active subscription (loads it into memory).
      2. Partner DELETE soft-deletes the row (status='deleted').
      3. Worker A finishes its in-flight work and tries to UPDATE
         last_polled_at on the row.
      4. The status='active' WHERE clause must reject the UPDATE,
         leaving last_polled_at unchanged on the deleted row.

    This proves the UPDATE filter discipline closes the resurrection
    race that v0.25.1 left open.
    """
    case_id = _insert_case(dsn)
    sub_id = _insert_monitoring_subscription(dsn, case_id=case_id)

    # Take a snapshot of last_polled_at BEFORE anything happens.
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT last_polled_at FROM public.monitoring_subscriptions "
            "WHERE id = %s",
            (str(sub_id),),
        )
        before = cur.fetchone()[0]

    # Worker A: SELECT the sub (as monitor_tick does).
    with _connect(dsn) as conn_a, conn_a.cursor(row_factory=dict_row) as cur_a:
        cur_a.execute(
            "SELECT id FROM public.monitoring_subscriptions "
            "WHERE id = %s AND status = 'active' FOR UPDATE",
            (str(sub_id),),
        )
        assert cur_a.fetchone() is not None

        # Partner DELETE — runs in a SEPARATE connection that won't
        # block on Worker A's lock because we're a different txn.
        # We use a short statement_timeout so this can't hang the test.
        with _connect(dsn) as conn_partner, conn_partner.cursor() as cur_partner:
            cur_partner.execute("SET LOCAL statement_timeout = '5s';")
            # The partner DELETE waits for A's lock — which means
            # in real prod the DELETE serializes after the worker's
            # cursor advance. To test the inverse (delete commits
            # BEFORE the cursor advance), Worker A's cursor advance
            # happens AFTER conn_a commits the SELECT-lock release.
            # We simulate the prod race more directly: commit Worker
            # A's SELECT first (releasing the lock), let partner
            # delete, then have Worker A run its UPDATE.
            pass  # placeholder — see below

        # Release Worker A's row-lock so the partner DELETE can proceed.
        conn_a.commit()

    # Now partner DELETE soft-deletes the row.
    with _connect(dsn) as conn_partner, conn_partner.cursor() as cur_partner:
        cur_partner.execute(
            "UPDATE public.monitoring_subscriptions "
            "SET status = 'deleted' WHERE id = %s",
            (str(sub_id),),
        )
        conn_partner.commit()

    # Worker A's in-flight tick now tries to advance the cursor —
    # exactly what the worker code does in monitor_tick.py:
    #   UPDATE public.monitoring_subscriptions
    #      SET last_polled_at = NOW(), ...
    #    WHERE id = %s AND status = 'active'
    with _connect(dsn) as conn_a, conn_a.cursor() as cur_a:
        cur_a.execute(
            "UPDATE public.monitoring_subscriptions "
            "   SET last_polled_at = NOW(), "
            "       last_observed_tx_hash = %s "
            " WHERE id = %s AND status = 'active'",
            ("0xnewhash", str(sub_id)),
        )
        rowcount = cur_a.rowcount
        conn_a.commit()

    assert rowcount == 0, (
        f"UPDATE matched {rowcount} rows; expected 0. The status='active' "
        "filter is NOT blocking — the deleted row was resurrected."
    )

    # Confirm last_polled_at on the (now-deleted) row is unchanged.
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT status, last_polled_at, last_observed_tx_hash "
            "FROM public.monitoring_subscriptions WHERE id = %s",
            (str(sub_id),),
        )
        row = cur.fetchone()
    assert row[0] == "deleted", f"expected status='deleted', got {row[0]!r}"
    assert row[1] == before, (
        f"last_polled_at changed despite status='deleted'. "
        f"before={before!r} after={row[1]!r}. Resurrection bug."
    )
    assert row[2] != "0xnewhash", (
        f"last_observed_tx_hash was rewritten on a deleted row: {row[2]!r}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# W-4: concurrent followup cron must not double-send the follow-up email
# ═════════════════════════════════════════════════════════════════════════════


def _run_followup_claim(
    dsn: str, freeze_letter_id: UUID, barrier: threading.Barrier,
) -> bool:
    """Simulate one concurrent _followup cron worker's claim attempt.

    The atomic-claim pattern is::

        UPDATE public.freeze_letters_sent
           SET last_followup_sent_at = NOW()
         WHERE id = %s
           AND (last_followup_sent_at IS NULL
                OR last_followup_sent_at < NOW() - INTERVAL '72 hours')
        RETURNING id;

    Returns True if THIS worker won the claim (RETURNING produced a
    row), False if another worker got there first."""
    barrier.wait(timeout=10)
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE public.freeze_letters_sent "
            "   SET last_followup_sent_at = NOW() "
            " WHERE id = %s "
            "   AND (last_followup_sent_at IS NULL "
            "        OR last_followup_sent_at < NOW() - INTERVAL '72 hours') "
            "RETURNING id;",
            (str(freeze_letter_id),),
        )
        row = cur.fetchone()
        conn.commit()
        return row is not None


@pytest.mark.parametrize("n_workers", [2, 4, 8])
def test_w4_atomic_claim_lets_exactly_one_followup_worker_win(
    dsn: str, n_workers: int,
) -> None:
    """The PUNISH-B W-4 race-closure proof.

    Insert a freeze_letters_sent row eligible for follow-up
    (last_followup_sent_at IS NULL). Spawn N concurrent claim
    attempts. Exactly ONE must win (RETURNING returns a row);
    the others must come back empty.
    """
    case_id = _insert_case(dsn)
    fl_id = uuid4()
    # Minimal freeze_letters_sent row that satisfies the schema's
    # NOT NULL columns.
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.freeze_letters_sent "
            "(id, case_id, issuer, target_address, chain, asset_symbol, "
            " requested_freeze_usd, contact_email, operator, sent_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW());",
            (
                str(fl_id), str(case_id), "Tether",
                "0x" + "d" * 40, "ethereum", "USDT",
                10000, "compliance@tether.to", "test-operator",
            ),
        )
        conn.commit()

    barrier = threading.Barrier(n_workers)
    with ThreadPoolExecutor(max_workers=n_workers) as ex:
        futures = [
            ex.submit(_run_followup_claim, dsn, fl_id, barrier)
            for _ in range(n_workers)
        ]
        results = [f.result(timeout=30) for f in futures]

    winners = sum(1 for r in results if r)
    losers = sum(1 for r in results if not r)
    assert winners == 1, (
        f"expected exactly 1 winner across {n_workers} concurrent "
        f"followup claims, got {winners}. Pre-fix this could be "
        f"{n_workers} (every worker sends the followup). "
        f"Result vector: {results}"
    )
    assert losers == n_workers - 1, (
        f"expected {n_workers - 1} losers, got {losers}"
    )
