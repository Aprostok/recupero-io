"""Adversarial audit of `recupero.worker.db.WorkerDB` SQL hygiene.

These tests run with `psycopg.connect` patched so they exercise only
the SQL strings and parameter dicts WorkerDB constructs — no live DB
required.

Audited properties (see worker-DB audit spec):
  1. `%s` / `%(name)s` parameter binding (no f-string interpolation
     of attacker-controlled values).
  2. `with conn.cursor() as cur:` scoping (no leaked cursors).
  3. `autocommit=True` per connection.
  4. UUID-typed parameters validated at the Python boundary.
  5. SELECT statements use explicit column lists (no `SELECT *` or
     `RETURNING *`).
  6. UPDATE statements carry a WHERE clause.
  7. Unbounded SELECTs carry a LIMIT.
  8. Reaper methods cope with empty result sets.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from recupero.worker.db import WorkerDB

# ----- helpers ----- #


def _make_db() -> WorkerDB:
    return WorkerDB(dsn="postgresql://u:p@h/d", worker_id="worker-test")


def _captured_sql(mock_connect: MagicMock) -> str:
    """Return the SQL string passed to cursor.execute."""
    conn = mock_connect.return_value.__enter__.return_value
    cur = conn.cursor.return_value.__enter__.return_value
    assert cur.execute.called, "cursor.execute was never called"
    return cur.execute.call_args.args[0]


def _captured_params(mock_connect: MagicMock):
    conn = mock_connect.return_value.__enter__.return_value
    cur = conn.cursor.return_value.__enter__.return_value
    return cur.execute.call_args.args[1]


# ----- tests ----- #


def test_claim_one_select_has_explicit_column_list_no_returning_star() -> None:
    """`claim_one`'s RETURNING clause must NOT be `RETURNING *`.

    Schema drift (extra columns added by Jacob's admin UI) can leak
    columns the worker has never seen into the pydantic
    `Investigation` model. We've got `extra='ignore'` as a safety
    net, but the safer contract is an explicit column list so
    additions are deliberate.
    """
    fake_row = {
        "id": uuid4(),
        "status": "claimed",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
    }
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
        m.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value.fetchone.return_value = fake_row
        _make_db().claim_one()
        sql = _captured_sql(m)

    assert "RETURNING *" not in sql, (
        "claim_one uses `RETURNING *` — schema drift will silently "
        "deliver columns the worker model can't see. Use an explicit "
        "column list."
    )


def test_heartbeat_rejects_non_uuid_strings() -> None:
    """`heartbeat` should reject obviously non-UUID inputs at the
    Python boundary, not at the database.

    The signature is `(self, investigation_id: UUID)`. Python doesn't
    enforce the annotation. If a caller hands in a string like
    `'pending'` or `"' OR 1=1 --"`, the parameter is still bound
    safely, but the type contract is broken and the failure surface
    moves from Python (clean ValueError) to psycopg (ugly DataError
    from inside the DB call).
    """
    db = _make_db()
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()):
        with pytest.raises((ValueError, TypeError)):
            db.heartbeat("not-a-uuid")  # type: ignore[arg-type]


def test_mark_failed_rejects_non_uuid_strings() -> None:
    db = _make_db()
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()):
        with pytest.raises((ValueError, TypeError)):
            db.mark_failed(
                "garbage-id",  # type: ignore[arg-type]
                stage="x",
                error="y",
            )


def test_fetch_case_rejects_non_uuid_strings() -> None:
    db = _make_db()
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()):
        with pytest.raises((ValueError, TypeError)):
            db.fetch_case("definitely-not-a-uuid")  # type: ignore[arg-type]


def test_transition_uses_param_binding_no_status_interpolation() -> None:
    """`transition` must bind `status` via a `%(status)s` placeholder
    — NEVER f-string it in. If a future refactor f-strings the value,
    the SQL string would contain the literal status text, which would
    open the door to injection if status ever became
    caller-influenced (e.g., a future stage='retry:user_label')."""
    fake_id = uuid4()
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
        _make_db().transition(fake_id, status="tracing")
        sql = _captured_sql(m)
        params = _captured_params(m)

    # The status value must reach the DB via the parameter dict, not
    # as a literal in the SQL.
    assert "'tracing'" not in sql
    assert params["status"] == "tracing"
    # Status placeholder must be present.
    assert "%(status)s" in sql


def test_every_update_has_a_where_clause() -> None:
    """Static-text audit of WorkerDB SQL: every UPDATE block must
    contain a WHERE — never a bare `UPDATE table SET …`. We exercise
    each writer method once and inspect the SQL it generates."""
    fake_id = uuid4()
    methods = [
        ("heartbeat",            lambda d: d.heartbeat(fake_id)),
        ("transition",           lambda d: d.transition(fake_id, status="tracing")),
        ("record_api_cost",      lambda d: d.record_api_cost(fake_id, 0)),
        ("mark_review_required", lambda d: d.mark_review_required(fake_id)),
        ("mark_failed",          lambda d: d.mark_failed(fake_id, stage="s", error="e")),
    ]
    pattern_update = re.compile(r"\bUPDATE\b", re.IGNORECASE)
    pattern_where  = re.compile(r"\bWHERE\b",  re.IGNORECASE)

    for name, call in methods:
        with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
            call(_make_db())
            sql = _captured_sql(m)
        # Every UPDATE in the SQL must be followed by a WHERE somewhere.
        assert pattern_update.search(sql), f"{name}: no UPDATE found"
        assert pattern_where.search(sql), (
            f"{name}: UPDATE without WHERE — would touch every row!"
        )


def test_claim_one_select_has_limit() -> None:
    """`claim_one`'s inner SELECT must carry a LIMIT to avoid locking
    the entire claimable queue when SKIP LOCKED is invoked."""
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
        m.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value.fetchone.return_value = None
        _make_db().claim_one()
        sql = _captured_sql(m)
    assert re.search(r"\bLIMIT\s+1\b", sql, re.IGNORECASE), (
        "claim_one inner SELECT lacks LIMIT 1 — would scan and lock "
        "the entire claimable queue."
    )


def test_reap_post_deploy_orphans_handles_empty_result() -> None:
    """The reaper must return an empty list (not raise) when nothing
    is stale. Defends against the empty-result-set case noted in the
    spec."""
    with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
        m.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value.fetchall.return_value = []
        result = _make_db().reap_post_deploy_orphans(stale_after_sec=90)
    assert result == []


def test_all_connect_calls_use_autocommit_true() -> None:
    """Every `psycopg.connect(...)` inside WorkerDB must pass
    `autocommit=True`. Without it, the implicit transaction would
    sit open until garbage collection, holding row locks across the
    short-lived connection lifetime."""
    fake_id = uuid4()
    calls = [
        lambda d: d.heartbeat(fake_id),
        lambda d: d.transition(fake_id, status="tracing"),
        lambda d: d.mark_failed(fake_id, stage="s", error="e"),
        lambda d: d.reap_stale_claims(stale_after_sec=300),
    ]
    for call in calls:
        with patch("recupero.worker.db.psycopg.connect", new=MagicMock()) as m:
            try:
                call(_make_db())
            except Exception:
                pass  # we only care about connect kwargs
            assert m.called, "psycopg.connect was not invoked"
            _, kwargs = m.call_args
            assert kwargs.get("autocommit") is True, (
                f"connect() called without autocommit=True: kwargs={kwargs}"
            )
