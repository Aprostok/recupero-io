"""Unit tests for the ``Investigation`` pydantic model in ``worker/db``.

These exist to catch the specific class of bug that wedged Jacob's
first wallet-trace run for 12+ hours in production:

  * The DB row for a wallet trace had ``incident_time IS NULL`` (admin
    UI didn't collect one; full-history trace was intended).
  * ``claim_one`` ran the ``UPDATE ... RETURNING *`` first, putting the
    row into ``claimed`` state with ``last_heartbeat_at=NOW()``.
  * Then it tried to construct ``Investigation.model_validate(row)``.
  * The model declared ``incident_time: datetime`` (non-null), so
    pydantic raised ``ValidationError``.
  * ``_try_claim`` caught the exception and returned ``None``. The row
    was left stuck in ``claimed`` status with the worker that never
    actually started any work — the heartbeat thread also never ran,
    so 5 minutes later the reaper killed it with ``"heartbeat older
    than 300s — worker presumed dead"``.

Three different workers reproduced this exact pattern on three
different containers before the bug was caught. Every wallet-trace
row would have wedged identically. The fix: every column that the
admin UI may legitimately leave NULL on a wallet-trace row MUST be
optional in the model.

These tests assert the model accepts every documented-nullable column
in a wallet-trace shape. They run in <10ms and don't touch the DB.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from recupero.worker.db import Investigation


def _minimal_wallet_trace_row() -> dict:
    """The minimum DB-row shape a Jacob-spec wallet-trace insert produces.

    Mirrors what the admin UI writes when an operator hits "Trace
    wallet" with no case association: case_id NULL, incident_time NULL,
    skip flags both True, label optional, seed_address + chain set.
    """
    return {
        "id": uuid4(),
        "case_id": None,
        "status": "pending",
        "triggered_by": "alec@recupero.io",
        "triggered_at": datetime.now(UTC),
        "worker_id": None,
        "claimed_at": None,
        "last_heartbeat_at": None,
        "started_at": None,
        "completed_at": None,
        "failed_at": None,
        "error_message": None,
        "error_stage": None,
        "review_required_at": None,
        "chain": "ethereum",
        "seed_address": "0x8E3b200f356724299643402148a25FD4B852Bd53",
        "incident_time": None,
        "max_depth": 2,
        "dust_threshold_usd": None,
        "label": None,
        "skip_editorial": True,
        "skip_freeze_briefs": True,
    }


def test_wallet_trace_row_validates() -> None:
    """The exact shape Jacob's UI inserts must parse without error.

    Regression: prior to the fix this raised ``ValidationError`` on
    ``incident_time`` because the field was declared non-null. The
    silent-catch in ``_try_claim`` masked the failure and the row sat
    in 'claimed' for 5min until the reaper killed it.
    """
    inv = Investigation.model_validate(_minimal_wallet_trace_row())
    assert inv.case_id is None
    assert inv.incident_time is None
    assert inv.skip_editorial is True
    assert inv.skip_freeze_briefs is True
    assert inv.chain == "ethereum"


def test_legacy_case_driven_row_still_validates() -> None:
    """Existing case-driven rows (case_id set, incident_time set, skip
    flags False) must continue to work. This is the v1 shape that
    pre-dates the wallet-trace migration — guarantees the fix didn't
    accidentally break the happy path."""
    row = _minimal_wallet_trace_row()
    row.update({
        "case_id": uuid4(),
        "incident_time": datetime(2024, 6, 15, 14, 30, tzinfo=UTC),
        "skip_editorial": False,
        "skip_freeze_briefs": False,
    })
    inv = Investigation.model_validate(row)
    assert inv.case_id is not None
    assert inv.incident_time is not None
    assert inv.skip_editorial is False


def test_extra_columns_ignored() -> None:
    """The investigations table grows over time. New columns the worker
    doesn't read (UI-only fields, future migrations) must be silently
    dropped, not rejected — otherwise a column-add migration becomes
    a worker-deploy coupling."""
    row = _minimal_wallet_trace_row()
    row["future_column_v8"] = "garbage"
    row["another_future_field"] = {"nested": True}
    inv = Investigation.model_validate(row)
    assert inv.id == row["id"]


def test_only_required_fields() -> None:
    """The pydantic model should accept rows that omit every nullable
    field. Useful for cron-inserted rows that bypass the admin UI
    entirely (e.g., the watch-tick promotion path)."""
    minimal = {
        "id": uuid4(),
        "status": "pending",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
    }
    inv = Investigation.model_validate(minimal)
    assert inv.case_id is None
    assert inv.incident_time is None
    assert inv.label is None
    assert inv.skip_editorial is False
    assert inv.skip_freeze_briefs is False
    assert inv.max_depth == 1
    assert inv.dust_threshold_usd is None


def test_missing_required_field_raises() -> None:
    """The handful of truly-required columns (id, status, chain,
    seed_address) must still raise when absent — these are NOT NULL
    in the schema and an absence is a real bug."""
    from pydantic import ValidationError

    for field in ("id", "status", "chain", "seed_address"):
        row = _minimal_wallet_trace_row()
        row.pop(field)
        with pytest.raises(ValidationError):
            Investigation.model_validate(row)
