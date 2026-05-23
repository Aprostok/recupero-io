"""Lock the UUID-validation contract on fetch_live_filing_status.

RIGOR-Jacob (regression lock): `freeze_letters_sent.case_id` and
`freeze_letters_sent.investigation_id` are UUID-typed columns. The
worker pipeline can pass either:

  * A real UUID (production path — `cases.id` is a UUID); OR
  * A synthetic brief identifier (e.g. ``"V-CFI01"``) for test
    fixtures and CLI emit_brief invocations.

Pre-fix, when a non-UUID was passed the SQL raised
``invalid input syntax for type uuid: "V-CFI01"``. The function's
broad try/except swallowed it as a WARN log, but
``test_prod_no_silent_errors`` (correctly) rejects any WARN — so
the V-CFI01 production-path test broke the entire suite. Fix:
validate up-front, return empty status silently when the filter
value isn't a UUID. Same fail-closed shape as "no DSN configured".

These tests pin that behavior. A future refactor that drops the
guard would re-introduce the V-CFI01 regression and fail here.
"""

from __future__ import annotations

import logging
from unittest.mock import patch
from uuid import uuid4


def test_non_uuid_case_id_returns_empty_silently(caplog) -> None:
    """case_id='V-CFI01' (a non-UUID string) returns an empty status
    WITHOUT a WARN log. The caller's expectation is "this case has no
    DB-recorded freeze letters yet" — same as the no-DSN branch."""
    from recupero.freeze_learning.status import fetch_live_filing_status

    with caplog.at_level(logging.WARNING, logger="recupero.freeze_learning.status"):
        result = fetch_live_filing_status(
            case_id="V-CFI01",
            dsn="postgresql://fake:fake@nowhere/never",
        )

    assert result.is_empty is True
    assert not result.letters
    # The critical regression-lock: no WARN, no ERROR. A DEBUG
    # message is acceptable.
    warn_or_error = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING
        and r.name == "recupero.freeze_learning.status"
    ]
    assert not warn_or_error, (
        f"non-UUID case_id should not emit WARN; got: "
        f"{[r.getMessage() for r in warn_or_error]}"
    )


def test_non_uuid_investigation_id_returns_empty_silently(caplog) -> None:
    """Same contract for investigation_id."""
    from recupero.freeze_learning.status import fetch_live_filing_status

    with caplog.at_level(logging.WARNING, logger="recupero.freeze_learning.status"):
        result = fetch_live_filing_status(
            investigation_id="not-a-uuid",
            dsn="postgresql://fake:fake@nowhere/never",
        )

    assert result.is_empty is True
    warn_or_error = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING
        and r.name == "recupero.freeze_learning.status"
    ]
    assert not warn_or_error


def test_valid_uuid_case_id_attempts_db_call() -> None:
    """The guard ONLY skips on non-UUID input. A real UUID must still
    reach the SQL path. We patch ``recupero._common.db_connect`` (the
    canonical import location — the status module imports it inside
    the function body, so module-level patching wouldn't intercept).
    """
    import recupero._common as common_mod
    from recupero.freeze_learning import status as status_mod

    real_uuid = uuid4()
    called = {"hit": False}

    class FakeCursor:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def execute(self, sql, params):
            called["hit"] = True
            called["sql"] = sql
            called["params"] = params
        def fetchall(self): return []
        def fetchone(self):
            return {
                "active_subs": 0, "alerts_fired": 0,
                "last_alert_at": None,
            }

    class FakeConn:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def cursor(self): return FakeCursor()

    def fake_connect(dsn, **kwargs):
        return FakeConn()

    with patch.object(common_mod, "db_connect", fake_connect):
        status_mod.fetch_live_filing_status(
            case_id=real_uuid,
            dsn="postgresql://fake:fake@nowhere/never",
        )

    assert called["hit"] is True, (
        "valid UUID case_id should reach the SQL path — guard is "
        "over-zealous if this fails"
    )


def test_none_case_id_and_investigation_id_returns_empty() -> None:
    """No filter key supplied — return empty (existing contract,
    unchanged by the UUID guard)."""
    from recupero.freeze_learning.status import fetch_live_filing_status

    result = fetch_live_filing_status(
        case_id=None,
        investigation_id=None,
        dsn="postgresql://fake:fake@nowhere/never",
    )
    assert result.is_empty is True


def test_empty_string_case_id_returns_empty_silently(caplog) -> None:
    """Edge case: case_id='' should be treated as non-UUID, return
    empty silently. Defensive — an upstream bug that produces '' must
    not crash the deliverable pipeline."""
    from recupero.freeze_learning.status import fetch_live_filing_status

    with caplog.at_level(logging.WARNING, logger="recupero.freeze_learning.status"):
        result = fetch_live_filing_status(
            case_id="",
            dsn="postgresql://fake:fake@nowhere/never",
        )

    assert result.is_empty is True
    warn_or_error = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING
        and r.name == "recupero.freeze_learning.status"
    ]
    # An empty string with no investigation_id triggers the existing
    # "called without case_id or investigation_id" WARN — that's the
    # documented contract and we don't want to silently mask it.
    # The UUID guard kicks in ONLY when case_id is truthy-but-non-UUID.
    # Accept either zero WARNs OR exactly the misuse WARN.
    if warn_or_error:
        assert len(warn_or_error) == 1
        assert "without case_id" in warn_or_error[0].getMessage()
