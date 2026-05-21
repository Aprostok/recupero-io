"""Tests for v0.21.0 freeze-outcome intake — API + recorder + ops CLI.

Covers:
  * record_outcome_by_target — happy path, 404 path, 422 path
  * VALID_OUTCOME_TYPES — includes silence_14d from migration 018
  * POST /v1/freeze-outcomes — 201 / 404 / 422 / 503 paths
  * Auth required (no api key → 401)
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from recupero.freeze_learning.recorder import (
    VALID_OUTCOME_TYPES,
    LetterNotFoundError,
    record_outcome_by_target,
)

CASE_ID = UUID("99999999-9999-9999-9999-999999999999")
LETTER_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
OUTCOME_ID = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
TARGET = "0xT" + "0" * 39


# ─────────────────────────────────────────────────────────────────────────────
# VALID_OUTCOME_TYPES — schema parity
# ─────────────────────────────────────────────────────────────────────────────


def test_valid_outcome_types_includes_silence_14d():
    """Migration 018 extended the freeze_outcomes CHECK constraint to
    include silence_14d. VALID_OUTCOME_TYPES must mirror this so the
    Python-side validation matches the DB-side."""
    assert "silence_14d" in VALID_OUTCOME_TYPES
    assert "full_freeze" in VALID_OUTCOME_TYPES
    assert "returned_to_victim" in VALID_OUTCOME_TYPES


def test_valid_outcome_types_excludes_invalid_strings():
    """A typo (eg 'frozen' instead of 'full_freeze') must be rejected
    by Python-side validation before reaching the DB."""
    assert "frozen" not in VALID_OUTCOME_TYPES
    assert "freeze" not in VALID_OUTCOME_TYPES
    assert "" not in VALID_OUTCOME_TYPES


# ─────────────────────────────────────────────────────────────────────────────
# record_outcome_by_target — DB-mocked unit tests
# ─────────────────────────────────────────────────────────────────────────────


def test_record_by_target_raises_on_unknown_outcome_type():
    """ValueError on a non-VALID outcome type, before any DB call.

    Defends against typo-driven CHECK constraint failures.
    """
    with pytest.raises(ValueError):
        record_outcome_by_target(
            case_id=CASE_ID,
            issuer="Tether",
            target_address=TARGET,
            outcome_type="totally-frozen",   # invalid
            dsn="postgres://fake",
        )


def test_record_by_target_raises_letter_not_found():
    """When no matching freeze_letters_sent row exists, the function
    raises LetterNotFoundError so the API layer can produce a 404."""

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchone(self):
            return None  # no matching letter
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    from recupero.freeze_learning import recorder as rec
    with patch.object(rec, "db_connect", return_value=_StubConn()):
        with pytest.raises(LetterNotFoundError):
            record_outcome_by_target(
                case_id=CASE_ID,
                issuer="Tether",
                target_address=TARGET,
                outcome_type="acknowledged",
                dsn="postgres://fake",
            )


def test_record_by_target_happy_path_delegates_to_record_outcome():
    """Letter found → record_outcome() called with the resolved letter_id."""

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchone(self):
            return (LETTER_ID,)
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    captured_kwargs: dict = {}

    def _stub_record_outcome(**kwargs):
        captured_kwargs.update(kwargs)
        return OUTCOME_ID

    from recupero.freeze_learning import recorder as rec
    with patch.object(rec, "db_connect", return_value=_StubConn()), \
         patch.object(rec, "record_outcome", side_effect=_stub_record_outcome):
        outcome_id = record_outcome_by_target(
            case_id=CASE_ID,
            issuer="Tether",
            target_address=TARGET,
            outcome_type="full_freeze",
            frozen_usd=Decimal("1200000"),
            dsn="postgres://fake",
        )

    assert outcome_id == OUTCOME_ID
    assert captured_kwargs["letter_id"] == LETTER_ID
    assert captured_kwargs["outcome_type"] == "full_freeze"
    assert captured_kwargs["frozen_usd"] == Decimal("1200000")


# ─────────────────────────────────────────────────────────────────────────────
# POST /v1/freeze-outcomes — API surface
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def api_client(monkeypatch):
    """FastAPI TestClient with API key auth wired up + DSN env set.

    Auth scheme: RECUPERO_API_KEYS is a comma list of name:secret
    pairs. The X-Recupero-API-Key header carries the SECRET.

    v0.28.0 (S-1): the test key is granted admin authorization so
    legacy tests (which pre-date the multi-tenant gate) still pass.
    New tests that exercise the gate use a separate fixture that
    omits the admin grant.
    """
    monkeypatch.setenv("RECUPERO_API_KEYS", "tester:secret-test-token-xyz")
    monkeypatch.setenv("RECUPERO_API_KEY_ADMINS", "tester")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import app
    return TestClient(app)


def _post_outcome(client, payload, api_secret="secret-test-token-xyz"):
    return client.post(
        "/v1/freeze-outcomes",
        json=payload,
        headers={"X-Recupero-API-Key": api_secret},
    )


def test_api_freeze_outcome_201_on_happy_path(api_client):
    """201 with outcome_id in the body when the recorder succeeds."""
    with patch(
        "recupero.freeze_learning.recorder.record_outcome_by_target",
        return_value=OUTCOME_ID,
    ):
        resp = _post_outcome(api_client, {
            "case_id": str(CASE_ID),
            "issuer": "Tether",
            "target_address": TARGET,
            "outcome_type": "full_freeze",
            "frozen_usd": 1200000.0,
        })
    assert resp.status_code == 201
    body = resp.json()
    assert body["outcome_id"] == str(OUTCOME_ID)
    assert body["case_id"] == str(CASE_ID)
    assert body["issuer"] == "Tether"
    assert body["outcome_type"] == "full_freeze"


def test_api_freeze_outcome_404_when_letter_not_found(api_client):
    """LetterNotFoundError → 404. v0.28.0 (S-1): the detail is now
    generic ('freeze outcome not recorded') instead of echoing the
    LetterNotFoundError message, which previously leaked the
    submitted (case_id, issuer, target_address) triple back via
    a body-diff oracle. Auditing path verified: the response body
    is byte-identical to the unauthorized-access body, so a probing
    attacker can no longer distinguish missing-letter from
    not-authorized."""
    with patch(
        "recupero.freeze_learning.recorder.record_outcome_by_target",
        side_effect=LetterNotFoundError("no match (case=X issuer=Y target=Z)"),
    ):
        resp = _post_outcome(api_client, {
            "case_id": str(CASE_ID),
            "issuer": "Coinbase",
            "target_address": TARGET,
            "outcome_type": "acknowledged",
        })
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    # Generic message; MUST NOT echo any input/internal detail.
    assert detail == "freeze outcome not recorded"
    assert "case=" not in detail
    assert "target=" not in detail


def test_api_freeze_outcome_422_on_invalid_outcome_type(api_client):
    """A typo like 'frozen' → 422 (rejected before DB call)."""
    resp = _post_outcome(api_client, {
        "case_id": str(CASE_ID),
        "issuer": "Tether",
        "target_address": TARGET,
        "outcome_type": "frozen",   # invalid
    })
    assert resp.status_code == 422


def test_api_freeze_outcome_422_on_invalid_case_uuid(api_client):
    """Non-UUID case_id → 422 with clear error message."""
    resp = _post_outcome(api_client, {
        "case_id": "not-a-uuid",
        "issuer": "Tether",
        "target_address": TARGET,
        "outcome_type": "acknowledged",
    })
    assert resp.status_code == 422
    assert "UUID" in resp.json()["detail"]


def test_api_freeze_outcome_401_without_api_key(api_client):
    """Auth required — missing X-API-Key header → 401."""
    resp = api_client.post(
        "/v1/freeze-outcomes",
        json={
            "case_id": str(CASE_ID),
            "issuer": "Tether",
            "target_address": TARGET,
            "outcome_type": "acknowledged",
        },
    )
    assert resp.status_code in (401, 403)


def test_api_freeze_outcome_503_when_dsn_unset(api_client, monkeypatch):
    """Without SUPABASE_DB_URL → 503 (don't leak that we're DB-backed
    with a raw error to the caller — generic 'unavailable' detail)."""
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    resp = _post_outcome(api_client, {
        "case_id": str(CASE_ID),
        "issuer": "Tether",
        "target_address": TARGET,
        "outcome_type": "acknowledged",
    })
    assert resp.status_code == 503
    assert "unavailable" in resp.json()["detail"].lower()


def test_api_freeze_outcome_503_does_not_leak_dsn_on_runtime_error(api_client):
    """If record_outcome_by_target raises RuntimeError (e.g. embedded
    DSN in psycopg error message), the API must return a generic 503
    rather than echoing the message."""
    with patch(
        "recupero.freeze_learning.recorder.record_outcome_by_target",
        side_effect=RuntimeError(
            "DB error at host=db.xxxxxxxxxxxxxxxx.supabase.co:6543 "
            "password=secret123",
        ),
    ):
        resp = _post_outcome(api_client, {
            "case_id": str(CASE_ID),
            "issuer": "Tether",
            "target_address": TARGET,
            "outcome_type": "full_freeze",
        })
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert "password" not in detail
    assert "supabase.co" not in detail
    assert "record failed" in detail.lower()
