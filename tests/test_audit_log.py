"""Audit-log store + endpoint (SOC 2 CC6/CC7). DB-free contract + fake-DB path.

The full DB round-trip runs in prod against Postgres; these pin the CI-safe
contract: no DSN → no connection; a DB error never propagates (the audited
action must not break); the INSERT carries the right append-only columns; and
the /v1/audit endpoint is admin-gated + degrades to empty without a DB.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from recupero.audit import list_audit_events, record_audit_event
from recupero.audit import store as audit_store

# ---- fake DB plumbing ---- #


class _FakeCursor:
    def __init__(self, rows=None) -> None:
        self.executed: list[tuple] = []
        self._rows = rows or []

    def execute(self, sql, params=None):  # noqa: ANN001
        self.executed.append((sql, params))

    def fetchall(self):
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):  # noqa: ANN002
        return False


class _FakeConn:
    def __init__(self, cur) -> None:
        self._cur = cur

    def cursor(self):
        return self._cur

    def __enter__(self):
        return self

    def __exit__(self, *exc):  # noqa: ANN002
        return False


def _patch_db(monkeypatch, cur, *, raise_on_connect=False) -> None:
    @contextmanager
    def _fake_db_connect(dsn, **kw) -> Iterator[_FakeConn]:  # noqa: ANN001
        if raise_on_connect:
            raise RuntimeError("db down")
        yield _FakeConn(cur)
    monkeypatch.setattr("recupero._common.db_connect", _fake_db_connect)


# ---- DB-free contract ---- #


def test_record_no_dsn_returns_false() -> None:
    # Unreachable DSN would raise if a connection were attempted; None short-
    # circuits to False before any connect.
    assert record_audit_event(None, actor="a", action="label.promote") is False


def test_list_no_dsn_returns_empty() -> None:
    assert list_audit_events(None) == []


# ---- record path ---- #


def test_record_inserts_append_only_columns(monkeypatch) -> None:
    cur = _FakeCursor()
    _patch_db(monkeypatch, cur)
    ok = record_audit_event(
        "postgresql://x", actor="tester@x", action="label.promote",
        target="0xabc", target_kind="label_candidate",
        metadata={"candidate_id": 7, "category": "bridge"},
    )
    assert ok is True
    assert len(cur.executed) == 1
    sql, params = cur.executed[0]
    assert "INSERT INTO public.audit_log" in sql
    assert "tester@x" in params and "label.promote" in params and "0xabc" in params


def test_record_never_raises_on_db_error(monkeypatch) -> None:
    cur = _FakeCursor()
    _patch_db(monkeypatch, cur, raise_on_connect=True)
    # Must return False, NOT raise — an audit failure cannot break the action.
    assert record_audit_event("postgresql://x", actor="a", action="x") is False


def test_metadata_capped() -> None:
    huge = {"blob": "x" * 10_000}
    encoded = audit_store._safe_metadata(huge)
    assert len(encoded) < 200 and "_truncated" in encoded


def test_list_parses_rows(monkeypatch) -> None:
    rows = [(
        1, None, "tester", "label.reject", "0xdef", "label_candidate",
        "success", "1.2.3.4", '{"reason": "spoof"}',
    )]
    cur = _FakeCursor(rows=rows)
    _patch_db(monkeypatch, cur)
    out = list_audit_events("postgresql://x", limit=10)
    assert len(out) == 1
    assert out[0].action == "label.reject"
    assert out[0].metadata == {"reason": "spoof"}
    assert out[0].to_json_safe()["actor"] == "tester"


def test_list_filter_builds_safe_where(monkeypatch) -> None:
    cur = _FakeCursor(rows=[])
    _patch_db(monkeypatch, cur)
    list_audit_events("postgresql://x", actor="a", action="label.promote", limit=5)
    sql, params = cur.executed[0]
    assert "WHERE actor = %s AND action = %s" in sql
    assert params == ("a", "label.promote", 5)


# ---- /v1/audit endpoint ---- #


@pytest.fixture
def client() -> Iterator[TestClient]:
    from recupero.api.app import app
    with TestClient(app) as c:
        yield c


def test_audit_endpoint_503_without_admin_key(client, monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    r = client.get("/v1/audit")
    assert r.status_code == 503


def test_audit_endpoint_401_wrong_key(client, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    r = client.get("/v1/audit", headers={"X-Recupero-Admin-Key": "wrong"})
    assert r.status_code == 401


def test_audit_endpoint_empty_without_dsn(client, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    r = client.get("/v1/audit", headers={"X-Recupero-Admin-Key": "secret"})
    assert r.status_code == 200
    body = r.json()
    assert body == {"events": [], "count": 0, "db_configured": False}
