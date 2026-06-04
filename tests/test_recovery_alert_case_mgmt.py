"""KYT alert case-management (#10) — store update + PATCH endpoint.

Adds an assign/transition/note lifecycle on the recovery-alerts queue. DB-free
validation + a fake-DB update path; the PATCH endpoint is admin-gated and
audit-logged.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from recupero.monitoring import recovery_alerts_store as store

# ---- fake DB ---- #


class _FakeCursor:
    def __init__(self, fetchone=None) -> None:
        self.executed: list[tuple] = []
        self._fetchone = fetchone

    def execute(self, sql, params=None):  # noqa: ANN001
        self.executed.append((sql, params))

    def fetchone(self):
        return self._fetchone

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


def _patch(monkeypatch, cur) -> None:
    @contextmanager
    def _fake(dsn, **kw):  # noqa: ANN001
        yield _FakeConn(cur)
    monkeypatch.setattr(store, "db_connect", _fake)


# ---- store: validation (DB-free) ---- #


def test_invalid_status_raises_before_db() -> None:
    # Bad status must raise BEFORE any connection (unreachable DSN would error).
    with pytest.raises(ValueError, match="invalid status"):
        store.update_alert_case("postgresql://nope:1@127.0.0.1:1/x", 1, status="bogus")


def test_invalid_alert_id_raises() -> None:
    with pytest.raises(ValueError, match="invalid alert_id"):
        store.update_alert_case("postgresql://x", "not-an-int", assignee="a")


def test_lifecycle_statuses_allowed() -> None:
    assert {"open", "acknowledged", "in_progress", "resolved", "dismissed"} <= set(
        store._ALLOWED_STATUS
    )


# ---- store: update path ---- #


def test_update_returns_row(monkeypatch) -> None:
    cur = _FakeCursor(fetchone=(
        7, "0xabc", "ethereum", "critical", "freezable_outflow",
        "in_progress", "analyst@x", "looking into it",
    ))
    _patch(monkeypatch, cur)
    out = store.update_alert_case(
        "postgresql://x", 7, status="in_progress",
        assignee="analyst@x", note="looking into it",
    )
    assert out is not None
    assert out["id"] == 7 and out["status"] == "in_progress"
    assert out["assignee"] == "analyst@x"
    # COALESCE-based single UPDATE; status passed twice (set + changed_at CASE).
    sql, params = cur.executed[0]
    assert "COALESCE" in sql and "UPDATE public.recovery_alerts" in sql
    assert params == ("in_progress", "analyst@x", "looking into it", "in_progress", 7)


def test_update_not_found_returns_none(monkeypatch) -> None:
    cur = _FakeCursor(fetchone=None)
    _patch(monkeypatch, cur)
    assert store.update_alert_case("postgresql://x", 999, status="resolved") is None


# ---- PATCH endpoint ---- #


@pytest.fixture
def client() -> Iterator[TestClient]:
    from recupero.api.app import app
    with TestClient(app) as c:
        yield c


def test_patch_503_without_admin_key(client, monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    r = client.patch("/v1/recovery-alerts/1", json={"status": "resolved"})
    assert r.status_code == 503


def test_patch_401_wrong_key(client, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    r = client.patch("/v1/recovery-alerts/1", json={"status": "resolved"},
                     headers={"X-Recupero-Admin-Key": "wrong"})
    assert r.status_code == 401


def test_patch_503_without_dsn(client, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    r = client.patch("/v1/recovery-alerts/1", json={"status": "resolved"},
                     headers={"X-Recupero-Admin-Key": "secret"})
    assert r.status_code == 503


def test_patch_success(client, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://x")
    updated = {"id": 5, "status": "resolved", "assignee": "a", "resolution_note": "done"}
    monkeypatch.setattr(
        "recupero.monitoring.recovery_alerts_store.update_alert_case",
        lambda dsn, aid, **kw: updated,
    )
    r = client.patch("/v1/recovery-alerts/5", json={"status": "resolved", "note": "done"},
                     headers={"X-Recupero-Admin-Key": "secret"})
    assert r.status_code == 200, r.text
    assert r.json() == {"alert": updated, "updated": True}


def test_patch_404_when_alert_missing(client, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://x")
    monkeypatch.setattr(
        "recupero.monitoring.recovery_alerts_store.update_alert_case",
        lambda dsn, aid, **kw: None,
    )
    r = client.patch("/v1/recovery-alerts/999", json={"status": "resolved"},
                     headers={"X-Recupero-Admin-Key": "secret"})
    assert r.status_code == 404


def test_patch_400_no_fields(client, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://x")
    r = client.patch("/v1/recovery-alerts/1", json={},
                     headers={"X-Recupero-Admin-Key": "secret"})
    assert r.status_code == 400
