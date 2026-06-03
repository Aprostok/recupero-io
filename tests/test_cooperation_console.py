"""Tests for the Cooperation-Intelligence operator console + admin JSON endpoint.

Builds a LOCAL FastAPI app mounting only ``cooperation_api.router`` so these
tests exercise the router in isolation (no app.py coupling).

The no-DB path is the load-bearing contract: with a valid admin key but
``SUPABASE_DB_URL`` unset, the JSON endpoint MUST degrade to an empty 200 body
({"profiles": [], "count": 0, "db_configured": False}) — never a 500, and
without requiring a DB / psycopg to import or run the tests.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero.api.cooperation_api import router


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_cooperation_json_503_when_admin_key_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    res = client.get("/v1/cooperation")
    assert res.status_code == 503


def test_cooperation_json_401_on_wrong_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/cooperation", headers={"X-Recupero-Admin-Key": "wrong-key"}
    )
    assert res.status_code == 401


def test_cooperation_console_shell_is_unauthenticated_html(
    client: TestClient,
) -> None:
    res = client.get("/v1/cooperation/console")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    html = res.text
    assert "Cooperation" in html
    assert "X-Recupero-Admin-Key" in html
    assert "/v1/cooperation" in html


def test_cooperation_json_degrades_to_empty_when_no_db(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Valid admin key but no DB configured → empty 200, never a 500 and
    # never touching the DB layer.
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    res = client.get(
        "/v1/cooperation", headers={"X-Recupero-Admin-Key": "correct-key"}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["profiles"] == []
    assert body["count"] == 0
    assert body["db_configured"] is False
