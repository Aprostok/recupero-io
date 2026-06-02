"""Tests for the Label-Freshness operator console + admin JSON endpoint.

Builds a LOCAL FastAPI app mounting only ``freshness_api.router`` so these
tests exercise the router in isolation (no app.py coupling).
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero.api.freshness_api import router


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_freshness_json_503_when_admin_key_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    res = client.get("/v1/freshness")
    assert res.status_code == 503


def test_freshness_json_401_on_wrong_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/freshness", headers={"X-Recupero-Admin-Key": "wrong-key"}
    )
    assert res.status_code == 401


def test_freshness_json_200_with_correct_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/freshness", headers={"X-Recupero-Admin-Key": "correct-key"}
    )
    assert res.status_code == 200
    body = res.json()
    assert "sources" in body
    assert "summary" in body


def test_freshness_console_shell_is_unauthenticated_html(
    client: TestClient,
) -> None:
    res = client.get("/v1/freshness/console")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    html = res.text
    assert "Label Freshness" in html
    assert "X-Recupero-Admin-Key" in html
    assert "/v1/freshness" in html
