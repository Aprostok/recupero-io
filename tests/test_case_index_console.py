"""Tests for the Case-Index operator console + admin JSON endpoint.

Builds a LOCAL FastAPI app mounting only ``case_index_api.router`` so these
tests exercise the router in isolation (no app.py coupling). The JSON endpoint
is a directory scan over the configured cases_root; in the test env there may be
0 cases, so we assert the response SHAPE, not its contents.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero.api.case_index_api import router


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_cases_json_503_when_admin_key_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    res = client.get("/v1/cases")
    assert res.status_code == 503


def test_cases_json_401_on_wrong_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/cases", headers={"X-Recupero-Admin-Key": "wrong-key"}
    )
    assert res.status_code == 401


def test_cases_json_200_with_correct_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/cases", headers={"X-Recupero-Admin-Key": "correct-key"}
    )
    assert res.status_code == 200
    body = res.json()
    # Assert the SHAPE, not the contents — the test env may have 0 cases.
    assert "cases" in body
    assert isinstance(body["cases"], list)
    assert "count" in body
    assert isinstance(body["count"], int)


def test_cases_console_shell_is_unauthenticated_html(
    client: TestClient,
) -> None:
    res = client.get("/v1/cases/console")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    html = res.text
    assert "Case Index" in html
    assert "X-Recupero-Admin-Key" in html
    assert "/v1/cases" in html
