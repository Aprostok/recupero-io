"""Tests for the Graph-Analysis operator console + admin JSON endpoint.

Builds a LOCAL FastAPI app mounting only ``graph_analysis_api.router`` so these
tests exercise the router in isolation (no app.py coupling).

The 200 JSON path is NOT tested here — it needs a real case on disk; the graph
algorithms themselves have their own unit tests (test for graph_analysis).
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero.api.graph_analysis_api import router


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_graph_analysis_json_503_when_admin_key_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    res = client.get("/v1/graph-analysis", params={"case_id": "X"})
    assert res.status_code == 503


def test_graph_analysis_json_401_on_wrong_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/graph-analysis",
        params={"case_id": "X"},
        headers={"X-Recupero-Admin-Key": "wrong-key"},
    )
    assert res.status_code == 401


def test_graph_analysis_json_400_on_blank_case_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    # Whitespace-only: param is present (so not a 422) but blank → our 400.
    res = client.get(
        "/v1/graph-analysis",
        params={"case_id": "   "},
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code == 400


def test_graph_analysis_json_400_on_empty_case_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/graph-analysis",
        params={"case_id": ""},
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code == 400


def test_graph_analysis_console_shell_is_unauthenticated_html(
    client: TestClient,
) -> None:
    res = client.get("/v1/graph-analysis/console")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    html = res.text
    assert "Graph Analysis" in html
    assert "X-Recupero-Admin-Key" in html
    assert "/v1/graph-analysis" in html
