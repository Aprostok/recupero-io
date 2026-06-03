"""Tests for the Trace-Benchmark operator console + admin JSON endpoint.

Builds a LOCAL FastAPI app mounting only ``benchmark_api.router`` so these tests
exercise the router in isolation (no app.py coupling).

The 200 JSON path is NOT tested here — it needs a real produced case with a
``case.json`` + ``freeze_brief.json`` AND an independently-verified
``ground_truth.json`` on disk; the scorer (load_ground_truth / score_case_dir)
has its own unit tests. This console is strictly read-only and never recomputes
the trace or derives the ground truth (that would be circular).
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero.api.benchmark_api import router


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_benchmark_json_503_when_admin_key_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    res = client.get("/v1/benchmark", params={"case_id": "X"})
    assert res.status_code == 503


def test_benchmark_json_401_on_wrong_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/benchmark",
        params={"case_id": "X"},
        headers={"X-Recupero-Admin-Key": "wrong-key"},
    )
    assert res.status_code == 401


def test_benchmark_json_404_on_missing_case(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    # A valid-shaped but nonexistent case id resolves to no case on disk → 404.
    res = client.get(
        "/v1/benchmark",
        params={"case_id": "no-such-case-xyz"},
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code == 404


def test_benchmark_json_guarded_on_blank_case_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    # Whitespace-only: param is present (so not necessarily a 422) but blank →
    # our 400. Accept the FastAPI-version-dependent shapes too.
    res = client.get(
        "/v1/benchmark",
        params={"case_id": "  "},
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code in {400, 404, 422}


def test_benchmark_console_shell_is_unauthenticated_html(
    client: TestClient,
) -> None:
    res = client.get("/v1/benchmark/console")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    html = res.text
    assert "Benchmark" in html
    assert "X-Recupero-Admin-Key" in html
    assert "/v1/benchmark" in html
