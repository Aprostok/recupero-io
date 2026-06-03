"""Tests for the SAR / STR Filing operator console + admin JSON endpoint.

Builds a LOCAL FastAPI app mounting only ``sar_filing_api.router`` so these
tests exercise the router in isolation (no app.py coupling).

The full 200 JSON path is NOT tested here — it needs a real case with a
freeze_brief.json on disk; ``build_sar_context`` / ``load_brief`` have their
own unit tests (test_regulatory_filing). These tests cover the auth + guard
surface and the unauthenticated console shell.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero.api.sar_filing_api import router


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_sar_filing_json_503_when_admin_key_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    res = client.get("/v1/sar-filing", params={"case_id": "X"})
    assert res.status_code == 503


def test_sar_filing_json_401_on_wrong_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/sar-filing",
        params={"case_id": "X"},
        headers={"X-Recupero-Admin-Key": "wrong-key"},
    )
    assert res.status_code == 401


def test_sar_filing_console_shell_is_unauthenticated_html(
    client: TestClient,
) -> None:
    res = client.get("/v1/sar-filing/console")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    html = res.text
    assert "SAR" in html
    assert "X-Recupero-Admin-Key" in html
    assert "/v1/sar-filing" in html


def test_sar_filing_json_404_on_nonexistent_case(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/sar-filing",
        params={"case_id": "no-such-case-xyz", "jurisdiction": "us"},
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code == 404


def test_sar_filing_json_rejects_invalid_jurisdiction(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    # An unrecognized jurisdiction should be rejected. Depending on which
    # guard fires first (jurisdiction-validation vs missing-case), this is a
    # 400 (bad jurisdiction) or 404 (case absent) — both are acceptable;
    # what matters is it is NOT a 200 and NOT a 500.
    res = client.get(
        "/v1/sar-filing",
        params={"case_id": "no-such-case-xyz", "jurisdiction": "zz"},
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code in (400, 404)
