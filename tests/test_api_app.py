"""Tests for the v0.15.1 FastAPI REST surface.

Exercises auth (missing key, bad key, dev bypass), rate limiting
(token-bucket exhaustion), and the four endpoints' response
shapes. Uses fastapi.testclient.TestClient so no live server is
needed.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from recupero.api.app import app
from recupero.api.auth import reset_buckets_for_tests


# ---- Fixtures ---- #


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A clean TestClient with rate-limit buckets reset per test."""
    reset_buckets_for_tests()
    with TestClient(app) as c:
        yield c
    reset_buckets_for_tests()


@pytest.fixture
def auth_env() -> Iterator[None]:
    """Configure a single API key 'tester:s3cret' for the test."""
    prev_keys = os.environ.get("RECUPERO_API_KEYS")
    prev_optional = os.environ.get("RECUPERO_API_AUTH_OPTIONAL")
    os.environ["RECUPERO_API_KEYS"] = "tester:s3cret"
    os.environ.pop("RECUPERO_API_AUTH_OPTIONAL", None)
    yield
    if prev_keys is None:
        os.environ.pop("RECUPERO_API_KEYS", None)
    else:
        os.environ["RECUPERO_API_KEYS"] = prev_keys
    if prev_optional is not None:
        os.environ["RECUPERO_API_AUTH_OPTIONAL"] = prev_optional


@pytest.fixture
def auth_bypass_env() -> Iterator[None]:
    """Enable RECUPERO_API_AUTH_OPTIONAL=1 (dev-bypass) for the test."""
    prev = os.environ.get("RECUPERO_API_AUTH_OPTIONAL")
    os.environ["RECUPERO_API_AUTH_OPTIONAL"] = "1"
    yield
    if prev is None:
        os.environ.pop("RECUPERO_API_AUTH_OPTIONAL", None)
    else:
        os.environ["RECUPERO_API_AUTH_OPTIONAL"] = prev


# ---- /v1/health (no auth) ---- #


def test_health_returns_200_unauthenticated(client: TestClient) -> None:
    """/v1/health must succeed without an API key — Railway /
    Kubernetes probes hit this unauthenticated."""
    r = client.get("/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert "uptime_seconds" in body
    assert body["uptime_seconds"] >= 0


def test_health_reports_git_sha_when_set(client: TestClient) -> None:
    prev = os.environ.get("RECUPERO_GIT_SHA")
    os.environ["RECUPERO_GIT_SHA"] = "abc123def"
    try:
        r = client.get("/v1/health")
        assert r.status_code == 200
        assert r.json()["git_sha"] == "abc123def"
    finally:
        if prev is None:
            os.environ.pop("RECUPERO_GIT_SHA", None)
        else:
            os.environ["RECUPERO_GIT_SHA"] = prev


# ---- Auth on /v1/screen ---- #


def test_screen_401_missing_api_key(client: TestClient, auth_env: None) -> None:
    r = client.post("/v1/screen", json={"address": "0xabc", "chain": "ethereum"})
    assert r.status_code == 401
    assert "Missing" in r.json()["detail"]


def test_screen_401_invalid_api_key(client: TestClient, auth_env: None) -> None:
    r = client.post(
        "/v1/screen",
        json={"address": "0xabc", "chain": "ethereum"},
        headers={"X-Recupero-API-Key": "wrong-secret"},
    )
    assert r.status_code == 401
    assert "Invalid" in r.json()["detail"]


def test_screen_happy_path_with_valid_key(
    client: TestClient, auth_env: None
) -> None:
    """A valid key + minimal payload should hit screen_address and
    return the to_json_safe()'d ScreeningResult dict."""
    r = client.post(
        "/v1/screen",
        json={
            "address": "0x0000000000000000000000000000000000000001",
            "chain": "ethereum",
            "use_correlation_db": False,
        },
        headers={"X-Recupero-API-Key": "s3cret"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # ScreeningResult.to_json_safe() shape
    assert "risk_verdict" in body
    assert "risk_score" in body
    assert "is_ofac_sanctioned" in body
    assert "is_mixer" in body
    assert "labels" in body
    assert "correlation" in body
    assert "data_sources_used" in body


def test_screen_works_with_auth_bypass(
    client: TestClient, auth_bypass_env: None
) -> None:
    """RECUPERO_API_AUTH_OPTIONAL=1 should let unauthenticated
    requests through. NEVER set in production."""
    r = client.post(
        "/v1/screen",
        json={
            "address": "0x0000000000000000000000000000000000000001",
            "chain": "ethereum",
            "use_correlation_db": False,
        },
    )
    assert r.status_code == 200, r.text


# ---- Rate limiting ---- #


def test_screen_429_after_burst_exhausted(
    client: TestClient, auth_env: None
) -> None:
    """Default burst is 20. Fire 25 rapid requests with the same
    key and the tail should be 429s."""
    payload = {
        "address": "0x0000000000000000000000000000000000000001",
        "chain": "ethereum",
        "use_correlation_db": False,
    }
    headers = {"X-Recupero-API-Key": "s3cret"}

    statuses = []
    for _ in range(25):
        r = client.post("/v1/screen", json=payload, headers=headers)
        statuses.append(r.status_code)

    # At least one 429 should appear in the tail — the bucket holds
    # ~20 tokens, refilling at 5/s, so 25 back-to-back exceeds it.
    assert 429 in statuses, statuses
    # And the FIRST request must have succeeded (bucket was full).
    assert statuses[0] == 200


# ---- /v1/token-risk ---- #


def test_token_risk_401_missing_key(
    client: TestClient, auth_env: None
) -> None:
    r = client.post(
        "/v1/token-risk",
        json={"contract_address": "0xtoken", "chain": "ethereum"},
    )
    assert r.status_code == 401


def test_token_risk_happy_path(
    client: TestClient, auth_bypass_env: None
) -> None:
    """No bytecode / tx-history / goplus → returns a 'clean' verdict
    (no signals) per score_token's empty-input contract."""
    r = client.post(
        "/v1/token-risk",
        json={
            "contract_address": "0xtoken",
            "chain": "ethereum",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["contract_address"] == "0xtoken"
    assert body["chain"] == "ethereum"
    assert body["verdict"] == "clean"
    assert "risk_score" in body
    assert "signals" in body


def test_token_risk_with_bytecode_signals(
    client: TestClient, auth_bypass_env: None
) -> None:
    """Bytecode supplied → bytecode_heuristic appears in
    data_sources_used regardless of whether signals fire."""
    r = client.post(
        "/v1/token-risk",
        json={
            "contract_address": "0xtoken",
            "chain": "ethereum",
            "bytecode": "0x6080604052",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "bytecode_heuristic" in body["data_sources_used"]


# ---- /v1/correlations ---- #


def test_correlations_503_when_dsn_unset(
    client: TestClient, auth_bypass_env: None
) -> None:
    """No SUPABASE_DB_URL → 503 (correlation lookup is unavailable
    rather than returning a misleading 'not found')."""
    prev = os.environ.get("SUPABASE_DB_URL")
    os.environ.pop("SUPABASE_DB_URL", None)
    try:
        r = client.get("/v1/correlations/0xabc")
        assert r.status_code == 503
        assert "SUPABASE_DB_URL" in r.json()["detail"]
    finally:
        if prev is not None:
            os.environ["SUPABASE_DB_URL"] = prev


def test_correlations_401_without_key(
    client: TestClient, auth_env: None
) -> None:
    r = client.get("/v1/correlations/0xabc")
    assert r.status_code == 401


def test_correlations_returns_not_found_when_lookup_empty(
    client: TestClient, auth_bypass_env: None
) -> None:
    """With a DSN set and lookup_correlations returning {},
    endpoint reports found=False with zero counts."""
    prev = os.environ.get("SUPABASE_DB_URL")
    os.environ["SUPABASE_DB_URL"] = "postgresql://fake:fake@localhost/none"
    try:
        with patch(
            "recupero.trace.correlation.lookup_correlations",
            return_value={},
        ):
            r = client.get("/v1/correlations/0xabc?chain=ethereum")
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["found"] is False
            assert body["total_prior_cases"] == 0
            assert body["address"] == "0xabc"
            assert body["chain"] == "ethereum"
    finally:
        if prev is None:
            os.environ.pop("SUPABASE_DB_URL", None)
        else:
            os.environ["SUPABASE_DB_URL"] = prev


# ---- OpenAPI surface ---- #


def test_openapi_spec_lists_endpoints(client: TestClient) -> None:
    """OpenAPI auto-spec at /openapi.json should list all four
    endpoints — exchanges and compliance teams use this to
    generate client SDKs."""
    r = client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    paths = spec["paths"]
    assert "/v1/health" in paths
    assert "/v1/screen" in paths
    assert "/v1/token-risk" in paths
    assert "/v1/correlations/{address}" in paths
    # The screen endpoint must declare a POST.
    assert "post" in paths["/v1/screen"]


def test_docs_endpoint_serves_swagger_ui(client: TestClient) -> None:
    """/docs serves the Swagger UI HTML page."""
    r = client.get("/docs")
    assert r.status_code == 200
    assert "swagger" in r.text.lower() or "openapi" in r.text.lower()
