"""Adversarial audit: /v1/correlations/{address} (the cross-case
correlation lookup endpoint in ``src/recupero/api/app.py``).

The endpoint serves aggregate prior-case counts for an address across
ALL operators (this is the documented "compounding-moat" capability —
no per-tenant isolation, BY DESIGN per recupero/trace/correlation.py).
The response carries ONLY aggregate counts + flags; no case_ids leak
out. The privacy hole would be if it did — see
``test_response_does_not_leak_case_ids``.

This file pins the input-shape gates so an authenticated caller can't:
  * pass a 16MB address path and force lookup_correlations to enumerate
    a giant ANY() query
  * pass bidi / zero-width / NUL / CRLF in the address to pollute logs
    or break downstream encoders
  * pass an unrecognized chain string and get a silent default
  * bypass the per-key rate limit
"""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

_API_SECRET = "secret-aaaaaaaaaaaaaaaaaaa"
_KEY = "tester"


@pytest.fixture(autouse=True)
def _isolate_buckets() -> Iterator[None]:
    from recupero.api.auth import reset_buckets_for_tests
    reset_buckets_for_tests()
    yield
    reset_buckets_for_tests()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("RECUPERO_API_KEYS", f"{_KEY}:{_API_SECRET}")
    monkeypatch.delenv("RECUPERO_API_AUTH_OPTIONAL", raising=False)
    monkeypatch.delenv("RECUPERO_API_KEY_ADMINS", raising=False)
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import app
    return TestClient(app)


_HDR = {"X-Recupero-API-Key": _API_SECRET}


# ─────────────────────────────────────────────────────────────────────────────
# 1. Address length cap — reject the 16MB payload
# ─────────────────────────────────────────────────────────────────────────────


def test_oversized_address_rejected(client: TestClient) -> None:
    """A 200-char address must be rejected (cap is 128, matching
    ScreenRequest.address). Without the cap an authenticated caller
    can submit a giant string and force lookup_correlations to walk it."""
    huge = "0x" + "a" * 500
    r = client.get(f"/v1/correlations/{huge}", headers=_HDR)
    assert r.status_code == 400, r.text


# ─────────────────────────────────────────────────────────────────────────────
# 2. NUL / CR / LF rejected (log injection + downstream encoder break)
# ─────────────────────────────────────────────────────────────────────────────


def test_nul_in_address_rejected(client: TestClient) -> None:
    # %00 must not silently fall through to _ck.
    r = client.get("/v1/correlations/0xabc%00def", headers=_HDR)
    assert r.status_code == 400, r.text


def test_crlf_in_address_rejected(client: TestClient) -> None:
    # %0D%0A — log-injection payload that lands in the api_key=%s log line.
    r = client.get("/v1/correlations/0xabc%0D%0AINJECTED", headers=_HDR)
    assert r.status_code == 400, r.text


# ─────────────────────────────────────────────────────────────────────────────
# 3. Bidi / zero-width trojans rejected in the address path
# ─────────────────────────────────────────────────────────────────────────────


def test_bidi_override_in_address_rejected(client: TestClient) -> None:
    # U+202E RIGHT-TO-LEFT OVERRIDE in the middle of the address.
    addr = "0xabc‮def"
    r = client.get(f"/v1/correlations/{addr}", headers=_HDR)
    assert r.status_code == 400, r.text


def test_zero_width_space_in_address_rejected(client: TestClient) -> None:
    addr = "0xabc​def"
    r = client.get(f"/v1/correlations/{addr}", headers=_HDR)
    assert r.status_code == 400, r.text


# ─────────────────────────────────────────────────────────────────────────────
# 4. Unsupported chain rejected (no silent default to ethereum)
# ─────────────────────────────────────────────────────────────────────────────


def test_unsupported_chain_rejected(client: TestClient) -> None:
    r = client.get(
        "/v1/correlations/0x" + "a" * 40 + "?chain=foobar",
        headers=_HDR,
    )
    assert r.status_code == 400, r.text


# ─────────────────────────────────────────────────────────────────────────────
# 5. Per-key rate limit applies to correlations (NOT just /v1/screen)
# ─────────────────────────────────────────────────────────────────────────────


def test_correlations_rate_limited_per_key(client: TestClient) -> None:
    """Burst is 20; 25 rapid GETs against the same key must produce 429s
    in the tail. This guards against a cheap per-key DoS vector
    (correlations does a DB hit per request)."""
    addr = "0x" + "a" * 40
    with patch(
        "recupero.trace.correlation.lookup_correlations",
        return_value={},
    ):
        statuses = [
            client.get(f"/v1/correlations/{addr}", headers=_HDR).status_code
            for _ in range(25)
        ]
    assert 429 in statuses, statuses


# ─────────────────────────────────────────────────────────────────────────────
# 6. Response does NOT leak case_ids from other operators
# ─────────────────────────────────────────────────────────────────────────────


def test_response_does_not_leak_case_ids(client: TestClient) -> None:
    """The endpoint returns aggregate counts ONLY — never the raw case_id
    list. Cross-case counts are intentional (compounding-moat); but the
    case_id values would identify other operators' victims."""
    from decimal import Decimal
    from uuid import UUID

    from recupero.trace.correlation import (
        CorrelationResult,
        PriorCaseAppearance,
    )
    fake_case_id = UUID("11111111-1111-1111-1111-111111111111")
    fake_result = {
        ("0x" + "a" * 40): CorrelationResult(
            address="0x" + "a" * 40,
            chain="ethereum",
            total_prior_cases=3,
            prior_ofac_exposed_count=1,
            prior_mixer_exposed_count=0,
            prior_drainer_attributed_count=2,
            prior_total_usd_flowed=Decimal("12345.67"),
            prior_roles_seen=["hop", "perpetrator_hub"],
            prior_case_appearances=[
                PriorCaseAppearance(
                    case_id=fake_case_id,
                    role="perpetrator_hub",
                    label_category=None,
                    label_name=None,
                    usd_flowed=Decimal("100"),
                    risk_verdict="malicious",
                    observed_at_iso="2025-01-01T00:00:00Z",
                ),
            ],
        ),
    }
    with patch(
        "recupero.trace.correlation.lookup_correlations",
        return_value=fake_result,
    ):
        r = client.get(
            "/v1/correlations/0x" + "a" * 40,
            headers=_HDR,
        )
    assert r.status_code == 200, r.text
    body_text = r.text
    # The raw case_id UUID string must NOT appear anywhere in the
    # JSON response — only aggregate counts + roles are public.
    assert str(fake_case_id) not in body_text, (
        f"Endpoint leaked case_id {fake_case_id} to caller — "
        f"cross-tenant disclosure"
    )
    body = r.json()
    assert "prior_case_appearances" not in body
    assert body["total_prior_cases"] == 3
