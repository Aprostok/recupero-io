"""Tests for the Bulk-Screening operator console + admin JSON endpoints.

Builds a LOCAL FastAPI app mounting only ``screening_api.router`` so these
tests exercise the router in isolation (no app.py coupling). The screener is
offline (local-seed DB only) so the bulk-screen path runs without network.

Pins: the admin-gate (503 when RECUPERO_ADMIN_KEY unset, 401 on bad key) on
both data endpoints; the unauthenticated console shell carrying NO data; the
bulk-screen happy path (results list with count + verdict/risk_band); the empty
input -> 400; and the dedupe + 100-cap truncation flag.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero.api.screening_api import _parse_addresses, router

_ZERO = "0x0000000000000000000000000000000000000000"


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---- admin gate (both data endpoints) ---- #


def test_bulk_503_when_admin_key_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    res = client.get("/v1/screening", params={"addresses": _ZERO})
    assert res.status_code == 503


def test_cache_stats_503_when_admin_key_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    res = client.get("/v1/screening/cache-stats")
    assert res.status_code == 503


def test_bulk_401_on_wrong_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/screening",
        params={"addresses": _ZERO},
        headers={"X-Recupero-Admin-Key": "wrong-key"},
    )
    assert res.status_code == 401


def test_cache_stats_401_on_wrong_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/screening/cache-stats",
        headers={"X-Recupero-Admin-Key": "wrong-key"},
    )
    assert res.status_code == 401


# ---- console shell ---- #


def test_console_shell_is_unauthenticated_html(client: TestClient) -> None:
    res = client.get("/v1/screening/console")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    html = res.text
    assert "Screening" in html
    assert "X-Recupero-Admin-Key" in html
    assert "/v1/screening" in html


# ---- bulk-screen behavior (offline local-seed screener) ---- #


def test_bulk_screen_200_with_valid_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/screening",
        params={"addresses": _ZERO},
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["count"] == 1
    assert body["truncated"] is False
    assert isinstance(body["results"], list)
    entry = body["results"][0]
    assert entry["address"] == _ZERO
    # Each entry carries a verdict (or risk_band) from build_address_profile.
    assert "verdict" in entry or "risk_band" in entry


def test_cache_stats_200_with_valid_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/screening/cache-stats",
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code == 200
    assert isinstance(res.json(), dict)


def test_bulk_screen_400_on_empty_addresses(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/screening",
        params={"addresses": "   "},
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code == 400


# ---- pure parser: dedupe + cap ---- #


def test_parse_addresses_dedupes_preserving_order() -> None:
    raw = "0xa, 0xb\n0xa\n 0xc , 0xb "
    addrs, truncated = _parse_addresses(raw)
    assert addrs == ["0xa", "0xb", "0xc"]
    assert truncated is False


def test_parse_addresses_caps_at_100_and_flags_truncation() -> None:
    raw = "\n".join(f"0x{i:040x}" for i in range(150))
    addrs, truncated = _parse_addresses(raw)
    assert len(addrs) == 100
    assert truncated is True


def test_parse_addresses_empty_is_empty() -> None:
    addrs, truncated = _parse_addresses("  ,\n ,, \n ")
    assert addrs == []
    assert truncated is False


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
