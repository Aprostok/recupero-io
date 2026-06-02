"""v0.35.14 (F3) — address/entity profile API + console.

Pins: the pure profile assembler (verdict band, exposure tags, labels +
sighting-history passthrough, honest "no hit" note); the admin-gate (503 when
RECUPERO_ADMIN_KEY unset, 401 on bad/missing key); address validation; and the
unauthenticated console shell carrying NO data.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from recupero.api.address_profile import build_address_profile
from recupero.screen.screener import (
    ScreeningCorrelation,
    ScreeningLabel,
    ScreeningResult,
)

_OFAC = "0x" + "11" * 20
_CLEAN = "0x" + "22" * 20


def _flagged_result():
    return ScreeningResult(
        address=_OFAC, chain="ethereum", risk_verdict="sanctioned", risk_score=10,
        is_ofac_sanctioned=True, is_mixer=False, is_ransomware=False, is_drainer=False,
        labels=[ScreeningLabel(
            name="OFAC SDN: Lazarus", category="ofac_sanctioned", severity=4,
            confidence="high", source="ofac_live",
        )],
        correlation=ScreeningCorrelation(
            prior_case_count=3, prior_ofac_exposed_count=2,
            prior_total_usd_flowed=Decimal("1000000"),
        ),
        investigator_note="Direct OFAC SDN hit.",
        data_sources_used=["local_seeds", "ofac_live", "correlation_db"],
    )


def _clean_result():
    return ScreeningResult(
        address=_CLEAN, chain="ethereum", risk_verdict="clean", risk_score=0,
        is_ofac_sanctioned=False, is_mixer=False, is_ransomware=False, is_drainer=False,
    )


# ---- pure assembler ---- #


def test_build_profile_flagged():
    p = build_address_profile(_flagged_result())
    assert p["verdict"] == "sanctioned"
    assert p["risk_band"] == "SANCTIONED"
    assert p["is_flagged"] is True
    assert p["exposure_tags"] == ["OFAC-sanctioned"]
    assert p["label_count"] == 1
    assert p["labels"][0]["confidence"] == "high"
    assert p["sighting_history"]["prior_case_count"] == 3
    assert p["sighting_history"]["prior_total_usd_flowed"] == "1000000"  # Decimal→str
    assert "note" not in p   # flagged → no "clean" disclaimer


def test_build_profile_clean_carries_honesty_note():
    p = build_address_profile(_clean_result())
    assert p["is_flagged"] is False
    assert p["exposure_tags"] == []
    assert p["label_count"] == 0
    assert "not a guarantee" in p["note"].lower()


def test_build_profile_multiple_exposure_tags():
    r = _clean_result()
    r.is_mixer = True
    r.is_drainer = True
    r.risk_verdict = "high"
    p = build_address_profile(r)
    assert set(p["exposure_tags"]) == {"Mixer", "Drainer"}
    assert p["is_flagged"] is True


# ---- route auth + behavior ---- #


def _client():
    from recupero.api.app import app
    return TestClient(app, raise_server_exceptions=True)


def test_profile_503_when_key_unset(monkeypatch):
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    r = _client().get("/v1/address/profile", params={"address": _OFAC})
    assert r.status_code == 503


def test_profile_401_on_bad_key(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    r = _client().get(
        "/v1/address/profile", params={"address": _OFAC},
        headers={"X-Recupero-Admin-Key": "wrong"},
    )
    assert r.status_code == 401


def test_profile_400_on_empty_address(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    r = _client().get(
        "/v1/address/profile", params={"address": "   "},
        headers={"X-Recupero-Admin-Key": "secret"},
    )
    assert r.status_code == 400


def test_profile_200_with_valid_key(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    # Patch the screener at its source module (the route imports it lazily).
    import recupero.screen.screener as screener_mod
    monkeypatch.setattr(screener_mod, "screen_address",
                        lambda *a, **k: _flagged_result())
    r = _client().get(
        "/v1/address/profile", params={"address": _OFAC, "chain": "ethereum"},
        headers={"X-Recupero-Admin-Key": "secret"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["risk_band"] == "SANCTIONED"
    assert "OFAC-sanctioned" in body["exposure_tags"]


def test_console_is_unauthenticated_html_with_no_data(monkeypatch):
    # Console must render WITHOUT a key and contain no live data.
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    r = _client().get("/v1/address/console")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Address Profile" in r.text
    assert "X-Recupero-Admin-Key" in r.text   # fetched client-side
    assert _OFAC not in r.text                 # no embedded data


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
