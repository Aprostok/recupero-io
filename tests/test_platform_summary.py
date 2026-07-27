"""Unit tests for the consumer case-summary endpoint (GET /v2/traces/{id}/summary).

Two layers, no live store:
* the pure freeze_brief → consumer-summary extraction (_build_summary_payload,
  _parse_usd), with the artifact loader monkeypatched to a canned brief;
* the trace_summary handler decision logic (org-scope 404, build-error mapping),
  calling the handler directly (FastAPI Depends bypassed on a direct call).
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from recupero.platform import router, store

# A trimmed real-shape freeze_brief (mirrors data/cases/ronin-d1-2022 keys).
_BRIEF = {
    "CASE_ID": "CASE-abc",
    "PRIMARY_CHAIN": "Ethereum",
    "INCIDENT_TYPE": "Bridge exploit",
    "INCIDENT_DATE": "2022-03-23",
    "VICTIM_NAME": "Acme",
    "TOTAL_LOSS_USD": "$572,186,472.25",
    "TOTAL_FREEZABLE_USD": "$1,000,000.00",
    "TOTAL_UNRECOVERABLE_USD": "$500,000,000.00",
    "MAX_RECOVERABLE_USD": "$1,000,000.00",
    "RECOVERABLE_PERCENT": "0.17%",
    "FREEZABLE_PERCENT": "0.17%",
    "RECOVERY_ESTIMATE": {
        "headline_summary": "Most funds mixed; ~$1M recoverable via exchange.",
        "expected_net_to_victim_usd": 750000,
        "probability_any_recovery_90d": 0.4,
    },
    "PERP_HUB": {"address": "0xhub", "chain": "ethereum", "usd_received": "$572,000,000"},
    "DESTINATIONS": [
        {"address": "0xcex", "chain": "ethereum", "status": "EXCHANGE", "role": "deposit",
         "usd_holding_now": "$1,000,000.00", "usd_received_in_trace": "$1,000,000.00",
         "notes": "Binance"},
        {"address": "0xmix", "chain": "ethereum", "status": "UNRECOVERABLE", "role": "mixer",
         "usd_holding_now": "$0", "usd_received_in_trace": "$400,000,000", "notes": "Tornado"},
        {"not_an_address": True},  # malformed → skipped
    ],
}


def _principal() -> store.OrgContext:
    return store.OrgContext(org_id="org1", plan="pro", user_id="u", role="owner")


# --------------------------------------------------------------------------- #
# _parse_usd
# --------------------------------------------------------------------------- #

def test_parse_usd_formats() -> None:
    assert router._parse_usd("$572,186,472.25") == 572186472.25
    assert router._parse_usd("0%") == 0.0
    assert router._parse_usd("0.17%") == 0.17
    assert router._parse_usd(1234) == 1234.0
    assert router._parse_usd("$0") == 0.0
    assert router._parse_usd(None) is None
    assert router._parse_usd("n/a") is None
    assert router._parse_usd(True) is None   # bool is not a number here


# --------------------------------------------------------------------------- #
# _build_summary_payload
# --------------------------------------------------------------------------- #

def test_build_summary_extracts_consumer_shape(monkeypatch) -> None:
    monkeypatch.setattr(router, "_load_case_artifact_json", lambda inv, cid, name: _BRIEF)
    monkeypatch.setattr(router, "_load_next_steps", lambda inv, cid: ["File an IC3 report"])
    out = router._build_summary_payload("inv1", "CASE-abc")

    assert out["case_id"] == "CASE-abc"
    assert out["chain"] == "Ethereum"
    assert out["totals"]["loss_usd"] == 572186472.25
    assert out["totals"]["max_recoverable_usd"] == 1000000.0
    assert out["totals"]["recoverable_percent"] == 0.17
    assert out["totals_display"]["loss_usd"] == "$572,186,472.25"  # brief's own string kept
    assert out["recovery"]["headline"].startswith("Most funds mixed")
    assert out["recovery"]["expected_net_to_victim_usd"] == 750000.0
    assert out["perp_hub"] == {"address": "0xhub", "chain": "ethereum", "usd_received": 572000000.0}
    # endpoints: 2 valid (malformed row skipped), numerics parsed, status preserved
    assert out["endpoint_count"] == 2
    statuses = {e["address"]: e["status"] for e in out["endpoints"]}
    assert statuses == {"0xcex": "EXCHANGE", "0xmix": "UNRECOVERABLE"}
    cex = next(e for e in out["endpoints"] if e["address"] == "0xcex")
    assert cex["usd_holding_now"] == 1000000.0 and cex["note"] == "Binance"
    assert out["next_steps"] == ["File an IC3 report"]


def test_build_summary_tolerates_missing_keys(monkeypatch) -> None:
    # An early/sparse brief (no DESTINATIONS, no estimate) must not crash.
    monkeypatch.setattr(router, "_load_case_artifact_json", lambda inv, cid, name: {"CASE_ID": "C"})
    monkeypatch.setattr(router, "_load_next_steps", lambda inv, cid: [])
    out = router._build_summary_payload("inv1", "C")
    assert out["endpoints"] == [] and out["endpoint_count"] == 0
    assert out["totals"]["loss_usd"] is None
    assert out["recovery"]["headline"] is None
    assert out["perp_hub"] is None


def test_next_steps_best_effort_returns_empty_on_missing(monkeypatch) -> None:
    def _boom(inv, cid, name):
        raise OSError("no ai_triage.json")
    monkeypatch.setattr(router, "_load_case_artifact_json", _boom)
    assert router._load_next_steps("inv", "c") == []


# --------------------------------------------------------------------------- #
# trace_summary handler
# --------------------------------------------------------------------------- #

def test_trace_summary_returns_payload(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_trace_status", lambda conn, org_id, investigation_id: {"case_id": "CASE-abc"})
    monkeypatch.setattr(router, "_build_summary_payload", lambda inv, cid: {"case_id": cid})
    out = router.trace_summary("inv1", principal=_principal(), conn=object())
    assert out == {"case_id": "CASE-abc"}


def test_trace_summary_404_when_not_in_org(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_trace_status", lambda conn, org_id, investigation_id: None)
    with pytest.raises(HTTPException) as ei:
        router.trace_summary("inv1", principal=_principal(), conn=object())
    assert ei.value.status_code == 404


def test_trace_summary_404_when_brief_not_ready(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_trace_status", lambda conn, org_id, investigation_id: {"case_id": "c"})

    def _boom(inv, cid):
        raise OSError("freeze_brief.json missing")
    monkeypatch.setattr(router, "_build_summary_payload", _boom)
    with pytest.raises(HTTPException) as ei:
        router.trace_summary("inv1", principal=_principal(), conn=object())
    assert ei.value.status_code == 404


def test_trace_summary_503_on_build_blowup(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_trace_status", lambda conn, org_id, investigation_id: {"case_id": "c"})

    def _boom(inv, cid):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(router, "_build_summary_payload", _boom)
    with pytest.raises(HTTPException) as ei:
        router.trace_summary("inv1", principal=_principal(), conn=object())
    assert ei.value.status_code == 503
