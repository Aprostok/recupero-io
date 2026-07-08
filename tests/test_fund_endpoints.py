"""Tests for the fund-endpoints view — "where the money is sitting now".

Two layers:
  * The PURE builder ``reports.fund_endpoints.build_fund_endpoints`` — exercised
    against a realistic freeze-brief dict (the meat: classification, rollup,
    reachable/gone split, USD parsing, movement annotation, de-dup).
  * The API router in isolation (auth gates + unauthenticated console shell),
    mirroring ``test_case_overview_console`` — the 200 JSON path needs a real
    case on disk and is covered by the builder tests instead.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero._common import canonical_address_key as _ck
from recupero.api.fund_endpoints_api import router
from recupero.reports.fund_endpoints import build_fund_endpoints

_A_USDC = "0x" + "a" * 40
_A_DAI = "0x" + "b" * 40
_A_CEX = "0x" + "c" * 40


def _sample_brief() -> dict:
    return {
        "TOTAL_LOSS_USD": "$3,500,000",
        "MAX_RECOVERABLE_USD": "$1,066.27",
        "RECOVERABLE_PERCENT": "0.03%",
        "TOTAL_FREEZABLE_USD": "$1,066.27",
        "TOTAL_UNRECOVERABLE_USD": "$850,000",
        "ALL_ISSUER_HOLDINGS": [
            {"issuer": "Circle", "symbol": "USDC", "holdings": [
                {"address": _A_USDC, "chain": "ethereum", "amount": "1066.27 USDC",
                 "usd": "$1,066.27", "status": "FREEZABLE",
                 "evidence_type": "current_balance", "observed_at": "2026-01-01T00:00:00Z"},
            ]},
            {"issuer": "Sky Protocol", "symbol": "DAI", "holdings": [
                {"address": _A_DAI, "chain": "ethereum", "amount": "655000 DAI",
                 "usd": "$655,000.00", "status": "TRACKED",
                 "evidence_type": "current_balance"},
            ]},
        ],
        "EXCHANGES": [
            {"exchange": "Binance", "deposits": [
                {"address": _A_CEX, "amount": "3 transfer(s)", "usd": "$12,000.00",
                 "date": "2026-01-02"},
            ]},
        ],
        "UNRECOVERABLE": [
            {"asset": "300 ETH (~$850,000)", "reason": "Sent to Tornado Cash. Mixed.",
             "issuer": "", "address": ""},
        ],
    }


# --------------------------------------------------------------------------- #
# Pure builder
# --------------------------------------------------------------------------- #

def test_builder_classifies_all_four_endpoint_kinds() -> None:
    v = build_fund_endpoints(_sample_brief())
    assert v["n_endpoints"] == 4
    by_status = {e["status"]: e for e in v["endpoints"]}
    assert set(by_status) == {"FREEZABLE", "TRACKED", "EXCHANGE", "UNRECOVERABLE"}
    # Headline figures pass through verbatim (never recomputed).
    assert v["total_loss_usd"] == "$3,500,000"
    assert v["max_recoverable_usd"] == "$1,066.27"


def test_builder_parses_usd_and_rollup() -> None:
    v = build_fund_endpoints(_sample_brief())
    roll = {r["status"]: r for r in v["rollup"]}
    assert roll["FREEZABLE"]["usd"] == pytest.approx(1066.27)
    assert roll["TRACKED"]["usd"] == pytest.approx(655000.0)
    assert roll["EXCHANGE"]["usd"] == pytest.approx(12000.0)
    # "300 ETH (~$850,000)" → the $ figure is recovered.
    assert roll["UNRECOVERABLE"]["usd"] == pytest.approx(850000.0)


def test_builder_reachable_vs_gone_split() -> None:
    v = build_fund_endpoints(_sample_brief())
    assert v["reachable_usd_numeric"] == pytest.approx(1066.27 + 655000.0 + 12000.0)
    assert v["gone_usd_numeric"] == pytest.approx(850000.0)


def test_builder_rollup_is_in_display_order() -> None:
    v = build_fund_endpoints(_sample_brief())
    order = [r["status"] for r in v["rollup"]]
    # canonical order: FREEZABLE, TRACKED, INVESTIGATE, EXCHANGE, UNRECOVERABLE
    assert order == ["FREEZABLE", "TRACKED", "EXCHANGE", "UNRECOVERABLE"]


def test_builder_sets_explorer_url_and_short() -> None:
    v = build_fund_endpoints(_sample_brief())
    usdc = next(e for e in v["endpoints"] if e["status"] == "FREEZABLE")
    assert usdc["explorer_url"] == "https://etherscan.io/address/" + _A_USDC
    assert usdc["short"]  # short_addr populated


def test_builder_empty_brief_sets_note() -> None:
    v = build_fund_endpoints({})
    assert v["n_endpoints"] == 0
    assert v["endpoints"] == []
    assert v["note"]  # honest "nothing to show" note
    assert v["reachable_usd_numeric"] == 0
    assert v["gone_usd_numeric"] == 0


def test_builder_handles_none_brief() -> None:
    v = build_fund_endpoints(None)
    assert v["n_endpoints"] == 0
    assert v["note"]


def test_builder_falls_back_to_freezable_when_all_holdings_absent() -> None:
    brief = {"FREEZABLE": [
        {"issuer": "Circle", "symbol": "USDC", "holdings": [
            {"address": _A_USDC, "chain": "ethereum", "amount": "1 USDC",
             "usd": "$1.00", "status": "FREEZABLE"},
        ]},
    ]}
    v = build_fund_endpoints(brief)
    assert v["n_endpoints"] == 1
    assert v["endpoints"][0]["status"] == "FREEZABLE"


def test_builder_movement_annotation_from_watchlist() -> None:
    index = {
        _ck(_A_USDC): {"movement": "moved", "last_delta_usd": "-1000.00",
                       "last_checked_at": "2026-01-05T00:00:00Z"},
        _ck(_A_DAI): {"movement": "still_present", "last_delta_usd": None,
                      "last_checked_at": "2026-01-05T00:00:00Z"},
    }
    v = build_fund_endpoints(_sample_brief(), watchlist_index=index)
    moved = [e for e in v["endpoints"] if e["movement"] == "moved"]
    assert len(moved) == 1
    assert moved[0]["status"] == "FREEZABLE"
    assert v["n_moved"] == 1
    assert v["moved_usd_numeric"] == pytest.approx(1066.27)
    # Unwatched endpoints default to the honest "never_checked".
    cex = next(e for e in v["endpoints"] if e["status"] == "EXCHANGE")
    assert cex["movement"] == "never_checked"


def test_builder_dedupes_repeated_holding_address() -> None:
    brief = _sample_brief()
    # Same address+token appears twice across issuer groups → one endpoint.
    brief["ALL_ISSUER_HOLDINGS"].append(
        {"issuer": "Circle", "symbol": "USDC", "holdings": [
            {"address": _A_USDC, "chain": "ethereum", "amount": "1066.27 USDC",
             "usd": "$1,066.27", "status": "FREEZABLE"},
        ]},
    )
    v = build_fund_endpoints(brief)
    usdc = [e for e in v["endpoints"] if _ck(e["address"] or "") == _ck(_A_USDC)]
    assert len(usdc) == 1


def test_builder_skips_unrecoverable_item_matching_existing_holding() -> None:
    brief = _sample_brief()
    # An editorial write-off that names an already-present holding is skipped
    # (the brief's own de-dup rule) so value isn't double-counted.
    brief["UNRECOVERABLE"].append(
        {"asset": "655000 DAI (~$655,000)", "reason": "dup", "issuer": "Sky Protocol",
         "address": _A_DAI},
    )
    v = build_fund_endpoints(brief)
    dai = [e for e in v["endpoints"] if _ck(e["address"] or "") == _ck(_A_DAI)]
    assert len(dai) == 1  # not doubled


def test_builder_reason_carried_on_offissuer_unrecoverable() -> None:
    v = build_fund_endpoints(_sample_brief())
    mixer = next(e for e in v["endpoints"] if e["status"] == "UNRECOVERABLE")
    assert "Tornado" in (mixer["reason"] or "")
    assert mixer["address"] is None  # off-issuer write-off, no on-chain address


# --------------------------------------------------------------------------- #
# API router (isolation) — auth gates + console shell
# --------------------------------------------------------------------------- #

@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_api_503_when_admin_key_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    res = client.get("/v1/fund-endpoints", params={"case_id": "X"})
    assert res.status_code == 503


def test_api_401_on_wrong_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/fund-endpoints",
        params={"case_id": "X"},
        headers={"X-Recupero-Admin-Key": "wrong-key"},
    )
    assert res.status_code == 401


def test_api_400_on_blank_case_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    res = client.get(
        "/v1/fund-endpoints",
        params={"case_id": "  "},
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code in {400, 404, 422}


def test_api_404_on_missing_case(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "correct-key")
    monkeypatch.delenv("RECUPERO_CASE_STORE", raising=False)
    res = client.get(
        "/v1/fund-endpoints",
        params={"case_id": "no-such-case-xyz"},
        headers={"X-Recupero-Admin-Key": "correct-key"},
    )
    assert res.status_code == 404


def test_console_shell_is_unauthenticated_html(client: TestClient) -> None:
    res = client.get("/v1/fund-endpoints/console")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    html = res.text
    assert "Where It" in html  # "Where It's Sitting Now"
    assert "X-Recupero-Admin-Key" in html
    assert "/v1/fund-endpoints" in html
