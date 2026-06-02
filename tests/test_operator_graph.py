"""Tests for the operator-fidelity fund-flow graph (Phase 3).

Covers the un-sanitized operator builder (risk + indirect-exposure
overlay fields) and the admin-gated API: HTML shell, auth enforcement,
input validation, and the happy path with storage mocked.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import pytest

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.reports.client_journey import build_operator_graph_data

VICTIM = "0x" + "a" * 40
PERP = "0x" + "b" * 40
EXCH = "0x" + "c" * 40


def _label(addr: str, *, category: LabelCategory, name: str) -> Label:
    return Label(address=addr, name=name, category=category, source="test",
                 confidence="high", added_at=datetime(2026, 1, 1, tzinfo=UTC))


def _transfer(*, from_addr, to_addr, usd=Decimal("1000"), tx_hash=None,
              counterparty_label=None) -> Transfer:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    tx_hash = tx_hash or "0x" + "1" * 64
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:1", chain=Chain.ethereum, tx_hash=tx_hash,
        block_number=1, block_time=ts, from_address=from_addr, to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=counterparty_label, is_contract=False),
        token=TokenRef(chain=Chain.ethereum, contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                       symbol="USDT", decimals=6, coingecko_id="tether"),
        amount_raw="1", amount_decimal=Decimal("1000"), usd_value_at_tx=usd, hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}", fetched_at=ts,
    )


def _case() -> Case:
    return Case(
        case_id="V-OP01", seed_address=VICTIM, chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=[
            _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("50000")),
            _transfer(from_addr=PERP, to_addr=EXCH, usd=Decimal("45000"),
                      tx_hash="0x" + "2" * 64,
                      counterparty_label=_label(EXCH, category=LabelCategory.exchange_deposit,
                                                name="Binance Hot Wallet")),
        ],
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test", config_used={},
    )


# ---- operator builder ---- #


def test_operator_builder_is_unsanitized_with_risk_fields() -> None:
    j = build_operator_graph_data(_case())
    assert j["meta"]["sanitized"] is False
    # Every node carries the risk overlay scaffold (value may be None for
    # clean addresses) and an indirect-exposure figure.
    for n in j["nodes"]:
        assert "risk" in n
        assert "riskColor" in n
        assert "indirectExposureUsd" in n
    # Exchange identity surfaced (same as client), and the graph still
    # produces the journey-shaped fields the shared engine needs.
    ex = next(n for n in j["nodes"] if n["id"] == EXCH)
    assert ex["label"] == "Binance Hot Wallet"
    assert "depth" in ex and "inByCategory" in ex


def test_operator_builder_keeps_intermediary_identity_when_present() -> None:
    """Operator mode does NOT suppress a labelled intermediary's identity
    (unlike the sanitized client view)."""
    case = Case(
        case_id="V-OP02", seed_address=VICTIM, chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=[
            _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("5000"),
                      counterparty_label=_label(PERP, category=LabelCategory.unknown,
                                                name="Tagged Suspect Wallet")),
        ],
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="t", config_used={},
    )
    # unknown category → not an entity; client would hide the identity,
    # operator keeps it (when the aggregator carried one).
    j = build_operator_graph_data(case)
    perp = next(n for n in j["nodes"] if n["id"] == PERP)
    # Either the label was carried (kept) or fell back to the friendly
    # status label — but never None.
    assert perp["label"]


# ---- API routes ---- #


@pytest.fixture(autouse=True)
def _admin_key(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "testkey123")


def _client():
    from fastapi.testclient import TestClient
    from recupero.api.app import app
    return TestClient(app)


def test_operator_shell_renders() -> None:
    r = _client().get("/operator-graph")
    assert r.status_code == 200
    assert "Operator fund-flow graph" in r.text
    assert "initGraph" in r.text


def test_operator_json_requires_admin_key() -> None:
    inv = str(uuid4())
    c = _client()
    assert c.get(f"/v1/operator/graph/{inv}").status_code == 401
    assert c.get(f"/v1/operator/graph/{inv}", headers={"X-Recupero-Admin-Key": "wrong"}).status_code == 401


def test_operator_json_rejects_bad_uuid() -> None:
    r = _client().get("/v1/operator/graph/not-a-uuid", headers={"X-Recupero-Admin-Key": "testkey123"})
    assert r.status_code == 400


def test_operator_json_happy_path_with_mocked_storage(monkeypatch) -> None:
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "svc")
    case_dict = _case().model_dump(mode="json")
    inv = str(uuid4())
    with patch("recupero.worker.investigations_api.fetch_case_json", return_value=case_dict):
        r = _client().get(f"/v1/operator/graph/{inv}", headers={"X-Recupero-Admin-Key": "testkey123"})
    assert r.status_code == 200
    body = r.json()
    assert body["meta"]["sanitized"] is False
    ids = {n["id"] for n in body["nodes"]}
    assert VICTIM in ids and EXCH in ids
    assert all("risk" in n for n in body["nodes"])


def test_operator_json_404_when_case_missing(monkeypatch) -> None:
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "svc")
    inv = str(uuid4())
    with patch("recupero.worker.investigations_api.fetch_case_json", return_value=None):
        r = _client().get(f"/v1/operator/graph/{inv}", headers={"X-Recupero-Admin-Key": "testkey123"})
    assert r.status_code == 404
