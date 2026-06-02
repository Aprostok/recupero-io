"""Tests for on-demand hop expansion (Phase 3.6).

The aggregation is pure and tested with synthetic adapter rows + a fake
adapter; the admin-gated endpoint is tested with the network call mocked.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4  # noqa: F401  (kept for parity with other suites)

import pytest

from recupero.models import Chain, TokenRef
from recupero.reports.graph_expand import aggregate_expansion, expand_address

ROOT = "0x" + "a" * 40
CP1 = "0x" + "b" * 40
CP2 = "0x" + "c" * 40

_USDC = TokenRef(chain=Chain.ethereum, contract="0x" + "d" * 40,
                 symbol="USDC", decimals=6, coingecko_id="usd-coin")
_ETH = TokenRef(chain=Chain.ethereum, contract="0x" + "e" * 40,
                symbol="ETH", decimals=18, coingecko_id="ethereum")


def _row(frm, to, token, raw, day):
    return {"from": frm, "to": to, "token": token, "amount_raw": raw,
            "block_time": datetime(2026, 1, day, tzinfo=UTC),
            "tx_hash": "0x" + "1" * 64,
            "explorer_url": "https://etherscan.io/tx/0x" + "1" * 64}


def test_aggregate_groups_and_ranks_by_value() -> None:
    rows = [
        _row(ROOT, CP1, _USDC, 25_000_000000, 1),
        _row(ROOT, CP1, _USDC, 5_000_000000, 3),
        _row(ROOT, CP2, _USDC, 1_000_000000, 2),
    ]
    out = aggregate_expansion(rows, root_address=ROOT, direction="out", chain="ethereum")
    assert [n["id"] for n in out["nodes"]] == [CP1, CP2]   # ranked by USD
    e1 = next(e for e in out["edges"] if e["target"] == CP1)
    assert e1["source"] == ROOT
    assert e1["transferCount"] == 2
    assert e1["totalUsd"] == "$30,000.00"
    assert e1["dominantSymbol"] == "USDC"
    assert e1["firstTime"] == "2026-01-01" and e1["lastTime"] == "2026-01-03"


def test_direction_in_flips_edge_orientation() -> None:
    rows = [_row(CP1, ROOT, _USDC, 7_000_000000, 5)]
    out = aggregate_expansion(rows, root_address=ROOT, direction="in", chain="ethereum")
    e = out["edges"][0]
    assert e["source"] == CP1 and e["target"] == ROOT
    assert out["meta"]["direction"] == "in"


def test_non_stablecoin_usd_is_zero_not_overstated() -> None:
    # ETH has no live price here → face-value estimate is 0 (never invented).
    rows = [_row(ROOT, CP1, _ETH, 5 * 10**18, 1)]
    out = aggregate_expansion(rows, root_address=ROOT, direction="out", chain="ethereum")
    assert out["edges"][0]["totalUsdNumeric"] == 0.0
    assert out["edges"][0]["transferCount"] == 1


def test_counterparty_cap_truncates_and_reports() -> None:
    rows = [_row(ROOT, "0x" + f"{i:040x}", _USDC, (i + 1) * 1_000000, 1) for i in range(60)]
    out = aggregate_expansion(rows, root_address=ROOT, direction="out", chain="ethereum",
                              max_counterparties=10)
    assert len(out["nodes"]) == 10
    assert out["meta"]["truncated"] == 50


def test_self_loops_dropped() -> None:
    rows = [_row(ROOT, ROOT, _USDC, 1_000000, 1)]
    out = aggregate_expansion(rows, root_address=ROOT, direction="out", chain="ethereum")
    assert out["nodes"] == [] and out["edges"] == []


class _FakeAdapter:
    def __init__(self, erc20):
        self._erc20 = erc20
        self.closed = False
    def fetch_native_outflows(self, addr, sb): return []
    def fetch_erc20_outflows(self, addr, sb): return self._erc20
    def fetch_native_inflows(self, addr, sb, **k): return []
    def fetch_erc20_inflows(self, addr, sb, **k): return []
    def close(self): self.closed = True


def test_expand_address_uses_injected_adapter() -> None:
    rows = [_row(ROOT, CP1, _USDC, 2_000_000000, 1)]
    fake = _FakeAdapter(rows)
    out = expand_address(chain=Chain.ethereum, address=ROOT, direction="out", adapter=fake)
    assert len(out["nodes"]) == 1 and out["nodes"][0]["id"] == CP1
    # injected adapter is NOT closed by expand_address (caller owns it)
    assert fake.closed is False


# ---- endpoint ---- #


@pytest.fixture(autouse=True)
def _admin_key(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "testkey123")


def _client():
    from fastapi.testclient import TestClient
    from recupero.api.app import app
    return TestClient(app)


def test_expand_endpoint_requires_admin_key() -> None:
    r = _client().get(f"/v1/operator/expand?chain=ethereum&address={ROOT}&direction=out")
    assert r.status_code == 401


def test_expand_endpoint_validates_chain_and_address() -> None:
    c = _client()
    h = {"X-Recupero-Admin-Key": "testkey123"}
    assert c.get(f"/v1/operator/expand?chain=nope&address={ROOT}", headers=h).status_code == 400
    assert c.get("/v1/operator/expand?chain=ethereum&address=", headers=h).status_code == 400


def test_expand_endpoint_happy_path_mocked() -> None:
    fake = {"nodes": [{"id": CP1, "label": "x", "short": "x", "status": "intermediary",
                       "statusLabel": "Intermediary wallet", "statusColor": "#64748B",
                       "chain": "ethereum", "chainColor": "#5B6CFF", "inboundUsd": "$1.00",
                       "outboundUsd": "$0.00", "explorerUrl": "", "clusterId": None,
                       "inByCategory": {}, "outByCategory": {}, "risk": None,
                       "riskColor": "#64748B", "indirectExposureUsd": 0.0, "expanded": True}],
            "edges": [], "meta": {"counterpartyCount": 1, "truncated": 0, "direction": "out"}}
    with patch("recupero.reports.graph_expand.expand_address", return_value=fake):
        r = _client().get(
            f"/v1/operator/expand?chain=ethereum&address={ROOT}&direction=out&limit=40",
            headers={"X-Recupero-Admin-Key": "testkey123"},
        )
    assert r.status_code == 200
    assert r.json()["nodes"][0]["id"] == CP1


def test_expand_endpoint_503_on_upstream_failure() -> None:
    with patch("recupero.reports.graph_expand.expand_address", side_effect=RuntimeError("no rpc")):
        r = _client().get(
            f"/v1/operator/expand?chain=ethereum&address={ROOT}&direction=out",
            headers={"X-Recupero-Admin-Key": "testkey123"},
        )
    assert r.status_code == 503
