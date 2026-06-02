"""v0.35.1 — live Watchlist / Watcher API + console.

Pins the auth model (admin-key gating, deny-by-default) and the JSON/HTML
surfaces. The console shell is intentionally unauthenticated (no data); the JSON
+ run endpoints require X-Recupero-Admin-Key.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from recupero.api.app import app
from recupero.monitoring.watchlist_dashboard import summarize_watchlist

client = TestClient(app)

ADMIN = "test-admin-key-123"
NOW = datetime(2026, 6, 2, 12, 0, tzinfo=UTC)


def _overview():
    rows = [{
        "address": "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291",
        "chain": "ethereum", "role": "current_holder", "is_freezeable": False,
        "issuer": None, "asset_symbol": "ETH", "asset_contract": None,
        "flagged_at": NOW, "status": "active", "priority": "standard",
        "label_category": "mixer", "label_name": "Tornado Cash: 100 ETH",
        "investigation_id": None, "last_balance_usd": "21629000",
        "last_native_balance": None, "last_tx_count": 1,
        "last_snapshot_at": NOW, "latest_delta_usd": "0", "prior_tx_count": 1,
    }]
    return summarize_watchlist(rows, now=NOW)


@pytest.fixture
def admin_env(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", ADMIN)
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://x")


def test_get_watchlist_503_without_admin_env(monkeypatch):
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    r = client.get("/v1/watchlist")
    assert r.status_code == 503


def test_get_watchlist_401_missing_key(admin_env):
    r = client.get("/v1/watchlist")
    assert r.status_code == 401


def test_get_watchlist_401_wrong_key(admin_env):
    r = client.get("/v1/watchlist", headers={"X-Recupero-Admin-Key": "nope"})
    assert r.status_code == 401


def test_get_watchlist_503_without_dsn(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", ADMIN)
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    r = client.get("/v1/watchlist", headers={"X-Recupero-Admin-Key": ADMIN})
    assert r.status_code == 503


def test_get_watchlist_200_shape(admin_env, monkeypatch):
    monkeypatch.setattr(
        "recupero.monitoring.watchlist_dashboard.build_watchlist_overview",
        lambda **kw: _overview(),
    )
    r = client.get("/v1/watchlist", headers={"X-Recupero-Admin-Key": ADMIN})
    assert r.status_code == 200
    body = r.json()
    assert body["n_items"] == 1
    assert body["rows"][0]["status"] == "UNRECOVERABLE"
    assert "by_status" in body and "by_chain" in body
    assert body["rows"][0]["status_emoji"]  # pill present


def test_console_served_unauthenticated():
    r = client.get("/v1/watchlist/console")
    assert r.status_code == 200
    assert "Watchlist Console" in r.text
    # The shell must NOT embed any watched-address data.
    assert "0xA160cdAB" not in r.text
    assert "X-Recupero-Admin-Key" in r.text  # client fetches with the header


def test_run_requires_admin(admin_env):
    r = client.post("/v1/watchlist/run")
    assert r.status_code == 401


def test_run_200(admin_env, monkeypatch):
    fake = SimpleNamespace(
        candidates=10, snapshotted=8, material_changes=[1, 2],
        skipped_cooldown=2, errors=[],
    )
    monkeypatch.setattr(
        "recupero.worker.watch_tick.run_watch_tick", lambda **kw: fake,
    )
    r = client.post("/v1/watchlist/run", headers={"X-Recupero-Admin-Key": ADMIN})
    assert r.status_code == 200
    body = r.json()
    assert body["snapshotted"] == 8 and body["moved"] == 2 and body["candidates"] == 10
