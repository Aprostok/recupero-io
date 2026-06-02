"""v0.35.19 (UI) — unified operator console hub.

Pins: the hub HTML is unauthenticated + data-free + links the live consoles; the
nav is public link metadata; the quick-stats endpoint is admin-gated (503 unset /
401 bad) and degrades to all-null when no DB is configured (never fails the page).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _client():
    from recupero.api.app import app
    return TestClient(app)


def test_hub_is_unauth_html_with_no_secret(monkeypatch):
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    r = _client().get("/v1/console")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Recupero Operator Console" in r.text
    assert "X-Recupero-Admin-Key" in r.text   # used client-side
    # The hub must not embed any admin key value.
    assert "RECUPERO_ADMIN_KEY" not in r.text or "set RECUPERO_ADMIN_KEY" not in r.text.split("<script")[0]


def test_nav_is_public_and_links_live_consoles():
    r = _client().get("/v1/console/nav")
    assert r.status_code == 200
    body = r.json()
    paths = {c["path"] for c in body["consoles"]}
    assert "/review-gate" in paths
    assert "/v1/watchlist/console" in paths
    assert "/v1/address/console" in paths
    assert body["count"] == len(body["consoles"])
    assert all(c.get("live") for c in body["consoles"])


def test_stats_503_when_key_unset(monkeypatch):
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    r = _client().get("/v1/console/stats")
    assert r.status_code == 503


def test_stats_401_on_bad_key(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    r = _client().get("/v1/console/stats", headers={"X-Recupero-Admin-Key": "wrong"})
    assert r.status_code == 401


def test_stats_degrades_to_null_without_db(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    r = _client().get("/v1/console/stats", headers={"X-Recupero-Admin-Key": "secret"})
    assert r.status_code == 200
    s = r.json()
    # All stats present as keys, all null (no DB) — page never fails.
    for k in ("pending_reviews", "watchlist_items", "watchlist_moved",
              "label_candidates_pending"):
        assert k in s and s[k] is None


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
