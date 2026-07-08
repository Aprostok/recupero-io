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


def test_shared_design_system_css_is_served():
    """The shared console stylesheet is public, text/css, and carries the
    design tokens consoles depend on."""
    r = _client().get("/v1/console/app.css")
    assert r.status_code == 200
    assert "text/css" in r.headers["content-type"]
    assert "--accent" in r.text and "prefers-color-scheme" in r.text
    # No secret in a public stylesheet.
    assert "RECUPERO_ADMIN_KEY" not in r.text


def test_recovery_alerts_console_links_shared_css():
    """A converted console links the shared stylesheet and no longer ships its
    own inline <style> block."""
    r = _client().get("/v1/recovery-alerts/console")
    assert r.status_code == 200
    assert '/v1/console/app.css' in r.text
    assert "<style>" not in r.text


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


def test_origin_story_is_public_html():
    """The origin-story page is a public, data-free narrative served under the
    console prefix and linked from the hub's About group."""
    c = _client()
    r = c.get("/v1/console/story")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Our Story" in r.text
    assert '/v1/console/app.css' in r.text          # uses the shared design system
    assert "X-Recupero-Admin-Key" not in r.text     # no auth, no secret on the page
    # It is reachable from the hub nav registry as a live console.
    nav = c.get("/v1/console/nav").json()["consoles"]
    story = [x for x in nav if x["path"] == "/v1/console/story"]
    assert story and story[0]["live"] is True and story[0]["group"] == "About"


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
    # All DB-backed stats present as keys, all null (no DB) — page never fails.
    for k in ("pending_reviews", "watchlist_items", "watchlist_moved",
              "label_candidates_pending"):
        assert k in s and s[k] is None
    # Filesystem case rollup keys are ALWAYS present and never require a DB.
    # Their value is None (no cases dir) or a non-negative int (scan ran) — we
    # assert the contract, not a specific count (a local cases dir may exist).
    for k in ("cases_total", "cases_with_brief", "cases_triaged",
              "cases_with_exhibit"):
        assert k in s
        assert s[k] is None or (isinstance(s[k], int) and s[k] >= 0)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
