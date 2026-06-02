"""Label-candidate Review console (HTML shell) — pins.

The router is not yet registered in the main app, so we build a LOCAL app
in the test and mount only this router. Pins mirror the watchlist /
operator-console shell contract: the console is unauthenticated HTML, it
contains NO live data, and it references the admin header + the existing
admin-gated JSON endpoint it fetches client-side.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero.api.label_review_console import router


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_console_is_unauth_html():
    r = _client().get("/v1/label-review/console")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


def test_console_title_and_shell_contract():
    body = _client().get("/v1/label-review/console").text
    # Page title / heading.
    assert "Label-candidate Review" in body
    # Admin header is used client-side (key stays in a header, not the URL).
    assert "X-Recupero-Admin-Key" in body
    # The shell fetches the EXISTING admin-gated endpoint.
    assert "/v1/labels/candidates" in body


def test_console_contains_no_live_data():
    body = _client().get("/v1/label-review/console").text
    # A data-free shell must not embed an admin key value, a DSN, or any
    # rendered candidate row — every dynamic value is fetched client-side.
    assert "set RECUPERO_ADMIN_KEY" not in body
    assert "SUPABASE_DB_URL" not in body
    assert "postgres://" not in body
    assert "postgresql://" not in body
    # No server-rendered candidate fields (e.g. an address row baked in).
    assert "0x" not in body


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
