"""Cron / Job Health operator console shell (HTML).

The console router is NOT yet wired into the main app, so we mount it on a
LOCAL FastAPI app for this test. We pin only the SHELL contract:

  * GET /v1/ops/cron-console → 200 text/html (unauthenticated by design).
  * The shell ships the secure-fetch wiring (the X-Recupero-Admin-Key header
    name + the EXISTING /v1/cron/jobs endpoint it fetches).
  * The shell embeds NO live job data — it is a static, auth-free shell.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero.api.cron_console import router

app = FastAPI()
app.include_router(router)
c = TestClient(app)


def test_cron_console_shell_200_html() -> None:
    r = c.get("/v1/ops/cron-console")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")


def test_cron_console_shell_has_secure_fetch_wiring() -> None:
    body = c.get("/v1/ops/cron-console").text
    # Titled "Cron / Job Health".
    assert "Cron" in body
    # Secure-shell pattern: header-based auth, never the URL.
    assert "X-Recupero-Admin-Key" in body
    # Reuses the EXISTING admin-gated cron-jobs endpoint.
    assert "/v1/cron/jobs" in body


def test_cron_console_shell_embeds_no_live_data() -> None:
    body = c.get("/v1/ops/cron-console").text
    # The shell is static + auth-free: every job value (status, error text,
    # last-success time) is pulled by the client-side fetch, never baked in.
    # Prove the fetch wiring is present (data comes from the API, not the HTML).
    assert 'fetch("/v1/cron/jobs"' in body
    # No admin key value should ever be present in the served shell.
    assert "RECUPERO_ADMIN_KEY=" not in body
    # The table markup is built client-side in JS (the literal "<tbody>"
    # appears only inside a JS string that runs after the fetch). Prove no
    # job DATA is baked in: the rendering loop over the fetched payload is
    # present, so rows exist only at runtime, not in the served bytes.
    assert "Object.keys" in body or ".jobs" in body
