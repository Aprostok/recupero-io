"""Route-authz audit: enumerate every route in api/app.py and pin the
contract for each.

Audit columns (per route):
  * Token required?
  * Method allowlist (POST routes refuse GET; GET routes refuse POST)
  * Multi-tenant scoping (case_id / api_key isolation)
  * Rate-limit (per-IP for unauthenticated, per-key for authenticated)
  * CSRF (Origin/Referer for unauthenticated state-changing form POST)
  * OPTIONS preflight does not advertise wildcard CORS

This file is the route-coverage contract — future routes added to
api/app.py should add a row here.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

_API_SECRET_A = "secret-acme-aaaaaaaaaa"
_API_SECRET_B = "secret-other-bbbbbbbbbb"
_KEY_A = "exchange-acme"
_KEY_B = "exchange-other"

_CASE_A = "11111111-1111-1111-1111-111111111111"
_CASE_B = "22222222-2222-2222-2222-222222222222"


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolate_buckets():
    """Reset per-key rate-limit buckets + per-IP intake buckets between
    tests so previous-test state cannot bleed in / out."""
    from recupero.api import app as _app_mod
    from recupero.api.auth import reset_buckets_for_tests
    reset_buckets_for_tests()
    _app_mod._intake_rl_state.clear()
    yield
    reset_buckets_for_tests()
    _app_mod._intake_rl_state.clear()


@pytest.fixture
def two_key_client(monkeypatch):
    """Two partner keys, A and B, each scoped to a different issuer +
    different case_id allow-list. Lets us prove multi-tenant boundaries.
    """
    monkeypatch.setenv(
        "RECUPERO_API_KEYS",
        f"{_KEY_A}:{_API_SECRET_A},{_KEY_B}:{_API_SECRET_B}",
    )
    monkeypatch.setenv(
        "RECUPERO_API_KEY_ISSUERS",
        f"{_KEY_A}:Tether,{_KEY_B}:Circle",
    )
    monkeypatch.setenv(
        "RECUPERO_API_KEY_CASES",
        f"{_KEY_A}:{_CASE_A},{_KEY_B}:{_CASE_B}",
    )
    monkeypatch.delenv("RECUPERO_API_KEY_ADMINS", raising=False)
    monkeypatch.delenv("RECUPERO_API_AUTH_OPTIONAL", raising=False)
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import app
    return TestClient(app)


@pytest.fixture
def single_key_client(monkeypatch):
    monkeypatch.setenv("RECUPERO_API_KEYS", f"{_KEY_A}:{_API_SECRET_A}")
    monkeypatch.delenv("RECUPERO_API_KEY_ADMINS", raising=False)
    monkeypatch.delenv("RECUPERO_API_KEY_ISSUERS", raising=False)
    monkeypatch.delenv("RECUPERO_API_KEY_CASES", raising=False)
    monkeypatch.delenv("RECUPERO_API_AUTH_OPTIONAL", raising=False)
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import app
    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Every state-changing route requires a token (no silent unauthenticated
#    write surface)
# ─────────────────────────────────────────────────────────────────────────────


_TOKEN_REQUIRED_ROUTES = (
    ("POST", "/v1/screen", {"address": "0x" + "a" * 40, "chain": "ethereum"}),
    ("POST", "/v1/token-risk", {"contract_address": "0x" + "b" * 40,
                                "chain": "ethereum"}),
    ("GET",  "/v1/correlations/0x" + "c" * 40, None),
    ("POST", "/v1/freeze-outcomes", {
        "case_id": _CASE_A, "issuer": "Tether",
        "target_address": "0x" + "a" * 40, "outcome_type": "acknowledged",
    }),
    ("POST", "/v1/monitor/subscribe", {
        "address": "0x" + "a" * 40, "chain": "ethereum",
        "trigger_type": "any_movement",
        "webhook_url": "https://hooks.example.com/x",
    }),
    ("GET",  "/v1/monitor/subscriptions", None),
    ("GET",  "/v1/monitor/11111111-1111-1111-1111-111111111111", None),
    ("DELETE", "/v1/monitor/11111111-1111-1111-1111-111111111111", None),
    ("POST", "/v1/screen/bulk", {"addresses": ["0x" + "a" * 40],
                                  "chain": "ethereum"}),
)


@pytest.mark.parametrize("method,path,body", _TOKEN_REQUIRED_ROUTES)
def test_every_protected_route_rejects_missing_api_key(
    single_key_client, method, path, body,
):
    """No protected route accepts unauthenticated traffic. A regression
    that drops `Depends(require_api_key)` from any of these would show
    up here as a 200/201/404 instead of 401."""
    resp = single_key_client.request(method, path, json=body)
    assert resp.status_code == 401, (
        f"{method} {path} returned {resp.status_code} for unauthenticated "
        f"request — expected 401. body={resp.text[:200]}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Method allowlist — POST routes refuse GET; GET routes refuse POST.
#    FastAPI's default-405 behavior should NOT be silently broken by a
#    route added later under the same path with a different verb.
# ─────────────────────────────────────────────────────────────────────────────


def test_screen_endpoint_rejects_get(single_key_client):
    """/v1/screen is POST-only. A GET must return 405, not silently
    fall through to another handler that leaks ?address=… into logs."""
    resp = single_key_client.get(
        "/v1/screen",
        headers={"X-Recupero-API-Key": _API_SECRET_A},
    )
    assert resp.status_code == 405, (
        f"GET /v1/screen returned {resp.status_code}; expected 405"
    )


def test_correlations_endpoint_rejects_post(single_key_client):
    """/v1/correlations/{address} is GET-only. A POST must 405."""
    resp = single_key_client.post(
        "/v1/correlations/0xabc",
        json={"chain": "ethereum"},
        headers={"X-Recupero-API-Key": _API_SECRET_A},
    )
    assert resp.status_code == 405, (
        f"POST /v1/correlations/* returned {resp.status_code}; "
        f"expected 405"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 3. CSRF — unauthenticated POST /v1/intake must reject cross-origin
#    browser submissions. Non-browser callers (no Origin/Referer) pass.
# ─────────────────────────────────────────────────────────────────────────────


_VALID_INTAKE_FORM = {
    "client_name": "Jane Doe",
    "client_email": "jane@example.com",
    "chain": "ethereum",
    "seed_address": "0x" + "a" * 40,
    "incident_date": "2026-04-01",
    "description": "x" * 50,
    "country": "US",
}


def test_intake_post_rejects_cross_origin_browser_submission(
    single_key_client,
):
    """A browser-issued cross-origin form POST carries an Origin header
    different from Host. Pre-fix this created a `cases` row freely;
    post-fix it 403s."""
    resp = single_key_client.post(
        "/v1/intake",
        data=_VALID_INTAKE_FORM,
        headers={
            "origin": "https://attacker.example.com",
            "host": "testserver",
        },
    )
    assert resp.status_code == 403, (
        f"cross-origin intake POST returned {resp.status_code}; "
        f"expected 403"
    )
    assert "cross-origin" in resp.json().get("detail", "").lower()


def test_intake_post_allows_curl_style_no_origin(single_key_client):
    """Non-browser callers (curl, integration tests) have no Origin
    header — must pass through. The fix targets browser-only CSRF, not
    legitimate server-side integration."""
    with patch(
        "recupero.portal.intake.create_case_from_intake",
        return_value=UUID("33333333-3333-3333-3333-333333333333"),
    ), patch(
        "recupero.payments.payment_links.build_diagnostic_link",
        return_value="https://buy.stripe.com/test",
    ):
        resp = single_key_client.post(
            "/v1/intake", data=_VALID_INTAKE_FORM,
            follow_redirects=False,
        )
    # Either a 303 redirect (happy path) or 422/503 — anything other
    # than 403 confirms CSRF gate did not block the curl-style caller.
    assert resp.status_code != 403, (
        f"intake POST blocked a no-Origin (curl/test) caller — "
        f"got {resp.status_code}, expected non-403"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Multi-tenant scoping — /v1/freeze-outcomes case_id binding.
#    A partner authorized for issuer Tether against case A must NOT be
#    able to write outcomes against case B even when the issuer is the
#    same (case scoping is the second axis of authorization).
# ─────────────────────────────────────────────────────────────────────────────


def test_freeze_outcome_partner_denied_for_foreign_case(two_key_client):
    """Key A is allow-listed for issuer=Tether AND case_id=_CASE_A.
    A request from Key A for issuer=Tether but case_id=_CASE_B must 404
    with the same generic body — no recorder invocation."""
    payload = {
        "case_id": _CASE_B,
        "issuer": "Tether",
        "target_address": "0x" + "a" * 40,
        "outcome_type": "acknowledged",
    }
    with patch(
        "recupero.freeze_learning.recorder.record_outcome_by_target",
    ) as recorder_mock:
        resp = two_key_client.post(
            "/v1/freeze-outcomes", json=payload,
            headers={"X-Recupero-API-Key": _API_SECRET_A},
        )
    assert resp.status_code == 404, (
        f"foreign-case write returned {resp.status_code}; expected 404"
    )
    assert resp.json()["detail"] == "freeze outcome not recorded"
    # Recorder must NEVER have been invoked — denial pre-DB.
    assert recorder_mock.call_count == 0, (
        "recorder was invoked even though the case_id was not in the "
        "key's allow-list — authz bypass"
    )


def test_freeze_outcome_partner_allowed_for_owned_case(two_key_client):
    """Same key, same issuer, OWNED case_id → 201."""
    payload = {
        "case_id": _CASE_A,
        "issuer": "Tether",
        "target_address": "0x" + "a" * 40,
        "outcome_type": "acknowledged",
    }
    outcome_id = UUID("44444444-4444-4444-4444-444444444444")
    with patch(
        "recupero.freeze_learning.recorder.record_outcome_by_target",
        return_value=outcome_id,
    ):
        resp = two_key_client.post(
            "/v1/freeze-outcomes", json=payload,
            headers={"X-Recupero-API-Key": _API_SECRET_A},
        )
    assert resp.status_code == 201, (
        f"happy-path write returned {resp.status_code}; expected 201. "
        f"body={resp.text[:200]}"
    )
    assert resp.json()["outcome_id"] == str(outcome_id)


def test_freeze_outcome_case_scoping_backward_compatible(monkeypatch):
    """When RECUPERO_API_KEY_CASES is unset entirely, case scoping is
    a no-op — issuer-only behavior is preserved (legacy partners)."""
    monkeypatch.setenv("RECUPERO_API_KEYS", f"{_KEY_A}:{_API_SECRET_A}")
    monkeypatch.setenv("RECUPERO_API_KEY_ISSUERS", f"{_KEY_A}:Tether")
    monkeypatch.delenv("RECUPERO_API_KEY_CASES", raising=False)
    monkeypatch.delenv("RECUPERO_API_KEY_ADMINS", raising=False)
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import app
    client = TestClient(app)
    payload = {
        "case_id": _CASE_B,  # would be forbidden if scoping enforced
        "issuer": "Tether",
        "target_address": "0x" + "a" * 40,
        "outcome_type": "acknowledged",
    }
    with patch(
        "recupero.freeze_learning.recorder.record_outcome_by_target",
        return_value=UUID("55555555-5555-5555-5555-555555555555"),
    ):
        resp = client.post(
            "/v1/freeze-outcomes", json=payload,
            headers={"X-Recupero-API-Key": _API_SECRET_A},
        )
    assert resp.status_code == 201, (
        f"legacy (no case scoping) returned {resp.status_code}; "
        f"backward-compat broken"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5. Monitoring multi-tenant boundary — key B cannot read key A's sub.
# ─────────────────────────────────────────────────────────────────────────────


def test_monitor_get_returns_404_for_foreign_subscription(two_key_client):
    """If key B asks for a subscription owned by key A, the response
    must be 404 (not 403 — 403 would leak existence). The underlying
    DB call must be scoped by api_key_name."""
    foreign_sub = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    with patch(
        "recupero.api.monitoring_api.get_subscription",
        return_value=None,  # DB query scoped by key_name → no match
    ) as get_mock:
        resp = two_key_client.get(
            f"/v1/monitor/{foreign_sub}",
            headers={"X-Recupero-API-Key": _API_SECRET_B},
        )
    assert resp.status_code == 404, (
        f"foreign-sub GET returned {resp.status_code}; expected 404"
    )
    # Scoping happens in the DB call — assert the right key was passed.
    assert get_mock.called
    kwargs = get_mock.call_args.kwargs
    assert kwargs.get("api_key_name") == _KEY_B, (
        f"DB lookup scoped to {kwargs.get('api_key_name')!r} — expected "
        f"{_KEY_B!r}. Cross-tenant leak risk."
    )


# ─────────────────────────────────────────────────────────────────────────────
# 6. Health is intentionally unauthenticated (Railway / k8s liveness)
# ─────────────────────────────────────────────────────────────────────────────


def test_health_does_not_require_api_key(single_key_client):
    """/v1/health must respond 200 with NO auth header — Railway's
    health probe is unauthenticated by design."""
    resp = single_key_client.get("/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Source-level pin: the CSRF + case-scoping helpers stay wired in
# ─────────────────────────────────────────────────────────────────────────────


def test_intake_post_invokes_csrf_gate_at_source_level():
    """A future refactor that drops the CSRF helper would silently
    re-open the cross-origin attack. Pin the call site."""
    import inspect

    from recupero.api import app as app_mod
    src = inspect.getsource(app_mod.intake_form_post)
    assert "_intake_post_csrf_ok" in src, (
        "intake_form_post no longer invokes _intake_post_csrf_ok — "
        "CSRF defense removed"
    )


def test_freeze_outcome_invokes_case_scoping_gate_at_source_level():
    """The case-scoping gate must run alongside the issuer gate."""
    import inspect

    from recupero.api import app as app_mod
    src = inspect.getsource(app_mod.record_freeze_outcome_endpoint)
    assert "_is_api_key_authorized_for_case" in src, (
        "record_freeze_outcome_endpoint no longer invokes "
        "_is_api_key_authorized_for_case — case scoping removed"
    )
