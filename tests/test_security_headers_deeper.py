"""Deeper security-header audit for portal/server.py.

This file pins the FULL set of security headers the portal MUST return
on every response shape (HTML 200, redirect 303/302, error 4xx/5xx).
The existing test_portal_server_caching.py covers Cache-Control / Vary;
this file covers the rest of the OWASP secure-headers checklist:

  * Content-Security-Policy           — XSS defense-in-depth
  * X-Content-Type-Options: nosniff   — MIME sniffing defense
  * X-Frame-Options: DENY             — clickjacking defense
  * Referrer-Policy                   — token-in-URL leak defense
  * Permissions-Policy                — disable unused powerful APIs
  * Strict-Transport-Security         — force HTTPS

The portal's bearer token sits in the URL path, so leakage protection
(Referrer-Policy + Cache-Control) is safety-critical. The other headers
are defense-in-depth — they raise the cost of any future XSS / iframe-
embedding / mixed-content regression.
"""

from __future__ import annotations

import urllib.parse
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import pytest

from recupero.portal.server import _PORTAL_SECURITY_HEADERS, handle_portal
from recupero.portal.tokens import VerifiedToken


def _mk_verified(**overrides) -> VerifiedToken:
    base = {
        "token_id": uuid4(),
        "case_id": uuid4(),
        "case_number": "V-99999",
        "client_name": "Audit Victim",
        "client_email": "victim@example.com",
        "case_status": "complete",
        "case_state": None,
        "estimated_value_usd": Decimal("50000"),
        "quoted_fee_usd": Decimal("10000"),
        "investigation_id": uuid4(),
        "engagement_started_at": None,
        "engagement_closed_at": None,
        "engagement_fee_paid_usd": None,
        "expires_at": datetime.now(UTC) + timedelta(days=30),
        "label": None,
    }
    base.update(overrides)
    return VerifiedToken(**base)


_SAME_ORIGIN_HEADERS = {
    "host": "portal.example.com",
    "origin": "https://portal.example.com",
}


@pytest.fixture(autouse=True)
def _pin_portal_origin(monkeypatch):
    monkeypatch.setenv(
        "RECUPERO_PORTAL_PUBLIC_ORIGIN", "https://portal.example.com"
    )


# ---------- Dict-level audit ---------- #


def test_portal_security_headers_dict_has_all_required_keys() -> None:
    """RED on missing header: the portal's standard header dict must
    define every header in the OWASP secure-headers checklist.

    A single missing key here means every portal response shape
    (HTML/redirect/error) is missing the header — this assertion fires
    once and protects all routes.
    """
    required = {
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Strict-Transport-Security",
    }
    missing = required - set(_PORTAL_SECURITY_HEADERS.keys())
    assert not missing, (
        f"_PORTAL_SECURITY_HEADERS missing required keys: {sorted(missing)}. "
        f"Every portal response shape inherits this dict via "
        f"_with_security_headers, so a missing key is missing on EVERY route."
    )


def test_portal_security_headers_have_strict_values() -> None:
    """RED on weak value: pin the exact strictness of each header.

    Catches regressions like X-Frame-Options=SAMEORIGIN (allows same-
    origin iframing of /sign — bypasses the DENY guarantee) or
    nosniff being dropped.
    """
    h = _PORTAL_SECURITY_HEADERS
    assert h["X-Content-Type-Options"].lower() == "nosniff"
    assert h["X-Frame-Options"].upper() == "DENY"
    # Referrer-Policy must be at least as strict as
    # strict-origin-when-cross-origin; the portal currently uses
    # the stricter `no-referrer` because the bearer token is in the URL
    # path and any cross-origin leak is a token leak. Accept either.
    rp = h["Referrer-Policy"].lower()
    assert rp in ("no-referrer", "strict-origin-when-cross-origin"), (
        f"Referrer-Policy={h['Referrer-Policy']!r} is too permissive — "
        f"token-in-URL portal must use no-referrer or stricter."
    )
    # HSTS must include max-age >= 1 year + includeSubDomains.
    hsts = h["Strict-Transport-Security"].lower()
    assert "max-age=31536000" in hsts
    assert "includesubdomains" in hsts.replace(" ", "")
    # CSP must include frame-ancestors 'none' (clickjacking) + a default
    # restrictive script policy.
    csp = h["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'self'" in csp
    assert "script-src" in csp
    # Permissions-Policy must disable at least camera/microphone/
    # geolocation/payment.
    pp = h["Permissions-Policy"]
    for feature in ("camera", "microphone", "geolocation", "payment"):
        assert f"{feature}=()" in pp, (
            f"Permissions-Policy missing {feature}=() — feature should "
            f"be explicitly disabled. Got: {pp!r}"
        )


# ---------- Route-level audit (every route must emit headers) ---------- #


def _assert_all_security_headers_present(response_headers: dict[str, str]) -> None:
    """Helper: assert every required header surfaces on a single response."""
    required = (
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Strict-Transport-Security",
    )
    missing = [h for h in required if h not in response_headers]
    assert not missing, (
        f"Response missing security headers: {missing}. "
        f"Got headers: {sorted(response_headers.keys())}"
    )


def test_status_page_emits_all_security_headers() -> None:
    """RED: GET /portal/<token> (HTML 200) must emit the full set."""
    verified = _mk_verified()
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test",
            body_bytes=b"", headers={},
        )
    assert code == 200
    _assert_all_security_headers_present(headers)


def test_sign_form_emits_all_security_headers() -> None:
    """RED: GET /portal/<token>/sign (HTML 200) must emit the full set."""
    verified = _mk_verified()
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=b"", headers={},
        )
    assert code == 200
    _assert_all_security_headers_present(headers)


def test_error_response_emits_all_security_headers() -> None:
    """RED: error responses (4xx / 5xx) must also emit headers.

    Error pages render under the same token-bearing URL — an attacker
    forcing a 404/403 must not get a response shape without CSP /
    X-Frame-Options / Permissions-Policy etc.
    """
    # /portal with no token → 404 via _render_error path.
    code, _body, headers = handle_portal(
        method="GET", path="/portal", body_bytes=b"", headers={},
    )
    assert code == 404
    _assert_all_security_headers_present(headers)


def test_csrf_rejection_emits_all_security_headers() -> None:
    """RED: 403 from CSRF/origin rejection must emit headers.

    The state-changing POST /sign rejection path is a high-value
    attacker target (probing Origin checks). Its 403 response must
    not skip the header set.
    """
    verified = _mk_verified()
    form = urllib.parse.urlencode({"signature_name": "X", "agree": "on"})
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        # No Origin header → _origin_matches_self returns False → 403.
        code, _body, headers = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={"host": "portal.example.com"},
        )
    assert code == 403
    _assert_all_security_headers_present(headers)


def test_redirect_response_emits_all_security_headers() -> None:
    """RED: 303/302 redirects must also emit the full header set.

    A redirect from /sign GET on an active engagement to /portal/<token>
    still travels under the token-bearing URL — clickjacking / framing
    defenses must apply equally to redirects.
    """
    # Active engagement → GET /sign redirects to /portal/<token>.
    verified = _mk_verified(
        engagement_started_at=datetime.now(UTC) - timedelta(days=1),
        engagement_closed_at=None,
    )
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=b"", headers={},
        )
    assert code in (302, 303)
    assert "Location" in headers
    _assert_all_security_headers_present(headers)
