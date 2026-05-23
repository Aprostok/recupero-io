"""RIGOR-Jacob Z16 regression tests for portal/server.py adversarial-
input + defense-in-depth bugs that Z2 didn't cover.

Three concrete bugs covered here:

  Z16-1 (PII pages cached by intermediate proxies / browser bfcache).
  The bearer token is in the URL path. Every portal HTML response
  (status, sign, signed, error) embeds PII (case_number, client_name,
  client_email, estimated_value_usd, sometimes the engagement fee)
  AND the URL contains the bearer token. The handler sets
  Referrer-Policy: no-referrer + CSP + HSTS — but it does NOT set
  Cache-Control. That means:

    * A shared HTTP cache / CDN sitting in front of the worker can
      cache the response under the URL path. Subsequent requests
      hitting the same path (e.g., the same victim visiting from a
      kiosk; an attacker who later guesses the URL) get the cached
      PII without ever hitting the backend's token-revocation check.
    * Browser bfcache can retain the rendered PII page across
      navigations / forward-back, well after the token has been
      rotated by the post-sign revocation.

  The artifact redirect already correctly sets
  ``Cache-Control: private, no-store, max-age=0`` (per v0.17.6
  round-10 fix). The HTML response paths were missed in that pass.

  Mitigation: tag every authenticated portal HTML response with
  ``Cache-Control: private, no-store, max-age=0`` so neither
  shared proxies nor browser bfcache retain PII.

  Z16-2 (closed-engagement GET /sign renders the sign form). The
  POST /sign handler explicitly rejects closed engagements with
  a 403 + "engagement was closed" message (v0.16.7 round-9 HIGH).
  The GET handler that renders the form does NOT — its short-
  circuit only triggers when ``engagement_started_at IS NOT NULL
  AND engagement_closed_at IS NULL`` (active engagement). A
  closed engagement falls through and renders sign.html.j2 as if
  the victim could still sign.

  Two concrete problems:
    1. UX-trap: the victim types their legal name + ticks the
       agreement box, hits Submit, gets a 403. Bad on its own.
    2. Defense-in-depth: if the closed-engagement POST guard ever
       regressed (refactor, test bypass), the only thing standing
       between a closed case and a silent re-engagement would be
       a single check. We want the GET path to ALSO redirect to
       the status page so the rejection is enforced at both
       request entries.

  Z16-3 (signed.html.j2 also leaks PII without Cache-Control). Same
  attack family as Z16-1 — the post-sign "you're engaged" page
  shows the signature_name + signed_at + fee in plaintext, and
  it's rendered with the now-revoked token in the URL. If a
  proxy caches this page under the (revoked) token URL, anyone
  later hitting that URL through the same proxy could see the
  signature row contents without authenticating.
"""

from __future__ import annotations

import urllib.parse
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import pytest

from recupero.portal.server import handle_portal
from recupero.portal.tokens import VerifiedToken


def _mk_verified(**overrides) -> VerifiedToken:
    base = {
        "token_id": uuid4(),
        "case_id": uuid4(),
        "case_number": "V-12345",
        "client_name": "Test Victim",
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


# ---------- Z16-1: Cache-Control on PII HTML responses ---------- #


def test_status_page_sets_cache_control_no_store() -> None:
    """Z16-1: GET /portal/<token> must respond with
    ``Cache-Control: private, no-store`` (or stronger).

    The status page embeds PII (case_number, client_name, client_email,
    estimated_value_usd) under a URL whose path contains the bearer
    token. Without no-store, a shared HTTP cache or browser bfcache
    can retain the rendered PII page after the token is rotated by
    the post-sign revocation. The artifact 302 already sets this
    header (v0.17.6 fix); the HTML response paths were missed.
    """
    verified = _mk_verified(case_number="V-87654", client_name="Alice Q.")
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test",
            body_bytes=b"", headers={},
        )
    assert code == 200
    assert b"V-87654" in body  # confirms PII is in the response body
    cc = (headers.get("Cache-Control") or "").lower()
    assert "no-store" in cc, (
        f"Status page is missing Cache-Control: no-store — "
        f"PII can be cached by intermediate proxies / browser bfcache. "
        f"Got Cache-Control={headers.get('Cache-Control')!r}"
    )


def test_sign_form_sets_cache_control_no_store() -> None:
    """Z16-1: GET /portal/<token>/sign must respond with no-store.

    The sign form renders case.client_name + case.quoted_fee_usd in
    the page body; both are PII that should not be cached under the
    token-bearing URL.
    """
    verified = _mk_verified(client_name="Bob R. Customer")
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=b"", headers={},
        )
    assert code == 200
    assert b"Bob R. Customer" in body
    cc = (headers.get("Cache-Control") or "").lower()
    assert "no-store" in cc, (
        f"Sign form is missing Cache-Control: no-store — "
        f"Got Cache-Control={headers.get('Cache-Control')!r}"
    )


def test_signed_confirmation_page_sets_cache_control_no_store() -> None:
    """Z16-3: POST /portal/<token>/sign success-page must respond
    with no-store.

    The signed.html.j2 page shows the just-captured signature_name +
    signed_at + fee, plus a link back to /portal/<token> using the
    NOW-REVOKED token. Without no-store, an intermediate cache can
    pin the rendered signature page under the token-bearing URL —
    later requests to the same URL through the same cache see the
    signature_name without re-authenticating.
    """
    verified = _mk_verified()
    form = urllib.parse.urlencode({"signature_name": "Alex Q. Smith", "agree": "on"})
    signed_at = datetime.now(UTC)
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch("recupero.portal.server._persist_signature", return_value=signed_at), \
         patch("recupero.portal.tokens.revoke_token", return_value=True):
        code, body, headers = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={**_SAME_ORIGIN_HEADERS, "user-agent": "test"},
        )
    assert code == 200
    assert b"Alex Q. Smith" in body
    cc = (headers.get("Cache-Control") or "").lower()
    assert "no-store" in cc, (
        f"Signed-confirmation page is missing Cache-Control: no-store — "
        f"the just-captured signature_name is rendered under a URL whose "
        f"token has just been revoked, but the page can still be cached. "
        f"Got Cache-Control={headers.get('Cache-Control')!r}"
    )


def test_error_page_sets_cache_control_no_store() -> None:
    """Z16-1: even the error response (token unavailable / 404 /
    503) must be marked no-store. Otherwise a misrouted request
    that exposes the URL to a shared cache (e.g., a victim
    forwarding the URL to a relative who lands a 404 through their
    ISP's caching proxy) pins a cacheable response — and the cache
    might serve stale 404s to the legitimate victim's revisit
    after the token was re-issued.
    """
    with patch("recupero.portal.server.verify_token", return_value=None), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-token-that-doesnt-match-any-row",
            body_bytes=b"", headers={},
        )
    assert code == 404
    cc = (headers.get("Cache-Control") or "").lower()
    assert "no-store" in cc, (
        f"Error response is missing Cache-Control: no-store — "
        f"Got Cache-Control={headers.get('Cache-Control')!r}"
    )


# ---------- Z16-2: GET /sign on closed engagement ---------- #


def test_get_sign_form_redirects_when_engagement_closed() -> None:
    """Z16-2: GET /portal/<token>/sign on a CLOSED engagement must NOT
    render the sign form. It should redirect to the status page (or
    return a 403, matching the POST handler's behavior).

    Pre-fix the GET handler's short-circuit only fires when engagement
    is ACTIVE (started_at IS NOT NULL AND closed_at IS NULL). For a
    closed engagement, both fields are set, the condition is False,
    and the sign form is rendered. The POST handler then rejects
    with a 403 'engagement was closed' — so the victim fills out
    their full legal name + ticks the agreement box, hits Submit,
    and gets blocked.

    Worse, this is a defense-in-depth gap: if the POST closed-
    engagement guard regressed (refactor, test mock, etc.), there
    would be NO server-side rejection of a close-then-reopen attempt
    via the sign flow. The GET path should also enforce the closed-
    engagement state.
    """
    verified = _mk_verified(
        engagement_started_at=datetime.now(UTC) - timedelta(days=60),
        engagement_closed_at=datetime.now(UTC) - timedelta(days=5),
    )
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=b"", headers={},
        )
    # Accept either a 303 redirect to the status page OR a 403
    # "closed" response. The bug-closing invariant is: do NOT
    # render the sign form with its <input name="signature_name">.
    assert b'name="signature_name"' not in body, (
        f"GET /sign on closed engagement rendered the sign form — "
        f"victim sees a form they can't submit. code={code}, "
        f"location={headers.get('Location')!r}"
    )
    # Concretely we expect a redirect to /portal/<token> (matches
    # the already-engaged short-circuit pattern).
    assert code in (303, 302, 403), (
        f"Expected redirect or 403 on closed-engagement GET /sign; got {code}"
    )
