"""Narrow route-authorization audit for portal/server.py.

Six concerns audited; each route in handle_portal is checked for:

  1. Token verification BEFORE any DB write / sensitive read.
  2. Case-binding (responses use only verified.case_id/investigation_id).
  3. Status-bound enforcement (signed engagement cannot be re-signed).
  4. Stolen-token / cross-origin replay defenses on state mutation.
  5. State mutation only via POST (no CSRF-vulnerable GET write).
  6. Cache-Control + Vary on every token-bound HTML/redirect response.

Audit conclusion: concerns 1, 2, 3, 4, 5 already satisfied by the
existing implementation (verified at top of dispatcher; case-bound
joins in verify_token; W4 closed-engagement guard on both GET and
POST /sign; Origin/Referer check on POST /sign; revoke_token only
ever runs inside the POST handler; no state-changing GET).

The remaining gap is concern 6's ``Vary`` header. Cache-Control:
private, no-store is already set on every portal response, but
intermediate CDN/proxy layers that ignore no-store on a private
response (a few do — Cloudflare's "Cache Everything" page rule, some
ISP transparent caches) still pick a cache key from URL + Vary'd
request headers only. Without a ``Vary`` header, two requests to the
same token URL from different browsers can collide on the CDN cache
key. The portal sends PII (case_number, client_email) and the bearer
token is in the URL → a misconfigured edge layer could serve one
victim's rendered status page to another visitor whose URL matched
because the operator copy-pasted the same token from a shared admin
window. ``Vary: Cookie, Authorization`` opts every response out of
URL-only cache keying.

Five RED tests below pin the Vary header on every portal response
path (status, sign-form, signed-confirmation, artifact 302, error)
plus a regression test that POST /sign still rejects CSRF (concern
4) so adding the Vary header doesn't accidentally regress the
existing Origin guard.
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


def _assert_vary_protects_pii(headers: dict[str, str], where: str) -> None:
    """A correctly-tagged response must declare Vary so a CDN can't
    coalesce two distinct-Cookie / distinct-Authorization requests
    onto the same cache entry. We require Cookie AND Authorization
    in the Vary list; either alone is incomplete.
    """
    vary = (headers.get("Vary") or "").lower()
    assert "cookie" in vary, (
        f"{where}: response missing 'Vary: Cookie' — a CDN may serve "
        f"one victim's rendered PII to a different browser whose request "
        f"happens to hash to the same URL key. Got Vary={headers.get('Vary')!r}"
    )
    assert "authorization" in vary, (
        f"{where}: response missing 'Vary: Authorization' — defense-in-depth "
        f"for future Bearer-header auth. Got Vary={headers.get('Vary')!r}"
    )


# ---------- concern 6: Vary header on every PII-bearing response ---------- #


def test_status_page_sets_vary_header() -> None:
    """GET /portal/<token> embeds PII (case_number, client_email,
    estimated_value_usd) under a URL whose path contains the bearer
    token. A CDN that ignores Cache-Control: no-store on a 'private'
    response (Cloudflare 'Cache Everything' rule, ISP-grade transparent
    proxies) still respects Vary for cache-key construction. Without
    Vary, two distinct browsers visiting the same URL hash to the same
    entry — one victim's PII can be served to a second visitor.
    """
    verified = _mk_verified()
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test",
            body_bytes=b"", headers={},
        )
    assert code == 200
    _assert_vary_protects_pii(headers, where="status page")


def test_sign_form_sets_vary_header() -> None:
    """GET /portal/<token>/sign renders the engagement-fee form with
    case.client_name + quoted_fee. Same CDN-keying risk as the status
    page.
    """
    verified = _mk_verified()
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=b"", headers={},
        )
    assert code == 200
    _assert_vary_protects_pii(headers, where="sign form")


def test_signed_confirmation_page_sets_vary_header() -> None:
    """POST /portal/<token>/sign success page reveals the just-captured
    signature_name + signed_at + fee. The token has just been revoked,
    BUT the response is rendered with the same URL — if any CDN cached
    it earlier under that URL, the entry is still keyed by URL only
    unless Vary tells it otherwise.
    """
    verified = _mk_verified()
    form = urllib.parse.urlencode({"signature_name": "Alex Q. Smith", "agree": "on"})
    signed_at = datetime.now(UTC)
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch("recupero.portal.server._persist_signature", return_value=signed_at), \
         patch("recupero.portal.tokens.revoke_token", return_value=True):
        code, _body, headers = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={**_SAME_ORIGIN_HEADERS, "user-agent": "test"},
        )
    assert code == 200
    _assert_vary_protects_pii(headers, where="signed confirmation")


def test_artifact_redirect_sets_vary_header() -> None:
    """GET /portal/<token>/artifact/<key> 302's to a signed Supabase
    Storage URL. The Location header reveals the signed URL (short
    TTL but still secret). Without Vary, a shared cache can pin the
    302 under the portal URL — another visitor with the same URL
    gets the signed Location and reads the file before the TTL
    expires.
    """
    verified = _mk_verified()
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch.dict(
             "os.environ",
             {"SUPABASE_URL": "https://x.supabase.co",
              "SUPABASE_SERVICE_ROLE_KEY": "k",
              "RECUPERO_PORTAL_PUBLIC_ORIGIN": "https://portal.example.com"},
             clear=False,
         ), patch(
             "recupero.portal.server._resolve_portal_artifact",
             return_value="investigations/abc/briefs/victim_summary_recoverable_x.pdf",
         ), patch(
             "recupero.worker.investigations_api._sign_storage_url",
             return_value="https://x.supabase.co/storage/v1/object/sign/abc?token=t",
         ):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/artifact/victim_summary",
            body_bytes=b"", headers={},
        )
    assert code == 302
    _assert_vary_protects_pii(headers, where="artifact redirect")


def test_error_page_sets_vary_header() -> None:
    """The 404 / 403 / 503 error response is also rendered with the
    same security-header set; Vary must appear there too so a
    misrouted request through an upstream cache doesn't pin the
    error response and serve it to the legitimate visitor after
    the token is re-issued.
    """
    with patch("recupero.portal.server.verify_token", return_value=None), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-token-that-doesnt-match-any-row",
            body_bytes=b"", headers={},
        )
    assert code == 404
    _assert_vary_protects_pii(headers, where="error page")


# ---------- concern 4 regression: CSRF guard still rejects bad Origin ---------- #


def test_post_sign_still_rejects_bad_origin() -> None:
    """Regression for the CSRF/cross-origin guard. Adding Vary must not
    weaken the Origin-match enforcement on POST /sign. A third-party
    page that learned a portal URL must NOT be able to auto-POST a
    $10K engagement.
    """
    verified = _mk_verified()
    form = urllib.parse.urlencode({"signature_name": "Alex Q. Smith", "agree": "on"})
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch("recupero.portal.server._persist_signature") as persist:
        code, _body, _headers = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={
                "host": "portal.example.com",
                "origin": "https://attacker.example",
                "user-agent": "test",
            },
        )
    assert code == 403
    persist.assert_not_called()
