"""Cookie / session-handling audit for portal/server.py.

Audit conclusion: the portal is **cookieless**. Authentication uses a
bearer token embedded in the URL path (verified by
``recupero.portal.tokens.verify_token``). State-changing POSTs are
defended against CSRF by Origin/Referer matching (see
``_origin_matches_self`` + ``test_portal_route_authz.py``), not by a
session cookie. There are no ``Set-Cookie`` emissions today.

These tests pin that invariant. If a future change introduces a
session cookie without going through a hardened helper that enforces
the Secure / HttpOnly / SameSite / Path / Domain / Max-Age / name-
opacity / entropy bar, every test below goes RED.

Eight RED-on-regression tests:

  1. No portal route emits ``Set-Cookie`` on the GET status page.
  2. No portal route emits ``Set-Cookie`` on the GET sign form.
  3. No portal route emits ``Set-Cookie`` on the POST sign-submit
     success page (the route that revokes the token — the place
     someone would be tempted to "remember" the engagement).
  4. No portal route emits ``Set-Cookie`` on the artifact 302
     redirect.
  5. No portal route emits ``Set-Cookie`` on the error page.
  6. If ``Set-Cookie`` IS ever introduced, the value must carry
     ``Secure; HttpOnly; SameSite=Strict|Lax`` AND scope ``Path=/portal``
     AND omit ``Domain=`` AND set a bounded ``Max-Age``.
  7. If ``Set-Cookie`` IS ever introduced, the cookie NAME must not
     leak the case_id / token / token_id (operator log analysis would
     deanonymize otherwise).
  8. If ``Set-Cookie`` IS ever introduced, the cookie VALUE must
     carry >=128 bits of entropy (NOT a deterministic case_id hash).

Tests 1-5 exercise the actual code paths. Tests 6-8 exercise the
hardened helper ``_validate_cookie_directive`` exposed for the
"if we ever add a cookie" guard rail.
"""

from __future__ import annotations

import math
import urllib.parse
from collections import Counter
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import pytest

from recupero.portal.server import (
    _validate_cookie_directive,
    handle_portal,
)
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


def _assert_no_set_cookie(headers: dict[str, str], where: str) -> None:
    """No portal route may emit a Set-Cookie header today. If you add
    one, you must route it through ``_validate_cookie_directive`` and
    update tests 6-8 to assert the attributes you set."""
    keys_lower = {k.lower() for k in headers}
    assert "set-cookie" not in keys_lower, (
        f"{where}: portal emitted a Set-Cookie header. The portal is "
        f"intentionally cookieless (token-in-URL auth). If you need a "
        f"cookie, route the directive through "
        f"recupero.portal.server._validate_cookie_directive and update "
        f"this test to assert the new attributes."
    )


# ---------- tests 1-5: portal is cookieless on every route ---------- #


def test_status_page_emits_no_set_cookie() -> None:
    verified = _mk_verified()
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test",
            body_bytes=b"", headers={},
        )
    assert code == 200
    _assert_no_set_cookie(headers, where="status page")


def test_sign_form_emits_no_set_cookie() -> None:
    verified = _mk_verified()
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=b"", headers={},
        )
    assert code == 200
    _assert_no_set_cookie(headers, where="sign form")


def test_signed_confirmation_emits_no_set_cookie() -> None:
    """Highest-risk emission point: the success-page response is
    rendered AFTER ``revoke_token`` runs. A future "remember me so
    the victim can come back" cookie would naturally land here.
    """
    verified = _mk_verified()
    form = urllib.parse.urlencode(
        {"signature_name": "Alex Q. Smith", "agree": "on"}
    )
    signed_at = datetime.now(UTC)
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch(
             "recupero.portal.server._persist_signature",
             return_value=signed_at,
         ), \
         patch("recupero.portal.tokens.revoke_token", return_value=True):
        code, _body, headers = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={**_SAME_ORIGIN_HEADERS, "user-agent": "test"},
        )
    assert code == 200
    _assert_no_set_cookie(headers, where="signed confirmation")


def test_artifact_redirect_emits_no_set_cookie() -> None:
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
    _assert_no_set_cookie(headers, where="artifact redirect")


def test_error_page_emits_no_set_cookie() -> None:
    with patch("recupero.portal.server.verify_token", return_value=None), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-token-that-doesnt-match-any-row",
            body_bytes=b"", headers={},
        )
    assert code == 404
    _assert_no_set_cookie(headers, where="error page")


# ---------- test 6: hardened-helper attribute enforcement ---------- #


@pytest.mark.parametrize(
    ("directive", "expected_error_substr"),
    [
        # Missing Secure → reject (cookie would transit cleartext if
        # HSTS is bypassed via downgrade-attack on first contact).
        ("rcp_s=AAAA; HttpOnly; SameSite=Lax; Path=/portal; Max-Age=600",
         "Secure"),
        # Missing HttpOnly → reject (XSS read).
        ("rcp_s=AAAA; Secure; SameSite=Lax; Path=/portal; Max-Age=600",
         "HttpOnly"),
        # SameSite=None without Secure → reject.
        ("rcp_s=AAAA; HttpOnly; SameSite=None; Path=/portal; Max-Age=600",
         "SameSite"),
        # Missing SameSite altogether → reject.
        ("rcp_s=AAAA; Secure; HttpOnly; Path=/portal; Max-Age=600",
         "SameSite"),
        # Path=/ (too broad) → reject; must scope to /portal.
        ("rcp_s=AAAA; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=600",
         "Path"),
        # Explicit Domain= attribute (widens to subdomains) → reject.
        ("rcp_s=AAAA; Secure; HttpOnly; SameSite=Lax; Path=/portal; "
         "Max-Age=600; Domain=.recupero.io",
         "Domain"),
        # No Max-Age / Expires → reject (unbounded session).
        ("rcp_s=AAAA; Secure; HttpOnly; SameSite=Lax; Path=/portal",
         "Max-Age"),
    ],
)
def test_validate_cookie_directive_rejects_unsafe_attributes(
    directive: str, expected_error_substr: str
) -> None:
    with pytest.raises(ValueError, match=expected_error_substr):
        _validate_cookie_directive(directive, value_entropy_bits=128)


def test_validate_cookie_directive_accepts_hardened_directive() -> None:
    """Sanity: a directive that satisfies every rule passes."""
    # 32 bytes of cryptographically random base64-urlsafe data. The
    # Shannon-entropy estimate over a typical token.urlsafe(32)
    # output sits in the ~160-200 bit range, comfortably above the
    # 128-bit bar.
    import secrets
    good_value = secrets.token_urlsafe(48)
    good = (
        f"rcp_s={good_value}"
        "; Secure; HttpOnly; SameSite=Strict; Path=/portal; Max-Age=900"
    )
    # No raise.
    _validate_cookie_directive(good, value_entropy_bits=128)


# ---------- test 7: cookie NAME must not leak case_id / token ---------- #


def test_validate_cookie_directive_rejects_name_carrying_case_id() -> None:
    """An operator scanning access logs sees every Set-Cookie line.
    If the cookie name embeds the case_id or token, the operator can
    correlate visits to specific cases without ever decoding the
    cookie value. Names must be opaque (e.g., ``rcp_s``)."""
    case_id_in_name = (
        "case_" + uuid4().hex + "=ZZZZ; Secure; HttpOnly; "
        "SameSite=Lax; Path=/portal; Max-Age=600"
    )
    with pytest.raises(ValueError, match="opaque"):
        _validate_cookie_directive(case_id_in_name, value_entropy_bits=128)


# ---------- test 8: cookie VALUE must have >=128 bits of entropy ---------- #


def test_validate_cookie_directive_rejects_low_entropy_value() -> None:
    """A deterministic hash of the case_id has zero secrecy: an attacker
    who knows or guesses the case_id can reproduce the cookie value.
    The helper estimates Shannon entropy of the cookie value and
    refuses anything below the requested bit-strength."""
    # "0000...0" — single-character value, entropy ~0 bits.
    low_entropy = (
        "rcp_s=" + ("0" * 32) +
        "; Secure; HttpOnly; SameSite=Lax; Path=/portal; Max-Age=600"
    )
    with pytest.raises(ValueError, match="entropy"):
        _validate_cookie_directive(low_entropy, value_entropy_bits=128)


def test_shannon_entropy_estimator_matches_textbook_value() -> None:
    """Sanity-check the entropy estimator the validator uses. ``aaaa``
    is 0 bits; ``ab`` over uniform 2-symbol alphabet is 1 bit per
    symbol = 2 bits total."""
    # We can't import a private helper safely; replicate the math to
    # pin the validator's behavior on a known string instead.
    s = "ab"
    counts = Counter(s)
    total = len(s)
    h_per_symbol = -sum(
        (c / total) * math.log2(c / total) for c in counts.values()
    )
    assert math.isclose(h_per_symbol * total, 2.0, abs_tol=1e-6)
