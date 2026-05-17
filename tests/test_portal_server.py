"""Tests for the portal HTTP handler's routing + pure helpers.

The handler's external surface is small — `handle_portal(method,
path, body_bytes, headers)` → `(code, body, headers)`. We exercise
the routing decisions, the form-submission validation, and the
404 paths.

DB writes go through a mocked psycopg.connect; the live signature-
capture path is verified end-to-end against the canary in the
release-time dry-run.
"""

from __future__ import annotations

import urllib.parse
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from recupero.portal.server import (
    _coerce_utc,
    _engagement_dict,
    _PORTAL_ARTIFACTS,
    _portal_artifact_list,
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
        "expires_at": datetime.now(timezone.utc) + timedelta(days=30),
        "label": None,
    }
    base.update(overrides)
    return VerifiedToken(**base)


# ---- _coerce_utc ---- #


def test_coerce_utc_none_stays_none() -> None:
    assert _coerce_utc(None) is None


def test_coerce_utc_naive_assumed_utc() -> None:
    """Defensive: a naive datetime (shouldn't happen with timestamptz)
    gets tagged UTC. Matches the engagement-summary helper's behavior."""
    naive = datetime(2026, 1, 1, 12, 0, 0)
    out = _coerce_utc(naive)
    assert out is not None
    assert out.tzinfo is timezone.utc


def test_coerce_utc_passes_aware_through() -> None:
    """An already-tz-aware datetime passes through unchanged."""
    aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert _coerce_utc(aware) is aware


# ---- _engagement_dict ---- #


def test_engagement_dict_not_engaged() -> None:
    """No engagement_started_at → status='not_engaged' + all derived
    fields are None/0."""
    out = _engagement_dict(_mk_verified())
    assert out["status"] == "not_engaged"
    assert out["days_since_start"] is None
    assert out["days_remaining"] is None


def test_engagement_dict_active() -> None:
    """Started but not closed, less than 30 days → 'active' +
    days_remaining = 30 - days_since_start."""
    started = datetime.now(timezone.utc) - timedelta(days=5)
    out = _engagement_dict(_mk_verified(engagement_started_at=started))
    assert out["status"] == "active"
    assert out["days_since_start"] == 5
    assert out["days_remaining"] == 25


def test_engagement_dict_closed_short_circuits() -> None:
    """engagement_closed_at set → 'closed' regardless of how long ago.
    days_remaining is None (not applicable to closed engagements)."""
    started = datetime.now(timezone.utc) - timedelta(days=10)
    closed = datetime.now(timezone.utc) - timedelta(days=2)
    out = _engagement_dict(_mk_verified(
        engagement_started_at=started,
        engagement_closed_at=closed,
    ))
    assert out["status"] == "closed"
    assert out["days_remaining"] is None


def test_engagement_dict_expired_after_30_days() -> None:
    """Active engagement past the 30-day window without close →
    'expired' + days_remaining = 0. Mirrors the engagement-API
    helper's behavior so the portal + admin UI tell the same
    story."""
    started = datetime.now(timezone.utc) - timedelta(days=35)
    out = _engagement_dict(_mk_verified(engagement_started_at=started))
    assert out["status"] == "expired"
    assert out["days_remaining"] == 0


# ---- _portal_artifact_list ---- #


def test_portal_artifact_list_includes_whitelisted_keys() -> None:
    """The list page builds entries from the _PORTAL_ARTIFACTS
    whitelist — we don't probe the bucket per-key.

    Today's whitelist is `victim_summary` (the customer-facing
    diagnostic) + `fund_flow` (the visualization). The engagement
    letter is intentionally NOT in the list — the customer signs
    it via the portal /sign flow, not by downloading a PDF; the
    signature record in engagement_signatures is the canonical
    evidence."""
    verified = _mk_verified()
    out = _portal_artifact_list(verified=verified)
    keys = {entry["key"] for entry in out}
    assert keys == set(_PORTAL_ARTIFACTS.keys())
    assert "victim_summary" in keys
    assert "fund_flow" in keys
    # Engagement letter is deliberately NOT a downloadable artifact.
    # Lock that so the next person who adds it has to think about
    # whether the sign flow + downloadable PDF should coexist.
    assert "engagement_letter" not in keys


def test_portal_artifact_list_empty_when_no_investigation() -> None:
    """A case with no investigation row → empty list (the diagnostic
    pipeline hasn't run yet, no artifacts exist in the bucket)."""
    verified = _mk_verified(investigation_id=None)
    out = _portal_artifact_list(verified=verified)
    assert out == []


# ---- handle_portal routing ---- #


def test_handle_portal_rejects_missing_token() -> None:
    """``/portal`` or ``/portal/`` with no token → 404."""
    code, _, _ = handle_portal(
        method="GET", path="/portal", body_bytes=b"", headers={},
    )
    assert code == 404


def test_handle_portal_404s_outside_portal_prefix() -> None:
    """Defensive: a request that somehow reaches the portal handler
    with a path NOT starting with /portal → 404. This shouldn't
    happen in practice (the health server only dispatches /portal
    routes here) but we lock the behavior."""
    code, _, _ = handle_portal(
        method="GET", path="/something-else", body_bytes=b"", headers={},
    )
    assert code == 404


def test_handle_portal_rejects_unknown_token() -> None:
    """A 43-char token that doesn't match any row → 404 'link
    unavailable'. We render the same error page used for revoked
    + expired tokens so the response doesn't leak existence."""
    with patch("recupero.portal.server.verify_token", return_value=None), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-token-that-doesnt-match-any-row",
            body_bytes=b"", headers={},
        )
    assert code == 404
    assert b"Link unavailable" in body or b"unavailable" in body
    assert headers["Content-Type"].startswith("text/html")


def test_handle_portal_500s_when_dsn_unset() -> None:
    """If RECUPERO_DB_URL is missing the portal can't function —
    return 503 so the operator notices in logs. Better than
    silently rendering an error page that looks like a token issue."""
    with patch("recupero.portal.server._get_dsn", return_value=""):
        code, _, _ = handle_portal(
            method="GET", path="/portal/abc", body_bytes=b"", headers={},
        )
    assert code == 503


def test_handle_portal_status_renders_html() -> None:
    """Happy path: valid token + GET /portal/<token> → 200 + HTML
    that contains the case number."""
    verified = _mk_verified(case_number="V-87654", client_name="Test Person")
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test",
            body_bytes=b"", headers={},
        )
    assert code == 200
    assert headers["Content-Type"].startswith("text/html")
    assert b"V-87654" in body
    assert b"Test Person" in body


def test_handle_portal_sign_form_rejects_short_name() -> None:
    """POST /portal/<token>/sign with name='Al' → re-renders the
    sign form with an error message, not a signature row."""
    verified = _mk_verified()
    form = urllib.parse.urlencode({"signature_name": "Al", "agree": "on"})
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch("recupero.portal.server._persist_signature") as persist:
        code, body, _ = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={"user-agent": "test"},
        )
    assert code == 200  # re-renders form, not 4xx
    assert b"full legal name" in body
    persist.assert_not_called()


def test_handle_portal_sign_form_rejects_missing_checkbox() -> None:
    """No 'agree=on' in the POST → reject."""
    verified = _mk_verified()
    form = urllib.parse.urlencode({"signature_name": "Alex Smith"})  # no agree
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch("recupero.portal.server._persist_signature") as persist:
        code, _, _ = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={},
        )
    assert code == 200
    persist.assert_not_called()


def test_handle_portal_sign_submit_redirects_if_already_engaged() -> None:
    """If engagement_started_at is set + closed_at is None, the
    customer is already engaged — POSTing /sign should redirect
    to the status page, NOT create a duplicate engagement_signatures
    row."""
    verified = _mk_verified(
        engagement_started_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    form = urllib.parse.urlencode({
        "signature_name": "Alex Smith", "agree": "on",
    })
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch("recupero.portal.server._persist_signature") as persist:
        code, _, headers = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={},
        )
    assert code == 303
    assert "Location" in headers
    persist.assert_not_called()


def test_handle_portal_sign_submit_happy_path() -> None:
    """Valid POST → calls _persist_signature with the captured
    name + fee + IP + UA, then renders the 'you're engaged' page."""
    verified = _mk_verified()
    form = urllib.parse.urlencode({
        "signature_name": "Alex Q. Smith", "agree": "on",
    })
    signed_at = datetime.now(timezone.utc)
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch("recupero.portal.server._persist_signature",
               return_value=signed_at) as persist:
        code, body, _ = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={
                "x-forwarded-for": "203.0.113.5, 10.0.0.1",
                "user-agent": "Mozilla/5.0",
            },
        )
    assert code == 200
    assert b"engaged" in body.lower()
    persist.assert_called_once()
    kwargs = persist.call_args.kwargs
    assert kwargs["signature_name"] == "Alex Q. Smith"
    # Fee comes from the fixture's quoted_fee_usd; the signature
    # form passes it through verbatim.
    assert kwargs["fee_usd"] == Decimal("10000")
    # Only the first IP from X-Forwarded-For is recorded.
    assert kwargs["ip_address"] == "203.0.113.5"
    assert kwargs["user_agent"] == "Mozilla/5.0"


def test_handle_portal_artifact_rejects_unknown_key() -> None:
    """Whitelist enforcement: GET /portal/<token>/artifact/foo with
    foo not in _PORTAL_ARTIFACTS → 404. Stops us from being tricked
    into signing arbitrary bucket paths."""
    verified = _mk_verified()
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, _, _ = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/artifact/etc-passwd",
            body_bytes=b"", headers={},
        )
    assert code == 404


def test_handle_portal_artifact_404_when_no_investigation() -> None:
    """A case with no investigation row can't have artifacts —
    return 404 with a helpful message."""
    verified = _mk_verified(investigation_id=None)
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"):
        code, body, _ = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/artifact/engagement_letter",
            body_bytes=b"", headers={},
        )
    assert code == 404
