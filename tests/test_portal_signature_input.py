"""RIGOR-Jacob Z2 regression tests for adversarial input handling in
the portal's /sign POST submission path.

Two concrete bugs covered here:

  Z2-1 (Unicode bidi trojans in signature_name) — pre-fix, a victim
  could sign as ``Smith‮nimdA`` (with RIGHT-TO-LEFT OVERRIDE).
  The engagement_signatures.signature_name column stored the bytes
  verbatim. Any operator/lawyer/auditor viewing the row in an
  admin UI saw the rendered glyphs as ``SmithAdmin``, undermining
  the legal-defensibility claim made on /sign ("Your IP address
  will be recorded for audit purposes"). The intake module already
  rejects this attack class via recupero.portal.intake._reject_unicode_trojans;
  the /sign POST path was missed.

  Z2-2 (CR/LF/NUL in signature_name) — pre-fix, a POST with
  ``signature_name=Alex%0d%0aFAKE-AUDIT-LINE`` stored a literal
  CR/LF in the DB column. The bytes survive into operator views
  (worker logs, admin export) and forge a legitimate-looking
  second line in the audit trail. Same attack family as the
  v0.16.7 user-agent CRLF strip — signature_name was missed.

  More concretely: a ``%00`` byte in signature_name causes psycopg
  to raise ``A string literal cannot contain NUL (0x00) characters``
  mid-transaction, breaking the engagement flow entirely. Free
  500-error for a determined attacker.

Both bugs are fixed by adding ``_reject_unicode_trojans`` rejection
+ ``_strip_control_chars`` sanitation to the signature_name path,
mirroring the existing intake.py + user-agent handling.
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


@pytest.mark.parametrize("trojan_char,description", [
    ("‮", "RIGHT-TO-LEFT OVERRIDE — bidi display spoof (CVE-2021-42574)"),
    ("‭", "LEFT-TO-RIGHT OVERRIDE"),
    ("⁦", "LEFT-TO-RIGHT ISOLATE"),
    ("⁧", "RIGHT-TO-LEFT ISOLATE"),
    ("​", "ZERO-WIDTH SPACE"),
    ("‌", "ZERO-WIDTH NON-JOINER"),
    ("‍", "ZERO-WIDTH JOINER"),
    ("﻿", "BYTE-ORDER MARK"),
    ("‎", "LEFT-TO-RIGHT MARK"),
    ("‏", "RIGHT-TO-LEFT MARK"),
])
def test_signature_name_rejects_unicode_trojans(
    trojan_char: str, description: str,
) -> None:
    """RIGOR-Jacob Z2-1: bidi overrides + zero-width + BOM in
    signature_name must be rejected at the form-validation stage,
    BEFORE _persist_signature writes the row to engagement_signatures.

    Pre-fix, the only validators were length (3-200 chars) and the
    'agree' checkbox. A name like ``Smith‮nimdA`` (16 chars,
    agree=on) sailed through to the DB. Operator views rendered
    it as ``SmithAdmin``.

    Post-fix the handler returns the sign form with a Unicode-
    hidden-char error, mirroring intake.py's behavior.
    """
    verified = _mk_verified()
    poisoned_name = f"Alex{trojan_char}Q. Smith"
    form = urllib.parse.urlencode(
        {"signature_name": poisoned_name, "agree": "on"}
    )
    with patch(
        "recupero.portal.server.verify_token", return_value=verified
    ), patch(
        "recupero.portal.server._get_dsn", return_value="fake-dsn"
    ), patch(
        "recupero.portal.server._persist_signature"
    ) as persist:
        code, body, _ = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={**_SAME_ORIGIN_HEADERS, "user-agent": "test"},
        )
    # MUST NOT call _persist_signature — the trojan must be
    # stopped at validation, not laundered into the DB.
    persist.assert_not_called(), (
        f"signature_name with {description!r} reached _persist_signature; "
        "should have been rejected at validation"
    )
    # Re-render the form (200) with an error message rather than 4xx
    # — matches the existing "short name / missing checkbox" behavior.
    assert code == 200
    assert b"hidden character" in body or b"invalid" in body.lower()


def test_signature_name_rejects_crlf_injection() -> None:
    """RIGOR-Jacob Z2-2: CR/LF in signature_name must be stripped or
    rejected before storage.

    Pre-fix, ``signature_name=Alex Smith\\r\\nFAKE-AUDIT-LINE`` would
    persist a multi-line string into engagement_signatures.signature_name.
    The bytes survive into operator views (admin UI, CSV exports,
    worker logs) where each CR/LF starts a fresh visual line —
    forging a legitimate-looking second audit entry under a real
    signature row.

    Same attack family as the v0.16.7 user-agent CRLF strip — the
    fix for user_agent landed but signature_name was missed.
    """
    verified = _mk_verified()
    poisoned = "Alex Smith\r\nFAKE-AUDIT-LINE: case approved"
    form = urllib.parse.urlencode(
        {"signature_name": poisoned, "agree": "on"}
    )
    signed_at = datetime.now(UTC)
    with patch(
        "recupero.portal.server.verify_token", return_value=verified
    ), patch(
        "recupero.portal.server._get_dsn", return_value="fake-dsn"
    ), patch(
        "recupero.portal.server._persist_signature",
        return_value=signed_at,
    ) as persist, patch(
        "recupero.portal.tokens.revoke_token", return_value=True
    ):
        code, _body, _ = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={**_SAME_ORIGIN_HEADERS, "user-agent": "test"},
        )
    # Either the handler returns the form with an error (preferred —
    # the victim sees what went wrong) OR it sanitizes and proceeds.
    # Both close the bug; reject the path where the persisted name
    # contains literal CR/LF.
    if persist.call_count == 1:
        # Sanitize-and-proceed branch — name reaches the DB but
        # CR/LF must be stripped.
        kwargs = persist.call_args.kwargs
        stored = kwargs["signature_name"]
        assert "\r" not in stored, (
            f"signature_name reached _persist_signature with raw CR: {stored!r}"
        )
        assert "\n" not in stored, (
            f"signature_name reached _persist_signature with raw LF: {stored!r}"
        )
    else:
        # Reject-at-validation branch — never reaches persist.
        assert code == 200
        persist.assert_not_called()


def test_signature_name_rejects_nul_byte() -> None:
    """RIGOR-Jacob Z2-2 (NUL variant): a NUL byte (\\x00) in
    signature_name must be rejected or stripped BEFORE psycopg
    sees it. Pre-fix, the NUL byte propagated to the INSERT
    parameter and psycopg raised ``A string literal cannot
    contain NUL (0x00) characters`` mid-transaction, returning
    a generic 500 to the victim. Free DoS for any attacker
    holding a portal URL.
    """
    verified = _mk_verified()
    poisoned = "Alex\x00Q. Smith"  # 12 chars, passes length floor
    form_qs = (
        "signature_name="
        + urllib.parse.quote(poisoned, safe="")
        + "&agree=on"
    )
    signed_at = datetime.now(UTC)
    with patch(
        "recupero.portal.server.verify_token", return_value=verified
    ), patch(
        "recupero.portal.server._get_dsn", return_value="fake-dsn"
    ), patch(
        "recupero.portal.server._persist_signature",
        return_value=signed_at,
    ) as persist, patch(
        "recupero.portal.tokens.revoke_token", return_value=True
    ):
        code, _body, _ = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form_qs.encode("utf-8"),
            headers={**_SAME_ORIGIN_HEADERS, "user-agent": "test"},
        )
    # As with CRLF, allow EITHER reject-at-validation (preferred)
    # or sanitize-and-proceed. The bug-closing invariant is: no
    # NUL byte ever reaches psycopg.
    if persist.call_count == 1:
        kwargs = persist.call_args.kwargs
        stored = kwargs["signature_name"]
        assert "\x00" not in stored, (
            f"NUL byte reached _persist_signature in signature_name: "
            f"{stored!r} — would crash psycopg INSERT"
        )
    else:
        assert code == 200
        persist.assert_not_called()


def test_signature_name_happy_path_with_unicode_legit_name() -> None:
    """RIGOR-Jacob Z2-1 negative case: a legitimate non-ASCII name
    must still be accepted. We explicitly want to support names
    like 山田太郎 / Müller / O'Brien — the rejection rule targets
    invisible/bidi-spoofing code points only, not non-Latin
    scripts in general.
    """
    verified = _mk_verified()
    name = "山田太郎"  # CJK — perfectly legitimate legal name
    form = urllib.parse.urlencode({"signature_name": name, "agree": "on"})
    signed_at = datetime.now(UTC)
    with patch(
        "recupero.portal.server.verify_token", return_value=verified
    ), patch(
        "recupero.portal.server._get_dsn", return_value="fake-dsn"
    ), patch(
        "recupero.portal.server._persist_signature",
        return_value=signed_at,
    ) as persist, patch(
        "recupero.portal.tokens.revoke_token", return_value=True
    ):
        code, _body, _ = handle_portal(
            method="POST",
            path="/portal/some-43-char-valid-token-for-this-test/sign",
            body_bytes=form.encode("utf-8"),
            headers={**_SAME_ORIGIN_HEADERS, "user-agent": "test"},
        )
    assert code == 200
    persist.assert_called_once()
    kwargs = persist.call_args.kwargs
    assert kwargs["signature_name"] == name
