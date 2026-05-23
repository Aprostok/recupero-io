"""Adversarial tests for src/recupero/portal/intake_notifications.py.

Hunt targets (v0.25.x post-intake confirmation path):

1. Malformed victim email — must fail BEFORE token-mint so we don't
   leave an orphan portal token in case_tokens that nobody received.
2. CRLF / bidi / zero-width in subject built from intake fields
   (case_number flows verbatim into the subject string). send_email
   sanitizes at the boundary, but we assert the contract here so a
   regression where send_email's sanitizer is bypassed (or someone
   wires a different transport) gets caught.
3. Bidi / zero-width in client_name flowing into HTML body — must
   not produce raw control glyphs in the rendered HTML (operators
   reviewing copy of the email shouldn't see right-to-left override
   spoofing the display).
4. Idempotency — calling send_intake_confirmation twice for the same
   investigation_id must NOT mint two portal tokens + send two
   confirmation emails. Stripe webhooks retry on transient failure;
   the post-commit side-effect block is not protected by the
   dispatcher's payment-row UNIQUE constraint, so a retry after a
   successful first send is a real production path.

These are RED tests — they document the bug before the fix lands.
After the fix in intake_notifications.py they go GREEN.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import UUID

from recupero.portal.intake_notifications import send_intake_confirmation

CASE_ID = UUID("11111111-1111-1111-1111-111111111111")
INV_ID = UUID("22222222-2222-2222-2222-222222222222")
TOKEN_ID = UUID("33333333-3333-3333-3333-333333333333")


def _stub_db_with_case_row(row):
    """Stub db_connect: one cursor.fetchone() returns ``row``."""

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchone(self): return row
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    return _StubConn()


# ───── 1. malformed victim email — fail before token-mint ─────


def test_malformed_client_email_does_not_mint_portal_token():
    """A poisoned client_email (CRLF smuggle) must NOT cause us to
    mint a portal token. The token is a bearer credential — minting
    it before validating the recipient address means a failed-send
    leaves an orphan token in case_tokens that an attacker who can
    scrape DB rows / logs can replay.

    The function should validate the recipient FIRST and short-circuit.
    """
    poisoned = "victim@example.com\r\nBcc: leak@evil.com"
    stub_conn = _stub_db_with_case_row(
        (poisoned, "Jane Doe", "RCP-INTAKE-abc"),
    )

    generate_mock = MagicMock(
        return_value=(TOKEN_ID, "tok-xyz", None),
    )

    with patch(
        "recupero._common.db_connect", return_value=stub_conn,
    ), patch(
        "recupero.portal.tokens.generate_token", generate_mock,
    ), patch(
        "recupero.portal.tokens.public_portal_url",
        return_value="https://recupero.io/portal/tok-xyz",
    ), patch("recupero.worker._email.send_email") as send_mock:
        result = send_intake_confirmation(
            case_id=CASE_ID, investigation_id=INV_ID,
            dsn="postgres://fake",
        )

    assert result.success is False, (
        "CRLF in client_email must be rejected before any side effect"
    )
    assert generate_mock.call_count == 0, (
        f"portal token minted for invalid recipient "
        f"(call_count={generate_mock.call_count}) — orphan-token leak"
    )
    assert send_mock.call_count == 0, (
        "send_email called with smuggled CRLF address"
    )


# ───── 2. CRLF in case_number must not survive into subject ─────


def test_crlf_in_case_number_does_not_reach_subject_header():
    """case_number is read from the DB and concatenated into the
    subject ``f"Recupero — Case {case_number} received..."``. If a
    poisoned case_number ever slips into the DB (eg via a future
    intake form that allows operator-edited case identifiers), CRLF
    in it would smuggle headers. We assert send_email receives a
    subject with no CR/LF.
    """
    poisoned_case = "RCP-123\r\nBcc: leak@evil.com"
    stub_conn = _stub_db_with_case_row(
        ("victim@example.com", "Jane", poisoned_case),
    )
    fake_email_result = type(
        "FakeResult", (),
        {"success": True, "message_id": "msg-1",
         "error": None, "skipped": False},
    )()

    with patch(
        "recupero._common.db_connect", return_value=stub_conn,
    ), patch(
        "recupero.worker._email.has_been_sent", return_value=False,
    ), patch(
        "recupero.portal.tokens.generate_token",
        return_value=(TOKEN_ID, "tok", None),
    ), patch(
        "recupero.portal.tokens.public_portal_url",
        return_value="https://recupero.io/portal/tok",
    ), patch(
        "recupero.worker._email.send_email",
        return_value=fake_email_result,
    ) as send_mock:
        send_intake_confirmation(
            case_id=CASE_ID, investigation_id=INV_ID,
            dsn="postgres://fake",
        )

    assert send_mock.call_count == 1
    subject_arg = send_mock.call_args.kwargs["subject"]
    assert "\r" not in subject_arg and "\n" not in subject_arg, (
        f"CRLF survived into subject: {subject_arg!r}"
    )
    assert "Bcc:" not in subject_arg, (
        "smuggled Bcc header fragment in subject"
    )


# ───── 3. bidi / zero-width in client_name must not raw-glyph the HTML ─


def test_bidi_and_zero_width_in_client_name_sanitized_in_html():
    """A right-to-left override (U+202E) or zero-width space (U+200B)
    in client_name renders invisibly / spoofs direction in operator
    email clients reviewing CC'd copies. We require the rendered HTML
    to NOT contain a raw RLO / ZWSP glyph — either stripped or HTML
    entity-encoded is acceptable.
    """
    poisoned_name = "Jane‮evil​Doe"
    stub_conn = _stub_db_with_case_row(
        ("victim@example.com", poisoned_name, "RCP-abc"),
    )
    fake_email_result = type(
        "FakeResult", (),
        {"success": True, "message_id": "m",
         "error": None, "skipped": False},
    )()

    captured_html = {}

    def _capture(**kw):
        captured_html["html"] = kw["html"]
        return fake_email_result

    with patch(
        "recupero._common.db_connect", return_value=stub_conn,
    ), patch(
        "recupero.worker._email.has_been_sent", return_value=False,
    ), patch(
        "recupero.portal.tokens.generate_token",
        return_value=(TOKEN_ID, "tok", None),
    ), patch(
        "recupero.portal.tokens.public_portal_url",
        return_value="https://recupero.io/portal/tok",
    ), patch(
        "recupero.worker._email.send_email", side_effect=_capture,
    ):
        send_intake_confirmation(
            case_id=CASE_ID, investigation_id=INV_ID,
            dsn="postgres://fake",
        )

    html_body = captured_html["html"]
    assert "‮" not in html_body, (
        "raw RLO (U+202E) survived into rendered HTML body"
    )
    assert "​" not in html_body, (
        "raw zero-width space (U+200B) survived into rendered HTML body"
    )


# ───── 4. idempotency — second call must NOT mint a 2nd token+email ─


def test_double_invocation_does_not_send_two_confirmations():
    """Stripe webhook retries are a real production path. If the
    dispatcher's post-commit block runs twice for the same
    investigation_id, send_intake_confirmation must NOT mint a
    second portal token AND must NOT send a second email.

    Implementation guidance: gate on
    recupero.worker._email.has_been_sent(investigation_id, "intake_confirmation")
    BEFORE the token-mint step. Already-sent → return success=True,
    email_sent=False, no side effects.
    """
    stub_conn = _stub_db_with_case_row(
        ("victim@example.com", "Jane Doe", "RCP-INTAKE-abc"),
    )
    fake_email_result = type(
        "FakeResult", (),
        {"success": True, "message_id": "msg",
         "error": None, "skipped": False},
    )()

    generate_mock = MagicMock(
        return_value=(TOKEN_ID, "tok-xyz", None),
    )
    # First call: nothing sent yet. Second call: already-sent row exists.
    has_been_sent_mock = MagicMock(side_effect=[False, True])

    with patch(
        "recupero._common.db_connect", return_value=stub_conn,
    ), patch(
        "recupero.portal.tokens.generate_token", generate_mock,
    ), patch(
        "recupero.portal.tokens.public_portal_url",
        return_value="https://recupero.io/portal/tok-xyz",
    ), patch(
        "recupero.worker._email.send_email",
        return_value=fake_email_result,
    ) as send_mock, patch(
        "recupero.worker._email.has_been_sent", has_been_sent_mock,
    ):
        r1 = send_intake_confirmation(
            case_id=CASE_ID, investigation_id=INV_ID,
            dsn="postgres://fake",
        )
        r2 = send_intake_confirmation(
            case_id=CASE_ID, investigation_id=INV_ID,
            dsn="postgres://fake",
        )

    assert r1.success is True and r1.email_sent is True
    assert r2.success is True, (
        "second invocation should return a clean idempotent success"
    )
    assert r2.email_sent is False, (
        "second invocation re-sent the confirmation email — Stripe "
        "webhook retry would double-confirm the victim"
    )
    assert send_mock.call_count == 1, (
        f"send_email called {send_mock.call_count} times across two "
        "invocations — idempotency check missing"
    )
    assert generate_mock.call_count == 1, (
        f"portal token minted {generate_mock.call_count} times — "
        "orphan token left in case_tokens on every webhook retry"
    )


# ───── 5. idempotency check failure must not crash the function ─


def test_idempotency_check_crash_does_not_crash_confirmation():
    """If has_been_sent itself raises (DB blip), the function must
    still return a structured result. Fail-CLOSED on the audit query
    (treat as already-sent) is the safer default — see the
    fail-closed precedent in worker/_email.has_been_sent's docstring.
    """
    stub_conn = _stub_db_with_case_row(
        ("victim@example.com", "Jane", "RCP-abc"),
    )

    with patch(
        "recupero._common.db_connect", return_value=stub_conn,
    ), patch(
        "recupero.worker._email.has_been_sent",
        side_effect=RuntimeError("simulated DB blip"),
    ), patch(
        "recupero.portal.tokens.generate_token",
        return_value=(TOKEN_ID, "tok", None),
    ), patch(
        "recupero.portal.tokens.public_portal_url",
        return_value="https://recupero.io/portal/tok",
    ), patch("recupero.worker._email.send_email") as send_mock:
        # Must not raise. Either fails closed (no send) or proceeds —
        # either is acceptable, but no exception.
        result = send_intake_confirmation(
            case_id=CASE_ID, investigation_id=INV_ID,
            dsn="postgres://fake",
        )

    # We don't assert a specific outcome — only that the function
    # returns a structured result. The whole point of
    # IntakeConfirmationResult is "never raises".
    assert result is not None
    assert hasattr(result, "success")
    _ = send_mock  # may or may not have been called depending on policy
