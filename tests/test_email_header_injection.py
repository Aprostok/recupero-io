"""Adversarial-input tests for SMTP / Resend header injection.

The Resend HTTP API takes a JSON body; Resend's MTA then translates
those fields into MIME headers on the way out. A CRLF in a "subject"
string therefore becomes a literal `\\r\\n` between two header lines
on the wire — an attacker who controls any payload-derived value
(counterparty label, asset symbol, issuer name) can inject arbitrary
headers (``Bcc:``, ``X-Forge:``, second ``To:``) unless the sender
strips CR / LF / NUL before handing the value to the API.

These tests exercise the canonical sanitizer (``_sanitize_email_header``)
+ the end-to-end ``send_email`` path with malicious subject / cc /
bcc / display-name inputs, asserting:

  * sanitization NEVER leaks CR / LF / NUL into the outbound JSON body,
  * each attack class is documented next to the test that fires it,
  * existing legitimate inputs (UTF-8 subjects, long-but-bounded
    issuer names, real freeze-letter subjects) round-trip unchanged.

The Resend HTTP call is mocked so the tests run offline.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from recupero.worker._email import (
    _sanitize_email_header,
    _validate_email_address,
    send_email,
)


# ---- _sanitize_email_header: pure-function attack matrix ---- #


@pytest.mark.parametrize(
    "payload",
    [
        # Classic CRLF Bcc smuggle
        "Recupero Update\r\nBcc: leak@evil.com",
        "Recupero Update\nBcc: leak@evil.com",
        "Recupero Update\rBcc: leak@evil.com",
        # Encoded forms (some HTTP layers decode these; defense in depth)
        "Recupero Update\r\nX-Forge: 1\r\n",
        # NUL terminator smuggle — some MTAs treat NUL as end-of-header
        "Recupero\x00Bcc: leak@evil.com",
        # Vertical tab / form feed — RFC 5322 §2.1.1 treats these as
        # line separators on some MTAs
        "Recupero\x0bBcc: leak@evil.com",
        "Recupero\x0cBcc: leak@evil.com",
        # Bidi RLO can hide a fake "From:" in the display
        "‮Recupero ecivreS",
        # LRE / RLE
        "‪Recupero",
        "‫Recupero",
        # PDF (pop directional formatting)
        "Recupero‬",
        # Bidi isolates U+2066..U+2069 — Outlook + Apple Mail render
        "⁦Recupero⁩",
    ],
)
def test_sanitize_strips_all_injection_classes(payload) -> None:
    """For every attack-class payload, the sanitizer output must be
    free of CR / LF / NUL / VT / FF / bidi controls. The check is on
    the OUTPUT (not whether the input was rejected) — the function is
    a strip, not a validator, so legitimate prefixes survive."""
    out = _sanitize_email_header(payload)
    for forbidden in ("\r", "\n", "\x00", "\x0b", "\x0c"):
        assert forbidden not in out, (
            f"sanitizer leaked {forbidden!r} from payload {payload!r}: out={out!r}"
        )
    # Bidi control codepoints
    for cp in (
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
        0x2066, 0x2067, 0x2068, 0x2069,
    ):
        assert chr(cp) not in out, (
            f"sanitizer leaked U+{cp:04X} from {payload!r}: out={out!r}"
        )


def test_sanitize_preserves_legitimate_subject() -> None:
    """A normal freeze-letter subject must round-trip unchanged."""
    s = "Compliance Freeze Request — Case 12345678: USDT at $42,000 recoverable"
    assert _sanitize_email_header(s) == s


def test_sanitize_handles_none() -> None:
    """None → empty string. Never raises."""
    assert _sanitize_email_header(None) == ""


def test_sanitize_caps_length_at_998() -> None:
    """RFC 5322 §2.1.1 caps a header line at 998 octets excluding CRLF.
    A 10KB subject has crashed real MTAs (Postfix < 3.4 silently
    drops, sendmail throws). We cap at 800 to leave room for folding +
    encoded-word overhead."""
    monster = "X" * 10_000
    out = _sanitize_email_header(monster)
    assert len(out) <= 998
    assert len(out) <= 800  # current cap


def test_sanitize_non_string_input() -> None:
    """Defensive coercion: int / UUID / dataclass field reach here
    via a code path that should have stringified upstream, but the
    sanitizer must not crash on the bad-call shape."""
    assert _sanitize_email_header(12345) == "12345"


# ---- send_email: end-to-end header-injection guard ---- #


def _fake_urlopen_capturing(captured: dict):
    """Build a urlopen stub that records the JSON body for inspection."""
    def fake_urlopen(req, **_):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        class FakeResp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self):
                return json.dumps({"id": "msg_test"}).encode("utf-8")
        return FakeResp()
    return fake_urlopen


def test_send_email_strips_crlf_from_subject(monkeypatch) -> None:
    """A poisoned counterparty_label flowing into a freeze-letter
    subject (e.g. via a regressed on-chain label DB row) must be
    sanitized to plain text before it reaches the JSON body — Resend
    would otherwise translate the CRLF into a second header line."""
    monkeypatch.setenv("RESEND_API_KEY", "test")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    captured: dict = {}
    with patch(
        "recupero.worker._email.urllib.request.urlopen",
        _fake_urlopen_capturing(captured),
    ), patch("recupero.worker._email._log_to_audit"):
        result = send_email(
            to="ok@example.com",
            subject="Freeze\r\nBcc: leak@evil.com",
            html="<p>body</p>",
            email_type="freeze_letter",
        )
    assert result.success
    assert "\r" not in captured["body"]["subject"]
    assert "\n" not in captured["body"]["subject"]
    assert "Bcc:" not in captured["body"]["subject"]


def test_send_email_rejects_crlf_in_recipient(monkeypatch) -> None:
    """`to="victim@bank.com\\r\\nBcc: leak@evil.com"` must be rejected
    BEFORE the Resend POST. Returning a clean failure means the
    caller (freeze_followup cron, intake_notifications) can roll back
    its claim instead of advancing pipeline state on an injected
    Bcc."""
    monkeypatch.setenv("RESEND_API_KEY", "test")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    called = {"n": 0}
    def should_not_be_called(*_a, **_kw):
        called["n"] += 1
        raise AssertionError("urlopen called with poisoned recipient")
    with patch(
        "recupero.worker._email.urllib.request.urlopen",
        should_not_be_called,
    ), patch("recupero.worker._email._log_to_audit"):
        result = send_email(
            to="victim@bank.com\r\nBcc: leak@evil.com",
            subject="ok",
            html="<p>body</p>",
            email_type="freeze_letter",
        )
    assert result.success is False
    assert "invalid recipient" in (result.error or "")
    assert called["n"] == 0


def test_send_email_drops_invalid_cc_bcc(monkeypatch) -> None:
    """An attacker can't smuggle a Bcc via the cc/bcc lists either —
    addresses that fail the regex are silently DROPPED (better to
    lose a cc than leak a copy to the attacker)."""
    monkeypatch.setenv("RESEND_API_KEY", "test")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    captured: dict = {}
    with patch(
        "recupero.worker._email.urllib.request.urlopen",
        _fake_urlopen_capturing(captured),
    ), patch("recupero.worker._email._log_to_audit"):
        result = send_email(
            to="ok@example.com",
            subject="ok",
            html="<p>body</p>",
            email_type="le_handoff",
            cc=[
                "real-cc@example.com",
                "leak@evil.com\r\nBcc: deeper@evil.com",  # poisoned
                "not-an-email",                              # invalid
            ],
            bcc=["valid-bcc@example.com", "\r\nX-Forge: 1"],
        )
    assert result.success
    assert captured["body"]["cc"] == ["real-cc@example.com"]
    assert captured["body"]["bcc"] == ["valid-bcc@example.com"]


def test_send_email_long_subject_capped(monkeypatch) -> None:
    """10KB subject lines crash some MTAs. The sender caps the
    serialized subject well under RFC 5322's 998-octet line limit."""
    monkeypatch.setenv("RESEND_API_KEY", "test")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    captured: dict = {}
    with patch(
        "recupero.worker._email.urllib.request.urlopen",
        _fake_urlopen_capturing(captured),
    ), patch("recupero.worker._email._log_to_audit"):
        send_email(
            to="ok@example.com",
            subject="A" * 10_000,
            html="<p>x</p>",
            email_type="ops_alert",
        )
    assert len(captured["body"]["subject"]) <= 998


def test_send_email_from_name_at_sign_strips_display_name(monkeypatch) -> None:
    """From-spoofing class: an attacker controlling the display name
    can place ``victim@bank.com`` as the name; most email clients
    render only the name, so the recipient sees an apparent From of
    their bank. Sender drops the display name when it contains an
    ``@`` — better to deliver from an angle-wrapped raw address than
    spoof the visual chrome."""
    monkeypatch.setenv("RESEND_API_KEY", "test")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    captured: dict = {}
    with patch(
        "recupero.worker._email.urllib.request.urlopen",
        _fake_urlopen_capturing(captured),
    ), patch("recupero.worker._email._log_to_audit"):
        send_email(
            to="ok@example.com",
            subject="ok",
            html="<p>x</p>",
            email_type="victim_summary",
            from_addr="real@recupero.io",
            from_name="victim@bank.com",  # spoof attempt
        )
    from_field = captured["body"]["from"]
    assert "victim@bank.com" not in from_field.split("<")[0]


def test_send_email_from_name_with_bidi_stripped(monkeypatch) -> None:
    """A bidi RLO in the display name can make ``moc.kreper@evil``
    render as ``live@reper.com`` in a recipient's client. Sanitize
    these out of the name before they hit the wire."""
    monkeypatch.setenv("RESEND_API_KEY", "test")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    captured: dict = {}
    with patch(
        "recupero.worker._email.urllib.request.urlopen",
        _fake_urlopen_capturing(captured),
    ), patch("recupero.worker._email._log_to_audit"):
        send_email(
            to="ok@example.com",
            subject="ok",
            html="<p>x</p>",
            email_type="victim_summary",
            from_addr="real@recupero.io",
            from_name="Recupero‮evil",
        )
    from_field = captured["body"]["from"]
    assert "‮" not in from_field
    for cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
               0x2066, 0x2067, 0x2068, 0x2069):
        assert chr(cp) not in from_field


def test_send_email_crlf_in_from_env(monkeypatch) -> None:
    """RECUPERO_EMAIL_FROM is operator-set, but if it's pulled from a
    secrets manager that allows newlines, a stray CRLF must not
    inject a Bcc into every email the worker sends."""
    monkeypatch.setenv("RESEND_API_KEY", "test")
    monkeypatch.setenv("RECUPERO_EMAIL_FROM", "ops@recupero.io\r\nBcc: leak@evil.com")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    captured: dict = {}
    with patch(
        "recupero.worker._email.urllib.request.urlopen",
        _fake_urlopen_capturing(captured),
    ), patch("recupero.worker._email._log_to_audit"):
        send_email(
            to="ok@example.com", subject="ok",
            html="<p>x</p>", email_type="ops_alert",
        )
    from_field = captured["body"]["from"]
    assert "\r" not in from_field
    assert "\n" not in from_field
    assert "Bcc:" not in from_field


def test_validator_helper_smoke() -> None:
    """Quick sanity check that the validator is exposed + works.
    Detailed semantics live in test_email_rfc5322_validation.py."""
    assert _validate_email_address("alec@recupero.io")
    assert not _validate_email_address("alec@recupero.io\r\nBcc: x@y.com")
    assert not _validate_email_address("")
    assert not _validate_email_address(None)
