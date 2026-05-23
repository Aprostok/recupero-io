"""RFC 5322 / 5321 address-shape rejection tests.

The codebase doesn't carry an `email-validator` dependency, so the
canonical helper ``_validate_email_address`` rolls a strict regex.
Strictness is deliberate: we never see quoted local parts, IP
literal hosts, or comments in legitimate victim / law-firm /
issuer addresses, but every one of those shapes is an attacker's
way to smuggle data past naïve parsers (the URL parser disagrees
with the auth check, etc.).

These tests pin the policy:

  * accept the boring ``local@host.tld`` shape with the usual
    punctuation in the local-part,
  * reject quoted local parts, IP literals, multi-@, CRLF /
    bidi inside, length > 254 (RFC 3696 ceiling), TLD < 2,
  * reject the empty string and None.

If a future change loosens the validator (e.g. adopts
``email-validator``), update the rejections list with intent —
don't silently regress the strict shape.
"""

from __future__ import annotations

import pytest

from recupero.worker._email import _validate_email_address


# ---- Accept: the boring legitimate shapes ---- #


@pytest.mark.parametrize("addr", [
    "alec@recupero.io",
    "compliance@recupero.io",
    "ops+alerts@example.com",          # plus-addressing
    "first.last@example.co.uk",        # multi-label TLD
    "a@b.io",                          # short local + 2-char TLD
    "victim_123@bank-corp.net",        # underscore + hyphen
    "Test.Email@Example.COM",          # mixed case
    "x" * 60 + "@example.com",         # local-part near 64
])
def test_validator_accepts_legitimate_addresses(addr) -> None:
    assert _validate_email_address(addr) is True, addr


# ---- Reject: shape-level malformations ---- #


@pytest.mark.parametrize("addr", [
    None,                              # null
    "",                                # empty
    "no-at-sign",                      # no @
    "@host.com",                       # empty local
    "alec@",                           # empty host
    "alec@@example.com",               # double @
    "alec@example",                    # no TLD
    "alec@example.",                   # trailing dot
    "alec@.example.com",               # leading dot label
    "alec@example..com",               # empty label
    "alec@example.c",                  # 1-char TLD
    "alec@-example.com",               # leading hyphen on label
    "alec@example-.com",               # trailing hyphen on label
    # IPv4 literal — legal per RFC 5321 §4.1.3 but never seen on
    # legitimate inbound; classic smuggle target for label confusion
    # between URL parser and SMTP parser.
    "alec@[192.168.1.1]",
    # IPv6 literal — same reasoning
    "alec@[IPv6:::1]",
    # Quoted local part (legal RFC 5321 §4.1.2) — never in real
    # data, classic confusion vector ("a@b"@c.com)
    '"a@b"@c.com',
    "\"a b\"@c.com",
    # Comment (legal RFC 5322 §3.2.3) — never in real data
    "alec(comment)@example.com",
])
def test_validator_rejects_malformed(addr) -> None:
    assert _validate_email_address(addr) is False, repr(addr)


# ---- Reject: control / injection chars inside an address ---- #


@pytest.mark.parametrize("addr", [
    "alec@example.com\r\nBcc: leak@evil.com",
    "alec\r\n@example.com",
    "alec@example.com\n",
    "alec@example.com\r",
    "alec@example.com\x00",                       # NUL
    "alec\nb@example.com",                        # bare \n smuggle
    "alec@example.com\x0b",                       # VT
    "alec@example.com\x0c",                       # FF
    "alec@example.com ",                          # trailing whitespace
    " alec@example.com",                          # leading whitespace
    "alec @example.com",                          # interior space
    "alec@exa mple.com",                          # interior space in host
    "alec‮@example.com",                     # bidi RLO
    "alec⁦@example.com",                     # bidi LRI
])
def test_validator_rejects_control_and_injection_chars(addr) -> None:
    assert _validate_email_address(addr) is False, repr(addr)


# ---- Reject: length ceilings ---- #


def test_validator_rejects_overlong_total_address() -> None:
    """RFC 3696 §3 caps a full email address at 254 octets.
    Anything longer is unroutable and a fingerprint of a buffer
    overflow probe."""
    long_local = "x" * 250
    addr = f"{long_local}@example.com"  # > 254 total
    assert len(addr) > 254
    assert _validate_email_address(addr) is False


def test_validator_rejects_overlong_local_part() -> None:
    """RFC 5321 §4.5.3.1.1 caps the local-part at 64 octets."""
    addr = ("x" * 65) + "@example.com"
    assert _validate_email_address(addr) is False


# ---- Type safety ---- #


@pytest.mark.parametrize("bad_type", [12345, 12.5, ["a@b.com"], {"a": "b"}, True])
def test_validator_rejects_non_string_types(bad_type) -> None:
    """An accidental pass of a list / int (e.g. from an unwrapped
    DB row or a kwarg-collision bug) must NOT pass validation; the
    helper returns False rather than raising so the caller's audit
    log captures the rejection."""
    assert _validate_email_address(bad_type) is False  # type: ignore[arg-type]


# ---- Cross-check: the digest_email SMTP path validates too ---- #


def test_digest_email_recipients_validated(monkeypatch) -> None:
    """RECUPERO_DIGEST_RECIPIENTS is parsed comma-separated. A
    poisoned entry must be DROPPED (not raise, not silently passed
    to EmailMessage which would crash on \\n in a header)."""
    from recupero.worker import digest_email

    monkeypatch.setenv(
        "RECUPERO_DIGEST_RECIPIENTS",
        "ok@example.com,bad\r\nBcc: leak@evil.com,also-ok@example.com",
    )
    monkeypatch.setenv("RECUPERO_DIGEST_ALWAYS_SEND", "1")
    monkeypatch.setenv("RECUPERO_SMTP_HOST", "smtp.test")
    monkeypatch.setenv("RECUPERO_SMTP_USER", "u")
    monkeypatch.setenv("RECUPERO_SMTP_PASSWORD", "p")

    captured = {}
    class FakeSMTP:
        def __init__(self, *a, **kw): captured["init"] = (a, kw)
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def ehlo(self): pass
        def starttls(self): pass
        def login(self, *_): pass
        def send_message(self, msg): captured["msg"] = msg

    monkeypatch.setattr(digest_email.smtplib, "SMTP", FakeSMTP)

    # Use a non-existent html path to short-circuit the alternative-
    # part read; the function logs WARN and continues.
    from pathlib import Path
    sent = digest_email.maybe_send_digest_email(
        html_path=Path("/no/such/file.html"),
        pdf_path=None,
        digest_id="d1",
        material_count=1,
        freezeable_count=0,
        total_outflow_usd="$0",
        tick_date="2025-01-01",
    )
    assert sent is True
    to_header = captured["msg"]["To"]
    assert "ok@example.com" in to_header
    assert "also-ok@example.com" in to_header
    assert "leak@evil.com" not in to_header
    assert "Bcc:" not in to_header
    assert "\r" not in to_header
    assert "\n" not in to_header


def test_digest_email_no_valid_recipients_skips(monkeypatch) -> None:
    """All recipients invalid → digest skipped, no SMTP connection."""
    from recupero.worker import digest_email

    monkeypatch.setenv("RECUPERO_DIGEST_RECIPIENTS",
                       "bad\r\nBcc: leak@evil.com,also-bad@@example.com")
    monkeypatch.setenv("RECUPERO_DIGEST_ALWAYS_SEND", "1")
    monkeypatch.setenv("RECUPERO_SMTP_HOST", "smtp.test")
    monkeypatch.setenv("RECUPERO_SMTP_USER", "u")
    monkeypatch.setenv("RECUPERO_SMTP_PASSWORD", "p")

    called = {"smtp": 0}
    class ExplodingSMTP:
        def __init__(self, *_a, **_kw):
            called["smtp"] += 1
            raise AssertionError("SMTP opened despite no valid recipients")
    monkeypatch.setattr(digest_email.smtplib, "SMTP", ExplodingSMTP)

    from pathlib import Path
    sent = digest_email.maybe_send_digest_email(
        html_path=Path("/no/such/file.html"),
        pdf_path=None,
        digest_id="d1",
        material_count=1,
        freezeable_count=0,
        total_outflow_usd="$0",
        tick_date="2025-01-01",
    )
    assert sent is False
    assert called["smtp"] == 0
