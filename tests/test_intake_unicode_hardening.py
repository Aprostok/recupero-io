"""RIGOR-Jacob E: Unicode-trap defenses for intake form fields.

The /v1/intake form is unauthenticated and the entered values flow
into:
  * cases.client_name → operator triage UI
  * cases.client_email → confirmation email + LE handoff "Victim"
  * cases.description → operator triage UI
  * Stripe Checkout metadata
  * Later: the LE handoff Section 1 ("Victim Profile")

Three concrete attack shapes that the current ``.strip()`` +
length-cap pre-check DOES NOT defend against:

  1. **Bidi / RTL override characters** (\\u202E, \\u202D, \\u2066,
     \\u2067, \\u2068, \\u2069). Standard ``str.strip()`` only
     removes ASCII whitespace, so a name like ``"Smith\\u202EnimdA"``
     passes validation and renders in viewers as ``"SmithAdmin"`` —
     a Trojan-Source-class display spoof (CVE-2021-42574).
  2. **Null bytes**. ``"admin\\x00"`` crashes Postgres TEXT inserts,
     but only AFTER the cases row partially commits and the Stripe
     Checkout URL has been generated. We'd leak a working payment
     link that points at a half-broken case.
  3. **Newline in email** (``"victim@x.y\\nBcc: attacker@x.y"``).
     Lands directly in confirmation-email headers via SMTP header
     injection if any sender library doesn't sanitize.

Lock the contract: each shape is rejected with
IntakeValidationError, NOT silently passed through to the DB.
"""

from __future__ import annotations

import pytest


def _good_form() -> dict[str, str]:
    return {
        "client_name": "Jane Smith",
        "client_email": "jane@example.com",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2026-01-15",
        "description": "Phishing attack drained my wallet.",
        "country": "US",
    }


@pytest.mark.parametrize("bidi_char", [
    "‮",  # RTL override
    "‭",  # LTR override
    "⁦",  # LTR isolate
    "⁧",  # RTL isolate
    "⁨",  # First-strong isolate
    "⁩",  # Pop directional isolate
    "‎",  # LTR mark (subtle)
    "‏",  # RTL mark
])
def test_bidi_control_in_client_name_rejected(bidi_char: str) -> None:
    """Trojan-Source / CVE-2021-42574. A name with bidi controls
    embedded renders ambiguously in viewers. Reject."""
    from recupero.portal.intake import (
        IntakeValidationError,
        validate_intake_payload,
    )

    form = _good_form()
    form["client_name"] = f"Smith{bidi_char}nimdA"
    with pytest.raises(IntakeValidationError) as exc_info:
        validate_intake_payload(form)
    assert exc_info.value.field == "client_name"


@pytest.mark.parametrize("bidi_char", ["‮", "⁦"])
def test_bidi_control_in_description_rejected(bidi_char: str) -> None:
    """Description is the largest free-text field. Bidi controls
    here are the highest-impact display spoof — operators reading
    triage UI would see misleading sentence direction."""
    from recupero.portal.intake import (
        IntakeValidationError,
        validate_intake_payload,
    )

    form = _good_form()
    form["description"] = f"They took {bidi_char}1000 USDT from me."
    with pytest.raises(IntakeValidationError) as exc_info:
        validate_intake_payload(form)
    assert exc_info.value.field == "description"


def test_null_byte_in_client_name_rejected() -> None:
    """A null byte in cases.client_name would crash psycopg's TEXT
    insert AFTER the Stripe Checkout URL is generated. Reject early
    so we don't leak a half-broken case."""
    from recupero.portal.intake import (
        IntakeValidationError,
        validate_intake_payload,
    )

    form = _good_form()
    form["client_name"] = "Jane\x00Smith"
    with pytest.raises(IntakeValidationError) as exc_info:
        validate_intake_payload(form)
    assert exc_info.value.field == "client_name"


def test_null_byte_in_description_rejected() -> None:
    """Same hardening on description."""
    from recupero.portal.intake import (
        IntakeValidationError,
        validate_intake_payload,
    )

    form = _good_form()
    form["description"] = "Phishing\x00attack."
    with pytest.raises(IntakeValidationError) as exc_info:
        validate_intake_payload(form)
    assert exc_info.value.field == "description"


def test_newline_in_email_rejected() -> None:
    """SMTP header injection via newline-in-email. Even if the
    sender library is hardened, defense-in-depth at the intake
    layer is cheap.

    The current _EMAIL_RE uses [^@\\s]+ which excludes ALL
    whitespace including \\n, so this should ALREADY be rejected
    via "doesn't look like a valid email address" — confirm the
    contract holds."""
    from recupero.portal.intake import (
        IntakeValidationError,
        validate_intake_payload,
    )

    form = _good_form()
    form["client_email"] = "victim@x.y\nBcc: attacker@evil.com"
    with pytest.raises(IntakeValidationError) as exc_info:
        validate_intake_payload(form)
    assert exc_info.value.field == "client_email"


def test_carriage_return_in_email_rejected() -> None:
    """\\r is the more common header-injection vector (CRLF). The
    regex's \\s class catches \\r."""
    from recupero.portal.intake import (
        IntakeValidationError,
        validate_intake_payload,
    )

    form = _good_form()
    form["client_email"] = "victim@x.y\r\nBcc: attacker@x.y"
    with pytest.raises(IntakeValidationError) as exc_info:
        validate_intake_payload(form)
    assert exc_info.value.field == "client_email"


def test_emoji_in_client_name_accepted() -> None:
    """Sanity: hardening must NOT block legitimate Unicode. A name
    with an emoji or non-Latin script is valid."""
    from recupero.portal.intake import validate_intake_payload

    form = _good_form()
    form["client_name"] = "山田太郎"  # Japanese name
    payload = validate_intake_payload(form)
    assert payload.client_name == "山田太郎"


def test_unicode_letters_in_description_accepted() -> None:
    """Sanity: a description in any natural language is valid."""
    from recupero.portal.intake import validate_intake_payload

    form = _good_form()
    form["description"] = "Mi cartera fue vaciada después del phishing."
    payload = validate_intake_payload(form)
    assert "vaciada" in payload.description
