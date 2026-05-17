"""Tests for the banners injected into the auto-sent victim-summary
email: the portal-link banner (v0.5.4) and the engagement Pay-Now
banner (v0.6.2).

Both banners are built by recupero.worker._deliverables helpers
and prepended to the email body before the Resend send. Failures
in EITHER helper must NOT block the send — they degrade gracefully
to "send with the surviving banner(s)" so the customer always
gets their PDFs and at least one CTA.

Contracts under test:
  * Portal banner:
    - Returns "" when case_id is None (wallet trace path).
    - Returns "" when SUPABASE_DB_URL is unset.
    - Returns "" when generate_token raises.
    - Returns HTML with the portal URL on happy path.
    - Inline styles only (Gmail strips <style> blocks).
  * Pay-Now banner:
    - Returns "" when RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK
      is unset (dev / pre-Stripe deployments degrade cleanly).
    - Returns HTML with the engagement Payment Link URL on happy
      path, with investigation_id encoded as client_reference_id.
    - Inline styles only.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

from recupero.worker._deliverables import (
    _build_pay_engagement_banner_html,
    _build_portal_banner_html,
)


def test_banner_empty_when_case_id_none() -> None:
    """Wallet-trace investigations have no real case → no portal
    link possible → banner is empty string (prepend is a no-op)."""
    out = _build_portal_banner_html(case_id=None)
    assert out == ""


def test_banner_empty_when_dsn_unset(monkeypatch) -> None:
    """No DB connection string → we can't insert into case_tokens
    → return "" instead of crashing the email send."""
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    out = _build_portal_banner_html(case_id=str(uuid4()))
    assert out == ""


def test_banner_empty_when_token_mint_fails(monkeypatch) -> None:
    """generate_token raised (DB down, FK miss, etc.) → return ""
    so the email send proceeds without a banner. Logged as a
    warning, not raised — non-fatal for the broader pipeline."""
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://fake")
    with patch(
        "recupero.portal.tokens.generate_token",
        side_effect=RuntimeError("DB down"),
    ):
        out = _build_portal_banner_html(case_id=str(uuid4()))
    assert out == ""


def test_banner_happy_path(monkeypatch) -> None:
    """generate_token succeeds → return HTML containing the portal
    URL and a clickable button. The URL is built via
    public_portal_url so the env-var precedence is honored."""
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://fake")
    monkeypatch.setenv(
        "RECUPERO_PORTAL_BASE_URL", "https://portal.recupero.io",
    )
    fake_token_value = "fake-token-43-chars-xxxxxxxxxxxxxxxxxxxxxxx"
    with patch(
        "recupero.portal.tokens.generate_token",
        return_value=(uuid4(), fake_token_value, None),
    ):
        out = _build_portal_banner_html(case_id=str(uuid4()))
    assert out, "banner should be non-empty on the happy path"
    assert f"https://portal.recupero.io/portal/{fake_token_value}" in out
    # The clickable element is an <a> tag (works in every email
    # client; <button> tags don't render reliably in Gmail).
    assert "<a href=" in out
    # The text the customer sees on the button — locks the CTA so
    # a future "let's reword this" change has to update the test.
    assert "Open case page" in out


def test_banner_uses_inline_styles_only(monkeypatch) -> None:
    """Gmail strips <style> blocks aggressively. Inline styles are
    the only reliable way to make the banner look right across
    Gmail / Outlook / Apple Mail. Lock the requirement so a future
    'let's refactor to a stylesheet' change has to also update
    every recipient mail client we care about."""
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://fake")
    with patch(
        "recupero.portal.tokens.generate_token",
        return_value=(uuid4(), "tok-43-chars-xxxxxxxxxxxxxxxxxxxxxxxxxxx", None),
    ):
        out = _build_portal_banner_html(case_id=str(uuid4()))
    assert "<style" not in out.lower()
    assert "style=" in out  # inline styles are present


# ---- _build_pay_engagement_banner_html (v0.6.2) ---- #


def test_pay_banner_empty_when_env_unset(monkeypatch) -> None:
    """No RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK → return "" so
    the auto-send still goes out with just the portal banner.
    Dev / pre-Stripe deployments degrade cleanly."""
    monkeypatch.delenv("RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK", raising=False)
    out = _build_pay_engagement_banner_html(
        investigation_id=str(uuid4()), victim_email="x@y.com",
    )
    assert out == ""


def test_pay_banner_happy_path(monkeypatch) -> None:
    """With the env var set + valid investigation_id → HTML with
    the Stripe Payment Link URL (containing the eng:<inv_id>
    client_reference_id) and the Pay-Now CTA text."""
    monkeypatch.setenv(
        "RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK",
        "https://buy.stripe.com/test_eng",
    )
    inv_id = uuid4()
    out = _build_pay_engagement_banner_html(
        investigation_id=str(inv_id), victim_email="victim@example.com",
    )
    assert out, "banner should be non-empty on the happy path"
    # The URL is encoded — assert on substrings that survive encoding
    assert "buy.stripe.com/test_eng" in out
    assert "client_reference_id" in out
    # The investigation_id appears as the second colon-separated
    # segment of the encoded CRI. Stripe encodes colons as %3A.
    assert f"eng%3A{inv_id}" in out
    assert "Begin recovery" in out  # CTA text
    # The amount comes from recupero._pricing.ENGAGEMENT_FEE_USD;
    # any future price change updates the banner without touching
    # this test.
    from recupero._pricing import ENGAGEMENT_FEE_USD, fmt_usd_short
    assert fmt_usd_short(ENGAGEMENT_FEE_USD) in out


def test_pay_banner_returns_empty_on_invalid_investigation_id(monkeypatch) -> None:
    """Garbage investigation_id (not a UUID) → build_engagement_link
    raises ValueError on UUID() construction → banner returns ""
    instead of crashing the auto-send."""
    monkeypatch.setenv(
        "RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK",
        "https://buy.stripe.com/test_eng",
    )
    out = _build_pay_engagement_banner_html(
        investigation_id="not-a-uuid", victim_email=None,
    )
    assert out == ""


def test_pay_banner_uses_inline_styles_only(monkeypatch) -> None:
    """Same Gmail-survival requirement as the portal banner."""
    monkeypatch.setenv(
        "RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK",
        "https://buy.stripe.com/test_eng",
    )
    out = _build_pay_engagement_banner_html(
        investigation_id=str(uuid4()), victim_email=None,
    )
    assert "<style" not in out.lower()
    assert "style=" in out


def test_pay_banner_email_optional(monkeypatch) -> None:
    """victim.email is None (rare but possible — intake form
    allowed empty email at some point) → banner still builds.
    Stripe's checkout page asks for email; the customer just
    types it manually."""
    monkeypatch.setenv(
        "RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK",
        "https://buy.stripe.com/test_eng",
    )
    out = _build_pay_engagement_banner_html(
        investigation_id=str(uuid4()), victim_email=None,
    )
    assert out
    # Without prefilled_email the URL doesn't include that param.
    assert "prefilled_email" not in out
