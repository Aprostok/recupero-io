"""Tests for the portal-link banner injected into the auto-sent
victim-summary email.

The banner is built by recupero.worker._deliverables._build_portal_banner_html
and prepended to the email body before the Resend send. Failures
to mint a token must NOT block the send — they degrade gracefully
to "send without banner" so the customer still gets their PDFs.

Contracts under test:
  * Returns "" when case_id is None (wallet trace path).
  * Returns "" when SUPABASE_DB_URL is unset (no DB reachable).
  * Returns "" when generate_token raises (DB error, FK miss).
  * Returns HTML with the portal URL when the happy path works.
  * The injected HTML uses inline styles only (Gmail strips
    <style> blocks; we lock the requirement against future
    "let's add a stylesheet" temptations).
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

from recupero.worker._deliverables import _build_portal_banner_html


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
