"""Tests for the /v2 transactional emailer + its wiring into the reset flow."""

from __future__ import annotations

from recupero.platform import emailer, router, store


def test_send_link_email_graceful_without_config() -> None:
    # RESEND_API_KEY unset in the test env → engine send_email returns
    # success=False (never raises), so our wrapper returns False.
    assert emailer.send_link_email(
        to="x@example.com", kind="verify", url="https://app/verify?token=abc",
    ) is False


def test_send_link_email_success(monkeypatch) -> None:
    import recupero.worker._email as we

    class _Res:
        success = True

    captured = {}
    monkeypatch.setattr(
        we, "send_email",
        lambda **k: captured.update(k) or _Res(),
    )
    ok = emailer.send_link_email(
        to="x@example.com", kind="password_reset", url="https://app/reset?token=t",
    )
    assert ok is True
    assert captured["to"] == "x@example.com"
    assert captured["email_type"] == "platform_password_reset"
    # the link is embedded in the HTML body
    assert "reset?token=t" in captured["html"]


def test_reset_request_emails_link_but_never_returns_token(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_APP_BASE_URL", "https://app.example")
    monkeypatch.setattr(store, "get_user_by_email", lambda conn, email: {"id": "u1"})
    minted = {}
    monkeypatch.setattr(store, "create_user_token", lambda conn, **k: minted.update(k))
    sent = {}
    monkeypatch.setattr(
        emailer, "send_link_email",
        lambda **k: sent.update(k) or True,
    )
    out = router.request_password_reset(
        router.ResetRequestIn(email="user@example.com"), conn=object(),
    )
    # 202-shape, and NO token in the response …
    assert out == {"status": "sent"}
    assert "token" not in out
    # … but the reset link WAS emailed, and the emailed URL carries the same
    # token whose hash was stored.
    assert sent["kind"] == "password_reset"
    assert sent["to"] == "user@example.com"
    assert "reset?token=" in sent["url"]
