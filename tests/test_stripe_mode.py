"""Tests for the Stripe test/live mode detector.

Pure function on three string inputs (webhook secret, two
Payment Link URLs) → ModeReport. No DB, no network, easy to lock.

Contracts under test:
  * Webhook secret prefix classification (whsec_test_ / whsec_ /
    anything else).
  * Payment Link URL classification (test_* path / non-test path /
    anything else).
  * Mismatch detection — at least two non-unknown signals disagree.
  * Consensus across all signals when they agree.
  * The format_mismatch_warning helper produces actionable text.
"""

from __future__ import annotations

from recupero.payments.stripe_mode import (
    ModeReport,
    classify_payment_link,
    classify_webhook_secret,
    detect_mode_from_env,
    format_mismatch_warning,
)

# ---- classify_webhook_secret ---- #


def test_classify_webhook_test_secret() -> None:
    """The Stripe-documented test webhook prefix is whsec_test_."""
    assert classify_webhook_secret("whsec_test_abc123xyz") == "test"


def test_classify_webhook_live_secret() -> None:
    """Anything starting with whsec_ that isn't whsec_test_ is live.
    Stripe doesn't add a 'whsec_live_' prefix — production secrets
    are just 'whsec_' + random."""
    assert classify_webhook_secret("whsec_realprodsecret123") == "live"


def test_classify_webhook_empty_or_none() -> None:
    """Unset env var → 'unknown', not 'test' or 'live'."""
    assert classify_webhook_secret(None) == "unknown"
    assert classify_webhook_secret("") == "unknown"
    assert classify_webhook_secret("   ") == "unknown"


def test_classify_webhook_garbage() -> None:
    """A value that doesn't look like any known Stripe prefix →
    'unknown'. Defensive against operator paste-typos."""
    assert classify_webhook_secret("sk_live_definitelywrongkind") == "unknown"
    assert classify_webhook_secret("hello world") == "unknown"


def test_classify_webhook_strips_whitespace() -> None:
    """Operators sometimes paste with trailing newlines. Strip."""
    assert classify_webhook_secret("  whsec_test_x  \n") == "test"


# ---- classify_payment_link ---- #


def test_classify_payment_link_test() -> None:
    """Stripe test Payment Links have /test_ in the path."""
    assert classify_payment_link(
        "https://buy.stripe.com/test_xyz123"
    ) == "test"


def test_classify_payment_link_live() -> None:
    """Production Payment Links don't have the test_ prefix.
    Stripe uses a path like /aBcDe123 (random suffix)."""
    assert classify_payment_link(
        "https://buy.stripe.com/aBcDe123"
    ) == "live"


def test_classify_payment_link_handles_query_params() -> None:
    """The classifier must work even when the URL carries
    client_reference_id + prefilled_email params."""
    test_url = (
        "https://buy.stripe.com/test_xyz?client_reference_id=eng:abc"
    )
    live_url = (
        "https://buy.stripe.com/aBcDe?client_reference_id=eng:abc"
    )
    assert classify_payment_link(test_url) == "test"
    assert classify_payment_link(live_url) == "live"


def test_classify_payment_link_non_stripe() -> None:
    """A URL that isn't a buy.stripe.com URL → 'unknown'. Catches
    operator mistakes like pasting a Stripe Dashboard URL instead
    of a Payment Link URL."""
    assert classify_payment_link(
        "https://dashboard.stripe.com/test/payments"
    ) == "unknown"
    assert classify_payment_link("not a url") == "unknown"
    assert classify_payment_link("") == "unknown"
    assert classify_payment_link(None) == "unknown"


# ---- detect_mode_from_env (full integration) ---- #


def test_detect_all_test(monkeypatch) -> None:
    """Three signals all test → consensus='test', no mismatch."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_x")
    monkeypatch.setenv("RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK",
                       "https://buy.stripe.com/test_diag")
    monkeypatch.setenv("RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK",
                       "https://buy.stripe.com/test_eng")
    report = detect_mode_from_env()
    assert report.webhook_secret == "test"
    assert report.diagnostic_link == "test"
    assert report.engagement_link == "test"
    assert report.mismatch is False
    assert report.consensus == "test"


def test_detect_all_live(monkeypatch) -> None:
    """Three live signals → consensus='live', no mismatch."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_realprod")
    monkeypatch.setenv("RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK",
                       "https://buy.stripe.com/prodlink1")
    monkeypatch.setenv("RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK",
                       "https://buy.stripe.com/prodlink2")
    report = detect_mode_from_env()
    assert report.mismatch is False
    assert report.consensus == "live"


def test_detect_test_secret_live_links_is_mismatch(monkeypatch) -> None:
    """The classic footgun: webhook secret is test mode but
    Payment Links are live. mismatch=True, consensus='unknown'."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_x")
    monkeypatch.setenv("RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK",
                       "https://buy.stripe.com/prodlink")
    monkeypatch.setenv("RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK",
                       "https://buy.stripe.com/prodlink2")
    report = detect_mode_from_env()
    assert report.mismatch is True
    assert report.consensus == "unknown"


def test_detect_one_unknown_does_not_count_as_mismatch(monkeypatch) -> None:
    """If two signals are test/live but the third is unknown
    (env unset), that's NOT a mismatch — it's a partial config.
    The consensus is the agreed value of the configured signals."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_x")
    monkeypatch.setenv("RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK",
                       "https://buy.stripe.com/test_diag")
    monkeypatch.delenv(
        "RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK", raising=False,
    )
    report = detect_mode_from_env()
    assert report.mismatch is False
    assert report.consensus == "test"
    assert report.engagement_link == "unknown"


def test_detect_all_unset(monkeypatch) -> None:
    """All three env vars unset → all 'unknown', not a mismatch
    (nothing to mismatch against), consensus='unknown'."""
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv(
        "RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK", raising=False,
    )
    monkeypatch.delenv(
        "RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK", raising=False,
    )
    report = detect_mode_from_env()
    assert report.mismatch is False
    assert report.consensus == "unknown"


# ---- format_mismatch_warning ---- #


def test_format_warning_empty_when_no_mismatch() -> None:
    """No mismatch → empty string. CLI prints nothing in this case."""
    report = ModeReport(
        webhook_secret="test", diagnostic_link="test",
        engagement_link="test", mismatch=False,
    )
    assert format_mismatch_warning(report) == ""


def test_format_warning_includes_all_signals() -> None:
    """The warning text lists each env var with its classification.
    Operator reads this and immediately sees which var is wrong."""
    report = ModeReport(
        webhook_secret="test", diagnostic_link="live",
        engagement_link="live", mismatch=True,
    )
    out = format_mismatch_warning(report)
    assert "WARNING" in out
    assert "STRIPE_WEBHOOK_SECRET" in out
    assert "RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK" in out
    assert "RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK" in out
    assert "test" in out
    assert "live" in out


def test_format_warning_mentions_fix() -> None:
    """The warning should tell the operator what to do, not just
    that something is wrong."""
    report = ModeReport(
        webhook_secret="test", diagnostic_link="live",
        engagement_link="live", mismatch=True,
    )
    out = format_mismatch_warning(report)
    assert "Fix" in out or "fix" in out
    # And reference Railway since that's where the operator changes
    # the env vars on the production worker.
    assert "Railway" in out
