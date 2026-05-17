"""Detect Stripe test-mode vs live-mode from observable signals.

Stripe's API uses two separate sets of credentials + URLs:
  * Test mode (whsec_test_*, buy.stripe.com/test_*, pk_test_*, sk_test_*)
  * Live mode (whsec_*, buy.stripe.com/*, pk_live_*, sk_live_*)

Mixing these is the most common Stripe integration footgun:
  * Live Payment Link + test webhook secret → every real
    customer payment fails signature verification, never lands
    in public.payments, customer paid but workflow doesn't advance.
  * Test Payment Link + live webhook secret → same shape,
    inverse: test transactions look like they worked from the
    Dashboard but the worker never sees them.

This module exposes a single classifier that operators can call
from the CLI ("am I configured for test or live?") and the
generate-payment-link command can use to spot mismatches before
minting a URL that won't work.

The detection is heuristic — Stripe doesn't expose a "what mode
am I in" API endpoint. We match against documented URL/key
prefixes; an exotic future Stripe rotation could fool the
detector, but the warning has guidance for that case too.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

# Env var names. Centralized so the CLI's error messages
# reference the same strings the operator needs to set.
ENV_WEBHOOK_SECRET = "STRIPE_WEBHOOK_SECRET"
ENV_DIAGNOSTIC_LINK = "RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK"
ENV_ENGAGEMENT_LINK = "RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK"


StripeMode = Literal["test", "live", "unknown"]


@dataclass(frozen=True)
class ModeReport:
    """Per-signal classification + an overall verdict.

    Each field is one of 'test' | 'live' | 'unknown'. ``mismatch``
    is True iff at least two signals disagree on test vs live.
    The CLI uses this to print a warning before minting a URL.
    """
    webhook_secret: StripeMode
    diagnostic_link: StripeMode
    engagement_link: StripeMode
    mismatch: bool

    @property
    def consensus(self) -> StripeMode:
        """Single-word summary across all signals. Returns 'unknown'
        if any signal is unknown OR the signals disagree."""
        if self.mismatch:
            return "unknown"
        # All non-unknown agree. Return their shared value.
        for v in (self.webhook_secret, self.diagnostic_link,
                  self.engagement_link):
            if v != "unknown":
                return v
        return "unknown"


def classify_webhook_secret(value: str | None) -> StripeMode:
    """Stripe webhook signing secrets:
      whsec_test_*   → test
      whsec_*        → live (any prefix that isn't whsec_test_)
      anything else  → unknown (probably misconfigured or empty)
    """
    if not value:
        return "unknown"
    v = value.strip()
    if v.startswith("whsec_test_"):
        return "test"
    if v.startswith("whsec_"):
        return "live"
    return "unknown"


def classify_payment_link(url: str | None) -> StripeMode:
    """Stripe Payment Links:
      buy.stripe.com/test_*   → test
      buy.stripe.com/*        → live (anything after the host that
                                doesn't start with /test_)
      anything else           → unknown (operator pasted the wrong
                                URL, or it's not a Payment Link at all)
    """
    if not url:
        return "unknown"
    v = url.strip().lower()
    if "buy.stripe.com/test_" in v:
        return "test"
    if "buy.stripe.com/" in v:
        return "live"
    return "unknown"


def detect_mode_from_env() -> ModeReport:
    """Probe env vars + return a ModeReport classifying each signal.

    Caller (the CLI) is responsible for deciding what to do with
    a mismatch — typically print a warning + ask for confirmation
    before proceeding.
    """
    ws = classify_webhook_secret(os.environ.get(ENV_WEBHOOK_SECRET))
    dl = classify_payment_link(os.environ.get(ENV_DIAGNOSTIC_LINK))
    el = classify_payment_link(os.environ.get(ENV_ENGAGEMENT_LINK))

    # Mismatch: at least two non-unknown signals disagree.
    non_unknown = {m for m in (ws, dl, el) if m != "unknown"}
    mismatch = len(non_unknown) > 1

    return ModeReport(
        webhook_secret=ws,
        diagnostic_link=dl,
        engagement_link=el,
        mismatch=mismatch,
    )


def format_mismatch_warning(report: ModeReport) -> str:
    """Human-readable warning text for a mismatch case. Multi-line
    string the CLI can write directly to stderr."""
    if not report.mismatch:
        return ""

    lines = [
        "WARNING: Stripe test/live mode mismatch detected.",
        "",
        f"  {ENV_WEBHOOK_SECRET:50s} = {report.webhook_secret}",
        f"  {ENV_DIAGNOSTIC_LINK:50s} = {report.diagnostic_link}",
        f"  {ENV_ENGAGEMENT_LINK:50s} = {report.engagement_link}",
        "",
        "When these don't all match, customer payments will fail "
        "signature verification and the workflow won't advance.",
        "",
        "Fix:",
        "  - Test mode: all values should be the 'test_' / 'whsec_test_' variants.",
        "  - Live mode: all values should be the live variants.",
        "",
        "Configure all three to the same mode in Railway, then "
        "re-deploy.",
    ]
    return "\n".join(lines)


__all__ = (
    "ENV_WEBHOOK_SECRET",
    "ENV_DIAGNOSTIC_LINK",
    "ENV_ENGAGEMENT_LINK",
    "ModeReport",
    "StripeMode",
    "classify_payment_link",
    "classify_webhook_secret",
    "detect_mode_from_env",
    "format_mismatch_warning",
)
