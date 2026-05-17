"""recupero-ops stripe-mode

Reports the current Stripe configuration mode (test vs live) by
classifying each of the three env-var signals:

  STRIPE_WEBHOOK_SECRET
  RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK
  RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK

Exit codes:
  0 — all three classified, all agree (test OR live).
  1 — mismatch detected; details on stderr.
  2 — at least one signal is 'unknown' (env var unset or
      unrecognized format) but no actual mismatch among the
      ones that are set. Use this exit code to gate on "is
      Stripe wired up at all" in CI checks.

Operator usage:
  $ recupero-ops stripe-mode
  STRIPE_WEBHOOK_SECRET                              = test
  RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK            = test
  RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK            = test
  Consensus: test mode (all three signals agree).
"""

from __future__ import annotations

import sys

from recupero.payments.stripe_mode import (
    ENV_DIAGNOSTIC_LINK, ENV_ENGAGEMENT_LINK, ENV_WEBHOOK_SECRET,
    detect_mode_from_env, format_mismatch_warning,
)


def run() -> int:
    """Print the current Stripe mode classification. Returns
    0/1/2 per the exit-code docs in the module docstring."""
    report = detect_mode_from_env()

    print(f"{ENV_WEBHOOK_SECRET:50s} = {report.webhook_secret}")
    print(f"{ENV_DIAGNOSTIC_LINK:50s} = {report.diagnostic_link}")
    print(f"{ENV_ENGAGEMENT_LINK:50s} = {report.engagement_link}")
    print()

    if report.mismatch:
        print(format_mismatch_warning(report), file=sys.stderr)
        return 1

    if report.consensus == "unknown":
        print(
            "WARN: Stripe is not fully configured. At least one env "
            "var is unset or in an unrecognized format. Set all "
            "three to the same mode (test or live) in Railway "
            "before sending payment links to customers."
        )
        return 2

    print(
        f"Consensus: {report.consensus} mode "
        "(all configured signals agree)."
    )
    return 0


__all__ = ("run",)
