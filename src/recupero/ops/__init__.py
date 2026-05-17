"""Operator CLI helpers — recupero-ops <command> <args>.

This package exposes a set of small, single-purpose commands the
operator runs against in-flight investigations. They wrap what
would otherwise be hand-typed SQL statements and one-off Python
scripts into named commands with consistent argument parsing,
confirmation prompts for destructive operations, and idempotency
where appropriate.

Available commands:

  recupero-ops status <inv_id>
      Show the full state of an investigation: row metadata,
      engagement status, emails sent (audit log), artifact
      inventory. The single command the operator runs to see
      everything about a case.

  recupero-ops mark-engaged <inv_id> [--fee 10000]
      Start a Tier-2 engagement. Sets engagement_started_at=NOW()
      and engagement_fee_paid_usd=<fee>. Activates the follow-up
      cron for this case. Idempotent — running twice is a no-op.

  recupero-ops mark-closed <inv_id> [--reason TEXT]
      Close an active engagement. Sets engagement_closed_at=NOW().
      The reason is recorded in change_summary for audit. Stops
      the follow-up cron from sending further updates.

  recupero-ops send-freeze-letters <inv_id>
      Send the prepared compliance freeze letters for an
      investigation to their respective issuer compliance teams.
      Requires interactive confirmation (lists recipients,
      prompts y/N) — this is the most-sensitive operator action.
      Uses the same email primitive + audit log + idempotency as
      the auto-send paths.

  recupero-ops send-le-handoff <inv_id> --to EMAIL
      Send the LE handoff package to a specific law-enforcement
      officer or attorney. Operator supplies the recipient
      address.

  recupero-ops followup-now <inv_id>
      Force-send a follow-up status email immediately, bypassing
      the 6-day cadence check. Used when the operator has a
      material update they want to communicate sooner.

All commands write to the existing emails_sent audit log + use
the existing RECUPERO_DISABLE_EMAIL kill-switch for safe local
testing.
"""

from __future__ import annotations

__all__ = ()
