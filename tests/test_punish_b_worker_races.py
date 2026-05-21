"""PUNISH-B W-2 / W-3 / W-4: worker-side races on monitor_tick + followup cron.

W-2: monitor_tick's SELECT pulls active subs with NO row lock. Two
     overlapping cron instances both pull the same N rows and both
     deliver alerts → duplicate webhooks + emails.
W-3: monitor_tick's UPDATE doesn't filter on status='active'. If a
     partner DELETEs (soft-delete → status='deleted') WHILE a tick
     is mid-poll, the worker still dispatches AND rewrites
     last_polled_at on the deleted row.
W-4: _followup.py weekly-engagement cron has no claim pattern. Two
     overlapping cron instances both send the same weekly recap
     email to the same victim.

This file is the source-level guard for all three. Each one fails
on a missing SQL discipline pattern (FOR UPDATE SKIP LOCKED,
status='active' filter, atomic-claim UPDATE-RETURNING).
"""

from __future__ import annotations

import inspect

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# W-2: monitor_tick must use FOR UPDATE SKIP LOCKED on the select
# ─────────────────────────────────────────────────────────────────────────────


def test_w2_monitor_tick_select_uses_for_update_skip_locked():
    """The subscription-fetch SQL must acquire a row lock so two
    overlapping cron instances don't both deliver the same alerts.
    Pre-fix: bare SELECT with no lock. Two ticks → same N rows →
    duplicate webhooks fired."""
    from recupero.worker import monitor_tick

    src = inspect.getsource(monitor_tick)
    # The select_sql constant must contain FOR UPDATE SKIP LOCKED.
    assert "FOR UPDATE SKIP LOCKED" in src, (
        "monitor_tick's subscription SELECT does not use "
        "FOR UPDATE SKIP LOCKED. Concurrent cron instances pull "
        "the same active rows and deliver duplicate webhooks + "
        "emails. The cluster-builder + worker-pipeline modules "
        "already use this pattern — apply it here."
    )


# ─────────────────────────────────────────────────────────────────────────────
# W-3: monitor_tick UPDATE must filter status='active'
# ─────────────────────────────────────────────────────────────────────────────


def test_w3_monitor_tick_update_filters_status_active():
    """The cursor-advance UPDATE at the end of each per-row tick
    must NOT touch soft-deleted rows. Pre-fix: UPDATE WHERE id=%s
    (no status filter), so a partner DELETE mid-tick let the
    worker dispatch + rewrite last_polled_at on a deleted sub."""
    from recupero.worker import monitor_tick
    src = inspect.getsource(monitor_tick)
    # Find the UPDATE on monitoring_subscriptions.
    # It must include an AND status='active' (or equivalent).
    import re
    m = re.search(
        r"UPDATE\s+public\.monitoring_subscriptions[\s\S]*?WHERE[^;]+;",
        src, flags=re.IGNORECASE,
    )
    assert m, "could not find monitor_tick UPDATE statement"
    update_block = m.group(0)
    assert "status" in update_block, (
        "monitor_tick UPDATE does not filter on status='active'. "
        "A partner DELETE mid-poll resurrects the row's "
        "last_polled_at and the dispatch fires AFTER the partner "
        "asked us to stop. UPDATE block:\n" + update_block
    )


# ─────────────────────────────────────────────────────────────────────────────
# W-4: weekly-engagement followup cron needs atomic claim
# ─────────────────────────────────────────────────────────────────────────────


def test_w4_followup_cron_uses_atomic_claim_pattern():
    """The freeze-followup module already uses _try_claim_stage_advance
    (UPDATE ... WHERE last_state=X RETURNING id) — atomic claim.
    The weekly-engagement followup cron at worker/_followup.py
    must use the same pattern. Pre-fix: plain SELECT + send + UPDATE,
    two cron instances both send the recap email."""
    from recupero.worker import _followup
    src = inspect.getsource(_followup)
    # Atomic-claim pattern: UPDATE ... WHERE <stale-check> RETURNING id.
    # The freeze-followup module is the canonical example —
    # _followup.py needs the same shape.
    has_returning_update = bool(
        # Match: UPDATE ... RETURNING (case-insensitive,
        # multi-line, allow indentation)
        __import__("re").search(
            r"UPDATE\s+public\.[a-z_]+[\s\S]+?RETURNING",
            src, flags=__import__("re").IGNORECASE,
        )
    )
    assert has_returning_update, (
        "_followup.py weekly-engagement cron does not use an "
        "UPDATE ... RETURNING atomic-claim pattern. Two overlapping "
        "cron instances both pass the SELECT, both send the recap, "
        "both write last_followup_sent_at — victim gets the same "
        "email twice."
    )
