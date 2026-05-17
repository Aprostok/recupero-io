"""Subscription poller logic (v0.13.2).

Pure functions — no I/O. Given a subscription's configuration and
the latest observed on-chain activity, decide whether a trigger
has fired and (if so) which AlertPayload to emit.

This separation lets us unit-test all the trigger rules without
mocking Esplora / Etherscan / TronGrid. The worker stage glues
this together with the chain adapters + the dispatcher.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID

log = logging.getLogger(__name__)


# Trigger types matching the CHECK constraint in
# monitoring_subscriptions.trigger_type.
TRIGGER_ANY = "any_movement"
TRIGGER_USD = "movement_above_usd"
TRIGGER_BALANCE_DROP = "balance_drop"
TRIGGER_OFAC = "ofac_contact"

VALID_TRIGGERS = frozenset([
    TRIGGER_ANY, TRIGGER_USD, TRIGGER_BALANCE_DROP, TRIGGER_OFAC,
])


@dataclass(frozen=True)
class Subscription:
    """In-memory shape of a monitoring_subscriptions row."""
    subscription_id: UUID
    address: str
    chain: str
    trigger_type: str
    threshold_usd: Decimal | None
    webhook_url: str
    webhook_secret: str | None
    last_observed_tx_hash: str | None


@dataclass(frozen=True)
class ObservedActivity:
    """One new on-chain event observed for a watched address.

    Built by the worker from chain-adapter outputs. We don't care
    about direction at this layer — the trigger rules do.
    """
    tx_hash: str
    block_time_iso: str
    amount_usd: Decimal | None
    direction: str               # 'inflow' | 'outflow'
    counterparty: str | None
    counterparty_label: str | None
    counterparty_is_ofac: bool
    explorer_url: str


@dataclass(frozen=True)
class TriggerDecision:
    """Result of evaluating one subscription against one observation."""
    should_fire: bool
    reason: str | None
    next_last_observed_tx_hash: str  # to write back to the subscription


def evaluate_trigger(
    sub: Subscription,
    activity: ObservedActivity,
) -> TriggerDecision:
    """Decide whether ``activity`` should fire ``sub``'s webhook.

    Returns TriggerDecision with should_fire flag + a human-readable
    reason (for the audit log) + the next cursor value to write
    back to the subscription.

    Cursor semantics: we ALWAYS advance the cursor to the activity's
    tx_hash — even when we don't fire — so the next poll doesn't
    re-evaluate this tx.
    """
    if sub.trigger_type not in VALID_TRIGGERS:
        log.warning(
            "subscription %s has invalid trigger_type %r — skipping",
            sub.subscription_id, sub.trigger_type,
        )
        return TriggerDecision(
            should_fire=False,
            reason=f"invalid trigger_type {sub.trigger_type!r}",
            next_last_observed_tx_hash=activity.tx_hash,
        )

    # Already-alerted dedupe: if the observation's tx_hash matches
    # the cursor, we've already evaluated this tx; don't re-fire.
    if (
        sub.last_observed_tx_hash is not None
        and sub.last_observed_tx_hash == activity.tx_hash
    ):
        return TriggerDecision(
            should_fire=False,
            reason="already-alerted (cursor matches)",
            next_last_observed_tx_hash=activity.tx_hash,
        )

    fire = False
    reason: str | None = None

    if sub.trigger_type == TRIGGER_ANY:
        # Fire on any movement, regardless of direction or amount.
        fire = True
        reason = f"any_movement trigger fired (direction={activity.direction})"

    elif sub.trigger_type == TRIGGER_USD:
        # Fire only on outflows above threshold_usd.
        threshold = sub.threshold_usd or Decimal("0")
        if (
            activity.direction == "outflow"
            and activity.amount_usd is not None
            and activity.amount_usd >= threshold
        ):
            fire = True
            reason = (
                f"movement_above_usd: outflow {activity.amount_usd} "
                f">= threshold {threshold}"
            )
        else:
            reason = (
                f"movement_above_usd: skipped "
                f"(direction={activity.direction}, "
                f"amount_usd={activity.amount_usd}, "
                f"threshold={threshold})"
            )

    elif sub.trigger_type == TRIGGER_BALANCE_DROP:
        # Balance-drop semantics require the caller to compute the
        # post-tx balance. For v0.13.2 we approximate: any outflow
        # is a balance drop. (Real impl would query the chain for
        # current balance; deferred to v0.13.x.)
        if activity.direction == "outflow":
            fire = True
            reason = "balance_drop: outflow detected"
        else:
            reason = "balance_drop: inflow, no balance drop"

    elif sub.trigger_type == TRIGGER_OFAC:
        # Fire on either-direction tx where the counterparty is
        # OFAC-listed.
        if activity.counterparty_is_ofac:
            fire = True
            label = activity.counterparty_label or "(unlabeled OFAC entity)"
            reason = f"ofac_contact: {activity.direction} with {label}"
        else:
            reason = "ofac_contact: counterparty not OFAC-listed"

    return TriggerDecision(
        should_fire=fire,
        reason=reason,
        next_last_observed_tx_hash=activity.tx_hash,
    )


def evaluate_all_activities(
    sub: Subscription,
    activities: list[ObservedActivity],
) -> tuple[list[ObservedActivity], str]:
    """Given the full activity list for an address (newest first),
    return the SUBSET that should fire alerts and the new cursor.

    The function walks activities oldest-first (reversed input) so:
      * Activities older than the cursor are skipped (already alerted).
      * Each new activity is evaluated independently.
      * The cursor advances to the newest activity at the end.

    Returns ``(to_fire, new_cursor)``. The caller persists
    new_cursor back to the subscription regardless of whether any
    activities fired.
    """
    if not activities:
        return [], sub.last_observed_tx_hash or ""

    # Activities are typically newest-first; walk oldest-first so we
    # can short-circuit at the cursor.
    oldest_first = list(reversed(activities))

    # If we have a cursor, drop activities at-or-older than the cursor.
    if sub.last_observed_tx_hash is not None:
        try:
            cursor_idx = next(
                i for i, a in enumerate(oldest_first)
                if a.tx_hash == sub.last_observed_tx_hash
            )
            oldest_first = oldest_first[cursor_idx + 1:]
        except StopIteration:
            # Cursor not in the current batch — could mean the
            # cursored tx scrolled off (deep history) OR the cursor
            # is for an older session. Conservative: evaluate
            # everything, but this can produce a burst of "false
            # new" alerts. The first-poll case (cursor is NULL)
            # handles initial subscription setup — we DON'T fire on
            # historical activity, we just set the cursor to the
            # newest tx.
            if sub.last_observed_tx_hash:
                log.info(
                    "subscription %s: cursor tx %s not in current batch; "
                    "advancing to newest without firing",
                    sub.subscription_id, sub.last_observed_tx_hash,
                )
                # Don't fire on anything; advance cursor.
                return [], activities[0].tx_hash

    # First poll (no cursor): don't fire on historical activity, just
    # bookmark.
    if sub.last_observed_tx_hash is None:
        return [], activities[0].tx_hash

    to_fire: list[ObservedActivity] = []
    new_cursor = sub.last_observed_tx_hash
    for activity in oldest_first:
        decision = evaluate_trigger(sub, activity)
        if decision.should_fire:
            to_fire.append(activity)
        new_cursor = decision.next_last_observed_tx_hash
    return to_fire, new_cursor


__all__ = (
    "TRIGGER_ANY",
    "TRIGGER_USD",
    "TRIGGER_BALANCE_DROP",
    "TRIGGER_OFAC",
    "VALID_TRIGGERS",
    "Subscription",
    "ObservedActivity",
    "TriggerDecision",
    "evaluate_trigger",
    "evaluate_all_activities",
)
