"""Proactive recovery alerts (v0.35.13 — roadmap D6).

The watchlist tick (``worker/watch_tick.py``) snapshots every watched wallet and
flags material balance/tx deltas. D6 turns the most recovery-relevant of those
deltas into a prioritized **"act now" alert**: when funds at a *freezable*
address start leaving, when *tracked* (identified-but-not-yet-freezable) funds
move (so we can re-trace and catch the new venue), or when *long-dormant* funds
reactivate — the moments when a recovery is won or lost.

This is the alert layer on top of the existing monitoring data. It is PURE: it
reads the ``MaterialChange`` records the tick already computed (duck-typed, so
no import cycle with watch_tick and so tests can feed lightweight stand-ins) and
emits ranked ``RecoveryAlert`` records. Dormancy is computed from the snapshot
timestamps already on the change — no clock dependency, fully deterministic.

Forensic posture: an alert is an operational prompt to RE-TRACE / FILE, never a
claim about where the funds went. Identifying the new destination (and whether
it is freezable) requires a fresh trace — the alert says "look now", it does not
fabricate a destination.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

log = logging.getLogger(__name__)

# Default minimum |Δ USD| for a movement to raise an alert. Higher bar than the
# digest's mention threshold — an alert is an interrupt, so it should fire only
# on a move worth acting on. Operator-overridable per call.
_DEFAULT_MIN_MOVE_USD = Decimal("100")

# A wallet untouched for at least this many days, then moving, is "reactivated".
_DEFAULT_DORMANCY_DAYS = 30

_SEVERITY_RANK = {"critical": 2, "high": 1, "info": 0}


@dataclass(frozen=True)
class RecoveryAlert:
    """One prioritized recovery prompt derived from a watch-tick change."""
    address: str
    chain: str
    severity: str          # "critical" | "high"
    kind: str              # freezable_outflow | tracked_outflow |
    #                        dormant_reactivation | freezable_inflow
    delta_usd: str         # formatted, finite-guarded
    dormant_days: int | None
    role: str
    label_name: str | None
    message: str
    recommended_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "chain": self.chain,
            "severity": self.severity,
            "kind": self.kind,
            "delta_usd": self.delta_usd,
            "dormant_days": self.dormant_days,
            "role": self.role,
            "label_name": self.label_name,
            "message": self.message,
            "recommended_action": self.recommended_action,
        }


def _finite(value: Any) -> Decimal | None:
    if value is None:
        return None
    try:
        d = value if isinstance(value, Decimal) else Decimal(str(value))
    except (ValueError, ArithmeticError, TypeError):
        return None
    return d if d.is_finite() else None


def _dormant_days(change: Any) -> int | None:
    prior = getattr(change, "prior_taken_at", None)
    new = getattr(change, "new_taken_at", None)
    if prior is None or new is None:
        return None
    try:
        delta = new - prior
        return max(0, int(delta.total_seconds() // 86400))
    except (TypeError, AttributeError, ValueError, OverflowError):
        return None


def evaluate_recovery_alerts(
    changes: Any,
    *,
    min_move_usd: Decimal | None = None,
    dormancy_days: int = _DEFAULT_DORMANCY_DAYS,
) -> list[RecoveryAlert]:
    """PURE: ``MaterialChange``-like records → ranked recovery alerts.

    A change raises an alert only when it represents a material movement
    (``|Δ USD| >= min_move_usd`` or a positive tx-count delta after dormancy).
    Severity:
      * freezable address + outflow → CRITICAL (freezable funds leaving);
      * tracked (not-yet-freezable) address + outflow → CRITICAL (re-trace to
        catch the new venue before it is lost);
      * dormant (≥ ``dormancy_days``) wallet + any material move → at least HIGH;
        dormant + outflow escalates to CRITICAL;
      * freezable address + inflow → HIGH (a freeze opportunity arrived).
    Sorted by severity then |Δ USD| descending.
    """
    floor = min_move_usd if min_move_usd is not None else _DEFAULT_MIN_MOVE_USD
    alerts: list[RecoveryAlert] = []

    for ch in changes or []:
        delta = _finite(getattr(ch, "delta_usd", None))
        tx_delta = getattr(ch, "tx_count_delta", None)
        tx_delta = tx_delta if isinstance(tx_delta, int) else None

        moved_usd = delta is not None and abs(delta) >= floor
        moved_tx = bool(tx_delta and tx_delta > 0)
        if not (moved_usd or moved_tx):
            continue

        is_freezeable = bool(getattr(ch, "is_freezeable", False))
        outflow = delta is not None and delta < 0
        inflow = delta is not None and delta > 0
        dormant = _dormant_days(ch)
        is_dormant = dormant is not None and dormant >= dormancy_days

        address = str(getattr(ch, "address", "") or "")
        chain = str(getattr(ch, "chain", "") or "")
        role = str(getattr(ch, "role", "") or "")
        label_name = getattr(ch, "label_name", None)
        delta_str = f"${delta:,.2f}" if delta is not None else "(unpriced)"

        # Classify (highest-severity rule wins).
        severity: str
        kind: str
        message: str
        action: str
        if outflow and is_freezeable:
            severity, kind = "critical", "freezable_outflow"
            message = (
                f"Freezable funds are LEAVING a known address ({delta_str}). "
                "They may be heading to a non-freezable venue."
            )
            action = (
                "Re-run the trace on this address NOW and refresh/escalate the "
                "freeze request with the issuer before the funds move on."
            )
        elif outflow:
            severity, kind = "critical", "tracked_outflow"
            message = (
                f"Tracked (identified-but-not-freezable) funds are MOVING "
                f"({delta_str})."
            )
            action = (
                "Re-run the trace immediately to identify the new destination; "
                "if it is a freezable venue, file a freeze at once."
            )
            if is_dormant:
                message = f"Long-dormant ({dormant}d) tracked funds reactivated and are moving ({delta_str})."
        elif is_dormant:
            severity, kind = "high", "dormant_reactivation"
            message = (
                f"Long-dormant funds reactivated after {dormant} days "
                f"(Δ {delta_str}). Dormant funds in motion often precede a "
                "cash-out."
            )
            action = "Re-run the trace now; watch for movement toward a freezable venue."
        elif inflow and is_freezeable:
            severity, kind = "high", "freezable_inflow"
            message = (
                f"Funds arrived at a freezable address ({delta_str}) — a freeze "
                "opportunity."
            )
            action = "Confirm the inbound and file a freeze request with the issuer/exchange."
        else:
            # Material tx-count move with no priced direction + not dormant —
            # informational, not an interrupt. Skip to keep alerts high-signal.
            continue

        alerts.append(RecoveryAlert(
            address=address, chain=chain, severity=severity, kind=kind,
            delta_usd=delta_str, dormant_days=dormant, role=role,
            label_name=label_name, message=message, recommended_action=action,
        ))

    alerts.sort(
        key=lambda a: (
            _SEVERITY_RANK.get(a.severity, 0),
            abs(_finite(a.delta_usd.replace("$", "").replace(",", "")) or Decimal(0)),
        ),
        reverse=True,
    )
    return alerts


def recovery_alerts_to_dict(alerts: list[RecoveryAlert]) -> dict[str, Any]:
    """Serialize alerts + a severity summary (for digests / notifications)."""
    return {
        "alerts": [a.to_dict() for a in alerts],
        "summary": {
            "total": len(alerts),
            "critical": sum(1 for a in alerts if a.severity == "critical"),
            "high": sum(1 for a in alerts if a.severity == "high"),
        },
    }


__all__ = (
    "RecoveryAlert",
    "evaluate_recovery_alerts",
    "recovery_alerts_to_dict",
)
