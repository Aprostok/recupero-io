"""Auto-incident response planner (v0.35.18 — roadmap D4).

D6 (``recovery_alerts``) fires when watched funds move — "act now". D4 turns
that alert into a concrete, ordered response plan an operator (or, later, an
automation) executes: re-trace the moved address, then — conditional on where
the re-trace lands — file the right legal instrument for that venue type, notify
the assigned investigator / IC3 reference, and set a follow-up. This is the
"monitor → trace → file" loop the incumbents automate, expressed as a reviewable
checklist.

PURE + deterministic: ``build_incident_plan(alert, ...)`` reads a
``RecoveryAlert`` (duck-typed) + optional case context and emits an ordered
``IncidentPlan``. It NEVER claims where the funds went — the destination is
unknown until the re-trace runs, so the freeze/subpoena steps are explicitly
CONDITIONAL ("if the re-trace lands at a VASP deposit → …"). Nothing is
fabricated; no action is executed here (the plan is a recommendation).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_URGENCY_FOR = {"critical": "immediate", "high": "same-day", "info": "routine"}


@dataclass(frozen=True)
class IncidentStep:
    """One ordered action in the response plan."""
    order: int
    action: str
    target: str
    urgency: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "action": self.action,
            "target": self.target,
            "urgency": self.urgency,
            "rationale": self.rationale,
        }


@dataclass
class IncidentPlan:
    """An ordered recovery response to one alert."""
    address: str
    chain: str
    alert_kind: str
    severity: str
    steps: list[IncidentStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "chain": self.chain,
            "alert_kind": self.alert_kind,
            "severity": self.severity,
            "steps": [s.to_dict() for s in self.steps],
            "step_count": len(self.steps),
        }


def build_incident_plan(
    alert: Any,
    *,
    ic3_case_id: str | None = None,
    le_contact: str | None = None,
    investigation_id: str | None = None,
) -> IncidentPlan:
    """PURE: a D6 ``RecoveryAlert`` (or dict) → an ordered ``IncidentPlan``.

    Severity drives urgency. The freeze/subpoena step is CONDITIONAL on the
    re-trace result (we don't know the destination venue yet — never assume it).
    Always re-trace first; always notify + set a follow-up.
    """
    def _f(name: str, default: Any = "") -> Any:
        if isinstance(alert, dict):
            return alert.get(name, default)
        return getattr(alert, name, default)

    address = str(_f("address") or "")
    chain = str(_f("chain") or "")
    kind = str(_f("kind") or "movement")
    severity = str(_f("severity") or "high")
    delta = str(_f("delta_usd") or "")
    urgency = _URGENCY_FOR.get(severity, "same-day")

    steps: list[IncidentStep] = []
    n = 0

    def add(action: str, target: str, rationale: str, *, urg: str | None = None) -> None:
        nonlocal n
        n += 1
        steps.append(IncidentStep(
            order=n, action=action, target=target,
            urgency=urg or urgency, rationale=rationale,
        ))

    # 1. Always: re-trace the moved address to find the NEW destination.
    add(
        "re-trace", address,
        f"Funds moved ({delta}); re-run the trace from this address to identify "
        "the current destination before acting.",
    )

    # 2. Venue-conditional response (we don't know the venue until step 1 runs).
    if kind in ("freezable_outflow", "tracked_outflow"):
        add(
            "freeze-or-subpoena (conditional on re-trace)",
            "destination venue from step 1",
            "IF the re-trace lands at a VASP deposit address → file an "
            "exchange-subpoena / 314(b) to that exchange; IF at an "
            "issuer-controlled token balance → file an issuer freeze request; "
            "IF at a mixer/non-custodial endpoint → mark UNRECOVERABLE and keep "
            "monitoring. Do not pre-assume the venue.",
        )
    elif kind == "freezable_inflow":
        add(
            "file freeze request",
            f"{address} ({chain})",
            "Funds arrived at a freezable address — file/refresh the freeze "
            "request with the controlling issuer/exchange while they are present.",
        )
    else:  # dormant_reactivation / other
        add(
            "tighten monitoring + prep",
            address,
            "Dormant funds reactivated; raise the watch frequency and prepare "
            "freeze templates so a move toward a freezable venue can be acted on "
            "within minutes.",
            urg="same-day",
        )

    # 3. Always: notify LE / investigator with the case reference.
    le_target = le_contact or (f"IC3 ref {ic3_case_id}" if ic3_case_id else "assigned investigator")
    add(
        "notify law-enforcement / investigator", le_target,
        "Report the movement and the planned action so any parallel LE process "
        "(MLAT, seizure warrant) can be coordinated."
        + (f" Reference IC3 case {ic3_case_id}." if ic3_case_id else ""),
    )

    # 4. Always: record + set a follow-up on the watchlist.
    add(
        "update watchlist + set follow-up",
        f"investigation {investigation_id}" if investigation_id else "watchlist entry",
        "Log this alert + the action taken and schedule a follow-up re-check so "
        "the next movement is caught.",
        urg="routine",
    )

    return IncidentPlan(
        address=address, chain=chain, alert_kind=kind, severity=severity, steps=steps,
    )


def build_incident_plans(
    alerts: Any,
    *,
    ic3_case_id: str | None = None,
    le_contact: str | None = None,
    investigation_id: str | None = None,
) -> list[dict[str, Any]]:
    """Convenience: plans (as dicts) for a list of alerts, highest-severity
    first (preserving the alerts' incoming order within a severity)."""
    rank = {"critical": 0, "high": 1, "info": 2}
    out = [
        build_incident_plan(
            a, ic3_case_id=ic3_case_id, le_contact=le_contact,
            investigation_id=investigation_id,
        )
        for a in (alerts or [])
    ]
    out.sort(key=lambda p: rank.get(p.severity, 9))
    return [p.to_dict() for p in out]


__all__ = (
    "IncidentStep",
    "IncidentPlan",
    "build_incident_plan",
    "build_incident_plans",
)
