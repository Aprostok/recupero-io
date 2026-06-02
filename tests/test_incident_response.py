"""v0.35.18 (D4) — auto-incident response planner.

Pins: re-trace is always step 1; the freeze/subpoena step is CONDITIONAL on the
re-trace (no pre-assumed destination); LE notify carries the IC3 ref; severity →
urgency; multi-alert plans sort critical-first; and it consumes a real D6
RecoveryAlert. The plan recommends, never executes; nothing fabricated.
"""

from __future__ import annotations

from recupero.monitoring.incident_response import (
    build_incident_plan,
    build_incident_plans,
)
from recupero.monitoring.recovery_alerts import RecoveryAlert

A = "0x" + "a" * 40


def _alert(kind="tracked_outflow", severity="critical", **kw):
    base = {
        "address": A, "chain": "ethereum", "kind": kind, "severity": severity,
        "delta_usd": "$-5,000.00", "dormant_days": None, "role": "holding",
        "label_name": None, "message": "moving", "recommended_action": "re-trace",
    }
    base.update(kw)
    return base


def test_retrace_is_always_first_step():
    plan = build_incident_plan(_alert())
    assert plan.steps[0].order == 1
    assert "re-trace" in plan.steps[0].action
    assert plan.steps[0].target == A


def test_tracked_outflow_has_conditional_freeze_step():
    plan = build_incident_plan(_alert(kind="tracked_outflow", severity="critical"))
    step2 = plan.steps[1]
    assert "conditional" in step2.action.lower()
    # Must NOT pre-assume the venue — language is explicitly IF/THEN.
    assert "IF the re-trace lands" in step2.rationale
    assert step2.urgency == "immediate"   # critical → immediate


def test_freezable_inflow_files_freeze():
    plan = build_incident_plan(_alert(kind="freezable_inflow", severity="high",
                                      delta_usd="$800.00"))
    assert any("file freeze request" in s.action for s in plan.steps)


def test_dormant_reactivation_tightens_monitoring():
    plan = build_incident_plan(_alert(kind="dormant_reactivation", severity="high",
                                      dormant_days=90))
    assert any("monitoring" in s.action for s in plan.steps)


def test_le_notify_carries_ic3_ref():
    plan = build_incident_plan(_alert(), ic3_case_id="IC3-2026-0001")
    notify = next(s for s in plan.steps if "notify" in s.action)
    assert "IC3-2026-0001" in notify.target or "IC3-2026-0001" in notify.rationale


def test_steps_are_contiguously_ordered_and_end_with_followup():
    plan = build_incident_plan(_alert(), investigation_id="abc-123")
    assert [s.order for s in plan.steps] == list(range(1, len(plan.steps) + 1))
    assert "follow-up" in plan.steps[-1].action
    assert "abc-123" in plan.steps[-1].target


def test_build_plans_sorts_critical_first():
    alerts = [
        _alert(kind="dormant_reactivation", severity="high", address="0x" + "b" * 40),
        _alert(kind="tracked_outflow", severity="critical", address=A),
    ]
    plans = build_incident_plans(alerts)
    assert plans[0]["severity"] == "critical"
    assert plans[0]["address"] == A
    assert plans[1]["severity"] == "high"


def test_consumes_real_recovery_alert():
    alert = RecoveryAlert(
        address=A, chain="ethereum", severity="critical", kind="freezable_outflow",
        delta_usd="$-9,000.00", dormant_days=None, role="holding", label_name="Tether",
        message="freezable funds leaving", recommended_action="re-trace + freeze",
    )
    plan = build_incident_plan(alert)
    assert plan.to_dict()["alert_kind"] == "freezable_outflow"
    assert plan.to_dict()["step_count"] >= 4
    assert plan.steps[0].action.startswith("re-trace")
