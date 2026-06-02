"""v0.35.13 (D6) — proactive recovery alerts.

Pins: freezable/tracked outflow → CRITICAL; dormant reactivation → HIGH;
freezable inflow → HIGH; below-threshold + NaN deltas raise nothing; dormant +
outflow escalates and is messaged as reactivation; severity+|Δ| sorting; the
evaluator never crashes on garbage; alerts are prompts to re-trace/file, not
destination claims.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

from recupero.monitoring.recovery_alerts import (
    evaluate_recovery_alerts,
    recovery_alerts_to_dict,
)

T0 = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def _change(**kw):
    base = {
        "address": "0x" + "a" * 40,
        "chain": "ethereum",
        "role": "holding",
        "label_name": None,
        "is_freezeable": False,
        "issuer": None,
        "asset_symbol": "USDC",
        "prior_taken_at": T0 - timedelta(days=1),
        "prior_usd": Decimal("1000"),
        "new_taken_at": T0,
        "new_usd": Decimal("0"),
        "new_tx_count": 5,
        "prior_tx_count": 4,
        "delta_usd": Decimal("-1000"),
        "tx_count_delta": 1,
        "reason": "balance dropped",
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_freezable_outflow_is_critical():
    a = evaluate_recovery_alerts([_change(is_freezeable=True, delta_usd=Decimal("-5000"))])
    assert len(a) == 1
    assert a[0].severity == "critical"
    assert a[0].kind == "freezable_outflow"
    assert "freeze" in a[0].recommended_action.lower()


def test_tracked_outflow_is_critical():
    a = evaluate_recovery_alerts([_change(is_freezeable=False, delta_usd=Decimal("-2000"))])
    assert a[0].severity == "critical"
    assert a[0].kind == "tracked_outflow"
    assert "re-run the trace" in a[0].recommended_action.lower()


def test_dormant_reactivation_is_high():
    # 60 days dormant, then a material INFLOW (not freezeable) → dormant_reactivation.
    a = evaluate_recovery_alerts([_change(
        is_freezeable=False,
        prior_taken_at=T0 - timedelta(days=60),
        delta_usd=Decimal("500"),
    )])
    assert a[0].severity == "high"
    assert a[0].kind == "dormant_reactivation"
    assert a[0].dormant_days == 60


def test_dormant_outflow_escalates_to_critical():
    a = evaluate_recovery_alerts([_change(
        is_freezeable=False,
        prior_taken_at=T0 - timedelta(days=90),
        delta_usd=Decimal("-3000"),
    )])
    assert a[0].severity == "critical"
    assert a[0].kind == "tracked_outflow"
    assert "reactivated" in a[0].message.lower()


def test_freezable_inflow_is_high():
    a = evaluate_recovery_alerts([_change(
        is_freezeable=True, delta_usd=Decimal("800"),
        prior_taken_at=T0 - timedelta(days=1),
    )])
    assert a[0].severity == "high"
    assert a[0].kind == "freezable_inflow"


def test_below_threshold_no_alert():
    a = evaluate_recovery_alerts(
        [_change(delta_usd=Decimal("-50"), tx_count_delta=0)],
        min_move_usd=Decimal("100"),
    )
    assert a == []


def test_nan_delta_no_crash_no_alert():
    a = evaluate_recovery_alerts([_change(delta_usd=Decimal("NaN"), tx_count_delta=0)])
    assert a == []


def test_sorting_critical_before_high_then_by_magnitude():
    changes = [
        _change(address="0x" + "b" * 40, is_freezeable=True, delta_usd=Decimal("900"),
                prior_taken_at=T0 - timedelta(days=1)),       # high freezable_inflow $900
        _change(address="0x" + "c" * 40, is_freezeable=True, delta_usd=Decimal("-100")),  # critical $100
        _change(address="0x" + "d" * 40, is_freezeable=True, delta_usd=Decimal("-9000")), # critical $9000
    ]
    a = evaluate_recovery_alerts(changes)
    assert [x.severity for x in a] == ["critical", "critical", "high"]
    # Within critical, larger magnitude first.
    assert a[0].delta_usd == "$-9,000.00"
    assert a[1].delta_usd == "$-100.00"


def test_to_dict_summary():
    a = evaluate_recovery_alerts([
        _change(is_freezeable=True, delta_usd=Decimal("-5000")),
        _change(address="0x" + "e" * 40, is_freezeable=True, delta_usd=Decimal("700"),
                prior_taken_at=T0 - timedelta(days=1)),
    ])
    d = recovery_alerts_to_dict(a)
    assert d["summary"]["total"] == 2
    assert d["summary"]["critical"] == 1
    assert d["summary"]["high"] == 1


def test_empty_and_garbage_inputs():
    assert evaluate_recovery_alerts([]) == []
    assert evaluate_recovery_alerts(None) == []
    # An object missing fields must not crash (duck-typed getattr).
    assert evaluate_recovery_alerts([SimpleNamespace()]) == []
