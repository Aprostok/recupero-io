"""Roadmap-#1 v3 item #3: alert → auto-draft → human-gate freeze loop.

A freezable_inflow/outflow recovery alert becomes a pre-filled FreezeDraft that
is enqueued into the human-review queue (awaiting_review) — NEVER auto-sent.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

from recupero.monitoring.freeze_draft import (
    FreezeDraft,
    draft_freeze_from_alert,
    enqueue_freeze_drafts,
    render_freeze_draft_body,
)
from recupero.monitoring.recovery_alerts import RecoveryAlert, evaluate_recovery_alerts

_ADDR = "0x" + "ab" * 20


def _alert(kind, *, inv="inv-1", address=_ADDR, label=None):
    return RecoveryAlert(
        address=address, chain="ethereum", severity="high", kind=kind,
        delta_usd="$70,000.00", dormant_days=None, role="current_holder",
        label_name=label, message="m", recommended_action="a",
        investigation_id=inv,
    )


def test_draft_only_for_freeze_actionable_kinds() -> None:
    assert isinstance(draft_freeze_from_alert(_alert("freezable_inflow")), FreezeDraft)
    assert isinstance(draft_freeze_from_alert(_alert("freezable_outflow")), FreezeDraft)
    # re-trace prompts are NOT freeze-actionable
    assert draft_freeze_from_alert(_alert("tracked_outflow")) is None
    assert draft_freeze_from_alert(_alert("dormant_reactivation")) is None


def test_draft_requires_originating_case() -> None:
    # Without an investigation_id we can't attach a review row → no draft.
    assert draft_freeze_from_alert(_alert("freezable_inflow", inv=None)) is None
    assert draft_freeze_from_alert(_alert("freezable_inflow", inv="")) is None


def test_draft_body_marks_human_approval_and_escapes() -> None:
    d = draft_freeze_from_alert(_alert("freezable_inflow", inv="case-42"))
    assert d is not None
    assert "AWAITING HUMAN APPROVAL" in d.body
    assert "NOT sent" in d.body
    assert "case-42" in d.body
    assert d.status == "awaiting_review"
    # HTML-escape an attacker-influenced label
    body = render_freeze_draft_body(
        investigation_id="i", address=_ADDR, chain="ethereum",
        kind="freezable_inflow", delta_usd="$1.00", role="hop",
        label_name="<script>alert(1)</script>",
    )
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_enqueue_writes_drafts_only_for_actionable(tmp_path) -> None:
    alerts = [
        _alert("freezable_inflow", address="0x" + "11" * 20),
        _alert("tracked_outflow", address="0x" + "22" * 20),   # skipped
        _alert("freezable_outflow", address="0x" + "33" * 20),
        _alert("freezable_inflow", inv=None, address="0x" + "44" * 20),  # no case → skipped
    ]
    # dsn=None → no DB insert, but draft artifacts ARE written (best-effort).
    written = enqueue_freeze_drafts(alerts, out_dir=tmp_path, dsn=None)
    assert len(written) == 2
    for p in written:
        assert p.name.startswith("freeze_request_draft_")
        assert p.is_file()
        assert "AWAITING HUMAN APPROVAL" in p.read_text(encoding="utf-8")


def test_enqueue_two_cases_same_address_get_distinct_drafts(tmp_path) -> None:
    # roadmap-v4 #4 collision fix: two CASES watching the SAME address must
    # produce two distinct artifacts — previously the filename keyed only on
    # (address, kind), so the second draft overwrote the first and BOTH review
    # rows pointed at one file carrying only the second case's id.
    alerts = [
        _alert("freezable_inflow", inv="case-aaaa"),
        _alert("freezable_inflow", inv="case-bbbb"),
    ]
    written = enqueue_freeze_drafts(alerts, out_dir=tmp_path, dsn=None)
    assert len(written) == 2
    assert len({p.name for p in written}) == 2          # distinct filenames
    bodies = {p.name: p.read_text(encoding="utf-8") for p in written}
    assert sum("case-aaaa" in b for b in bodies.values()) == 1
    assert sum("case-bbbb" in b for b in bodies.values()) == 1


def test_evaluate_recovery_alerts_threads_investigation_id() -> None:
    change = SimpleNamespace(
        address=_ADDR, chain="ethereum", role="current_holder",
        label_name="Circle", is_freezeable=True,
        delta_usd=Decimal("70000"), tx_count_delta=1,
        prior_taken_at=None, new_taken_at=None, investigation_id="inv-77",
    )
    alerts = evaluate_recovery_alerts([change], min_move_usd=Decimal("1"))
    assert len(alerts) == 1
    assert alerts[0].kind == "freezable_inflow"
    assert alerts[0].investigation_id == "inv-77"
    # and that alert drafts cleanly end-to-end
    assert isinstance(draft_freeze_from_alert(alerts[0]), FreezeDraft)
