"""Tests for v0.21.0 freeze-letter follow-up cron.

Covers:
  * _compute_next_transition — pure-function state machine
  * Stage thresholds (72h / 7d / 14d) — boundary correctness
  * Race-safe skip when a freeze_outcomes row appears mid-tick
  * Stage advance + silence_14d outcome write
  * Template rendering — all three templates render without
    StrictUndefined firing
  * No double-send: re-running the cron at the same moment is
    a no-op
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import UUID

from recupero.worker._freeze_followup import (
    FreezeFollowupCandidate,
    _compute_next_transition,
    _render_followup_html,
    run_freeze_followup_cron,
)

LETTER_ID = UUID("66666666-6666-6666-6666-666666666666")
CASE_ID = UUID("77777777-7777-7777-7777-777777777777")
INV_ID = UUID("88888888-8888-8888-8888-888888888888")


def _candidate(
    *,
    next_stage: str,
    template_name: str = "freeze_followup_nudge.html.j2",
    sent_at: datetime | None = None,
    contact_email: str | None = "compliance@tether.to",
    investigator_email: str | None = "ops@recupero.io",
) -> FreezeFollowupCandidate:
    """Build a FreezeFollowupCandidate for template / dispatch tests."""
    if sent_at is None:
        sent_at = datetime.now(UTC) - timedelta(hours=72, minutes=10)
    return FreezeFollowupCandidate(
        letter_id=LETTER_ID,
        case_id=CASE_ID,
        investigation_id=INV_ID,
        issuer="Tether",
        target_address="0xT" + "0" * 39,
        chain="ethereum",
        asset_symbol="USDT",
        requested_freeze_usd=1_200_000,
        letter_subject="Freeze request: case RCP-2026-0427",
        letter_tier="le_backed",
        contact_email=contact_email,
        sent_at=sent_at,
        last_followup_sent_at=None,
        followup_stage="initial",
        next_stage=next_stage,
        template_name=template_name,
        investigator_email=investigator_email,
        ic3_case_id="I-2026-12345",
        jurisdiction="BVI",
    )


# ─────────────────────────────────────────────────────────────────────────────
# _compute_next_transition — pure-function state machine
# ─────────────────────────────────────────────────────────────────────────────


def test_transition_initial_before_72h_returns_none():
    """A letter sent 71 hours ago is not yet eligible for nudge_72h."""
    now = datetime.now(UTC)
    sent = now - timedelta(hours=71)
    assert _compute_next_transition(sent, "initial", now) is None


def test_transition_initial_at_72h_fires_nudge():
    """Exactly 72 hours after sent_at, the nudge_72h transition fires."""
    now = datetime.now(UTC)
    sent = now - timedelta(hours=72)
    result = _compute_next_transition(sent, "initial", now)
    assert result is not None
    next_stage, template = result
    assert next_stage == "nudge_72h"
    assert template == "freeze_followup_nudge.html.j2"


def test_transition_nudge_before_7d_returns_none():
    """A letter at nudge_72h but only 6 days old is not yet ready for
    escalation_7d."""
    now = datetime.now(UTC)
    sent = now - timedelta(days=6)
    assert _compute_next_transition(sent, "nudge_72h", now) is None


def test_transition_nudge_at_7d_fires_escalation():
    """7 days after sent_at, an existing nudge_72h advances to escalation_7d."""
    now = datetime.now(UTC)
    sent = now - timedelta(days=7)
    result = _compute_next_transition(sent, "nudge_72h", now)
    assert result is not None
    next_stage, template = result
    assert next_stage == "escalation_7d"
    assert template == "freeze_followup_escalation.html.j2"


def test_transition_escalation_at_14d_fires_silence():
    """14 days after sent_at, an existing escalation_7d advances to silence_14d."""
    now = datetime.now(UTC)
    sent = now - timedelta(days=14)
    result = _compute_next_transition(sent, "escalation_7d", now)
    assert result is not None
    next_stage, template = result
    assert next_stage == "silence_14d"
    assert template == "freeze_followup_silence.html.j2"


def test_transition_silence_is_terminal():
    """A letter already at silence_14d does NOT transition further —
    silence is the terminal stage in this cron's view (later
    silence_30d / silence_90d are operator-recorded via the ops CLI,
    not auto-advanced)."""
    now = datetime.now(UTC)
    sent = now - timedelta(days=90)  # very old
    assert _compute_next_transition(sent, "silence_14d", now) is None


def test_transition_jumps_to_highest_stage_for_stale_letters():
    """v0.21.1 audit-fix A3: a letter sent 30 days ago at stage='initial'
    (cron downtime, manual rollback) jumps directly to silence_14d
    rather than firing three escalating emails across consecutive
    cron ticks.

    Pre-v0.21.1 the function returned the NEXT stage only, so a stale
    letter walked initial→nudge_72h→escalation_7d→silence_14d across
    three cron ticks (~12-18 hours apart at the recommended 6h cadence),
    sending three issuer-facing emails inside half a day — looks erratic
    from the issuer's perspective and races a real outcome being recorded.

    Now: the function picks the most-advanced stage whose threshold
    has elapsed AND is strictly after the current stage. silence_14d
    is the only INTERNAL stage (operator alert, not issuer-facing),
    so jumping straight there is safe — the issuer never sees the
    skipped nudge/escalation."""
    now = datetime.now(UTC)
    sent = now - timedelta(days=30)
    result = _compute_next_transition(sent, "initial", now)
    assert result is not None
    next_stage, _ = result
    assert next_stage == "silence_14d", (
        f"Expected stage-jump to silence_14d on a 30-day-old letter, "
        f"got {next_stage}"
    )


def test_transition_jumps_to_escalation_for_letter_aged_8_days():
    """An 8-day-old letter at stage='initial' jumps to escalation_7d
    (skipping nudge_72h) rather than walking the chain. silence_14d
    threshold not yet reached."""
    now = datetime.now(UTC)
    sent = now - timedelta(days=8)
    result = _compute_next_transition(sent, "initial", now)
    assert result is not None
    next_stage, _ = result
    assert next_stage == "escalation_7d"


def test_transition_clock_skew_returns_none():
    """v0.21.1 audit-fix A3: defensive — sent_at in the future
    (NTP skew between worker and DB) returns None rather than
    firing a nudge with negative elapsed."""
    now = datetime.now(UTC)
    sent = now + timedelta(hours=1)
    assert _compute_next_transition(sent, "initial", now) is None


# ─────────────────────────────────────────────────────────────────────────────
# Template rendering — all three templates render under StrictUndefined
# ─────────────────────────────────────────────────────────────────────────────


def test_render_nudge_template_succeeds():
    """The nudge_72h template renders without StrictUndefined firing
    given a minimal-shape candidate."""
    cand = _candidate(next_stage="nudge_72h",
                      template_name="freeze_followup_nudge.html.j2")
    html = _render_followup_html(
        cand,
        investigator_name="Jacob Test",
        investigator_entity="Recupero Investigations LLC",
    )
    assert "Tether" in html or "compliance" in html.lower()
    assert "USDT" in html
    assert "1,200,000" in html  # formatted USD amount


def test_render_escalation_template_succeeds():
    """The 7d escalation template renders cleanly."""
    cand = _candidate(
        next_stage="escalation_7d",
        template_name="freeze_followup_escalation.html.j2",
        sent_at=datetime.now(UTC) - timedelta(days=7, hours=1),
    )
    cand = FreezeFollowupCandidate(**{
        **cand.__dict__,
        "last_followup_sent_at": datetime.now(UTC) - timedelta(days=4),
    })
    html = _render_followup_html(
        cand,
        investigator_name="Jacob Test",
        investigator_entity="Recupero Investigations LLC",
    )
    assert "escalation" in html.lower() or "7-day" in html.lower()
    # IC3 reference must surface when present — high-stakes signal
    assert "I-2026-12345" in html


def test_render_silence_template_succeeds():
    """The 14d silence template renders as an INTERNAL alert (subject
    line tested separately)."""
    cand = _candidate(
        next_stage="silence_14d",
        template_name="freeze_followup_silence.html.j2",
        sent_at=datetime.now(UTC) - timedelta(days=14, hours=1),
    )
    html = _render_followup_html(
        cand,
        investigator_name="Jacob Test",
        investigator_entity="Recupero Investigations LLC",
    )
    # The internal-alert template recommends grand jury subpoena
    assert "subpoena" in html.lower()
    assert "MLAT" in html or "BVI" in html  # jurisdiction-specific advice
    assert "internal" in html.lower()  # banner text


# ─────────────────────────────────────────────────────────────────────────────
# run_freeze_followup_cron — orchestration smoke
# ─────────────────────────────────────────────────────────────────────────────


def test_cron_skips_candidate_when_outcome_appears_during_tick():
    """v0.21.1 (audit-fix C1): bulk SELECT included letter L, but an
    operator records a freeze_outcomes row before the dispatcher sends
    the email. The atomic claim UPDATE detects the outcome row via its
    NOT EXISTS clause and returns False → skip the send.
    """
    cand = _candidate(next_stage="nudge_72h")

    with patch(
        "recupero.worker._freeze_followup.find_freeze_followups_due",
        return_value=[cand],
    ), patch(
        "recupero.worker._freeze_followup._try_claim_stage_advance",
        return_value=False,  # claim lost (outcome row or concurrent tick)
    ), patch(
        "recupero.worker._email.send_email",
    ) as mock_send:
        result = run_freeze_followup_cron(dsn="postgres://fake")

    mock_send.assert_not_called()
    assert result.candidates_found == 1
    assert result.skipped_due_to_outcome_race == 1
    assert result.sent_ok == 0


def test_cron_sends_after_successful_claim():
    """v0.21.1 (audit-fix C1+E3): happy path. The claim UPDATE succeeds
    (advancing the stage AND verifying no outcome row exists), then
    the email send succeeds. No rollback needed; the stage was
    advanced as part of the claim."""
    cand = _candidate(next_stage="nudge_72h")

    fake_send = MagicMock(
        return_value=type("R", (), {
            "success": True, "message_id": "m1", "error": None,
            "skipped": False,
        })(),
    )
    claim_calls = []

    def _stub_claim(*, letter_id, current_stage, new_stage, dsn):
        claim_calls.append((letter_id, current_stage, new_stage))
        return True

    rollback_called = []

    def _stub_rollback(*, letter_id, previous_stage, dsn):
        rollback_called.append((letter_id, previous_stage))

    with patch(
        "recupero.worker._freeze_followup.find_freeze_followups_due",
        return_value=[cand],
    ), patch(
        "recupero.worker._freeze_followup._try_claim_stage_advance",
        side_effect=_stub_claim,
    ), patch(
        "recupero.worker._freeze_followup._rollback_stage_advance",
        side_effect=_stub_rollback,
    ), patch(
        "recupero.worker._email.send_email",
        side_effect=fake_send,
    ):
        result = run_freeze_followup_cron(dsn="postgres://fake")

    assert result.sent_ok == 1
    assert result.send_failures == 0
    assert result.silence_outcomes_written == 0
    assert claim_calls == [(LETTER_ID, "initial", "nudge_72h")]
    assert rollback_called == [], "Successful send must not roll back the claim"


def test_cron_silence_14d_writes_outcome_row_and_routes_to_investigator():
    """When advancing to silence_14d, the cron must:
      1. Send the INTERNAL alert to the investigator (not the issuer)
      2. Write a freeze_outcomes row with outcome_type='silence_14d'
      3. Advance the followup_stage to silence_14d (done via the claim)
    """
    cand = _candidate(
        next_stage="silence_14d",
        template_name="freeze_followup_silence.html.j2",
        sent_at=datetime.now(UTC) - timedelta(days=14, hours=1),
    )

    recipient_captured = []

    def _capture_recipient(**kwargs):
        recipient_captured.append(kwargs.get("to"))
        return type("R", (), {
            "success": True, "message_id": "m1", "error": None,
            "skipped": False,
        })()

    silence_writes = []

    def _stub_silence(*, letter_id, dsn):
        silence_writes.append(letter_id)

    with patch(
        "recupero.worker._freeze_followup.find_freeze_followups_due",
        return_value=[cand],
    ), patch(
        "recupero.worker._freeze_followup._try_claim_stage_advance",
        return_value=True,
    ), patch(
        "recupero.worker._email.send_email",
        side_effect=_capture_recipient,
    ), patch(
        "recupero.worker._freeze_followup._write_silence_outcome",
        side_effect=_stub_silence,
    ):
        result = run_freeze_followup_cron(dsn="postgres://fake")

    # silence_14d email goes to INVESTIGATOR, not issuer compliance
    assert recipient_captured == ["ops@recupero.io"]
    assert result.silence_outcomes_written == 1
    assert silence_writes == [LETTER_ID]


def test_cron_send_failure_rolls_back_claim():
    """v0.21.1 (audit-fix C1+E3): when send_email fails AFTER the
    claim succeeded, the cron must roll back the stage so the next
    tick retries cleanly. Pre-v0.21.1 a send failure left the stage
    NOT advanced (claim-then-send pattern was reversed); the new
    pattern advances stage as part of the claim, so the failure path
    MUST roll back to restore retry-ability."""
    cand = _candidate(next_stage="nudge_72h")

    fake_send_fail = MagicMock(
        return_value=type("R", (), {
            "success": False, "message_id": None,
            "error": "HTTP 500", "skipped": False,
        })(),
    )
    rollback_called = []

    def _stub_rollback(*, letter_id, previous_stage, dsn):
        rollback_called.append((letter_id, previous_stage))

    with patch(
        "recupero.worker._freeze_followup.find_freeze_followups_due",
        return_value=[cand],
    ), patch(
        "recupero.worker._freeze_followup._try_claim_stage_advance",
        return_value=True,
    ), patch(
        "recupero.worker._freeze_followup._rollback_stage_advance",
        side_effect=_stub_rollback,
    ), patch(
        "recupero.worker._email.send_email",
        side_effect=fake_send_fail,
    ):
        result = run_freeze_followup_cron(dsn="postgres://fake")

    assert result.send_failures == 1
    assert result.sent_ok == 0
    assert rollback_called == [(LETTER_ID, "initial")], (
        "Stage advance must be ROLLED BACK on send failure so next "
        "tick retries the same letter rather than silently dropping it"
    )
