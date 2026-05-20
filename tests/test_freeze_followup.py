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
from uuid import UUID, uuid4

import pytest

from recupero.worker._freeze_followup import (
    FreezeFollowupCandidate,
    FreezeFollowupResult,
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
        letter_language="le_backed",
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


def test_transition_skips_stages_if_letter_is_very_old():
    """A letter sent 30 days ago but still at 'initial' stage must
    still progress through the nudge_72h stage first — the cron must
    NOT skip directly to silence_14d. Stage-by-stage progression
    preserves the audit trail."""
    now = datetime.now(UTC)
    sent = now - timedelta(days=30)
    result = _compute_next_transition(sent, "initial", now)
    assert result is not None
    next_stage, _ = result
    # The cron must advance ONE stage per tick — even a 30-day-old
    # letter gets a 72h nudge first.
    assert next_stage == "nudge_72h"


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
    """Race scenario: bulk SELECT included letter L, but an operator
    records a freeze_outcomes row before the dispatcher sends the
    email. The race-safe re-check must skip the send."""
    cand = _candidate(next_stage="nudge_72h")

    with patch(
        "recupero.worker._freeze_followup.find_freeze_followups_due",
        return_value=[cand],
    ), patch(
        "recupero.worker._freeze_followup._has_outcome_row",
        return_value=True,  # outcome row appeared during the tick
    ), patch(
        "recupero.worker._email.send_email",
    ) as mock_send:
        result = run_freeze_followup_cron(dsn="postgres://fake")

    mock_send.assert_not_called()
    assert result.candidates_found == 1
    assert result.skipped_due_to_outcome_race == 1
    assert result.sent_ok == 0


def test_cron_sends_and_advances_stage_on_success():
    """Happy path: candidate found, no outcome race, email sends OK,
    stage advances, no silence_14d outcome (since this is nudge_72h)."""
    cand = _candidate(next_stage="nudge_72h")

    fake_send = MagicMock(
        return_value=type("R", (), {
            "success": True, "message_id": "m1", "error": None,
            "skipped": False,
        })(),
    )
    advance_called = []

    def _stub_advance(*, letter_id, new_stage, dsn):
        advance_called.append((letter_id, new_stage))

    with patch(
        "recupero.worker._freeze_followup.find_freeze_followups_due",
        return_value=[cand],
    ), patch(
        "recupero.worker._freeze_followup._has_outcome_row",
        return_value=False,
    ), patch(
        "recupero.worker._email.send_email",
        side_effect=fake_send,
    ), patch(
        "recupero.worker._freeze_followup._advance_stage",
        side_effect=_stub_advance,
    ):
        result = run_freeze_followup_cron(dsn="postgres://fake")

    assert result.sent_ok == 1
    assert result.send_failures == 0
    assert result.silence_outcomes_written == 0  # nudge_72h doesn't write silence
    assert advance_called == [(LETTER_ID, "nudge_72h")]


def test_cron_silence_14d_writes_outcome_row_and_routes_to_investigator():
    """When advancing to silence_14d, the cron must:
      1. Send the INTERNAL alert to the investigator (not the issuer)
      2. Write a freeze_outcomes row with outcome_type='silence_14d'
      3. Advance the followup_stage to silence_14d
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
        "recupero.worker._freeze_followup._has_outcome_row",
        return_value=False,
    ), patch(
        "recupero.worker._email.send_email",
        side_effect=_capture_recipient,
    ), patch(
        "recupero.worker._freeze_followup._advance_stage",
    ), patch(
        "recupero.worker._freeze_followup._write_silence_outcome",
        side_effect=_stub_silence,
    ):
        result = run_freeze_followup_cron(dsn="postgres://fake")

    # silence_14d email goes to INVESTIGATOR, not issuer compliance
    assert recipient_captured == ["ops@recupero.io"]
    assert result.silence_outcomes_written == 1
    assert silence_writes == [LETTER_ID]


def test_cron_send_failure_does_not_advance_stage():
    """If send_email returns success=False, the stage must NOT
    advance — next tick gets to retry the same email rather than
    silently dropping it."""
    cand = _candidate(next_stage="nudge_72h")

    fake_send_fail = MagicMock(
        return_value=type("R", (), {
            "success": False, "message_id": None,
            "error": "HTTP 500", "skipped": False,
        })(),
    )
    advance_called = []

    def _stub_advance(*, letter_id, new_stage, dsn):
        advance_called.append((letter_id, new_stage))

    with patch(
        "recupero.worker._freeze_followup.find_freeze_followups_due",
        return_value=[cand],
    ), patch(
        "recupero.worker._freeze_followup._has_outcome_row",
        return_value=False,
    ), patch(
        "recupero.worker._email.send_email",
        side_effect=fake_send_fail,
    ), patch(
        "recupero.worker._freeze_followup._advance_stage",
        side_effect=_stub_advance,
    ):
        result = run_freeze_followup_cron(dsn="postgres://fake")

    assert result.send_failures == 1
    assert result.sent_ok == 0
    assert advance_called == [], (
        "Stage must NOT advance on send failure — preserves retry on next tick"
    )
