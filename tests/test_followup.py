"""Tests for the weekly engagement follow-up cron.

The cron is invoked via ``recupero-worker --send-followups`` once
daily. It queries investigations for active engagements due for
a status update and sends one follow-up email per eligible row.

Most of the testable surface here is the prose-helper logic +
candidate dataclass shape + status-summary heuristics. The DB
query and email-send paths are integration concerns covered by
end-to-end smoke against the live DB (operator runs
``--send-followups`` after marking an investigation engaged).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import pytest

from recupero.worker._followup import (
    FollowupCandidate,
    _build_next_steps,
    _build_status_summary,
    _describe_email_action,
    _ENGAGEMENT_WINDOW_DAYS,
    _FOLLOWUP_CADENCE_DAYS,
)


def _candidate(
    *,
    engagement_days_ago: int = 7,
    last_followup_days_ago: int | None = None,
    freezable_issuers: list[str] | None = None,
) -> FollowupCandidate:
    now = datetime.now(timezone.utc)
    return FollowupCandidate(
        investigation_id=uuid4(),
        case_id=uuid4(),
        victim_email="victim@example.com",
        victim_name="Jane Doe",
        engagement_started_at=now - timedelta(days=engagement_days_ago),
        last_followup_sent_at=(
            now - timedelta(days=last_followup_days_ago)
            if last_followup_days_ago is not None else None
        ),
        chain="ethereum",
        seed_address="0x" + "a" * 40,
        freezable_issuers=freezable_issuers or ["Circle", "Tether"],
    )


# ---- _describe_email_action ---- #


def test_describe_victim_summary() -> None:
    """victim_summary email type has specific description."""
    desc = _describe_email_action(
        "victim_summary", "jane@example.com",
        "Recupero Investigation Summary"
    )
    assert "Diagnostic summary" in desc
    assert "jane@example.com" in desc


def test_describe_freeze_letter() -> None:
    desc = _describe_email_action(
        "freeze_letter", "compliance@circle.com",
        "Freeze Request"
    )
    assert "freeze request" in desc.lower()
    assert "compliance@circle.com" in desc


def test_describe_le_handoff() -> None:
    desc = _describe_email_action(
        "le_handoff", "cryptocurrency@fbi.gov",
        "LE Handoff"
    )
    assert "Law-enforcement handoff" in desc
    assert "cryptocurrency@fbi.gov" in desc


def test_describe_followup_email() -> None:
    """Prior follow-up emails appear in the action log too — so
    week-4 followup shows week-1/2/3 follow-ups in its actions
    section. Confirms the recursive-action pattern."""
    desc = _describe_email_action(
        "followup_w2", "victim@example.com",
        "Status update"
    )
    assert "weekly status update" in desc


def test_describe_unknown_email_type_falls_back() -> None:
    """Unknown email type → generic 'email sent to X' description."""
    desc = _describe_email_action(
        "weird_type", "x@example.com",
        "Some subject"
    )
    assert "Email sent to x@example.com" in desc


# ---- _build_status_summary ---- #


def test_status_fresh_engagement_acknowledged() -> None:
    """Day-0 or day-1 engagement: status acknowledges the engagement
    just started and letters are being prepared."""
    c = _candidate(engagement_days_ago=1)
    summary = _build_status_summary(
        candidate=c, recent_actions=[], days_since=1,
    )
    assert "just begun" in summary
    assert "1 days in" in summary
    assert "5-business-day" in summary


def test_status_no_freeze_or_le_sent() -> None:
    """Mid-engagement with no actions taken: status notes the gap."""
    c = _candidate(engagement_days_ago=10)
    summary = _build_status_summary(
        candidate=c, recent_actions=[], days_since=10,
    )
    assert "10 days since" in summary
    assert "have not yet been sent" in summary
    # LE handoff (singular) → "has not yet been delivered"
    assert "has not yet been delivered" in summary


def test_status_freeze_sent_le_not() -> None:
    """Partial progress: freeze sent, LE not yet."""
    c = _candidate(engagement_days_ago=10)
    actions = [
        {"timestamp": "2026-01-05",
         "description": "Compliance freeze request sent to compliance@circle.com."},
        {"timestamp": "2026-01-05",
         "description": "Compliance freeze request sent to compliance@tether.com."},
    ]
    summary = _build_status_summary(
        candidate=c, recent_actions=actions, days_since=10,
    )
    assert "2 issuer" in summary  # 2 freeze letters sent
    assert "has not yet been delivered" in summary  # LE not sent (singular subject)


def test_status_both_sent() -> None:
    """All major actions done — status reflects both freeze + LE sent."""
    c = _candidate(engagement_days_ago=14)
    actions = [
        {"timestamp": "2026-01-05",
         "description": "Compliance freeze request sent to compliance@circle.com."},
        {"timestamp": "2026-01-06",
         "description": "Law-enforcement handoff package sent to cryptocurrency@fbi.gov."},
    ]
    summary = _build_status_summary(
        candidate=c, recent_actions=actions, days_since=14,
    )
    assert "1 issuer" in summary
    assert "has been delivered" in summary or "has been delivered." in summary


# ---- _build_next_steps ---- #


def test_next_steps_freshly_engaged() -> None:
    """No actions yet → next steps prioritize sending the letters."""
    c = _candidate(engagement_days_ago=1)
    steps = _build_next_steps(candidate=c, recent_actions=[])
    assert len(steps) >= 3
    # First step: send compliance letters
    assert any("compliance freeze" in s.lower() for s in steps)
    # Second step: deliver LE handoff
    assert any("law-enforcement" in s.lower() for s in steps)


def test_next_steps_post_freeze_send() -> None:
    """After freeze letters sent → next step is follow-up, not
    initial send."""
    c = _candidate(engagement_days_ago=7)
    actions = [
        {"timestamp": "2026-01-05",
         "description": "Compliance freeze request sent to compliance@circle.com."},
    ]
    steps = _build_next_steps(candidate=c, recent_actions=actions)
    # First step shifts from "send" to "follow up"
    assert any("Follow up" in s and "compliance" in s.lower() for s in steps)
    # No "send the freeze requests" — we already did that
    assert not any(s.startswith("Send compliance freeze") for s in steps)


def test_next_steps_post_le_send() -> None:
    """After LE handoff delivered → next step is coordination, not
    initial send."""
    c = _candidate(engagement_days_ago=7)
    actions = [
        {"timestamp": "2026-01-06",
         "description": "Law-enforcement handoff package sent to cryptocurrency@fbi.gov."},
    ]
    steps = _build_next_steps(candidate=c, recent_actions=actions)
    assert any("Coordinate" in s and "law-enforcement" in s.lower() for s in steps)
    # No "deliver the LE handoff" — we already did
    assert not any("Deliver the law-enforcement" in s for s in steps)


def test_next_steps_always_includes_watch_perpetrator_wallets() -> None:
    """Every follow-up suggests watching for on-chain activity —
    standard hygiene that doesn't depend on what's been done."""
    c = _candidate(engagement_days_ago=10)
    steps = _build_next_steps(candidate=c, recent_actions=[])
    assert any("on-chain activity" in s for s in steps)


# ---- timing constants ---- #


def test_engagement_window_is_30_days() -> None:
    """Lock the 30-day commitment from the engagement letter."""
    assert _ENGAGEMENT_WINDOW_DAYS == 30


def test_followup_cadence_is_6_days() -> None:
    """6-day cadence — slightly under 7 so the time-of-day doesn't
    drift later week-over-week."""
    assert _FOLLOWUP_CADENCE_DAYS == 6


# ---- FollowupCandidate dataclass ---- #


def test_candidate_required_fields() -> None:
    """All required fields present + types correct."""
    c = _candidate()
    assert isinstance(c.investigation_id, type(uuid4()))
    assert c.victim_email == "victim@example.com"
    assert c.victim_name == "Jane Doe"
    assert isinstance(c.engagement_started_at, datetime)


def test_candidate_freezable_issuers_optional() -> None:
    """freezable_issuers is nullable for cases that didn't populate
    that column."""
    now = datetime.now(timezone.utc)
    c = FollowupCandidate(
        investigation_id=uuid4(),
        case_id=None,
        victim_email="x@example.com",
        victim_name="X",
        engagement_started_at=now - timedelta(days=5),
        last_followup_sent_at=None,
        chain="ethereum",
        seed_address="0x" + "a" * 40,
        freezable_issuers=None,
    )
    assert c.freezable_issuers is None
