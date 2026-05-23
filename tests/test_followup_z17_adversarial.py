"""RIGOR-Jacob Z17: adversarial-input hardening for the weekly
engagement follow-up cron (worker/_followup.py).

Bugs covered:

* Z17-F1: run_followup_cron lacked a per-row try/except — one bad
  candidate (e.g. naive-datetime in engagement_started_at, or a
  rendering exception inside send_followup that escaped its inner
  try/excepts) crashed the entire batch and silently skipped every
  remaining engagement for the day. Confirmed by patching
  send_followup to raise on row #1 of a 3-row batch; pre-fix the
  whole batch raised; post-fix rows #2 and #3 are still processed.

* Z17-F2: _build_status_summary used a non-defensive
  ``"It's been {days_since} days"`` format that produced
  ``"It's been -3 days since your engagement began."`` when the
  operator set engagement_started_at in the future (clock skew or
  data entry error). Reads as nonsense to the victim. Pre-fix
  ``days_since`` was passed through unchecked; post-fix it's
  clamped at 0 before rendering.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from recupero.worker import _followup as fu_mod
from recupero.worker._followup import (
    FollowupCandidate,
    _build_status_summary,
    run_followup_cron,
)


def _mk_candidate(*, days_ago: int = 7, email: str = "v@example.com") -> FollowupCandidate:
    now = datetime.now(UTC)
    return FollowupCandidate(
        investigation_id=uuid4(),
        case_id=uuid4(),
        victim_email=email,
        victim_name="Jane Doe",
        engagement_started_at=now - timedelta(days=days_ago),
        last_followup_sent_at=None,
        chain="ethereum",
        seed_address="0x" + "a" * 40,
        freezable_issuers=["Circle"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Z17-F1: one bad row must NOT kill the whole batch
# ─────────────────────────────────────────────────────────────────────────────


def test_one_failing_row_does_not_crash_remaining_batch() -> None:
    """Three eligible candidates. send_followup raises on the first.
    The cron MUST log the failure and continue processing rows 2 and
    3 — silently skipping the day's other followups because of one
    bad row violates the 30-day weekly-status commitment."""
    c1 = _mk_candidate(days_ago=7)
    c2 = _mk_candidate(days_ago=14)
    c3 = _mk_candidate(days_ago=21)

    calls: list[FollowupCandidate] = []

    def fake_send(*, candidate: FollowupCandidate, dsn: str) -> bool:
        calls.append(candidate)
        if candidate is c1:
            raise RuntimeError(
                "synthetic crash mid-render (e.g. naive datetime subtract)"
            )
        return True

    with patch.object(
        fu_mod, "find_followups_due", return_value=[c1, c2, c3]
    ), patch.object(fu_mod, "send_followup", side_effect=fake_send):
        result = run_followup_cron(dsn="dummy://")

    assert len(calls) == 3, (
        f"all 3 candidates should be attempted regardless of #1's crash; "
        f"got {len(calls)} attempts"
    )
    assert result["candidates"] == 3
    assert result["sent"] == 2
    assert result["failed"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Z17-F2: negative days_since must not render "-N days"
# ─────────────────────────────────────────────────────────────────────────────


def test_status_summary_clamps_negative_days_since() -> None:
    """Engagement_started_at in the future (operator data entry bug
    / clock skew) MUST NOT produce ``"It's been -3 days since"`` in
    the victim's email. The renderer should clamp to >= 0."""
    c = _mk_candidate(days_ago=-3)  # future start date
    summary = _build_status_summary(
        candidate=c, recent_actions=[], days_since=-3,
    )
    assert "-3" not in summary, (
        f"negative days_since leaked into rendered prose: {summary!r}"
    )
    # The fresh-engagement branch (days_since < 3) catches negatives
    # too because -3 < 3, so the freshness message is what gets
    # rendered. But the inline "{days_since} days in" must read 0.
    assert "0 days in" in summary or "just begun" in summary
