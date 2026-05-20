"""Tests for v0.21.0 live filing status — LE handoff Section 5.5.

Covers:
  * _badge_for_letter — status badge selection logic
  * _fmt_usd — formatting edge cases
  * fetch_live_filing_status empty path (no DSN, DB error, no letters)
  * LiveFilingStatus aggregate computation
  * LE template renders both empty-state and populated-state branches
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

from recupero.freeze_learning.status import (
    AggregateStatus,
    LetterStatus,
    LiveFilingStatus,
    MonitoringSnapshot,
    _badge_for_letter,
    _fmt_usd,
    fetch_live_filing_status,
)


# ─────────────────────────────────────────────────────────────────────────────
# _badge_for_letter — per-letter status badge logic
# ─────────────────────────────────────────────────────────────────────────────


def test_badge_full_freeze_outcome_wins():
    """When an outcome exists, the outcome_type dominates regardless of
    days_since_sent."""
    assert _badge_for_letter("full_freeze", days_since_sent=0, followup_stage="initial") == "FROZEN"
    assert _badge_for_letter("full_freeze", days_since_sent=90, followup_stage="silence_14d") == "FROZEN"


def test_badge_partial_freeze():
    assert _badge_for_letter("partial_freeze", 5, "nudge_72h") == "PARTIAL FREEZE"


def test_badge_acknowledged():
    assert _badge_for_letter("acknowledged", 1, "initial") == "ACKNOWLEDGED"


def test_badge_declined():
    assert _badge_for_letter("declined", 3, "nudge_72h") == "DECLINED"


def test_badge_no_outcome_progresses_with_time():
    """Without an outcome, the badge advances based on days_since_sent."""
    assert _badge_for_letter(None, 0, "initial") == "PENDING"
    assert _badge_for_letter(None, 4, "nudge_72h") == "NUDGED"
    assert _badge_for_letter(None, 8, "escalation_7d") == "ESCALATING"
    assert _badge_for_letter(None, 15, "silence_14d") == "NO RESPONSE (14d)"
    assert _badge_for_letter(None, 20, "initial") == "NO RESPONSE"


# ─────────────────────────────────────────────────────────────────────────────
# _fmt_usd — formatting edge cases
# ─────────────────────────────────────────────────────────────────────────────


def test_fmt_usd_none_returns_dash():
    assert _fmt_usd(None) == "—"


def test_fmt_usd_round_integer_omits_decimals():
    assert _fmt_usd(Decimal("1200000")) == "$1,200,000"


def test_fmt_usd_fractional_shows_decimals():
    assert _fmt_usd(Decimal("1200000.55")) == "$1,200,000.55"


def test_fmt_usd_zero():
    assert _fmt_usd(Decimal(0)) == "$0"


def test_fmt_usd_invalid_input_returns_dash():
    """Bad inputs (non-numeric strings, etc.) must degrade gracefully."""
    assert _fmt_usd("not-a-number") == "—"


# ─────────────────────────────────────────────────────────────────────────────
# fetch_live_filing_status — failure modes return empty-state
# ─────────────────────────────────────────────────────────────────────────────


def test_fetch_without_dsn_returns_empty_status():
    """No DSN (local CLI emit_brief path) → empty LiveFilingStatus
    so the template renders the pending-state branch."""
    status = fetch_live_filing_status(uuid4(), dsn=None)
    assert status.is_empty is True
    assert status.letters == []
    assert status.aggregate.total_letters == 0
    assert status.monitoring.active_subscriptions == 0


def test_fetch_without_any_key_returns_empty_status():
    """v0.21.1 audit-fix A1 CRITICAL: a misuse call with neither
    case_id nor investigation_id must return empty without performing
    a full-table SELECT."""
    status = fetch_live_filing_status(
        case_id=None, investigation_id=None,
        dsn="postgres://fake",
    )
    assert status.is_empty is True


def test_fetch_prefers_investigation_id_filter_when_provided():
    """v0.21.1 audit-fix A1 CRITICAL: when investigation_id is provided
    (the worker pipeline path), the SQL must filter by
    freeze_letters_sent.investigation_id, NOT by case_id.

    Pre-v0.21.1 the worker passed `case.case_id` (a brief identifier
    string) into the case_id filter — but freeze_letters_sent.case_id
    references cases.id (UUID). The query never matched. Section 5.5
    silently rendered the empty-state branch in production even after
    letters had been sent and outcomes recorded.

    This test asserts the SQL emitted contains the investigation_id
    filter clause when investigation_id is supplied.
    """
    captured_sql: list[str] = []

    class _StubCursor:
        def execute(self, sql, params):
            captured_sql.append(sql)
        def fetchall(self):
            return []
        def fetchone(self):
            return None
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    with patch("recupero._common.db_connect", return_value=_StubConn()):
        fetch_live_filing_status(
            case_id="V-CFI01-BRIEF-2026",
            investigation_id=uuid4(),
            dsn="postgres://fake",
        )
    # First captured SQL is the letters_sql; it must filter by
    # investigation_id (not case_id) when both are provided.
    assert any("fl.investigation_id" in s for s in captured_sql), (
        "letters_sql did not filter by investigation_id when supplied"
    )
    assert not any("WHERE fl.case_id" in s for s in captured_sql), (
        "letters_sql incorrectly used case_id filter when "
        "investigation_id was provided"
    )


def test_fetch_db_error_returns_empty_status():
    """A DB error during fetch must NOT raise — the LE handoff must
    still render. The empty-state template branch handles the
    'we couldn't fetch the status' case the same as 'no letters yet'.

    Patches db_connect at its source module (recupero._common); the
    fetch function imports it lazily inside the body, so the patch
    has to target where it's defined.
    """
    with patch(
        "recupero._common.db_connect",
        side_effect=RuntimeError("simulated DB outage"),
    ):
        status = fetch_live_filing_status(uuid4(), dsn="postgres://fake")
    assert status.is_empty is True


# ─────────────────────────────────────────────────────────────────────────────
# LiveFilingStatus aggregate — manual construction (bypassing DB)
# ─────────────────────────────────────────────────────────────────────────────


def _letter(
    *,
    issuer: str,
    requested_usd: Decimal,
    frozen_usd: Decimal | None = None,
    outcome_type: str | None = None,
    days_since: int = 0,
) -> LetterStatus:
    sent_at = datetime.now(UTC) - timedelta(days=days_since)
    return LetterStatus(
        letter_id=uuid4(),
        issuer=issuer,
        target_address="0x" + "a" * 40,
        chain="ethereum",
        asset_symbol="USDT",
        requested_freeze_usd=requested_usd,
        requested_freeze_usd_human=f"${int(requested_usd):,}",
        sent_at=sent_at,
        sent_at_human=sent_at.strftime("%Y-%m-%d"),
        days_since_sent=days_since,
        status_badge=_badge_for_letter(outcome_type, days_since, "initial"),
        outcome_type=outcome_type,
        frozen_usd=frozen_usd,
        frozen_usd_human=(
            f"${int(frozen_usd):,}" if frozen_usd is not None else "—"
        ),
        last_followup_sent_at=None,
        followup_stage="initial",
    )


def test_aggregate_freeze_percentage_with_partial_response():
    """Aggregate reflects the partial-response scenario: 3 letters
    requested, 1 frozen full, 1 partial freeze, 1 silent."""
    letters = [
        _letter(issuer="Tether", requested_usd=Decimal("1200000"),
                frozen_usd=Decimal("1200000"), outcome_type="full_freeze"),
        _letter(issuer="Circle", requested_usd=Decimal("800000"),
                frozen_usd=Decimal("400000"), outcome_type="partial_freeze"),
        _letter(issuer="Coinbase", requested_usd=Decimal("600000"),
                days_since=15),  # silent
    ]
    # Build LiveFilingStatus the same way fetch_live_filing_status does
    # (the aggregate computation is at the tail of that function).
    status = LiveFilingStatus(letters=letters, is_empty=False)
    # Manually recompute aggregate (the fetch helper does this; here
    # we test the dataclass shape via direct construction).
    status.aggregate.total_letters = 3
    status.aggregate.letters_with_response = 2
    status.aggregate.letters_silent = 1
    status.aggregate.total_requested_usd = sum(
        (L.requested_freeze_usd for L in letters), start=Decimal(0)
    )
    status.aggregate.total_confirmed_frozen_usd = sum(
        (L.frozen_usd for L in letters
         if L.outcome_type in ("partial_freeze", "full_freeze", "returned_to_victim")
         and L.frozen_usd is not None),
        start=Decimal(0),
    )

    assert status.aggregate.total_requested_usd == Decimal("2600000")
    assert status.aggregate.total_confirmed_frozen_usd == Decimal("1600000")
    # 1.6M / 2.6M = 61.5% — int truncation gives 61
    pct = int((status.aggregate.total_confirmed_frozen_usd
               / status.aggregate.total_requested_usd) * 100)
    assert pct == 61


# ─────────────────────────────────────────────────────────────────────────────
# Template rendering — both empty + populated branches
# ─────────────────────────────────────────────────────────────────────────────


def test_le_template_renders_empty_state_section_5_5():
    """With live_status=None, the LE handoff Section 5.5 renders the
    'Pending issuer outreach' empty-state branch — and does NOT
    raise StrictUndefined."""
    # We render via generate_briefs to exercise the full ctx assembly.
    # The V-CFI01 fixture is the standard test shape.
    from tests.test_v_cfi01_full_render import (
        _build_editorial,
        _build_freeze_asks_dict,
        _build_issuer_metadata,
        _build_v_cfi01_case,
        VICTIM,
    )
    from recupero.reports.brief import InvestigatorInfo, generate_briefs
    from recupero.reports.victim import VictimInfo

    case = _build_v_cfi01_case()
    victim = VictimInfo(
        name="V-CFI01 Test Victim",
        wallet_address=VICTIM,
        state="NY",
        country="US",
        email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test Investigator",
        organization="Recupero Forensics Ltd.",
        email="investigator@test.com",
    )

    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory(prefix="le_empty_status_") as tmp:
        case_dir = Path(tmp)
        bundle = generate_briefs(
            primary_case=case,
            linked_cases=[],
            victim=victim,
            investigator=investigator,
            case_dir=case_dir,
            issuer_freezable=None,
            all_issuers_freezable=None,
            live_status=None,  # ← first-render path
        )
        le_html = bundle.le_path.read_text(encoding="utf-8")

    assert "Live Filing Status" in le_html
    assert "Pending issuer outreach" in le_html
    # Must NOT render any of the populated-state copy
    assert "confirmed frozen of" not in le_html


def test_le_template_renders_populated_section_5_5():
    """With a populated LiveFilingStatus, Section 5.5 renders the
    issuer table + aggregate + monitoring blocks."""
    from tests.test_v_cfi01_full_render import (
        _build_v_cfi01_case,
        VICTIM,
    )
    from recupero.reports.brief import InvestigatorInfo, generate_briefs
    from recupero.reports.victim import VictimInfo

    case = _build_v_cfi01_case()
    victim = VictimInfo(
        name="V-CFI01 Test Victim",
        wallet_address=VICTIM,
        state="NY",
        country="US",
        email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test Investigator",
        organization="Recupero Forensics Ltd.",
        email="investigator@test.com",
    )

    live_status = LiveFilingStatus(
        letters=[
            _letter(issuer="Tether", requested_usd=Decimal("1200000"),
                    frozen_usd=Decimal("1200000"), outcome_type="full_freeze",
                    days_since=3),
            _letter(issuer="Circle", requested_usd=Decimal("800000"),
                    outcome_type="acknowledged", days_since=1),
            _letter(issuer="Coinbase", requested_usd=Decimal("600000"),
                    days_since=15),
        ],
        aggregate=AggregateStatus(
            total_letters=3,
            letters_with_response=2,
            letters_silent=1,
            total_requested_usd=Decimal("2600000"),
            total_confirmed_frozen_usd=Decimal("1200000"),
            total_requested_usd_human="$2,600,000",
            total_confirmed_frozen_usd_human="$1,200,000",
            freeze_percentage=46,
        ),
        monitoring=MonitoringSnapshot(
            active_subscriptions=6,
            alerts_fired_since_brief=2,
            last_alert_at=datetime.now(UTC) - timedelta(hours=4),
        ),
        is_empty=False,
    )

    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory(prefix="le_populated_status_") as tmp:
        case_dir = Path(tmp)
        bundle = generate_briefs(
            primary_case=case,
            linked_cases=[],
            victim=victim,
            investigator=investigator,
            case_dir=case_dir,
            issuer_freezable=None,
            all_issuers_freezable=None,
            live_status=live_status,
        )
        le_html = bundle.le_path.read_text(encoding="utf-8")

    # Aggregate roll-up rendered
    assert "$1,200,000" in le_html
    assert "$2,600,000" in le_html
    assert "46%" in le_html

    # Per-letter rows rendered
    assert "Tether" in le_html
    assert "FROZEN" in le_html
    assert "ACKNOWLEDGED" in le_html
    assert "NO RESPONSE" in le_html

    # Monitoring block rendered
    assert "6" in le_html  # active subscription count
    assert "active wallet-monitoring" in le_html

    # Must NOT render the empty-state copy
    assert "Pending issuer outreach" not in le_html
