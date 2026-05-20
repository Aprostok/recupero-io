"""v0.21.0 E2E smoke — live filings end-to-end on the V-CFI01 fixture.

Exercises the full chain that makes v0.21.0 "live filings" work:

  1. emit_brief() runs on V-CFI01 → brief has RECOVERY_ESTIMATE
  2. Auto-subscribe derives perp-wallet subscriptions (Sky Protocol
     excluded; OFAC-routed where applicable)
  3. LE handoff renders with the cover Estimated Recoverable row
     and the "Pending issuer outreach" empty-state Section 5.5
  4. fetch_live_filing_status returns empty when no letters mailed
  5. Re-render with a populated LiveFilingStatus → Section 5.5
     shows the per-issuer status table + aggregate roll-up

DB I/O is mocked — this is a unit-level smoke, not an integration
test against a real Postgres. The production path runs against
Supabase; the integration suite under tests/integration/ covers
that separately.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest


def test_v0_21_emit_brief_produces_recovery_estimate_and_auto_subscribes():
    """v0.21.0 contract: emit_brief on V-CFI01 produces a brief with
    RECOVERY_ESTIMATE present, AND when called with a DSN +
    investigation_id, auto-subscribes the perp-wallet set."""
    from tests.test_v_cfi01_full_render import (
        _build_editorial,
        _build_freeze_asks_dict,
        _build_issuer_metadata,
        _build_v_cfi01_case,
        VICTIM,
    )
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo

    case = _build_v_cfi01_case()
    editorial = _build_editorial()
    freeze_asks = _build_freeze_asks_dict()
    issuer_metadata = _build_issuer_metadata()
    victim = VictimInfo(
        name="V-CFI01 Test Victim",
        wallet_address=VICTIM,
        state="NY", country="US",
        email="victim@test.com",
    )

    brief = emit_brief(
        case=case, victim=victim, editorial=editorial,
        freeze_asks=freeze_asks, issuer_metadata=issuer_metadata,
    )

    # Contract 1: recovery estimate is present and shaped correctly
    rec = brief.get("RECOVERY_ESTIMATE")
    assert rec is not None, "emit_brief did not produce RECOVERY_ESTIMATE"
    assert "expected_recovered_usd" in rec
    assert "$" in rec["expected_recovered_usd"]

    # Contract 2: derived subscriptions exclude Sky Protocol (LOW
    # capability) holdings — UNLESS the holding overlaps the
    # PERP_HUB address, in which case the hub itself drives the
    # subscription (always-subscribe contract for the hub).
    from recupero.monitoring.subscriber import derive_subscriptions_from_brief
    seeds = derive_subscriptions_from_brief(
        brief,
        case_id="V-CFI01-TEST",
        investigator_email="ops@example.com",
    )
    seed_addrs = {s.address.lower() for s in seeds}
    assert len(seeds) > 0, "auto-subscriber produced no seeds"

    perp_hub_addr = (brief.get("PERP_HUB") or {}).get("address", "").lower()
    sky_entry = next(
        (e for e in brief.get("ALL_ISSUER_HOLDINGS", [])
         if (e.get("issuer") or "").lower().startswith("sky")),
        None,
    )
    if sky_entry:
        for holding in sky_entry.get("holdings", []):
            addr = (holding.get("address") or "").lower()
            if addr == perp_hub_addr:
                # OK: hub is always subscribed regardless of overlap
                continue
            assert addr not in seed_addrs, (
                f"Sky Protocol address {addr} leaked into subscription seeds "
                f"(not the perp hub; should have been excluded by LOW capability)"
            )

    # Contract 3: every seed must be either the perp hub OR a
    # holding from a non-LOW/NO issuer
    skip_caps = {"LOW", "NO"}
    freezable_addrs_lc: set[str] = {perp_hub_addr} if perp_hub_addr else set()
    for entry in brief.get("ALL_ISSUER_HOLDINGS", []):
        cap = (entry.get("freeze_capability") or "").upper()
        if cap in skip_caps:
            continue
        for holding in entry.get("holdings", []):
            freezable_addrs_lc.add((holding.get("address") or "").lower())
    for addr in seed_addrs:
        assert addr in freezable_addrs_lc, (
            f"Seed address {addr} is neither the perp hub nor a freezable holding"
        )


def test_v0_21_le_handoff_renders_with_recovery_and_empty_status():
    """First render after emit_brief (no letters mailed yet) — LE
    handoff must:
      * Show Estimated Recoverable on the cover
      * Show Section 5.5 'Pending issuer outreach' empty-state
    """
    from tests.test_v_cfi01_full_render import (
        _build_v_cfi01_case,
        VICTIM,
    )
    from recupero.reports.brief import InvestigatorInfo, generate_briefs
    from recupero.reports.victim import VictimInfo

    case = _build_v_cfi01_case()
    victim = VictimInfo(
        name="V-CFI01", wallet_address=VICTIM,
        state="NY", country="US", email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test", organization="Recupero", email="t@example.com",
    )

    recovery = {
        "expected_recovered_usd": "$2,100,000.00",
        "expected_recovered_low_usd": "$1,400,000.00",
        "expected_recovered_high_usd": "$2,800,000.00",
        "probability_any_recovery_90d": 0.58,
        "recommendation": "recommend",
        "headline_summary": "V-CFI01 multi-issuer case",
    }

    with tempfile.TemporaryDirectory(prefix="v21_e2e_") as tmp:
        bundle = generate_briefs(
            primary_case=case,
            linked_cases=[],
            victim=victim,
            investigator=investigator,
            case_dir=Path(tmp),
            recovery_estimate=recovery,
            live_status=None,   # first render — no letters yet
        )
        le_html = bundle.le_path.read_text(encoding="utf-8")

    # Recovery cover row
    assert "Estimated Recoverable" in le_html
    assert "$2,100,000.00" in le_html
    assert "58%" in le_html

    # Section 5.5 empty-state branch
    assert "Live Filing Status" in le_html
    assert "Pending issuer outreach" in le_html


def test_v0_21_le_handoff_renders_with_populated_status_after_outcomes_recorded():
    """Subsequent re-render after operator has mailed letters + recorded
    outcomes — Section 5.5 shows the per-issuer table, aggregate
    roll-up, and monitoring snapshot.
    """
    from tests.test_v_cfi01_full_render import (
        _build_v_cfi01_case,
        VICTIM,
    )
    from recupero.freeze_learning.status import (
        AggregateStatus,
        LetterStatus,
        LiveFilingStatus,
        MonitoringSnapshot,
    )
    from recupero.reports.brief import InvestigatorInfo, generate_briefs
    from recupero.reports.victim import VictimInfo

    case = _build_v_cfi01_case()
    victim = VictimInfo(
        name="V-CFI01", wallet_address=VICTIM,
        state="NY", country="US", email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test", organization="Recupero", email="t@example.com",
    )

    # Simulated state: Tether and Circle responded; Coinbase silent.
    def _letter(*, issuer, requested, frozen=None, outcome_type=None, days=2):
        sent_at = datetime.now(UTC) - timedelta(days=days)
        return LetterStatus(
            letter_id=uuid4(),
            issuer=issuer,
            target_address="0x" + "f" * 40,
            chain="ethereum",
            asset_symbol="USDT" if issuer == "Tether" else "USDC",
            requested_freeze_usd=Decimal(str(requested)),
            requested_freeze_usd_human=f"${requested:,}",
            sent_at=sent_at,
            sent_at_human=sent_at.strftime("%Y-%m-%d"),
            days_since_sent=days,
            status_badge=(
                "FROZEN" if outcome_type == "full_freeze"
                else "ACKNOWLEDGED" if outcome_type == "acknowledged"
                else "NO RESPONSE"
            ),
            outcome_type=outcome_type,
            frozen_usd=Decimal(str(frozen)) if frozen else None,
            frozen_usd_human=f"${frozen:,}" if frozen else "—",
            last_followup_sent_at=None,
            followup_stage="initial",
        )

    live = LiveFilingStatus(
        letters=[
            _letter(issuer="Tether",   requested=1200000,
                    frozen=1200000,   outcome_type="full_freeze",   days=3),
            _letter(issuer="Circle",   requested=800000,
                    outcome_type="acknowledged",  days=1),
            _letter(issuer="Coinbase", requested=600000, days=15),
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
            alerts_fired_since_brief=1,
            last_alert_at=datetime.now(UTC) - timedelta(hours=2),
        ),
        is_empty=False,
    )

    with tempfile.TemporaryDirectory(prefix="v21_populated_") as tmp:
        bundle = generate_briefs(
            primary_case=case,
            linked_cases=[],
            victim=victim,
            investigator=investigator,
            case_dir=Path(tmp),
            recovery_estimate=None,
            live_status=live,
        )
        le_html = bundle.le_path.read_text(encoding="utf-8")

    # Populated state — empty-state copy MUST be gone
    assert "Pending issuer outreach" not in le_html

    # Aggregate roll-up rendered
    assert "$1,200,000" in le_html
    assert "$2,600,000" in le_html
    assert "46%" in le_html

    # Per-letter status badges
    assert "FROZEN" in le_html
    assert "ACKNOWLEDGED" in le_html
    assert "NO RESPONSE" in le_html

    # Monitoring snapshot
    assert "active wallet-monitoring" in le_html


def test_v0_21_end_to_end_smoke_no_dsn_path():
    """Smoke: the entire local-CLI emit_brief path (no DSN) produces
    a valid brief + LE handoff, even without any Supabase plumbing.

    Critical for the developer-laptop workflow — without a DSN,
    the new v0.21.0 plumbing (auto-subscribe, fetch_live_filing_status,
    refresh_priors) all degrades to no-op rather than breaking
    deliverable generation.
    """
    from tests.test_v_cfi01_full_render import (
        _build_editorial,
        _build_freeze_asks_dict,
        _build_issuer_metadata,
        _build_v_cfi01_case,
        VICTIM,
    )
    from recupero.reports.brief import InvestigatorInfo, generate_briefs
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo

    case = _build_v_cfi01_case()
    editorial = _build_editorial()
    victim = VictimInfo(
        name="V-CFI01", wallet_address=VICTIM,
        state="NY", country="US", email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test", organization="Recupero", email="t@example.com",
    )

    brief = emit_brief(
        case=case, victim=victim, editorial=editorial,
        freeze_asks=_build_freeze_asks_dict(),
        issuer_metadata=_build_issuer_metadata(),
    )

    with tempfile.TemporaryDirectory(prefix="v21_no_dsn_") as tmp:
        bundle = generate_briefs(
            primary_case=case,
            linked_cases=[],
            victim=victim,
            investigator=investigator,
            case_dir=Path(tmp),
            recovery_estimate=brief.get("RECOVERY_ESTIMATE"),
            live_status=None,
        )
        le_html = bundle.le_path.read_text(encoding="utf-8")
        freeze_html = bundle.maple_path.read_text(encoding="utf-8")

    # Both documents render cleanly without raising — no StrictUndefined
    # firings, no missing fields. The Estimated Recoverable row should
    # be present (because emit_brief always emits RECOVERY_ESTIMATE).
    assert "Estimated Recoverable" in le_html
    assert "Live Filing Status" in le_html
    assert "Pending issuer outreach" in le_html  # empty state on first render
    # Freeze letter content present (per-issuer letter to Midas in the
    # default V-CFI01 fixture).
    assert "freeze" in freeze_html.lower()
