"""Tests for v0.14.3 class-action / cross-victim correlation."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from recupero.models import Case, Chain
from recupero.trace.class_action import (
    ClassActionOpportunity,
    SharedAddress,
    compute_class_action_opportunity,
)
from recupero.trace.correlation import (
    CorrelationResult,
    PriorCaseAppearance,
)


def _make_case() -> Case:
    return Case(
        case_id="V-CFI-099",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 4, 1, tzinfo=timezone.utc),
        transfers=[],
        trace_started_at=datetime(2026, 4, 1, tzinfo=timezone.utc),
        software_version="test",
        config_used={},
    )


def _correlation(
    *,
    address: str = "0xperp",
    prior_case_ids: list[UUID] | None = None,
    role: str = "perpetrator_hub",
    total_usd: Decimal = Decimal("100000"),
    ofac: int = 0,
    drainer: int = 0,
) -> CorrelationResult:
    prior_case_ids = prior_case_ids or [uuid4()]
    appearances = [
        PriorCaseAppearance(
            case_id=cid,
            role=role,
            label_category=None,
            label_name=None,
            usd_flowed=total_usd / len(prior_case_ids),
            risk_verdict=None,
            observed_at_iso="2026-01-01T00:00:00Z",
        )
        for cid in prior_case_ids
    ]
    return CorrelationResult(
        address=address,
        chain="ethereum",
        total_prior_cases=len(prior_case_ids),
        prior_ofac_exposed_count=ofac,
        prior_mixer_exposed_count=0,
        prior_drainer_attributed_count=drainer,
        prior_total_usd_flowed=total_usd,
        prior_roles_seen=[role],
        prior_case_appearances=appearances,
    )


# ---- Triggering logic ---- #


def test_no_correlations_returns_empty_untriggered() -> None:
    case = _make_case()
    opp = compute_class_action_opportunity(case=case, correlations={})
    assert opp.triggered is False
    assert opp.potential_co_victim_case_count == 0


def test_single_perp_hub_match_below_threshold_not_triggered() -> None:
    """ONE prior case sharing the perp hub → not enough alone to
    trigger (the heuristic threshold is 2 qualifying-role shares
    OR a 2+address-shared single prior case)."""
    case = _make_case()
    correlations = {
        "0xperp": _correlation(
            address="0xperp",
            prior_case_ids=[uuid4()],
            role="perpetrator_hub",
        ),
    }
    opp = compute_class_action_opportunity(case=case, correlations=correlations)
    assert opp.triggered is False
    # But the address IS still surfaced for context.
    assert len(opp.shared_addresses) == 1


def test_two_qualifying_shares_triggers() -> None:
    """Two perp-hub-class addresses sharing prior cases → trigger."""
    case = _make_case()
    correlations = {
        "0xperp_hub": _correlation(
            address="0xperp_hub",
            prior_case_ids=[uuid4()],
            role="perpetrator_hub",
            total_usd=Decimal("500000"),
        ),
        "0xdrainer": _correlation(
            address="0xdrainer",
            prior_case_ids=[uuid4()],
            role="drainer_contract",
            total_usd=Decimal("300000"),
        ),
    }
    opp = compute_class_action_opportunity(case=case, correlations=correlations)
    assert opp.triggered is True
    assert opp.qualifying_share_count == 2
    assert "CLASS-ACTION OPPORTUNITY" in opp.investigator_note


def test_single_prior_case_with_two_shared_addresses_triggers() -> None:
    """Even one shared QUALIFYING perp hub is enough when the SAME
    prior case shares 2+ addresses with this one (strong same-
    perpetrator signal)."""
    case = _make_case()
    shared_case_id = uuid4()
    correlations = {
        "0xperp": _correlation(
            address="0xperp",
            prior_case_ids=[shared_case_id],
            role="perpetrator_hub",
        ),
        "0xhop1": _correlation(
            address="0xhop1",
            prior_case_ids=[shared_case_id],   # SAME prior case
            role="high_risk_destination",
        ),
    }
    opp = compute_class_action_opportunity(case=case, correlations=correlations)
    assert opp.triggered is True
    assert "same-perpetrator signal" in opp.investigator_note


def test_exchange_only_shares_not_triggered() -> None:
    """Sharing CEX hot wallet addresses across cases is NOT a
    class-action signal — those are public infrastructure."""
    case = _make_case()
    correlations = {
        "0xbinance": _correlation(
            address="0xbinance",
            prior_case_ids=[uuid4(), uuid4(), uuid4()],
            role="exchange_deposit",
        ),
        "0xkraken": _correlation(
            address="0xkraken",
            prior_case_ids=[uuid4(), uuid4()],
            role="exchange_deposit",
        ),
    }
    opp = compute_class_action_opportunity(case=case, correlations=correlations)
    assert opp.triggered is False
    # And those addresses should be entirely excluded from shared_addresses
    # because they're pure infrastructure.
    assert len(opp.shared_addresses) == 0


# ---- Estimated combined loss ---- #


def test_combined_loss_sums_across_prior_cases() -> None:
    case = _make_case()
    correlations = {
        "0xperp_hub": _correlation(
            address="0xperp_hub",
            prior_case_ids=[uuid4()],
            role="perpetrator_hub",
            total_usd=Decimal("500000"),
        ),
        "0xdrainer": _correlation(
            address="0xdrainer",
            prior_case_ids=[uuid4()],
            role="drainer_contract",
            total_usd=Decimal("300000"),
        ),
    }
    opp = compute_class_action_opportunity(case=case, correlations=correlations)
    assert opp.estimated_combined_loss == Decimal("800000")


# ---- Shared addresses sorted ---- #


def test_qualifying_addresses_listed_before_others() -> None:
    """In the brief, qualifying-role (perpetrator_hub /
    drainer_contract / high_risk_destination) shared addresses
    should appear FIRST so the investigator sees them at a glance."""
    case = _make_case()
    correlations = {
        "0xhop": _correlation(
            address="0xhop",
            prior_case_ids=[uuid4()],
            role="hop",   # NON-qualifying (general hop)
            total_usd=Decimal("100000"),
        ),
        "0xperp": _correlation(
            address="0xperp",
            prior_case_ids=[uuid4()],
            role="perpetrator_hub",  # qualifying
            total_usd=Decimal("50000"),
        ),
    }
    opp = compute_class_action_opportunity(case=case, correlations=correlations)
    # Even though hop has higher USD, the qualifying address should
    # come first.
    assert opp.shared_addresses[0].role_in_current_case == "perpetrator_hub"


def test_shared_addresses_carry_ofac_drainer_flags() -> None:
    """The brief surfaces whether shared addresses had OFAC /
    drainer exposure in prior cases."""
    case = _make_case()
    correlations = {
        "0xperp": _correlation(
            address="0xperp",
            prior_case_ids=[uuid4(), uuid4()],
            role="perpetrator_hub",
            ofac=1,
            drainer=2,
        ),
        "0xanother": _correlation(
            address="0xanother",
            prior_case_ids=[uuid4()],
            role="drainer_contract",
        ),
    }
    opp = compute_class_action_opportunity(case=case, correlations=correlations)
    perp_share = next(s for s in opp.shared_addresses if s.address == "0xperp")
    assert perp_share.prior_ofac_exposed is True
    assert perp_share.prior_drainer_attributed is True


# ---- to_json_safe ---- #


def test_to_json_safe_serializes_decimals() -> None:
    """Brief section is consumed by JS renderers — must be
    json.dumps-safe."""
    import json
    case = _make_case()
    correlations = {
        "0xperp_hub": _correlation(
            address="0xperp_hub",
            prior_case_ids=[uuid4(), uuid4()],
            role="perpetrator_hub",
            total_usd=Decimal("1500000"),
        ),
        "0xdrainer": _correlation(
            address="0xdrainer",
            prior_case_ids=[uuid4()],
            role="drainer_contract",
            total_usd=Decimal("750000"),
        ),
    }
    opp = compute_class_action_opportunity(case=case, correlations=correlations)
    d = opp.to_json_safe()
    json.dumps(d)  # must not raise
    assert d["triggered"] is True
    assert d["estimated_combined_loss"] == "$2,250,000.00"
    assert d["qualifying_share_count"] == 2
    # Field shape lock for downstream consumers.
    addr = d["shared_addresses"][0]
    assert "address" in addr
    assert "role_in_current_case" in addr
    assert "appeared_in_case_count" in addr
    assert "total_usd_across_prior_cases" in addr
    assert "prior_ofac_exposed" in addr


def test_untriggered_section_has_helpful_note() -> None:
    """Even when not triggered, the section's note should explain
    why (rather than being a bare empty)."""
    case = _make_case()
    opp = compute_class_action_opportunity(case=case, correlations={})
    assert opp.triggered is False
    assert len(opp.investigator_note) > 20  # not empty


def test_pure_infrastructure_shares_get_explanatory_note() -> None:
    """When the only matches are CEX/bridge/mixer (infrastructure),
    the note explains it."""
    case = _make_case()
    correlations = {
        "0xbinance": _correlation(
            address="0xbinance",
            prior_case_ids=[uuid4()],
            role="exchange_deposit",
        ),
    }
    opp = compute_class_action_opportunity(case=case, correlations=correlations)
    assert opp.triggered is False
    # Note still relevant for the investigator.
    assert len(opp.investigator_note) > 20
