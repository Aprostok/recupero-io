"""Tests for the law-enforcement filing-route recommender.

Goal: the LE handoff PDF should tell the recipient (victim or
attorney) specifically WHERE to file, not generically "send this to
law enforcement". This module generates structured routing data
based on:

  * Victim's country (US-specific paths vs international fallback)
  * Victim's US state (state-AG cybercrime contacts)
  * Loss amount (loss-tier escalations: FBI VAU at $100k+,
    Secret Service at $1M+)

Tests run in <50ms — pure-Python lookup logic, no I/O.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from recupero.worker._le_routing import (
    GENERIC_STATE_AG,
    IC3,
    FBI_VAU,
    INTERNATIONAL_FALLBACK,
    LEContact,
    LERoutingPlan,
    SECRET_SERVICE_ECTF,
    _normalize_state,
    _STATE_LE_CONTACTS,
    recommend_le_routes,
)


# ---- recommend_le_routes: country / state / loss decision logic ---- #


def test_us_baseline_always_includes_ic3() -> None:
    """Every US case gets IC3 as a primary route. This is the
    federal-record baseline that doesn't depend on state or loss."""
    plan = recommend_le_routes(state=None, country="US", total_loss_usd=None)
    assert IC3 in plan.primary_routes


def test_us_with_known_state_adds_state_routes() -> None:
    """A known state in _STATE_LE_CONTACTS adds state-level routes."""
    plan = recommend_le_routes(state="CA", country="US", total_loss_usd=None)
    assert IC3 in plan.primary_routes
    assert len(plan.state_routes) > 0
    # California has 2 specific routes (AG eCrime + DFPI)
    state_names = [r.name for r in plan.state_routes]
    assert any("California" in name for name in state_names)


def test_us_with_unknown_state_uses_generic_fallback() -> None:
    """A US state not in the lookup table falls back to the generic
    state-AG recommendation."""
    plan = recommend_le_routes(state="WV", country="US", total_loss_usd=None)
    assert GENERIC_STATE_AG in plan.state_routes
    # Should have a note about the missing-state-data
    assert any("WV" in note or "specific contact data" in note for note in plan.notes)


def test_us_with_no_state_includes_note() -> None:
    """When state is None, no state-route is added but a note
    encourages the operator to follow up with the victim."""
    plan = recommend_le_routes(state=None, country="US", total_loss_usd=None)
    assert plan.state_routes == []
    assert any("US state is not on file" in note for note in plan.notes)


def test_non_us_uses_international_fallback() -> None:
    """Non-US victims get the international fallback only — no IC3,
    no US-specific state routes."""
    plan = recommend_le_routes(state=None, country="UK", total_loss_usd=None)
    assert IC3 not in plan.primary_routes
    assert INTERNATIONAL_FALLBACK in plan.primary_routes
    # Note about the country
    assert any("UK" in note for note in plan.notes)


def test_non_us_loss_tier_does_not_escalate_to_fbi() -> None:
    """Even high-loss non-US cases don't trigger US-federal
    escalations — FBI / Secret Service aren't appropriate channels
    for non-US victims."""
    plan = recommend_le_routes(
        state="London", country="UK", total_loss_usd=Decimal("500000"),
    )
    assert FBI_VAU not in plan.escalation_routes
    assert SECRET_SERVICE_ECTF not in plan.escalation_routes


def test_loss_under_100k_no_escalations() -> None:
    """US loss under $100k triggers no escalations — IC3 + state
    only is the right channel set."""
    plan = recommend_le_routes(state="CA", country="US",
                               total_loss_usd=Decimal("25000"))
    assert FBI_VAU not in plan.escalation_routes
    assert SECRET_SERVICE_ECTF not in plan.escalation_routes


def test_loss_at_100k_triggers_fbi_vau() -> None:
    """Exactly $100k crosses the threshold (inclusive) for FBI VAU."""
    plan = recommend_le_routes(state="CA", country="US",
                               total_loss_usd=Decimal("100000"))
    assert FBI_VAU in plan.escalation_routes
    # Loss-amount mentioned in the note
    assert any("100,000" in note or "$100k" in note.lower()
               or "$100,000" in note for note in plan.notes)


def test_loss_over_100k_includes_fbi_vau() -> None:
    """Mid-range US loss ($250k) triggers FBI VAU but not Secret
    Service."""
    plan = recommend_le_routes(state="NY", country="US",
                               total_loss_usd=Decimal("250000"))
    assert FBI_VAU in plan.escalation_routes
    assert SECRET_SERVICE_ECTF not in plan.escalation_routes


def test_loss_over_1m_adds_secret_service() -> None:
    """$1M+ loss adds Secret Service ECTF on top of FBI VAU."""
    plan = recommend_le_routes(state="CA", country="US",
                               total_loss_usd=Decimal("1500000"))
    assert FBI_VAU in plan.escalation_routes
    assert SECRET_SERVICE_ECTF in plan.escalation_routes


def test_loss_none_does_not_trigger_escalations() -> None:
    """Unknown loss amount → no escalations. Conservative default."""
    plan = recommend_le_routes(state="CA", country="US",
                               total_loss_usd=None)
    assert FBI_VAU not in plan.escalation_routes
    assert SECRET_SERVICE_ECTF not in plan.escalation_routes


# ---- _normalize_state ---- #


def test_normalize_state_postal_code() -> None:
    assert _normalize_state("CA") == "CA"
    assert _normalize_state("ca") == "CA"
    assert _normalize_state("NY") == "NY"


def test_normalize_state_full_name() -> None:
    """Full state names normalize to their postal code."""
    assert _normalize_state("California") == "CA"
    assert _normalize_state("california") == "CA"
    assert _normalize_state("New York") == "NY"


def test_normalize_state_unknown_returns_uppercased() -> None:
    """Unknown state input returns the input uppercased (for
    display in the 'no data for this state' note)."""
    assert _normalize_state("Atlantis") == "ATLANTIS"


# ---- Country normalization ---- #


def test_country_uppercase_us() -> None:
    """``US``, ``USA``, ``United States`` all treated as US."""
    for country in ["US", "us", "USA", "usa", "United States", "united states"]:
        plan = recommend_le_routes(state=None, country=country,
                                   total_loss_usd=None)
        assert IC3 in plan.primary_routes, f"country={country!r} failed"


def test_country_none_defaults_to_us() -> None:
    """No country → assume US (most common). Better default than
    immediately falling to the international fallback."""
    plan = recommend_le_routes(state=None, country=None,
                               total_loss_usd=None)
    assert IC3 in plan.primary_routes
    assert INTERNATIONAL_FALLBACK not in plan.primary_routes


# ---- LERoutingPlan dataclass shape ---- #


def test_routing_plan_empty_lists_independent() -> None:
    """Two LERoutingPlan instances must have independent default
    lists (the field(default_factory=list) idiom)."""
    p1 = LERoutingPlan()
    p2 = LERoutingPlan()
    p1.primary_routes.append(IC3)
    assert p2.primary_routes == []


def test_le_contact_immutable() -> None:
    """LEContact is frozen — contacts shouldn't be mutated after
    construction (they're shared module-level constants)."""
    with pytest.raises(Exception):
        IC3.name = "modified"  # type: ignore[misc]


# ---- Realistic full scenarios ---- #


def test_california_phishing_victim_50k_loss() -> None:
    """End-to-end: CA victim, $50k crypto-phishing loss. Expected
    routing: IC3 + California state routes, no FBI VAU
    (under $100k)."""
    plan = recommend_le_routes(state="CA", country="US",
                               total_loss_usd=Decimal("50000"))
    assert IC3 in plan.primary_routes
    assert len(plan.state_routes) >= 1
    assert FBI_VAU not in plan.escalation_routes


def test_ny_high_value_victim_750k_loss() -> None:
    """End-to-end: NY victim, $750k loss. Expected: IC3 + NY state
    + FBI VAU (over $100k threshold). NOT Secret Service (under
    $1M threshold)."""
    plan = recommend_le_routes(state="NY", country="US",
                               total_loss_usd=Decimal("750000"))
    assert IC3 in plan.primary_routes
    assert FBI_VAU in plan.escalation_routes
    assert SECRET_SERVICE_ECTF not in plan.escalation_routes


def test_full_escalation_scenario_2m_loss() -> None:
    """$2M California case: every channel engaged. IC3 + CA state
    + FBI VAU + Secret Service. Most-comprehensive recommendation
    set."""
    plan = recommend_le_routes(state="CA", country="US",
                               total_loss_usd=Decimal("2000000"))
    assert IC3 in plan.primary_routes
    assert any("California" in r.jurisdiction for r in plan.state_routes)
    assert FBI_VAU in plan.escalation_routes
    assert SECRET_SERVICE_ECTF in plan.escalation_routes


def test_uk_victim_minimum_path() -> None:
    """UK victim → international fallback only. No US channels
    even if loss is high."""
    plan = recommend_le_routes(state=None, country="UK",
                               total_loss_usd=Decimal("100000"))
    assert plan.primary_routes == [INTERNATIONAL_FALLBACK]
    assert plan.state_routes == []
    assert plan.escalation_routes == []
