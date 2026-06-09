"""Roadmap-#1 v3 item #4: cooperation intelligence DRIVES dispatch.

annotate_dispatch_with_cooperation() flags each freeze-letter dispatch entry
with the cooperation-driven recommended legal instrument so a known black-hole /
OFAC-exposed / chronically-silent issuer is routed toward a subpoena instead of
silently getting another futile informal email — WITHOUT ever dropping a freeze
ask (advisory annotation only).
"""

from __future__ import annotations

from recupero.monitoring.cooperation_intelligence import (
    INSTRUMENT_DIRECT_REQUEST,
    INSTRUMENT_GRAND_JURY_SUBPOENA,
    IssuerCooperationProfile,
    annotate_dispatch_with_cooperation,
)


def test_black_hole_issuer_flagged_for_escalation() -> None:
    plan = [{"issuer": "Garantex", "contact_email": "le@garantex.example",
             "token": "USDT", "total_usd": "$1,000,000"}]
    profiles = {
        "Garantex": IssuerCooperationProfile(
            issuer="Garantex", n_letters_sent=5, is_black_hole=True,
        )
    }
    out = annotate_dispatch_with_cooperation(plan, profiles)
    assert len(out) == 1  # freeze ask never dropped
    e = out[0]
    assert e["escalate_beyond_email"] is True
    assert e["recommended_instrument"] == INSTRUMENT_GRAND_JURY_SUBPOENA
    assert e["recommendation_reason"]
    # The entry is still fully dispatchable (contact preserved).
    assert e["contact_email"] == "le@garantex.example"
    assert e["token"] == "USDT"


def test_responsive_confident_issuer_not_escalated() -> None:
    plan = [{"issuer": "Coinbase", "contact_email": "subpoenas@coinbase.com"}]
    profiles = {
        "Coinbase": IssuerCooperationProfile(
            issuer="Coinbase", n_letters_sent=10,
            has_confident_profile=True, response_rate=0.80,
        )
    }
    out = annotate_dispatch_with_cooperation(plan, profiles)
    assert out[0]["recommended_instrument"] == INSTRUMENT_DIRECT_REQUEST
    assert out[0]["escalate_beyond_email"] is False


def test_ofac_exposed_issuer_escalated_to_subpoena() -> None:
    plan = [{"issuer": "Garantex"}]
    out = annotate_dispatch_with_cooperation(
        plan, {}, ofac_exposed_issuers={"Garantex"},
    )
    assert out[0]["recommended_instrument"] == INSTRUMENT_GRAND_JURY_SUBPOENA
    assert out[0]["escalate_beyond_email"] is True


def test_unknown_issuer_defaults_to_standard_no_escalation() -> None:
    # No profile on file → standard direct request, not escalated.
    plan = [{"issuer": "Brand New Exchange XYZ"}]
    out = annotate_dispatch_with_cooperation(plan, {})
    assert out[0]["recommended_instrument"] == INSTRUMENT_DIRECT_REQUEST
    assert out[0]["escalate_beyond_email"] is False


def test_inputs_not_mutated_and_all_entries_preserved() -> None:
    plan = [{"issuer": "A"}, {"issuer": "B"}, {"issuer": "C"}]
    original = [dict(e) for e in plan]
    out = annotate_dispatch_with_cooperation(plan, {})
    assert len(out) == 3  # every freeze ask kept
    # Originals are untouched (annotation lands on shallow copies).
    assert plan == original
    assert all("recommended_instrument" in e for e in out)
    assert all("escalate_beyond_email" in e for e in out)


def test_issuer_name_normalized_for_profile_match() -> None:
    # A trailing space on the dispatch issuer must still match the profile
    # (whose key is normalized) — otherwise a black hole would be missed.
    plan = [{"issuer": "Tether "}]
    profiles = {
        "Tether": IssuerCooperationProfile(
            issuer="Tether", n_letters_sent=4, is_black_hole=True,
        )
    }
    out = annotate_dispatch_with_cooperation(plan, profiles)
    assert out[0]["escalate_beyond_email"] is True
    assert out[0]["recommended_instrument"] == INSTRUMENT_GRAND_JURY_SUBPOENA
