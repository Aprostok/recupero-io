"""Tests for v0.21.0 auto-subscribe in emit_brief.

Covers:
  * derive_subscriptions_from_brief — pure-function seed derivation
  * Sky-Protocol-style LOW/NO capability exclusion
  * OFAC-routing for risk-flagged addresses
  * (PERP_HUB, ALL_ISSUER_HOLDINGS) dedup
  * persist_subscriptions — INSERT ON CONFLICT semantics
  * auto_subscribe_from_brief — no-op when DSN unset, safe on failure
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import UUID

from recupero.monitoring.subscriber import (
    SubscriptionSeed,
    auto_subscribe_from_brief,
    derive_subscriptions_from_brief,
    persist_subscriptions,
)

CASE_ID = "RCP-2026-0427"
INV_ID = UUID("55555555-5555-5555-5555-555555555555")
INVESTIGATOR = "investigator@example.com"

VICTIM_WALLET = "0xV" + "0" * 39
PERP_HUB = "0xH" + "0" * 39
TETHER_DEST = "0xT" + "0" * 39
CIRCLE_DEST = "0xC" + "0" * 39
SKY_DEST = "0xS" + "0" * 39
OFAC_FLAGGED = "0xF" + "0" * 39


def _v_cfi01_shape_brief(**overrides):
    """Build a V-CFI01-shape brief dict with PERP_HUB + 4 freezable
    issuers + Sky Protocol DAI as UNRECOVERABLE."""
    brief = {
        "CASE_ID": CASE_ID,
        "PRIMARY_CHAIN": "ethereum",
        "PERP_HUB": {
            "address": PERP_HUB,
            "chain": "ethereum",
        },
        "ALL_ISSUER_HOLDINGS": [
            {
                "issuer": "Tether",
                "freeze_capability": "HIGH",
                "holdings": [
                    {"address": TETHER_DEST, "chain": "ethereum",
                     "status": "FREEZABLE"},
                ],
            },
            {
                "issuer": "Circle",
                "freeze_capability": "HIGH",
                "holdings": [
                    {"address": CIRCLE_DEST, "chain": "ethereum",
                     "status": "FREEZABLE"},
                ],
            },
            {
                "issuer": "Sky Protocol",
                "freeze_capability": "LOW",  # ← unrecoverable
                "holdings": [
                    {"address": SKY_DEST, "chain": "ethereum",
                     "status": "UNRECOVERABLE"},
                ],
            },
        ],
        "RISK_ASSESSMENT": {"addresses": {}},
        "INDIRECT_EXPOSURE": {"addresses": {}},
        "INVESTIGATOR_EMAIL": INVESTIGATOR,
    }
    brief.update(overrides)
    return brief


# ─────────────────────────────────────────────────────────────────────────────
# derive_subscriptions_from_brief — pure-function seed derivation
# ─────────────────────────────────────────────────────────────────────────────


def test_derive_includes_perp_hub_and_freezable_holdings():
    """PERP_HUB + Tether + Circle destinations seed subscriptions."""
    seeds = derive_subscriptions_from_brief(
        _v_cfi01_shape_brief(),
        case_id=CASE_ID,
        investigation_id=INV_ID,
        investigator_email=INVESTIGATOR,
    )
    addrs = {s.address.lower() for s in seeds}
    assert PERP_HUB.lower() in addrs
    assert TETHER_DEST.lower() in addrs
    assert CIRCLE_DEST.lower() in addrs


def test_derive_excludes_low_capability_holdings():
    """Sky Protocol (freeze_capability=LOW) must NOT seed a subscription.

    Without this carve-out the investigator would receive movement
    alerts on a wallet they have no freeze pathway for — pure noise.
    """
    seeds = derive_subscriptions_from_brief(
        _v_cfi01_shape_brief(),
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
    )
    addrs = {s.address.lower() for s in seeds}
    assert SKY_DEST.lower() not in addrs, (
        "Sky Protocol DAI (LOW capability) leaked into subscriber seeds — "
        "the LOW/NO carve-out is broken."
    )


def test_derive_excludes_no_capability_holdings():
    """Holdings under an issuer with freeze_capability='NO' (raw form
    from older briefs) are also excluded."""
    brief = _v_cfi01_shape_brief()
    brief["ALL_ISSUER_HOLDINGS"][2]["freeze_capability"] = "NO"
    seeds = derive_subscriptions_from_brief(
        brief,
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
    )
    addrs = {s.address.lower() for s in seeds}
    assert SKY_DEST.lower() not in addrs


def test_derive_includes_tracked_holding_under_low_capability():
    """v0.34.4: a TRACKED holding (identified funds we can't freeze TODAY but
    that still sit there) under a LOW/NO-capability issuer MUST be watched —
    that's the whole point of TRACKED: alert us if/when the funds move so we can
    recover them later. Only NON-TRACKED holdings under such issuers stay carved
    out. This is the Zigha dormant-DAI case (~$16.9M)."""
    brief = _v_cfi01_shape_brief()
    # Sky Protocol DAI, LOW capability, but the funds are identified + held →
    # classified TRACKED upstream.
    brief["ALL_ISSUER_HOLDINGS"][2]["holdings"][0]["status"] = "TRACKED"
    seeds = derive_subscriptions_from_brief(
        brief,
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
    )
    by_addr = {s.address.lower(): s for s in seeds}
    assert SKY_DEST.lower() in by_addr, (
        "TRACKED holding under a LOW-capability issuer was NOT subscribed — "
        "dormant recoverable-later funds would go unmonitored (the Zigha "
        "$16.9M DAI failure mode)."
    )
    # watched for ANY movement so we catch it the moment it relocates.
    assert by_addr[SKY_DEST.lower()].trigger_type == "any_movement"
    assert "TRACKED" in (by_addr[SKY_DEST.lower()].label or "")


def test_derive_routes_ofac_addresses_to_ofac_contact_trigger():
    """An address flagged in RISK_ASSESSMENT as OFAC-exposed must
    get trigger_type='ofac_contact' (fires on inflows too, not just
    outflows). Default is 'any_movement'."""
    brief = _v_cfi01_shape_brief()
    brief["ALL_ISSUER_HOLDINGS"].append({
        "issuer": "(unknown)",
        "freeze_capability": "MEDIUM",
        "holdings": [{"address": OFAC_FLAGGED, "chain": "ethereum"}],
    })
    brief["RISK_ASSESSMENT"]["addresses"][OFAC_FLAGGED] = {
        "ofac_exposed": True,
        "score": 95,
    }
    seeds = derive_subscriptions_from_brief(
        brief,
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
    )
    by_addr = {s.address.lower(): s.trigger_type for s in seeds}
    assert by_addr.get(OFAC_FLAGGED.lower()) == "ofac_contact"
    # Tether is not OFAC-flagged, so its trigger is any_movement
    assert by_addr.get(TETHER_DEST.lower()) == "any_movement"


def test_derive_picks_up_ofac_from_exposures_list_shape():
    """The risk section sometimes carries the OFAC signal in an
    `exposures` list with risk_category='ofac' rather than as a
    boolean. The derivation must catch both shapes."""
    brief = _v_cfi01_shape_brief()
    brief["RISK_ASSESSMENT"]["addresses"][TETHER_DEST] = {
        "exposures": [
            {"counterparty_name": "OFAC SDN entry", "risk_category": "ofac_sanctions"},
        ],
    }
    seeds = derive_subscriptions_from_brief(
        brief,
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
    )
    by_addr = {s.address.lower(): s.trigger_type for s in seeds}
    assert by_addr[TETHER_DEST.lower()] == "ofac_contact"


def test_derive_deduplicates_perp_hub_overlap():
    """If PERP_HUB appears again as a holding, only one seed is produced.

    The dedup keys on (canonical_address, chain) — PERP_HUB wins
    because it's processed first.
    """
    brief = _v_cfi01_shape_brief()
    # Add the perp hub also as a holding under Tether
    brief["ALL_ISSUER_HOLDINGS"][0]["holdings"].append(
        {"address": PERP_HUB, "chain": "ethereum"}
    )
    seeds = derive_subscriptions_from_brief(
        brief,
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
    )
    hub_seeds = [s for s in seeds if s.address.lower() == PERP_HUB.lower()]
    assert len(hub_seeds) == 1
    assert "Perp hub" in hub_seeds[0].label


def test_derive_canonicalizes_evm_addresses_for_dedup():
    """An address that appears with mixed-case in one place and lowercase
    in another must collapse to one seed (the EVM addresses are
    case-insensitive on-chain)."""
    brief = _v_cfi01_shape_brief()
    # Re-add Tether destination in MIXED case under a second issuer
    brief["ALL_ISSUER_HOLDINGS"].append({
        "issuer": "OtherIssuer",
        "freeze_capability": "HIGH",
        "holdings": [{
            "address": TETHER_DEST.upper().replace("X", "x"),  # mixed
            "chain": "ethereum",
        }],
    })
    seeds = derive_subscriptions_from_brief(
        brief,
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
    )
    tether_seeds = [
        s for s in seeds
        if s.address.lower() == TETHER_DEST.lower()
    ]
    assert len(tether_seeds) == 1, (
        f"EVM dedup failed — found {len(tether_seeds)} seeds for the same address"
    )


def test_derive_uses_created_by_scoped_to_case():
    """All seeds for a given case carry created_by='emit_brief:<case_id>',
    enabling the ON CONFLICT uniqueness scope and the ops CLI to find
    all subs for a case via LIKE filtering."""
    seeds = derive_subscriptions_from_brief(
        _v_cfi01_shape_brief(),
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
    )
    for seed in seeds:
        assert seed.created_by == f"emit_brief:{CASE_ID}"


def test_derive_returns_empty_when_brief_has_no_perp_hub_or_holdings():
    """An empty brief shape produces zero seeds — no spurious inserts."""
    seeds = derive_subscriptions_from_brief(
        {"CASE_ID": CASE_ID, "PRIMARY_CHAIN": "ethereum"},
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
    )
    assert seeds == []


def test_derive_falls_back_to_primary_chain_when_holding_chain_missing():
    """A holding without an explicit `chain` field inherits PRIMARY_CHAIN.

    Real briefs always populate this, but the safety net keeps the
    seeder from inserting NULL into the chain column (which would
    raise a constraint violation).
    """
    brief = _v_cfi01_shape_brief()
    brief["ALL_ISSUER_HOLDINGS"][0]["holdings"][0].pop("chain", None)
    seeds = derive_subscriptions_from_brief(
        brief,
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
    )
    tether_seed = next(
        s for s in seeds if s.address.lower() == TETHER_DEST.lower()
    )
    assert tether_seed.chain == "ethereum"


# ─────────────────────────────────────────────────────────────────────────────
# persist_subscriptions — DB integration (mocked)
# ─────────────────────────────────────────────────────────────────────────────


def test_persist_skips_seeds_without_alert_email():
    """A seed without an alert_email would violate the
    channel-targets-present CHECK (no webhook_url either). Must skip,
    not insert.
    """
    seeds = [
        SubscriptionSeed(
            address=PERP_HUB, chain="ethereum",
            trigger_type="any_movement",
            alert_email=None,
            case_id=CASE_ID, investigation_id=None,
            label="Perp hub", created_by=f"emit_brief:{CASE_ID}",
        ),
    ]
    # No DB connect required — function short-circuits before DB call.
    inserted, skipped = persist_subscriptions(seeds, dsn="postgres://fake")
    # The function may still attempt to open a connection; we only
    # assert no INSERT was attempted for the email-less seed.
    assert inserted == 0
    assert skipped >= 1


def test_persist_no_seeds_returns_zero_zero():
    """Empty seed list short-circuits without touching the DB."""
    inserted, skipped = persist_subscriptions([], dsn="postgres://fake")
    assert (inserted, skipped) == (0, 0)


# ─────────────────────────────────────────────────────────────────────────────
# auto_subscribe_from_brief — convenience + failure modes
# ─────────────────────────────────────────────────────────────────────────────


def test_auto_subscribe_no_dsn_is_noop():
    """Without DSN (local CLI emit_brief), the auto-subscribe step
    must be a no-op — emit_brief still writes freeze_brief.json
    successfully on a developer laptop."""
    inserted, skipped = auto_subscribe_from_brief(
        _v_cfi01_shape_brief(),
        case_id=CASE_ID,
        investigator_email=INVESTIGATOR,
        dsn=None,
    )
    assert (inserted, skipped) == (0, 0)


def test_auto_subscribe_swallows_persist_failures():
    """Any failure inside derive/persist must be caught — never
    propagate up to emit_brief."""
    with patch(
        "recupero.monitoring.subscriber.persist_subscriptions",
        side_effect=RuntimeError("simulated DB blowup"),
    ):
        # Must not raise
        inserted, skipped = auto_subscribe_from_brief(
            _v_cfi01_shape_brief(),
            case_id=CASE_ID,
            investigator_email=INVESTIGATOR,
            dsn="postgres://fake",
        )
    assert (inserted, skipped) == (0, 0)


def test_auto_subscribe_passes_investigator_email_through():
    """The investigator_email kwarg must reach the SubscriptionSeed."""
    captured_seeds: list[SubscriptionSeed] = []

    def _stub_persist(seeds, *, dsn):
        captured_seeds.extend(seeds)
        return (len(seeds), 0)

    with patch(
        "recupero.monitoring.subscriber.persist_subscriptions",
        side_effect=_stub_persist,
    ):
        auto_subscribe_from_brief(
            _v_cfi01_shape_brief(),
            case_id=CASE_ID,
            investigator_email="jacob@recupero.io",
            dsn="postgres://fake",
        )
    assert len(captured_seeds) > 0
    for seed in captured_seeds:
        assert seed.alert_email == "jacob@recupero.io"
