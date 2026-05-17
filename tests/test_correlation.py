"""Tests for v0.11.0 cross-case correlation.

The DB I/O is mocked — these tests verify:
  * build_observations produces the right shape per case
  * Role taxonomy maps from LabelCategory correctly
  * Per-(address, role) dedup works (same address, same role,
    one observation)
  * correlations_to_brief_section serializes summary + per-address
  * Severity-aware investigator notes
  * Empty cases / no transfers degrade gracefully
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID, uuid4

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.trace.correlation import (
    AddressObservation,
    CorrelationResult,
    PriorCaseAppearance,
    build_observations,
    correlations_to_brief_section,
)


# ---- Fixtures ---- #


def _mk_label(addr: str, *, category: LabelCategory, name: str = "TestLabel") -> Label:
    return Label(
        address=addr,
        name=name,
        category=category,
        source="test",
        confidence="high",
        added_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal = Decimal("1000"),
    tx_hash: str | None = None,
    counterparty_label: Label | None = None,
    chain: Chain = Chain.ethereum,
) -> Transfer:
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tx_hash = tx_hash or ("0x" + "1" * 64)
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:1",
        chain=chain,
        tx_hash=tx_hash,
        block_number=1,
        block_time=ts,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=counterparty_label, is_contract=False,
        ),
        token=TokenRef(
            chain=chain,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDC", decimals=6, coingecko_id="usd-coin",
        ),
        amount_raw="1000000000",
        amount_decimal=Decimal("1000"),
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=ts,
    )


def _mk_case(transfers: list[Transfer], seed: str = "0x" + "a" * 40) -> Case:
    return Case(
        case_id="test",
        seed_address=seed,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        software_version="test",
        config_used={},
    )


# ---- build_observations ---- #


def test_empty_case_only_emits_victim() -> None:
    """Even without any transfers, the seed address is always
    recorded as the victim — otherwise zero-loss cases would
    leave no trace in the index."""
    case = _mk_case([])
    obs = build_observations(case)
    assert len(obs) == 1
    assert obs[0].address == ("0x" + "a" * 40)
    assert obs[0].role == "victim"


def test_case_with_one_transfer_emits_victim_plus_hop() -> None:
    """Victim → unlabeled address → at minimum: victim role +
    hop role for the recipient."""
    perp = "0x" + "b" * 40
    case = _mk_case([_mk_transfer(from_addr="0x" + "a" * 40, to_addr=perp)])
    obs = build_observations(case)
    addrs = {o.address: o for o in obs}
    assert ("0x" + "a" * 40) in addrs
    assert ("0x" + "b" * 40) in addrs
    assert addrs["0x" + "a" * 40].role == "victim"
    # Unlabeled counterparty defaults to 'hop'.
    assert addrs[perp].role == "hop"


def test_counterparty_label_maps_to_role() -> None:
    """Counterparty with LabelCategory.exchange_deposit → role
    should be 'exchange_deposit' (not 'hop')."""
    cex_deposit = "0x" + "c" * 40
    label = _mk_label(
        cex_deposit, category=LabelCategory.exchange_deposit,
        name="Binance Hot Wallet",
    )
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=cex_deposit,
            counterparty_label=label,
        ),
    ])
    obs = build_observations(case)
    by_addr = {o.address: o for o in obs}
    assert by_addr[cex_deposit].role == "exchange_deposit"
    assert by_addr[cex_deposit].label_name == "Binance Hot Wallet"


def test_perpetrator_label_maps_to_perpetrator_hub_role() -> None:
    perp = "0x" + "d" * 40
    label = _mk_label(perp, category=LabelCategory.perpetrator, name="Perp Wallet")
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=perp,
            counterparty_label=label,
        ),
    ])
    obs = build_observations(case)
    by_addr = {o.address: o for o in obs}
    assert by_addr[perp].role == "perpetrator_hub"


def test_mixer_label_maps_to_mixer_role() -> None:
    mixer = "0x" + "e" * 40
    label = _mk_label(mixer, category=LabelCategory.mixer, name="Tornado Cash 10 ETH")
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=mixer,
            counterparty_label=label,
        ),
    ])
    obs = build_observations(case)
    by_addr = {o.address: o for o in obs}
    assert by_addr[mixer].role == "mixer"


def test_usd_flow_is_summed_across_transfers() -> None:
    """The same counterparty receiving multiple transfers should
    have usd_flowed = sum of those transfers."""
    perp = "0x" + "b" * 40
    case = _mk_case([
        _mk_transfer(from_addr="0x" + "a" * 40, to_addr=perp,
                     usd=Decimal("1000"), tx_hash="0x" + "1" * 64),
        _mk_transfer(from_addr="0x" + "a" * 40, to_addr=perp,
                     usd=Decimal("2500"), tx_hash="0x" + "2" * 64),
    ])
    obs = build_observations(case)
    by_addr = {o.address: o for o in obs}
    # The victim sent $3500 total; the perp received $3500 total.
    assert by_addr[perp].usd_flowed == Decimal("3500")


def test_risk_assessment_flags_ofac_exposure() -> None:
    """An address with an OFAC-category exposure in
    risk_assessment should be flagged is_ofac_exposed=True."""
    perp = "0x" + "b" * 40
    case = _mk_case([_mk_transfer(from_addr="0x" + "a" * 40, to_addr=perp)])
    risk_assessment = {
        "addresses": {
            perp: {
                "score": 10,
                "verdict": "SANCTIONED — direct exposure to OFAC SDN List",
                "exposures": [{
                    "risk_category": "ofac_sanctioned",
                    "counterparty": "0xlazarus",
                    "counterparty_name": "Lazarus Group",
                    "severity": 4,
                    "direction": "outflow",
                    "tx_count": 1,
                    "total_usd": "$50,000",
                }],
            },
        },
    }
    obs = build_observations(case, risk_assessment=risk_assessment)
    by_addr = {o.address: o for o in obs}
    assert by_addr[perp].is_ofac_exposed is True
    assert by_addr[perp].is_mixer_exposed is False
    assert by_addr[perp].risk_score == 10
    assert "SANCTIONED" in (by_addr[perp].risk_verdict or "")


def test_role_dedupe_same_address_same_role_once() -> None:
    """Same address as counterparty in many transfers → ONE
    observation row (per role). The UNIQUE constraint on
    (address, chain, case_id, role) enforces this in the DB; the
    builder should not produce dupes that would conflict on upsert."""
    perp = "0x" + "b" * 40
    case = _mk_case([
        _mk_transfer(from_addr="0x" + "a" * 40, to_addr=perp,
                     tx_hash="0x" + "1" * 64),
        _mk_transfer(from_addr="0x" + "a" * 40, to_addr=perp,
                     tx_hash="0x" + "2" * 64),
        _mk_transfer(from_addr="0x" + "a" * 40, to_addr=perp,
                     tx_hash="0x" + "3" * 64),
    ])
    obs = build_observations(case)
    perp_obs = [o for o in obs if o.address == perp]
    assert len(perp_obs) == 1


def test_freeze_targets_flagged_as_exchange_deposit() -> None:
    """Addresses listed in freeze_targets_by_addr should be
    recorded with role='exchange_deposit' even if they didn't
    appear as a transfer counterparty (e.g. holder addresses
    surfaced via balance scan)."""
    cex_holder = "0x" + "f" * 40
    case = _mk_case([])
    obs = build_observations(
        case,
        freeze_targets_by_addr={cex_holder: {"issuer": "Circle"}},
    )
    by_addr = {o.address: o for o in obs}
    assert cex_holder in by_addr
    assert by_addr[cex_holder].role == "exchange_deposit"


def test_observation_carries_case_id_and_investigation_id() -> None:
    case_uuid = UUID("11111111-1111-1111-1111-111111111111")
    inv_uuid = UUID("22222222-2222-2222-2222-222222222222")
    case = _mk_case([_mk_transfer(
        from_addr="0x" + "a" * 40, to_addr="0x" + "b" * 40,
    )])
    obs = build_observations(case, case_id=case_uuid, investigation_id=inv_uuid)
    assert all(o.case_id == case_uuid for o in obs)
    assert all(o.investigation_id == inv_uuid for o in obs)


# ---- correlations_to_brief_section ---- #


def test_empty_correlations_produces_empty_summary() -> None:
    section = correlations_to_brief_section({})
    assert section["addresses"] == {}
    assert section["summary"]["recidivist_address_count"] == 0


def test_single_recidivist_address_in_section() -> None:
    """Address with 1 prior case appearance → 1 entry in section
    with the headline note."""
    case_uuid = uuid4()
    corr = CorrelationResult(
        address="0xperp",
        chain="ethereum",
        total_prior_cases=1,
        prior_ofac_exposed_count=0,
        prior_mixer_exposed_count=0,
        prior_drainer_attributed_count=0,
        prior_total_usd_flowed=Decimal("1234.56"),
        prior_roles_seen=["hop"],
        prior_case_appearances=[PriorCaseAppearance(
            case_id=case_uuid,
            role="hop",
            label_category=None,
            label_name=None,
            usd_flowed=Decimal("1234.56"),
            risk_verdict=None,
            observed_at_iso="2026-01-01T00:00:00Z",
        )],
    )
    section = correlations_to_brief_section({"0xperp": corr})
    assert "0xperp" in section["addresses"]
    entry = section["addresses"]["0xperp"]
    assert entry["total_prior_cases"] == 1
    assert entry["prior_total_usd_flowed"] == "$1,234.56"
    note = entry["investigator_note"]
    assert "1 prior case" in note
    assert "$1,234.56" in note


def test_ofac_recidivist_flagged_in_summary() -> None:
    """Address OFAC-exposed in a prior case should be counted as
    ofac_recidivist in the summary."""
    corr = CorrelationResult(
        address="0xperp",
        chain="ethereum",
        total_prior_cases=2,
        prior_ofac_exposed_count=1,
        prior_mixer_exposed_count=0,
        prior_drainer_attributed_count=0,
        prior_total_usd_flowed=Decimal("50000"),
        prior_roles_seen=["hop", "perpetrator_hub"],
        prior_case_appearances=[],
    )
    section = correlations_to_brief_section({"0xperp": corr})
    assert section["summary"]["ofac_recidivist_count"] == 1
    assert section["summary"]["recidivist_address_count"] == 1
    # Highest prior case count surfaces in summary.
    assert section["summary"]["highest_prior_case_count"] == 2
    assert section["summary"]["highest_prior_case_address"] == "0xperp"


def test_drainer_recidivist_note_mentions_drainer() -> None:
    """Drainer-attributed-in-prior-cases addresses get the
    'attributed to drainer infrastructure' note."""
    corr = CorrelationResult(
        address="0xperp",
        chain="ethereum",
        total_prior_cases=3,
        prior_ofac_exposed_count=0,
        prior_mixer_exposed_count=0,
        prior_drainer_attributed_count=2,
        prior_total_usd_flowed=Decimal("100000"),
        prior_roles_seen=["drainer_contract"],
        prior_case_appearances=[],
    )
    section = correlations_to_brief_section({"0xperp": corr})
    note = section["addresses"]["0xperp"]["investigator_note"]
    assert "drainer infrastructure" in note
    assert section["summary"]["drainer_recidivist_count"] == 1


def test_zero_prior_cases_filtered_from_section() -> None:
    """Defensive: a CorrelationResult with total_prior_cases=0
    should not produce a section entry (shouldn't happen in
    practice but the lookup-fail path could surface it)."""
    corr = CorrelationResult(
        address="0xperp",
        chain="ethereum",
        total_prior_cases=0,
        prior_ofac_exposed_count=0,
        prior_mixer_exposed_count=0,
        prior_drainer_attributed_count=0,
        prior_total_usd_flowed=Decimal("0"),
        prior_roles_seen=[],
        prior_case_appearances=[],
    )
    section = correlations_to_brief_section({"0xperp": corr})
    assert section["addresses"] == {}
    assert section["summary"]["recidivist_address_count"] == 0


# ---- AddressObservation shape lock ---- #


def test_address_observation_is_frozen_dataclass() -> None:
    """The observation dataclass must be frozen so it's
    hashable / comparable downstream (sets, dedupe queries)."""
    obs = AddressObservation(
        address="0xabc",
        chain="ethereum",
        case_id=None,
        investigation_id=None,
        role="hop",
        label_category=None,
        label_name=None,
        usd_flowed=None,
        risk_score=None,
        risk_verdict=None,
        is_ofac_exposed=False,
        is_mixer_exposed=False,
        is_drainer_attributed=False,
    )
    import pytest
    with pytest.raises(Exception):  # frozen dataclass → FrozenInstanceError
        obs.address = "0xdef"  # type: ignore[misc]
