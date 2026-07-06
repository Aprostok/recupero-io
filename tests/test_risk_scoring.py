"""Tests for v0.9.1 risk scoring (OFAC + mixer + darknet exposure).

This is the compliance / law-enforcement-facing layer. Output
is used by:
  * The brief's RISK_ASSESSMENT section (operator + customer view)
  * Issuer freeze letters (Circle / Tether compliance reviews
    OFAC hits faster than non-flagged cases)
  * The CSV export for government tester workflows

Contracts under test:
  * load_high_risk_db — schema flexibility (v0.9.1 + legacy
    mixers.json), missing-file fallback
  * score_addresses — direction tracking (inflow vs outflow),
    aggregation by counterparty, severity-weighted scoring
  * Verdict semantics — OFAC dispositive (any contact → SANCTIONED)
  * Brief-section shape
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.trace.risk_scoring import (
    AddressRiskScore,
    HighRiskEntry,
    load_high_risk_db,
    risk_scores_to_brief_section,
    score_addresses,
)


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal,
    tx_suffix: str = "1",
    chain: Chain = Chain.ethereum,
) -> Transfer:
    tx_hash = "0x" + (tx_suffix * 64)[:64]
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:1",
        chain=chain,
        tx_hash=tx_hash,
        block_number=1,
        block_time=ts,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(
            chain=chain, contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDC", decimals=6, coingecko_id="usd-coin",
        ),
        amount_raw="1000000000",
        amount_decimal=Decimal("1000"),
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=ts,
    )


def _mk_case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="test",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test",
        config_used={},
    )


# ---- load_high_risk_db ---- #


def test_load_high_risk_includes_ofac_entries() -> None:
    """The shipped seed file has Lazarus Group + Hydra +
    Garantex etc. Loader should surface them."""
    db = load_high_risk_db()
    assert len(db) > 0
    # Lazarus Group from the Ronin Bridge exploit
    lazarus = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
    assert lazarus in db
    assert db[lazarus].risk_category == "ofac_sanctioned"
    assert db[lazarus].severity == 4


def test_load_high_risk_tornado_is_high_risk_not_sanctioned() -> None:
    """v0.34 #8: OFAC DELISTED the Tornado Cash protocol on 2025-03-21 (Fifth
    Circuit). The mixers.json Tornado notes record the delisting, so the loader
    must classify them as 'mixer_high_risk' (severity 3) — NOT 'mixer_sanctioned'
    — so a hit does NOT route to an OFAC freeze letter. (A still-listed mixer
    whose notes say OFAC with no delisting marker is still promoted; see
    test_delisting_marker_demotes_sanctioned_promotion.)"""
    db = load_high_risk_db()
    # Tornado Cash 0.1 ETH from the seed file
    tornado = "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936"
    assert tornado in db
    assert db[tornado].risk_category == "mixer_high_risk"
    assert db[tornado].severity == 3
    assert "delisted" in (db[tornado].notes or "").lower()


def test_delisting_marker_demotes_sanctioned_promotion() -> None:
    """v0.34 #8 (seed-independent): the mixers.json loader promotes an
    OFAC-noted entry to 'mixer_sanctioned' (sev 4) — UNLESS the notes record a
    delisting/overturn, in which case it demotes to 'mixer_high_risk' (sev 3).
    This pins the loader's discrimination directly (not via the shipped seeds),
    so the Tornado-Cash-delisting behavior can't silently regress."""
    delisted_addr = "0x" + "d" * 40   # OFAC mention + delisting marker
    listed_addr = "0x" + "e" * 40     # OFAC mention, still listed
    mixers_payload = [
        {
            "address": delisted_addr,
            "name": "DelistedMixerShape",
            "notes": "OFAC-sanctioned 2022-08-08; DELISTED 2025-03-21 (5th Cir.)",
        },
        {
            "address": listed_addr,
            "name": "StillSanctionedMixerShape",
            "notes": "OFAC-sanctioned — active SDN designation",
        },
    ]
    with TemporaryDirectory() as td:
        hr = Path(td) / "hr.json"
        hr.write_text(json.dumps({"addresses": []}))
        mx = Path(td) / "mx.json"
        mx.write_text(json.dumps(mixers_payload))
        rw = Path(td) / "rw.json"
        rw.write_text(json.dumps({"addresses": []}))
        db = load_high_risk_db(hr, mx, rw)

    # Delisted entry: demoted to high-risk (no OFAC freeze-letter routing).
    assert db[delisted_addr].risk_category == "mixer_high_risk"
    assert db[delisted_addr].severity == 3
    # Still-listed entry: promoted to sanctioned (the loader's default).
    assert db[listed_addr].risk_category == "mixer_sanctioned"
    assert db[listed_addr].severity == 4


def test_ofac_feed_provides_authoritative_attribution() -> None:
    """v0.34 — sanctioned coverage comes from the committed OFAC SDN feed
    (ofac_crypto_live.csv) with OFAC's OWN attribution, not hand-maintained
    hardcoded labels (which a cross-check proved were systematically wrong).
    Locks in: the feed loads, and previously-mislabeled addresses now resolve
    to their true OFAC entity (and the fabricated 'Sinbad' EVM entry is gone)."""
    db = load_high_risk_db()
    # The feed is substantial (Treasury lists hundreds of crypto addresses).
    assert len(db) > 500
    # Previously hardcoded as "Garantex" — OFAC actually lists it under SUEX.
    suex = db.get("0x308ed4b7b49797e1a98d3818bff6fe5385410370")
    assert suex is not None and "SUEX" in suex.name
    assert suex.risk_category == "ofac_sanctioned"
    # Previously hardcoded as "Sinbad.io" — OFAC lists it under Mingming Wang.
    wang = db.get("0xfac583c0cf07ea434052c49115a4682172ab6b4f")
    assert wang is not None and "WANG" in wang.name.upper()
    # The fabricated "Sinbad.io" EVM entry (actually a Tornado pool, not in SDN)
    # must be gone.
    assert "0xb1c8094b234dce6e03f10a5b673c1d8c69739a00" not in db


def test_load_high_risk_missing_file_returns_empty() -> None:
    """All seed files missing → empty dict, never raises. The always-on OFAC
    live feed is isolated via a missing ofac_csv_path so this asserts the
    seed-loading behavior, not the committed authoritative feed."""
    db = load_high_risk_db(
        high_risk_path=Path("/does/not/exist.json"),
        mixers_path=Path("/does/not/exist2.json"),
        ransomware_path=Path("/does/not/exist3.json"),
        ofac_csv_path=Path("/does/not/exist_ofac.csv"),
        # v0.39: isolate the committed internal-blacklist seed too, so this
        # asserts seed-loading behavior, not the shipped curated known-bad list.
        internal_blacklist_path=Path("/does/not/exist_ibl.json"),
        internal_blacklist_seed_path=Path("/does/not/exist_ibl_seed.json"),
    )
    assert db == {}


def test_load_high_risk_with_custom_paths(tmp_path) -> None:
    """Custom seed files work — useful for compliance teams
    adding their own internal allow/deny lists."""
    custom = tmp_path / "custom.json"
    custom.write_text(json.dumps({
        "addresses": [{
            "address": "0xfeed0000000000000000000000000000000000ff",
            "name": "Custom watchlist entry",
            "risk_category": "ofac_sanctioned",
            "severity": 4,
        }],
    }), encoding="utf-8")
    db = load_high_risk_db(
        high_risk_path=custom,
        mixers_path=Path("/nope.json"),
        ransomware_path=Path("/nope2.json"),
        ofac_csv_path=Path("/nope_ofac.csv"),
        internal_blacklist_path=Path("/nope_ibl.json"),
        internal_blacklist_seed_path=Path("/nope_ibl_seed.json"),
    )
    assert len(db) == 1
    entry = next(iter(db.values()))
    assert entry.name == "Custom watchlist entry"
    assert entry.severity == 4


# ---- score_addresses ---- #


def test_no_high_risk_db_returns_empty() -> None:
    """Without a seed, scoring returns empty (no risk attributed
    to any address). Better than failing the brief."""
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr="0x" + "b" * 40,
            usd=Decimal("1000"),
        ),
    ])
    out = score_addresses(case, high_risk_db={})
    assert out == {}


def test_outflow_to_lazarus_flags_sender() -> None:
    """A transfer FROM a case address TO an OFAC-sanctioned
    Lazarus address → the sender gets flagged with an
    outflow exposure."""
    lazarus = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
    sender = "0x" + "1" * 40
    fake_db = {lazarus: HighRiskEntry(
        address=lazarus, name="Lazarus Group", risk_category="ofac_sanctioned",
        severity=4,
    )}
    case = _mk_case([
        _mk_transfer(from_addr=sender, to_addr=lazarus,
                     usd=Decimal("50000")),
    ])
    out = score_addresses(case, high_risk_db=fake_db)
    assert sender in out
    score = out[sender]
    assert score.score == 4  # severity 4 × tx_count 1
    assert "SANCTIONED" in score.verdict
    assert len(score.exposures) == 1
    assert score.exposures[0].direction == "outflow"
    assert score.exposures[0].counterparty == lazarus
    assert score.exposures[0].counterparty_name == "Lazarus Group"


def test_inflow_from_sanctioned_flags_receiver() -> None:
    """A transfer FROM a sanctioned address TO a case address →
    the RECEIVER gets flagged with an inflow exposure. This is
    how an investigator detects 'address X received funds from
    a Lazarus-controlled wallet.'"""
    lazarus = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
    receiver = "0x" + "2" * 40
    fake_db = {lazarus: HighRiskEntry(
        address=lazarus, name="Lazarus Group", risk_category="ofac_sanctioned",
        severity=4,
    )}
    case = _mk_case([
        _mk_transfer(from_addr=lazarus, to_addr=receiver,
                     usd=Decimal("50000")),
    ])
    out = score_addresses(case, high_risk_db=fake_db)
    assert receiver in out
    assert out[receiver].exposures[0].direction == "inflow"


def test_score_aggregates_multiple_transfers_to_same_counterparty() -> None:
    """5 transfers to the same Tornado Cash pool → tx_count = 5,
    score = 4 × 5 = 20, one exposure entry."""
    tornado = "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936"
    sender = "0x" + "1" * 40
    fake_db = {tornado: HighRiskEntry(
        address=tornado, name="Tornado Cash: 0.1 ETH",
        risk_category="mixer_sanctioned", severity=4,
    )}
    case = _mk_case([
        _mk_transfer(from_addr=sender, to_addr=tornado,
                     usd=Decimal("100"), tx_suffix=str(i))
        for i in range(1, 6)
    ])
    out = score_addresses(case, high_risk_db=fake_db)
    assert out[sender].score == 20
    assert len(out[sender].exposures) == 1
    assert out[sender].exposures[0].tx_count == 5
    assert out[sender].exposures[0].total_usd == Decimal("500")


def test_score_sorts_exposures_by_severity() -> None:
    """An address with multiple exposures of different severities
    → highest severity first in the exposures list. Investigator
    reads top-down and sees the most-actionable first."""
    high_sev = "0x" + "f" * 40
    low_sev = "0x" + "e" * 40
    sender = "0x" + "1" * 40
    fake_db = {
        high_sev: HighRiskEntry(
            address=high_sev, name="OFAC-flagged",
            risk_category="ofac_sanctioned", severity=4,
        ),
        low_sev: HighRiskEntry(
            address=low_sev, name="Scam drainer",
            risk_category="scam_drainer", severity=3,
        ),
    }
    case = _mk_case([
        _mk_transfer(from_addr=sender, to_addr=low_sev,
                     usd=Decimal("1000"), tx_suffix="1"),
        _mk_transfer(from_addr=sender, to_addr=high_sev,
                     usd=Decimal("1000"), tx_suffix="2"),
    ])
    out = score_addresses(case, high_risk_db=fake_db)
    exposures = out[sender].exposures
    assert exposures[0].severity == 4  # OFAC first
    assert exposures[1].severity == 3


def test_no_exposure_returns_empty_for_clean_address() -> None:
    """An address that only interacts with non-risky counterparties
    doesn't appear in the output dict. The result is naturally
    focused on the addresses an investigator needs to act on."""
    sender = "0x" + "1" * 40
    receiver = "0x" + "2" * 40
    fake_db = {"0x" + "f" * 40: HighRiskEntry(
        address="0x" + "f" * 40, name="Unrelated risky",
        risk_category="ofac_sanctioned", severity=4,
    )}
    case = _mk_case([
        _mk_transfer(from_addr=sender, to_addr=receiver,
                     usd=Decimal("1000")),
    ])
    out = score_addresses(case, high_risk_db=fake_db)
    assert out == {}


# ---- Verdict semantics ---- #


def test_ofac_exposure_is_dispositive_verdict() -> None:
    """Even one transaction with an OFAC-sanctioned counterparty
    → verdict 'SANCTIONED' regardless of numeric score. Matches
    Treasury's 50% Rule view: any transaction with sanctioned
    entity is a sanctioned transaction."""
    sender = "0x" + "1" * 40
    # RIGOR-2 (F841): removed `fake_db = {...}` that was never patched
    # into anything. The test instead manually appends an
    # AddressExposure and calls _verdict_for_score(score) below —
    # the fake_db was a leftover from an earlier injection approach.
    score = AddressRiskScore(
        address=sender, score=1,  # low numeric score
        exposures=[],
    )
    # Manually inject the right exposure
    from recupero.trace.risk_scoring import AddressExposure, _verdict_for_score
    score.exposures.append(AddressExposure(
        counterparty="0xfeed", counterparty_name="Sanctioned",
        risk_category="ofac_sanctioned", severity=4,
        direction="outflow", tx_count=1,
        total_usd=Decimal("1"),
    ))
    verdict = _verdict_for_score(score)
    assert "SANCTIONED" in verdict
    assert "OFAC" in verdict


def test_clean_verdict_when_no_exposures() -> None:
    from recupero.trace.risk_scoring import _verdict_for_score
    score = AddressRiskScore(address="0x1", score=0, exposures=[])
    assert _verdict_for_score(score).startswith("CLEAN")


def test_intl_sanctioned_is_dispositive_but_not_ofac() -> None:
    """A non-OFAC sanctions hit (EU/UN/UK/…) is SANCTIONED-class — it must NOT
    fall through to the numeric "HIGH-RISK — exposure to mixers or scam ops"
    verdict — but it must NOT be worded/counted as OFAC (that would mis-route
    the freeze letter + trigger the OFAC-only recovery multiplier)."""
    from recupero.trace.risk_scoring import AddressExposure, _verdict_for_score
    score = AddressRiskScore(address="0x1", score=4, exposures=[
        AddressExposure(
            counterparty="0xfeed", counterparty_name="EU-sanctioned wallet",
            risk_category="intl_sanctioned", severity=4,
            direction="outflow", tx_count=1, total_usd=Decimal("1"),
        ),
    ])
    verdict = _verdict_for_score(score)
    assert verdict.startswith("SANCTIONED")
    assert "non-OFAC" in verdict
    assert "OFAC SDN" not in verdict  # not routed as an OFAC designation
    assert "mixer" not in verdict.lower()  # the pre-fix wrong wording


def test_intl_sanctioned_summary_count_separate_from_ofac() -> None:
    """intl_sanctioned_count is a distinct headline count; it does NOT inflate
    ofac_exposed_count (which drives OFAC-licensed-counsel routing)."""
    eu = "0x" + "e" * 40
    sender = "0x" + "1" * 40
    fake_db = {eu: HighRiskEntry(
        address=eu, name="EU-sanctioned wallet",
        risk_category="intl_sanctioned", severity=4,
    )}
    case = _mk_case([
        _mk_transfer(from_addr=sender, to_addr=eu, usd=Decimal("50000")),
    ])
    section = risk_scores_to_brief_section(score_addresses(case, high_risk_db=fake_db))
    summary = section["summary"]
    assert summary["intl_sanctioned_count"] == 1
    assert summary["ofac_exposed_count"] == 0
    assert summary["mixer_exposed_count"] == 0
    assert section["addresses"][sender]["verdict"].startswith("SANCTIONED")


# ---- Brief section ---- #


def test_brief_section_shape() -> None:
    """Locked: brief consumers bind against these keys."""
    lazarus = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
    sender = "0x" + "1" * 40
    fake_db = {lazarus: HighRiskEntry(
        address=lazarus, name="Lazarus", risk_category="ofac_sanctioned",
        severity=4,
    )}
    case = _mk_case([
        _mk_transfer(from_addr=sender, to_addr=lazarus,
                     usd=Decimal("50000")),
    ])
    scores = score_addresses(case, high_risk_db=fake_db)
    section = risk_scores_to_brief_section(scores)

    assert "addresses" in section
    assert "summary" in section

    summary = section["summary"]
    assert summary["addresses_assessed"] == 1
    assert summary["ofac_exposed_count"] == 1
    assert summary["mixer_exposed_count"] == 0
    assert summary["highest_score"] == 4
    assert summary["highest_score_address"] == sender

    addr_entry = section["addresses"][sender]
    assert addr_entry["score"] == 4
    assert "SANCTIONED" in addr_entry["verdict"]
    assert len(addr_entry["exposures"]) == 1
    exp = addr_entry["exposures"][0]
    assert exp["counterparty_name"] == "Lazarus"
    assert exp["risk_category"] == "ofac_sanctioned"
    assert exp["direction"] == "outflow"
    assert exp["total_usd"] == "$50,000.00"


def test_brief_section_empty_when_no_exposures() -> None:
    """Clean case → empty addresses + zeroed summary."""
    section = risk_scores_to_brief_section({})
    assert section["addresses"] == {}
    assert section["summary"]["addresses_assessed"] == 0
    assert section["summary"]["ofac_exposed_count"] == 0
    assert section["summary"]["highest_score"] == 0
    assert section["summary"]["highest_score_address"] is None


def test_load_preserves_base58_case_for_solana() -> None:
    """v0.17.5 (round-10 forensic HIGH): pre-v0.17.5 the loader
    stored every address ``addr.lower()`` which mangled base58
    chains. A sanctioned Solana wallet pasted in its canonical
    mixed-case form would never be found by a case-preserving
    screener lookup. Now: only EVM (0x + 40 hex) gets lowercased;
    base58 entries land as-given.
    """
    from recupero.trace.risk_scoring import load_high_risk_db

    with TemporaryDirectory() as td:
        td_p = Path(td)
        hr_path = td_p / "high_risk.json"
        hr_path.write_text(json.dumps({
            "_meta": {"_section": "test"},
            "addresses": [
                {
                    # Real Solana address (mixed-case base58).
                    "address": "BcrW1fJRwSoNYRBn5UxbVKsKsXdNRwGsQbf5KAcDuwfV",
                    "name": "Test Sanctioned SOL",
                    "risk_category": "ofac_sanctioned",
                    "severity": 4,
                },
                {
                    # Real EVM address (checksum-cased).
                    "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "name": "Test EVM",
                    "risk_category": "ofac_sanctioned",
                    "severity": 4,
                },
            ],
        }))
        mx_path = td_p / "mixers.json"
        mx_path.write_text("[]")
        rw_path = td_p / "ransomware.json"
        rw_path.write_text(json.dumps({"addresses": []}))
        db = load_high_risk_db(
            high_risk_path=hr_path,
            mixers_path=mx_path,
            ransomware_path=rw_path,
        )

    # Solana entry preserved case-for-case.
    assert "BcrW1fJRwSoNYRBn5UxbVKsKsXdNRwGsQbf5KAcDuwfV" in db, (
        f"Solana base58 was mangled by lowercasing — got keys {list(db)}"
    )
    # EVM entry was lowercased canonically.
    assert "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" in db
    assert "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" not in db
