"""Tests for v0.12.1 wallet-screening API.

DB I/O is skipped (use_correlation_db=False) — these tests verify
the verdict + score logic against the local risk seeds.
"""

from __future__ import annotations

from decimal import Decimal

from recupero.screen.screener import (
    ScreeningCorrelation,
    ScreeningResult,
    screen_address,
)
from recupero.trace.risk_scoring import HighRiskEntry

# ---- Seed-driven verdicts ---- #


def test_ofac_address_is_sanctioned() -> None:
    """An address listed in the seed as ofac_sanctioned → verdict
    SANCTIONED, score 10, is_ofac_sanctioned=True, investigator note
    mentions OFAC."""
    addr = "0x" + "1" * 40
    db = {addr: HighRiskEntry(
        address=addr, name="Lazarus Group",
        risk_category="ofac_sanctioned", severity=4,
        ofac_listing_date="2022-04-14",
    )}
    result = screen_address(
        addr, chain="ethereum",
        use_correlation_db=False, high_risk_db=db,
    )
    assert result.risk_verdict == "sanctioned"
    assert result.is_ofac_sanctioned is True
    assert result.risk_score == 10
    assert result.labels[0].name == "Lazarus Group"
    assert "OFAC" in result.investigator_note
    assert "2022-04-14" in result.investigator_note


def test_ransomware_address_is_sanctioned() -> None:
    addr = "0x" + "2" * 40
    db = {addr: HighRiskEntry(
        address=addr, name="LockBit Operator",
        risk_category="ransomware", severity=4,
    )}
    result = screen_address(addr, use_correlation_db=False, high_risk_db=db)
    assert result.risk_verdict == "sanctioned"
    assert result.is_ransomware is True
    assert "ransomware" in result.investigator_note.lower()


def test_mixer_sanctioned_is_sanctioned() -> None:
    """mixer_sanctioned category → verdict SANCTIONED (not 'high'),
    matching how Treasury's 50% Rule treats Tornado Cash et al."""
    addr = "0x" + "3" * 40
    db = {addr: HighRiskEntry(
        address=addr, name="Tornado Cash: 100 ETH",
        risk_category="mixer_sanctioned", severity=4,
    )}
    result = screen_address(addr, use_correlation_db=False, high_risk_db=db)
    assert result.risk_verdict == "sanctioned"
    assert result.is_mixer is True
    assert result.risk_score == 9


def test_drainer_is_high() -> None:
    """A scam_drainer (sev 3) is high-risk but not 'sanctioned' —
    these are private actors, not Treasury-listed."""
    addr = "0x" + "4" * 40
    db = {addr: HighRiskEntry(
        address=addr, name="Inferno Drainer",
        risk_category="scam_drainer", severity=3,
    )}
    result = screen_address(addr, use_correlation_db=False, high_risk_db=db)
    assert result.risk_verdict == "high"
    assert result.is_drainer is True
    assert result.risk_score == 7
    assert "drainer" in result.investigator_note.lower()


def test_clean_address_is_clean() -> None:
    """An address with no seed hit and no correlation history →
    verdict CLEAN, score 0."""
    addr = "0x" + "5" * 40
    result = screen_address(addr, use_correlation_db=False, high_risk_db={})
    assert result.risk_verdict == "clean"
    assert result.risk_score == 0
    assert result.is_ofac_sanctioned is False
    assert result.is_mixer is False
    assert result.is_drainer is False
    assert result.labels == []


# ---- Correlation-driven verdicts (no seed hit) ---- #


def test_ofac_in_prior_case_is_high_risk() -> None:
    """No seed hit but the address appeared in a prior case that
    had OFAC exposure → verdict HIGH (indirect exposure)."""
    # RIGOR-2 (F841): removed unused `addr = "0x" + "6" * 40` — the
    # test pivoted to calling _verdict_for() directly with the
    # correlation object, never used the address.
    correlation = ScreeningCorrelation(
        prior_case_count=2,
        prior_ofac_exposed_count=1,
        prior_total_usd_flowed=Decimal("50000"),
    )
    # We build the ScreeningResult by calling screen_address with
    # use_correlation_db=False then patching the correlation — but
    # cleaner: assert the verdict via the public path by stubbing
    # the lookup. Easier: directly test the helper.
    from recupero.screen.screener import _verdict_for
    verdict = _verdict_for(
        is_ofac=False, is_mixer=False, is_ransomware=False, is_drainer=False,
        score=6, correlation=correlation,
    )
    assert verdict == "high"


def test_three_prior_cases_no_seed_is_medium() -> None:
    from recupero.screen.screener import _verdict_for
    correlation = ScreeningCorrelation(prior_case_count=3)
    verdict = _verdict_for(
        is_ofac=False, is_mixer=False, is_ransomware=False, is_drainer=False,
        score=3, correlation=correlation,
    )
    assert verdict == "medium"


def test_one_prior_case_no_seed_is_low() -> None:
    from recupero.screen.screener import _verdict_for
    correlation = ScreeningCorrelation(prior_case_count=1)
    verdict = _verdict_for(
        is_ofac=False, is_mixer=False, is_ransomware=False, is_drainer=False,
        score=1, correlation=correlation,
    )
    assert verdict == "low"


# ---- Address normalization ---- #


def test_evm_address_lowercased() -> None:
    """Mixed-case EVM address gets lowercased so it matches the
    seed DB's lowercased keys."""
    upper = "0xABCDef1234567890ABCDef1234567890aBCdEf12"
    lower = upper.lower()
    db = {lower: HighRiskEntry(
        address=lower, name="Test", risk_category="ofac_sanctioned",
        severity=4,
    )}
    result = screen_address(
        upper, chain="ethereum",
        use_correlation_db=False, high_risk_db=db,
    )
    assert result.address == lower
    assert result.risk_verdict == "sanctioned"


def test_tron_address_case_preserved() -> None:
    """Tron base58check is case-sensitive — do NOT lowercase."""
    tron_addr = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    result = screen_address(
        tron_addr, chain="tron",
        use_correlation_db=False, high_risk_db={},
    )
    assert result.address == tron_addr  # case preserved
    assert result.chain == "tron"


def test_empty_address_rejected() -> None:
    import pytest
    with pytest.raises(ValueError, match="empty"):
        screen_address("", use_correlation_db=False, high_risk_db={})


def test_non_string_rejected() -> None:
    import pytest
    with pytest.raises(TypeError, match="must be str"):
        screen_address(12345, use_correlation_db=False, high_risk_db={})  # type: ignore[arg-type]


# ---- to_json_safe ---- #


def test_to_json_safe_serializes_decimal() -> None:
    """Decimal is not JSON-serializable; to_json_safe converts to
    string so REST handlers can json.dumps the result directly."""
    result = ScreeningResult(
        address="0xabc", chain="ethereum",
        risk_verdict="medium", risk_score=3,
        is_ofac_sanctioned=False, is_mixer=False,
        is_ransomware=False, is_drainer=False,
        correlation=ScreeningCorrelation(
            prior_case_count=2,
            prior_total_usd_flowed=Decimal("12345.67"),
        ),
    )
    d = result.to_json_safe()
    # Decimal got serialized as a string
    assert d["correlation"]["prior_total_usd_flowed"] == "12345.67"
    # Top-level is still a plain dict (no Decimal lurking).
    import json
    json.dumps(d)  # should not raise


def test_clean_verdict_data_sources_includes_local() -> None:
    """The screening result always reports its data provenance."""
    result = screen_address(
        "0x" + "f" * 40,
        use_correlation_db=False, high_risk_db={},
    )
    assert "local_seeds" in result.data_sources_used
    assert "correlation_db" not in result.data_sources_used


# ---- Score calibration sanity ---- #


def test_score_calibration_ordered() -> None:
    """OFAC > ransomware > drainer > clean. Lock the ordering so
    a future change can't accidentally make a drainer score higher
    than an OFAC entry."""
    ofac_db = {"a": HighRiskEntry(
        address="a", name="o", risk_category="ofac_sanctioned", severity=4,
    )}
    ransomware_db = {"a": HighRiskEntry(
        address="a", name="r", risk_category="ransomware", severity=4,
    )}
    drainer_db = {"a": HighRiskEntry(
        address="a", name="d", risk_category="scam_drainer", severity=3,
    )}
    s_ofac = screen_address("a", use_correlation_db=False, high_risk_db=ofac_db)
    s_ransomware = screen_address("a", use_correlation_db=False, high_risk_db=ransomware_db)
    s_drainer = screen_address("a", use_correlation_db=False, high_risk_db=drainer_db)
    s_clean = screen_address("z", use_correlation_db=False, high_risk_db={})
    assert s_ofac.risk_score > s_ransomware.risk_score > s_drainer.risk_score > s_clean.risk_score
