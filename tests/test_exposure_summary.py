"""v0.38.0 — fund-flow exposure summary (TRM/Chainalysis-style headline %)."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.trace.exposure_summary import compute_exposure_summary
from recupero.trace.risk_scoring import HighRiskEntry

SEED = "0x" + "a" * 40
MIXER = "0x" + "b" * 40
SANCTIONED = "0x" + "c" * 40
CLEAN = "0x" + "d" * 40


def _t(to_addr: str, usd: str, sfx: str) -> Transfer:
    txh = "0x" + (sfx * 64)[:64]
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    return Transfer(
        transfer_id=f"ethereum:{txh}:1", chain=Chain.ethereum, tx_hash=txh,
        block_number=1, block_time=ts, from_address=SEED, to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(chain=Chain.ethereum, contract=None, symbol="ETH",
                       decimals=18, coingecko_id="ethereum"),
        amount_raw="1", amount_decimal=Decimal("1"),
        usd_value_at_tx=Decimal(usd), hop_depth=0,
        explorer_url=f"https://etherscan.io/tx/{txh}", fetched_at=ts,
    )


def _case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="test", seed_address=SEED, chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC), transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test", config_used={},
    )


def _db() -> dict[str, HighRiskEntry]:
    return {
        MIXER.lower(): HighRiskEntry(
            address=MIXER.lower(), name="Tornado Cash",
            risk_category="mixer_high_risk", severity=3),
        SANCTIONED.lower(): HighRiskEntry(
            address=SANCTIONED.lower(), name="Lazarus Group",
            risk_category="ofac_sanctioned", severity=4),
    }


def test_no_high_risk_db_returns_none() -> None:
    case = _case([_t(CLEAN, "100", "1")])
    assert compute_exposure_summary(case, {}) is None


def test_benign_case_returns_none() -> None:
    # transfers only to clean addresses → no exposure → None (brief stays clean)
    case = _case([_t(CLEAN, "9999", "1")])
    assert compute_exposure_summary(case, _db()) is None


def test_direct_exposure_percentages_and_headline() -> None:
    case = _case([
        _t(MIXER, "1000", "1"),
        _t(SANCTIONED, "500", "2"),
        _t(CLEAN, "8500", "3"),
    ])
    out = compute_exposure_summary(
        case, _db(), total_traced_usd=Decimal("10000"),
    )
    assert out is not None
    # OFAC ranks above mixer → headline + first row is the sanctioned exposure.
    assert out["headline"] == "5.0% of traced value ($500.00) reached OFAC-sanctioned entities"
    cats = {r["category"]: r for r in out["by_category"]}
    assert cats["ofac_sanctioned"]["direct_pct"] == 5.0
    assert cats["ofac_sanctioned"]["direct_usd"] == "$500.00"
    assert cats["mixer_high_risk"]["direct_pct"] == 10.0
    assert out["by_category"][0]["category"] == "ofac_sanctioned"  # ranked first
    assert out["total_direct_exposure_usd"] == "$1,500.00"
    assert out["total_direct_exposure_pct"] == 15.0


def test_denominator_defaults_to_seed_outflows() -> None:
    case = _case([_t(MIXER, "2000", "1"), _t(CLEAN, "2000", "2")])
    out = compute_exposure_summary(case, _db())  # no explicit denom
    assert out is not None
    cats = {r["category"]: r for r in out["by_category"]}
    # denom = seed outflows = 4000; mixer 2000 → 50%
    assert cats["mixer_high_risk"]["direct_pct"] == 50.0


def test_pct_capped_at_100() -> None:
    case = _case([_t(MIXER, "1000", "1")])
    out = compute_exposure_summary(case, _db(), total_traced_usd=Decimal("100"))
    cats = {r["category"]: r for r in out["by_category"]}
    assert cats["mixer_high_risk"]["direct_pct"] == 100.0  # 1000/100 capped
