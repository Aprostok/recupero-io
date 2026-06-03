"""v0.38 (#1) — attribution-coverage report + prioritized labeling targets."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.trace.attribution_coverage import compute_attribution_coverage
from recupero.trace.risk_scoring import HighRiskEntry

SEED = "0x" + "a" * 40
EXCH = "0x" + "b" * 40   # labeled exchange
MIXER = "0x" + "c" * 40  # high-risk db
UNL1 = "0x" + "d" * 40   # unlabeled, big value
UNL2 = "0x" + "e" * 40   # unlabeled, small value
T0 = datetime(2026, 1, 1, tzinfo=UTC)


class _FakeLabelStore:
    def __init__(self, mapping: dict[str, Label] | None = None) -> None:
        self._m = {k.lower(): v for k, v in (mapping or {}).items()}

    def lookup(self, address, chain=Chain.ethereum, *, point_in_time=None):  # noqa: ANN001
        return self._m.get(address.lower() if address.startswith("0x") else address)


def _label(addr: str, cat: LabelCategory, name: str) -> Label:
    return Label(address=addr, name=name, category=cat, source="test", added_at=T0)


def _t(to_addr: str, usd: str, sfx: str) -> Transfer:
    txh = "0x" + (sfx * 64)[:64]
    return Transfer(
        transfer_id=f"ethereum:{txh}:1", chain=Chain.ethereum, tx_hash=txh,
        block_number=1, block_time=T0, from_address=SEED, to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(chain=Chain.ethereum, contract=None, symbol="ETH",
                       decimals=18, coingecko_id="ethereum"),
        amount_raw="1", amount_decimal=Decimal("1"),
        usd_value_at_tx=Decimal(usd), hop_depth=0,
        explorer_url=f"https://etherscan.io/tx/{txh}", fetched_at=T0,
    )


def _case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="t", seed_address=SEED, chain=Chain.ethereum, incident_time=T0,
        transfers=transfers, trace_started_at=T0, software_version="t", config_used={},
    )


def _store() -> _FakeLabelStore:
    return _FakeLabelStore({EXCH: _label(EXCH, LabelCategory.exchange_deposit, "Binance")})


def _db() -> dict[str, HighRiskEntry]:
    return {MIXER.lower(): HighRiskEntry(
        address=MIXER.lower(), name="Tornado Cash",
        risk_category="mixer_high_risk", severity=3)}


def test_empty_case_returns_none() -> None:
    assert compute_attribution_coverage(_case([]), _store()) is None


def test_coverage_and_targets_ranked_by_value() -> None:
    case = _case([
        _t(EXCH, "1000", "1"),    # attributed (label)
        _t(MIXER, "500", "2"),    # attributed (high-risk)
        _t(UNL1, "8000", "3"),    # unlabeled, biggest
        _t(UNL2, "500", "4"),     # unlabeled, small
    ])
    out = compute_attribution_coverage(case, _store(), high_risk_db=_db())
    assert out is not None
    # attributed value = 1000 + 500 = 1500 of 10000 → 15%
    assert out["coverage_pct_by_value"] == 15.0
    assert out["attributed_value"] == "$1,500.00"
    assert out["total_counterparty_value"] == "$10,000.00"
    # 2 of 4 counterparties attributed → 50%
    assert out["coverage_pct_by_count"] == 50.0
    assert out["attributed_count"] == 2
    # targets ranked by inbound value: UNL1 first, then UNL2
    targets = out["labeling_targets"]
    assert [t["address"] for t in targets] == [UNL1, UNL2]
    assert targets[0]["inbound_usd"] == "$8,000.00"
    # sources rolled up
    assert out["attributed_by_source"]["exchange_deposit"] == 1
    assert out["attributed_by_source"]["high_risk"] == 1


def test_seed_excluded_from_targets() -> None:
    # a transfer back to the seed must not appear as a labeling target
    case = _case([_t(SEED, "999", "1"), _t(UNL1, "100", "2")])
    out = compute_attribution_coverage(case, _store())
    addrs = {t["address"] for t in out["labeling_targets"]}
    assert SEED not in addrs
    assert UNL1 in addrs


def test_no_label_store_all_unlabeled() -> None:
    case = _case([_t(UNL1, "100", "1")])
    out = compute_attribution_coverage(case, None)
    assert out["coverage_pct_by_value"] == 0.0
    assert out["attributed_count"] == 0
    assert out["labeling_targets"][0]["address"] == UNL1


def test_top_n_caps_targets() -> None:
    case = _case([_t("0x" + f"{i:040x}", str(100 - i), str(i + 1)) for i in range(20)])
    out = compute_attribution_coverage(case, None, top_n=5)
    assert len(out["labeling_targets"]) == 5


def test_full_coverage_when_all_labeled() -> None:
    case = _case([_t(EXCH, "1000", "1"), _t(MIXER, "1000", "2")])
    out = compute_attribution_coverage(case, _store(), high_risk_db=_db())
    assert out["coverage_pct_by_value"] == 100.0
    assert out["labeling_targets"] == []
