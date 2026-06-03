"""v0.38.0 (#2) — TRM/Chainalysis-style NAMED entity hints on wallet clusters.

`_name_clusters_by_counterparty` attaches an ``entity_hint`` to each cluster
derived from the dominant LABELED counterparty its members share (funding /
withdrawal). It is an ASSOCIATION, never an identity claim: confidence is
medium for a shared exchange counterparty, low otherwise, never high.

These exercise the function directly (it is the new logic; cluster *formation*
is covered by test_v031_clustering.py) plus the end-to-end wiring through
``compute_clusters_with_metadata``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
from recupero.trace.clustering import (
    _name_clusters_by_counterparty,
    compute_clusters_with_metadata,
)

T0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)


class _FakeLabelStore:
    def __init__(self, mapping: dict[str, Label] | None = None) -> None:
        self._mapping = {k.lower(): v for k, v in (mapping or {}).items()}

    def lookup(self, address: str, chain: Chain = Chain.ethereum) -> Label | None:
        if not isinstance(address, str):
            return None
        key = address.lower() if address.startswith("0x") else address
        return self._mapping.get(key)


def _label(addr: str, category: LabelCategory, *, name: str) -> Label:
    return Label(
        address=addr, name=name, category=category, source="test",
        added_at=T0,
    )


def _t(from_addr: str, to_addr: str, *, sfx: str, mins: int = 0) -> Transfer:
    tx = "0x" + (sfx * 64)[:64]
    bt = T0 + timedelta(minutes=mins)
    return Transfer(
        transfer_id=f"ethereum:{tx}:{int(bt.timestamp())}",
        chain=Chain.ethereum, tx_hash=tx, block_number=1, block_time=bt,
        from_address=from_addr, to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(chain=Chain.ethereum, contract=None, symbol="ETH",
                       decimals=18, coingecko_id="ethereum"),
        amount_raw="1", amount_decimal=Decimal("1"),
        usd_value_at_tx=Decimal("1000"), hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx}", fetched_at=bt,
    )


def _case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="t", seed_address="0x" + "9" * 40, chain=Chain.ethereum,
        incident_time=T0, transfers=transfers, trace_started_at=T0,
        software_version="test", config_used={},
    )


# ----- direct unit tests of the naming function ----- #


def test_shared_exchange_counterparty_names_cluster_medium() -> None:
    """Two member wallets both withdrawing to the same labeled exchange
    deposit → entity_hint names the exchange, confidence medium."""
    w1 = "0x" + "1" * 40
    w2 = "0x" + "2" * 40
    binance = "0x" + "b" * 40
    store = _FakeLabelStore({
        binance: _label(binance, LabelCategory.exchange_deposit, name="Binance"),
    })
    case = _case([
        _t(w1, binance, sfx="a", mins=0),
        _t(w2, binance, sfx="b", mins=5),
    ])
    clusters = [{"addresses": [w1, w2]}]
    _name_clusters_by_counterparty(clusters, case, store)

    hint = clusters[0]["entity_hint"]
    assert hint is not None
    assert hint["name"] == "Binance"
    assert hint["category"] == "exchange_deposit"
    assert hint["confidence"] == "medium"
    assert hint["shared_counterparty_transfers"] == 2
    assert hint["relationship"] == "shared_counterparty"
    assert "not an identity claim" in hint["note"]


def test_no_labeled_counterparty_yields_none() -> None:
    w1 = "0x" + "1" * 40
    w2 = "0x" + "2" * 40
    unlabeled = "0x" + "e" * 40
    store = _FakeLabelStore({})  # nothing labeled
    case = _case([_t(w1, unlabeled, sfx="a"), _t(w2, unlabeled, sfx="b")])
    clusters = [{"addresses": [w1, w2]}]
    _name_clusters_by_counterparty(clusters, case, store)
    assert clusters[0]["entity_hint"] is None


def test_exchange_outranks_bridge_when_both_present() -> None:
    """A shared exchange counterparty outranks a shared bridge even if the
    bridge has more transfers — exchange attribution is the stronger signal."""
    w1 = "0x" + "1" * 40
    w2 = "0x" + "2" * 40
    exch = "0x" + "b" * 40
    bridge = "0x" + "d" * 40
    store = _FakeLabelStore({
        exch: _label(exch, LabelCategory.exchange_hot_wallet, name="Kraken"),
        bridge: _label(bridge, LabelCategory.bridge, name="Hop"),
    })
    case = _case([
        _t(w1, exch, sfx="a"),
        _t(w1, bridge, sfx="b", mins=1),
        _t(w2, bridge, sfx="c", mins=2),
        _t(w2, bridge, sfx="d", mins=3),
    ])
    clusters = [{"addresses": [w1, w2]}]
    _name_clusters_by_counterparty(clusters, case, store)
    hint = clusters[0]["entity_hint"]
    assert hint["name"] == "Kraken"
    assert hint["category"] == "exchange_hot_wallet"
    assert hint["confidence"] == "medium"


def test_non_exchange_counterparty_is_low_confidence() -> None:
    w1 = "0x" + "1" * 40
    w2 = "0x" + "2" * 40
    bridge = "0x" + "d" * 40
    store = _FakeLabelStore({
        bridge: _label(bridge, LabelCategory.bridge, name="Hop"),
    })
    case = _case([_t(w1, bridge, sfx="a"), _t(w2, bridge, sfx="b", mins=1)])
    clusters = [{"addresses": [w1, w2]}]
    _name_clusters_by_counterparty(clusters, case, store)
    hint = clusters[0]["entity_hint"]
    assert hint["name"] == "Hop"
    assert hint["confidence"] == "low"


def test_intra_cluster_transfers_are_ignored() -> None:
    """A transfer between two cluster members is not a counterparty signal."""
    w1 = "0x" + "1" * 40
    w2 = "0x" + "2" * 40
    store = _FakeLabelStore({
        w2: _label(w2, LabelCategory.exchange_deposit, name="ShouldNotMatter"),
    })
    case = _case([_t(w1, w2, sfx="a")])  # both in the cluster
    clusters = [{"addresses": [w1, w2]}]
    _name_clusters_by_counterparty(clusters, case, store)
    assert clusters[0]["entity_hint"] is None


# ----- end-to-end wiring through compute_clusters_with_metadata ----- #


def test_entity_hint_present_when_label_store_supplied() -> None:
    """Clusters formed by common funding get an entity_hint key when a
    label_store is passed; the dominant labeled counterparty names them."""
    funder = "0x" + "f" * 40           # unlabeled common funder → forms cluster
    w1 = "0x" + "1" * 40
    w2 = "0x" + "2" * 40
    binance = "0x" + "b" * 40
    store = _FakeLabelStore({
        binance: _label(binance, LabelCategory.exchange_deposit, name="Binance"),
    })
    case = _case([
        # common funding within 1h → H3 clusters w1+w2
        _t(funder, w1, sfx="a", mins=0),
        _t(funder, w2, sfx="b", mins=10),
        # both withdraw to the same labeled exchange → names the cluster
        _t(w1, binance, sfx="c", mins=20),
        _t(w2, binance, sfx="d", mins=25),
    ])
    clusters = compute_clusters_with_metadata(case, label_store=store)
    assert clusters, "expected a cluster from common funding"
    target = next((c for c in clusters if w1 in c["addresses"]), None)
    assert target is not None
    assert "entity_hint" in target
    assert target["entity_hint"]["name"] == "Binance"


def test_no_entity_hint_key_when_label_store_none() -> None:
    """Without a label store the naming pass does not run (no entity_hint)."""
    funder = "0x" + "f" * 40
    w1 = "0x" + "1" * 40
    w2 = "0x" + "2" * 40
    case = _case([
        _t(funder, w1, sfx="a", mins=0),
        _t(funder, w2, sfx="b", mins=10),
    ])
    clusters = compute_clusters_with_metadata(case, label_store=None)
    for c in clusters:
        assert "entity_hint" not in c
