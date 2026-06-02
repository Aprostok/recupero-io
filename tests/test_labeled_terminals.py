"""v0.34.7 label-aware terminals (TRM/Chainalysis "stop-and-flag at the mixer").

At a directed node, a same-asset outflow that lands at a LABELED mixer / exchange
/ bridge is the traced money's END STATE — recorded (so the brief classifies it
UNRECOVERABLE / EXCHANGE / etc. from the existing label) and NOT chased. These
unit tests pin the pure detector's forensic contract:
  * same on-chain asset only (contract identity — a spoof-symbol token is ignored);
  * cross-asset outflows are not summed (we follow the traced funds);
  * only mixer/exchange/bridge categories are terminals (defi/staking/unknown not);
  * aggregates (amount, USD, tx count) are correct; mixer→UNRECOVERABLE etc.;
  * unlabeled outflows are never invented into a terminal.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any

from recupero.models import LabelCategory
from recupero.trace.tracer import (
    _detect_labeled_terminals,
    _same_onchain_asset,
    _terminal_status_for_category,
)


def _tok(symbol: str = "ETH", contract: str | None = None) -> Any:
    return SimpleNamespace(symbol=symbol, contract=contract)


def _inbound(symbol: str = "ETH", contract: str | None = None) -> Any:
    return SimpleNamespace(token=_tok(symbol, contract))


def _outflow(
    to: str,
    amount: str,
    *,
    category: LabelCategory | None = None,
    name: str = "Some Service",
    symbol: str = "ETH",
    contract: str | None = None,
    usd: str | None = None,
    tx: str = "0xtx",
) -> Any:
    label = None if category is None else SimpleNamespace(category=category, name=name)
    cp = SimpleNamespace(label=label)
    return SimpleNamespace(
        to_address=to,
        amount_decimal=Decimal(amount),
        usd_value_at_tx=None if usd is None else Decimal(usd),
        tx_hash=tx,
        token=_tok(symbol, contract),
        counterparty=cp,
    )


# ----------------------------- status mapping ----------------------------- #


def test_status_mapping() -> None:
    assert _terminal_status_for_category(LabelCategory.mixer) == "UNRECOVERABLE"
    assert _terminal_status_for_category(LabelCategory.exchange_deposit) == "EXCHANGE"
    assert _terminal_status_for_category(LabelCategory.exchange_hot_wallet) == "EXCHANGE"
    assert _terminal_status_for_category(LabelCategory.bridge) == "BRIDGE"
    assert _terminal_status_for_category(LabelCategory.defi_protocol) == "TRANSIT"


# --------------------------- same-asset identity --------------------------- #


def test_same_onchain_asset_native_by_symbol() -> None:
    assert _same_onchain_asset(_tok("ETH"), _tok("ETH")) is True
    assert _same_onchain_asset(_tok("ETH"), _tok("WETH")) is False


def test_same_onchain_asset_contract_identity() -> None:
    real = "0x6b175474e89094c44da98b954eedeac495271d0f"
    assert _same_onchain_asset(_tok("DAI", real), _tok("DAI", real.upper())) is True
    # same symbol, different contract = spoof → NOT the same asset
    assert _same_onchain_asset(_tok("DAI", real), _tok("DAI", "0xdeadbeef")) is False
    # a known contract never matches an unknown one
    assert _same_onchain_asset(_tok("DAI", real), _tok("DAI", None)) is False


# ----------------------------- terminal detection -------------------------- #


def test_mixer_terminal_detected_unrecoverable() -> None:
    inbound = _inbound("ETH")
    # 3 same-asset sends to one mixer (a peel into Tornado), none ~the inbound.
    outs = [
        _outflow("0xmix", "30", category=LabelCategory.mixer, name="Tornado Cash: 100 ETH", usd="90000", tx="0xa"),
        _outflow("0xmix", "30", category=LabelCategory.mixer, name="Tornado Cash: 100 ETH", usd="90000", tx="0xb"),
        _outflow("0xmix", "40", category=LabelCategory.mixer, name="Tornado Cash: 100 ETH", usd="120000", tx="0xc"),
        _outflow("0xother", "5", symbol="ETH", tx="0xd"),  # unlabeled — ignored
    ]
    records, kept = _detect_labeled_terminals(
        inbound=inbound, node_outflows=outs, node_addr="0xnode", depth=2,
    )
    assert len(records) == 1
    r = records[0]
    assert r["status"] == "UNRECOVERABLE"
    assert r["label_category"] == "mixer"
    assert r["terminal_address"] == "0xmix"
    assert r["tx_count"] == 3
    assert r["agg_amount"] == "100"
    assert r["agg_usd"] == 300000.0
    assert r["node"] == "0xnode" and r["depth"] == 2
    assert set(r["sample_tx_hashes"]) == {"0xa", "0xb", "0xc"}
    # the 3 real mixer outflows are KEPT (re-recorded); the unlabeled one is not
    assert len(kept) == 3
    assert all(k.to_address == "0xmix" for k in kept)


def test_exchange_terminal_detected() -> None:
    inbound = _inbound("ETH")
    outs = [_outflow("0xcex", "12", category=LabelCategory.exchange_deposit, name="Binance", usd="36000")]
    records, kept = _detect_labeled_terminals(
        inbound=inbound, node_outflows=outs, node_addr="0xn", depth=1,
    )
    assert len(records) == 1 and records[0]["status"] == "EXCHANGE"
    assert len(kept) == 1


def test_multiple_terminals_each_recorded() -> None:
    inbound = _inbound("ETH")
    outs = [
        _outflow("0xmix", "50", category=LabelCategory.mixer, name="Tornado", tx="0x1"),
        _outflow("0xcex", "20", category=LabelCategory.exchange_hot_wallet, name="OKX", tx="0x2"),
    ]
    records, kept = _detect_labeled_terminals(
        inbound=inbound, node_outflows=outs, node_addr="0xn", depth=1,
    )
    statuses = {r["terminal_address"]: r["status"] for r in records}
    assert statuses == {"0xmix": "UNRECOVERABLE", "0xcex": "EXCHANGE"}
    assert len(kept) == 2


def test_non_terminal_categories_ignored() -> None:
    inbound = _inbound("ETH")
    outs = [
        _outflow("0xstake", "50", category=LabelCategory.staking, name="Lido"),
        _outflow("0xdefi", "50", category=LabelCategory.defi_protocol, name="Uniswap"),
        _outflow("0xvic", "50", category=LabelCategory.victim, name="Victim"),
    ]
    records, kept = _detect_labeled_terminals(
        inbound=inbound, node_outflows=outs, node_addr="0xn", depth=1,
    )
    assert records == [] and kept == []


def test_unlabeled_outflows_never_invented() -> None:
    inbound = _inbound("ETH")
    outs = [_outflow("0xunknown", "100", category=None)]
    records, kept = _detect_labeled_terminals(
        inbound=inbound, node_outflows=outs, node_addr="0xn", depth=1,
    )
    assert records == [] and kept == []


def test_cross_asset_outflow_not_summed() -> None:
    # Node received ETH but sent USDC to a mixer — not the traced (ETH) funds.
    inbound = _inbound("ETH")
    outs = [_outflow("0xmix", "1000", category=LabelCategory.mixer, name="Tornado", symbol="USDC")]
    records, kept = _detect_labeled_terminals(
        inbound=inbound, node_outflows=outs, node_addr="0xn", depth=1,
    )
    assert records == [] and kept == []


def test_spoof_contract_not_summed() -> None:
    real = "0x6b175474e89094c44da98b954eedeac495271d0f"
    inbound = _inbound("DAI", real)
    outs = [
        _outflow("0xmix", "500", category=LabelCategory.mixer, name="Tornado",
                 symbol="DAI", contract="0xdeadbeef"),  # spoof DAI
    ]
    records, kept = _detect_labeled_terminals(
        inbound=inbound, node_outflows=outs, node_addr="0xn", depth=1,
    )
    assert records == [] and kept == []
