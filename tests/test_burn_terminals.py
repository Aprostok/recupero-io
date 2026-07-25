"""Burn-sink terminals in the value-directed tracer (activation of the dormant
burn_sinks module into the BFS stop-and-flag seam).

Funds sent to a known burn sink (0x0 / 0xdEaD / a chain incinerator) are provably
destroyed → the traced money's end state: recorded as an UNRECOVERABLE terminal
(``label_category="burn_sink"``) and NEVER traversed. These unit tests pin the
pure detector's forensic contract, mirroring test_labeled_terminals:
  * only real burn-sink destinations are terminals (registry-driven);
  * same on-chain asset only (a cross-asset / spoof-symbol send is ignored);
  * burn intent is chain-coupled (a Tron burn address on ethereum is NOT a burn);
  * aggregates (amount, USD, tx count) are correct; status is UNRECOVERABLE;
  * the burn reason is surfaced in label_name (dead-address / zero-address / …).
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any

from recupero.trace.tracer import _detect_burn_terminals

# Canonical EVM sinks (from trace.burn_sinks registry).
_DEAD = "0x000000000000000000000000000000000000dead"
_ZERO = "0x0000000000000000000000000000000000000000"
# Tron burn (base58, only a burn on chain="tron").
_TRON_BURN = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"


def _tok(symbol: str = "ETH", contract: str | None = None) -> Any:
    return SimpleNamespace(symbol=symbol, contract=contract)


def _inbound(symbol: str = "ETH", contract: str | None = None) -> Any:
    return SimpleNamespace(token=_tok(symbol, contract))


def _outflow(
    to: str,
    amount: str,
    *,
    chain: str = "ethereum",
    symbol: str = "ETH",
    contract: str | None = None,
    usd: str | None = None,
    tx: str = "0xtx",
) -> Any:
    return SimpleNamespace(
        to_address=to,
        amount_decimal=Decimal(amount),
        usd_value_at_tx=None if usd is None else Decimal(usd),
        tx_hash=tx,
        token=_tok(symbol, contract),
        chain=SimpleNamespace(value=chain),
    )


def test_burn_terminal_detected_unrecoverable() -> None:
    inbound = _inbound("ETH")
    outs = [
        _outflow(_DEAD, "30", usd="90000", tx="0xa"),
        _outflow(_DEAD, "70", usd="210000", tx="0xb"),
        _outflow("0xother", "5", tx="0xd"),  # not a burn — ignored
    ]
    records, kept = _detect_burn_terminals(
        inbound=inbound, node_outflows=outs, node_addr="0xnode", depth=2,
    )
    assert len(records) == 1
    r = records[0]
    assert r["status"] == "UNRECOVERABLE"
    assert r["label_category"] == "burn_sink"
    assert r["label_name"] == "dead-address"   # the burn reason is surfaced
    assert r["terminal_address"] == _DEAD
    assert r["tx_count"] == 2
    assert r["agg_amount"] == "100"
    assert r["agg_usd"] == 300000.0
    assert r["node"] == "0xnode" and r["depth"] == 2
    assert set(r["sample_tx_hashes"]) == {"0xa", "0xb"}
    assert len(kept) == 2 and all(k.to_address == _DEAD for k in kept)


def test_zero_address_burn() -> None:
    records, kept = _detect_burn_terminals(
        inbound=_inbound("ETH"),
        node_outflows=[_outflow(_ZERO, "12", usd="36000")],
        node_addr="0xn", depth=1,
    )
    assert len(records) == 1 and records[0]["status"] == "UNRECOVERABLE"
    assert records[0]["label_name"] == "zero-address"
    assert len(kept) == 1


def test_non_burn_destination_ignored() -> None:
    records, kept = _detect_burn_terminals(
        inbound=_inbound("ETH"),
        node_outflows=[_outflow("0xnotaburn", "100")],
        node_addr="0xn", depth=1,
    )
    assert records == [] and kept == []


def test_cross_asset_burn_not_summed() -> None:
    # Node received ETH but sent USDC to the burn — not the traced (ETH) funds.
    records, kept = _detect_burn_terminals(
        inbound=_inbound("ETH"),
        node_outflows=[_outflow(_DEAD, "1000", symbol="USDC")],
        node_addr="0xn", depth=1,
    )
    assert records == [] and kept == []


def test_burn_intent_is_chain_coupled() -> None:
    # The Tron base58 burn address has no meaning on ethereum → NOT a burn.
    records, _ = _detect_burn_terminals(
        inbound=_inbound("ETH"),
        node_outflows=[_outflow(_TRON_BURN, "50", chain="ethereum")],
        node_addr="0xn", depth=1,
    )
    assert records == []
    # ...but it IS a burn on tron (native TRX same-asset).
    records2, kept2 = _detect_burn_terminals(
        inbound=_inbound("TRX"),
        node_outflows=[_outflow(_TRON_BURN, "50", chain="tron", symbol="TRX")],
        node_addr="0xn", depth=1,
    )
    assert len(records2) == 1 and records2[0]["label_category"] == "burn_sink"
    assert len(kept2) == 1


def test_spoof_contract_not_summed() -> None:
    real = "0x6b175474e89094c44da98b954eedeac495271d0f"
    records, kept = _detect_burn_terminals(
        inbound=_inbound("DAI", real),
        node_outflows=[_outflow(_DEAD, "500", symbol="DAI", contract="0xdeadbeef")],
        node_addr="0xn", depth=1,
    )
    assert records == [] and kept == []
