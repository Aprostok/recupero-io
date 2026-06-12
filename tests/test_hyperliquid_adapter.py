"""Roadmap-v4 Tier-2 #12: Hyperliquid for_chain adapter.

Builds on the LIVE-VERIFIED HyperliquidLedgerEvent / get_non_funding_ledger_
updates shape (already covered by test_hyperliquid_*); here we verify the
adapter maps withdraw/deposit ledger events to the tracer's normalized-transfer
dict shape and is registered in ChainAdapter.for_chain.
"""

from __future__ import annotations

from decimal import Decimal

from recupero.chains.hyperliquid.adapter import HyperliquidAdapter
from recupero.chains.hyperliquid.client import HyperliquidLedgerEvent
from recupero.models import Chain

_USER = "0x" + "11" * 20
_ARB_DEST = "0x" + "ab" * 20


def _evt(delta_type, usdc_delta, *, destination=None, h="0xevt", time_ms=1_700_000_000_000):
    return HyperliquidLedgerEvent(
        time_ms=time_ms, hash=h, delta_type=delta_type,
        usdc_delta=Decimal(usdc_delta), destination=destination, raw={},
    )


class _StubClient:
    def __init__(self, events):
        self.events = events
        self.closed = False

    def get_non_funding_ledger_updates(self, user, *, start_time_ms, end_time_ms=None):
        self.user = user
        self.start_time_ms = start_time_ms
        return self.events

    def close(self):
        self.closed = True


def test_for_chain_returns_hyperliquid_adapter() -> None:
    from recupero.chains.base import ChainAdapter
    a = ChainAdapter.for_chain(Chain.hyperliquid, None)
    assert isinstance(a, HyperliquidAdapter)
    a.close()


def test_withdraw_maps_to_normalized_outflow() -> None:
    a = HyperliquidAdapter(client=_StubClient([
        _evt("withdraw", "-1000.5", destination=_ARB_DEST),
    ]))
    rows = a.fetch_native_outflows(_USER)
    assert len(rows) == 1
    r = rows[0]
    assert r["chain"] == Chain.hyperliquid
    assert r["from"].lower() == _USER          # outflow: from = the HL user
    assert r["to"].lower() == _ARB_DEST        # to = the Arbitrum destination
    assert r["amount_raw"] == 1_000_500_000    # 1000.5 USDC * 1e6
    assert r["token"].symbol == "USDC"
    assert r["token"].decimals == 6
    assert r["_native_source"] == "hyperliquid_ledger"
    # start_time_ms = epoch 0 (all history)
    assert a.client.start_time_ms == 0


def test_internal_delta_types_excluded() -> None:
    a = HyperliquidAdapter(client=_StubClient([
        _evt("spotTransfer", "-50", destination=_ARB_DEST),
        _evt("accountClassTransfer", "-50"),
        _evt("subAccountTransfer", "-50", destination=_ARB_DEST),
    ]))
    assert a.fetch_native_outflows(_USER) == []   # none are external value flows


def test_deposit_is_inflow_not_outflow() -> None:
    a = HyperliquidAdapter(client=_StubClient([
        _evt("deposit", "2000", destination=_ARB_DEST),
    ]))
    assert a.fetch_native_outflows(_USER) == []
    inflows = a.fetch_inflows(_USER)
    assert len(inflows) == 1
    assert inflows[0]["to"].lower() == _USER       # deposit: to = the HL user
    assert inflows[0]["amount_raw"] == 2_000_000_000


def test_zero_and_nonfinite_deltas_skipped() -> None:
    a = HyperliquidAdapter(client=_StubClient([
        _evt("withdraw", "0", destination=_ARB_DEST),
        HyperliquidLedgerEvent(time_ms=1, hash="0xnan", delta_type="withdraw",
                               usdc_delta=Decimal("NaN"), destination=_ARB_DEST, raw={}),
    ]))
    assert a.fetch_native_outflows(_USER) == []


def test_unknown_destination_is_placeholder_not_fabricated() -> None:
    a = HyperliquidAdapter(client=_StubClient([
        _evt("withdraw", "-10", destination=None),
    ]))
    rows = a.fetch_native_outflows(_USER)
    assert len(rows) == 1
    # destination unresolved → terminal placeholder, never a made-up 0x address
    assert rows[0]["to"] == "hyperliquid:unknown_destination"


def test_erc20_outflows_always_empty() -> None:
    a = HyperliquidAdapter(client=_StubClient([_evt("withdraw", "-1", destination=_ARB_DEST)]))
    assert a.fetch_erc20_outflows(_USER) == []


def test_is_contract_false_and_no_blocks() -> None:
    from datetime import UTC, datetime
    a = HyperliquidAdapter(client=_StubClient([]))
    assert a.is_contract(_USER) is False
    assert a.block_at_or_before(datetime.now(UTC)) == -1


def test_evidence_receipt_raises_not_fabricated() -> None:
    import pytest
    a = HyperliquidAdapter(client=_StubClient([]))
    with pytest.raises(ValueError, match="no per-event receipt"):
        a.fetch_evidence_receipt("0xevt")
