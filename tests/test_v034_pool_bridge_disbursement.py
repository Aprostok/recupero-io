"""v0.34 Wave #3 — pool/native-swap bridge disbursement matching.

Pool bridges (Allbridge, Celer) and native-swap bridges (THORChain) deliver to
a DIFFERENT recipient than the sender, so the same-address lock-mint heuristic
can't find them. match_pool_bridge_disbursement follows the DESTINATION bridge
contract's OUTFLOWS and correlates by amount+time in the strict
amount_time_only mode (distinctive amount + unique match + 'low'). These tests
use a fake adapter (no network) and pin the safe behavior.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from recupero.models import Chain
from recupero.trace.cross_chain import (
    BridgeInfo,
    CrossChainHandoff,
    bridge_address_on_chain,
    match_pool_bridge_disbursement,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)
_BRIDGE = "0x" + "b" * 40
_RECIPIENT = "0x" + "c" * 40


class _Tok:
    def __init__(self, symbol: str = "ETH", decimals: int = 18) -> None:
        self.symbol = symbol
        self.decimals = decimals


class _FakeAdapter:
    """Returns canned ERC-20 outflow rows for the bridge address."""

    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows
        self.chain = Chain.arbitrum

    def block_at_or_before(self, _dt: datetime) -> int:
        return 100

    def fetch_native_outflows(self, _addr, _start, max_results=500):  # noqa: ANN001,ANN201
        return []

    def fetch_erc20_outflows(self, _addr, _start, max_results=500):  # noqa: ANN001,ANN201
        return self._rows


def _handoff(amount: str) -> CrossChainHandoff:
    return CrossChainHandoff(
        source_address="0x" + "a" * 40,
        source_chain=Chain.ethereum,
        source_tx_hash="0x" + "1" * 64,
        source_explorer_url="https://etherscan.io/tx/x",
        bridge_name="Allbridge Core Bridge",
        bridge_protocol="Allbridge",
        bridge_address="0x" + "d" * 40,
        amount_decimal=Decimal(amount),
        amount_usd=Decimal("1000"),
        token_symbol="ETH",
        block_time_iso="2026-01-01T00:00:00Z",
        follow_up_url=None,
        destination_chain_candidates=("arbitrum",),
    )


def _row(amount_raw: str, *, tx: str = "0xfeed", mins: int = 10) -> dict:
    return {
        "to": _RECIPIENT,
        "tx_hash": tx,
        "amount_raw": amount_raw,
        "block_time": _T0 + timedelta(minutes=mins),
        "token": _Tok(),
        "chain": "arbitrum",
        "explorer_url": "https://arbiscan.io/tx/x",
    }


# ---- bridge_address_on_chain ---- #


def test_bridge_address_on_chain_finds_protocol() -> None:
    db = {
        (Chain.arbitrum, _BRIDGE): BridgeInfo(
            chain=Chain.arbitrum, address=_BRIDGE, name="Allbridge Core Bridge",
            protocol="Allbridge", confidence="high", follow_up_url=None,
            supports_to_chains=(),
        ),
    }
    assert bridge_address_on_chain(db, "Allbridge", Chain.arbitrum) == _BRIDGE
    assert bridge_address_on_chain(db, "Allbridge", Chain.optimism) is None
    assert bridge_address_on_chain(db, "Mayan", Chain.arbitrum) is None
    assert bridge_address_on_chain(db, "", Chain.arbitrum) is None


# ---- match_pool_bridge_disbursement ---- #


def test_distinctive_unique_disbursement_matches_recipient_low() -> None:
    # 1.234567 ETH out to a DIFFERENT recipient -> matched, low confidence.
    adapter = _FakeAdapter([_row("1234567000000000000", mins=5)])
    r = match_pool_bridge_disbursement(
        _handoff("1.234567"), dst_adapter=adapter, dst_bridge_address=_BRIDGE,
    )
    assert r is not None
    assert r.confidence == "low"
    assert r.candidate.address == _RECIPIENT


def test_round_amount_not_matched() -> None:
    adapter = _FakeAdapter([_row("1000000000000000000")])  # 1.0 ETH (round)
    assert match_pool_bridge_disbursement(
        _handoff("1.0"), dst_adapter=adapter, dst_bridge_address=_BRIDGE,
    ) is None


def test_multiple_qualifying_disbursements_refused() -> None:
    adapter = _FakeAdapter([
        _row("1234567000000000000", tx="0xa", mins=4),
        _row("1234567000000000000", tx="0xb", mins=9),
    ])
    assert match_pool_bridge_disbursement(
        _handoff("1.234567"), dst_adapter=adapter, dst_bridge_address=_BRIDGE,
    ) is None


def test_no_bridge_address_returns_none() -> None:
    adapter = _FakeAdapter([_row("1234567000000000000")])
    assert match_pool_bridge_disbursement(
        _handoff("1.234567"), dst_adapter=adapter, dst_bridge_address="",
    ) is None


def test_never_high_confidence() -> None:
    adapter = _FakeAdapter([_row("13374280000000000000", mins=1)])  # 13.37428
    r = match_pool_bridge_disbursement(
        _handoff("13.37428"), dst_adapter=adapter, dst_bridge_address=_BRIDGE,
    )
    assert r is not None and r.confidence == "low"
