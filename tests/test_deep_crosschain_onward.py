"""v0.37.1 — deep cross-chain continuation (#1): the destination chain now
follows GENERIC value-bearing onward hops, not just DEX-swap outputs, so a
plain ``bridge-receiver -> wallet -> ... -> exchange`` trail on the destination
chain is traced to depth instead of dead-ending after one hop.

This pins the explosion-safety gating of `_collect_onward_value_seeds`, which
mirrors the primary BFS enqueue gate (`_consider_enqueue`): a seed is followed
ONLY if it passes `should_traverse` (depth/burn/label-stop), is inside the
cross-chain time window, is not already visited, and (when `stop_at_contract`)
is not a contract. The caller additionally excludes service-wallet sources so a
commingling node on the destination chain can't fan the trace out.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from recupero.models import (
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.trace.policies import TracePolicy
from recupero.trace.tracer import _address_visited_key, _collect_onward_value_seeds

_BRIDGE_TIME = datetime(2025, 1, 15, 12, 0, tzinfo=UTC)


class _FakeAdapter:
    """Minimal adapter — the collector only calls is_contract()."""

    def __init__(self, contracts: set[str] | None = None) -> None:
        self._contracts = {c.lower() for c in (contracts or set())}

    def is_contract(self, address: str) -> bool:
        return address.lower() in self._contracts


def _t(
    to_addr: str,
    *,
    block_time: datetime = _BRIDGE_TIME + timedelta(hours=1),
    label_cat: LabelCategory | None = None,
    hop_depth: int = 1,
) -> Transfer:
    label = None
    if label_cat is not None:
        label = Label(
            address=to_addr, name="x", category=label_cat,
            source="test", confidence="high", added_at=_BRIDGE_TIME,
        )
    return Transfer(
        transfer_id=f"ethereum:{to_addr}:0",
        chain=Chain.ethereum,
        tx_hash="0x" + "a" * 64,
        block_number=1,
        block_time=block_time,
        from_address="0x" + "1" * 40,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=label),
        token=TokenRef(
            chain=Chain.ethereum, contract=None, symbol="ETH",
            decimals=18, coingecko_id="ethereum",
        ),
        amount_raw="1000000000000000000",
        amount_decimal=Decimal("1"),
        usd_value_at_tx=Decimal("3000"),
        hop_depth=hop_depth,
        fetched_at=_BRIDGE_TIME,
        explorer_url="https://etherscan.io/tx/0xabc",
    )


_EOA1 = "0x" + "a1" * 20
_EOA2 = "0x" + "b2" * 20
_CONTRACT = "0x" + "c3" * 20
_EXCHANGE = "0x" + "d4" * 20
_VISITED = "0x" + "e5" * 20


def _policy() -> TracePolicy:
    # max_depth high enough that the depth gate doesn't fire (wave count
    # bounds the dest trace, not should_traverse's depth check).
    return TracePolicy(max_depth=8)


def test_plain_eoa_onward_hop_is_followed() -> None:
    visited: set[str] = set()
    seeds = _collect_onward_value_seeds(
        [_t(_EOA1), _t(_EOA2)],
        chain=Chain.ethereum, adapter=_FakeAdapter(), policy=_policy(),
        visited=visited, src_time=_BRIDGE_TIME, window_end=None,
    )
    assert set(s.lower() for s in seeds) == {_EOA1.lower(), _EOA2.lower()}
    # Marked visited so a later wave / the caller won't re-enqueue them.
    assert _address_visited_key(Chain.ethereum, _EOA1) in visited
    assert _address_visited_key(Chain.ethereum, _EOA2) in visited


def test_already_visited_is_skipped() -> None:
    visited = {_address_visited_key(Chain.ethereum, _VISITED)}
    seeds = _collect_onward_value_seeds(
        [_t(_VISITED)],
        chain=Chain.ethereum, adapter=_FakeAdapter(), policy=_policy(),
        visited=visited, src_time=_BRIDGE_TIME, window_end=None,
    )
    assert seeds == []


def test_contract_dest_is_not_traversed() -> None:
    seeds = _collect_onward_value_seeds(
        [_t(_CONTRACT)],
        chain=Chain.ethereum, adapter=_FakeAdapter({_CONTRACT}),
        policy=_policy(), visited=set(),
        src_time=_BRIDGE_TIME, window_end=None,
    )
    assert seeds == []


def test_exchange_labeled_dest_is_a_stop() -> None:
    # stop_at_exchange (default True) → should_traverse returns False.
    seeds = _collect_onward_value_seeds(
        [_t(_EXCHANGE, label_cat=LabelCategory.exchange_deposit)],
        chain=Chain.ethereum, adapter=_FakeAdapter(), policy=_policy(),
        visited=set(), src_time=_BRIDGE_TIME, window_end=None,
    )
    assert seeds == []


def test_pre_bridge_hop_is_dropped() -> None:
    # A transfer BEFORE the bridge handoff is not onward movement of these funds.
    seeds = _collect_onward_value_seeds(
        [_t(_EOA1, block_time=_BRIDGE_TIME - timedelta(hours=2))],
        chain=Chain.ethereum, adapter=_FakeAdapter(), policy=_policy(),
        visited=set(), src_time=_BRIDGE_TIME, window_end=None,
    )
    assert seeds == []


def test_after_window_end_is_dropped() -> None:
    window_end = _BRIDGE_TIME + timedelta(hours=2)
    seeds = _collect_onward_value_seeds(
        [_t(_EOA1, block_time=_BRIDGE_TIME + timedelta(hours=5))],
        chain=Chain.ethereum, adapter=_FakeAdapter(), policy=_policy(),
        visited=set(), src_time=_BRIDGE_TIME, window_end=window_end,
    )
    assert seeds == []
