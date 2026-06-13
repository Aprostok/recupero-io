"""Trace-completeness caps for the Sui + Aptos adapters.

Both previously truncated SILENTLY: Sui at a hardcoded max_pages=3 (150 txs),
Aptos at the Indexer's 100-row-per-query cap (no pagination). These tests lock in
the hardening:
  * Sui now derives its page cap from the project transfer budget
    (RECUPERO_MAX_TRANSFERS_PER_ADDRESS, default 50_000) like every other chain,
    and WARNS when it exhausts the cap with more pages available.
  * Aptos WARNS when a fetch saturates the Indexer's 100-row cap (so an
    incomplete trace is flagged, never silent).
"""
from __future__ import annotations

import logging

from recupero.chains.aptos.adapter import _INDEXER_PAGE_CAP, AptosAdapter
from recupero.chains.sui.adapter import (
    _HARD_PAGE_CEILING,
    SuiAdapter,
    _resolve_max_pages,
)

_SUI_ADDR = "0x" + "1" * 64
_APT_ADDR = "0x" + "a" * 64


# --------------------------------------------------------------------------- #
# Sui: budget-derived page cap
# --------------------------------------------------------------------------- #
def test_resolve_max_pages_budget_math():
    assert _resolve_max_pages(None, 50) == 1000        # default 50_000 / 50
    assert _resolve_max_pages(500, 50) == 10
    assert _resolve_max_pages(0, 50) == _HARD_PAGE_CEILING        # disabled = unbounded
    assert _resolve_max_pages(-1, 50) == _HARD_PAGE_CEILING
    assert _resolve_max_pages(10**9, 50) == _HARD_PAGE_CEILING    # clamped
    assert _resolve_max_pages(1, 50) == 1


def test_sui_default_cap_from_env(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    assert SuiAdapter(client=_StubSui())._max_pages == 1000   # platform default
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "250")
    assert SuiAdapter(client=_StubSui())._max_pages == 5      # ceil(250/50)
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "garbage")
    assert SuiAdapter(client=_StubSui())._max_pages == 1000   # garbage → default
    # explicit kwarg still overrides
    assert SuiAdapter(client=_StubSui(), max_pages=3)._max_pages == 3


class _StubSui:
    """Always reports another page available → drives the truncation path."""

    def __init__(self, *, infinite=True):
        self.infinite = infinite
        self.calls = 0

    def query_transaction_blocks(self, tx_filter, *, cursor=None, limit=50,
                                 descending=True):
        self.calls += 1
        return {"data": [], "nextCursor": "c", "hasNextPage": self.infinite}

    def get_coin_metadata(self, coin_type):
        return None

    def close(self):
        pass


def test_sui_warns_on_truncation(caplog):
    stub = _StubSui(infinite=True)
    ad = SuiAdapter(client=stub, max_pages=2)
    with caplog.at_level(logging.WARNING):
        ad.fetch_native_outflows(_SUI_ADDR, 0)
    assert stub.calls == 2                       # stopped exactly at the cap
    assert "INCOMPLETE" in caplog.text
    assert "RECUPERO_MAX_TRANSFERS_PER_ADDRESS" in caplog.text


def test_sui_no_warning_when_exhausted(caplog):
    stub = _StubSui(infinite=False)              # hasNextPage=False → natural end
    ad = SuiAdapter(client=stub, max_pages=2)
    with caplog.at_level(logging.WARNING):
        ad.fetch_native_outflows(_SUI_ADDR, 0)
    assert stub.calls == 1
    assert "INCOMPLETE" not in caplog.text


# --------------------------------------------------------------------------- #
# Aptos: Indexer 100-row saturation warning
# --------------------------------------------------------------------------- #
class _StubAptos:
    def __init__(self, *, n_withdraws):
        self._n = n_withdraws

    def withdraw_activities(self, owner, *, limit=100):
        return [
            {"transaction_version": 1000 + i, "asset_type": "0x1::aptos_coin::AptosCoin",
             "amount": "100", "transaction_timestamp": "2026-06-13T00:00:00",
             "type": "0x1::fungible_asset::Withdraw", "owner_address": owner}
            for i in range(self._n)
        ]

    def deposit_activities(self, owner, *, limit=100):
        return []

    def activities_at_versions(self, versions, *, limit=1000):
        return []

    def asset_metadata(self, asset_types):
        return {}

    def close(self):
        pass


def test_aptos_warns_when_activity_fetch_saturates(caplog):
    ad = AptosAdapter(client=_StubAptos(n_withdraws=_INDEXER_PAGE_CAP))
    with caplog.at_level(logging.WARNING):
        ad.fetch_native_outflows(_APT_ADDR, 0)
    assert "saturated the Indexer" in caplog.text
    assert "INCOMPLETE" in caplog.text


def test_aptos_no_warning_below_cap(caplog):
    ad = AptosAdapter(client=_StubAptos(n_withdraws=5))
    with caplog.at_level(logging.WARNING):
        ad.fetch_native_outflows(_APT_ADDR, 0)
    assert "saturated the Indexer" not in caplog.text
