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

from recupero.chains.aptos.adapter import AptosAdapter
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
# Aptos: budget-cap saturation warning (the client now paginates past the
# Indexer's 100-row-per-query cap; the only remaining bound is the budget)
# --------------------------------------------------------------------------- #
class _StubAptos:
    def __init__(self, *, n_withdraws):
        self._n = n_withdraws

    def withdraw_activities(self, owner, *, limit=100):
        n = min(self._n, limit)
        return [
            {"transaction_version": 1000 + i, "asset_type": "0x1::aptos_coin::AptosCoin",
             "amount": "100", "transaction_timestamp": "2026-06-13T00:00:00",
             "type": "0x1::fungible_asset::Withdraw", "owner_address": owner}
            for i in range(n)
        ]

    def deposit_activities(self, owner, *, limit=100):
        return []

    def activities_at_versions(self, versions, *, limit=1000):
        return []

    def asset_metadata(self, asset_types):
        return {}

    def close(self):
        pass


def test_aptos_default_budget_from_env(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    assert AptosAdapter(client=_StubAptos(n_withdraws=0))._max_legs == 50_000
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "0")  # disabled→ceiling
    assert AptosAdapter(client=_StubAptos(n_withdraws=0))._max_legs == 250_000
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "750")
    assert AptosAdapter(client=_StubAptos(n_withdraws=0))._max_legs == 750


def test_aptos_warns_when_budget_hit(caplog):
    # fetch returns exactly the budget → real truncation at the budget.
    ad = AptosAdapter(client=_StubAptos(n_withdraws=5), max_legs=5)
    with caplog.at_level(logging.WARNING):
        ad.fetch_native_outflows(_APT_ADDR, 0)
    assert "hit the 5-row budget" in caplog.text
    assert "INCOMPLETE" in caplog.text


def test_aptos_no_warning_below_budget(caplog):
    ad = AptosAdapter(client=_StubAptos(n_withdraws=3), max_legs=50)
    with caplog.at_level(logging.WARNING):
        ad.fetch_native_outflows(_APT_ADDR, 0)
    assert "budget" not in caplog.text


# --------------------------------------------------------------------------- #
# Aptos client: compound-cursor pagination past the 100-row indexer cap
# --------------------------------------------------------------------------- #
def _make_paginating_gql(calls, *, short_at=3):
    """Fake _gql: full pages until ``short_at``, then a short page (exhausted).
    Respects the requested ``page`` size and advances by the cursor it receives."""
    from recupero.chains.aptos import client as cl

    def fake_gql(query, variables):
        calls.append((variables["v"], variables["e"], variables["page"]))
        page = variables["page"]
        base = 1000 if variables["v"] == cl._MAX_BIGINT else variables["v"] - 1
        n = page if len(calls) < short_at else 10
        rows = [{"transaction_version": base - i, "event_index": 0,
                 "owner_address": "0xowner", "amount": "1",
                 "asset_type": "0x1::aptos_coin::AptosCoin", "type": "Withdraw"}
                for i in range(n)]
        return {"fungible_asset_activities": rows}

    return fake_gql


def test_client_paginates_until_short_page(monkeypatch):
    from recupero.chains.aptos import client as cl
    c = cl.AptosIndexerClient()
    calls: list = []
    monkeypatch.setattr(c, "_gql", _make_paginating_gql(calls, short_at=3))
    out = c.withdraw_activities("0xowner", limit=1000)
    assert len(out) == 210                       # 100 + 100 + 10 (short → stop)
    assert len(calls) == 3
    assert calls[0][0] == cl._MAX_BIGINT          # first page: cursor = MAX
    assert calls[1][0] == 901                     # advanced to last version of p1
    assert calls[2][0] == 801


def test_client_pagination_respects_budget(monkeypatch):
    from recupero.chains.aptos import client as cl
    c = cl.AptosIndexerClient()
    calls: list = []
    monkeypatch.setattr(c, "_gql", _make_paginating_gql(calls, short_at=99))
    out = c.withdraw_activities("0xowner", limit=150)
    assert len(out) == 150                        # stops at the budget
    assert len(calls) == 2                        # 100 + 50 (second page sized to budget)
    assert calls[1][2] == 50                       # page size clamped to remaining budget


def test_client_stuck_cursor_guard(monkeypatch):
    from recupero.chains.aptos import client as cl
    c = cl.AptosIndexerClient()

    def stuck_gql(query, variables):
        # always returns a full page ending at the SAME cursor → must not loop.
        return {"fungible_asset_activities": [
            {"transaction_version": 500, "event_index": 0} for _ in range(cl._PAGE_SIZE)
        ]}

    monkeypatch.setattr(c, "_gql", stuck_gql)
    out = c.withdraw_activities("0xowner", limit=10_000)
    assert len(out) == cl._PAGE_SIZE              # one page, then the guard breaks


def test_client_returns_partial_on_midpagination_error(monkeypatch):
    from recupero.chains.aptos import client as cl
    c = cl.AptosIndexerClient()
    n = {"i": 0}

    def flaky_gql(query, variables):
        n["i"] += 1
        if n["i"] == 1:
            return {"fungible_asset_activities": [
                {"transaction_version": 1000 - i, "event_index": 0}
                for i in range(cl._PAGE_SIZE)
            ]}
        raise cl.AptosIndexerError("upstream 408 timeout")   # page 2 fails

    monkeypatch.setattr(c, "_gql", flaky_gql)
    out = c.withdraw_activities("0xowner", limit=1000)
    assert len(out) == cl._PAGE_SIZE              # page 1 kept, not lost


def test_client_propagates_page1_failure(monkeypatch):
    import pytest as _pytest

    from recupero.chains.aptos import client as cl
    c = cl.AptosIndexerClient()

    def dead_gql(query, variables):
        raise cl.AptosIndexerError("upstream down")

    monkeypatch.setattr(c, "_gql", dead_gql)
    with _pytest.raises(cl.AptosIndexerError):     # nothing collected → caller degrades
        c.withdraw_activities("0xowner", limit=1000)
