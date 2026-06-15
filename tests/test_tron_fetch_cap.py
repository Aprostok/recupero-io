"""Tron fetch budget: the adapter now threads a config-derived pagination cap
into the TronGrid client instead of leaving both the TRC-20 and native-TRX paths
on the client's hardcoded 50-page (~10k event) default — a silent truncation on
the chain that carries ~half of all USDT laundering. The client already WARNS on
max_pages exhaustion; this wires the cap to RECUPERO_MAX_TRANSFERS_PER_ADDRESS.
"""
from __future__ import annotations

from recupero.chains.tron.adapter import (
    _HARD_PAGE_CEILING,
    TronAdapter,
    _resolve_tron_max_pages,
)

# valid base58check Tron addresses (case-sensitive)
_PERP = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"


class _FakeTron:
    def __init__(self):
        self.seen: dict[str, int] = {}

    def get_native_transactions(self, address, **kwargs):
        self.seen["native"] = kwargs.get("max_pages")
        return []

    def get_trc20_transfers(self, address, **kwargs):
        self.seen["trc20"] = kwargs.get("max_pages")
        return []


def test_resolve_tron_max_pages_math(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    assert _resolve_tron_max_pages() == 250                  # 50_000 / 200
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "1000")
    assert _resolve_tron_max_pages() == 5                    # ceil(1000/200)
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "0")
    assert _resolve_tron_max_pages() == _HARD_PAGE_CEILING   # disabled = unbounded
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "10000000")
    assert _resolve_tron_max_pages() == _HARD_PAGE_CEILING   # clamped
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "garbage")
    assert _resolve_tron_max_pages() == 250                  # garbage → default


def test_adapter_threads_default_budget_to_both_paths(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    fc = _FakeTron()
    ad = TronAdapter(client=fc)
    ad.fetch_native_outflows(_PERP, 0)
    ad.fetch_erc20_outflows(_PERP, 0)
    assert fc.seen["native"] == 250          # was the client default 50
    assert fc.seen["trc20"] == 250


def test_adapter_honors_env_override(monkeypatch):
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "600")
    fc = _FakeTron()
    ad = TronAdapter(client=fc)          # cap resolved in __init__
    ad.fetch_erc20_outflows(_PERP, 0)
    assert fc.seen["trc20"] == 3          # ceil(600/200)
