"""Solana fetch budget: the adapter now derives the Helius pagination cap from
config.trace.max_transfers_per_address (it already receives the config bundle)
and threads it into get_parsed_transactions — instead of leaving it on the
client's hardcoded max_pages=50 (~5_000 txs), a silent truncation below the
project standard. The helius client also now WARNS on max_pages exhaustion.
"""
from __future__ import annotations

from recupero.chains.solana.adapter import (
    _HARD_PAGE_CEILING,
    SolanaAdapter,
    _resolve_sol_max_pages,
)
from recupero.config import RecuperoConfig, RecuperoEnv


def test_resolve_sol_max_pages_math():
    assert _resolve_sol_max_pages(None) == 500             # 50_000 / 100
    assert _resolve_sol_max_pages(50_000) == 500
    assert _resolve_sol_max_pages(250) == 3                # ceil(250/100)
    assert _resolve_sol_max_pages(0) == _HARD_PAGE_CEILING  # disabled = unbounded
    assert _resolve_sol_max_pages(-1) == _HARD_PAGE_CEILING
    assert _resolve_sol_max_pages(10**9) == _HARD_PAGE_CEILING  # clamped
    assert _resolve_sol_max_pages(1) == 1


def _adapter() -> SolanaAdapter:
    # Real __init__ path (resolves _max_pages from cfg.trace); a dummy key
    # satisfies the HELIUS_API_KEY requirement and no network is touched.
    return SolanaAdapter(bundle=(RecuperoConfig(), RecuperoEnv(HELIUS_API_KEY="k")))


def test_adapter_derives_default_cap_from_config():
    assert _adapter()._max_pages == 500       # default budget 50_000 / 100


def test_adapter_threads_cap_into_client(monkeypatch):
    ad = _adapter()
    seen: dict[str, int] = {}

    def fake_gpt(address, *, limit=100, stop_if_older_than=None, max_pages=50):
        seen["max_pages"] = max_pages
        seen["limit"] = limit
        return []

    monkeypatch.setattr(ad.client, "get_parsed_transactions", fake_gpt)
    ad._fetch_all("So1anaAddr1111111111111111111111111111111", 0)
    assert seen["max_pages"] == ad._max_pages == 500   # was the client default 50
    assert seen["limit"] == 100
