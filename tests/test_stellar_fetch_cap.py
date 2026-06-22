"""Stellar fetch budget: the adapter now cursor-paginates Horizon payments (was a
single un-paginated get_payments(limit=100) — a hard 100-payment cap on a
stablecoin off-ramp). Pages walk the paging_token cursor up to a budget from
RECUPERO_MAX_TRANSFERS_PER_ADDRESS, stop early past the start cutoff, and WARN
when the page cap is exhausted with more history available.
"""
from __future__ import annotations

import logging

from recupero.chains.stellar.adapter import (
    _HARD_PAGE_CEILING,
    StellarAdapter,
    _resolve_stellar_max_pages,
)

A = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
B = "GBF2VV4VTXG6VNFY54D7MUXZPTSMBDF3XHM73BXXF3VNZJQGATFYIHYD"
_RECENT = "2026-06-18T00:00:00Z"
_OLD = "2001-01-01T00:00:00Z"


def _rec(i: int, created: str = _RECENT) -> dict:
    return {
        "type": "payment", "transaction_successful": True, "from": A, "to": B,
        "amount": "1.0000000", "asset_type": "native", "created_at": created,
        "transaction_hash": f"tx{i}", "paging_token": str(i),
    }


class _PagingFake:
    """Serves records[start:start+limit] keyed off the paging_token cursor."""

    def __init__(self, total: int, created: str = _RECENT):
        self.records = [_rec(i, created) for i in range(total)]
        self.calls: list = []

    def get_payments(self, account, *, limit=100, cursor=None):
        self.calls.append((cursor, limit))
        if cursor is None:
            start = 0
        else:
            start = next((i + 1 for i, r in enumerate(self.records)
                          if r["paging_token"] == cursor), len(self.records))
        return self.records[start:start + limit]

    def close(self):
        pass


def test_resolve_stellar_max_pages_math(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    assert _resolve_stellar_max_pages() == 250                 # 50_000 / 200
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "400")
    assert _resolve_stellar_max_pages() == 2
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "0")
    assert _resolve_stellar_max_pages() == _HARD_PAGE_CEILING
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "garbage")
    assert _resolve_stellar_max_pages() == 250


def test_paginates_all_payments(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    fake = _PagingFake(450)                       # 200 + 200 + 50
    rows = StellarAdapter(client=fake).fetch_native_outflows(A, 0)
    assert len(rows) == 450                       # was hard-capped at 100
    assert len(fake.calls) == 3
    assert fake.calls[0][0] is None               # first page: no cursor
    assert fake.calls[1][0] == "199"              # cursor advanced
    assert fake.calls[2][0] == "399"


def test_warns_when_budget_exhausted(monkeypatch, caplog):
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "400")  # → 2 pages
    fake = _PagingFake(450)
    with caplog.at_level(logging.WARNING):
        rows = StellarAdapter(client=fake).fetch_native_outflows(A, 0)
    assert len(fake.calls) == 2 and len(rows) == 400
    assert "INCOMPLETE" in caplog.text


def test_start_block_early_stop(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    fake = _PagingFake(450, created=_OLD)         # all older than the cutoff
    rows = StellarAdapter(client=fake).fetch_native_outflows(A, start_block=2_000_000_000)
    assert rows == []                             # all filtered (too old)
    assert len(fake.calls) == 1                   # stopped after the first page
