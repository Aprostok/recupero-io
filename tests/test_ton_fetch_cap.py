"""TON fetch budget: both paths now paginate past the one-shot 100-row cap.

Native (v2 getTransactions) walks the (lt, hash) backward cursor — continuation
pages re-include the cursor tx as row 0 (verified live), which is dropped. Jetton
(v3 jetton/transfers) walks offset. Both honor RECUPERO_MAX_TRANSFERS_PER_ADDRESS
and warn on budget exhaustion.
"""
from __future__ import annotations

import logging

from recupero.chains.ton.adapter import (
    _HARD_PAGE_CEILING,
    TonAdapter,
    _resolve_ton_max_pages,
)

# a valid raw TON address (the USDT-TON jetton master, normalizes fine)
_A = "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe"


def test_resolve_ton_max_pages_math(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    assert _resolve_ton_max_pages() == 500                  # 50_000 / 100
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "250")
    assert _resolve_ton_max_pages() == 3                    # ceil(250/100)
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "0")
    assert _resolve_ton_max_pages() == _HARD_PAGE_CEILING
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "garbage")
    assert _resolve_ton_max_pages() == 500


# --------------------------------------------------------------------------- #
# native: (lt, hash) backward cursor + boundary-dup drop
# --------------------------------------------------------------------------- #
def _native_tx(i: int):
    # full pages have 100 rows; lt descends; hash unique per lt
    return {"transaction_id": {"lt": str(1000 - i), "hash": f"h{1000 - i}"},
            "utime": 1_700_000_000, "out_msgs": []}


class _NativeFake:
    """Serves v2 getTransactions pages keyed by the (lt) cursor, re-including the
    cursor tx as row 0 of continuation pages (the real toncenter behavior)."""

    def __init__(self, total: int):
        self.all = [_native_tx(i) for i in range(total)]   # newest-first
        self.calls: list = []

    def get_transactions(self, address, *, limit=100, to_lt=None, lt=None, tx_hash=None):
        self.calls.append(lt)
        if lt is None:
            start = 0
        else:
            idx = next((i for i, t in enumerate(self.all)
                        if t["transaction_id"]["lt"] == lt), None)
            if idx is None:
                return []
            start = idx                       # re-include the cursor tx (row 0)
        return self.all[start:start + limit]

    def get_jetton_transfers(self, *, owner_address, limit=100, offset=0):
        return {"jetton_transfers": []}

    def close(self):
        pass


def test_native_paginates_with_lt_cursor_and_drops_boundary(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    fake = _NativeFake(250)                    # 100 + 100 + 50 (raw); dups dropped
    ad = TonAdapter(client=fake)
    txs = ad._paginate_native("EQowner", _A, 0)
    # 250 unique txs, NO duplicates despite the re-included boundary rows
    lts = [t["transaction_id"]["lt"] for t in txs]
    assert len(txs) == 250
    assert len(set(lts)) == 250                # boundary dedup worked
    assert len(fake.calls) == 3
    assert fake.calls[0] is None               # page 1: no cursor


def test_native_budget_warning(monkeypatch, caplog):
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "100")  # → 1 page
    fake = _NativeFake(250)
    ad = TonAdapter(client=fake)
    with caplog.at_level(logging.WARNING):
        ad._paginate_native("EQowner", _A, 0)
    assert "INCOMPLETE" in caplog.text


# --------------------------------------------------------------------------- #
# jetton: offset pagination
# --------------------------------------------------------------------------- #
class _JettonFake:
    def __init__(self, total: int):
        self.all = [{"i": i} for i in range(total)]
        self.calls: list = []

    def get_jetton_transfers(self, *, owner_address, limit=100, offset=0):
        self.calls.append(offset)
        return {"jetton_transfers": self.all[offset:offset + limit]}

    def get_transactions(self, address, *, limit=100, to_lt=None, lt=None, tx_hash=None):
        return []

    def close(self):
        pass


def test_jetton_paginates_by_offset(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    fake = _JettonFake(230)                    # 100 + 100 + 30
    ad = TonAdapter(client=fake)
    transfers = ad._paginate_jetton("EQowner", _A)
    assert len(transfers) == 230
    assert fake.calls == [0, 100, 200]


def test_jetton_budget_warning(monkeypatch, caplog):
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "100")  # → 1 page
    fake = _JettonFake(230)
    ad = TonAdapter(client=fake)
    with caplog.at_level(logging.WARNING):
        ad._paginate_jetton("EQowner", _A)
    assert "INCOMPLETE" in caplog.text


# --------------------------------------------------------------------------- #
# explorer URL: base64 tx hash → URL-safe canonical hex (raw '/' broke the link)
# --------------------------------------------------------------------------- #
def test_explorer_tx_url_converts_base64_hash_to_hex():
    import base64 as _b64

    from recupero.chains.ton.adapter import _tx_hash_to_hex

    ad = TonAdapter()
    b64 = "VTqWb5pG+IktEzRFvnkH6SNP+nh5bU5SSvUiLoEE9m8="   # real-shaped, has '+' '/'
    expected_hex = _b64.b64decode(b64).hex()
    url = ad.explorer_tx_url(b64)
    assert url == f"https://tonviewer.com/transaction/{expected_hex}"
    assert "/" not in url.split("/transaction/", 1)[1]     # no path-splitting
    assert "+" not in url and "=" not in url
    # helper is idempotent on already-hex input (fallback path)
    assert _tx_hash_to_hex(expected_hex) == expected_hex
    # non-decodable junk falls back to the raw value (no crash)
    assert _tx_hash_to_hex("not-base64-or-hex!!") == "not-base64-or-hex!!"
