"""Sui mainnet adapter (roadmap-v4: Sui live transfer coverage).

Fixtures mirror the LIVE-VERIFIED (2026-06) ``suix_queryTransactionBlocks`` shape:
a tx with ``digest`` / ``timestampMs`` / ``transaction.data.sender`` and
``balanceChanges[]`` where each entry is
``{owner: {AddressOwner: 0x..}, coinType, amount(signed str)}``. Pinned coin
decimals (SUI=9, USDC=6, USDT=6) and the CoinGecko ids were verified against
``suix_getCoinMetadata`` on the live full node.
"""

from __future__ import annotations

from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.sui.adapter import SUI_COIN_TYPE, SuiAdapter
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain

# 0x + 64 hex (canonical Sui addresses).
_A = "0x" + "a" * 64        # the watched/sending wallet
_B = "0x" + "b" * 64        # a recipient
_C = "0x" + "c" * 64        # a second recipient
_USDC = ("0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7"
         "::usdc::USDC")
_CETUS = ("0x06864a6f921804860930db6ddbe2e16acdf8504495ea7481637a1c8b9a8fe54b"
          "::cetus::CETUS")


def _bal(addr: str, coin: str, amount: str) -> dict[str, Any]:
    return {"owner": {"AddressOwner": addr}, "coinType": coin, "amount": amount}


def _tx(digest: str, sender: str, balance_changes: list[dict[str, Any]],
        ts: int = 1781305965390) -> dict[str, Any]:
    return {
        "digest": digest,
        "timestampMs": ts,
        "transaction": {"data": {"sender": sender, "messageVersion": "v1"}},
        "balanceChanges": balance_changes,
    }


class _StubClient:
    """Mimics SuiRPCClient: serves a fixed page per filter + a metadata map."""

    def __init__(self, by_filter: dict[str, list[dict[str, Any]]],
                 meta: dict[str, dict[str, Any]] | None = None) -> None:
        self.by_filter = by_filter
        self.meta = meta or {}
        self.base_url = "https://fullnode.mainnet.sui.io"
        self.calls: list[dict[str, Any]] = []

    def query_transaction_blocks(self, tx_filter, *, cursor=None, limit=50,
                                 descending=True):
        key = next(iter(tx_filter))  # "FromAddress" / "ToAddress"
        self.calls.append({"filter": tx_filter, "limit": limit,
                           "descending": descending})
        return {"data": self.by_filter.get(key, []), "nextCursor": None,
                "hasNextPage": False}

    def get_coin_metadata(self, coin_type):
        return self.meta.get(coin_type)

    def close(self):  # pragma: no cover - trivial
        pass


def _adapter(stub: _StubClient) -> SuiAdapter:
    return SuiAdapter(client=stub)


# ---- outflows ---- #


def test_simple_usdc_transfer_emits_one_edge() -> None:
    # A sends 100 USDC to B: A -100, B +100.
    tx = _tx("DIG1", _A, [_bal(_A, _USDC, "-100000000"),
                          _bal(_B, _USDC, "100000000")])
    stub = _StubClient({"FromAddress": [tx]})
    rows = _adapter(stub).fetch_erc20_outflows(_A)
    assert len(rows) == 1
    r = rows[0]
    assert r["from"] == _A and r["to"] == _B
    assert r["amount_raw"] == 100000000          # recipient's positive delta
    assert r["token"].symbol == "USDC" and r["token"].decimals == 6
    assert r["token"].coingecko_id == "usd-coin"
    assert r["chain"] == Chain.sui
    assert r["tx_hash"] == "DIG1"


def test_native_sui_transfer_uses_recipient_amount_not_gas() -> None:
    # A sends 5 SUI to B. A's delta is gas-inflated (-5.01 SUI); B's is clean +5.
    tx = _tx("DIG2", _A, [_bal(_A, SUI_COIN_TYPE, "-5010000000"),
                          _bal(_B, SUI_COIN_TYPE, "5000000000")])
    stub = _StubClient({"FromAddress": [tx]})
    rows = _adapter(stub).fetch_native_outflows(_A)
    assert len(rows) == 1
    assert rows[0]["amount_raw"] == 5000000000   # the clean transferred value
    assert rows[0]["token"].symbol == "SUI" and rows[0]["token"].decimals == 9


def test_multi_recipient_emits_an_edge_each() -> None:
    tx = _tx("DIG3", _A, [_bal(_A, _USDC, "-200000000"),
                          _bal(_B, _USDC, "100000000"),
                          _bal(_C, _USDC, "100000000")])
    stub = _StubClient({"FromAddress": [tx]})
    rows = _adapter(stub).fetch_erc20_outflows(_A)
    assert {r["to"] for r in rows} == {_B, _C}
    assert all(r["amount_raw"] == 100000000 for r in rows)


def test_swap_to_self_emits_no_native_outflow() -> None:
    # A swap: A's SUI goes down, A's USDC goes up — both AddressOwner=A. There is
    # NO other-address positive recipient → not a wallet-to-wallet transfer.
    tx = _tx("DIG4", _A, [_bal(_A, SUI_COIN_TYPE, "-5000000000"),
                          _bal(_A, _USDC, "4980000000")])
    stub = _StubClient({"FromAddress": [tx]})
    assert _adapter(stub).fetch_native_outflows(_A) == []


def test_object_owner_recipient_is_not_an_edge() -> None:
    # SUI leaves A into a shared/pool OBJECT (not an AddressOwner) → no edge.
    tx = _tx("DIG5", _A, [
        _bal(_A, SUI_COIN_TYPE, "-5000000000"),
        {"owner": {"ObjectOwner": "0x" + "f" * 64},
         "coinType": SUI_COIN_TYPE, "amount": "5000000000"},
    ])
    stub = _StubClient({"FromAddress": [tx]})
    assert _adapter(stub).fetch_native_outflows(_A) == []


def test_outflow_requires_sender_negative() -> None:
    # If A's net for the coin is positive (a pure inbound surfaced under a
    # FromAddress filter), it is NOT an outflow.
    tx = _tx("DIG6", _A, [_bal(_A, _USDC, "100000000"),
                          _bal(_B, _USDC, "-100000000")])
    stub = _StubClient({"FromAddress": [tx]})
    assert _adapter(stub).fetch_erc20_outflows(_A) == []


# ---- token resolution (decimals) ---- #


def test_unknown_coin_resolved_via_metadata() -> None:
    tx = _tx("DIG7", _A, [_bal(_A, _CETUS, "-44299403"),
                          _bal(_B, _CETUS, "44299403")])
    stub = _StubClient({"FromAddress": [tx]},
                       meta={_CETUS: {"decimals": 9, "symbol": "CETUS"}})
    rows = _adapter(stub).fetch_erc20_outflows(_A)
    assert len(rows) == 1
    assert rows[0]["token"].symbol == "CETUS" and rows[0]["token"].decimals == 9
    assert rows[0]["token"].coingecko_id is None   # not a pinned-priceable coin


def test_unresolvable_coin_is_skipped_not_guessed() -> None:
    # Metadata unavailable → SKIP the edge rather than fabricate decimals.
    tx = _tx("DIG8", _A, [_bal(_A, _CETUS, "-44299403"),
                          _bal(_B, _CETUS, "44299403")])
    stub = _StubClient({"FromAddress": [tx]}, meta={})   # no metadata
    assert _adapter(stub).fetch_erc20_outflows(_A) == []


# ---- inflows ---- #


def test_inbound_attributes_from_tx_sender() -> None:
    # B receives 100 USDC; the tx sender A is the 'from'.
    tx = _tx("DIG9", _A, [_bal(_A, _USDC, "-100000000"),
                          _bal(_B, _USDC, "100000000")])
    stub = _StubClient({"ToAddress": [tx]})
    rows = _adapter(stub).fetch_erc20_inflows(_B)
    assert len(rows) == 1
    assert rows[0]["from"] == _A and rows[0]["to"] == _B
    assert rows[0]["amount_raw"] == 100000000


def test_start_block_ts_filter_excludes_older() -> None:
    old = _tx("OLD", _A, [_bal(_A, _USDC, "-1"), _bal(_B, _USDC, "1")],
              ts=1_000_000_000_000)   # ~2001-09 in ms
    stub = _StubClient({"FromAddress": [old]})
    # start_block as a unix-second cutoff well after the tx's time.
    assert _adapter(stub).fetch_erc20_outflows(_A, start_block=2_000_000_000) == []


# ---- address handling + dispatch ---- #


def test_address_case_insensitive_match() -> None:
    # Move addresses are case-insensitive; an upper-case focus still matches.
    tx = _tx("DIGA", _A, [_bal(_A, _USDC, "-100"), _bal(_B, _USDC, "100")])
    stub = _StubClient({"FromAddress": [tx]})
    rows = _adapter(stub).fetch_erc20_outflows(_A.upper())
    assert len(rows) == 1 and rows[0]["from"] == _A


def test_invalid_address_returns_empty() -> None:
    stub = _StubClient({"FromAddress": []})
    assert _adapter(stub).fetch_erc20_outflows("not-an-address") == []


def test_malformed_tx_survives() -> None:
    stub = _StubClient({"FromAddress": ["junk", {}, {"digest": "X"}, None]})
    assert _adapter(stub).fetch_erc20_outflows(_A) == []


def test_for_chain_returns_sui_adapter() -> None:
    cfg, env = RecuperoConfig(), RecuperoEnv(ETHERSCAN_API_KEY="dummy")
    adapter = ChainAdapter.for_chain(Chain.sui, (cfg, env))
    assert isinstance(adapter, SuiAdapter)
    assert adapter.chain == Chain.sui
    adapter.close()


def test_explorer_urls() -> None:
    a = _adapter(_StubClient({}))
    assert a.explorer_tx_url("DIG").startswith("https://suiscan.xyz/mainnet/tx/")
    assert a.explorer_address_url(_A).endswith(_A)
