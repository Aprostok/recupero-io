"""Aptos mainnet adapter (roadmap-v4: Aptos live transfer coverage).

Fixtures mirror the LIVE-VERIFIED (2026-06) Aptos Indexer
``fungible_asset_activities`` shape: owner-resolved rows
``{owner_address, amount, asset_type, type, transaction_version,
transaction_timestamp}`` where a transfer A->B of asset X at version V is a
Withdraw owned by A + a Deposit owned by B. Pinned decimals (APT=8, USDC=6) and
the canonical asset addresses were verified against the live Indexer.
"""

from __future__ import annotations

from typing import Any

from recupero.chains.aptos.adapter import APT_COIN_TYPE, AptosAdapter
from recupero.chains.base import ChainAdapter
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain

_A = "0x" + "a" * 64
_B = "0x" + "b" * 64
_C = "0x" + "c" * 64
_X = "0x" + "d" * 64
_USDC = "0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b"
_WBTC = "0x68844a0d7f2587e726ad0579f3d640865bb4162c08a4589eeda3f9689ec52a3d"

_WD = "0x1::fungible_asset::Withdraw"
_DEP = "0x1::fungible_asset::Deposit"


def _act(owner: str, asset: str, amount: int, typ: str, version: int,
         ts: str = "2026-06-13T00:08:27") -> dict[str, Any]:
    return {"owner_address": owner, "amount": amount, "asset_type": asset,
            "type": typ, "transaction_version": version, "transaction_timestamp": ts}


class _StubClient:
    """Mimics AptosIndexerClient over a flat list of activity rows + metadata."""

    def __init__(self, rows: list[dict[str, Any]],
                 meta: dict[str, dict[str, Any]] | None = None) -> None:
        self.rows = rows
        self.meta = meta or {}
        self.base_url = "https://api.mainnet.aptoslabs.com/v1/graphql"

    def withdraw_activities(self, owner, *, limit=100):
        return [r for r in self.rows
                if r["owner_address"] == owner and "withdraw" in r["type"].lower()][:limit]

    def deposit_activities(self, owner, *, limit=100):
        return [r for r in self.rows
                if r["owner_address"] == owner and "deposit" in r["type"].lower()][:limit]

    def activities_at_versions(self, versions, *, limit=1000):
        vs = set(versions)
        return [r for r in self.rows if r["transaction_version"] in vs][:limit]

    def asset_metadata(self, asset_types):
        return {a: self.meta[a] for a in asset_types if a in self.meta}

    def close(self):  # pragma: no cover - trivial
        pass


def _adapter(stub: _StubClient) -> AptosAdapter:
    return AptosAdapter(client=stub)


# ---- outflows ---- #


def test_simple_usdc_transfer_emits_one_edge() -> None:
    rows = [_act(_A, _USDC, 100000000, _WD, 5707189210),
            _act(_B, _USDC, 100000000, _DEP, 5707189210)]
    out = _adapter(_StubClient(rows)).fetch_erc20_outflows(_A)
    assert len(out) == 1
    r = out[0]
    assert r["from"] == _A and r["to"] == _B
    assert r["amount_raw"] == 100000000
    assert r["token"].symbol == "USDC" and r["token"].decimals == 6
    assert r["token"].coingecko_id == "usd-coin"
    assert r["chain"] == Chain.aptos
    assert r["tx_hash"] == "5707189210" and r["block_number"] == 5707189210


def test_native_apt_transfer() -> None:
    rows = [_act(_A, APT_COIN_TYPE, 500000000, _WD, 42),
            _act(_B, APT_COIN_TYPE, 500000000, _DEP, 42)]
    out = _adapter(_StubClient(rows)).fetch_native_outflows(_A)
    assert len(out) == 1
    assert out[0]["token"].symbol == "APT" and out[0]["token"].decimals == 8
    assert out[0]["amount_raw"] == 500000000


def test_multi_recipient_emits_an_edge_each() -> None:
    rows = [_act(_A, _USDC, 200000000, _WD, 7),
            _act(_B, _USDC, 100000000, _DEP, 7),
            _act(_C, _USDC, 100000000, _DEP, 7)]
    out = _adapter(_StubClient(rows)).fetch_erc20_outflows(_A)
    assert {r["to"] for r in out} == {_B, _C}
    assert all(r["amount_raw"] == 100000000 for r in out)


def test_ambiguous_multi_withdrawer_is_skipped() -> None:
    # A AND X both withdraw USDC at the same version -> who funded B's deposit is
    # ambiguous -> emit NOTHING rather than mis-attribute A->B.
    rows = [_act(_A, _USDC, 100000000, _WD, 9),
            _act(_X, _USDC, 100000000, _WD, 9),
            _act(_B, _USDC, 200000000, _DEP, 9)]
    assert _adapter(_StubClient(rows)).fetch_erc20_outflows(_A) == []


def test_swap_round_trip_to_self_emits_no_edge() -> None:
    # A withdraws WBTC and receives WBTC back to self (swap mechanics) -> the only
    # same-asset deposit is to A itself -> no transfer-out edge.
    rows = [_act(_A, _WBTC, 1225, _WD, 11),
            _act(_A, _WBTC, 1225, _DEP, 11)]
    stub = _StubClient(rows, meta={_WBTC: {"symbol": "WBTC", "decimals": 8}})
    assert _adapter(stub).fetch_erc20_outflows(_A) == []


# ---- token resolution (decimals) ---- #


def test_unknown_asset_resolved_via_metadata() -> None:
    rows = [_act(_A, _WBTC, 1225, _WD, 13), _act(_B, _WBTC, 1225, _DEP, 13)]
    stub = _StubClient(rows, meta={_WBTC: {"symbol": "WBTC", "decimals": 8}})
    out = _adapter(stub).fetch_erc20_outflows(_A)
    assert len(out) == 1
    assert out[0]["token"].symbol == "WBTC" and out[0]["token"].decimals == 8
    assert out[0]["token"].coingecko_id is None   # resolved, not pinned-priceable


def test_unresolvable_asset_is_skipped_not_guessed() -> None:
    rows = [_act(_A, _WBTC, 1225, _WD, 15), _act(_B, _WBTC, 1225, _DEP, 15)]
    stub = _StubClient(rows, meta={})   # no metadata for _WBTC
    assert _adapter(stub).fetch_erc20_outflows(_A) == []


def test_symbol_spoof_not_pinned_by_symbol() -> None:
    # A fake asset that *claims* symbol USDT must NOT inherit USDT pricing — it's
    # resolved by its own metadata with coingecko_id=None (pin is by address only).
    fake = "0x" + "e" * 64
    rows = [_act(_A, fake, 5, _WD, 17), _act(_B, fake, 5, _DEP, 17)]
    stub = _StubClient(rows, meta={fake: {"symbol": "USDT", "decimals": 8}})
    out = _adapter(stub).fetch_erc20_outflows(_A)
    assert len(out) == 1
    assert out[0]["token"].coingecko_id is None
    assert out[0]["token"].contract == fake


# ---- inflows ---- #


def test_inbound_single_source() -> None:
    rows = [_act(_A, _USDC, 100000000, _WD, 19),
            _act(_B, _USDC, 100000000, _DEP, 19)]
    out = _adapter(_StubClient(rows)).fetch_erc20_inflows(_B)
    assert len(out) == 1
    assert out[0]["from"] == _A and out[0]["to"] == _B
    assert out[0]["amount_raw"] == 100000000


def test_inbound_ambiguous_multi_source_skipped() -> None:
    rows = [_act(_A, _USDC, 50000000, _WD, 21),
            _act(_X, _USDC, 50000000, _WD, 21),
            _act(_B, _USDC, 100000000, _DEP, 21)]
    assert _adapter(_StubClient(rows)).fetch_erc20_inflows(_B) == []


def test_start_block_ts_filter_excludes_older() -> None:
    rows = [_act(_A, _USDC, 1, _WD, 23, ts="2001-09-09T01:46:40"),
            _act(_B, _USDC, 1, _DEP, 23, ts="2001-09-09T01:46:40")]
    out = _adapter(_StubClient(rows)).fetch_erc20_outflows(_A, start_block=2_000_000_000)
    assert out == []


# ---- address handling + dispatch ---- #


def test_address_short_form_normalizes_and_matches() -> None:
    short = "0x1"
    full = "0x" + "0" * 63 + "1"
    rows = [_act(full, _USDC, 7, _WD, 25), _act(_B, _USDC, 7, _DEP, 25)]
    out = _adapter(_StubClient(rows)).fetch_erc20_outflows(short)
    assert len(out) == 1 and out[0]["from"] == full


def test_invalid_address_returns_empty() -> None:
    assert _adapter(_StubClient([])).fetch_erc20_outflows("not-an-address") == []


def test_for_chain_returns_aptos_adapter() -> None:
    cfg, env = RecuperoConfig(), RecuperoEnv(ETHERSCAN_API_KEY="dummy")
    adapter = ChainAdapter.for_chain(Chain.aptos, (cfg, env))
    assert isinstance(adapter, AptosAdapter)
    assert adapter.chain == Chain.aptos
    adapter.close()


def test_explorer_urls() -> None:
    a = _adapter(_StubClient([]))
    assert a.explorer_tx_url("42").startswith("https://explorer.aptoslabs.com/txn/")
    assert "network=mainnet" in a.explorer_address_url(_A)
