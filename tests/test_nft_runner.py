"""Roadmap-v4 Tier-2 #6 (phase A): observed-NFT-flow runner.

Activates the dormant ``nft_transfers`` parser as a gated, post-trace case
artifact. Phase A is OBSERVATIONS only: real on-chain transfers involving
traced wallets, no value claims, no followed recipients.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from recupero.trace.nft_runner import (
    collect_nft_flows,
    flows_to_json,
    nft_flows_enabled,
    traced_wallets,
)

_W1 = "0x" + "aa" * 20
_W2 = "0x" + "bb" * 20
_OTHER = "0x" + "cc" * 20


def _transfer(frm):
    return SimpleNamespace(from_address=frm, to_address=_OTHER)


def _row(*, frm, to, h="0xh1", token_id="7", name="TestKitties"):
    # Etherscan tokennfttx shape (live-verified 2026-06).
    return {"from": frm, "to": to, "hash": h, "contractAddress": "0x" + "dd" * 20,
            "tokenID": token_id, "timeStamp": "1716000000", "tokenName": name}


class _StubAdapter:
    def __init__(self, rows_by_wallet: dict[str, Any]):
        self.rows_by_wallet = rows_by_wallet
        self.calls: list[str] = []

    def fetch_nft_transfers_raw(self, address, _chain, _sb, _eb):
        self.calls.append(address.lower())
        rows = self.rows_by_wallet.get(address.lower(), [])
        if isinstance(rows, Exception):
            raise rows
        return rows


def test_gate_default_off(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_NFT_FLOWS", raising=False)
    assert nft_flows_enabled() is False
    # ZERO adapter calls when gated off (no force).
    adapter = _StubAdapter({_W1: [_row(frm=_W1, to=_OTHER)]})
    out = collect_nft_flows(
        transfers=[_transfer(_W1)], adapter=adapter, chain="ethereum",
    )
    assert out == []
    assert adapter.calls == []
    monkeypatch.setenv("RECUPERO_NFT_FLOWS", "1")
    assert nft_flows_enabled() is True


def test_traced_wallets_dedup_and_cap() -> None:
    transfers = [_transfer(_W1), _transfer(_W1.upper()), _transfer(_W2)]
    assert traced_wallets(transfers) == [_W1, _W2]  # case-insensitive dedup
    assert traced_wallets(transfers, max_wallets=1) == [_W1]


def test_collect_annotates_direction_and_counterparty() -> None:
    adapter = _StubAdapter({
        _W1: [
            _row(frm=_W1, to=_OTHER, h="0xout"),   # wallet sends NFT away
            _row(frm=_OTHER, to=_W1, h="0xin"),    # wallet receives an NFT
        ],
    })
    flows = collect_nft_flows(
        transfers=[_transfer(_W1)], adapter=adapter, chain="ethereum",
        force=True,
    )
    by_tx = {f["tx_hash"]: f for f in flows}
    assert by_tx["0xout"]["direction"] == "out"
    assert by_tx["0xout"]["counterparty"] == _OTHER
    assert by_tx["0xin"]["direction"] == "in"
    assert by_tx["0xin"]["counterparty"] == _OTHER
    # observations only: no fabricated USD value
    assert by_tx["0xout"]["value_at_transfer_usd"] is None
    assert by_tx["0xout"]["collection_name"] == "TestKitties"


def test_collect_dedups_transfer_between_two_traced_wallets() -> None:
    # The SAME transfer appears in both wallets' histories — emitted once.
    shared = _row(frm=_W1, to=_W2, h="0xshared")
    adapter = _StubAdapter({_W1: [shared], _W2: [shared]})
    flows = collect_nft_flows(
        transfers=[_transfer(_W1), _transfer(_W2)], adapter=adapter,
        chain="ethereum", force=True,
    )
    assert len(flows) == 1
    assert flows[0]["tx_hash"] == "0xshared"


def test_collect_per_wallet_failure_skips_not_aborts() -> None:
    adapter = _StubAdapter({
        _W1: RuntimeError("explorer down"),
        _W2: [_row(frm=_W2, to=_OTHER, h="0xok")],
    })
    flows = collect_nft_flows(
        transfers=[_transfer(_W1), _transfer(_W2)], adapter=adapter,
        chain="ethereum", force=True,
    )
    assert [f["tx_hash"] for f in flows] == ["0xok"]


def test_flows_to_json_artifact_shape() -> None:
    doc = flows_to_json([{"tx_hash": "0x1"}])
    assert doc["kind"] == "recupero_nft_flows"
    assert doc["flow_count"] == 1
    assert "OBSERVATIONS only" in doc["disclaimer"]
    assert "not followed" in doc["disclaimer"]
