"""Tests for ERC-721 / ERC-1155 transfer parsing (v0.32.1 trace gap B)."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from recupero.trace.nft_transfers import (
    fetch_nft_transfers,
)


class _StubAdapter:
    """Adapter that returns canned raw rows."""

    def __init__(self, rows: list[dict[str, Any]] | Exception) -> None:
        self._rows = rows

    def fetch_nft_transfers_raw(self, *_args: Any, **_kw: Any) -> Any:
        if isinstance(self._rows, Exception):
            raise self._rows
        return self._rows


def test_erc721_single_transfer() -> None:
    """One ERC-721 row → one NFTTransfer with value_count=1."""
    rows = [
        {
            "from": "0xAAAA000000000000000000000000000000000001",
            "to": "0xBBBB000000000000000000000000000000000002",
            "hash": "0xabc123",
            "rawContract": {"address": "0xCCCC000000000000000000000000000000000003"},
            "tokenId": "0x42",
            "category": "erc721",
            "metadata": {"blockTimestamp": "1716000000"},
        }
    ]
    out = fetch_nft_transfers("0xABCD", "ethereum", 1, 100, _StubAdapter(rows))
    assert len(out) == 1
    assert out[0].token_standard == "erc721"
    assert out[0].token_id == "66"  # 0x42 = 66
    assert out[0].value_count == 1
    assert out[0].contract_address == "0xcccc000000000000000000000000000000000003"


def test_erc1155_single_transfer() -> None:
    """ERC-1155 with a single (tokenId, value) → one NFTTransfer."""
    rows = [
        {
            "from": "0xAAAA000000000000000000000000000000000001",
            "to": "0xBBBB000000000000000000000000000000000002",
            "hash": "0xabc456",
            "rawContract": {"address": "0xCCCC000000000000000000000000000000000003"},
            "category": "erc1155",
            "erc1155Metadata": [{"tokenId": "0x1", "value": "0x05"}],
        }
    ]
    out = fetch_nft_transfers("0xABCD", "ethereum", 1, 100, _StubAdapter(rows))
    assert len(out) == 1
    assert out[0].token_standard == "erc1155"
    assert out[0].token_id == "1"
    assert out[0].value_count == 5


def test_erc1155_batch_emits_one_per_pair() -> None:
    """ERC-1155 TransferBatch with 3 IDs → 3 NFTTransfer rows."""
    rows = [
        {
            "from": "0xAAAA000000000000000000000000000000000001",
            "to": "0xBBBB000000000000000000000000000000000002",
            "hash": "0xbatch",
            "rawContract": {"address": "0xCCCC000000000000000000000000000000000003"},
            "category": "erc1155",
            "erc1155Metadata": [
                {"tokenId": "0x10", "value": "0x02"},
                {"tokenId": "0x11", "value": "0x01"},
                {"tokenId": "0x12", "value": "0x07"},
            ],
        }
    ]
    out = fetch_nft_transfers("0xABCD", "ethereum", 1, 100, _StubAdapter(rows))
    assert len(out) == 3
    assert {t.token_id for t in out} == {"16", "17", "18"}
    counts = {t.token_id: t.value_count for t in out}
    assert counts["16"] == 2
    assert counts["17"] == 1
    assert counts["18"] == 7


def test_missing_token_id_skipped() -> None:
    """Row with no tokenId → skipped, no crash."""
    rows = [
        {
            "from": "0xAAAA000000000000000000000000000000000001",
            "to": "0xBBBB000000000000000000000000000000000002",
            "hash": "0xskip",
            "rawContract": {"address": "0xCCCC000000000000000000000000000000000003"},
            "category": "erc721",
            # tokenId omitted
        },
        {
            "from": "0xAAAA000000000000000000000000000000000001",
            "to": "0xBBBB000000000000000000000000000000000002",
            "hash": "0xok",
            "rawContract": {"address": "0xCCCC000000000000000000000000000000000003"},
            "tokenId": "0x7",
            "category": "erc721",
        },
    ]
    out = fetch_nft_transfers("0xABCD", "ethereum", 1, 100, _StubAdapter(rows))
    assert len(out) == 1
    assert out[0].token_id == "7"


def test_usd_none_doesnt_crash() -> None:
    """USD field absent → value_at_transfer_usd is None, no exceptions."""
    rows = [
        {
            "from": "0xaaaa000000000000000000000000000000000001",
            "to": "0xbbbb000000000000000000000000000000000002",
            "hash": "0xprice_missing",
            "rawContract": {"address": "0xcccc000000000000000000000000000000000003"},
            "tokenId": "0x9",
            "category": "erc721",
        }
    ]
    out = fetch_nft_transfers("0xABCD", "ethereum", 1, 100, _StubAdapter(rows))
    assert len(out) == 1
    assert out[0].value_at_transfer_usd is None


def test_usd_present_parsed_as_decimal() -> None:
    """USD field present → exposed as Decimal."""
    rows = [
        {
            "from": "0xaaaa000000000000000000000000000000000001",
            "to": "0xbbbb000000000000000000000000000000000002",
            "hash": "0xpriced",
            "rawContract": {"address": "0xcccc000000000000000000000000000000000003"},
            "tokenId": "0xa",
            "category": "erc721",
            "valueAtTransferUsd": "12.34",
        }
    ]
    out = fetch_nft_transfers("0xABCD", "ethereum", 1, 100, _StubAdapter(rows))
    assert len(out) == 1
    assert out[0].value_at_transfer_usd == Decimal("12.34")


def test_adapter_exception_returns_empty() -> None:
    """Adapter raising → graceful []."""
    out = fetch_nft_transfers(
        "0xABCD",
        "ethereum",
        1,
        100,
        _StubAdapter(RuntimeError("RPC died")),
    )
    assert out == []


def test_unknown_category_skipped() -> None:
    """category='cryptopunk' (unsupported) → skipped."""
    rows = [
        {
            "from": "0xaaaa000000000000000000000000000000000001",
            "to": "0xbbbb000000000000000000000000000000000002",
            "hash": "0xexotic",
            "rawContract": {"address": "0xcccc000000000000000000000000000000000003"},
            "tokenId": "0x1",
            "category": "cryptopunk",
        }
    ]
    out = fetch_nft_transfers("0xABCD", "ethereum", 1, 100, _StubAdapter(rows))
    assert out == []


def test_etherscan_shape_works() -> None:
    """Etherscan tokennfttx-style rows (contractAddress + tokenID + timeStamp)."""
    rows = [
        {
            "from": "0xaaaa000000000000000000000000000000000001",
            "to": "0xbbbb000000000000000000000000000000000002",
            "hash": "0xetherscan",
            "contractAddress": "0xCCCC000000000000000000000000000000000003",
            "tokenID": "99",
            "timeStamp": "1716000123",
        }
    ]
    out = fetch_nft_transfers("0xABCD", "ethereum", 1, 100, _StubAdapter(rows))
    assert len(out) == 1
    assert out[0].token_id == "99"
    assert out[0].token_standard == "erc721"
    assert out[0].block_time == 1716000123


# ---- roadmap-v4 #6: LIVE-VERIFIED Etherscan v2 shapes (2026-06) ----------


def test_etherscan_token1155tx_shape_tokenvalue_and_category_tag() -> None:
    """A REAL token1155tx row (live-verified 2026-06): quantity rides in
    ``tokenValue`` (not ``value``), the token id is ``tokenID`` (Etherscan
    casing), and the row has no category field — the EVM adapter tags it
    erc1155 by endpoint. Without the tag + tokenValue support this row was
    misclassified erc721 with qty=1."""
    rows = [
        {
            # trimmed real row from api.etherscan.io v2 token1155tx
            "blockNumber": "8404139",
            "timeStamp": "1566531158",
            "hash": "0x01e854b967d76d383e3ccaaa5d5e79c5f4a234f3ddcfe4b0070e818b1bb5df60",
            "contractAddress": "0xfaafdc07907ff5120a76b34b731b278c38d6043c",
            "from": "0xaaa40c2180b84db849ade830806b4a3576926094",
            "to": "0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459",
            "tokenID": "50885195465617476130364524454612758401242002731102529075193460287108347330626",
            "tokenValue": "3",
            "tokenName": "Enjin",
            "category": "erc1155",  # the adapter's per-endpoint tag
        }
    ]
    out = fetch_nft_transfers("0xABCD", "ethereum", 1, 100, _StubAdapter(rows))
    assert len(out) == 1
    t = out[0]
    assert t.token_standard == "erc1155"
    assert t.value_count == 3                       # tokenValue, NOT default 1
    assert t.token_id.endswith("347330626")         # huge id kept as str
    assert t.collection_name == "Enjin"
    assert t.block_time == 1566531158


def test_etherscan_tokennfttx_real_row_collection_name() -> None:
    """A REAL tokennfttx row (live-verified 2026-06) parses as erc721 and
    carries the display-only collection name."""
    rows = [
        {
            "blockNumber": "4684994",
            "timeStamp": "1512559743",
            "hash": "0x46bfbac4aab21f6c557952b529bb9de1ef2ae75f7d9453b4f5354a8b614e5e40",
            "from": "0x0d41f957181e584db82d2e316837b2de1738c477",
            "contractAddress": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
            "to": "0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459",
            "tokenID": "109130",
            "tokenName": "CryptoKitties",
        }
    ]
    out = fetch_nft_transfers("0xABCD", "ethereum", 1, 100, _StubAdapter(rows))
    assert len(out) == 1
    t = out[0]
    assert t.token_standard == "erc721"
    assert t.token_id == "109130"
    assert t.value_count == 1
    assert t.collection_name == "CryptoKitties"


def test_adapter_tags_erc1155_rows(monkeypatch) -> None:
    """EvmAdapter.fetch_nft_transfers_raw tags token1155tx rows with
    category=erc1155 and leaves tokennfttx rows untagged (erc721 default)."""
    from recupero.chains.evm.adapter import EvmAdapter

    class _Client:
        def get_nft_transfers(self, addr, *, start_block, end_block, max_results):
            return [{"hash": "0x721", "from": "0xa", "to": "0xb"}]

        def get_erc1155_transfers(self, addr, *, start_block, end_block, max_results):
            return [{"hash": "0x1155", "from": "0xa", "to": "0xb"}]

    adapter = EvmAdapter.__new__(EvmAdapter)  # no network ctor
    adapter.client = _Client()
    rows = adapter.fetch_nft_transfers_raw(
        "0x" + "ab" * 20, "ethereum", 0, 99_999_999,
    )
    by_hash = {r["hash"]: r for r in rows}
    assert "category" not in by_hash["0x721"]
    assert by_hash["0x1155"]["category"] == "erc1155"


def test_adapter_without_nft_endpoints_yields_empty() -> None:
    """A backing client lacking the NFT endpoints (e.g. a bare Alchemy-only
    client) degrades to [] instead of raising."""
    from recupero.chains.evm.adapter import EvmAdapter

    adapter = EvmAdapter.__new__(EvmAdapter)
    adapter.client = object()
    assert adapter.fetch_nft_transfers_raw(
        "0x" + "ab" * 20, "ethereum", 0,
    ) == []
