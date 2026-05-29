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
