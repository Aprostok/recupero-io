"""ERC-721 / ERC-1155 transfer endpoint (v0.32.1 trace gap B).

Reactor's panels include NFT mint/transfer rows next to fungible
flows. Without this, NFT-collateralized scams (BAYC, Azuki "rug",
mint-and-flip wash trades) drop off the trace entirely. The pricing
layer in trace.tracer only enumerates ERC-20 / native-coin flows.

Two upstream paths:
  * Alchemy `alchemy_getAssetTransfers` (preferred — already used by
    the EVM adapter, gives us standard, batch, and per-id rows).
  * Etherscan `tokennfttx` action (fallback — slower, no ERC-1155).

The adapter abstraction here is intentionally narrow: anything that
exposes `fetch_nft_transfers_raw(...)` returning the raw provider rows
satisfies the contract. We do the parsing in this module so we don't
spread NFT-shape knowledge across chain adapters.

# TODO(wave-4-integration): wire `fetch_nft_transfers` into
# trace.tracer's BFS frontier after ERC-20 enumeration; merge by
# (from, to, tx_hash) so NFT hops show up in the brief.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class NFTTransfer:
    """One NFT transfer row (post-canonicalization).

    For ERC-1155 batch transfers, one (tokenId, value) pair = one row.
    `value_count` is always >= 1; for ERC-721 it's always 1.
    """

    from_address: str
    to_address: str
    tx_hash: str
    contract_address: str
    token_id: str  # Always str — token IDs can exceed 2^53.
    token_standard: str  # "erc721" | "erc1155"
    value_count: int  # ERC-1155 quantity; 1 for ERC-721.
    block_time: int | None
    value_at_transfer_usd: Decimal | None
    # Collection display name when the provider supplies one (Etherscan's
    # ``tokenName``, e.g. "CryptoKitties"). Display-only — never used for
    # identity or value claims (an attacker controls their token's name).
    collection_name: str | None = None


def _canon_addr(addr: Any) -> str:
    if not isinstance(addr, str):
        return ""
    return addr.strip().lower()


def _to_int(val: Any) -> int | None:
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return None
        try:
            if s.startswith("0x") or s.startswith("0X"):
                return int(s, 16)
            return int(s, 10)
        except ValueError:
            return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _to_decimal(val: Any) -> Decimal | None:
    """Coerce to Decimal, returning None on bad input (including NaN)."""
    if val is None:
        return None
    try:
        d = Decimal(str(val))
        if not d.is_finite():
            return None
        return d
    except (ValueError, ArithmeticError):
        return None


def _normalize_token_id(raw: Any) -> str | None:
    """Token IDs can be very large — keep as decimal string."""
    if raw is None:
        return None
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return None
        # Hex form
        if s.startswith("0x") or s.startswith("0X"):
            try:
                return str(int(s, 16))
            except ValueError:
                return None
        # Decimal form
        if s.isdigit():
            return s
        try:
            return str(int(s, 10))
        except ValueError:
            return None
    if isinstance(raw, int):
        return str(raw)
    return None


def _parse_one_row(row: dict[str, Any]) -> list[NFTTransfer]:
    """Parse one provider row into 0..N NFTTransfer records.

    Provider rows can look like Alchemy's normalized shape:
      {
        "from": "0x..", "to": "0x..", "hash": "0x..",
        "rawContract": {"address": "0x..", "value": "0x.."},
        "tokenId": "0x..", "category": "erc721" | "erc1155",
        "erc1155Metadata": [{"tokenId": "0x..", "value": "0x.."}, ...]
        "metadata": {"blockTimestamp": "..."},
        "valueAtTransferUsd": "12.34"  (provider-augmented)
      }

    Etherscan's tokennfttx rows look like:
      {"from": "...", "to": "...", "hash": "...", "contractAddress": "...",
       "tokenID": "...", "timeStamp": "..."}
    These are always ERC-721 (Etherscan endpoint is per-standard).
    """
    if not isinstance(row, dict):
        return []

    frm = _canon_addr(row.get("from"))
    to = _canon_addr(row.get("to"))
    tx_hash = row.get("hash") or row.get("transactionHash")

    if not isinstance(tx_hash, str) or not frm or not to:
        log.debug("nft_transfers: skipping row missing from/to/hash")
        return []

    # Contract address — Alchemy puts it in rawContract; Etherscan uses
    # contractAddress.
    raw_contract = row.get("rawContract") or {}
    contract_addr = _canon_addr(
        raw_contract.get("address") if isinstance(raw_contract, dict) else None
    )
    if not contract_addr:
        contract_addr = _canon_addr(row.get("contractAddress"))
    if not contract_addr:
        log.debug("nft_transfers: skipping row missing contract address")
        return []

    # Category — Alchemy gives it explicitly; Etherscan endpoint is always
    # erc721 (per the tokennfttx endpoint contract).
    category = row.get("category")
    if isinstance(category, str):
        category = category.strip().lower()
    else:
        category = "erc721"

    if category not in ("erc721", "erc1155"):
        log.debug("nft_transfers: unsupported category=%r, skipping", category)
        return []

    # Timestamp — accept several shapes
    block_time = _to_int(row.get("blockTimestamp"))
    if block_time is None:
        meta = row.get("metadata")
        if isinstance(meta, dict):
            bt_raw = meta.get("blockTimestamp")
            if isinstance(bt_raw, str):
                # ISO-ish strings → try to parse as Unix timestamp first;
                # if not numeric, leave as None (the brief layer can
                # re-resolve via block number).
                block_time = _to_int(bt_raw)
    if block_time is None:
        block_time = _to_int(row.get("timeStamp"))

    usd = _to_decimal(row.get("valueAtTransferUsd"))

    # Collection display name (Etherscan tokenName) — display-only.
    name_raw = row.get("tokenName")
    collection = name_raw.strip() if isinstance(name_raw, str) and name_raw.strip() else None

    out: list[NFTTransfer] = []

    if category == "erc1155":
        # Batch shape: one row may carry many (tokenId, value) pairs.
        batch = row.get("erc1155Metadata")
        if isinstance(batch, list) and batch:
            for pair in batch:
                if not isinstance(pair, dict):
                    continue
                tid = _normalize_token_id(pair.get("tokenId"))
                if tid is None:
                    log.debug("nft_transfers: ERC-1155 row missing tokenId, skipping pair")
                    continue
                qty_raw = pair.get("value")
                qty = _to_int(qty_raw)
                if qty is None:
                    # Try hex string interpretation explicitly.
                    if isinstance(qty_raw, str) and qty_raw.startswith("0x"):
                        try:
                            qty = int(qty_raw, 16)
                        except ValueError:
                            qty = None
                if qty is None or qty < 1:
                    qty = 1
                out.append(
                    NFTTransfer(
                        from_address=frm,
                        to_address=to,
                        tx_hash=tx_hash,
                        contract_address=contract_addr,
                        token_id=tid,
                        token_standard="erc1155",
                        value_count=qty,
                        block_time=block_time,
                        value_at_transfer_usd=usd,
                        collection_name=collection,
                    )
                )
            return out
        # Non-batch ERC-1155 single transfer.
        # Token id: Alchemy uses ``tokenId``; Etherscan token1155tx uses
        # ``tokenID`` (LIVE-VERIFIED 2026-06, same casing as tokennfttx).
        tid = _normalize_token_id(row.get("tokenId") or row.get("tokenID"))
        if tid is None:
            log.debug("nft_transfers: ERC-1155 single missing tokenId, skipping")
            return []
        # Quantity: Etherscan's token1155tx puts it in ``tokenValue``
        # (LIVE-VERIFIED 2026-06); Alchemy-shaped rows use ``value``.
        qty = _to_int(row.get("tokenValue"))
        if qty is None:
            qty = _to_int(row.get("value")) or 1
        if qty < 1:
            qty = 1
        out.append(
            NFTTransfer(
                from_address=frm,
                to_address=to,
                tx_hash=tx_hash,
                contract_address=contract_addr,
                token_id=tid,
                token_standard="erc1155",
                value_count=qty,
                block_time=block_time,
                value_at_transfer_usd=usd,
                collection_name=collection,
            )
        )
        return out

    # ERC-721
    tid = _normalize_token_id(row.get("tokenId") or row.get("tokenID"))
    if tid is None:
        log.debug("nft_transfers: ERC-721 row missing tokenId, skipping")
        return []
    out.append(
        NFTTransfer(
            from_address=frm,
            to_address=to,
            tx_hash=tx_hash,
            contract_address=contract_addr,
            token_id=tid,
            token_standard="erc721",
            value_count=1,
            block_time=block_time,
            value_at_transfer_usd=usd,
            collection_name=collection,
        )
    )
    return out


def fetch_nft_transfers(
    address: str,
    chain: str,
    start_block: int,
    end_block: int,
    evm_adapter: Any,
) -> list[NFTTransfer]:
    """Pull NFT transfers for `address` between `start_block` and `end_block`.

    Best-effort: returns [] on adapter failure rather than raising,
    so the BFS frontier expansion stays robust.

    Adapter contract (duck-typed):
      adapter.fetch_nft_transfers_raw(address, chain, start_block, end_block)
        -> list[dict]   # raw provider rows
    """
    if not isinstance(address, str) or not address.strip():
        return []
    if not isinstance(chain, str) or not chain.strip():
        return []

    fetch = getattr(evm_adapter, "fetch_nft_transfers_raw", None)
    if not callable(fetch):
        log.debug("nft_transfers: adapter has no fetch_nft_transfers_raw")
        return []

    try:
        raw_rows = fetch(address, chain, start_block, end_block)
    except Exception as exc:
        log.warning("nft_transfers: adapter fetch failed: %s", exc)
        return []

    if not isinstance(raw_rows, list):
        log.warning("nft_transfers: adapter returned non-list, got %s", type(raw_rows))
        return []

    out: list[NFTTransfer] = []
    for row in raw_rows:
        try:
            out.extend(_parse_one_row(row))
        except Exception as exc:
            log.warning("nft_transfers: parse error on row, skipping: %s", exc)
            continue
    return out
