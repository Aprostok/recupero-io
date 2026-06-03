"""TON chain adapter (TON Center backend).

Covers the two laundering-relevant transfer classes on TON:
  * Native TON — v2 ``getTransactions``; an outflow is any ``out_msg`` with a
    positive ``value`` (nanoton, 9 decimals).
  * Jetton (USDT-TON et al.) — v3 ``jetton/transfers`` (already decoded to
    source / destination / amount / jetton_master). USDT-TON is THE dominant
    stablecoin off-ramp on TON, mirroring USDT-TRC20 on Tron.

All addresses are canonicalized to the raw lower-cased form (``normalize_ton_
address``) at this boundary, so the same wallet matches across the v2 (friendly)
and v3 (raw) APIs. block_at_or_before returns a unix-ts cutoff (TON has no
ts→block index at the free tier); fetches filter on ``utime`` / ``transaction_
now``. Data shapes verified live against toncenter.com.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime
from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.ton.address import normalize_ton_address, raw_to_friendly
from recupero.chains.ton.client import TonCenterClient, TonCenterError
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)

TON_SYMBOL = "TON"
TON_DECIMALS = 9
TON_COINGECKO_ID = "the-open-network"

_TONVIEWER_TX = "https://tonviewer.com/transaction/"
_TONVIEWER_ADDR = "https://tonviewer.com/"

# Priceable Jetton metadata keyed by canonical raw jetton_master address.
# (symbol, decimals, coingecko_id). USDT-TON is the dominant stablecoin rail.
_JETTON_META: dict[str, tuple[str, int, str]] = {
    "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe":
        ("USDT", 6, "tether"),
}


def _utime_to_dt(utime: Any) -> datetime:
    try:
        return datetime.fromtimestamp(int(utime), tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.fromtimestamp(0, tz=UTC)


class TonAdapter(ChainAdapter):
    """TON mainnet adapter (native TON + Jetton transfers via TON Center)."""

    def __init__(
        self, api_key: str | None = None, *, client: TonCenterClient | None = None,
    ) -> None:
        self.client = client or TonCenterClient(api_key=api_key)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.client.close()

    # --- block / time --- #

    def block_at_or_before(self, ts: datetime) -> int:
        """TON has no ts→block index at the free tier; we window by ``utime``.
        Return the unix-second cutoff; fetches filter rows with time >= it."""
        return int(ts.timestamp())

    # --- classification --- #

    def is_contract(self, address: Address) -> bool:
        """On TON every account is a smart contract, but ordinary wallets behave
        as user accounts. We conservatively report False (wallet-like) so the
        tracer does not mis-classify standard wallets as protocol contracts —
        Jetton/DEX special-casing is handled by labels, not this flag."""
        return False

    # --- native TON outflows --- #

    def fetch_native_outflows(
        self, from_address: Address, start_block: int,
    ) -> list[dict[str, Any]]:
        """Native-TON outbound transfers from ``from_address`` since the
        ``start_block`` (unix-ts) cutoff. An outflow is an ``out_msg`` with a
        positive value."""
        try:
            canonical_from = normalize_ton_address(from_address)
        except ValueError:
            log.debug("ton: skipping un-normalizable address %r", from_address)
            return []
        # TON Center accepts raw or friendly; query with friendly bounceable.
        query_addr = raw_to_friendly(canonical_from)
        try:
            txs = self.client.get_transactions(query_addr, limit=100)
        except TonCenterError as exc:
            log.warning("ton native fetch failed for %s: %s", canonical_from, exc)
            return []

        out: list[dict[str, Any]] = []
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            utime = tx.get("utime")
            if not isinstance(utime, (int, float)) or int(utime) < start_block:
                continue
            tx_id = tx.get("transaction_id") or {}
            tx_hash = tx_id.get("hash") if isinstance(tx_id, dict) else None
            if not isinstance(tx_hash, str) or not tx_hash:
                continue
            block_time = _utime_to_dt(utime)
            for msg in tx.get("out_msgs") or []:
                norm = self._normalize_native_msg(
                    msg, canonical_from, tx_hash, block_time,
                )
                if norm is not None:
                    out.append(norm)
        return out

    def _normalize_native_msg(
        self, msg: Any, canonical_from: str, tx_hash: str, block_time: datetime,
    ) -> dict[str, Any] | None:
        if not isinstance(msg, dict):
            return None
        dest = msg.get("destination")
        if not isinstance(dest, str) or not dest:
            return None  # message with no destination (e.g. log/event)
        try:
            amount_raw = int(msg.get("value") or 0)
        except (TypeError, ValueError):
            return None
        if amount_raw <= 0:
            return None
        try:
            to_addr = normalize_ton_address(dest)
        except ValueError:
            return None
        if to_addr == canonical_from:
            return None  # self-message
        return {
            "chain": Chain.ton,
            "tx_hash": tx_hash,
            "block_number": 0,  # TON uses logical time; block_time is authoritative
            "block_time": block_time,
            "log_index": None,
            "from": canonical_from,
            "to": to_addr,
            "token": TokenRef(
                chain=Chain.ton, contract=None, symbol=TON_SYMBOL,
                decimals=TON_DECIMALS, coingecko_id=TON_COINGECKO_ID,
            ),
            "amount_raw": amount_raw,
            "explorer_url": self.explorer_tx_url(tx_hash),
        }

    # --- Jetton (token) outflows --- #

    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int,
    ) -> list[dict[str, Any]]:
        """Jetton outbound transfers (USDT-TON etc.) from ``from_address`` since
        the ``start_block`` (unix-ts) cutoff, via the v3 decoded-transfer API."""
        try:
            canonical_from = normalize_ton_address(from_address)
        except ValueError:
            return []
        query_addr = raw_to_friendly(canonical_from)
        try:
            body = self.client.get_jetton_transfers(owner_address=query_addr, limit=100)
        except TonCenterError as exc:
            log.warning("ton jetton fetch failed for %s: %s", canonical_from, exc)
            return []

        transfers = body.get("jetton_transfers") if isinstance(body, dict) else None
        if not isinstance(transfers, list):
            return []
        out: list[dict[str, Any]] = []
        for tr in transfers:
            norm = self._normalize_jetton(tr, canonical_from, start_block)
            if norm is not None:
                out.append(norm)
        return out

    def _normalize_jetton(
        self, tr: Any, canonical_from: str, start_block: int,
    ) -> dict[str, Any] | None:
        if not isinstance(tr, dict):
            return None
        src = tr.get("source")
        dest = tr.get("destination")
        if not isinstance(src, str) or not isinstance(dest, str):
            return None
        try:
            from_addr = normalize_ton_address(src)
            to_addr = normalize_ton_address(dest)
        except ValueError:
            return None
        # Only outbound from the queried owner.
        if from_addr != canonical_from:
            return None
        if from_addr == to_addr:
            return None
        now = tr.get("transaction_now")
        if not isinstance(now, (int, float)) or int(now) < start_block:
            return None
        master_raw = tr.get("jetton_master")
        try:
            master = normalize_ton_address(master_raw) if master_raw else None
        except ValueError:
            master = None
        meta = _JETTON_META.get(master or "")
        if meta is None:
            # Unknown jetton: we can't trust decimals → don't fabricate a USD-
            # bearing transfer. Skip (mirrors the EVM "refuse to guess decimals"
            # posture). Extending _JETTON_META is a one-line addition.
            return None
        symbol, decimals, cg_id = meta
        try:
            amount_raw = int(tr.get("amount") or 0)
        except (TypeError, ValueError):
            return None
        if amount_raw <= 0:
            return None
        tx_hash = tr.get("transaction_hash")
        if not isinstance(tx_hash, str) or not tx_hash:
            return None
        return {
            "chain": Chain.ton,
            "tx_hash": tx_hash,
            "block_number": 0,
            "block_time": _utime_to_dt(now),
            "log_index": None,
            "from": from_addr,
            "to": to_addr,
            "token": TokenRef(
                chain=Chain.ton, contract=master, symbol=symbol,
                decimals=decimals, coingecko_id=cg_id,
            ),
            "amount_raw": amount_raw,
            "explorer_url": self.explorer_tx_url(tx_hash),
        }

    # --- evidence + explorer --- #

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        # TON Center v2 has no by-hash receipt that maps cleanly to the
        # EvidenceReceipt shape without a (lt, hash) pair; we package what we
        # have. Block header is left empty (TON masterchain seqno not resolved
        # here) — the explorer URL is the authoritative custody anchor.
        return EvidenceReceipt(
            chain=Chain.ton,
            tx_hash=tx_hash,
            block_number=0,
            block_time=datetime.fromtimestamp(0, tz=UTC),
            raw_transaction={},
            raw_receipt={},
            raw_block_header={},
            fetched_at=datetime.now(UTC),
            fetched_from="toncenter.com",
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"{_TONVIEWER_TX}{tx_hash}"

    def explorer_address_url(self, address: Address) -> str:
        try:
            friendly = raw_to_friendly(normalize_ton_address(address))
        except ValueError:
            friendly = address
        return f"{_TONVIEWER_ADDR}{friendly}"


__all__ = (
    "TonAdapter",
    "TON_SYMBOL",
    "TON_DECIMALS",
    "TON_COINGECKO_ID",
    "_JETTON_META",
)
