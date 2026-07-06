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
import os
from datetime import UTC, datetime
from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.ton.address import normalize_ton_address, raw_to_friendly
from recupero.chains.ton.client import TonCenterClient, TonCenterError
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)

# Per-address fetch budget. Pre-this BOTH fetch paths made a SINGLE limit=100 call
# and never paginated — a hard 100-row cap that silently truncated any active TON
# wallet (USDT-TON is THE dominant stablecoin off-ramp on TON). Now both paginate
# up to a budget from RECUPERO_MAX_TRANSFERS_PER_ADDRESS (TON Center pages ~100).
_TON_PAGE_SIZE = 100
_DEFAULT_MAX_TRANSFERS_PER_ADDRESS = 50_000
_HARD_PAGE_CEILING = 5_000  # runaway backstop (5_000 x 100 = 500k rows).


def _resolve_ton_max_pages() -> int:
    """RECUPERO_MAX_TRANSFERS_PER_ADDRESS → a TON Center page cap. ``<= 0``
    (disabled/unbounded) → the hard ceiling; else ceil(budget / 100) clamped."""
    raw = os.environ.get("RECUPERO_MAX_TRANSFERS_PER_ADDRESS")
    budget = _DEFAULT_MAX_TRANSFERS_PER_ADDRESS
    if raw is not None:
        try:
            budget = int(raw)
        except (TypeError, ValueError):
            budget = _DEFAULT_MAX_TRANSFERS_PER_ADDRESS
    if budget <= 0:
        return _HARD_PAGE_CEILING
    pages = -(-budget // _TON_PAGE_SIZE)  # ceil, no float
    return max(1, min(_HARD_PAGE_CEILING, pages))

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
        # Budget-derived pagination cap (was a single un-paginated 100-row call).
        self._max_pages = _resolve_ton_max_pages()

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
        txs = self._paginate_native(query_addr, canonical_from, start_block)

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

    def _paginate_native(
        self, query_addr: str, canonical_from: str, start_block: int,
    ) -> list[dict[str, Any]]:
        """Walk v2 getTransactions backward via the (lt, hash) cursor up to the
        budget. Continuation pages re-include the cursor tx as row 0 (verified
        live) → dropped. Stops on a short page, past the start cutoff, the budget,
        or a stuck cursor; keeps partial results on a mid-pagination error."""
        out: list[dict[str, Any]] = []
        lt: str | None = None
        cur_hash: str | None = None
        for _page in range(self._max_pages):
            try:
                batch = self.client.get_transactions(
                    query_addr, limit=_TON_PAGE_SIZE, lt=lt, tx_hash=cur_hash,
                )
            except TonCenterError as exc:
                if out:
                    log.warning("ton: native pagination stopped early for %s after "
                                "%d tx(s): %s", canonical_from, len(out), exc)
                    break
                log.warning("ton native fetch failed for %s: %s", canonical_from, exc)
                return []
            if not isinstance(batch, list) or not batch:
                break
            raw_len = len(batch)
            # Continuation pages re-include the cursor tx as the first row → drop.
            if lt is not None and (batch[0].get("transaction_id") or {}).get("lt") == lt:
                batch = batch[1:]
            if not batch:
                break  # only the boundary remained → exhausted
            out.extend(batch)
            # Early-stop: newest-first, so once a page's oldest tx predates the
            # cutoff, every later page is older too.
            if start_block > 0:
                oldest = batch[-1].get("utime")
                if isinstance(oldest, (int, float)) and int(oldest) < start_block:
                    break
            last_id = batch[-1].get("transaction_id") or {}
            new_lt = last_id.get("lt")
            new_hash = last_id.get("hash")
            if not new_lt or not new_hash or new_lt == lt:
                break  # can't advance / stuck cursor
            lt, cur_hash = str(new_lt), str(new_hash)
            if raw_len < _TON_PAGE_SIZE:
                break  # last page (fewer than a full page fetched)
        else:
            log.warning(
                "ton: native trace hit the %d-page cap for %s with more history "
                "available — trace may be INCOMPLETE; raise "
                "RECUPERO_MAX_TRANSFERS_PER_ADDRESS.",
                self._max_pages, canonical_from,
            )
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
        transfers = self._paginate_jetton(query_addr, canonical_from)

        out: list[dict[str, Any]] = []
        for tr in transfers:
            norm = self._normalize_jetton(tr, canonical_from, start_block)
            if norm is not None:
                out.append(norm)
        return out

    def _paginate_jetton(
        self, query_addr: str, canonical_from: str,
    ) -> list[dict[str, Any]]:
        """Walk v3 jetton/transfers via offset up to the budget. Stops on a short
        page, the budget, or an error (partial results kept)."""
        out: list[dict[str, Any]] = []
        offset = 0
        for _page in range(self._max_pages):
            try:
                body = self.client.get_jetton_transfers(
                    owner_address=query_addr, limit=_TON_PAGE_SIZE, offset=offset,
                )
            except TonCenterError as exc:
                if out:
                    log.warning("ton: jetton pagination stopped early for %s after "
                                "%d transfer(s): %s", canonical_from, len(out), exc)
                    break
                log.warning("ton jetton fetch failed for %s: %s", canonical_from, exc)
                return []
            batch = body.get("jetton_transfers") if isinstance(body, dict) else None
            if not isinstance(batch, list) or not batch:
                break
            out.extend(batch)
            if len(batch) < _TON_PAGE_SIZE:  # short page → exhausted
                break
            offset += _TON_PAGE_SIZE
        else:
            log.warning(
                "ton: jetton trace hit the %d-page cap for %s with more transfers "
                "available — trace may be INCOMPLETE; raise "
                "RECUPERO_MAX_TRANSFERS_PER_ADDRESS.",
                self._max_pages, canonical_from,
            )
        return out

    def _resolve_jetton_meta(
        self, master: str | None,
    ) -> tuple[str, int | None, str | None]:
        """Resolve (symbol, decimals, coingecko_id) for a Jetton master.

        Pinned canonical stables (``_JETTON_META``: USDT-TON → tether/6) are
        returned verbatim for certainty. For any OTHER jetton we fetch
        AUTHORITATIVE decimals from TON Center (``client.jetton_decimals``,
        cached) and leave ``coingecko_id=None`` so the pricing layer resolves
        USD by the master CONTRACT on platform ``the-open-network`` — no guessed
        decimals, no fabricated price. Returns decimals=None when unresolvable
        (caller must skip the transfer)."""
        if not master:
            return "JETTON", None, None
        pinned = _JETTON_META.get(master)
        if pinned is not None:
            return pinned
        decimals: int | None = None
        try:
            decimals = self.client.jetton_decimals(master)
        except Exception as exc:  # noqa: BLE001
            log.debug("ton: jetton_decimals(%s) failed: %s", master, exc)
        return "JETTON", decimals, None

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
        symbol, decimals, cg_id = self._resolve_jetton_meta(master)
        if decimals is None:
            # Decimals unresolvable (unknown master, API miss) → refuse to guess
            # (mirrors the EVM "refuse to guess decimals" posture). Skip.
            return None
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
