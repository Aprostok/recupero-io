"""Stellar chain adapter (Horizon backend).

Covers classic ``payment`` operations — native XLM and issued assets (USDC/USDT)
— which is the stablecoin off-ramp surface that matters for tracing + freezes.
All amounts on Stellar carry 7 decimals (stroops); Horizon returns them as
decimal strings (e.g. "4164.6400000"), which we convert to raw integer units.

block_at_or_before returns a unix-ts cutoff (Horizon has no ts→ledger index at
this endpoint); fetches filter on each payment's ``created_at``. Addresses are
canonicalized via the StrKey validator. Data shapes verified live against
horizon.stellar.org. Path-payments / create_account are deferred (only direct
``payment`` ops are normalized in v1).
"""

from __future__ import annotations

import contextlib
import logging
import os
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.stellar.address import normalize_stellar_address
from recupero.chains.stellar.client import HorizonClient, HorizonError
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)

# Per-address fetch budget. Pre-this the adapter made a SINGLE get_payments call
# (limit=100) and never paginated — a hard 100-payment cap that silently
# truncated any active Stellar account (a stablecoin off-ramp). Now it cursor-
# paginates (Horizon paging_token) up to a budget from
# RECUPERO_MAX_TRANSFERS_PER_ADDRESS (Horizon's max page size is 200).
_STELLAR_PAGE_SIZE = 200
_DEFAULT_MAX_TRANSFERS_PER_ADDRESS = 50_000
_HARD_PAGE_CEILING = 5_000  # runaway backstop (5_000 x 200 = 1M payments).


def _resolve_stellar_max_pages() -> int:
    """RECUPERO_MAX_TRANSFERS_PER_ADDRESS → a Horizon page cap. ``<= 0``
    (disabled/unbounded) → the hard ceiling; else ceil(budget / 200) clamped."""
    raw = os.environ.get("RECUPERO_MAX_TRANSFERS_PER_ADDRESS")
    budget = _DEFAULT_MAX_TRANSFERS_PER_ADDRESS
    if raw is not None:
        try:
            budget = int(raw)
        except (TypeError, ValueError):
            budget = _DEFAULT_MAX_TRANSFERS_PER_ADDRESS
    if budget <= 0:
        return _HARD_PAGE_CEILING
    pages = -(-budget // _STELLAR_PAGE_SIZE)  # ceil, no float
    return max(1, min(_HARD_PAGE_CEILING, pages))

XLM_SYMBOL = "XLM"
XLM_DECIMALS = 7
XLM_COINGECKO_ID = "stellar"
_ASSET_DECIMALS = 7  # all Stellar assets use 7-decimal precision

_EXPERT_TX = "https://stellar.expert/explorer/public/tx/"
_EXPERT_ADDR = "https://stellar.expert/explorer/public/account/"

# Priceable issued assets by asset_code → coingecko id. Only assets we can value
# with confidence; others are still traced but priced by contract-resolution
# (coingecko_id=None). USDC = Circle (freeze-relevant), USDT = Tether.
_ASSET_COINGECKO: dict[str, str] = {"USDC": "usd-coin", "USDT": "tether"}


def _parse_created_at(raw: Any) -> datetime:
    if isinstance(raw, str) and raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.fromtimestamp(0, tz=UTC)


def _amount_to_raw(raw: Any) -> int | None:
    """Decimal-string amount → raw 7-decimal integer units. None if unparseable."""
    try:
        return int((Decimal(str(raw)) * (10 ** _ASSET_DECIMALS)).to_integral_value())
    except (InvalidOperation, TypeError, ValueError):
        return None


class StellarAdapter(ChainAdapter):
    """Stellar mainnet adapter (native XLM + issued-asset payments via Horizon)."""

    def __init__(self, *, client: HorizonClient | None = None) -> None:
        self.client = client or HorizonClient()
        # Budget-derived pagination cap (was a single un-paginated 100-payment call).
        self._max_pages = _resolve_stellar_max_pages()

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.client.close()

    def block_at_or_before(self, ts: datetime) -> int:
        """Unix-ts cutoff; fetches filter on payment created_at >= it."""
        return int(ts.timestamp())

    def is_contract(self, address: Address) -> bool:
        """Classic Stellar accounts are not contracts; Soroban (C-addrs) are out
        of scope. Conservatively False."""
        return False

    # --- native XLM --- #

    def fetch_native_outflows(
        self, from_address: Address, start_block: int,
    ) -> list[dict[str, Any]]:
        return self._fetch_payments(from_address, start_block, native=True)

    # --- issued assets (USDC/USDT/…) --- #

    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int,
    ) -> list[dict[str, Any]]:
        return self._fetch_payments(from_address, start_block, native=False)

    def _fetch_payments(
        self, from_address: Address, start_block: int, *, native: bool,
    ) -> list[dict[str, Any]]:
        try:
            account = normalize_stellar_address(from_address)
        except ValueError:
            return []

        out: list[dict[str, Any]] = []
        cursor: str | None = None
        for _page in range(self._max_pages):
            try:
                batch = self.client.get_payments(
                    account, limit=_STELLAR_PAGE_SIZE, cursor=cursor,
                )
            except HorizonError as exc:
                if out:
                    # Mid-pagination failure: keep what we collected (partial >
                    # nothing), don't lose it.
                    log.warning("stellar: pagination stopped early for %s after "
                                "%d row(s): %s", account, len(out), exc)
                    break
                log.warning("stellar payments fetch failed for %s: %s", account, exc)
                return []
            if not batch:
                break
            for rec in batch:
                norm = self._normalize_payment(
                    rec, account, start_block, native=native,
                )
                if norm is not None:
                    out.append(norm)
            # Records are newest-first; once a page's OLDEST record predates the
            # start cutoff, every later page is older too — stop paginating.
            if start_block > 0:
                oldest = batch[-1]
                if int(_parse_created_at(oldest.get("created_at")).timestamp()) < start_block:
                    break
            if len(batch) < _STELLAR_PAGE_SIZE:  # short page → exhausted
                break
            cursor = batch[-1].get("paging_token")
            if not cursor:
                break
        else:
            log.warning(
                "stellar: hit the %d-page cap for %s with more history available "
                "— trace may be INCOMPLETE; raise RECUPERO_MAX_TRANSFERS_PER_ADDRESS.",
                self._max_pages, account,
            )
        return out

    def _normalize_payment(
        self, rec: Any, account: str, start_block: int, *, native: bool,
    ) -> dict[str, Any] | None:
        if not isinstance(rec, dict) or rec.get("type") != "payment":
            return None
        if rec.get("transaction_successful") is False:
            return None
        asset_type = rec.get("asset_type")
        is_native = asset_type == "native"
        if native != is_native:
            return None
        # Outflow only: this account is the sender.
        if rec.get("from") != account:
            return None
        dest = rec.get("to")
        if not isinstance(dest, str) or not dest:
            return None
        try:
            to_addr = normalize_stellar_address(dest)
        except ValueError:
            return None
        if to_addr == account:
            return None
        created = rec.get("created_at")
        block_time = _parse_created_at(created)
        if int(block_time.timestamp()) < start_block:
            return None
        amount_raw = _amount_to_raw(rec.get("amount"))
        if amount_raw is None or amount_raw <= 0:
            return None
        tx_hash = rec.get("transaction_hash")
        if not isinstance(tx_hash, str) or not tx_hash:
            return None

        if is_native:
            token = TokenRef(
                chain=Chain.stellar, contract=None, symbol=XLM_SYMBOL,
                decimals=XLM_DECIMALS, coingecko_id=XLM_COINGECKO_ID,
            )
        else:
            code = str(rec.get("asset_code") or "")
            issuer = str(rec.get("asset_issuer") or "")
            if not code or not issuer:
                return None
            token = TokenRef(
                chain=Chain.stellar,
                contract=f"{code}-{issuer}",  # Stellar canonical asset id
                symbol=code, decimals=_ASSET_DECIMALS,
                coingecko_id=_ASSET_COINGECKO.get(code),
            )

        return {
            "chain": Chain.stellar,
            "tx_hash": tx_hash,
            "block_number": 0,  # Stellar uses ledger seq; block_time is authoritative
            "block_time": block_time,
            "log_index": None,
            "from": account,
            "to": to_addr,
            "token": token,
            "amount_raw": amount_raw,
            "explorer_url": self.explorer_tx_url(tx_hash),
        }

    # --- evidence + explorer --- #

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        return EvidenceReceipt(
            chain=Chain.stellar,
            tx_hash=tx_hash,
            block_number=0,
            block_time=datetime.fromtimestamp(0, tz=UTC),
            raw_transaction={},
            raw_receipt={},
            raw_block_header={},
            fetched_at=datetime.now(UTC),
            fetched_from="horizon.stellar.org",
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"{_EXPERT_TX}{tx_hash}"

    def explorer_address_url(self, address: Address) -> str:
        return f"{_EXPERT_ADDR}{address}"


__all__ = (
    "StellarAdapter",
    "XLM_SYMBOL",
    "XLM_DECIMALS",
    "XLM_COINGECKO_ID",
)
