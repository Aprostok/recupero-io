"""Sui mainnet chain adapter (roadmap-v4: Sui live transfer coverage).

Closes the gap where ``ChainAdapter.for_chain(Chain.sui)`` raised
NotImplementedError, so a trace that bridged INTO Sui (Wormhole / native-USDC
routes) dead-ended — the Sui hop showed in the brief but the BFS never followed
where the funds went next. Sui-native USDC (Circle) + USDT (Tether) are
issuer-freezable, so reaching them is directly actionable.

Sui has no per-transfer event log. The authoritative value-flow record is a
transaction's ``balanceChanges``: the NET per-owner per-coin delta over the whole
tx (a SIGNED amount in raw base units). This adapter reconstructs honest
from->to edges by pairing the sender's negative coin delta with the OTHER
AddressOwners' positive deltas of the SAME coinType within the tx:

  * A simple ``A -> B`` transfer of N USDC shows ``A: -N, B: +N`` -> one edge.
  * A multi-recipient send shows one negative + several positives -> one edge each.
  * A DEX swap (the sender's coin goes to a pool *object*, not an address) has NO
    AddressOwner positive recipient -> NO edge is emitted (correct: it's a swap,
    handled by the on-chain swap-output logic, not a wallet-to-wallet transfer).

Scope (v1, like Stellar's "direct payments only"): only AddressOwner<->
AddressOwner coin movements are emitted. Object/Shared owners (pools, dynamic
fields) are not fabricated into followable address nodes.

Forensic posture: amounts are the EXACT raw deltas the RPC returns (the recipient
positive amount, never gas-contaminated). Decimals come from a small set of
LIVE-VERIFIED pinned coins (SUI/USDC/USDT) or a real ``getCoinMetadata`` lookup;
a coin whose metadata can't be resolved is SKIPPED, never assigned guessed
decimals. Addresses are canonicalised via the verified Move-VM codec. Sui exposes
no per-event receipt block here, so ``fetch_evidence_receipt`` returns a digest +
explorer pointer (raw_* empty) rather than inventing block data.
"""

from __future__ import annotations

import contextlib
import logging
import os
from datetime import UTC, datetime
from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.move_address import is_valid_sui_address, normalize_sui_address
from recupero.chains.sui.client import SuiRPCClient, SuiRPCError
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)

# Native gas coin.
SUI_COIN_TYPE = "0x2::sui::SUI"
SUI_SYMBOL = "SUI"
SUI_DECIMALS = 9
SUI_COINGECKO_ID = "sui"

_SUISCAN_TX = "https://suiscan.xyz/mainnet/tx/"
_SUISCAN_ADDR = "https://suiscan.xyz/mainnet/account/"

# LIVE-VERIFIED (2026-06) high-value coins: (symbol, decimals, coingecko_id).
# Pinning these avoids a metadata round-trip on the freeze-relevant assets and
# carries the priceable coingecko id. Everything else is resolved via
# getCoinMetadata (decimals real, coingecko_id None) or skipped if unresolvable.
_PINNED_COINS: dict[str, tuple[str, int, str | None]] = {
    SUI_COIN_TYPE: (SUI_SYMBOL, SUI_DECIMALS, SUI_COINGECKO_ID),
    # Circle native USDC on Sui.
    "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC":
        ("USDC", 6, "usd-coin"),
    # Wormhole-wrapped USDT (the long-standing "coin::COIN" type).
    "0xc060006111016b8a020ad5b33834984a437aaa7d3c74c18e09a95d48aceab08c::coin::COIN":
        ("USDT", 6, "tether"),
    # Sui-bridge USDT.
    "0x375f70cf2ae4c00bf37117d0c85a2c71545e6ee05c4a5c7d282cd66a4504b068::usdt::USDT":
        ("USDT", 6, "tether"),
}


# Per-address fetch budget. Mirrors the project standard
# (config.trace.max_transfers_per_address = 50_000, env-overridable) so a Sui
# trace through a busy address isn't silently capped far below every other
# chain. Pre-this the adapter hardcoded max_pages=3 (150 txs) and truncated
# SILENTLY; now the cap is budget-derived + a truncation is WARNED, never silent.
_DEFAULT_MAX_TRANSFERS_PER_ADDRESS = 50_000
_HARD_PAGE_CEILING = 5_000  # 5_000 pages x 50 = 250k txs — a runaway backstop.


def _resolve_max_pages(budget: int | None, page_size: int) -> int:
    """Translate a per-address transfer budget into a page cap.
    ``budget <= 0`` means disabled/unbounded → the hard ceiling; otherwise
    ceil(budget / page_size) clamped to ``[1, _HARD_PAGE_CEILING]``."""
    cap = _DEFAULT_MAX_TRANSFERS_PER_ADDRESS if budget is None else budget
    if cap <= 0:
        return _HARD_PAGE_CEILING
    pages = -(-cap // max(1, page_size))  # ceil, no float
    return max(1, min(_HARD_PAGE_CEILING, pages))


def _env_transfer_budget() -> int | None:
    """RECUPERO_MAX_TRANSFERS_PER_ADDRESS as an int, or None when unset/garbage."""
    raw = os.environ.get("RECUPERO_MAX_TRANSFERS_PER_ADDRESS")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _owner_address(owner: Any) -> str | None:
    """Extract the AddressOwner from a balanceChange ``owner``. Object/Shared/
    Immutable owners (and anything malformed) -> None (not an address node)."""
    if isinstance(owner, dict):
        addr = owner.get("AddressOwner")
        if isinstance(addr, str) and is_valid_sui_address(addr):
            return normalize_sui_address(addr)
    return None


def _block_time(ms: Any) -> datetime:
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.fromtimestamp(0, tz=UTC)


class SuiAdapter(ChainAdapter):
    """Sui mainnet adapter (native SUI + coin transfers via JSON-RPC)."""

    chain = Chain.sui

    def __init__(self, *, client: SuiRPCClient | None = None,
                 max_pages: int | None = None, page_size: int = 50) -> None:
        self.client = client or SuiRPCClient()
        self._page_size = max(1, min(page_size, 50))
        # max_pages=None (default) → derive from the project transfer budget
        # (RECUPERO_MAX_TRANSFERS_PER_ADDRESS, default 50_000). An explicit
        # int still overrides (tests / a caller that wants a tight cap).
        if max_pages is None:
            max_pages = _resolve_max_pages(_env_transfer_budget(), self._page_size)
        self._max_pages = max(1, max_pages)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.client.close()

    # ----- block / time -----

    def block_at_or_before(self, ts: datetime) -> int:
        """Sui orders by checkpoint, not a ts->index endpoint; the BFS filters
        client-side on each tx's timestampMs. Return a unix-ts cutoff."""
        return int(ts.timestamp())

    def is_contract(self, address: Address) -> bool:  # noqa: ARG002
        """Sui packages are addressed separately from user accounts; a traced
        owner address is an account. Conservatively False (no contract-skip)."""
        return False

    # ----- token resolution -----

    def _resolve_token(self, coin_type: str) -> TokenRef | None:
        """Build a TokenRef for ``coin_type`` from the pinned map or live
        metadata. ``None`` (skip the edge) when decimals can't be resolved —
        never guess decimals."""
        pinned = _PINNED_COINS.get(coin_type)
        if pinned is not None:
            symbol, decimals, cg = pinned
        else:
            meta = self.client.get_coin_metadata(coin_type)
            if not isinstance(meta, dict):
                return None
            try:
                decimals = int(meta.get("decimals"))
            except (TypeError, ValueError):
                return None
            if decimals < 0 or decimals > 255:
                return None
            symbol = str(meta.get("symbol") or coin_type.rsplit("::", 1)[-1])[:32]
            cg = None
        return TokenRef(
            chain=Chain.sui, contract=coin_type, symbol=symbol,
            decimals=decimals, coingecko_id=cg,
        )

    # ----- balanceChange -> normalized edges -----

    def _balances_by_coin(
        self, balance_changes: Any,
    ) -> dict[str, dict[str, int]]:
        """Collapse balanceChanges into ``{coinType: {address: net_raw}}`` over
        AddressOwner entries only (object/shared owners ignored)."""
        out: dict[str, dict[str, int]] = {}
        if not isinstance(balance_changes, list):
            return out
        for bc in balance_changes:
            if not isinstance(bc, dict):
                continue
            addr = _owner_address(bc.get("owner"))
            coin = bc.get("coinType")
            if addr is None or not isinstance(coin, str) or not coin:
                continue
            try:
                amt = int(str(bc.get("amount")))
            except (TypeError, ValueError):
                continue
            coin_map = out.setdefault(coin, {})
            coin_map[addr] = coin_map.get(addr, 0) + amt
        return out

    def _normalize_tx(
        self, tx: Any, focus: str, *, outflow: bool, native: bool,
    ) -> list[dict[str, Any]]:
        if not isinstance(tx, dict):
            return []
        digest = tx.get("digest")
        if not isinstance(digest, str) or not digest:
            return []
        sender = (
            tx.get("transaction", {}).get("data", {}).get("sender")
            if isinstance(tx.get("transaction"), dict) else None
        )
        block_time = _block_time(tx.get("timestampMs"))
        balances = self._balances_by_coin(tx.get("balanceChanges"))

        edges: list[dict[str, Any]] = []
        for coin, by_addr in balances.items():
            if native != (coin == SUI_COIN_TYPE):
                continue
            token: TokenRef | None = None  # resolve lazily (skips metadata calls)

            if outflow:
                # focus must have sent this coin (net negative) for an outflow.
                if by_addr.get(focus, 0) >= 0:
                    continue
                recipients = [
                    (a, amt) for a, amt in by_addr.items()
                    if a != focus and amt > 0
                ]
                for to_addr, amt in recipients:
                    token = token or self._resolve_token(coin)
                    if token is None:
                        break
                    edges.append(self._edge(
                        digest, block_time, focus, to_addr, token, amt,
                    ))
            else:
                # inbound: focus received this coin (net positive).
                got = by_addr.get(focus, 0)
                if got <= 0:
                    continue
                token = token or self._resolve_token(coin)
                if token is None:
                    continue
                from_addr = self._attribute_source(sender, focus, by_addr)
                edges.append(self._edge(
                    digest, block_time, from_addr, focus, token, got,
                ))
        return edges

    @staticmethod
    def _attribute_source(sender: Any, focus: str, by_addr: dict[str, int]) -> str:
        """Best honest 'from' for an inbound edge: the tx sender if it's a real
        address other than focus; else the largest decreaser of this coin; else a
        non-fabricated placeholder."""
        if isinstance(sender, str) and is_valid_sui_address(sender):
            norm = normalize_sui_address(sender)
            if norm != focus:
                return norm
        decreasers = sorted(
            ((a, amt) for a, amt in by_addr.items() if a != focus and amt < 0),
            key=lambda kv: kv[1],
        )
        if decreasers:
            return decreasers[0][0]
        return "sui:unknown_source"

    def _edge(
        self, digest: str, block_time: datetime, frm: str, to: str,
        token: TokenRef, amount_raw: int,
    ) -> dict[str, Any]:
        return {
            "chain": Chain.sui,
            "tx_hash": digest,
            "block_number": 0,  # Sui uses checkpoints; block_time is authoritative
            "block_time": block_time,
            "log_index": None,
            "from": frm,
            "to": to,
            "token": token,
            "amount_raw": int(amount_raw),
            "explorer_url": self.explorer_tx_url(digest),
            "_native_source": "sui_balance_change",
        }

    # ----- transfer fetching -----

    def _fetch(
        self, address: Address, start_block: int, *, outflow: bool, native: bool,
    ) -> list[dict[str, Any]]:
        if not is_valid_sui_address(address):
            return []
        focus = normalize_sui_address(address)
        tx_filter = {"FromAddress": focus} if outflow else {"ToAddress": focus}
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        for _page in range(self._max_pages):
            try:
                page = self.client.query_transaction_blocks(
                    tx_filter, cursor=cursor, limit=self._page_size,
                    descending=True,
                )
            except SuiRPCError as exc:
                log.warning("sui: queryTransactionBlocks failed for %s: %s",
                            focus, exc)
                break
            for tx in page.get("data", []):
                bt = _block_time(tx.get("timestampMs")) if isinstance(tx, dict) else None
                if bt is not None and int(bt.timestamp()) < start_block:
                    continue
                out.extend(self._normalize_tx(
                    tx, focus, outflow=outflow, native=native,
                ))
            if not page.get("hasNextPage"):
                break
            cursor = page.get("nextCursor")
            if not cursor:
                break
        else:
            # Loop ran the full page cap while more pages remained → truncated.
            log.warning(
                "sui: %s trace hit the %d-page cap (~%d txs) for %s with more "
                "pages available — trace may be INCOMPLETE; raise "
                "RECUPERO_MAX_TRANSFERS_PER_ADDRESS.",
                "outflow" if outflow else "inflow", self._max_pages,
                self._max_pages * self._page_size, focus,
            )
        return out

    def fetch_native_outflows(
        self, from_address: Address, start_block: int = 0,
    ) -> list[dict[str, Any]]:
        return self._fetch(from_address, start_block, outflow=True, native=True)

    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int = 0,
    ) -> list[dict[str, Any]]:
        return self._fetch(from_address, start_block, outflow=True, native=False)

    def fetch_native_inflows(
        self, to_address: Address, start_block: int = 0,
        *, max_results: int | None = None,  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        return self._fetch(to_address, start_block, outflow=False, native=True)

    def fetch_erc20_inflows(
        self, to_address: Address, start_block: int = 0,
        *, max_results: int | None = None,  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        # Inbound non-native coins (the BFS reverse hop / bridge-in correlation).
        if not is_valid_sui_address(to_address):
            return []
        focus = normalize_sui_address(to_address)
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        for _page in range(self._max_pages):
            try:
                page = self.client.query_transaction_blocks(
                    {"ToAddress": focus}, cursor=cursor, limit=self._page_size,
                    descending=True,
                )
            except SuiRPCError:
                break
            for tx in page.get("data", []):
                bt = _block_time(tx.get("timestampMs")) if isinstance(tx, dict) else None
                if bt is not None and int(bt.timestamp()) < start_block:
                    continue
                out.extend(self._normalize_tx(
                    tx, focus, outflow=False, native=False,
                ))
            if not page.get("hasNextPage"):
                break
            cursor = page.get("nextCursor")
            if not cursor:
                break
        else:
            log.warning(
                "sui: inflow (coin) trace hit the %d-page cap (~%d txs) for %s "
                "with more pages available — trace may be INCOMPLETE; raise "
                "RECUPERO_MAX_TRANSFERS_PER_ADDRESS.",
                self._max_pages, self._max_pages * self._page_size, focus,
            )
        return out

    # ----- evidence + explorer -----

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        """Anchor the receipt to the REAL on-chain time. ``sui_getTransactionBlock``
        returns ``timestampMs`` + ``checkpoint`` (+ the tx input/effects) in a single
        call, so the chain-of-custody record carries a true block time instead of a
        placeholder. Best-effort: a transport/RPC failure falls back to the
        unknown-time sentinel (epoch 0, raw_* empty) rather than raising — a
        transient RPC blip never breaks evidence writing, and we never fabricate a
        time we couldn't fetch."""
        block_time = datetime.fromtimestamp(0, tz=UTC)
        block_number = 0
        raw_tx: dict[str, Any] = {}
        raw_effects: dict[str, Any] = {}
        try:
            tb = self.client.get_transaction_block(tx_hash)
        except SuiRPCError as exc:
            log.warning("sui: evidence block fetch failed for %s: %s", tx_hash, exc)
            tb = None
        if isinstance(tb, dict):
            bt = _block_time(tb.get("timestampMs"))
            if int(bt.timestamp()) > 0:  # real time fetched (not the epoch-0 fallback)
                block_time = bt
            try:
                block_number = int(tb.get("checkpoint"))
            except (TypeError, ValueError):
                block_number = 0
            if isinstance(tb.get("transaction"), dict):
                raw_tx = tb["transaction"]
            if isinstance(tb.get("effects"), dict):
                raw_effects = tb["effects"]
        return EvidenceReceipt(
            chain=Chain.sui,
            tx_hash=tx_hash,
            block_number=block_number,
            block_time=block_time,
            raw_transaction=raw_tx,
            raw_receipt=raw_effects,
            raw_block_header={},
            fetched_at=datetime.now(UTC),
            fetched_from=self.client.base_url,
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"{_SUISCAN_TX}{tx_hash}"

    def explorer_address_url(self, address: Address) -> str:
        return f"{_SUISCAN_ADDR}{address}"


__all__ = (
    "SuiAdapter",
    "SUI_COIN_TYPE",
    "SUI_SYMBOL",
    "SUI_DECIMALS",
    "SUI_COINGECKO_ID",
)
