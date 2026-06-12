"""Hyperliquid chain adapter (roadmap-v4 Tier-2 #12).

The gap this closes: ``ChainAdapter.for_chain(Chain.hyperliquid)`` raised
NotImplementedError, so when a trace bridged INTO Hyperliquid (the top perps
venue) the cross-chain continuation silently dead-ended — the HL hop showed in
the brief but the BFS never followed where the funds went next. The dedicated
``scrape_hyperliquid_case`` only SEEDS a case from an HL wallet; it is not the
continuation path.

Hyperliquid is not a block chain — it is a perps/spot venue with an internal
USDC ledger and Ethereum-format (0x) addresses. The only EXTERNAL value-flow
events are ``withdraw`` (USDC leaving HL, bridged to the same address on
Arbitrum) and ``deposit`` (USDC arriving). This adapter exposes those as
Transfer-shaped normalized rows so the BFS can follow an HL node's withdrawals
to their Arbitrum USDC destination — a freezable continuation.

It reuses the LIVE-VERIFIED ``HyperliquidClient.get_non_funding_ledger_updates``
+ ``HyperliquidLedgerEvent`` (delta_type / signed usdc_delta / destination) and
the same money-flow filter the proven scraper uses, so no new on-chain shape is
introduced. Internal HL ledger categories (spotTransfer, accountClassTransfer,
subAccountTransfer, …) are NOT external transfers and are excluded.

Forensic posture: amounts are exact USDC micro-units; a withdrawal's
``destination`` is the protocol-reported Arbitrum recipient (best-effort
re-resolved when absent, else a terminal placeholder — never fabricated). HL
has no per-event receipt endpoint, so ``fetch_evidence_receipt`` raises (the
tracer's evidence writer is best-effort) rather than inventing a block.
"""

from __future__ import annotations

import logging
from datetime import datetime
from decimal import Decimal
from typing import Any

from recupero.chains.hyperliquid.client import (
    HyperliquidClient,
    _is_hex_address,
    resolve_unknown_destination,
)
from recupero.chains.hyperliquid.scraper import (
    ARBITRUM_USDC,
    USDC_DECIMALS,
    _sanitize_address_field,
)
from recupero.models import Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)

# Only these ledger delta_types are EXTERNAL value flows (same set the proven
# scraper uses). Everything else is HL-internal accounting.
_MONEY_FLOW_DELTA_TYPES = frozenset({"withdraw", "deposit"})

# Hyperliquid's info API takes a start time, not a block. Epoch 0 = "all
# history" (the client paginates); a continuation node is one wallet, bounded.
_ALL_HISTORY_START_MS = 0


def _norm_addr(value: str | None, *, fallback: str) -> str:
    """Checksum a hex address; otherwise return a sanitized placeholder
    (never fabricate an address)."""
    if _is_hex_address(value):
        try:
            from eth_utils import to_checksum_address
            return to_checksum_address(value)
        except Exception:  # noqa: BLE001
            return str(value).lower()
    return _sanitize_address_field(value, fallback=fallback)


class HyperliquidAdapter:
    """Mimics the ChainAdapter surface the BFS uses (does not inherit the ABC,
    whose ``Address`` type is EVM-shaped — same pattern as CosmosAdapter)."""

    def __init__(self, client: HyperliquidClient | None = None) -> None:
        self.client = client or HyperliquidClient()

    # ----- block / time -----

    def block_at_or_before(self, ts: datetime) -> int:  # noqa: ARG002
        """Hyperliquid has no blocks; the BFS filters client-side by time."""
        return -1

    def is_contract(self, address: str) -> bool:  # noqa: ARG002
        """HL addresses are user EOAs (Ethereum-format). The bridge is the only
        contract and is not a trace continuation target — treat all as EOA."""
        return False

    # ----- transfer fetching -----

    def _money_flows(
        self, address: str, *, outflow: bool
    ) -> list[dict[str, Any]]:
        try:
            events = self.client.get_non_funding_ledger_updates(
                address, start_time_ms=_ALL_HISTORY_START_MS,
            )
        except Exception as exc:  # noqa: BLE001 — best-effort continuation fetch
            log.warning("hyperliquid: ledger fetch failed user=%s: %s", address, exc)
            return []
        out: list[dict[str, Any]] = []
        for evt in events:
            delta = getattr(evt, "usdc_delta", None)
            if delta is None or not delta.is_finite() or delta == 0:
                continue
            if getattr(evt, "delta_type", None) not in _MONEY_FLOW_DELTA_TYPES:
                continue  # internal accounting, not an external transfer
            is_out = delta < 0
            if is_out != outflow:
                continue
            dest = evt.destination
            if is_out and not _is_hex_address(dest):
                # best-effort re-resolve a missing withdrawal destination
                resolved = resolve_unknown_destination(address, evt.when)
                if resolved is not None and _is_hex_address(resolved):
                    dest = resolved
            counterparty = _norm_addr(
                dest,
                fallback=("hyperliquid:unknown_destination" if is_out
                          else "hyperliquid:unknown_source"),
            )
            user = _norm_addr(address, fallback="hyperliquid:user")
            try:
                amount_raw = int(abs(delta) * Decimal(10 ** USDC_DECIMALS))
            except (ValueError, ArithmeticError):
                continue
            out.append({
                "chain": Chain.hyperliquid,
                "tx_hash": str(getattr(evt, "hash", "") or ""),
                # HL has no block height; the ms timestamp is the only ordinal.
                "block_number": int(getattr(evt, "time_ms", 0) or 0),
                "block_time": evt.when,
                "log_index": None,
                "from": user if is_out else counterparty,
                "to": counterparty if is_out else user,
                "token": TokenRef(
                    chain=Chain.hyperliquid,
                    contract=ARBITRUM_USDC,
                    symbol="USDC",
                    decimals=USDC_DECIMALS,
                    coingecko_id="usd-coin",
                ),
                "amount_raw": amount_raw,
                "explorer_url": self.explorer_tx_url(str(getattr(evt, "hash", ""))),
                "_native_source": "hyperliquid_ledger",
            })
        return out

    def fetch_native_outflows(
        self, from_address: str, start_block: int = 0  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        """USDC withdrawals OUT of Hyperliquid (bridged to Arbitrum). The only
        external outflow on a venue with no native gas token."""
        return self._money_flows(from_address, outflow=True)

    def fetch_erc20_outflows(
        self, from_address: str, start_block: int = 0  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        """Hyperliquid has no ERC-20 surface — USDC is exposed via the native
        path. Always empty (signature preserved for adapter compatibility)."""
        return []

    def fetch_inflows(
        self, to_address: str, start_block: int = 0  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        """USDC deposits INTO Hyperliquid — for the BFS reverse hop."""
        return self._money_flows(to_address, outflow=False)

    # ----- evidence / explorer -----

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        """Hyperliquid exposes no per-event receipt endpoint — there is no
        block to anchor a chain-of-custody record. Raise rather than fabricate;
        the tracer's evidence writer is best-effort and logs the miss (the
        ledger event itself, surfaced as the Transfer, is the evidence)."""
        raise ValueError(
            "hyperliquid: no per-event receipt endpoint; the ledger event "
            f"({tx_hash!r}) is surfaced inline as the transfer record"
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"https://app.hyperliquid.xyz/explorer/tx/{tx_hash}"

    def explorer_address_url(self, address: str) -> str:
        return f"https://app.hyperliquid.xyz/explorer/address/{address}"

    # ----- lifecycle -----

    def close(self) -> None:
        if self.client is not None:
            self.client.close()


__all__ = ("HyperliquidAdapter",)
