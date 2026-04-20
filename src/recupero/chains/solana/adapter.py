"""Solana adapter — implements the ChainAdapter interface over Helius.

Key design decision: Solana has no "block number" in the Ethereum sense. It
has slots, but there's no direct "slot at timestamp" API. Rather than shoehorn
a fake mapping, this adapter treats the tracer's ``start_block`` parameter as
a unix timestamp (the value returned by ``block_at_or_before``). Internally
we filter Helius's time-stamped transactions against that cutoff.

This is strictly for use by the tracer — external callers of
``block_at_or_before`` should NOT interpret the return value as a slot.

Native asset: SOL (9 decimals).
Token standard: SPL tokens, including USDC (mint EPjFWdd5...).
Explorer: solscan.io (public, no auth required).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.solana.helius import HeliusClient
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)


SOLANA_NATIVE_DECIMALS = 9            # 1 SOL = 10^9 lamports
WRAPPED_SOL_MINT = "So11111111111111111111111111111111111111112"
USDC_SOLANA_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDT_SOLANA_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"

# CoinGecko IDs for common Solana mints, to save API lookups
_MINT_TO_COINGECKO_ID: dict[str, str] = {
    USDC_SOLANA_MINT: "usd-coin",
    USDT_SOLANA_MINT: "tether",
    WRAPPED_SOL_MINT: "solana",
    # Jito staked SOL, for completeness
    "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn": "jito-staked-sol",
    # Marinade mSOL
    "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So": "msol",
    # BONK
    "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263": "bonk",
    # JUP
    "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN": "jupiter-exchange-solana",
}


class SolanaAdapter(ChainAdapter):
    chain = Chain.solana

    def __init__(self, bundle: tuple[RecuperoConfig, RecuperoEnv]) -> None:
        cfg, env = bundle
        self.cfg = cfg
        if not env.HELIUS_API_KEY:
            raise ValueError(
                "HELIUS_API_KEY is required for Solana tracing. "
                "Get a free key at helius.dev and add it to .env."
            )
        self.client = HeliusClient(api_key=env.HELIUS_API_KEY)
        self._is_program_cache: dict[str, bool] = {}

    # ---------- Required interface ----------

    def block_at_or_before(self, ts: datetime) -> int:
        """Return the unix timestamp of ``ts``, used as a cutoff by fetch_*.

        NOT a slot number — the Solana adapter uses timestamps directly
        because there's no reliable "slot at timestamp" API. The tracer
        treats the returned int opaquely as ``start_block``.
        """
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return int(ts.timestamp())

    def is_contract(self, address: Address) -> bool:
        """On Solana, 'contract' means 'program account' (executable)."""
        addr = str(address)
        if addr in self._is_program_cache:
            return self._is_program_cache[addr]
        try:
            info = self.client.get_account_info(addr)
            is_program = bool(info.get("executable", False))
        except Exception as e:  # noqa: BLE001
            log.debug("solana is_contract check failed for %s: %s", addr, e)
            is_program = False
        self._is_program_cache[addr] = is_program
        return is_program

    def fetch_native_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        """Fetch SOL outflows since ``start_block`` (interpreted as unix ts)."""
        raw = self._fetch_all(str(from_address), start_block)
        out: list[dict[str, Any]] = []
        for tx in raw:
            if tx.get("timestamp", 0) < start_block:
                continue
            for nt in tx.get("nativeTransfers", []) or []:
                if (nt.get("fromUserAccount") or "") != str(from_address):
                    continue
                amount_lamports = int(nt.get("amount", 0))
                if amount_lamports == 0:
                    continue
                out.append(self._normalize_native(tx, nt, amount_lamports))
        return out

    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        """Fetch SPL token outflows since ``start_block`` (interpreted as unix ts).

        (Method is named ``erc20`` for interface compatibility with EVM chains;
        on Solana these are SPL tokens.)
        """
        raw = self._fetch_all(str(from_address), start_block)
        out: list[dict[str, Any]] = []
        for tx in raw:
            if tx.get("timestamp", 0) < start_block:
                continue
            for tt in tx.get("tokenTransfers", []) or []:
                if (tt.get("fromUserAccount") or "") != str(from_address):
                    continue
                raw_amount = tt.get("rawTokenAmount") or {}
                amount_raw_str = str(raw_amount.get("tokenAmount") or tt.get("tokenAmount") or "0")
                # rawTokenAmount.tokenAmount is a raw integer string; tokenAmount
                # is a decimal float — prefer raw where available.
                try:
                    amount_raw = int(amount_raw_str)
                except ValueError:
                    # Fall back to float conversion if necessary
                    try:
                        amount_raw = int(float(amount_raw_str) * (10 ** int(raw_amount.get("decimals", 0) or 0)))
                    except (ValueError, TypeError):
                        amount_raw = 0
                if amount_raw == 0:
                    continue
                out.append(self._normalize_spl(tx, tt, amount_raw))
        return out

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        """Fetch the Helius parsed-transaction record as the receipt.

        Note: Solana uses signatures (base58, ~88 chars), not the 0x-hex of EVM.
        ``tx_hash`` here is the signature.
        """
        raw = self.client.get_parsed_transaction(tx_hash) or {}
        block_number = int(raw.get("slot", 0))
        block_time = datetime.fromtimestamp(int(raw.get("timestamp", 0) or 0), tz=timezone.utc)
        return EvidenceReceipt(
            chain=self.chain, tx_hash=tx_hash, block_number=block_number,
            block_time=block_time,
            raw_transaction=raw, raw_receipt={}, raw_block_header={},
            fetched_at=datetime.now(timezone.utc),
            fetched_from=self.client.BASE,
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"https://solscan.io/tx/{tx_hash}"

    def explorer_address_url(self, address: Address) -> str:
        return f"https://solscan.io/account/{address}"

    # ---------- Internals ----------

    def _fetch_all(self, address: str, cutoff_unix: int) -> list[dict[str, Any]]:
        """Fetch all parsed txs from Helius for address, stopping when older
        than cutoff. Cached per-address to avoid double-calling for native+SPL."""
        key = (address, cutoff_unix)
        cache = getattr(self, "_tx_cache", None)
        if cache is None:
            cache = {}
            self._tx_cache = cache
        if key in cache:
            return cache[key]
        txs = self.client.get_parsed_transactions(
            address, limit=100, stop_if_older_than=cutoff_unix,
        )
        cache[key] = txs
        return txs

    def _normalize_native(
        self, tx: dict[str, Any], nt: dict[str, Any], amount_lamports: int
    ) -> dict[str, Any]:
        slot = int(tx.get("slot", 0))
        block_time = datetime.fromtimestamp(int(tx.get("timestamp", 0) or 0), tz=timezone.utc)
        token = TokenRef(
            chain=Chain.solana, contract=None,
            symbol="SOL", decimals=SOLANA_NATIVE_DECIMALS,
            coingecko_id="solana",
        )
        return {
            "chain": Chain.solana,
            "tx_hash": tx.get("signature", ""),
            "block_number": slot,
            "block_time": block_time,
            "log_index": None,
            "from": nt.get("fromUserAccount", ""),
            "to": nt.get("toUserAccount", ""),
            "token": token,
            "amount_raw": amount_lamports,
            "explorer_url": self.explorer_tx_url(tx.get("signature", "")),
        }

    def _normalize_spl(
        self, tx: dict[str, Any], tt: dict[str, Any], amount_raw: int
    ) -> dict[str, Any]:
        slot = int(tx.get("slot", 0))
        block_time = datetime.fromtimestamp(int(tx.get("timestamp", 0) or 0), tz=timezone.utc)
        mint = tt.get("mint", "")
        raw_amount = tt.get("rawTokenAmount") or {}
        # Decimals: prefer rawTokenAmount.decimals, fall back to a reasonable default
        decimals_raw = raw_amount.get("decimals")
        if decimals_raw is None:
            # For stablecoins, assume 6; for others, assume 9 (SOL-like). This is
            # only a fallback; Helius almost always populates it.
            decimals = 6 if mint in (USDC_SOLANA_MINT, USDT_SOLANA_MINT) else 9
        else:
            decimals = int(decimals_raw)
        # Symbol — we don't get it from Helius for SPL, so derive conservatively
        symbol = _symbol_from_mint(mint)
        token = TokenRef(
            chain=Chain.solana,
            contract=mint,
            symbol=symbol,
            decimals=decimals,
            coingecko_id=_MINT_TO_COINGECKO_ID.get(mint),
        )
        return {
            "chain": Chain.solana,
            "tx_hash": tx.get("signature", ""),
            "block_number": slot,
            "block_time": block_time,
            "log_index": None,
            "from": tt.get("fromUserAccount", ""),
            "to": tt.get("toUserAccount", ""),
            "token": token,
            "amount_raw": amount_raw,
            "explorer_url": self.explorer_tx_url(tx.get("signature", "")),
        }


def _symbol_from_mint(mint: str) -> str:
    """Best-effort symbol lookup for common SPL tokens. Unknown → first 4 of mint."""
    if mint == USDC_SOLANA_MINT:
        return "USDC"
    if mint == USDT_SOLANA_MINT:
        return "USDT"
    if mint == WRAPPED_SOL_MINT:
        return "WSOL"
    if mint == "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn":
        return "JitoSOL"
    if mint == "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So":
        return "mSOL"
    if mint == "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263":
        return "BONK"
    if mint == "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN":
        return "JUP"
    return mint[:4] if mint else "?"
