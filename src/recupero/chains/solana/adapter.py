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
from datetime import UTC, datetime
from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.solana.address import (
    SolanaAddressError,
    normalize_solana_address,
)
from recupero.chains.solana.helius import HeliusClient
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)


def _safe_unix_to_datetime(ts: Any) -> datetime:
    """Convert an untrusted unix-seconds value to a UTC datetime.

    Helius is an external API. A compromised / buggy response can
    carry timestamps that crash ``datetime.fromtimestamp`` —
    OverflowError (>~year 9999), OSError (Windows on very-negative),
    ValueError (Linux on very-negative). Any of these would abort
    the BFS hop mid-iteration. We clamp to a sentinel (epoch) so
    downstream code keeps moving; callers may also detect a sentinel
    block_time and drop the row if they prefer.
    """
    try:
        ts_int = int(ts or 0)
    except (TypeError, ValueError):
        return datetime.fromtimestamp(0, tz=UTC)
    try:
        return datetime.fromtimestamp(ts_int, tz=UTC)
    except (OverflowError, OSError, ValueError):
        log.warning(
            "solana: clamping out-of-range timestamp %r to epoch", ts_int,
        )
        return datetime.fromtimestamp(0, tz=UTC)


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
            ts = ts.replace(tzinfo=UTC)
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
        self, from_address: Address, start_block: int,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch SOL outflows since ``start_block`` (interpreted as unix ts)."""
        # v0.16.9 (round-9 forensic CRIT): normalize at the boundary so
        # the case-sensitive base58 comparison below is reliable. Solana
        # addresses are case-sensitive on-chain — comparing operator-
        # pasted strings to Helius response fields without normalization
        # silently dropped outflows when the seed was typed in a
        # different case than the canonical form.
        try:
            from_address = normalize_solana_address(str(from_address))
        except SolanaAddressError:
            log.warning(
                "solana fetch_native_outflows: invalid address %r; returning empty",
                from_address,
            )
            return []
        raw = self._fetch_all(from_address, start_block)
        out: list[dict[str, Any]] = []
        for tx in raw:
            try:
                if int(tx.get("timestamp", 0) or 0) < start_block:
                    continue
            except (TypeError, ValueError):
                continue
            for nt in tx.get("nativeTransfers", []) or []:
                if (nt.get("fromUserAccount") or "") != from_address:
                    continue
                try:
                    amount_lamports = int(nt.get("amount", 0) or 0)
                except (TypeError, ValueError):
                    continue
                if amount_lamports == 0:
                    continue
                try:
                    out.append(self._normalize_native(tx, nt, amount_lamports))
                except Exception as e:  # noqa: BLE001
                    log.warning(
                        "solana: dropping native transfer (sig=%s): %s",
                        tx.get("signature", "?"), e,
                    )
                    continue
        return out

    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch SPL token outflows since ``start_block`` (interpreted as unix ts).

        (Method is named ``erc20`` for interface compatibility with EVM chains;
        on Solana these are SPL tokens.)
        """
        # v0.16.9: see fetch_native_outflows comment — same normalize-
        # at-boundary fix for case-sensitive base58.
        try:
            from_address = normalize_solana_address(str(from_address))
        except SolanaAddressError:
            log.warning(
                "solana fetch_erc20_outflows: invalid address %r; returning empty",
                from_address,
            )
            return []
        raw = self._fetch_all(from_address, start_block)
        out: list[dict[str, Any]] = []
        for tx in raw:
            try:
                if int(tx.get("timestamp", 0) or 0) < start_block:
                    continue
            except (TypeError, ValueError):
                continue
            for tt in tx.get("tokenTransfers", []) or []:
                if (tt.get("fromUserAccount") or "") != from_address:
                    continue
                raw_amount = tt.get("rawTokenAmount") or {}
                # Helius exposes the SPL amount two ways with DIFFERENT units:
                #   * rawTokenAmount.tokenAmount — the BASE-UNIT integer
                #     string (already scaled by 10**decimals). Use as-is.
                #   * tt.tokenAmount — a HUMAN decimal string (e.g. "1.5").
                #     This one must be multiplied by 10**decimals.
                # v0.32.1 (chain-audit): the prior code merged both fields
                # into one string and, on the int() fallback, ALWAYS scaled
                # by 10**decimals. When the base-unit field was present but
                # not int-parseable (scientific notation / stray decimal),
                # that DOUBLE-scaled an already-scaled amount — inflating the
                # transfer by 10**decimals and corrupting the BFS USD math.
                # Each field now carries its own contract.
                raw_int_str = raw_amount.get("tokenAmount")
                human_str = tt.get("tokenAmount")
                # Clamp the scaling exponent: the SPL mint `decimals` field is
                # a u8 (on-chain max 255). Bounding it also blocks a DoS where
                # an attacker-supplied huge `decimals` makes `10 ** decimals`
                # build a multi-gigabyte integer before any OverflowError.
                try:
                    decimals = int(raw_amount.get("decimals", 0) or 0)
                except (ValueError, TypeError):
                    decimals = 0
                decimals = max(0, min(decimals, 255))
                amount_raw: int | None = None
                # 1) Prefer the base-unit field — already scaled, NEVER scale.
                if raw_int_str is not None:
                    try:
                        amount_raw = int(str(raw_int_str))
                    except (ValueError, TypeError):
                        amount_raw = None  # malformed → try the human field
                # 2) Only when the base-unit field is absent/unparseable,
                #    derive from the HUMAN decimal field WITH scaling. This
                #    path is hardened against attacker-supplied ``Infinity`` /
                #    extreme values that would otherwise raise OverflowError
                #    uncaught and kill the BFS hop.
                if amount_raw is None and human_str is not None:
                    try:
                        amount_raw = int(float(str(human_str)) * (10 ** decimals))
                    except (ValueError, TypeError, OverflowError):
                        amount_raw = None
                # Drop zero / malformed / negative magnitudes (outflow amounts
                # are positive base units). `not amount_raw` short-circuits the
                # None/0 case before the `<= 0` comparison touches None.
                if not amount_raw or amount_raw <= 0:
                    continue
                try:
                    out.append(self._normalize_spl(tx, tt, amount_raw))
                except Exception as e:  # noqa: BLE001
                    log.warning(
                        "solana: dropping SPL transfer (sig=%s): %s",
                        tx.get("signature", "?"), e,
                    )
                    continue
        return out

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        """Fetch the Helius parsed-transaction record as the receipt.

        Note: Solana uses signatures (base58, ~88 chars), not the 0x-hex of EVM.
        ``tx_hash`` here is the signature.
        """
        raw = self.client.get_parsed_transaction(tx_hash) or {}
        try:
            block_number = int(raw.get("slot", 0) or 0)
        except (TypeError, ValueError):
            block_number = 0
        block_time = _safe_unix_to_datetime(raw.get("timestamp", 0))
        return EvidenceReceipt(
            chain=self.chain, tx_hash=tx_hash, block_number=block_number,
            block_time=block_time,
            raw_transaction=raw, raw_receipt={}, raw_block_header={},
            fetched_at=datetime.now(UTC),
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
        try:
            slot = int(tx.get("slot", 0) or 0)
        except (TypeError, ValueError):
            slot = 0
        block_time = _safe_unix_to_datetime(tx.get("timestamp", 0))
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
        try:
            slot = int(tx.get("slot", 0) or 0)
        except (TypeError, ValueError):
            slot = 0
        block_time = _safe_unix_to_datetime(tx.get("timestamp", 0))
        mint = tt.get("mint", "")
        raw_amount = tt.get("rawTokenAmount") or {}
        # Decimals: prefer rawTokenAmount.decimals, fall back to a reasonable default
        decimals_raw = raw_amount.get("decimals")
        if decimals_raw is None:
            # For stablecoins, assume 6; for others, assume 9 (SOL-like). This is
            # only a fallback; Helius almost always populates it.
            decimals = 6 if mint in (USDC_SOLANA_MINT, USDT_SOLANA_MINT) else 9
        else:
            try:
                decimals = int(decimals_raw)
            except (TypeError, ValueError):
                decimals = 6 if mint in (USDC_SOLANA_MINT, USDT_SOLANA_MINT) else 9
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
