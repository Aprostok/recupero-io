"""CoinGecko historical price client.

Phase 1 uses daily granularity (CoinGecko free tier). Documented limitation:
intraday price moves are not captured. For most theft cases the daily close is
within a few percent of the actual tx-time price; report flags this.

For ERC-20 tokens, we need a contract → coingecko_id mapping. Phase 1 ships a
small static map plus a fallback that calls /coins/contract/{platform}/{address}
on first encounter and caches the result.

Stablecoin shortcut: USDT, USDC, DAI, BUSD, FDUSD treated as $1.00 with a
"stablecoin_par" pricing source. Saves enormous API quota.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import TokenRef
from recupero.pricing.cache import PriceCache

log = logging.getLogger(__name__)


# --- Stablecoin shortcut ---
# Only apply $1.00 par if BOTH the symbol matches AND the contract is the canonical
# one. Many phishing/spoof tokens reuse well-known symbols ("USDC", "USDT") at
# attacker-controlled contracts to confuse traders. Without this guard, the pricing
# layer would mark a 211,484,177,701,000,000-unit fake-USDC transfer as
# $211 quadrillion ($1.00 × the raw value, with the spoof's bogus decimals).
_STABLECOIN_SYMBOLS = {"USDT", "USDC", "DAI", "BUSD", "FDUSD", "TUSD", "USDP", "USDE", "PYUSD"}
_CANONICAL_STABLECOIN_CONTRACTS: dict[str, str] = {
    "USDT": "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "DAI": "0x6b175474e89094c44da98b954eedeac495271d0f",
    "BUSD": "0x4fabb145d64652a948d72533023f6e7a623c7c53",
    "FDUSD": "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409",
    "TUSD": "0x0000000000085d4780b73119b644ae5ecd22b376",
    "USDP": "0x8e870d67f660d95d5be530380d0ec0bd388289e1",
    "PYUSD": "0x6c3ea9036406852006290770bedfcaba0e23a0e8",
}

# Hard sanity ceiling on per-transfer USD. Any single transfer claiming more than
# this is treated as a pricing error and excluded from totals. The largest known
# legitimate single tx in DeFi history is ~$1B (institutional treasury moves);
# $100M ceiling catches obvious bugs without false-positiving real activity.
_PER_TRANSFER_USD_SANITY_CEILING = Decimal("100_000_000")

# --- Static contract → CoinGecko ID map for the most common ERC-20s ---
# Address → coingecko_id, lowercased addresses for lookup convenience
_CONTRACT_TO_CG: dict[str, str] = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "tether",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "usd-coin",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "dai",
    "0x4fabb145d64652a948d72533023f6e7a623c7c53": "binance-usd",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "weth",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "wrapped-bitcoin",
    "0x514910771af9ca656af840dff83e8264ecf986ca": "chainlink",
    "0x6982508145454ce325ddbe47a25d4ec3d2311933": "pepe",
    "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce": "shiba-inu",
    "0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0": "matic-network",
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": "uniswap",
    "0x6810e776880c02933d47db1b9fc05908e5386b96": "gnosis",
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": "staked-ether",
    "0xae78736cd615f374d3085123a210448e74fc6393": "rocket-pool-eth",
    "0x853d955acef822db058eb8505911ed77f175b99e": "frax",
    "0x57e114b691db790c35207b2e685d4a43181e6061": "ondo-finance",
}


@dataclass
class PriceResult:
    usd_value: Decimal | None
    source: str | None
    error: str | None


class _RateLimiter:
    def __init__(self, rps: float) -> None:
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            sleep = self._next_allowed - now
            if sleep > 0:
                time.sleep(sleep)
                now = time.monotonic()
            self._next_allowed = now + self.min_interval


class CoinGeckoClient:
    """Computes historical USD price for a TokenRef at a given timestamp."""

    BASE_URL_PRO = "https://pro-api.coingecko.com/api/v3"
    BASE_URL_PUBLIC = "https://api.coingecko.com/api/v3"
    PLATFORM = "ethereum"  # CoinGecko platform id for Ethereum mainnet

    def __init__(self, config: RecuperoConfig, env: RecuperoEnv, cache_dir: Path) -> None:
        self.cfg = config
        self.api_key = env.COINGECKO_API_KEY
        self.cache = PriceCache(cache_dir)
        self.limiter = _RateLimiter(config.pricing.requests_per_second)
        # Pro vs Demo. Both tiers issue keys starting with "CG-", so we cannot
        # distinguish by key prefix — must come from explicit COINGECKO_TIER env var.
        # Default is "demo" (matches what most users have on the free tier).
        # Demo: public host + x_cg_demo_api_key query param.
        # Pro:  pro host + x-cg-pro-api-key header.
        self._is_pro = (env.COINGECKO_TIER or "demo").lower() == "pro"
        self._client = httpx.Client(timeout=30.0)
        self._contract_id_cache: dict[str, str | None] = dict(_CONTRACT_TO_CG)

    def close(self) -> None:
        self._client.close()

    # ---------- Public API ----------

    def price_at(self, token: TokenRef, when: datetime) -> PriceResult:
        """Returns USD price PER UNIT of `token` at `when` (daily granularity).

        IMPORTANT: this is the per-token price, not the value of any specific
        transfer. To compute the USD value of a transfer, multiply this by
        the transfer's amount_decimal.
        """
        # Stablecoin shortcut — but ONLY for the genuine canonical contract.
        # Spoofed tokens with the same symbol at attacker-controlled contracts
        # must NOT be priced at par; they get rejected with a clear error.
        symbol_upper = token.symbol.upper()
        if symbol_upper in _STABLECOIN_SYMBOLS:
            canonical = _CANONICAL_STABLECOIN_CONTRACTS.get(symbol_upper)
            token_contract_lower = (token.contract or "").lower()
            if canonical and token_contract_lower == canonical:
                return PriceResult(
                    usd_value=Decimal("1.00"),
                    source="stablecoin_par",
                    error=None,
                )
            # Symbol matches a stablecoin but contract does NOT match canonical.
            # This is almost always a phishing/spoof token. Refuse to price.
            return PriceResult(
                usd_value=None,
                source=None,
                error=f"spoofed_canonical_symbol:{symbol_upper}_at_{token_contract_lower or 'no_contract'}",
            )

        # Resolve to coingecko_id
        cg_id = token.coingecko_id or self._resolve_cg_id(token)
        if not cg_id:
            return PriceResult(
                usd_value=None,
                source=None,
                error="no_coingecko_mapping",
            )

        d = when.date()
        key = f"coingecko:{cg_id}:{d.isoformat()}"
        cached = self.cache.get(key)
        if cached is not None and "usd" in cached:
            usd = cached["usd"]
            return PriceResult(
                usd_value=Decimal(str(usd)) if usd is not None else None,
                source=key,
                error=None if usd is not None else cached.get("error"),
            )

        # Fetch
        try:
            usd = self._fetch_history(cg_id, d)
        except Exception as e:  # noqa: BLE001 — we want to keep tracing alive
            log.debug("coingecko fetch failed for %s on %s: %s", cg_id, d, e)
            self.cache.put(key, {"usd": None, "error": f"fetch_error: {e}"})
            return PriceResult(usd_value=None, source=None, error=f"fetch_error: {e}")

        self.cache.put(key, {"usd": str(usd) if usd is not None else None})
        return PriceResult(
            usd_value=Decimal(str(usd)) if usd is not None else None,
            source=key,
            error=None if usd is not None else "no_price_data",
        )

    # ---------- Internals ----------

    def _resolve_cg_id(self, token: TokenRef) -> str | None:
        if token.contract is None:
            # Native — caller should have set coingecko_id ('ethereum' for ETH)
            return None
        addr_lower = token.contract.lower()
        if addr_lower in self._contract_id_cache:
            return self._contract_id_cache[addr_lower]
        try:
            cg_id = self._fetch_contract_to_id(addr_lower)
        except Exception as e:  # noqa: BLE001
            log.debug("coingecko contract->id resolution failed for %s: %s", addr_lower, e)
            cg_id = None
        self._contract_id_cache[addr_lower] = cg_id
        return cg_id

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    def _fetch_contract_to_id(self, contract_lower: str) -> str | None:
        url = f"{self._base_url()}/coins/{self.PLATFORM}/contract/{contract_lower}"
        self.limiter.wait()
        resp = self._client.get(url, headers=self._headers(), params=self._auth_params())
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            time.sleep(15)
            return None
        resp.raise_for_status()
        data = resp.json()
        return data.get("id")

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    def _fetch_history(self, cg_id: str, d: date) -> Decimal | None:
        # CoinGecko expects DD-MM-YYYY
        date_str = f"{d.day:02d}-{d.month:02d}-{d.year}"
        url = f"{self._base_url()}/coins/{cg_id}/history"
        params = {"date": date_str, "localization": "false", **self._auth_params()}
        self.limiter.wait()
        resp = self._client.get(url, headers=self._headers(), params=params)
        if resp.status_code == 429:
            time.sleep(15)
            raise httpx.TransportError("rate limited")
        resp.raise_for_status()
        data = resp.json()
        try:
            usd = data["market_data"]["current_price"]["usd"]
            return Decimal(str(usd))
        except (KeyError, TypeError):
            return None

    def _base_url(self) -> str:
        return self.BASE_URL_PRO if self._is_pro else self.BASE_URL_PUBLIC

    def _headers(self) -> dict[str, str]:
        if self._is_pro and self.api_key:
            return {"x-cg-pro-api-key": self.api_key}
        return {}

    def _auth_params(self) -> dict[str, str]:
        # Demo keys use query param
        if not self._is_pro and self.api_key:
            return {"x_cg_demo_api_key": self.api_key}
        return {}
