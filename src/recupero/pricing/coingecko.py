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
from recupero.models import Chain, TokenRef
from recupero.pricing.cache import PriceCache

log = logging.getLogger(__name__)


# --- CoinGecko platform identifiers per chain ---
# These are the path segments CoinGecko uses in /coins/{platform}/contract/{addr}
# to look up tokens by contract address on a specific chain.
_CHAIN_TO_CG_PLATFORM: dict[Chain, str] = {
    Chain.ethereum: "ethereum",
    Chain.arbitrum: "arbitrum-one",
    Chain.bsc: "binance-smart-chain",
    Chain.solana: "solana",
    Chain.base: "base",
    Chain.polygon: "polygon-pos",
}


# --- Stablecoin shortcut ---
# Only apply $1.00 par if BOTH the symbol matches AND the contract is the canonical
# one ON THE GIVEN CHAIN. Many phishing/spoof tokens reuse well-known symbols
# ("USDC", "USDT") at attacker-controlled contracts to confuse traders. Without
# this guard, the pricing layer would mark a 211,484,177,701,000,000-unit fake-USDC
# transfer as $211 quadrillion.
#
# Keyed by (chain, symbol) because the same stablecoin has different contract
# addresses on each chain — Ethereum USDC (0xa0b86991) is NOT the same contract
# as Arbitrum USDC (0xaf88d065), but both are legitimate $1.00 stablecoins.
_STABLECOIN_SYMBOLS = {"USDT", "USDC", "DAI", "BUSD", "FDUSD", "TUSD", "USDP", "USDE", "PYUSD"}

_CANONICAL_STABLECOIN_CONTRACTS: dict[tuple[Chain, str], str] = {
    # Ethereum
    (Chain.ethereum, "USDT"):  "0xdac17f958d2ee523a2206206994597c13d831ec7",
    (Chain.ethereum, "USDC"):  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    (Chain.ethereum, "DAI"):   "0x6b175474e89094c44da98b954eedeac495271d0f",
    (Chain.ethereum, "BUSD"):  "0x4fabb145d64652a948d72533023f6e7a623c7c53",
    (Chain.ethereum, "FDUSD"): "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409",
    (Chain.ethereum, "TUSD"):  "0x0000000000085d4780b73119b644ae5ecd22b376",
    (Chain.ethereum, "USDP"):  "0x8e870d67f660d95d5be530380d0ec0bd388289e1",
    (Chain.ethereum, "PYUSD"): "0x6c3ea9036406852006290770bedfcaba0e23a0e8",
    # Arbitrum (native, not bridged)
    (Chain.arbitrum, "USDC"):  "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
    (Chain.arbitrum, "USDT"):  "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
    (Chain.arbitrum, "DAI"):   "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1",
    # Arbitrum bridged USDC.e (legacy)
    (Chain.arbitrum, "USDC.E"): "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8",
    # BSC
    (Chain.bsc, "USDT"):       "0x55d398326f99059ff775485246999027b3197955",
    (Chain.bsc, "USDC"):       "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
    (Chain.bsc, "BUSD"):       "0xe9e7cea3dedca5984780bafc599bd69add087d56",
    (Chain.bsc, "DAI"):        "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3",
    # Solana (base58, not hex; lower-cased for lookup consistency)
    (Chain.solana, "USDC"):    "epjfwdd5aufqssqem2qn1xzybapc8g4weggkzwytdt1v",
    (Chain.solana, "USDT"):    "es9vmfrzacermjfrf4h2fyd4kconky11mcce8benwnyb",
    # Base
    (Chain.base, "USDC"):      "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    # Polygon
    (Chain.polygon, "USDC"):   "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
    (Chain.polygon, "USDT"):   "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
    (Chain.polygon, "DAI"):    "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063",
}

# Hard sanity ceiling on per-transfer USD. Any single transfer claiming more than
# this is treated as a pricing error and excluded from totals. The largest known
# legitimate single tx in DeFi history is ~$1B (institutional treasury moves);
# $100M ceiling catches obvious bugs without false-positiving real activity.
_PER_TRANSFER_USD_SANITY_CEILING = Decimal("100_000_000")

# --- Static contract → CoinGecko ID map for the most common ERC-20s ---
# Chain-scoped. Address → coingecko_id, lowercased addresses for lookup convenience.
# On Ethereum. For other chains, add entries as we encounter them.
_CONTRACT_TO_CG: dict[tuple[Chain, str], str] = {
    (Chain.ethereum, "0xdac17f958d2ee523a2206206994597c13d831ec7"): "tether",
    (Chain.ethereum, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"): "usd-coin",
    (Chain.ethereum, "0x6b175474e89094c44da98b954eedeac495271d0f"): "dai",
    (Chain.ethereum, "0x4fabb145d64652a948d72533023f6e7a623c7c53"): "binance-usd",
    (Chain.ethereum, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"): "weth",
    (Chain.ethereum, "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"): "wrapped-bitcoin",
    (Chain.ethereum, "0x514910771af9ca656af840dff83e8264ecf986ca"): "chainlink",
    (Chain.ethereum, "0x6982508145454ce325ddbe47a25d4ec3d2311933"): "pepe",
    (Chain.ethereum, "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce"): "shiba-inu",
    (Chain.ethereum, "0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0"): "matic-network",
    (Chain.ethereum, "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"): "uniswap",
    (Chain.ethereum, "0x6810e776880c02933d47db1b9fc05908e5386b96"): "gnosis",
    (Chain.ethereum, "0xae7ab96520de3a18e5e111b5eaab095312d7fe84"): "staked-ether",
    (Chain.ethereum, "0xae78736cd615f374d3085123a210448e74fc6393"): "rocket-pool-eth",
    (Chain.ethereum, "0x853d955acef822db058eb8505911ed77f175b99e"): "frax",
    (Chain.ethereum, "0x57e114b691db790c35207b2e685d4a43181e6061"): "ondo-finance",
    # Arbitrum — WETH and a few common ones worth avoiding an API call for
    (Chain.arbitrum, "0x82af49447d8a07e3bd95bd0d56f35241523fbab1"): "weth",
    (Chain.arbitrum, "0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f"): "wrapped-bitcoin",
    # BSC WBNB
    (Chain.bsc, "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"): "wbnb",
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

    def __init__(self, config: RecuperoConfig, env: RecuperoEnv, cache_dir: Path) -> None:
        self.cfg = config
        self.api_key = env.COINGECKO_API_KEY
        self.cache = PriceCache(cache_dir)
        self.limiter = _RateLimiter(config.pricing.requests_per_second)
        self._is_pro = (env.COINGECKO_TIER or "demo").lower() == "pro"
        self._client = httpx.Client(timeout=30.0)
        # Cache key is (chain, contract_lower) so Ethereum USDC and Arbitrum USDC
        # don't collide. Seeded from the static map.
        self._contract_id_cache: dict[tuple[Chain, str], str | None] = dict(_CONTRACT_TO_CG)

    def close(self) -> None:
        self._client.close()

    # ---------- Public API ----------

    def price_at(self, token: TokenRef, when: datetime) -> PriceResult:
        """Returns USD price PER UNIT of `token` at `when` (daily granularity).

        IMPORTANT: this is the per-token price, not the value of any specific
        transfer. To compute the USD value of a transfer, multiply this by
        the transfer's amount_decimal.
        """
        # Stablecoin shortcut — but ONLY for the genuine canonical contract on
        # the SAME CHAIN. Spoofed tokens with the same symbol at attacker-
        # controlled contracts must NOT be priced at par.
        #
        # Key insight: Arbitrum USDC and Ethereum USDC are DIFFERENT contracts
        # but both are legitimate $1.00 stablecoins. The (chain, symbol) key
        # handles this correctly.
        symbol_upper = token.symbol.upper()
        if symbol_upper in _STABLECOIN_SYMBOLS:
            canonical = _CANONICAL_STABLECOIN_CONTRACTS.get((token.chain, symbol_upper))
            token_contract_lower = (token.contract or "").lower()
            if canonical and token_contract_lower == canonical:
                return PriceResult(
                    usd_value=Decimal("1.00"),
                    source="stablecoin_par",
                    error=None,
                )
            # Symbol matches a stablecoin but contract does NOT match canonical
            # for this chain. Either a spoof OR a legit stablecoin on a chain we
            # haven't added to the canonical map yet. Refuse to price at par to
            # be safe, but let the regular resolution path try the CoinGecko
            # contract lookup below.
            log.debug(
                "stablecoin symbol %s on %s at %s does not match canonical — falling through",
                symbol_upper, token.chain.value, token_contract_lower or "no_contract",
            )

        # Resolve to coingecko_id (via token's hint, static map, or API)
        cg_id = token.coingecko_id or self._resolve_cg_id(token)
        if not cg_id:
            # Before giving up, if this was a stablecoin-symbol token we couldn't
            # resolve, surface the spoof-suspicion clearly rather than a generic
            # "no mapping" error.
            if symbol_upper in _STABLECOIN_SYMBOLS:
                return PriceResult(
                    usd_value=None,
                    source=None,
                    error=f"spoofed_canonical_symbol:{symbol_upper}_at_{(token.contract or '').lower() or 'no_contract'}_on_{token.chain.value}",
                )
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
        cache_key = (token.chain, addr_lower)
        if cache_key in self._contract_id_cache:
            return self._contract_id_cache[cache_key]
        try:
            cg_id = self._fetch_contract_to_id(token.chain, addr_lower)
        except Exception as e:  # noqa: BLE001
            log.debug(
                "coingecko contract->id resolution failed for %s on %s: %s",
                addr_lower, token.chain.value, e,
            )
            cg_id = None
        self._contract_id_cache[cache_key] = cg_id
        return cg_id

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    def _fetch_contract_to_id(self, chain: Chain, contract_lower: str) -> str | None:
        platform = _CHAIN_TO_CG_PLATFORM.get(chain)
        if platform is None:
            log.debug("no coingecko platform mapping for chain %s", chain.value)
            return None
        url = f"{self._base_url()}/coins/{platform}/contract/{contract_lower}"
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

    def price_now(self, token: TokenRef) -> PriceResult:
        """Returns current USD price for a TokenRef. Uses /simple/price endpoint
        (much cheaper than /coins/{id}/history). For dormant-wallet detection
        we want today's price, not the historical price at the incident.

        Stablecoins still get the $1.00 par treatment.
        """
        symbol_upper = token.symbol.upper()
        if symbol_upper in _STABLECOIN_SYMBOLS:
            canonical = _CANONICAL_STABLECOIN_CONTRACTS.get((token.chain, symbol_upper))
            token_contract_lower = (token.contract or "").lower()
            if canonical and token_contract_lower == canonical:
                return PriceResult(
                    usd_value=Decimal("1.00"), source="stablecoin_par", error=None,
                )

        cg_id = token.coingecko_id or self._resolve_cg_id(token)
        if not cg_id:
            return PriceResult(
                usd_value=None, source=None, error="no_coingecko_mapping",
            )

        # Cache key includes today's date so we re-fetch at most once per day
        from datetime import date as _date
        today_iso = _date.today().isoformat()
        cache_key = f"coingecko:simple:{cg_id}:{today_iso}"
        cached = self.cache.get(cache_key)
        if cached is not None and "usd" in cached:
            usd = cached["usd"]
            return PriceResult(
                usd_value=Decimal(str(usd)) if usd is not None else None,
                source=cache_key, error=None if usd is not None else cached.get("error"),
            )

        try:
            usd = self._fetch_simple_price(cg_id)
        except Exception as e:  # noqa: BLE001
            log.debug("coingecko price_now failed for %s: %s", cg_id, e)
            self.cache.put(cache_key, {"usd": None, "error": f"fetch_error: {e}"})
            return PriceResult(usd_value=None, source=None, error=f"fetch_error: {e}")

        self.cache.put(cache_key, {"usd": str(usd) if usd is not None else None})
        return PriceResult(
            usd_value=Decimal(str(usd)) if usd is not None else None,
            source=cache_key, error=None if usd is not None else "no_price_data",
        )

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    def _fetch_simple_price(self, cg_id: str) -> Decimal | None:
        url = f"{self._base_url()}/simple/price"
        params = {"ids": cg_id, "vs_currencies": "usd", **self._auth_params()}
        self.limiter.wait()
        resp = self._client.get(url, headers=self._headers(), params=params)
        if resp.status_code == 429:
            time.sleep(15)
            raise httpx.TransportError("rate limited")
        resp.raise_for_status()
        data = resp.json()
        try:
            return Decimal(str(data[cg_id]["usd"]))
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
