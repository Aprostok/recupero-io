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
    # Tron — CoinGecko platform id is "tron"; required for contract→id
    # resolution on TRC-20 tokens (added in v0.16.7).
    Chain.tron: "tron",
    # v0.20.0 (round-13 chain-coverage research): platform mappings
    # for the 7 EVM chains added via Etherscan V2 multichain. Without
    # these entries, contract→USD lookups silently fail for tokens
    # on these chains; the trace produces unpriced transfers and the
    # USD-value-at-tx column reads "(unknown)" in the brief.
    Chain.optimism:  "optimistic-ethereum",
    Chain.avalanche: "avalanche",
    Chain.linea:     "linea",
    Chain.blast:     "blast",
    Chain.zksync:    "zksync",
    Chain.scroll:    "scroll",
    Chain.mantle:    "mantle",
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
    # Solana (base58 — case-sensitive on-chain).
    # v0.17.5 (round-10 forensic HIGH): canonical mixed-case stored
    # exactly as the mint publishes. The matching helper compares
    # exact-equal for base58 chains so a vanity-mined spoof whose
    # lowercase form collides with USDC's can no longer be priced
    # at par. EVM remains lowercase-compared (EIP-55 checksum is a
    # UI convention, not a uniqueness factor).
    (Chain.solana, "USDC"):    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    (Chain.solana, "USDT"):    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
    # Tron — CRITICAL: USDT-TRC20 is the largest stablecoin deployment in
    # crypto (~$60B circulating, the single biggest USDT chain). Pre-v0.16.7
    # the absence of this entry meant a legit USDT-TRC20 transfer fell
    # through to the API contract-lookup path and, if CoinGecko was momentarily
    # unreachable, ended up flagged as `spoofed_canonical_symbol`.
    # v0.17.5: stored in canonical on-chain case for the same
    # base58-spoof-protection reason as Solana above.
    (Chain.tron, "USDT"):      "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
    (Chain.tron, "USDC"):      "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8",
    # v0.18.0 (round-11 pricing-CRIT-002): canonical Tron USDD address
    # per tronscan + issuers.json is "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR"
    # (uppercase R, lowercase p in positions 9-10). Pre-v0.18.0 we had
    # `TNUC9Qb1rrPS5CbWLmNMxXBjyFoydXjWFR` (lowercase rr, uppercase P) —
    # a different on-chain address. Tron base58check is case-sensitive,
    # so the comparison would always miss → real USDD transfers fell
    # through to `spoofed_canonical_symbol`.
    (Chain.tron, "USDD"):      "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR",
    # Base
    (Chain.base, "USDC"):      "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    # Polygon
    (Chain.polygon, "USDC"):   "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
    (Chain.polygon, "USDT"):   "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
    (Chain.polygon, "DAI"):    "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063",
    # v0.20.0 (round-13 chain-coverage research): canonical stablecoin
    # contracts on the 7 EVM chains added in v0.20.0. Pre-v0.20.0 a
    # legit USDC transfer on (e.g.) Optimism fell through to the
    # `spoofed_canonical_symbol` branch because the (chain, symbol)
    # tuple had no canonical entry. The brief then refused to price
    # the transfer at par and rendered `(unknown)` for the USD value.
    # Sources: chain-native USDC docs (Circle) + USDT bridge contracts
    # (Tether's official deployments page).
    # --- Optimism ---
    (Chain.optimism, "USDC"):   "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
    (Chain.optimism, "USDT"):   "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58",
    (Chain.optimism, "DAI"):    "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1",
    (Chain.optimism, "USDC.E"): "0x7f5c764cbc14f9669b88837ca1490cca17c31607",
    # --- Avalanche C-Chain ---
    (Chain.avalanche, "USDC"):  "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e",
    (Chain.avalanche, "USDT"):  "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7",
    (Chain.avalanche, "DAI"):   "0xd586e7f844cea2f87f50152665bcbc2c279d8d70",
    # --- Linea ---
    (Chain.linea, "USDC"):      "0x176211869ca2b568f2a7d4ee941e073a821ee1ff",
    (Chain.linea, "USDT"):      "0xa219439258ca9da29e9cc4ce5596924745e12b93",
    # --- Blast ---
    # Blast's canonical USDC is a "USDB" wrapper (yield-bearing); listed
    # as USDB symbol per Blast docs. Real USDC is bridged via WBTC-style
    # cross-chain wrappers — pricing falls through to the API path.
    (Chain.blast, "USDB"):      "0x4300000000000000000000000000000000000003",
    # --- zkSync Era ---
    (Chain.zksync, "USDC"):     "0x1d17cbcf0d6d143135ae902365d2e5e2a16538d4",
    (Chain.zksync, "USDC.E"):   "0x3355df6d4c9c3035724fd0e3914de96a5a83aaf4",
    (Chain.zksync, "USDT"):     "0x493257fd37edb34451f62edf8d2a0c418852ba4c",
    # --- Scroll ---
    (Chain.scroll, "USDC"):     "0x06efdbff2a14a7c8e15944d1f4a48f9f95f663a4",
    (Chain.scroll, "USDT"):     "0xf55bec9cafdbe8730f096aa55dad6d22d44099df",
    # --- Mantle ---
    # Mantle's bridged USDC + USDT (Multichain-era wrappers).
    (Chain.mantle, "USDC"):     "0x09bc4e0d864854c6afb6eb9a9cdf58ac190d0df9",
    (Chain.mantle, "USDT"):     "0x201eba5cc46d216ce6dc03f6a759e8e766e956ae",
}

# v0.17.5 (round-10 forensic HIGH): case-aware comparison so base58
# stablecoin spoofs don't match the canonical contract. EVM contracts
# are case-insensitive (the EIP-55 checksum is just a UI convention) so
# lowercase comparison is correct. Solana / Tron / Bitcoin base58 IS
# case-sensitive, so we compare exactly — except the canonical map
# stores them lowercase for lookup-key consistency, so the input is
# also lowercased for chains where the on-chain alphabet is fixed
# lowercase or case-insensitive.
_CASE_INSENSITIVE_CHAINS = frozenset({
    Chain.ethereum, Chain.arbitrum, Chain.bsc, Chain.polygon, Chain.base,
    # v0.20.0 (round-13 chain-coverage research): the 7 EVM chains
    # added via Etherscan V2 multichain. EIP-55 checksum is a UI
    # convention; lowercase comparison is correct for all EVM chains.
    Chain.optimism, Chain.avalanche, Chain.linea, Chain.blast,
    Chain.zksync, Chain.scroll, Chain.mantle,
    # Bitcoin uses bech32 (all-lowercase per BIP173) — case-insensitive.
    Chain.bitcoin,
})


def _contract_matches_canonical(
    chain: Chain,
    token_contract: str,
    canonical_contract: str,
) -> bool:
    """Case-aware match for stablecoin canonical-contract checks.

    EVM + bech32 → lowercase compare. Base58 (Solana / Tron) → exact.
    The canonical map's base58 entries are stored lowercase but for
    fixed-case-format chains that's not actually meaningful, so we
    fall back to exact-match against the stored form (a future cleanup
    would store base58 in canonical case, but the current map is
    consistent so this still rejects spoofs whose case differs).
    """
    if not token_contract:
        return False
    if chain in _CASE_INSENSITIVE_CHAINS:
        return token_contract.lower() == canonical_contract.lower()
    # Base58 (Solana, Tron) — case-sensitive on-chain. The canonical
    # map currently stores them lowercased; an attacker would need to
    # vanity-mine an address whose lowercased form matches USDT's,
    # which is computationally hard but not impossible. Compare the
    # input as-is to the stored form so a spoof with non-lowercase
    # characters won't pass.
    return token_contract == canonical_contract


# Hard sanity ceiling on per-transfer USD. Any single transfer claiming more
# than this is treated as a pricing error and excluded from totals.
#
# v0.16.7 (round-9 forensic audit HIGH): raised from $100M to $2B. The prior
# ceiling rejected legitimate institutional/treasury moves and — more
# critically — the largest theft events (Ronin Bridge ~$625M, Poly Network
# ~$611M, BNB Bridge ~$570M). The headline-impact cases were precisely the
# ones whose USD would be silently nulled. The accompanying code comment
# already stated the largest legit single tx is "~$1B", so $100M never made
# sense as a ceiling. $2B leaves headroom while still rejecting obvious
# bugs (a 6-decimal-token amount misread as 18-decimal would land in the
# 10^12-X range, well above any ceiling).
_PER_TRANSFER_USD_SANITY_CEILING = Decimal("2_000_000_000")

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
    # MATIC token on Ethereum mainnet — historical Polygon staking token.
    # The 2024-09-04 redenomination migrated this to POL; CoinGecko keyed
    # historical prices under "matic-network" but current price lives at
    # "polygon-ecosystem-token". Keep BOTH mapping rows so historical
    # incidents resolve correctly:
    (Chain.ethereum, "0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0"): "matic-network",
    (Chain.ethereum, "0x455e53cbb86018ac2b8092fdcd39d8444affc3f6"): "polygon-ecosystem-token",
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


def _safe_finite_nonneg_decimal(raw: object) -> Decimal | None:
    """Parse an arbitrary upstream value (cache JSON, CoinGecko payload)
    into a finite non-negative ``Decimal``, or ``None`` if it fails.

    RIGOR-Jacob F: CoinGecko's API and the price cache are the source of
    every USD value in case.json. A poisoned payload (``"NaN"`` /
    ``"Infinity"`` / a negative number from a spoofed proxy) must NOT
    propagate into transfer-USD math — non-finite Decimals bypass every
    ``> ceiling`` check (NaN comparisons return False), and negative
    prices render in freeze letters as ``"-$1,500.00 lost"``.
    """
    if raw is None:
        return None
    try:
        value = Decimal(str(raw))
    except (ArithmeticError, ValueError, TypeError):
        return None
    if not value.is_finite():
        return None
    if value < 0:
        return None
    return value


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
        # Reserve a slot under the lock, then sleep WITHOUT holding the lock.
        # The previous implementation called time.sleep() inside `with self._lock:`,
        # which serialized every worker thread on the same CoinGecko client
        # instance: with N threads sharing one limiter at 0.5 rps, a flood of
        # 10 lookups would block for 20s wall-clock even though the *intent*
        # was a 2-second pacing window. Holding the lock only long enough to
        # advance `_next_allowed` lets threads queue their reservations in
        # parallel and each one sleeps on its own.
        with self._lock:
            now = time.monotonic()
            target = max(self._next_allowed, now)
            self._next_allowed = target + self.min_interval
        delay = target - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class CoinGeckoClient:
    """Computes historical USD price for a TokenRef at a given timestamp."""

    BASE_URL_PRO = "https://pro-api.coingecko.com/api/v3"
    BASE_URL_PUBLIC = "https://api.coingecko.com/api/v3"

    def __init__(
        self,
        config: RecuperoConfig,
        env: RecuperoEnv,
        cache_dir: Path | None = None,
        *,
        dsn: str | None = None,
        # v0.32 — optional per-case API budget tracker. See
        # ``observability/api_budget.py`` for the contract.
        budget: object | None = None,
    ) -> None:
        """Create the client with either a Postgres or file-system cache.

        Precedence:
          1. explicit ``dsn`` argument
          2. ``SUPABASE_DB_URL`` env var (worker production path)
          3. ``cache_dir`` (CLI / tests / no-DB scenarios)

        Postgres cache survives across investigations and is shared across
        worker replicas — important for Phase 2 nightly monitoring where
        the same cases get re-traced daily. File cache survives only
        within a single investigation's tempdir.

        Setting the env var unblocks the persistent cache without any
        call-site changes; tests that explicitly want the file cache
        should clear ``SUPABASE_DB_URL`` from their environment.
        """
        import os

        from recupero.pricing.cache import make_price_cache

        effective_dsn = dsn or os.environ.get("SUPABASE_DB_URL")

        self.cfg = config
        self.api_key = env.COINGECKO_API_KEY
        # v0.32 per-case API budget. Propagated to the lazy-loaded
        # DeFiLlama fallback so both providers share the cap.
        self.budget = budget
        self.cache = make_price_cache(
            dsn=effective_dsn if effective_dsn else None,
            cache_dir=cache_dir,
        )
        self.limiter = _RateLimiter(config.pricing.requests_per_second)
        self._is_pro = (env.COINGECKO_TIER or "demo").lower() == "pro"
        # Split connect vs read timeout: api.coingecko.com is rate-limited
        # and occasionally slow-loris during burst. A 10s connect cap fails
        # fast on hung-handshake so the next caller can proceed instead of
        # waiting 30s for the full read window to drain.
        self._client = httpx.Client(
            timeout=httpx.Timeout(
                connect=10.0,
                read=30.0,
                write=30.0,
                pool=30.0,
            )
        )
        # Cache key is (chain, contract_lower) so Ethereum USDC and Arbitrum USDC
        # don't collide. Seeded from the static map.
        self._contract_id_cache: dict[tuple[Chain, str], str | None] = dict(_CONTRACT_TO_CG)

        # v0.31.5 — secondary provider chain. Lazy-loaded so the
        # CoinGecko-only cache path (set `RECUPERO_PRICING_FALLBACK=none`)
        # doesn't pay the DeFiLlama client's httpx-client + tempdir
        # creation cost. Bind the cache_dir for the lazy ctor.
        self._fallback_cache_dir = cache_dir
        self._fallback_dsn = dsn
        self._defillama_client: object | None = None
        raw_fb = os.environ.get("RECUPERO_PRICING_FALLBACK", "defillama")
        # Accept None/empty as the default; any value other than
        # `none` (case-insensitive) leaves the fallback on. The
        # forward-compat shape lets us add e.g. `coinpaprika` later
        # without a flag-day change to the parser.
        self._fallback_enabled = (raw_fb or "defillama").strip().lower() != "none"

    def close(self) -> None:
        self._client.close()
        if self._defillama_client is not None:
            try:
                self._defillama_client.close()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass

    def _try_fallback(self, token: TokenRef, when: datetime) -> PriceResult | None:
        """Lazy-init the DeFiLlama client and attempt a fallback lookup.

        Returns a ``PriceResult`` with ``usd_value`` set on success;
        ``None`` on miss / disabled / non-fatal error so the caller
        can fall through to the documented "no price" branch.

        Stablecoin par + spoof-suspicion is handled by the caller
        before this point — by the time we're here, CoinGecko has
        already told us "no data" or "rate limited".
        """
        # Use getattr with safe defaults so test scaffolding that
        # constructs the client via __new__() (bypassing __init__) —
        # see test_coingecko_adversarial_prices._build_client — still
        # exercises the existing CoinGecko-only path. A missing
        # _fallback_enabled flag is treated as "disabled" so the
        # legacy assertion behavior is preserved.
        if not getattr(self, "_fallback_enabled", False):
            return None
        client = self._get_defillama_client()
        if client is None:
            return None
        try:
            result = client.get_price_at(
                chain=token.chain,
                contract=token.contract,
                symbol=token.symbol,
                ts=when,
                coingecko_id=token.coingecko_id,
            )
        except Exception as e:  # noqa: BLE001 — fallback must never crash trace
            log.debug("defillama fallback raised for %s: %s", token.symbol, e)
            return None
        if result is None or result.usd_value is None:
            return None
        # Translate DeFiLlama's PriceResult into the CoinGecko-side
        # PriceResult so callers don't need to special-case provenance.
        return PriceResult(
            usd_value=result.usd_value,
            source=result.source,
            error=None,
        )

    def _get_defillama_client(self) -> object | None:
        """Lazy import + construct so the CoinGecko-only path stays light."""
        if self._defillama_client is not None:
            return self._defillama_client
        try:
            from recupero.pricing.defillama import DeFiLlamaClient
        except ImportError as e:
            log.debug("defillama fallback module unavailable: %s", e)
            return None
        try:
            self._defillama_client = DeFiLlamaClient(
                config=self.cfg,
                env=RecuperoEnv(),  # picks up env-var freshness on first call
                cache_dir=self._fallback_cache_dir,
                dsn=self._fallback_dsn,
                # v0.32 — propagate the per-case API budget so the
                # fallback also counts toward the cap (defillama
                # itself is free per the cost model, but recording
                # the call count surfaces the burn rate to the
                # operator regardless).
                budget=getattr(self, "budget", None),
            )
        except Exception as e:  # noqa: BLE001 — construction must never crash trace
            log.debug("defillama fallback construction failed: %s", e)
            return None
        return self._defillama_client

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
            if canonical and _contract_matches_canonical(
                token.chain, token.contract or "", canonical,
            ):
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
                symbol_upper, token.chain.value, (token.contract or "no_contract"),
            )

        # Resolve to coingecko_id (via token's hint, static map, or API)
        cg_id = token.coingecko_id or self._resolve_cg_id(token)
        if not cg_id:
            # Before giving up, if this was a stablecoin-symbol token we couldn't
            # resolve, surface the spoof-suspicion clearly rather than a generic
            # "no mapping" error.
            if symbol_upper in _STABLECOIN_SYMBOLS:
                # v0.17.5 (round-10 forensic MED): the error string uses the
                # raw token.contract (no .lower()) so base58 chains preserve
                # case in the audit trail — an operator triaging the row needs
                # to see the actual on-chain address pattern to confirm the spoof.
                return PriceResult(
                    usd_value=None,
                    source=None,
                    error=f"spoofed_canonical_symbol:{symbol_upper}_at_{(token.contract or 'no_contract')}_on_{token.chain.value}",
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
            # RIGOR-Jacob F: re-validate the cached value at read time.
            # An attacker who corrupted the cache file with
            # ``{"usd": "NaN"}`` (or a stale entry from a pre-hardening
            # build of the fetcher) must not be able to short-circuit
            # the fetch-side guard. Treat poison as "no cached value"
            # so the fetch path runs and re-populates with a clean entry.
            parsed = _safe_finite_nonneg_decimal(usd) if usd is not None else None
            if usd is None:
                return PriceResult(
                    usd_value=None,
                    source=key,
                    error=cached.get("error"),
                )
            if parsed is not None:
                return PriceResult(
                    usd_value=parsed,
                    source=key,
                    error=None,
                )
            # Poisoned cache entry — log and fall through to refetch.
            log.warning(
                "coingecko cache for %s carried non-finite/negative usd=%r; "
                "ignoring and refetching",
                key, usd,
            )

        # Fetch
        try:
            usd = self._fetch_history(cg_id, d)
        except Exception as e:  # noqa: BLE001 — we want to keep tracing alive
            log.debug("coingecko fetch failed for %s on %s: %s", cg_id, d, e)
            # DO NOT cache transient fetch errors. The previous code wrote
            # {"usd": None, "error": "fetch_error: ..."} into the persistent
            # cache, which meant a single 5xx blip during a token's first
            # lookup permanently poisoned the cache for that (token, date)
            # pair — every subsequent run read None back and never re-fetched.
            # Cache only holds confirmed "CoinGecko returned a valid response
            # with no USD price for this date" (handled below as usd=None).
            #
            # v0.31.5 fallback: transient CoinGecko failure (rate limit,
            # network) is the most common reason the brief's USD column
            # goes dark. Try DeFiLlama before giving up.
            fallback = self._try_fallback(token, when)
            if fallback is not None:
                return fallback
            return PriceResult(usd_value=None, source=None, error=f"fetch_error: {e}")

        # `usd is None` here means CoinGecko's response parsed successfully
        # but had no market_data.current_price.usd — a real "no data for this
        # date" answer (e.g. token didn't exist yet on that day). Safe to cache.
        self.cache.put(key, {"usd": str(usd) if usd is not None else None})
        if usd is not None:
            return PriceResult(
                usd_value=Decimal(str(usd)),
                source=key,
                error=None,
            )

        # CoinGecko returned a clean "no data" response. Try the
        # secondary provider (v0.31.5 fallback chain) so a single
        # rate-limit / unsupported-token hiccup doesn't render the
        # brief's Section 4 USD column as `(unpriced)`.
        fallback = self._try_fallback(token, when)
        if fallback is not None:
            return fallback
        return PriceResult(
            usd_value=None,
            source=key,
            error="no_price_data",
        )

    # ---------- Internals ----------

    def _resolve_cg_id(self, token: TokenRef) -> str | None:
        if token.contract is None:
            # Native — caller should have set coingecko_id ('ethereum' for ETH)
            return None
        # v0.18.0 (round-11 forensic-HIGH-002): chain-aware case
        # preservation. EVM contracts are case-insensitive (lowercased
        # for canonical-key consistency); Solana / Tron mints are
        # case-sensitive at the network layer AND CoinGecko expects the
        # canonical mixed-case form at /coins/{platform}/contract/{addr}.
        # Pre-v0.18.0 every base58 lookup got lowercased → 404 → cached
        # as None → every non-stablecoin SPL/TRC-20 was unpriced AND the
        # process-wide cache poisoned for that token.
        from recupero._common import canonical_address_key as _ck
        canon = _ck(token.contract)
        cache_key = (token.chain, canon)
        if cache_key in self._contract_id_cache:
            return self._contract_id_cache[cache_key]
        try:
            cg_id = self._fetch_contract_to_id(token.chain, canon)
        except Exception as e:  # noqa: BLE001
            log.debug(
                "coingecko contract->id resolution failed for %s on %s: %s",
                canon, token.chain.value, e,
            )
            # Do NOT cache a transient lookup failure as None — that would
            # mean every subsequent transfer in this process for the same
            # token gets `no_coingecko_mapping` even after CoinGecko comes
            # back. A genuine 404 still caches (handled by _fetch_contract_to_id
            # returning None without raising).
            return None
        self._contract_id_cache[cache_key] = cg_id
        return cg_id

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    def _fetch_contract_to_id(self, chain: Chain, contract_canon: str) -> str | None:
        """v0.18.0: parameter renamed from `contract_lower` to `contract_canon`
        — for EVM platforms this is the lower-cased hex (CoinGecko expects
        lowercase); for Solana / Tron it's the canonical mixed-case base58
        (CoinGecko expects the on-chain canonical form, not the lowercased
        form which doesn't decode to a valid address)."""
        platform = _CHAIN_TO_CG_PLATFORM.get(chain)
        if platform is None:
            log.debug("no coingecko platform mapping for chain %s", chain.value)
            return None
        url = f"{self._base_url()}/coins/{platform}/contract/{contract_canon}"
        self.limiter.wait()
        resp = self._client.get(url, headers=self._headers(), params=self._auth_params())
        # v0.32 per-case API budget. getattr with default None defends
        # against test scaffolding that constructs the client via
        # __new__() (bypassing __init__) — see test_coingecko_adversarial_prices.
        _b = getattr(self, "budget", None)
        if _b is not None:
            _b.record("coingecko")
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            # Raise so tenacity backs off and retries instead of silently
            # returning None — a returned None used to be cached in
            # `_contract_id_cache` and permanently marked the token
            # un-priceable for the rest of the process.
            raise httpx.TransportError("coingecko rate limited (429)")
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
        # v0.32 per-case API budget. getattr with default None defends
        # against test scaffolding that constructs the client via
        # __new__() (bypassing __init__) — see test_coingecko_adversarial_prices.
        _b = getattr(self, "budget", None)
        if _b is not None:
            _b.record("coingecko")
        if resp.status_code == 429:
            # Tenacity handles the actual backoff (exponential 2→30s); raising
            # immediately lets the next caller share the cooldown rather than
            # the original 15s hard-sleep, which blocked the worker thread
            # for far longer than the public-tier 60s/min window required.
            raise httpx.TransportError("rate limited")
        resp.raise_for_status()
        data = resp.json()
        try:
            usd = data["market_data"]["current_price"]["usd"]
            price = Decimal(str(usd))
        except (KeyError, TypeError, ArithmeticError):
            return None
        # RIGOR-Jacob F: reject non-finite (NaN, Infinity) and negative
        # prices at the parse boundary. CoinGecko's API is the source of
        # every USD value in case.json. The tracer applies a $2B per-
        # transfer sanity ceiling, but ``abs(NaN) > 2B`` is False (NaN
        # comparisons always return False), so a poisoned ``{"usd": "NaN"}``
        # response would slip past every downstream guard and land NaN
        # in the LE handoff's "Total stolen" line. Negative prices render
        # in freeze letters as "-$1,500.00 lost" — operationally
        # nonsensical. Reject and return None so the "no price data"
        # branch runs.
        if not price.is_finite() or price < 0:
            log.warning(
                "coingecko %s on %s returned non-finite/negative price %r — "
                "rejecting at parse boundary",
                cg_id, d, usd,
            )
            return None
        return price

    def price_now(self, token: TokenRef) -> PriceResult:
        """Returns current USD price for a TokenRef. Uses /simple/price endpoint
        (much cheaper than /coins/{id}/history). For dormant-wallet detection
        we want today's price, not the historical price at the incident.

        Stablecoins still get the $1.00 par treatment — case-sensitive
        canonical check (v0.17.5) so base58 spoofs don't match.
        """
        symbol_upper = token.symbol.upper()
        if symbol_upper in _STABLECOIN_SYMBOLS:
            canonical = _CANONICAL_STABLECOIN_CONTRACTS.get((token.chain, symbol_upper))
            if canonical and _contract_matches_canonical(
                token.chain, token.contract or "", canonical,
            ):
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
            # RIGOR-Jacob F: same cache-poison defense as price_at —
            # the price_now cache feeds dormant-wallet detection and a
            # poisoned entry would render ``$Infinity`` in the brief.
            parsed = _safe_finite_nonneg_decimal(usd) if usd is not None else None
            if usd is None:
                return PriceResult(
                    usd_value=None,
                    source=cache_key,
                    error=cached.get("error"),
                )
            if parsed is not None:
                return PriceResult(
                    usd_value=parsed,
                    source=cache_key,
                    error=None,
                )
            log.warning(
                "coingecko price_now cache for %s carried non-finite/negative "
                "usd=%r; ignoring and refetching",
                cache_key, usd,
            )

        try:
            usd = self._fetch_simple_price(cg_id)
        except Exception as e:  # noqa: BLE001
            log.debug("coingecko price_now failed for %s: %s", cg_id, e)
            # See the matching note in price_at(): don't cache transient
            # fetch errors. Poisoned negative-cache entries kept dormant
            # detection from ever pricing a token whose first lookup
            # happened to coincide with a CoinGecko hiccup.
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
        # v0.32 per-case API budget. getattr with default None defends
        # against test scaffolding that constructs the client via
        # __new__() (bypassing __init__) — see test_coingecko_adversarial_prices.
        _b = getattr(self, "budget", None)
        if _b is not None:
            _b.record("coingecko")
        if resp.status_code == 429:
            time.sleep(15)
            raise httpx.TransportError("rate limited")
        resp.raise_for_status()
        data = resp.json()
        try:
            raw = data[cg_id]["usd"]
        except (KeyError, TypeError):
            return None
        # RIGOR-Jacob F: reject non-finite + negative at the parse boundary,
        # same shape as _fetch_history.
        parsed = _safe_finite_nonneg_decimal(raw)
        if parsed is None:
            log.warning(
                "coingecko simple price for %s returned non-finite/negative "
                "value %r — rejecting",
                cg_id, raw,
            )
        return parsed

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
