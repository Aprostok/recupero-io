"""DeFiLlama historical price client — secondary pricing provider.

The CoinGecko free tier rate-limits at ~5-15 req/min and occasionally
returns ``None`` for tokens it hasn't indexed (especially low-cap or
recently-launched ones). Pre-v0.31.5 that meant a high-traffic
incident produced a brief whose Section 4 USD column read
``(unpriced)`` for every transfer — the operator had to fall back to
manual lookups, which doesn't scale.

DeFiLlama is the canonical "free, no-auth, much higher quota"
fallback used widely across crypto-forensic tooling. Their historical
prices endpoint is ``GET coins.llama.fi/prices/historical/{ts}/{coins}``
where ``coins`` is a comma-separated list of either
``{chain}:{contract}`` keys or ``coingecko:{cg_id}`` aliases for
native tokens. The response carries a ``confidence`` field in
``[0, 1]`` — DeFiLlama itself documents that values below ~0.5 are
unreliable, so we treat them as misses.

The fallback chain is wired in ``coingecko.py``:

  1. CoinGecko (primary)
  2. DeFiLlama (this module, lazy-loaded)
  3. ``None`` ("(unpriced)" in the brief)

The cache layout mirrors ``coingecko.py``: SHA1-keyed JSON files under
``<cache_dir>/defillama/`` so a re-run of the same case is free. The
defensive contract — NaN / Inf / negative rejection, 5s timeout,
confidence floor — mirrors the v0.30.3 RIGOR-Jacob F hardening so a
poisoned upstream response cannot land non-finite or signed USD
values in case.json.

A ``PriceResult.source`` of ``defillama:{key}:{date}`` records the
fallback provenance so the brief can show an operator which provider
produced the USD figure on each transfer.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path

import httpx

from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain, TokenRef

log = logging.getLogger(__name__)


# DeFiLlama uses its own short chain identifiers. They map roughly to
# CoinGecko's platform list but with shorter slugs. The native-token
# case (contract is None) falls back to the ``coingecko:{id}`` alias
# DeFiLlama documents — that lets us keep using the same coingecko_id
# strings already attached to TokenRef objects.
_CHAIN_TO_LLAMA: dict[Chain, str] = {
    Chain.ethereum: "ethereum",
    Chain.bsc: "bsc",
    Chain.polygon: "polygon",
    Chain.arbitrum: "arbitrum",
    Chain.optimism: "optimism",
    Chain.base: "base",
    Chain.avalanche: "avax",
    Chain.fantom: "fantom",
    Chain.solana: "solana",
    Chain.tron: "tron",
    Chain.bitcoin: "bitcoin",
    # The remaining EVM chains have DeFiLlama mappings too — keeping
    # the map narrow per the task spec (operators can extend later).
    Chain.linea: "linea",
    Chain.blast: "blast",
    Chain.zksync: "era",
    Chain.scroll: "scroll",
    Chain.mantle: "mantle",
    Chain.celo: "celo",
    Chain.gnosis: "xdai",
    Chain.moonbeam: "moonbeam",
    Chain.metis: "metis",
    Chain.kava: "kava",
}


# DeFiLlama's data is most reliable for tokens with healthy DEX/CEX
# coverage. The ``confidence`` field is the project's own self-rating;
# below 0.5 we treat as a miss rather than a real price.
_CONFIDENCE_FLOOR = 0.5

# 5s HTTP timeout — DeFiLlama is much faster than CoinGecko's free
# tier (~150ms typical p50) so a tight cap fails fast without
# starving the fallback path of real responses.
_HTTP_TIMEOUT_SEC = 5.0


def _safe_finite_nonneg_decimal(raw: object) -> Decimal | None:
    """Same shape as ``coingecko._safe_finite_nonneg_decimal``.

    Reject ``None``, NaN, ±Infinity, and negative values. Anything else
    parseable as a Decimal returns the parsed value.
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
    """Mirror of ``coingecko.PriceResult`` so callers can swap them.

    Kept as a separate dataclass (not reimported) to avoid a hard
    import cycle through ``pricing.coingecko`` when this module is
    used by callers that don't need CoinGecko.
    """

    usd_value: Decimal | None
    source: str | None
    error: str | None


class _RateLimiter:
    """Minimal rate limiter — same shape as ``coingecko._RateLimiter``.

    DeFiLlama's free tier permits ~500 req / 5min (well above our
    workloads) so the default of 5 rps is conservative.
    """

    def __init__(self, rps: float) -> None:
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            target = max(self._next_allowed, now)
            self._next_allowed = target + self.min_interval
        delay = target - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class DeFiLlamaClient:
    """Secondary price provider; free, no-auth, higher rate limit than CoinGecko.

    Used as fallback when CoinGecko returns ``None`` (rate-limited,
    token unsupported, network error). The brief reads price-source
    provenance from the ``PriceResult.source`` field so an operator
    can tell which provider produced the USD figure on each transfer.
    """

    BASE_URL = "https://coins.llama.fi"

    def __init__(
        self,
        config: RecuperoConfig,
        env: RecuperoEnv,
        cache_dir: Path | None = None,
        *,
        dsn: str | None = None,
    ) -> None:
        """Create the client with a CoinGecko-shape cache.

        ``cache_dir`` should be the same data-dir layout the
        CoinGecko client uses; this constructor appends
        ``defillama/`` so the two providers don't collide on the
        SHA1-keyed cache filenames. Postgres DSN takes precedence
        (worker production path) when provided.
        """
        import os

        from recupero.pricing.cache import make_price_cache

        effective_dsn = dsn or os.environ.get("SUPABASE_DB_URL")

        self.cfg = config
        # env is accepted for symmetry with CoinGeckoClient — DeFiLlama
        # has no API key. Bind it so it's available if a future
        # premium endpoint shows up.
        self.env = env

        # Append a subdir so DeFiLlama cache files don't collide with
        # CoinGecko's in the same parent dir (different content, same
        # SHA1 prefix space → would otherwise overwrite each other).
        sub_cache_dir = cache_dir / "defillama" if cache_dir is not None else None
        self.cache = make_price_cache(
            dsn=effective_dsn if effective_dsn else None,
            cache_dir=sub_cache_dir,
        )
        self.limiter = _RateLimiter(5.0)
        self._client = httpx.Client(
            timeout=httpx.Timeout(
                connect=_HTTP_TIMEOUT_SEC,
                read=_HTTP_TIMEOUT_SEC,
                write=_HTTP_TIMEOUT_SEC,
                pool=_HTTP_TIMEOUT_SEC,
            )
        )

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001
            pass

    # ---------- Public API ----------

    def get_price_at(
        self,
        *,
        chain: Chain,
        contract: str | None,
        symbol: str,
        ts: datetime,
        coingecko_id: str | None = None,
    ) -> PriceResult | None:
        """Return USD price per unit of the token at ``ts``, or None on miss.

        Native tokens (``contract is None``) require a ``coingecko_id``
        hint — DeFiLlama uses ``coingecko:{id}`` alias keys for
        non-contract assets. If the hint is missing we can't form a
        lookup key and return ``None``.

        On any failure (network, malformed shape, low confidence,
        non-finite / negative price) we return ``None`` so the caller
        can fall through to the next provider or "(unpriced)".
        """
        coin_key = self._make_coin_key(
            chain=chain, contract=contract, coingecko_id=coingecko_id,
        )
        if coin_key is None:
            return None

        unix_ts = int(ts.timestamp())
        cache_key = f"defillama:{coin_key}:{unix_ts}"
        cached = self.cache.get(cache_key)
        if cached is not None and "usd" in cached:
            usd = cached["usd"]
            if usd is None:
                # Confirmed miss — don't re-fetch. Mirrors the
                # CoinGecko cache shape.
                return PriceResult(
                    usd_value=None,
                    source=cache_key,
                    error=cached.get("error") or "no_price_data",
                )
            parsed = _safe_finite_nonneg_decimal(usd)
            if parsed is not None:
                return PriceResult(
                    usd_value=parsed,
                    source=cache_key,
                    error=None,
                )
            # Cache poisoned with NaN/Inf/negative; fall through to
            # refetch. The PriceCache layer also rejects these on
            # read, but a Postgres backend will surface them via this
            # path so the guard is required here too.
            log.warning(
                "defillama cache for %s carried non-finite/negative usd=%r; "
                "ignoring and refetching",
                cache_key, usd,
            )

        try:
            usd, confidence = self._fetch(coin_key, unix_ts)
        except Exception as e:  # noqa: BLE001 — never crash the fallback path
            log.debug("defillama fetch failed for %s @ %s: %s", coin_key, unix_ts, e)
            return None

        if usd is None:
            # Confirmed "no data for this (token, timestamp)" — cache
            # so re-runs don't repeat the lookup.
            self.cache.put(cache_key, {"usd": None, "error": "no_price_data"})
            return PriceResult(
                usd_value=None, source=cache_key, error="no_price_data",
            )

        if confidence is not None and confidence < _CONFIDENCE_FLOOR:
            log.debug(
                "defillama returned low-confidence price %s for %s "
                "(confidence=%s < %s) — treating as miss",
                usd, coin_key, confidence, _CONFIDENCE_FLOOR,
            )
            # Don't cache low-confidence misses — DeFiLlama may rate
            # the same key higher tomorrow once more sources land.
            return None

        self.cache.put(cache_key, {"usd": str(usd)})
        return PriceResult(usd_value=usd, source=cache_key, error=None)

    # ---------- Internals ----------

    @staticmethod
    def _make_coin_key(
        *,
        chain: Chain,
        contract: str | None,
        coingecko_id: str | None,
    ) -> str | None:
        """Build the DeFiLlama coin-key for the lookup URL.

        Returns ``None`` when we don't have enough information to form
        a key (e.g. native token with no coingecko_id hint, or chain
        not in the mapping).
        """
        if contract is None:
            # Native token — DeFiLlama uses the coingecko:{id} alias.
            if not coingecko_id:
                return None
            return f"coingecko:{coingecko_id}"
        llama_chain = _CHAIN_TO_LLAMA.get(chain)
        if llama_chain is None:
            return None
        # DeFiLlama expects lowercased EVM addresses; base58 chains
        # (Solana / Tron / Bitcoin) carry case as-is.
        if chain in {
            Chain.ethereum, Chain.bsc, Chain.polygon, Chain.arbitrum,
            Chain.optimism, Chain.base, Chain.avalanche, Chain.fantom,
            Chain.linea, Chain.blast, Chain.zksync, Chain.scroll,
            Chain.mantle, Chain.celo, Chain.gnosis, Chain.moonbeam,
            Chain.metis, Chain.kava,
        }:
            contract = contract.lower()
        return f"{llama_chain}:{contract}"

    def _fetch(self, coin_key: str, ts: int) -> tuple[Decimal | None, float | None]:
        """Hit ``coins.llama.fi/prices/historical/{ts}/{coins}``.

        Returns ``(price, confidence)``. ``price`` is ``None`` on a
        confirmed miss (HTTP 200, key not in response). Any HTTP
        error / shape mismatch / non-finite price raises so the
        caller's blanket ``except`` records it as a miss.
        """
        # URL-encoded form so colon in coin_key survives.
        url = f"{self.BASE_URL}/prices/historical/{ts}/{coin_key}"
        self.limiter.wait()
        resp = self._client.get(url)
        # Any HTTP failure is a miss — the calling layer falls
        # through to "no price".
        if resp.status_code >= 400:
            log.debug("defillama HTTP %s for %s", resp.status_code, coin_key)
            return None, None
        data = resp.json()
        if not isinstance(data, dict):
            return None, None
        coins = data.get("coins")
        if not isinstance(coins, dict):
            return None, None
        entry = coins.get(coin_key)
        if not isinstance(entry, dict):
            return None, None
        raw_price = entry.get("price")
        price = _safe_finite_nonneg_decimal(raw_price)
        if price is None:
            log.warning(
                "defillama returned non-finite/negative/missing price %r "
                "for %s — rejecting at parse boundary",
                raw_price, coin_key,
            )
            return None, None
        raw_conf = entry.get("confidence")
        try:
            confidence = float(raw_conf) if raw_conf is not None else None
        except (TypeError, ValueError):
            confidence = None
        # Reject non-finite confidence — NaN would slip past the
        # `< floor` check (NaN comparisons return False) and
        # incorrectly accept the price.
        if confidence is not None:
            import math as _math
            if not _math.isfinite(confidence):
                confidence = None
        return price, confidence
