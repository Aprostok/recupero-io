#!/usr/bin/env python3
"""Prewarm the persistent pricing cache.

Pulls today's USD prices for a curated list of common ERC-20s on every
supported chain, plus all issuer-controlled freezable tokens (USDC,
USDT, DAI, etc.) from the issuer DB. Writes each into the
``public.pricing_cache`` Postgres table so subsequent worker runs hit
the cache instead of CoinGecko.

Why this helps:

  - Phase 2 nightly cron will trigger multiple investigations at once.
    Without prewarming, each worker fights for CoinGecko's 0.5 rps demo
    tier slot to look up the same dozen stablecoin/major-asset prices.
  - First-run-of-the-day cases pay full price for every token. With a
    prewarmed cache, common tokens skip CoinGecko entirely.
  - Pricing cache hits are global — one prewarm benefits all workers
    and all investigations until the date rolls over (cache key
    includes today's ISO date).

Usage:
    python scripts/prewarm_pricing_cache.py
    python scripts/prewarm_pricing_cache.py --chain ethereum
    python scripts/prewarm_pricing_cache.py --dry-run

The script is safe to run repeatedly. Cache entries are upserted with
``ON CONFLICT DO UPDATE``; re-running just refreshes ``cached_at``.

Designed to run as a daily scheduled task (e.g., 23:50 ET before the
midnight cron) so monitoring cases start with a hot cache.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import httpx  # noqa: E402
import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

log = logging.getLogger("prewarm")

_COINGECKO_BASE_PUBLIC = "https://api.coingecko.com/api/v3"

# Top ERC-20s by trace-relevance. Stablecoins always covered (issuer DB).
# These are the tokens we see most often in real cases. Worth a CoinGecko
# call each on prewarm.
_COINGECKO_IDS = [
    # Stablecoins (also covered by issuer DB; included here so the cache
    # has them even if the issuer DB is empty)
    "tether",
    "usd-coin",
    "dai",
    "binance-usd",
    "first-digital-usd",
    "true-usd",
    "paxos-standard",
    "paypal-usd",
    "usde",
    # Liquid staking
    "staked-ether",
    "rocket-pool-eth",
    "wrapped-steth",
    "ankreth",
    # Wrapped + bridge tokens
    "weth",
    "wrapped-bitcoin",
    "tbtc",
    "renbtc",
    # Top alt-L1 + LRTs
    "ether-fi-staked-eth",
    "kelp-dao-restaked-eth",
    "puffer-finance",
    "renzo-restaked-eth",
    # Common majors
    "ethereum",
    "bitcoin",
    "matic-network",
    "binancecoin",
    "chainlink",
    "uniswap",
    "shiba-inu",
    "pepe",
    "dogecoin",
    "litecoin",
    # Top DeFi
    "aave",
    "compound-governance-token",
    "curve-dao-token",
    "frax",
    "maker",
    "ondo-finance",
    "lido-dao",
]


def _today_iso() -> str:
    from datetime import date
    return date.today().isoformat()


def _existing_cache_keys(conn: psycopg.Connection, prefix: str) -> set[str]:
    """Return keys already cached for today (so we don't refetch them)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT cache_key FROM public.pricing_cache "
            "WHERE cache_key LIKE %s",
            (prefix + "%",),
        )
        return {r[0] for r in cur.fetchall()}


def _fetch_one(
    http: httpx.Client,
    cg_id: str,
    api_key: str | None,
) -> tuple[str | None, str | None]:
    """Fetch today's USD price for a single CoinGecko id. Returns
    (price_str, error_str). Either may be None — None price + None error
    means 'CoinGecko said no data', which we still cache to prevent
    refetching."""
    params = {"ids": cg_id, "vs_currencies": "usd"}
    headers = {"x-cg-demo-api-key": api_key} if api_key else {}
    try:
        resp = http.get(
            f"{_COINGECKO_BASE_PUBLIC}/simple/price",
            params=params, headers=headers, timeout=10.0,
        )
        if resp.status_code == 429:
            return None, "rate_limited"
        resp.raise_for_status()
        data = resp.json()
        price = data.get(cg_id, {}).get("usd")
        if price is None:
            return None, "no_price_data"
        return str(price), None
    except Exception as e:  # noqa: BLE001
        return None, f"fetch_error: {type(e).__name__}"


def _upsert(
    conn: psycopg.Connection,
    cache_key: str,
    usd_price: str | None,
    error_msg: str | None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.pricing_cache (cache_key, usd_price, error_msg)
            VALUES (%s, %s::numeric, %s)
            ON CONFLICT (cache_key) DO UPDATE SET
                usd_price = EXCLUDED.usd_price,
                error_msg = EXCLUDED.error_msg,
                cached_at = NOW()
            """,
            (cache_key, usd_price, error_msg),
        )


def _collect_issuer_db_ids() -> list[str]:
    """Pull CoinGecko ids implied by the issuer DB entries.

    The issuer DB stores (chain, contract) → IssuerEntry. We map common
    symbols to CoinGecko ids — most of them are already in _COINGECKO_IDS,
    but cover edge cases via the symbol→id map for safety.
    """
    SYMBOL_TO_CG = {
        "USDT": "tether",
        "USDC": "usd-coin",
        "DAI": "dai",
        "BUSD": "binance-usd",
        "PYUSD": "paypal-usd",
        "FDUSD": "first-digital-usd",
        "TUSD": "true-usd",
        "USDP": "paxos-standard",
        "stETH": "staked-ether",
        "rETH": "rocket-pool-eth",
        "tBTC": "tbtc",
        "cbBTC": "wrapped-bitcoin",  # closest CG mapping
        "msyrupUSDp": "msyrupusdp",  # may not resolve; will cache as no_price_data
    }
    try:
        from recupero.freeze.asks import load_issuer_db
        db = load_issuer_db()
    except Exception as e:  # noqa: BLE001
        log.warning("could not load issuer DB: %s", e)
        return []
    ids: set[str] = set()
    for (_chain, _contract), entry in db.items():
        cg_id = SYMBOL_TO_CG.get(entry.symbol)
        if cg_id:
            ids.add(cg_id)
    return sorted(ids)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch prices but don't write to the cache table.")
    parser.add_argument("--no-refresh-existing", action="store_true",
                        help="Skip ids already cached for today. Default: refresh all to bump cached_at.")
    parser.add_argument("--rps", type=float, default=0.4,
                        help="Pacing rate-limit (calls per second). Demo tier cap is 0.5; default 0.4 leaves margin.")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    dsn = os.getenv("SUPABASE_DB_URL")
    if not dsn:
        print("ERROR: SUPABASE_DB_URL is not set.", file=sys.stderr)
        return 2

    coingecko_key = os.getenv("COINGECKO_API_KEY")
    today = _today_iso()
    log.info("prewarming pricing cache for date=%s", today)

    # Combine the curated list + issuer-DB-derived ids
    all_ids = sorted(set(_COINGECKO_IDS) | set(_collect_issuer_db_ids()))
    log.info("prewarm target: %d unique CoinGecko ids", len(all_ids))

    # Cache key shape matches CoinGeckoClient.price_now:
    #   coingecko:simple:<cg_id>:<today_iso>
    key_prefix = f"coingecko:simple:"
    cache_keys = {cg_id: f"{key_prefix}{cg_id}:{today}" for cg_id in all_ids}

    skipped_existing = 0
    fetched = 0
    cached = 0
    errors = 0
    interval = 1.0 / max(args.rps, 0.1)

    with psycopg.connect(dsn, autocommit=False, connect_timeout=15,
                         prepare_threshold=None) as conn:
        if args.no_refresh_existing:
            existing = _existing_cache_keys(conn, key_prefix + "_")
            existing_today = {k for k in existing if k.endswith(today)}
            to_fetch = [i for i in all_ids if cache_keys[i] not in existing_today]
            skipped_existing = len(all_ids) - len(to_fetch)
            log.info("skipping %d ids already cached for today", skipped_existing)
        else:
            to_fetch = all_ids

        with httpx.Client() as http:
            for i, cg_id in enumerate(to_fetch, start=1):
                cache_key = cache_keys[cg_id]
                price, error = _fetch_one(http, cg_id, coingecko_key)
                fetched += 1
                if price is not None:
                    log.info("[%3d/%d] %s = $%s", i, len(to_fetch), cg_id, price)
                else:
                    log.warning("[%3d/%d] %s — %s", i, len(to_fetch), cg_id, error)
                    errors += 1

                if not args.dry_run:
                    try:
                        _upsert(conn, cache_key, price, error)
                        cached += 1
                    except Exception as e:  # noqa: BLE001
                        log.error("upsert failed for %s: %s", cache_key, e)

                # Rate-limit pacing
                time.sleep(interval)

        if not args.dry_run:
            conn.commit()

    log.info("done. fetched=%d cached=%d errors=%d skipped_existing=%d",
             fetched, cached, errors, skipped_existing)
    print(json.dumps({
        "date": today,
        "fetched": fetched,
        "cached": cached,
        "errors": errors,
        "skipped_existing": skipped_existing,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
