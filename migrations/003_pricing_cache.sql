-- Persistent CoinGecko price cache.
--
-- Previously each investigation got a per-tempdir prices_cache/ directory
-- thrown away at run end. For Phase 2 nightly monitoring (same cases
-- re-traced every day) and at any kind of scale, that means CoinGecko
-- gets repeatedly asked for the same prices, eating into the 0.5 rps
-- rate limit and slowing the freeze stage.
--
-- Schema mirrors the existing file-based cache interface
-- (PriceCache.get(key) / put(key, value)): a single string key, with
-- the value broken into queryable columns. Historical prices never
-- change so we cache forever; the (chain, contract, date) tuple is
-- naturally unique. `price_now` lookups cache by today's date and
-- naturally expire after one day when tomorrow's key misses.
--
-- Apply with: python scripts/apply_migration.py migrations/003_pricing_cache.sql
-- Idempotent: CREATE TABLE IF NOT EXISTS.

BEGIN;

CREATE TABLE IF NOT EXISTS public.pricing_cache (
    -- Cache key from the application layer. Examples:
    --   coingecko:simple:ethereum:2026-05-10        (price_now lookups)
    --   coingecko:circle-usd-coin:2026-05-08        (historical price_at lookups)
    -- Treat as opaque; the application owns the format.
    cache_key       TEXT PRIMARY KEY,

    -- The cached USD price. NULL means "we asked, no price was available"
    -- (fetch error, no CoinGecko mapping, etc.). NULL is meaningful —
    -- distinguishes "haven't cached" from "cached as not-priceable".
    usd_price       NUMERIC,

    -- The error string from the fetcher when usd_price IS NULL. NULL
    -- when the price was found OK.
    error_msg       TEXT,

    -- When this row was last written. For TTL or audit purposes.
    cached_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- For ops queries: "what tokens are we re-fetching most"
CREATE INDEX IF NOT EXISTS pricing_cache_cached_at_idx
    ON public.pricing_cache (cached_at DESC);

COMMIT;
