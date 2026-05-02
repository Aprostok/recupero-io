-- Recupero watchlist + nightly snapshot tables.
--
-- Populated automatically by the worker pipeline (every wallet visited
-- during a trace, except the victim, lands here). The is_freezeable
-- flag mirrors freeze_asks.json output; the nightly monitor only
-- snapshots rows where is_freezeable AND status='active' AND a prior
-- balance > 0 was observed, so mixers/bridges/dust wallets are
-- naturally skipped.
--
-- Manual add via scripts/recupero_watch.py (typer CLI).
-- LE export via scripts/export_watchlist.py.
-- Nightly diff via scripts/monitor_watchlist.py.
--
-- Apply with: python scripts/apply_migration.py migrations/001_watchlist.sql
-- Idempotent: every CREATE uses IF NOT EXISTS.

BEGIN;

-- ----- watchlist ----- --
CREATE TABLE IF NOT EXISTS public.watchlist (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address               TEXT NOT NULL,
    chain                 TEXT NOT NULL,
    case_id               UUID REFERENCES public.cases(id) ON DELETE SET NULL,
    investigation_id      UUID REFERENCES public.investigations(id) ON DELETE SET NULL,

    -- How this wallet ended up on the list.
    -- Values: 'perpetrator' | 'hop' | 'current_holder' | 'exchange_deposit'
    --       | 'mixer' | 'bridge' | 'unlabeled' | 'manual'
    role                  TEXT NOT NULL,
    -- Echoes recupero.models.LabelCategory at flag time, if known.
    label_category        TEXT,
    label_name            TEXT,

    -- Freeze targeting. is_freezeable=true means the asset issuer can
    -- freeze the wallet's holdings (USDC at Circle, USDT at Tether, etc.)
    -- or the holder is a known exchange deposit address.
    is_freezeable         BOOLEAN NOT NULL DEFAULT FALSE,
    issuer                TEXT,
    asset_symbol          TEXT,
    asset_contract        TEXT,

    flagged_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    flagged_by            TEXT NOT NULL DEFAULT 'worker',
    notes                 TEXT,

    -- Lifecycle. 'active' is the default; the monitor only ever
    -- snapshots active rows. The admin / LE updates state via the CLI.
    status                TEXT NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active','frozen','recovered','cleared')),
    cleared_at            TIMESTAMPTZ,
    cleared_reason        TEXT,

    -- Denormalized from latest snapshot for fast filtering / export.
    last_snapshot_at      TIMESTAMPTZ,
    last_balance_usd      NUMERIC,
    last_native_balance   NUMERIC,
    last_tx_count         INTEGER,

    -- Same wallet may appear in many investigations; we want one row per
    -- (address, chain, investigation) so each case keeps its own audit
    -- trail. Manual entries (no investigation_id) collapse to one per
    -- address+chain via the partial index below.
    UNIQUE (address, chain, investigation_id)
);

CREATE INDEX IF NOT EXISTS watchlist_active_freezeable_idx
    ON public.watchlist (status, is_freezeable, last_balance_usd)
    WHERE status = 'active' AND is_freezeable = TRUE;

CREATE INDEX IF NOT EXISTS watchlist_case_idx ON public.watchlist (case_id);
CREATE INDEX IF NOT EXISTS watchlist_address_chain_idx ON public.watchlist (address, chain);

-- One manual row per (address, chain) — partial unique index because
-- automatic rows have an investigation_id and can dedupe through the
-- composite key above.
CREATE UNIQUE INDEX IF NOT EXISTS watchlist_manual_unique_idx
    ON public.watchlist (address, chain)
    WHERE investigation_id IS NULL;

-- ----- watchlist_snapshots ----- --
CREATE TABLE IF NOT EXISTS public.watchlist_snapshots (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    watchlist_id          UUID NOT NULL
                          REFERENCES public.watchlist(id) ON DELETE CASCADE,
    taken_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Wei / lamports / etc. stored as exact NUMERIC(78,0).
    native_balance        NUMERIC,
    tx_count              INTEGER,
    -- Sum across native + tracked tokens, valued at fetch time.
    usd_value             NUMERIC,
    -- Change vs the previous snapshot (NULL for the first snapshot).
    delta_usd             NUMERIC,

    -- Per-token rows: [{symbol, contract, balance_decimal, usd_value}, ...]
    token_balances        JSONB,
    -- Source / freshness for debugging.
    source                TEXT,
    error                 TEXT
);

CREATE INDEX IF NOT EXISTS watchlist_snapshots_recent_idx
    ON public.watchlist_snapshots (watchlist_id, taken_at DESC);

COMMIT;
