-- 011_address_observations.sql
--
-- Cross-case address correlation table — the data substrate behind
-- "this address has appeared in 3 prior cases, 2 of which had OFAC
-- exposure" alerts in the brief.
--
-- This is the compounding-moat table for Recupero: every case the
-- worker traces APPENDS to this table, so the Nth case automatically
-- benefits from address sightings in cases 1..N-1. Without it, every
-- case is forensically isolated; with it, perpetrator wallets that
-- recycle across victims (the typical pig-butchering pattern) get
-- flagged the second time they show up.
--
-- TRM Labs and Chainalysis both run on a similar substrate — they've
-- just been ingesting since 2017. This migration starts our clock.
--
-- Apply with: python scripts/apply_migration.py migrations/011_address_observations.sql
-- Idempotent: every CREATE uses IF NOT EXISTS.

BEGIN;

-- ----- address_observations ----- --
-- One row per (address, chain, case_id) tuple. Multiple cases that
-- touched the same address each get their own row — the correlation
-- queries aggregate via address + chain. This shape:
--   * preserves per-case provenance (you can list which cases an
--     address showed up in without a separate join table)
--   * lets us track per-case context (role, USD seen) so the
--     correlation summary can say "appeared as 'perpetrator_hub' in
--     case X with $48k flowed through, and as 'hop' in case Y with
--     $230k"
--   * allows clean GDPR-style purges when a case is dropped (FK
--     ON DELETE CASCADE removes its observations)
CREATE TABLE IF NOT EXISTS public.address_observations (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The address as it appears on-chain. For EVM chains we store
    -- the LOWERCASE form (matches how risk_scoring + cluster code
    -- key addresses); for non-EVM (BTC, SOL, TRX) we preserve case
    -- because their address encodings are case-sensitive.
    address               TEXT NOT NULL,
    chain                 TEXT NOT NULL,

    -- Per-case provenance. case_id is nullable because some traces
    -- run without a case (intake screenings, internal R&D, wallet-
    -- trace investigations with case_id=NULL).
    case_id               UUID REFERENCES public.cases(id) ON DELETE CASCADE,
    investigation_id      UUID REFERENCES public.investigations(id) ON DELETE CASCADE,

    -- Role this address played in THIS case. Mirrors the watchlist
    -- table's role taxonomy so downstream queries can union them:
    --   'victim' | 'perpetrator_hub' | 'hop' | 'exchange_deposit'
    --   | 'high_risk_destination' | 'bridge' | 'mixer'
    --   | 'dex_router' | 'drainer_contract' | 'unlabeled' | 'manual'
    role                  TEXT NOT NULL,

    -- Echo of the LabelCategory at observation time. Captured so we
    -- can answer "was this address labeled as a mixer when WE saw
    -- it?" — labels evolve, this lets us prove historical context.
    label_category        TEXT,
    label_name            TEXT,

    -- USD flow associated with this observation. Sums across all
    -- transfers in this case where the address appeared as
    -- from/to. None for addresses we labeled but didn't see move
    -- funds (rare — usually they appear in clusters via H1/H2).
    usd_flowed            NUMERIC(20, 2),

    -- Snapshot of risk-scoring outputs for this address from THIS
    -- case. Lets the correlation summary say "exposed to OFAC in
    -- case X" without re-running the analyzer at lookup time.
    risk_score            INTEGER,
    risk_verdict          TEXT,  -- 'sanctioned' | 'high' | 'medium' | 'low' | 'clean'
    is_ofac_exposed       BOOLEAN NOT NULL DEFAULT FALSE,
    is_mixer_exposed      BOOLEAN NOT NULL DEFAULT FALSE,
    is_drainer_attributed BOOLEAN NOT NULL DEFAULT FALSE,

    -- Audit timestamps.
    observed_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Note: NO unique constraint on (address, chain, case_id) because
    -- the same address can appear multiple times in a single case with
    -- different roles (e.g., simultaneously a 'hop' and a 'cluster
    -- member'). The recorder dedupes per-role at write time.
    CONSTRAINT address_obs_role_per_case_unique
        UNIQUE (address, chain, case_id, role)
);

-- Index for the primary lookup: "for these addresses, give me all
-- prior observations across chains." Used by every correlation
-- lookup during brief assembly.
CREATE INDEX IF NOT EXISTS address_obs_addr_chain_idx
    ON public.address_observations (address, chain);

-- Index for per-case purges + audit listings.
CREATE INDEX IF NOT EXISTS address_obs_case_idx
    ON public.address_observations (case_id);

-- Risk-filtered lookups: "show me every OFAC-touching address we've
-- ever recorded." Partial index keeps it cheap.
CREATE INDEX IF NOT EXISTS address_obs_ofac_idx
    ON public.address_observations (address, chain)
    WHERE is_ofac_exposed = TRUE;

CREATE INDEX IF NOT EXISTS address_obs_mixer_idx
    ON public.address_observations (address, chain)
    WHERE is_mixer_exposed = TRUE;

CREATE INDEX IF NOT EXISTS address_obs_drainer_idx
    ON public.address_observations (address, chain)
    WHERE is_drainer_attributed = TRUE;

COMMENT ON TABLE public.address_observations IS
    'Cross-case address correlation. One row per (address, chain, '
    'case_id, role) tuple. Powers the CROSS_CASE_CORRELATION brief '
    'section so addresses recycling across cases auto-flag.';

COMMIT;
