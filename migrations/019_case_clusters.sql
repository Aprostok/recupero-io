-- 019_case_clusters.sql
--
-- v0.23.0 — Multi-victim cluster tracking.
--
-- The cross-case correlation pipeline (v0.11.0) already detects when
-- a single perpetrator wallet appears in multiple cases. v0.14.3
-- added a CLASS_ACTION_OPPORTUNITY section to the brief that
-- aggregates that detection at brief-render time. But neither
-- materializes the cluster as a persistent first-class entity —
-- every render re-derives it from the address_observations log,
-- and there's no stable handle ("cluster id") the operator can use
-- to refer to a multi-victim case group across tools.
--
-- This migration adds:
--
--   * case_clusters — one row per detected multi-victim cluster.
--     Persistent identifier (cluster_id); created when emit_brief
--     first detects perp-wallet overlap between the current case
--     and prior cases.
--
--   * case_cluster_members — many-to-many bridge between
--     case_clusters and cases. Records the per-case role
--     (originator vs newly_joined) so the aggregated cluster
--     handoff can sort cases chronologically by first appearance.
--
-- The cluster builder (recupero/monitoring/cluster_builder.py)
-- writes here at the tail of emit_brief, after auto-subscriptions
-- and the brief JSON write. Every operation is idempotent
-- (UNIQUE on shared_perp_address; ON CONFLICT DO NOTHING on
-- members) so re-emitting the brief on the same case re-joins
-- the same cluster.
--
-- Apply with: python scripts/apply_migration.py migrations/019_case_clusters.sql

BEGIN;

-- ----- case_clusters ----- --

CREATE TABLE IF NOT EXISTS public.case_clusters (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Friendly identifier for operator-facing surfaces (CLI, dashboards,
    -- the LE handoff Section). Generated from a hash of the shared
    -- perp wallet at cluster-creation time so two operators stamping
    -- the same wallet land on the same string.
    public_id                TEXT NOT NULL UNIQUE,

    -- The perp wallet whose overlap first triggered the cluster
    -- creation. Subsequent cases join the cluster when they share
    -- THIS wallet (or any wallet already in shared_perp_addresses).
    seed_perp_address        TEXT NOT NULL,
    seed_perp_chain          TEXT NOT NULL,

    -- Growing union of perp wallets that bind cases in this cluster.
    -- Maintained by the cluster builder as new cases join.
    shared_perp_addresses    TEXT[] NOT NULL DEFAULT '{}',
    shared_perp_chains       TEXT[] NOT NULL DEFAULT '{}',

    -- Aggregate counters maintained on join (denormalized for the
    -- dashboard query — could be re-derived from case_cluster_members
    -- joined to cases, but every cluster page hits this).
    member_case_count        INTEGER NOT NULL DEFAULT 0,
    total_loss_usd           NUMERIC(20, 2) NOT NULL DEFAULT 0,

    -- Lifecycle.
    status                   TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'consolidated', 'closed', 'archived')),

    -- Optional ops metadata.
    label                    TEXT,                       -- e.g. "Lazarus Group 2026-04 cluster"
    notes                    TEXT,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT case_cluster_seed_unique
        UNIQUE (seed_perp_address, seed_perp_chain)
);

CREATE INDEX IF NOT EXISTS case_clusters_status_idx
    ON public.case_clusters (status, member_case_count DESC)
    WHERE status = 'active';

COMMENT ON TABLE public.case_clusters IS
    'v0.23.0 — Multi-victim cluster groupings. One row per detected '
    'cluster of cases that share a perpetrator wallet. Created by '
    'recupero/monitoring/cluster_builder.py at emit_brief time when '
    'cross-case perp overlap is detected.';

-- ----- case_cluster_members ----- --

CREATE TABLE IF NOT EXISTS public.case_cluster_members (
    cluster_id               UUID NOT NULL REFERENCES
        public.case_clusters(id) ON DELETE CASCADE,
    case_id                  UUID REFERENCES public.cases(id) ON DELETE CASCADE,
    investigation_id         UUID REFERENCES public.investigations(id) ON DELETE CASCADE,

    -- 'originator' = first case observed for this cluster (the one
    --   that caused the cluster to be created).
    -- 'joined'     = subsequent case that joined an existing cluster
    --   on perp-wallet overlap.
    role                     TEXT NOT NULL
        CHECK (role IN ('originator', 'joined')),

    -- Snapshot of the case's headline loss at join time so the
    -- cluster aggregate doesn't drift if a case's brief is later
    -- regenerated. The cluster builder updates this when a case
    -- re-emits with a different TOTAL_LOSS_USD.
    case_total_loss_usd      NUMERIC(20, 2) NOT NULL DEFAULT 0,

    -- Which perp wallet was the bridge that linked this case to the
    -- cluster. Useful for the "this case joined because both share
    -- 0xabcd..." prose in the aggregated handoff.
    joined_via_address       TEXT,
    joined_via_chain         TEXT,

    joined_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (cluster_id, investigation_id)
);

CREATE INDEX IF NOT EXISTS case_cluster_members_by_case_idx
    ON public.case_cluster_members (case_id);

CREATE INDEX IF NOT EXISTS case_cluster_members_by_investigation_idx
    ON public.case_cluster_members (investigation_id);

COMMENT ON TABLE public.case_cluster_members IS
    'Many-to-many bridge between case_clusters and cases. One row per '
    '(cluster_id, investigation_id) — the PK enforces that the same '
    'investigation cannot join the same cluster twice.';

COMMIT;
