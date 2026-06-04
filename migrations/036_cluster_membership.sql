-- 036_cluster_membership.sql
--
-- v0.38 (enterprise non-data #7): CONTINUOUS, cross-case address clustering.
-- Per-case clustering (trace/clustering.py) and cross-case victim clustering
-- (cluster_builder) already exist, but each run is ephemeral/per-case. This
-- table accumulates address→cluster membership ACROSS cases so a later trace
-- can ask "is this address already in a known cluster?" — the persistent,
-- ahead-of-case clustering that distinguishes a continuous engine from a
-- per-case heuristic.
--
-- Membership is unioned over time (see trace/cluster_store.accumulate_cluster):
-- when a new co-spend/common-funding cluster shares any address with an
-- existing cluster, the two merge into one canonical cluster_id.
--
-- Additive + safe mid-deploy. Accumulation is best-effort (guarded; never
-- breaks a trace) and lookup degrades to None without the table/DSN.
--
-- Apply with: python -m recupero.ops apply-migration migrations/036_cluster_membership.sql

BEGIN;

CREATE TABLE IF NOT EXISTS public.cluster_membership (
    id          BIGSERIAL   PRIMARY KEY,
    address     TEXT        NOT NULL,
    chain       TEXT        NOT NULL,
    cluster_id  TEXT        NOT NULL,   -- canonical cluster the address belongs to
    heuristic   TEXT,                   -- strongest heuristic that grouped it
    confidence  TEXT,                   -- 'high' | 'medium' | 'low'
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- One membership row per (address, chain); re-observation updates cluster_id
    -- + last_seen via UPSERT.
    UNIQUE (address, chain)
);

COMMENT ON TABLE public.cluster_membership IS
    'v0.38 #7: persistent cross-case address→cluster membership, unioned over '
    'time. Accumulated (guarded) from per-case clusters; queried at trace time '
    'via trace/cluster_store.lookup_cluster.';

CREATE INDEX IF NOT EXISTS cluster_membership_cluster_idx
    ON public.cluster_membership (cluster_id);

COMMIT;
