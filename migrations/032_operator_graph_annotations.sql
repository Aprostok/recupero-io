-- 032_operator_graph_annotations.sql
--
-- v0.35 (Phase 3.9): operator graph annotations + saved/shareable graph
-- views. Two additive tables, both keyed by investigation_id so notes and
-- saved views travel with the case and any operator holding the admin key
-- sees the same thing (the "annotations feed the evidence report" +
-- "saved & shareable graphs" capability Reactor/TRM ship).
--
--   * operator_graph_annotations — one free-text note per (investigation,
--     graph node). Upserted; an empty note deletes the row.
--   * operator_graph_snapshots   — a named, saved view CONFIG (layout,
--     open groups, hidden statuses, filters, colour-by) as JSONB. Not the
--     ephemeral node positions or live-expanded hops — the reproducible
--     view configuration.
--
-- Additive + safe to run mid-deploy. The API degrades gracefully if this
-- migration hasn't been applied yet (annotations read as empty; writes
-- return 503), so deploying the code before the migration is non-fatal.
--
-- Apply with: python -m recupero.ops apply-migration migrations/032_operator_graph_annotations.sql

BEGIN;

CREATE TABLE IF NOT EXISTS public.operator_graph_annotations (
    investigation_id UUID        NOT NULL,
    node_id          TEXT        NOT NULL,
    note             TEXT        NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (investigation_id, node_id)
);

COMMENT ON TABLE public.operator_graph_annotations IS
    'v0.35 Phase 3.9: one investigator note per (investigation, graph node). '
    'Upserted via PUT /v1/operator/graph/{id}/annotations; empty note deletes.';

CREATE TABLE IF NOT EXISTS public.operator_graph_snapshots (
    investigation_id UUID        NOT NULL,
    name             TEXT        NOT NULL,
    state            JSONB       NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (investigation_id, name)
);

COMMENT ON TABLE public.operator_graph_snapshots IS
    'v0.35 Phase 3.9: named saved graph VIEW CONFIG (layout/filters/groups/'
    'colour-by) per investigation. Shareable across operators with the admin '
    'key. Stores reproducible config, not ephemeral node positions.';

COMMIT;
