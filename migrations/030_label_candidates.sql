-- 030_label_candidates.sql
--
-- v0.32 Tier-1 gaps #1 + #2 from docs/WHY_RECUPERO_WOULD_FAIL.md
-- §1.1 + §1.2:
--   * "Adversary adapts faster than label-DB updates" — a new bridge
--     protocol launches Monday, we add it Friday, 5 days of cases
--     pass through it undetected.
--   * "CEX hot-wallet rotation makes labels stale" — v0.31.2 Tron
--     entries dated 2026-05-26 will be wrong by Q3.
--
-- The auto-ingest pipeline pulls candidate labels from Etherscan /
-- Tronscan / Solscan / DeFiLlama into THIS table with
-- status='pending_review'. An operator promotes or rejects via the
-- /v1/labels/candidates/* endpoints in src/recupero/labels/api.py.
--
-- We deliberately do NOT auto-promote: a tag-spammer could inject
-- bogus "labels" into our DB if we trusted upstream tags blindly.
-- Two-stage workflow (INGEST → REVIEW) is the load-bearing safety.
--
-- Apply with: python scripts/apply_migration.py migrations/030_label_candidates.sql

BEGIN;

CREATE TABLE IF NOT EXISTS public.label_candidates (
    id                    BIGSERIAL PRIMARY KEY,
    address               TEXT NOT NULL,
    chain                 TEXT NOT NULL,
    proposed_category     TEXT NOT NULL,
    proposed_name         TEXT NOT NULL,
    proposed_confidence   TEXT NOT NULL DEFAULT 'low',
    source                TEXT NOT NULL,
    source_url            TEXT,
    raw_metadata          JSONB,
    status                TEXT NOT NULL DEFAULT 'pending_review'
        CHECK (status IN ('pending_review','promoted','rejected','expired')),
    review_notes          TEXT,
    reviewer_email        TEXT,
    reviewed_at_utc       TIMESTAMPTZ,
    created_at_utc        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (chain, address)
);

CREATE INDEX IF NOT EXISTS label_candidates_status_idx
    ON public.label_candidates(status);

COMMENT ON TABLE public.label_candidates IS
    'v0.32 auto-ingest pipeline (Tier-1 gaps #1 + #2). Daily cron '
    'pulls candidate labels from upstream tag APIs into this table; '
    'an operator reviews via /v1/labels/candidates/{id}/{promote,reject}. '
    'Promotion writes to src/recupero/labels/seeds/*.json (the '
    'version-controlled source of truth). Rejection records reason '
    'so the same address is never re-suggested.';

COMMIT;
