-- 028_brief_review_status.sql
--
-- v0.32 Tier-0 gap #1 — MANDATORY HUMAN REVIEW GATE.
--
-- Per docs/WHY_RECUPERO_WOULD_FAIL.md §0.1: ONE wrong brief in real
-- legal proceeding ends the company. The `UNSIGNED` watermark is a
-- disclaimer, not a workflow gate; operators can — and will — send
-- briefs unreviewed.  INVARIANTS A-E catch SHAPE errors only; they
-- don't catch "this label is semantically wrong."
--
-- This migration adds the system of record for human review of every
-- customer-facing / law-enforcement-facing artifact.  Each artifact
-- emitted by ``build_all_deliverables`` lands a row here in status
-- ``awaiting_review``.  The dispatcher refuses to send the artifact
-- until status is ``human_reviewed_approved`` or the explicit
-- ``overridden_unreviewed`` audit path is used.
--
-- The UNIQUE constraint on ``(case_id, artifact_kind, artifact_sha256)``
-- is load-bearing: re-rendering the artifact with different bytes
-- creates a NEW review row, so you can't approve once and then ship
-- a different version.
--
-- Apply with: python scripts/apply_migration.py migrations/028_brief_review_status.sql

BEGIN;

CREATE TABLE IF NOT EXISTS public.brief_reviews (
    id                              BIGSERIAL PRIMARY KEY,
    case_id                         UUID NOT NULL,
    artifact_kind                   TEXT NOT NULL CHECK (artifact_kind IN (
        'brief','le_handoff','freeze_request','engagement_letter',
        'subpoena','recovery_snapshot','cooperation_dashboard'
    )),
    artifact_path                   TEXT NOT NULL,
    artifact_sha256                 TEXT NOT NULL,        -- pin the EXACT bytes reviewed
    status                          TEXT NOT NULL DEFAULT 'awaiting_review' CHECK (status IN (
        'awaiting_review',
        'reviewer_assigned',
        'human_reviewed_approved',
        'human_reviewed_rejected',
        'overridden_unreviewed'                           -- explicit operator-override path; audited
    )),
    reviewer_email                  TEXT,
    review_started_at_utc           TIMESTAMPTZ,
    review_completed_at_utc         TIMESTAMPTZ,
    review_notes                    TEXT,
    override_reason                 TEXT,                 -- required if status='overridden_unreviewed'
    override_acknowledged_legal_risk BOOLEAN DEFAULT FALSE,
    created_at_utc                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (case_id, artifact_kind, artifact_sha256)
);

CREATE INDEX IF NOT EXISTS brief_reviews_status_idx
    ON public.brief_reviews (status);
CREATE INDEX IF NOT EXISTS brief_reviews_case_id_idx
    ON public.brief_reviews (case_id);

COMMENT ON TABLE public.brief_reviews IS
    'v0.32 mandatory human-review gate. Dispatcher refuses any '
    'external-facing artifact emission unless an approved (or '
    'explicitly-overridden) row exists for the exact SHA-256 of the '
    'artifact bytes.';

COMMIT;
