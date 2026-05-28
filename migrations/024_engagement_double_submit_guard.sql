-- 024_engagement_double_submit_guard.sql
--
-- v0.30.2 RENAMED from 015_engagement_double_submit_guard.sql to close
-- a duplicate-migration-number bug (V030_2_SECURITY_AUDIT.md T1-A).
-- Pre-v0.30.2 the filename collided with 015_case_tokens_hmac_constraints.sql;
-- on a glob-sorted apply_migration.py run, lexical order would
-- silently determine which 015_* landed first on a fresh deploy
-- machine, and an operator who only re-ran "the failing one" could
-- land prod with only one of the pair applied. Renumbered to 024 to
-- preserve apply-after-everything-else ordering (the engagement
-- guard touches engagement_signatures which has no dependency on
-- the case_tokens HMAC work).
--
-- v0.16.12 — Close the engagement double-submit race.
--
-- Pre-v0.16.12 the portal /sign POST handler's "already engaged"
-- short-circuit read engagement_started_at from a snapshot taken at
-- the start of the request. Two simultaneous POSTs (back-button
-- reload, hostile family member, browser-extension auto-retry) could
-- both pass the gate and both insert engagement_signatures rows for
-- the same investigation — polluting the chain-of-custody record
-- with multiple "signers" for one engagement.
--
-- This migration adds a partial unique index that:
--   * Enforces one ACTIVE signature row per investigation at the DB
--     level (independent of application logic).
--   * Only constrains rows tied to a live engagement
--     (`investigation_id IS NOT NULL`). Already-closed investigations
--     can carry historical signatures from prior engagement cycles
--     without conflict.
--
-- The application layer (recupero.portal.server._persist_signature)
-- wraps INSERT + UPDATE in a transaction that takes
-- `SELECT ... FOR UPDATE` on the investigations row, serializing
-- concurrent POSTs on the same investigation. The unique index is
-- defense-in-depth: if the row-lock fails (timeout, race, DB blip),
-- the constraint still rejects the duplicate.
--
-- Additive + safe to run mid-deploy. If duplicate rows already exist
-- the CREATE INDEX will fail with a clear error; operators must
-- de-dup manually before re-running.

BEGIN;

-- Partial unique on investigation_id when set. Multiple historical
-- signatures from earlier engagement cycles (closed-then-reopened)
-- remain allowed because the prior rows would have been retained
-- with their original investigation_id, and we only enforce at
-- INSERT time on rows the new INSERT collides with — which is
-- exactly the "two POSTs racing for the same investigation" case.
--
-- Note: this constraint is intentionally INDEPENDENT of
-- engagement_started_at / engagement_closed_at — those live on
-- investigations, not on signatures. We trust the application to
-- create a NEW investigation row for a reopened engagement
-- (current behavior); enforce one-signature-per-investigation
-- atomically.
CREATE UNIQUE INDEX IF NOT EXISTS engagement_signatures_one_per_investigation_idx
    ON public.engagement_signatures (investigation_id)
 WHERE investigation_id IS NOT NULL;

COMMENT ON INDEX public.engagement_signatures_one_per_investigation_idx IS
    'v0.16.12: enforces one signature row per investigation_id. '
    'Defense-in-depth against the back-button-reload / concurrent-POST '
    'double-submit race. Application layer also takes '
    'SELECT FOR UPDATE on investigations.';

COMMIT;
