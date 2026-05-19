-- 016_freeze_letters_unique_hardening.sql
--
-- v0.16.12 — Tighten the freeze_letters_sent UNIQUE so wallet-trace
-- rows (case_id IS NULL) don't bypass idempotency.
--
-- Pre-v0.16.12 the constraint was:
--   UNIQUE (case_id, issuer, target_address, asset_symbol)
--
-- Postgres treats NULL as not-equal in UNIQUE constraints, so any
-- row with case_id=NULL bypassed the idempotency guard — operators
-- running send-freeze-letters on a wallet-trace investigation (no
-- associated case_id) could double-send and the constraint wouldn't
-- catch it.
--
-- Migration plan:
--   1. Add a partial UNIQUE on (investigation_id, issuer,
--      target_address, asset_symbol) — covers wallet-trace rows
--      where case_id is NULL but investigation_id is populated.
--   2. Leave the existing case_id-based UNIQUE in place — covers
--      case-driven rows where case_id IS NOT NULL.
--   3. Together they cover both row shapes without forcing a
--      case_id NOT NULL change (which would break the wallet-trace
--      schema invariant: trace rows have no case).
--
-- Additive + safe to run mid-deploy. If duplicate wallet-trace
-- letter rows already exist the CREATE INDEX will fail with a
-- clear error; operators de-dup manually before re-running.

BEGIN;

CREATE UNIQUE INDEX IF NOT EXISTS freeze_letters_unique_per_investigation_target_idx
    ON public.freeze_letters_sent (investigation_id, issuer, target_address, asset_symbol)
 WHERE investigation_id IS NOT NULL AND case_id IS NULL;

COMMENT ON INDEX public.freeze_letters_unique_per_investigation_target_idx IS
    'v0.16.12: idempotency for wallet-trace freeze letters (case_id=NULL). '
    'Companion to the existing case_id-based UNIQUE; together they cover '
    'both case-driven and wallet-trace investigation rows.';

COMMIT;
