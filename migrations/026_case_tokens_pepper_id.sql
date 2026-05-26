-- 026_case_tokens_pepper_id.sql
--
-- v0.30.4 (V030_2_SECURITY_AUDIT T1-B): pepper-rotation recovery path.
--
-- Pre-v0.30.4, `RECUPERO_TOKEN_PEPPER` rotation silently broke every
-- previously-issued portal URL. Because the row stored only
-- `token_hmac` (HMAC of raw_token under the active pepper), there was
-- no way to enumerate "affected victims" after the rotation: the OLD
-- hash space and the NEW hash space are disjoint, so SELECTing by
-- token_hmac after rotation returns zero. The operator could not
-- target a re-issue and could not distinguish "rotated-out" from
-- "revoked".
--
-- Fix: add a `pepper_id` column that records a 4-byte short identifier
-- of the pepper used at INSERT time. On rotation, the operator:
--
--   1. Sets RECUPERO_TOKEN_PEPPER + RECUPERO_TOKEN_PEPPER_ID to new
--      values (both rotated together).
--   2. Runs:
--        SELECT case_id, label, last_used_at
--        FROM case_tokens
--        WHERE pepper_id = $OLD_ID
--          AND revoked_at IS NULL
--          AND expires_at > NOW();
--   3. Generates replacement tokens via `generate_token` and emails
--      victims the new portal links.
--
-- The pepper_id is a 4-byte hex string (8 chars) — short enough to fit
-- alongside the existing row, large enough to make accidental
-- collisions between pepper versions ~0%. NOT cryptographically
-- secret (printing it in logs is fine); it's a content-addressable
-- identifier, not an authenticator.
--
-- Backfill: existing rows get pepper_id='legacy'. After this migration
-- + a one-time RECUPERO_TOKEN_PEPPER_ID env var being set, all newly-
-- minted tokens carry the explicit ID. Pre-existing tokens are
-- de-facto unrecoverable on rotation (they were before this fix too;
-- the migration just makes the gap visible).

BEGIN;

ALTER TABLE case_tokens
    ADD COLUMN IF NOT EXISTS pepper_id VARCHAR(16) DEFAULT 'legacy';

-- Index for the rotation-recovery query above. Partial index keeps
-- it cheap — we only need fast lookup for live, unrevoked tokens.
CREATE INDEX IF NOT EXISTS case_tokens_pepper_id_active_idx
    ON case_tokens (pepper_id)
    WHERE revoked_at IS NULL;

-- Comment for operator clarity.
COMMENT ON COLUMN case_tokens.pepper_id IS
    'Short identifier (typically 4-byte hex) of the RECUPERO_TOKEN_PEPPER '
    'used to mint this row''s token_hmac. Lets operators enumerate '
    'tokens minted under an old pepper after rotation, for targeted '
    're-issue. ''legacy'' = minted before pepper_id tracking landed.';

COMMIT;
