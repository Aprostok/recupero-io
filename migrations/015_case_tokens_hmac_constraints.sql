BEGIN;

-- 015_case_tokens_hmac_constraints.sql
--
-- S-5 close-out (deferred from PUNISH-B): tighten constraints on
-- the token_hmac column + relax the raw `token` column ahead of
-- migration 016 which drops it.
--
-- This migration is safe to apply at any point with respect to code
-- deploy state:
--   * Pre-deploy worker still writes both `token` and `token_hmac`.
--     After this migration, `token` allows NULL — old INSERT keeps
--     working because old code always supplies a value.
--   * Post-deploy worker writes ONLY `token_hmac` (and never reads
--     `token`). After this migration, `token_hmac` is NOT NULL —
--     new INSERT keeps working because new code always supplies a
--     value.
--
-- PRECONDITION: the operator has run the token_hmac backfill so
-- every existing row has token_hmac populated. Verify with:
--   SELECT COUNT(*) FROM public.case_tokens WHERE token_hmac IS NULL;
-- That number MUST be 0 before this migration runs. The NOT NULL
-- ALTER below will fail otherwise.

-- Step 1: tighten token_hmac.
ALTER TABLE public.case_tokens
    ALTER COLUMN token_hmac SET NOT NULL;

ALTER TABLE public.case_tokens
    ADD CONSTRAINT case_tokens_token_hmac_unique UNIQUE (token_hmac);

-- Step 2: relax the raw `token` column. We keep the column for now
-- so old code paths in flight at the moment of migration apply
-- continue to work; migration 016 drops the column entirely after
-- the new code deploys.
ALTER TABLE public.case_tokens
    ALTER COLUMN token DROP NOT NULL;

-- Drop the existing unique constraint on `token` so new INSERTs
-- with token=NULL don't trip on it. (UNIQUE allows NULLs by default
-- in Postgres, but we want this clearly gone before column drop.)
ALTER TABLE public.case_tokens
    DROP CONSTRAINT IF EXISTS case_tokens_token_key;

-- The partial index on token is redundant once writes stop and the
-- new code reads token_hmac. Drop it to reclaim space + eliminate
-- the soon-to-be-irrelevant write amplification.
DROP INDEX IF EXISTS public.case_tokens_active_token_idx;

COMMENT ON COLUMN public.case_tokens.token_hmac IS
    'HMAC-SHA256(RECUPERO_TOKEN_PEPPER, token) hex digest. CANONICAL '
    'lookup column post-S-5. The raw token (sent only in the customer '
    'link URL) is never persisted from this release onward.';

COMMIT;
