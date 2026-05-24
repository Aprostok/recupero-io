BEGIN;

-- 023_drop_letter_language_column.sql
--
-- RIGOR-naming Step B (companion to 022): now that the code reads
-- and writes `letter_tier` exclusively, drop the legacy
-- `letter_language` column. Also retire the old unique constraint
-- + index that referenced it; add the same shape on `letter_tier`.
--
-- PREREQUISITE: every reader/writer of letter_language must have
-- been removed BEFORE this migration runs. The grep gate is:
--   $ grep -rn letter_language src/ tests/ -- and only the
--   historical migrations + this file should match.
--
-- SAFETY: both tables are empty in prod as of 2026-05-24. If rows
-- exist when re-running this in another environment, the DROP
-- COLUMN still succeeds (Postgres rewrites the row format silently)
-- but any old-code SELECT would have already been failing before
-- this point, so by definition no in-flight code is referencing
-- letter_language.

-- Step B.1: new UNIQUE constraint on (issuer, letter_tier). Replaces
-- the soon-to-die issuer_priors_unique_per_issuer_language. The
-- recorder.py ON CONFLICT (issuer, letter_tier) clause needs this
-- to function; create it BEFORE dropping the old one so any in-
-- flight insert during the migration window sees at least one
-- matching unique index.
ALTER TABLE public.issuer_freeze_priors
    ADD CONSTRAINT issuer_priors_unique_per_issuer_tier
        UNIQUE (issuer, letter_tier);

-- Step B.2: drop the now-stale unique constraint + index on
-- letter_language. Postgres won't let us drop the column while
-- these reference it.
ALTER TABLE public.issuer_freeze_priors
    DROP CONSTRAINT IF EXISTS issuer_priors_unique_per_issuer_language;

DROP INDEX IF EXISTS public.issuer_priors_lookup_idx;

-- Step B.3: also drop the CHECK constraint on letter_language so
-- the column drop doesn't trip on a constraint that references it.
-- The check constraint name in 013 was anonymous (Postgres auto-
-- named); locate it via the catalog.
DO $$
DECLARE
    cn TEXT;
BEGIN
    FOR cn IN
        SELECT conname
          FROM pg_constraint
         WHERE conrelid = 'public.freeze_letters_sent'::regclass
           AND contype = 'c'
           AND pg_get_constraintdef(oid) ILIKE '%letter_language%'
    LOOP
        EXECUTE format(
            'ALTER TABLE public.freeze_letters_sent DROP CONSTRAINT %I',
            cn
        );
    END LOOP;
END
$$;

-- Step B.4: drop letter_language from both tables. The column
-- bytes get reclaimed on the next VACUUM FULL; on small tables
-- this is fine to skip.
ALTER TABLE public.freeze_letters_sent
    DROP COLUMN IF EXISTS letter_language;

ALTER TABLE public.issuer_freeze_priors
    DROP COLUMN IF EXISTS letter_language;

COMMIT;
