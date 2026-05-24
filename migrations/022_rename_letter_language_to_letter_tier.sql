BEGIN;

-- 022_rename_letter_language_to_letter_tier.sql
--
-- RIGOR-naming (deferred from PUNISH-B): the column in
-- public.freeze_letters_sent + public.issuer_freeze_priors is named
-- `letter_language` but its values are escalation tiers, not
-- languages:
--   standard | le_backed | ausa_signed | mlat_routed | 314b | subpoena
--
-- "letter_tier" is the right name. This migration is a two-step
-- rename that keeps code working through a deploy window. Read this
-- before applying:
--
--   STEP A (this file): ADD letter_tier as a duplicate column +
--                       backfill from letter_language. Both columns
--                       coexist. Old code (reads letter_language)
--                       and new code (reads letter_tier) both work.
--   STEP B (next file): After the new code deploys and the dust
--                       settles (~1 week), drop letter_language.
--
-- DO NOT collapse step A and step B into a single migration. The
-- Railway worker auto-deploys on push to main; there is a brief
-- window where the old worker pod is still running while the new
-- pod boots. A single-step rename breaks the old pod for that
-- window because its SELECT statements still reference the old
-- column name.

-- Step A.1: add the new column, allowing NULL during backfill.
ALTER TABLE public.freeze_letters_sent
    ADD COLUMN IF NOT EXISTS letter_tier TEXT;

ALTER TABLE public.issuer_freeze_priors
    ADD COLUMN IF NOT EXISTS letter_tier TEXT;

-- Step A.2: backfill letter_tier from letter_language. Idempotent —
-- re-running is safe because the WHERE clause skips rows where the
-- destination column already has a value.
UPDATE public.freeze_letters_sent
   SET letter_tier = letter_language
 WHERE letter_tier IS NULL;

UPDATE public.issuer_freeze_priors
   SET letter_tier = letter_language
 WHERE letter_tier IS NULL;

-- Step A.3: pin the same NOT NULL + CHECK constraint shape on the
-- new column. We carry the same enum values forward; the rename is
-- pure naming, not a domain change.
ALTER TABLE public.freeze_letters_sent
    ALTER COLUMN letter_tier SET NOT NULL,
    ALTER COLUMN letter_tier SET DEFAULT 'standard';

ALTER TABLE public.freeze_letters_sent
    ADD CONSTRAINT freeze_letters_sent_letter_tier_check
        CHECK (letter_tier IN (
            'standard',
            'le_backed',
            'ausa_signed',
            'mlat_routed',
            '314b',
            'subpoena'
        ));

ALTER TABLE public.issuer_freeze_priors
    ALTER COLUMN letter_tier SET NOT NULL;

-- Step A.4: also create the new index so production lookups don't
-- regress when readers flip from letter_language to letter_tier.
CREATE INDEX IF NOT EXISTS issuer_priors_lookup_letter_tier_idx
    ON public.issuer_freeze_priors (issuer, letter_tier);

-- Documentation drift fix.
COMMENT ON COLUMN public.freeze_letters_sent.letter_tier IS
    'Escalation tier of the letter: standard | le_backed | '
    'ausa_signed | mlat_routed | 314b | subpoena. Renamed from '
    'letter_language (which was misleading — the values were never '
    'languages, only escalation strata).';

COMMENT ON COLUMN public.issuer_freeze_priors.letter_tier IS
    'Escalation tier — used as the per-issuer prior bucket. See '
    'freeze_letters_sent.letter_tier for the value enum.';

-- DO NOT drop letter_language yet. That happens in migration 023
-- AFTER the new worker code is confirmed to read letter_tier
-- exclusively and the old pod has been rolled.

COMMIT;
