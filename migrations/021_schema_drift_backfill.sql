BEGIN;

-- 021_schema_drift_backfill.sql
--
-- W12-03 schema-drift detector caught code references in production
-- paths to columns that no migration created. Tracked references:
--
--   * portal/tokens.py:277,278,299,300 — reads `cases.case_state` and
--     `cases.estimated_value_usd` when minting the portal-side case
--     summary block. Without these columns a fresh-deploy worker
--     crashes the moment a victim hits the portal.
--
--   * monitoring/law_firm_dashboard.py:286 — reads
--     `cases.total_loss_usd` to roll up the law-firm portfolio. The
--     module is defensive (try/except + fallback to 0), but adding
--     the column makes the production dashboard meaningful instead
--     of silently zero.
--
--   * worker/_freeze_followup.py:178,179 — reads
--     `investigations.investigator_email` and
--     `investigations.ic3_case_id`. `ic3_case_id` ALREADY exists on
--     `public.cases` (migration 000) and on `public.investigations`
--     (migration 011); the drift was the static detector following
--     the alias `i.ic3_case_id` and not finding it on investigations.
--     `investigator_email` is genuinely missing — added here so the
--     14-day silence-tracker can route the courtesy nudge to the
--     human investigator on record.
--
-- All adds are idempotent (`IF NOT EXISTS`). Re-running the migration
-- after a prod operator has manually added any of these columns is a
-- no-op.

ALTER TABLE public.cases
    ADD COLUMN IF NOT EXISTS case_state TEXT;

ALTER TABLE public.cases
    ADD COLUMN IF NOT EXISTS estimated_value_usd NUMERIC(20, 2);

ALTER TABLE public.cases
    ADD COLUMN IF NOT EXISTS total_loss_usd NUMERIC(20, 2);

ALTER TABLE public.investigations
    ADD COLUMN IF NOT EXISTS investigator_email TEXT;

ALTER TABLE public.investigations
    ADD COLUMN IF NOT EXISTS ic3_case_id TEXT;

-- W12-03 also flagged investigations.change_summary (referenced by
-- ops/commands/mark_closed.py:147 for the audit-row JSONB summary).
ALTER TABLE public.investigations
    ADD COLUMN IF NOT EXISTS change_summary JSONB;

COMMENT ON COLUMN public.cases.case_state IS
    'Stage of the case workflow as surfaced to the customer portal: '
    'intake / engaged / closed / unrecoverable. Distinct from the '
    'operator-facing `status` column which tracks worker pipeline state.';

COMMENT ON COLUMN public.cases.estimated_value_usd IS
    'Customer-supplied estimate of stolen-asset value at the time of '
    'intake. May differ from the worker-derived `total_loss_usd` once '
    'a trace completes.';

COMMENT ON COLUMN public.cases.total_loss_usd IS
    'Worker-derived total USD loss across all theft events for the '
    'case. Computed by emit_brief and persisted for portfolio '
    'roll-ups (law_firm_dashboard).';

COMMENT ON COLUMN public.investigations.investigator_email IS
    'Email of the human investigator on record for this '
    'investigation. Used by the 14-day silence-tracker followup to '
    'route the courtesy nudge to the right human.';

COMMENT ON COLUMN public.investigations.ic3_case_id IS
    'IC3 case ID once filed. Surfaced in the LE handoff template.';

COMMENT ON COLUMN public.investigations.change_summary IS
    'JSONB diff blob recording the operator-supplied change summary '
    'on mark_closed / promote_freezable transitions. Surfaces in '
    'the audit log so a future review can trace why the case left '
    'the active queue.';

COMMIT;
