-- 005_emails_sent.sql
--
-- Audit log of every email the worker sends on a case's behalf:
-- victim summary letters, engagement letters, compliance freeze
-- letters to issuer teams, LE handoffs to law enforcement.
--
-- Two reasons for a dedicated table rather than a JSONB column on
-- investigations:
--
--   1. Idempotency. The worker checks this table before sending so
--      a re-run (resume from awaiting_review, manual reset to
--      pending, post-deploy reaper recovery) doesn't double-send.
--      Doing this against a JSONB column would require row-level
--      locking on every send.
--
--   2. Audit trail. Operator may want to query "did Circle's
--      compliance team get this letter, when, and what message ID
--      did Resend issue" — that's a JOIN against investigations,
--      not a JSONB lookup.
--
-- This table is append-only in practice. We never UPDATE; we only
-- INSERT new rows. Failed sends get a row too (with error_message
-- populated) so the operator can see "we tried to send to X but
-- the email service rejected it" without having to read worker
-- logs.

CREATE TABLE IF NOT EXISTS public.emails_sent (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Which investigation this email is associated with. FK to
    -- investigations(id) for join convenience; ON DELETE SET NULL
    -- so deleting an investigation doesn't cascade-delete the
    -- audit record (audit data must outlive the row it audits).
    investigation_id uuid REFERENCES public.investigations(id) ON DELETE SET NULL,

    -- Recipient. Free-form so we can record bounces, fall-through
    -- sends, BCC additions, etc.
    to_address      text NOT NULL,

    -- Subject + a short preview for the operator UI.
    subject         text NOT NULL,
    preview_text    text,

    -- Email category. Drives idempotency (we use email_type +
    -- investigation_id + to_address as the dedup key) and helps
    -- the operator filter the audit log.
    --
    -- Known categories:
    --   victim_summary   — sent to the victim with the diagnostic
    --                      summary letter
    --   engagement_letter— sent to the victim with the Tier-2
    --                      engagement contract for signature
    --   freeze_letter    — sent to an issuer's compliance team
    --                      (Circle, Tether, Sky, Paxos)
    --   le_handoff       — sent to a law-enforcement officer with
    --                      the LE handoff package
    email_type      text NOT NULL,

    -- Sent timestamp. Always set, even on failure (records the
    -- attempt time, useful for back-off / retry decisions).
    sent_at         timestamptz NOT NULL DEFAULT NOW(),

    -- Resend message ID on success, NULL on failure.
    message_id      text,

    -- Error text on failure, NULL on success. Truncate to 4KB to
    -- prevent runaway log blobs from filling the row.
    error_message   text,

    -- Generation metadata for audit purposes.
    sent_by         text,    -- operator email / "worker:auto"

    -- For sends with file attachments, record their names so the
    -- audit log shows what was attached without us having to dig
    -- into the original deliverable bundle.
    attachments     text[]   -- e.g. {'trace_report_abc.pdf', 'flow_xyz.pdf'}
);

-- Idempotency index. The worker's auto-send path checks
-- `WHERE investigation_id = $1 AND email_type = $2 AND error_message IS NULL`
-- to determine whether a send has already succeeded. The index
-- makes that check O(log N) instead of O(rows).
CREATE INDEX IF NOT EXISTS emails_sent_inv_type_success_idx
    ON public.emails_sent (investigation_id, email_type)
    WHERE error_message IS NULL;

-- Recent-activity index for the operator dashboard.
CREATE INDEX IF NOT EXISTS emails_sent_by_time_idx
    ON public.emails_sent (sent_at DESC);

COMMENT ON TABLE public.emails_sent IS
    'Audit log of emails sent by the worker on behalf of cases. '
    'Append-only; row per attempt, including failures.';
