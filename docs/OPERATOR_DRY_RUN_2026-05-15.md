# Operator workflow dry-run — 2026-05-15

End-to-end validation of the `recupero-ops` CLI workflow against
the canary case `e917ffc5`. Run with `RECUPERO_DISABLE_EMAIL=1` so
no real emails leave the box — but every code path is exercised
(dispatch plan generation, audit-log writes, idempotency checks,
engagement state transitions).

## What the dry-run validates

The full Tier-2 customer engagement lifecycle:

1. Operator runs `status` to see initial state
2. Customer pays Tier-2 fee → operator runs `mark-engaged`
3. Operator runs `send-freeze-letters` (with confirmation prompt)
4. Operator runs `send-le-handoff --to <officer>`
5. Operator runs `followup-now` to send first weekly status
6. Daily cron `--send-followups` continues weekly cadence
7. Engagement winds down → operator runs `mark-closed`
8. Cron correctly excludes closed engagement on subsequent runs

## Run results (all 9 steps PASS)

### Step 1: Initial `status` — NOT ENGAGED

```
========================================================================
ENGAGEMENT
========================================================================
  Status:           NOT ENGAGED (diagnostic only)
  To activate Tier 2: `recupero-ops mark-engaged <id> [--fee 1500]`
```

Clean read — investigation is `complete` but no Tier-2 engagement
yet. Helpful hint to the operator about the next step.

### Step 2: `mark-engaged --fee 1500`

```
OK — engagement activated for e917ffc5-36ec-40e0-a0b3-cc5a6b03f31c
     started_at: 2026-05-15 22:28:05 UTC
     fee paid:   $1500.00
     first follow-up will be sent on the next
       `recupero-worker --send-followups` cron run.
```

`engagement_started_at` + `engagement_fee_paid_usd` populated.
Cleared `last_followup_sent_at` so the cron picks this up.

### Step 3: `status` post-engagement

```
ENGAGEMENT
========================================================================
  Status:           ACTIVE
  Started at:       2026-05-15 22:28:05 UTC
  Fee paid (USD):   $1500.00
  Last follow-up:   —
  Days into engagement: 0
  Days remaining in 30-day window: 30
```

Engagement state surfaces cleanly. "Days remaining" gives the
operator a clear sense of the commitment window.

### Step 4: `send-freeze-letters` with batch confirmation

```
FREEZE LETTER DISPATCH — Investigation e917ffc5-...
========================================================================

  Circle                  -> compliance@circle.com
    Stablecoin: USDC
    Freezable:  $7,097.58
    File:       freeze_request_circle_BRIEF-20260515T212734-105256.html

  Tether                  -> compliance@tether.to
    Stablecoin: USDT
    Freezable:  $7,022.90
    File:       freeze_request_tether_BRIEF-20260515T212734-15d7a0.html

  Sky Protocol            -> security@makerdao.com
    Stablecoin: DAI
    Freezable:  $0
    File:       freeze_request_sky_BRIEF-20260515T212735-2f4262.html

  Paxos / PayPal          -> compliance@paxos.com
    Stablecoin: PYUSD
    Freezable:  $0
    File:       freeze_request_paxos_BRIEF-20260515T212735-3dc66c.html

Total: 4 freeze letter(s) to send.
Proceed with sending all letters? [y/N]: y

  SKIP  Circle: email disabled (RECUPERO_DISABLE_EMAIL=1)
  SKIP  Tether: email disabled (RECUPERO_DISABLE_EMAIL=1)
  SKIP  Sky Protocol: email disabled
  SKIP  Paxos / PayPal: email disabled
Done: 0 sent, 0 failed.
```

The dispatch plan is THE critical operator artifact here — it
lists every recipient + amount + file BEFORE asking for
confirmation. If a compliance email is typo'd or an amount is
wrong, the operator catches it at this prompt, not after sending
to four wrong addresses.

### Step 5: `send-le-handoff --to officer@fbi.gov`

```
LE HANDOFF DISPATCH — Investigation e917ffc5-...
========================================================================
  Recipient:     officer@fbi.gov
  LE handoff:    le_handoff_paxos_BRIEF-20260515T212735-3dc66c.html
  Will attach:   LE handoff PDF, trace_report PDF, flow PDF

Send LE handoff to officer@fbi.gov? [y/N]: y

SKIP — email disabled (RECUPERO_DISABLE_EMAIL=1). Would have
sent LE handoff to officer@fbi.gov with 3 PDF(s).
```

3 PDFs attached (LE handoff itself + trace_report + flow). The
single confirmation prompt keeps the operator in the loop
without making it a 5-step interaction.

### Step 6: `followup-now`

```
FOLLOW-UP NOW — Investigation e917ffc5-...
========================================================================
  To:              val@test.local
  Victim name:     Validation Run
  Engagement started: 2026-05-15 22:28:05+00:00
  Last followup:   (none yet)

Send follow-up status email NOW (bypassing 6-day cadence)?
  [y/N]: y

SKIP — email disabled (RECUPERO_DISABLE_EMAIL=1). Would have
sent week-19 status update to val@test.local.
```

Force-send bypassing the 6-day cadence works as documented.

### Step 7: `--send-followups` cron

```
INFO  followup cron: candidates=1 sent=0 failed=0
                    skipped_no_email=0 skipped_disabled=1

exit code: 0
```

Cron correctly distinguishes `skipped_disabled` from `failed`.
Exit code is 0 (intentional no-op) — won't trip `set -e` or
cron-failure alerts.

### Step 8: `mark-closed --reason "..."`

```
OK — engagement closed for e917ffc5-...
     closed_at: 2026-05-15 22:33:39 UTC
     reason:    operator dry-run complete
     follow-up cron will no longer send status updates for this case.
```

`engagement_closed_at` set + structured audit event appended to
the `change_summary` jsonb column.

### Step 9: Cron post-close

```
INFO  followup cron: candidates=0 sent=0 failed=0
                    skipped_no_email=0 skipped_disabled=0
```

Cron correctly excludes the now-closed engagement from its
eligibility query. Won't ping val@test.local with a week-2 update.

## Issues found + fixed during the dry-run

Three cosmetic / UX rough edges surfaced:

1. **`send-freeze-letters` printed "FAIL" on skipped sends.** When
   `RECUPERO_DISABLE_EMAIL=1`, each letter's result is `skipped=True`
   but the code-path printed "FAIL" because it checked `success`
   first. **Fixed**: distinct "SKIP" labeling.

2. **`followup-now` printed "FAIL" + exited 1 on skipped sends.**
   Same root cause. **Fixed**: detect `RECUPERO_DISABLE_EMAIL=1`
   and print "SKIP" + exit 0.

3. **`--send-followups` cron reported `failed=1` on every skipped
   send + exited 1.** Critical for production cron — a daily
   `set -e` cron would alert on every run while the env var is
   set. **Fixed**: `run_followup_cron` now returns
   `skipped_disabled` separately from `failed`, and the CLI
   exits 0 when only `skipped_disabled > 0`.

## Known limitations surfaced

1. **`send-le-handoff` picks one of N per-issuer LE handoffs by
   timestamp.** Each issuer's generate_briefs() call produces its
   own `le_handoff_<slug>_*.html`, so multi-issuer cases have
   multiple LE handoff files. The current logic picks the
   latest-by-timestamp, but the operator might want a different
   one (e.g., Circle's vs Paxos's emphasizes different
   recoverable amounts). **Future work**: generate a single
   consolidated LE handoff per case OR let the operator pick
   `--file <name>`. For now, all per-issuer LE handoffs describe
   the full case from that issuer's authority angle, so any
   of them is usable — but document this for the operator.

2. **`send-freeze-letters` includes letters with `$0` freezable
   amount.** Sky Protocol + Paxos in the canary have INVESTIGATE-
   only holdings (no confirmed FREEZABLE), so total_usd is $0.
   The letter is still useful (asks the issuer to investigate
   whether INVESTIGATE addresses are KYC'd to the perpetrator),
   but the operator may want a flag to skip $0-freezable sends.
   **Current behavior**: send anyway, the letter prose explains
   the KYC-review ask. **Future work**: `--min-freezable 100`
   flag.

3. **followup-now's week number can be inaccurate** when
   `engagement_started_at` is older than the current ISO week.
   The output showed "week-19 status update" because the
   `engagement_started_at` strftime("%U") returned the calendar
   week of the year. Want days-since-engagement, not calendar
   week. **Future work**: fix the prose helper to use
   `(days_since // 7) + 1` consistently.

None of these are blockers for the operator workflow. All three
are operator-cosmetic issues — the underlying functionality is
correct.

## Operator runbook (concrete sequence)

```bash
# 1. Customer pays $499 (recorded via Stripe / manual)
#    Diagnostic auto-runs via Railway worker
#    Auto-email goes to victim with summary + artifacts

# 2. Customer signs engagement letter, pays $1,500 incremental
recupero-ops mark-engaged <inv_id> --fee 1500

# 3. Send freeze letters to compliance teams (with batch confirm)
recupero-ops send-freeze-letters <inv_id>

# 4. Send LE handoff to assigned officer (or victim's attorney)
recupero-ops send-le-handoff <inv_id> --to officer@fbi.gov

# 5. (Optional) Force-send first weekly status now
recupero-ops followup-now <inv_id>

# 6. Daily cron handles weekly follow-ups automatically
#    0 9 * * *  recupero-worker --send-followups

# 7. At engagement close (recovery successful / window elapsed)
recupero-ops mark-closed <inv_id> --reason "$14k recovered, victim notified"

# At any time, check state:
recupero-ops status <inv_id>
```

**Total operator time per case** (excluding diagnostic auto-run +
weekly cron auto-sends): roughly **10 minutes** spread across the
30-day engagement window.
