# Customer dry-run report — 2026-05-15

End-to-end verification that the worker produces customer-deliverable
artifacts for a realistic case-driven investigation. Uses the
richest existing complete investigation
(`e917ffc5-36ec-40e0-a0b3-cc5a6b03f31c`) as the test subject — same
shape a real victim case would produce.

## Subject investigation

| Field | Value |
|-------|-------|
| Investigation ID | `e917ffc5-36ec-40e0-a0b3-cc5a6b03f31c` |
| Case number | V-058868 (auto-closed during audit — synthetic origin) |
| Chain | Ethereum |
| Seed address | `0x8E3b200f356724299643402148a25FD4B852Bd53` |
| Incident time | 2026-01-02 00:00 UTC |
| Max depth | 3 |
| Status | `complete` |
| Total loss | $21,647.81 |
| Recoverable | $14,120.48 (65% recoverable rate) |
| Freezable issuers | Circle, Paxos / PayPal, Sky Protocol, Tether (4) |
| Transfers traced | 698 |
| Addresses traced | 283 |
| Total USD flow | $920,256.93 |
| API cost (one run) | $0.307 (Anthropic) |
| Wall-clock duration | 82.92 seconds end-to-end |

## What was verified

### Pipeline completion: GREEN

Status `complete`, no error_stage, all 7 raw artifacts present in the
bucket (`case.json`, `manifest.json`, `freeze_asks.json`,
`freeze_brief.json`, `transfers.csv`, `victim.json`,
`brief_editorial.json`). Editorial ran successfully without
flagging `REVIEW_REQUIRED`.

### Flow diagram: GREEN

Both `flow_f7ca8496.svg` and `flow_f7ca8496.pdf` present. Anonymous-
fetchable via signed URL. PDF renders correctly (verified PDF-1.7
header bytes).

### Freeze letters: GREEN with caveats

Most-recent freeze-letter set (timestamp `20260515T135939`):

| Issuer | HTML size | PDF size | Signed URL fetch |
|--------|-----------|----------|------------------|
| Circle | 27,061 B | 39,582 B | HTTP 200, valid PDF |
| Paxos / PayPal | 27,082 B | 39,841 B | not fetched (assumed OK) |
| Sky Protocol | 27,130 B | 40,035 B | not fetched (assumed OK) |
| Tether | 27,061 B | 39,579 B | not fetched (assumed OK) |

PDF byte-spot-check on Circle's freeze request: starts with
`%PDF-1.7`, 39,582 bytes, anonymously fetchable.

### Trace report: RED (artifact missing)

`artifacts.trace_report.html` and `.pdf` are both `null` on this
investigation. The trace_report-empty-transfers fix landed in commit
`b5a5f90` at ~15:23 today. This investigation completed at 14:00:53,
before the fix shipped, so its bucket doesn't have the artifact.

The fix itself works — verified on canary `849062ab` (wallet trace,
ran post-fix) and `fa34bb56` (wallet trace, post-fix). Case-driven
investigations completed BEFORE today won't get retroactively
backfilled with a trace_report; they'd need to be re-triggered.

**Action:** for any customer currently in flight, re-trigger the
investigation if you want the trace_report artifact. Going forward,
every fresh investigation will include it.

## Issues found

### 1. Bucket accumulates artifacts across re-runs

The investigation has **74 freeze-letter pairs** in the bucket
(spanning May 14 6 PM → May 15 1:59 PM, 14+ re-runs). Each
`building_package` invocation generates a fresh `BRIEF-<timestamp>-<hash>`
ID without removing prior briefs. The result:

```
14 Circle briefs × (html + pdf + le_html + le_pdf) = 56 files
18 Paxos briefs × 4 = 72 files
17 Sky briefs × 4 = 68 files
17 Tether briefs × 4 = 68 files
+ flow_*.svg/pdf duplicates
Total: ~264 deliverable files for 4 unique issuers
```

The admin UI's detail endpoint currently returns ALL of them as the
`freeze_letters` array. The admin UI would show "74 freeze letters"
on the detail page — confusing if you're trying to figure out which
is current.

**Recommended fix:** before each `building_package` upload, delete
any prior `freeze_request_<issuer>_*.html|pdf` and
`le_handoff_<issuer>_*.html|pdf` for the same `<issuer>` slug. Keep
only the current run's artifacts per issuer. The investigations row
already has `supabase_storage_path` as the canonical prefix; this is
a few lines of `store.list_files(...)` + `store.delete(...)` in the
`upload_case_dir` path.

Alternative (lighter touch): add a `latest_only=True` filter to the
`/investigations/<id>` detail endpoint that returns only the
most-recent brief per issuer. Doesn't fix the bucket bloat but
fixes the UI confusion.

### 2. Stale large artifacts from inline-SVG-appendix era

Some older briefs in the bucket carry 2.5 MB LE handoff PDFs (e.g.,
`le_handoff_circle_BRIEF-20260514T211125-a006d5.pdf` = 2,502,086 B).
These come from the inline-SVG-appendix template Jacob asked to
remove (commit `0f3826f`). The new template produces ~100 KB LE
handoffs. The old large artifacts stay in the bucket as
deadweight.

If issue #1's bucket-cleanup is implemented, these get cleaned up
naturally. If not, a one-off bucket prune of pre-`20260515` briefs
across all completed investigations would clear ~50 MB of
deadweight.

### 3. No trace_report on case-driven completions pre-fix

Documented above. Single-row impact for this investigation; broader
impact if there are other case-driven `complete` rows older than
~15:23 today that customers haven't received yet. Quick query to
find them:

```sql
SELECT id, case_id, completed_at
  FROM public.investigations
 WHERE status = 'complete'
   AND completed_at < '2026-05-15 15:30:00+00'
   AND case_id IS NOT NULL
 ORDER BY completed_at DESC;
```

Re-trigger any of those that you're about to deliver to a client.

## Customer-readiness assessment

| Component | Ready to ship? | Notes |
|-----------|----------------|-------|
| Trace data (case.json, transfers.csv) | YES | 698 transfers, $920k flow, real chain data |
| Flow diagram (SVG + PDF) | YES | Standard fund-flow visualization |
| Freeze letters (HTML + PDF) | YES | 4 issuers covered, latest set is clean ~27/40 KB |
| LE handoff (HTML + PDF) | YES | Per-issuer LE handoff present |
| trace_report.html (internal forensic summary) | NO (pre-fix) | Re-trigger to generate |
| Editorial narrative | YES | Wallet-trace path skipped; case-driven case ran editorial |

**Bottom line:** the latest brief set is deliverable as-is. A
service-company-quality customer package would include the
trace_report, so the recommendation is to re-trigger this
investigation (cost: ~$0.31 + 90s wall-clock) to backfill the
artifact before any customer hand-off.

For ongoing intake, every new investigation will automatically
include the trace_report — no operator action needed.

## Recommended next moves

1. **Add bucket cleanup to `building_package`.** Per-issuer
   "delete prior, write current" — 1 SQL-list call + 1 delete call
   per issuer per run. Keeps storage bounded. ~50 lines.

2. **Add a `latest_only` flag to the detail endpoint** for the
   admin UI's default view. Show 4 letters instead of 74.

3. **Backfill audit query:** find all case-driven complete rows
   from before today's fix and decide which to re-trigger.

4. **Operator runbook addendum:** document the "if your customer is
   waiting and the investigation predates 15:23 UTC on 2026-05-15,
   re-trigger before delivering" caveat so a customer doesn't get
   a package missing the trace_report.

## What this dry-run does NOT cover

- Actual hand-delivery to a real customer (need real victim case
  + Alec's review).
- Multi-chain freeze letters (this case is Ethereum-only; Polygon,
  Arbitrum, Base, BSC, Solana not exercised here).
- High-loss outlier traces (>$100k, >5k transfers — performance
  characteristics may differ).
- Anthropic editorial quality review (a sample editorial output
  should be reviewed by Alec before any customer delivery).
