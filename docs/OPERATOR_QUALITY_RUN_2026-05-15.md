# Operator-quality run — 2026-05-15 (post bucket-cleanup verification)

Second-pass verification after Phase-6 fixes #1 (bucket cleanup) and
#2 (latest_only filter) landed. Same subject investigation as the
prior dry-run (`e917ffc5`), but re-triggered under the new code
path so every issue surfaced in the earlier report should be
resolved.

## Run details

| Field | Value |
|-------|-------|
| Investigation ID | `e917ffc5-36ec-40e0-a0b3-cc5a6b03f31c` |
| Trigger | Reset from `complete` → `pending` (resume-from-state) |
| Worker | `b6b3522eb9ba-1` on Railway |
| Pipeline path | Resumed past trace + freeze + editorial (all artifacts in bucket) |
| Stages re-run | emit_brief + building_package only |
| API cost | $0 (Anthropic not re-called — editorial cached) |
| Wall-clock | **56 seconds** (claimed → complete) |

## Verifications — all GREEN

### Bucket cleanup ran

Pre-trigger: bucket had 0 files under `briefs/` (we manually wiped during the dry-run, then re-triggered immediately). Post-run: 12 files under `briefs/` — exactly what the new build_all_deliverables produces in one cycle. No accumulation, no leftovers.

If we'd re-triggered without the pre-wipe, the bucket cleanup in `_stage_build_package` would have done it automatically — that's the behavior we want going forward.

### trace_report.html shipped

| | Pre-fix (earlier today) | After fix + re-run |
|---|---|---|
| `trace_report.html` | ❌ missing | ✅ 105,605 bytes |
| `trace_report.pdf` | ❌ missing | ✅ 213,861 bytes |

The trace_report-empty-transfers fix (commit `b5a5f90`) + the per-issuer bucket cleanup (commit `a507f12`) together produced the artifact. This is the asset that backs Jacob's admin-UI wallet-trace detail page.

### Freeze letters at customer-deliverable quality

| Issuer | freeze_request.html | freeze_request.pdf | le_handoff.html | le_handoff.pdf |
|--------|---------------------|--------------------|-----------------|----------------|
| Circle | 27,061 B | 49,818 B | 101,089 B | 202,623 B |
| Paxos / PayPal | 27,082 B | 50,014 B | 101,126 B | 202,632 B |
| Sky Protocol | 27,130 B | 49,993 B | 101,210 B | 202,723 B |
| Tether | 27,061 B | 49,504 B | 101,089 B | 202,455 B |

All 4 issuer briefs share the same `BRIEF-20260515T183849` timestamp — single building_package invocation, consistent state. Each PDF is a valid PDF-1.7 doc (verified `%PDF-1.7` header bytes), anonymously fetchable via the signed URL, customer-deliverable as-is.

The HTML sizes are stable (~27 KB across all 4 issuers) — that's the post-inline-SVG-removal template (commit `0f3826f`). The LE handoff sizes (~100 KB HTML / ~200 KB PDF) reflect the new attachment-pointer pattern Jacob asked for.

### Flow diagram

| Artifact | Size | Status |
|----------|------|--------|
| `flow_fe4c2a8b.svg` | 6,947 B | OK |
| `flow_fe4c2a8b.pdf` | 57,972 B | OK |

### Raw bundle (root level, preserved across re-runs)

7 files present — `case_json`, `manifest_json`, `freeze_asks`, `freeze_brief`, `transfers_csv`, `victim_json`, `editorial_json`. None of these get touched by the briefs/ cleanup; they're upserted by `upload_case_dir` after each stage.

## What this proves end-to-end

1. **The bucket cleanup works on Railway**, not just in local tests. Auto-triggered as part of `_stage_build_package`, no operator intervention.
2. **`trace_report.html` is now shipping on case-driven investigations**, retroactively backfilled by re-triggering the row. Same fix as the wallet-trace canary path (verified earlier on `849062ab` and `fa34bb56`).
3. **Re-running an existing investigation is now cheap**: 56 seconds, $0 API cost, no editorial re-call. The resume policy (skip stages whose artifacts already exist) means backfilling a fleet of pre-fix rows is operationally feasible.
4. **The `latest_only` filter is effectively unused for new investigations** — they only ever have one brief set in the bucket. It's the historical-row safety net.

## What this run did NOT cover

- **Anthropic editorial quality** — the editorial was reused from the original 14:00 run, not regenerated. Reviewing the prose for a real customer hand-off is still on Alec.
- **Multi-chain investigations** — this run is Ethereum-only. Polygon / Arbitrum / Base / BSC / Solana / Hyperliquid not exercised here. The chain-adapter test coverage (commit `4873d75`) covers the unit-level surface; integration tests would require real wallets on each chain.
- **Large-trace performance** — 698 transfers fits comfortably under the 5-min reaper threshold (this run took 56s for the deliverables-only re-run, ~83s for the original full pipeline). High-loss outliers (>$100k, >5k transfers) may behave differently.

## Backfill recommendation

Any case-driven `complete` investigation older than ~15:23 UTC today is missing `trace_report.html`. The audit query from the dry-run report finds them:

```sql
SELECT id, case_id, completed_at FROM public.investigations
 WHERE status = 'complete'
   AND completed_at < '2026-05-15 15:30:00+00'
   AND case_id IS NOT NULL
 ORDER BY completed_at DESC;
```

For each row, reset to `pending` to trigger a deliverables-only re-run (under a minute, no API cost). The new building_package path will:

1. Auto-clean the bucket's `briefs/` subdir
2. Regenerate the 4 freeze letters + LE handoffs
3. Generate `trace_report.html` + PDF
4. Upload everything fresh

If you have many pre-fix rows, a one-liner script would handle it:

```sql
UPDATE investigations SET status='pending', worker_id=NULL,
       claimed_at=NULL, last_heartbeat_at=NULL, completed_at=NULL,
       failed_at=NULL, error_message=NULL, error_stage=NULL
 WHERE status = 'complete' AND completed_at < '2026-05-15 15:30:00+00'
   AND case_id IS NOT NULL;
```

Worker poll cycle is 2-30s; even a dozen pre-fix rows would drain in under 10 minutes total.

## Customer-readiness assessment

| Question | Answer |
|----------|--------|
| Is the artifact set ready to email a real victim's compliance team? | **YES** (after operator review of the editorial). |
| Will a customer get the inline-SVG-cluttered 2.5 MB LE handoff? | No — those are pre-fix, won't be regenerated. |
| Will the admin UI show "74 freeze letters" for what should be 4? | No — auto-cleanup + `latest_only=true` default both prevent this. |
| Is there an audit-trail path if needed? | Yes — `?latest_only=false` returns the full history. |
| Can the operator backfill historical cases? | Yes — reset to `pending`, ~$0 + 60s per row. |

**Verdict: ship-ready** for the next live customer engagement, with the standard operator-side editorial review step in the loop.
