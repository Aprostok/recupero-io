# V0.30.2 Scripts Audit — Production-Safety Sweep

**Date:** 2026-05-26 · **Branch:** `pdf-deliverables` · **Scope:** every `*.py` under `scripts/`

Single biggest finding: **no script has a prod-DSN guardrail.** `conftest.py` lacks one too (verified at lines 1-80). Every script that opens Postgres trusts whatever `SUPABASE_DB_URL` is in the operator's local `.env`. The mitigation today is "operators are careful." The other findings are smaller (one cron silently swallows failures, one cron blasts an external API).

---

## Triage table

| Script | Prod? | DB writes / external HTTP / secrets | Idempotent? | Status |
|---|---|---|---|---|
| `deploy_preflight.py` | CI / pre-merge | subprocess pytest, no DB | yes (read-only) | CLEAN |
| `deploy_to_production.py` | Operator | applies migrations via `schema_migrations`; subprocess smoke | yes (tracked) | CLEAN, see T2-A |
| `apply_migration.py` | Operator | applies one .sql file | yes (`IF NOT EXISTS` discipline + destructive-DDL guard L46-53) | CLEAN |
| `recupero_watch.py` | Operator | INSERT/UPDATE `public.watchlist`; ON CONFLICT keyed | yes | CLEAN |
| `monitor_watchlist.py` | Cron (nightly) | INSERT `watchlist_snapshots`; Etherscan + CoinGecko | yes | T2-B |
| `nightly_audit.py` | Cron (daily) | read-only; subprocesses pytest/ruff/mypy | yes | CLEAN |
| `prewarm_pricing_cache.py` | Cron (daily) | UPSERT `pricing_cache`; CoinGecko | yes (paced, L211 default 0.4rps) | CLEAN |
| `check_stale_reviews.py` | Cron (daily) | read-only SELECT | yes | CLEAN |
| `backup_investigations.py` | Cron (weekly) | read-only; writes local files; Supabase storage GET | yes | T3-A |
| `export_watchlist.py` | Operator | read-only SELECT | yes | CLEAN |
| `mutation_smoke.py` | CI | local edits + revert; subprocess pytest | yes (revert in `finally`) | CLEAN |
| `e2e_smoke.py` | Operator/CI | INSERT cases+investigations, DELETE on cleanup | yes (UUIDs) | T1-A |
| `insert_validation_row.py` | Operator | INSERT cases+investigations | yes (UUIDs) | T1-A |
| `approve_validation_row.py` | Operator | UPDATE investigations by id; writes bucket JSON | yes | T1-A |
| `download_validation_briefs.py` | Operator | read-only; writes local files | yes (path-traversal guard L38-53) | CLEAN |
| `seed_labels.py` | Local | appends to `data/labels/local_*.json` | NO — duplicates on re-run | T2-C |
| `_v029_expand_bridges.py` | One-shot | edits `bridges.json` | yes (`existing` set L19-22) | CLEAN |
| `_v029_1_expand_more_bridges.py` | One-shot | edits `bridges.json` | yes + collision assert L280 | CLEAN |
| `_v029_1_label_db_sweep.py` | One-shot | edits 3 seed JSONs | yes (skips already-tagged L90-92) | CLEAN |
| `smoke_deliverables.py` | Dev | local files only | yes (rmtree first L39-41) | CLEAN |
| `smoke_flow_diagram.py` | Dev | local files only | yes | CLEAN |
| `smoke_trace_report.py` | Dev | local files only | yes | CLEAN |
| `smoke_new_chains.py` | CI | external HTTP, no DB | yes | CLEAN |
| `trace_address.py` | Dev wrapper | runs `recupero trace` CLI | n/a | CLEAN |
| `trace_zigha_dust.py` | Dev one-shot | writes local case dirs | yes | CLEAN |
| `verify_zigha.py` | Dev | reads chain APIs, writes local case dir | yes | CLEAN |

---

## TIER-1 CRITICAL (immediate damage potential)

### T1-A — Validation/E2E scripts can write straight into prod with no fence
`scripts/insert_validation_row.py` (L78-79), `scripts/e2e_smoke.py` (L289), and `scripts/approve_validation_row.py` (L77-81) all do `load_dotenv(override=True)` + `os.environ["SUPABASE_DB_URL"]` with **no check that the DSN points at staging vs production**. `insert_validation_row.py` then INSERTs `cases` + `investigations` (L111-135). `e2e_smoke.py` will additionally `DELETE FROM public.investigations` + `DELETE FROM public.cases` (L243-247) in its cleanup `finally`.

Failure mode: operator runs `python scripts/e2e_smoke.py` against a `.env` they forgot was pointing at prod → a synthetic "S-xxxxxx" case lands in the customer-facing investigations table, then 15 minutes later the cleanup DELETEs it. `cleanup` is keyed by the UUID it just inserted, so it does NOT mass-delete — but the synthetic row will already have been claimed by the prod worker and started spending Anthropic/Etherscan credit.

**Recommended fix:** add an assertion at the top of each that `SUPABASE_DB_URL` does not contain the prod hostname OR require `RECUPERO_ALLOW_PROD_VALIDATION=1`. Mirror the conftest pattern proposed in V030_OBSERVABILITY_GAPS gap #4 (fail-loud when env is misconfigured).

---

## TIER-2 HIGH

### T2-A — `deploy_to_production.py` migration step has split-transaction window
`apply_migration_file` (L172-211) runs `cur.execute(sql)` and the `INSERT INTO schema_migrations` in one transaction (good). But `run_migrations` calls `list_pending_migrations` in `autocommit=True` (L161-169) which bootstraps `schema_migrations` outside the migration tx. If migration N+1 lands while migration N's apply is mid-flight on a second operator's session, both will see the same "pending" set. The risk is theoretical (single operator runs it), but the **interactive prompt at L256-258 swallows the operator's "n" reply silently** — it returns a `StepResult(ok=False)` whose only signal is the summary line. No advisory lock is taken on `schema_migrations` either. Recommend `SELECT pg_advisory_xact_lock(...)` on a deploy-namespace key inside `run_migrations` before reading the pending set.

### T2-B — `monitor_watchlist.py` cron swallows partial failures
L268-284: on Etherscan fetch error the script logs a warning, appends to `errors`, and writes a snapshot row with `error=str(e)[:500]`. The summary JSON is emitted at L341 and the script exits **1 only if movements were detected** (L342). Etherscan being entirely down → 100% of fetches fail → `movement_count=0` → exit 0 → cron reports green. Operator has no signal until the Sentry alert (if/when wired per gap #1 of V030_OBSERVABILITY_GAPS).

Recommended fix: if `len(errors) / max(len(targets), 1) > 0.5`, exit 2 ("partial outage"). Or: track an `error_rate` Prometheus gauge and let the metrics-scraper alert.

### T2-C — `seed_labels.py add` is non-idempotent
L76-77: `existing = json.loads(...) if exists else []`; then `existing.append(...)`. Running the same `seed_labels.py add --address 0xabc --name Foo ...` twice creates two rows for the same address in `local_<file>.json`. The downstream `LabelStore.load` may de-dupe (not verified), but the on-disk file balloons. Recommend an upsert keyed by `(chain, address.lower())` or a `--replace` flag.

---

## TIER-3 MEDIUM

### T3-A — `backup_investigations.py --include-bucket` has no concurrency cap
`_backup_bucket` (L133-162) iterates every bucket file serially over a 60s-timeout httpx client. On the current ~50-case dataset this is fine; at 1k cases it's an hour. More importantly: a partial failure mid-walk (network blip) raises `RuntimeError` from `_list_bucket_prefix` (L112) which **propagates and the script returns 2** — but `_dump_table` already wrote `investigations.json` + `cases.json` to disk with no `manifest.json`. Operators auditing the backup directory can mistake a half-written backup for a complete one.

Recommended fix: write `manifest.json` last with a `complete: true` flag, OR move the bucket loop into a `try/except` that records `bucket: {error: ...}` in the manifest and still exits 0 (table backup is the critical part).

### T3-B — `prewarm_pricing_cache.py` rate-limit is correct but not adaptive
L137: HTTP 429 returns `(None, "rate_limited")` and the next iteration just sleeps the static interval (L275). A CoinGecko 1-min ban would burn through the whole list with every entry stamped `rate_limited`. The cache TTL is one day (L19-20) so the operator gets 24h of `error_msg="rate_limited"` entries. Recommend: on first 429, double the interval and emit a non-fatal warning to stdout summary.

### T3-C — `apply_migration.py` doesn't take an advisory lock either
L139-142: opens connection, runs single tx, commits. Two operators running it concurrently against the same migration file would both `cur.execute(sql)` — destructive-DDL guard is the only check (L46-53). For an `ALTER TABLE` migration this is "second one fails with a useful error"; for an `INSERT INTO seed_data` it's silent duplication. Recommend `pg_advisory_xact_lock(hashtext('recupero_migration'))` at L141.

---

## Negative findings (CLEAN — no concerns)

- `apply_migration.py` — destructive-DDL guard (L46-53), size cap (L40, 108-114), DSN scrub on error (L146), filepath sandboxing (L56-66, `_is_inside_migrations`). Reference implementation of a safe migration tool.
- `deploy_preflight.py` — purely read-only; subprocess-isolated; correct fail-loud exit-code semantics (L60-65); ASCII markers for Windows console (L330-332).
- `download_validation_briefs.py` — path-traversal guard at L38-53 (`_safe_local_path`) plus an explicit dot-segment reject at L67-69. Sandbox is correctly anchored.
- `_v029_*` one-shot scripts — all three idempotent via `(chain, address.lower())` key (`_v029_expand_bridges.py` L19-22; `_v029_1_*` L42-54 with explicit canonical-casing handling + collision-assert at L280).
- `_v029_1_label_db_sweep.py` — refuses to overwrite already-tagged entries (L90-92); has a chain-hint inference map at L53-65 that catches the v0.29.1 Tornado/BSC mislabel and would prevent a repeat.
- `nightly_audit.py` — read-only; per-check `try/except` isolation; never echoes secrets; subprocess-only side effects.
- `mutation_smoke.py` — patches files in-process and reverts in a `finally`; explicit `--no-integration` flag for environments without prod DSN.
- `check_stale_reviews.py` — single read-only SELECT; honors `--threshold-hours`; exit-code semantics correct (0/1/2).
- `recupero_watch.py` — `ON CONFLICT` is keyed correctly (L65-71); status enum validated (L41); chain enum validated (L42); no secrets ever printed.
- `verify_zigha.py`, `trace_zigha_dust.py`, `trace_address.py`, smoke_* — all dev tools writing only to local `data/cases/` or `scripts/_smoke_*_out/`. No prod DB connection; no secret echo.

---

## Cross-cutting recommendation (single ~30-line patch)

Add a `scripts/_prod_dsn_guard.py` helper:

```python
def assert_not_prod_dsn(dsn: str) -> None:
    if "PROD_HOST_HINT" in dsn and not os.getenv("RECUPERO_ALLOW_PROD"):
        raise SystemExit("Refusing to touch prod DSN. Set RECUPERO_ALLOW_PROD=1 to override.")
```

Import + call at top of `insert_validation_row.py`, `e2e_smoke.py`, `approve_validation_row.py`. Closes T1-A entirely. Mirror the same call in `apply_migration.py` to convert a destructive migration into a two-step confirm (already has `--yes-i-really-mean-it`, but doesn't gate on env).
