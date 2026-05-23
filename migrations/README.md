# Migrations

Ordered SQL migrations applied to the Supabase production database.
Filenames are `NNN_short_description.sql`, with NNN as a zero-padded
3-digit serial. Apply in order via `python -m recupero.ops apply-migration`.

## Concurrency rules (v0.16.12 — round-9 audit MEDIUM)

**Default**: wrap schema changes in `BEGIN; ... COMMIT;`. That gives
atomic apply/rollback so a crashed `apply-migration` doesn't leave
the schema half-changed.

**Exception**: `CREATE INDEX CONCURRENTLY` cannot run inside a
transaction. Migrations that build large indexes on tables with
production write traffic MUST:

1. Split the index build into its own migration file.
2. Omit `BEGIN/COMMIT`.
3. Use `CREATE INDEX CONCURRENTLY IF NOT EXISTS ...` so retries are
   safe.
4. Document the table size and expected build time in a header
   comment so the operator knows what to expect.

The Recupero tables are currently small (hundreds to tens of
thousands of rows), so the default `BEGIN`-wrapped path is correct
for everything shipped so far. The watchlist + investigations
tables will eventually outgrow this — when they do, the rule above
governs the migration shape.

## Destructive operations

Migrations that DROP columns, DROP tables, or UPDATE rows in a
non-idempotent way MUST be gated behind:

```bash
RECUPERO_CONFIRM_DESTRUCTIVE_MIGRATIONS=1
```

Pre-v0.16.12 migration 002_watchlist_cleanup.sql UPDATEs the
watchlist; future destructive migrations should follow the same gate
pattern.

## Idempotency

Every migration must be safe to re-run. Use:

* `CREATE TABLE IF NOT EXISTS`
* `CREATE INDEX IF NOT EXISTS` (with CONCURRENTLY when applicable)
* `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
* `DROP ... IF EXISTS` (when destructive is intentional)
* `ON CONFLICT DO NOTHING` for seed-data INSERTs

Avoid:

* `CREATE TABLE` without `IF NOT EXISTS`
* `INSERT ... VALUES` without `ON CONFLICT`
* Schema changes that depend on column-order (Postgres preserves order
  but views/triggers don't always)

## Migration log

| # | Title | Type | Notes |
|---|-------|------|-------|
| 001 | watchlist | additive | initial schema |
| 002 | watchlist cleanup | destructive | UPDATE; gate before re-run |
| 003 | pricing cache | additive | |
| 004 | watchlist priority | additive | adds priority column |
| 005 | emails sent | additive | audit trail |
| 006 | engagement tracking | additive | adds engagement_*  columns |
| 007 | case tokens | additive | portal bearer tokens |
| 008 | engagement signatures | additive | sign audit trail |
| 009 | kyc confirmation | additive | |
| 010 | payments | additive | Stripe events |
| 011 | address observations | additive | |
| 012 | monitoring subscriptions | additive | |
| 013 | freeze outcomes | additive | learned-prior input |
| 014 | case_token_hmac | additive | v0.16.12 — eliminate timing channel |
| 015 | engagement double-submit guard | additive | v0.16.12 — race fix |
| 016 | freeze letters unique hardening | additive | v0.16.12 — wallet-trace idempotency |
| 021 | cases + investigations drift backfill | additive | adds case_state / estimated_value_usd / total_loss_usd / change_summary — code-referenced columns that pre-existed in prod via admin UI |
