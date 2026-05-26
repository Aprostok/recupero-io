# Label DB completeness — root-cause diagnostic (v0.29 starting point)

After v0.28 closed the Zigha trace-coverage gap (1 of 7 known destinations
found), the user asked the deeper question: **why was the bridge label DB
incomplete in the first place?** This document captures the root-cause
analysis + the structural fixes v0.29 ships in response.

## What we know

Chronology of `src/recupero/labels/seeds/bridges.json` (via
`git log --follow`):

| Commit    | Date       | Event                                                                  | Entries |
|-----------|------------|------------------------------------------------------------------------|---------|
| `775b957` | 2026-04-20 | Initial import (v11)                                                   | ~10 (Ethereum-only, no `chain` field) |
| `cd5910d` | 2026-05-17 | `feat(trace): cross-chain handoff detection` — the feature this seed feeds | ~13 |
| `3d81d46` | 2026-05-23 | RIGOR Waves 5-14 + manifest cleanup; **Hyperliquid Arbitrum entry added**  | 31 (**1** Arbitrum) |
| `4d640d2` | 2026-05-26 | v0.28.0 Zigha fix — wholesale Arbitrum/Op/Base/Polygon coverage         | ~70 |
| `4cf72ba` | 2026-05-26 | v0.28.4 external verification audit; confidence downgrades             | ~70 |
| `26a0687` | 2026-05-26 | v0.28.5 re-promotion after WebFetch verification                       | ~70 |

**Scale.** Pre-v0.28 bridges.json had ~31 entries across 7 months. The single
Arbitrum row was Hyperliquid Bridge2 — added because Hyperliquid was a *case-
driven* requirement, not because someone audited Arbitrum bridge coverage.
By 2026-05-26 the file grew to 26 chain-tagged entries spanning 5 L2s, all
triggered by one $18M case.

Other categories show the same shape:
- `cex_deposits.json`: zero `chain` field tagging
- `defi_protocols.json`: L2 names appear in `notes` strings, not as a chain key
- No category has a coverage-matrix audit

## Root causes (systemic gaps)

### 1. Incremental case-driven growth, no coverage matrix [CRITICAL]

Every pre-v0.28 commit that touched bridges.json names a specific incident
or rigor wave. There was no commit titled "bridge coverage sweep" until
v0.28.0 — and v0.28.0 itself is the Zigha post-mortem. The repo's growth
pattern is "case surfaces a gap → add the one entry needed." Until v0.28,
**no developer had ever asked the question "do we cover Arbitrum?"** as a
first-class workstream.

### 2. Completeness test only checks family presence, not chain coverage [CRITICAL]

`tests/test_bridge_mapping_completeness.py::_REQUIRED_BRIDGE_FAMILIES`
asserts that at least one entry exists with a name matching `\bstargate\b`,
`\bdebridge\b`, etc. The Ethereum-side Stargate Router on its own satisfies
that assertion. There is no two-dimensional test of the form "for each
(family, chain) pair, an entry exists." A test that says "Stargate must
have rows on `{ethereum, arbitrum, optimism, base, polygon, bsc, avalanche}`"
would have failed loudly the day it was written.

### 3. Schema didn't require `chain` until v0.28 [HIGH]

Initial-import rows have no `chain` field at all (they're implicit Ethereum).
When chain-tagged rows were added in mid-May, no migration backfilled the
legacy rows or made `chain` required. The audit query
`sum(1 for b in bridges if b.get('chain') == 'arbitrum')` returned 1 — but
`sum(... if b.get('chain') == 'ethereum')` also returned 0 for the same
reason. The data shape made coverage gaps invisible to ad-hoc inspection.

### 4. Decoders and seeds drifted out of sync [HIGH]

`bridge_calldata.py` had decoders for Wormhole / Across / Stargate. The
seed file added a Hyperliquid (no decoder needed) entry but never added the
decoders for DeBridge / 1inch / LayerZero — so even adding seed rows would
have been silently useless without the decoder pair. There's no test that
asserts "every seed entry has a working decoder dispatched in
`bridge_calldata.py`" — the two are conceptually paired but mechanically
independent.

### 5. Confidence/provenance discipline retrofitted under pressure [MEDIUM]

The v0.28.4 audit downgraded ~12 entries from `high` to `medium` because
addresses had been added without external verification, then v0.28.5
re-promoted them after WebFetch-based confirmation. This is the right
outcome but exposes that **there was no provenance gate at write time** —
entries could be added with `confidence: high` and no `source` URL that
someone could re-verify, and they would pass CI.

### 6. No external sync job [MEDIUM]

`ofac_crypto_live.csv` has an auto-sync command (`recupero-ops ofac-sync`).
Bridges have nothing equivalent. There's no scheduled job that diffs our
seed against Dune's `cross_chain_bridges` table, L2Beat's bridge directory,
or DefiLlama's bridge list. Drift is permanent until a case surfaces it.

## What TRM/Chainalysis do differently

Commercial-grade label DBs cover ~50-100 bridge protocols across 80+ chains
because they treat the label DB as a **continuously-curated product**, not
a code artifact:

- **Coverage matrices as first-class data.** TRM's bridge module ships with
  explicit (protocol × chain × contract) tuples sourced from a curation team
  that watches L2Beat / DefiLlama / Dune dashboards. New bridge deployments
  enter via a sync pipeline within hours, not when a case surfaces them.
- **Multiple ingestion lanes**:
  (a) protocol-team contributions (Stargate publishes a JSON of their routers);
  (b) on-chain heuristics (large stable-token flows to a contract that emits
      a known bridge event → auto-flag for analyst review);
  (c) crawled docs sites;
  (d) customer feedback loops.
- **Per-bridge confidence scoring with decay**: stale entries auto-downgrade
  after N days without re-verification.
- **Coverage SLAs internal to the team**: "we will have a working label for
  any bridge with >$10M weekly volume within 5 business days of launch."
  This is a product commitment with staffing, not a best-effort dev task.
- **Decoder-and-label paired releases**: a new bridge protocol entry doesn't
  ship without the matching event/calldata decoder, gated by tests.

## v0.29 fixes — structural, not symptomatic

In order of impact:

### 1. (protocol × chain) coverage matrix test  (CRITICAL)

Extend `test_bridge_mapping_completeness.py` with a parametrized
`(family, chain)` matrix — e.g.
`Stargate × {ethereum, arbitrum, optimism, base, polygon, bsc, avalanche}`.
Today's single-axis "family present" check is insufficient and gave false
reassurance.

### 2. Require `chain` field on every bridge row  (CRITICAL)

Add a schema validator to `test_labels_seeds_integrity.py` that fails on any
bridge entry missing `chain`. Backfill legacy Ethereum rows in one commit.
This makes the gap visible to any future `grep`/audit query.

### 3. Pair seed entries with decoder coverage  (HIGH)

Add a test that asserts: for every `(family, chain)` in the matrix,
`decode_bridge_calldata` returns `confidence != "low"` on a canonical fixture
transaction. A row without a decoder is forensically useless and should fail
CI.

### 4. Provenance gate at write time  (HIGH)

Require `source` to be a URL (not a bare string like `"industry_known"`) for
any new entry with `confidence: high`. The v0.28.4 retrofit audit proved we
can do this with WebFetch — formalize it as the entry barrier, not a
post-hoc cleanup.

### 5. External diff/sync job  (MEDIUM)

Add a `recupero-ops bridge-sync` command, modeled on `ofac-sync`, that
pulls L2Beat's bridge directory + DefiLlama's `/bridges` API and outputs a
`bridges_diff.json` of (protocol, chain, address) tuples we lack. Run
weekly via cron. Even if all additions are manually triaged (false
positives matter), the diff surfaces gaps without waiting for a case.

### 6. Confidence decay  (MEDIUM)

Add `last_verified_at` to each row. A row with `confidence: high` and
`last_verified_at > 90 days` ago gets auto-downgraded in CI. Forces
periodic re-verification.

### 7. Sweep other label-DB categories  (MEDIUM)

A 1-day audit of `cex_deposits.json` / `defi_protocols.json` / `mixers.json`
for chain coverage is warranted before the next big case surfaces the next
gap. The label DB is a product surface, not a side-effect of cases — staff
it accordingly.
