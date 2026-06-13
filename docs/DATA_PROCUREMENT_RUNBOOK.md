# Data-Procurement Runbook — lighting up the built-but-dormant moat

The forensic **code** roadmap is essentially complete: chain coverage (BTC, ETH +
EVM L2s, Tron, Solana, TON, Stellar, Cosmos, Sui, Aptos), bridge/DeFi-reach
following, clustering, screening, freeze/legal artifacts, and the attribution
*pipeline* are all shipped. The durable competitive moat that remains is **DATA
SCALE**, and it is mostly **procurement / operator work, not engineering** —
several high-value capabilities are wired and inert, waiting only for a key, a
feed file, or an operator-curated list.

This runbook is the actionable checklist to turn that dormant code on. Each item
lists what it lights up, the exact command/env, the access path, and a rough cost
band. Commands are the `recupero-ops` CLI (see `--help`).

> Doctrine reminder: every imported label lands `pending_review` at LOW
> confidence and is operator-promoted — we never auto-trust a third-party feed as
> evidence, and we never hand-seed fabricated entries.

---

## Priority 1 — MistTrack attribution (the #1 gap vs Chainalysis)

**Lights up:** by-address entity attribution with MistTrack's (SlowMist) strongest
coverage — Tron/USDT laundering routes and scam/drainer/pig-butchering labels —
flowing into the candidate→review→promote queue.

**Wired, inert without a key.** The provider + the `misttrack-enrich` wiring are
shipped; with no `MISTTRACK_API_KEY` they make zero network calls.

1. Procure a MistTrack API key (SlowMist) — KYB/regulated-entity gating applies;
   contact via misttrack.io. Cost band: low-to-mid annual API tier.
2. Set `MISTTRACK_API_KEY` in the production environment.
3. Enrich a case's unknown hops (auto-targets the case's UNLABELED counterparties):
   ```
   recupero-ops misttrack-enrich --case <case_id>
   ```
   or an explicit batch: `--address <a> --address <b> --chain tron`.
4. Review + promote the resulting candidates via the labels API / review gate.

---

## Priority 2 — International sanctions (beyond OFAC)

**Lights up:** EU / UK HMT-OFSI / UN / Israel / Japan sanctioned crypto wallets in
screening + risk-scoring, alongside the already-live OFAC feed.

**Wired, inert until a feed file is imported.** `sanctions_intl_live.csv` is absent
by default → only OFAC screens today.

1. Download the OpenSanctions **CryptoWallet** bulk export (FtM JSON/NDJSON) from
   opensanctions.org. Cost band: a commercial-use data licence (free for
   non-commercial; commercial tiers are modest).
2. Import:
   ```
   recupero-ops import-sanctions --file <opensanctions_crypto_bulk.json>
   ```
3. The intl-sanctions CSV is then consulted by the screener + tracer next run.

---

## Priority 3 — OFAC live feed (already automated — verify it's running)

**Lights up:** the authoritative OFAC crypto sanctions list (the headline screen).
Already wired + cron'd (`ofac-sync`), refreshed continuously; the Label-Freshness
console shows the feed age as the headline alarm.

- Verify the cron job is scheduled in production and the freshness console shows a
  FRESH OFAC status. Manual refresh: `recupero-ops ofac-sync`.

---

## Priority 4 — Open-source attribution feeds (free breadth)

**Lights up:** bridge + exchange address labels from a free OSS attribution feed
(CSV / JSON / NDJSON of address/chain/category/name) into the review queue.

```
recupero-ops import-attribution --file <feed.{csv,json,ndjson}> --source <name>
```

Continuous free harvests (ScamSniffer/MEW drainer lists, TON entities, etc.) are
already cron'd via the daily label auto-ingest — no action needed beyond ensuring
the cron is enabled.

---

## Priority 5 — Internal known-bad blacklist (from your own case corpus)

**Lights up:** wallets seen across your own investigations, deduped with
provenance; only REAL illicit-role addresses (perpetrator/mixer/current-holder)
are armed to fire a high-risk verdict — never fixtures, victims, or services.

```
recupero-ops harvest-blacklist          # re-materialize from the case corpus
recupero-ops blacklist-arm --address <a> --chain <c> --reason "<why>"   # manual
```

---

## Priority 6 — Exchange LE-channel breadth (operator research, not code)

**Lights up:** more freeze/subpoena targets reach the verified dispatch path. ~14
exchanges have verified freeze contacts today; missing major/regional venues
(Upbit, Bithumb, HTX, Poloniex, Bitvavo, …) and stablecoin-issuer freeze channels
(Tether, Circle).

- For each venue, research its published law-enforcement / compliance freeze
  channel (LE portal URL or compliance email) and add it to the verified
  freeze-contact DB. Pure operator research keyed to each exchange's LE page.

---

## Priority 7 — Ransomware IOC feed (sourced, never hand-seeded)

**Lights up:** ransomware BTC/XMR payment addresses in screening. `ransomware.json`
is **intentionally empty** (anti-fabrication doctrine — we never hand-seed).

- Source a verified CISA / FBI IOC feed and import it through the attribution
  importer. Only a checksum-verifiable, maintained feed — not manual entry.

---

## At a glance

| # | Capability | Gate | Command / env | Type |
|---|-----------|------|---------------|------|
| 1 | MistTrack attribution | API key | `MISTTRACK_API_KEY` + `misttrack-enrich` | procurement |
| 2 | Intl sanctions | feed file | `import-sanctions --file` | data licence |
| 3 | OFAC feed | (running) | `ofac-sync` (cron'd) | verify |
| 4 | OSS attribution | feed file | `import-attribution --file` | free |
| 5 | Internal blacklist | case corpus | `harvest-blacklist` | operator |
| 6 | Exchange LE channels | research | verified freeze-contact DB | operator |
| 7 | Ransomware IOCs | sourced feed | `import-attribution` (CISA/FBI) | data |

**Biggest single lever:** Priority 1 (MistTrack) — it directly closes the #1
attribution gap vs Chainalysis and the code is already waiting on the key.
