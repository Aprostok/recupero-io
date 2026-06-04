# Attribution-data strategy — closing the Chainalysis moat

Synthesized 2026-06-03. The single largest gap between Recupero and Chainalysis
/ TRM is **attribution data scale**, not engineering. Our trace, clustering,
exposure, bridge-pairing, freeze, and legal pipelines are competitive; what we
lack is the labeled universe that turns `0x71c7…` into "Binance hot wallet 7".
This document is the actionable plan to close it.

## 1. The gap, quantified

| | Recupero today | Chainalysis (public estimates) |
|---|---|---|
| Labeled addresses | ~1,200–1,500 (402 seed + 796 OFAC + intl) | hundreds of **millions** |
| Named real-world services | ~120 (53 CEX-deposit, 242 bridge, 27 DeFi, 29 mixer…) | hundreds of **thousands** |
| Coverage on a real trace | most counterparties surface **unlabeled** | most surface named |

The code to *ingest* and *use* labels already exists (see §4). The gap is the
**data** flowing into it.

## 2. What "attribution" actually is (so we buy/build the right thing)

Three layers, in increasing difficulty:
1. **Address → cluster** (same-owner grouping). We have the heuristics
   (co-spend, common-funding, same-multichain, shared-CEX-withdrawal). At scale
   this needs chain-wide, continuous clustering — not per-case.
2. **Cluster → entity** (the cluster is "Binance"). This is the hard, valuable
   part: built from exchange data, KYC subpoena returns, OSINT, intelligence,
   and ground-truth seeds. This is Chainalysis's decade-long moat.
3. **Entity → metadata** (jurisdiction, freeze contact, risk). We already model
   this (`issuers.json`, `freeze` contacts) — it scales linearly with §2.

We should **buy/partner for layer 2 seeds**, **build layer 1 at scale**, and
keep owning layer 3.

## 3. Acquisition — build vs buy, in priority order

**Tier A — free / low-cost, harvest now (extend the existing pipeline):**
- Public tag APIs already wired: DeFiLlama, Tronscan, Solscan, Etherscan,
  **tonapi.io** (TON entity name-search → `fetch_candidate_ton_entities`,
  v0.38), and the **brianleect/etherscan-labels** OSS dumps across 6 EVM chains
  (ethereum/bsc/polygon/arbitrum/optimism/fantom →
  `fetch_candidate_etherscan_label_dumps`, v0.38 — exchange + bridge labels).
  **ScamSniffer** community blacklist (`fetch_candidate_scam_addresses`, v0.38
  — ~2.5k scam/drainer EVM addresses → `scam_drainer` candidates that promote
  into the high-risk DB at severity 3 / low confidence; community-sourced so
  ALWAYS operator-reviewed, never auto-trusted), and the **MyEtherWallet /
  ethereum-lists darklist** (`fetch_candidate_mew_darklist`, v0.38 — ~715
  community-reported phishing/scam EVM addresses with comments → scam_drainer).
  ADD MORE (same pattern — one allow-listed host + one fetcher):
  Blockscout label exports, Arkham/Breadcrumbs free tiers (ToS-permitting),
  community label sets (`ethereum-lists`, `0xScope` public, `walletlabels`),
  per-exchange published deposit/hot-wallet disclosures, OFAC/OpenSanctions
  (already synced), ransomware-payment trackers (Ransomwhere), bridge/DEX
  contract registries. Each = one allow-listed host + one fetcher in
  `labels/auto_ingest.py`; all flow through review→promote (no fabrication).
- **Exchange partnerships (highest ROI for freezes):** a data-sharing MOU with
  even 2–3 exchanges (deposit-address feeds for confirmed-theft cases) attributes
  the off-ramp directly and is the freeze unlock. This is relationship work, not
  code.

**Tier B — paid data:** license an entity/attribution dataset (Chainalysis
Kryptos, TRM, Elliptic, Merkle Science, Crystal, or a regional provider). Cost
scales with coverage; negotiate a forensic/recovery-use license. This is the
fastest way to jump layer-2 coverage by orders of magnitude.

**Tier C — intelligence/OSINT:** scam-report aggregators (Chainabuse, IC3
referrals, ScamSniffer), darknet/forum monitoring, victim-reported deposit
addresses (we already collect these in intake — feed them back as seeds).

## 4. What already exists (do NOT rebuild)

- **Ingest pipeline:** `labels/auto_ingest.py` (harvest → `label_candidates`
  table, migration 030) + review API (`/v1/labels/candidates`) +
  `promote_candidate` / `reject_candidate`. Daily cron `_job_label_auto_ingest`
  (capped) + `_job_ofac_sync`.
- **File harvest:** `labels/attribution_feed.py` — add any free feed as DATA,
  not code (CSV/JSON/NDJSON → candidates).
- **Cross-case clustering:** `monitoring/cluster_builder.py` (address_observations,
  multi-victim cluster IDs) + per-case clustering (`trace/clustering.py`,
  co-spend / common-funding / entity_hint naming).
- **Confidence doctrine:** never fabricate; `high` only on cryptographic match
  or direct DB hit; candidates land `low` + `pending_review`.

## 5. The in-product feedback loop (built this pass)

`trace/attribution_coverage.py` (`ATTRIBUTION_COVERAGE` in the brief) makes
growth systematic: for every traced case it reports the **% of traced value
landing at attributed vs unlabeled addresses** and ranks the **highest-value
unlabeled counterparties as labeling targets**. The loop:

1. Trace a case → coverage report flags the top-value unlabeled addresses.
2. Operator researches those (explorer, OSINT, the Tier-A/B sources).
3. Confirmed labels → `label_candidates` → review → promote → seed store.
4. Next trace is better-attributed; repeat.

This focuses scarce research time on the addresses that attribute the **largest
share of flow** — the same compounding mechanism Chainalysis uses, scaled to our
case volume. Every case makes the next one sharper.

## 6. Chain-wide clustering engine (the layer-1 scale build)

Per-case clustering ≠ Chainalysis. To cluster *ahead* of cases:
- Stand up a clustering service that continuously ingests full-chain transfers
  (BTC co-spend first — strongest, already implemented per-case; generalize to a
  persistent union-find over all txs), persists clusters keyed by stable IDs,
  and exposes "what cluster is this address in" at trace time.
- Storage: a cluster-membership table (address → cluster_id) + provenance.
- Cost: dominated by full-node / indexer infra (BTC + top EVM chains + Tron +
  TON). Build incrementally per chain by theft volume.

## 7. Phasing + rough cost

- **Phase 1 (weeks, low cost):** expand Tier-A harvest sources; wire victim-
  intake deposit addresses back as seeds; ship the coverage→target loop (done).
  Drives coverage up on the cases we actually run.
- **Phase 2 (1–2 quarters, partnership effort):** 2–3 exchange data MOUs;
  evaluate one Tier-B paid dataset license.
- **Phase 3 (sustained, infra cost):** chain-wide clustering engine, BTC then
  EVM/Tron/TON, persisted cluster store wired into the tracer.

## 8. Legal / compliance

- License terms for any purchased dataset MUST permit forensic + litigation use
  and redistribution inside deliverables; verify before relying on it in a SAR /
  exhibit pack.
- Keep provenance on every label (`source`, `source_url`, confidence) — already
  modeled — so a court-facing claim can be traced to its origin.
- Never fabricate or infer an identity at `high` confidence; association ≠
  identity (the cluster `entity_hint` posture).

---

**Bottom line:** the engineering is largely in place. Closing the moat is a
data-acquisition + partnership + clustering-infra program, not a feature. The
coverage→target loop shipped this pass turns every case we run into attribution
growth; Tiers A–C and the clustering engine scale it from there.
