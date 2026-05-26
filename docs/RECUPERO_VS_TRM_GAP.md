# Recupero vs. TRM Labs / Chainalysis — Honest Gap Analysis

**Audience:** the founder making resource decisions, not a customer or investor.
**Bias:** ruthlessly under-claim. Where a number is unverifiable, an order-of-magnitude is given and labeled as such.
**Date:** v0.28.5 / pre-v0.29.

---

## Section 1: The honest gap

### Label DB scale (addresses × services × chains)

| Dimension | Recupero (today) | TRM Labs | Chainalysis |
|---|---|---|---|
| Total labeled addresses | **~213** across all seed files (bridges 114, cex_deposits 39, defi 26, high_risk 16, mixers 12, ransomware 6) plus a synced OFAC live CSV | ~1B+ entity-tagged addresses (publicly cited) | ~1B+ tagged, ~500M+ with service attribution |
| Distinct services | ~40 unique entity names | ~80,000 services / VASPs | ~100,000+ services |
| Chains covered with labels | 7 nominally (eth, arb, op, base, polygon, bsc, solana — and most non-Ethereum coverage is post-v0.28, one week old) | 80+ chains with first-class coverage | 35+ chains with deep coverage, dozens more shallow |
| Curated entity types | Bridges, CEX deposits, OFAC, ransomware, mixers, DeFi | All of the above plus: gambling, P2P, OTC desks, payment processors, fraud shops, darknet markets, NFT marketplaces, scam categories with sub-taxonomies (rug pull, phishing, drainer-as-a-service, pig-butchering) | Same breadth as TRM, plus their proprietary cluster heuristics |

**This is a 6-to-7-order-of-magnitude gap on raw scale.** Two hundred labels vs. one billion. We are not in the same product category by this metric; we are an order of magnitude smaller than the *demo dataset* a commercial vendor would ship.

### Bridge protocol coverage

- **Recupero:** seed file lists ~26 chain-tagged bridge entries spanning ~7 protocol families (Wormhole, Across, Stargate, DeBridge, 1inch Fusion, Hop, Hyperliquid). Calldata decoders exist for 3 fully (Wormhole, Across, Stargate) and 2 in recognition-only mode (DeBridge, 1inch) — see `src/recupero/trace/bridge_calldata.py`.
- **TRM/Chainalysis:** 50–100+ bridge protocols with full event + calldata decoding, including cBridge, Synapse, Multichain (defunct but historically critical), Orbiter, Connext/Everclear, Squid, Mayan, Allbridge, Portal, Polygon zkEVM bridge, native rollup bridges, Avalanche Bridge, Hop, Symbiosis, THORChain (cross-asset bridging), Wanchain, IBC channels for Cosmos. Decoders are paired with each label release; coverage SLAs commit to 5-day turnaround on new launches.

**Gap:** ~5× on family count, ~10×+ on decoder fidelity, and we have zero coverage of native rollup bridges, IBC, or THORChain.

### DEX / aggregator coverage

- **Recupero:** `defi_protocols.json` has 26 addresses. 1inch is recognized as a router family with no actual swap-output decoding (we surface "Routed via 1inch" and stop).
- **TRM/Chainalysis:** Uniswap V2/V3/V4, Sushi, Curve, Balancer, PancakeSwap, TraderJoe, Camelot, Velodrome, Aerodrome, Raydium, Orca, Jupiter (Solana), 1inch, 0x, ParaSwap, KyberSwap, Matcha, CoW Swap, Odos — with full token-in/token-out event extraction and slippage analytics. Tens of thousands of pool addresses indexed per chain.

**Gap:** we don't really "have" DEX coverage. We have *recognition* of a handful of routers.

### CEX hot-wallet labels

- **Recupero:** 39 entries in `cex_deposits.json`, no `chain` field on most. Coinbase / Binance / Kraken / OKX / Bybit / Bitstamp / Gemini deposit addresses sampled. No automated refresh.
- **TRM/Chainalysis:** every major CEX has thousands of deposit addresses (CEXs rotate them daily); commercial vendors run clustering pipelines on the chain to auto-attribute new addresses to known clusters within hours. Estimated 100K+ CEX deposit addresses per major exchange.

**Gap:** ~3 orders of magnitude on CEX coverage, plus we have no clustering at all — every Recupero CEX label is hand-keyed.

### Mixer / privacy service labels

- **Recupero:** 12 entries in `mixers.json` — Tornado pools, Sinbad, Railgun, FixedFloat. That's it.
- **TRM/Chainalysis:** Tornado (all denominations × all chain deployments × all forks), ChipMixer (defunct but historically labeled), Sinbad / Blender lineage, Wasabi/Samourai (Bitcoin CoinJoin), Whirlpool, JoinMarket, Railgun, Aztec, Penumbra, Nocturne, plus non-KYC swap services (eXch, FixedFloat, ChangeNOW, SimpleSwap, StealthEx) with txn-level routing fingerprints. Hundreds of mixer-related contract / deposit addresses.

**Gap:** ~10× addresses, ~3× categories, and zero coverage of CoinJoin fingerprinting on Bitcoin.

### Sanctioned / OFAC / ransomware

- **Recupero:** OFAC SDN crypto sync via `ofac-sync` command is the one place we approach parity — we pull the Treasury XML directly and the live CSV is canonical. 16 hand-curated high-risk entries supplement it. Ransomware: 6 entries.
- **TRM/Chainalysis:** same OFAC source plus EU consolidated sanctions, UK OFSI, UN, plus internal attribution lists for sanctions-adjacent actors (DPRK clusters not yet on SDN, IRGC fronts, Hamas wallets). Ransomware: thousands of attributed payment addresses across 200+ ransomware families, with strain-level taxonomy (LockBit 3.0 vs. LockBit Black).

**Gap:** at parity on OFAC raw list; ~50× behind on attribution coverage, ~100× on ransomware.

### Decoder coverage

- **Recupero:** 5 bridge protocols recognized at calldata level, 3 with full destination decode. Zero DEX swap decoders. Zero NFT-marketplace decoders. Zero lending-protocol event extraction (Aave / Compound liquidations are invisible to us).
- **TRM/Chainalysis:** hundreds of protocol ABIs indexed, with event-level decoding for every top-100 protocol on every supported chain.

**Gap:** ~50–100× on protocols; we cover the bridges that one case (Zigha) needed.

### Risk-scoring engine

- **Recupero:** `src/recupero/screen/screener.py` exists. It is a **rule-based scorer** that maps (label hit, correlation count) → 0–10 score via hardcoded thresholds. No graph propagation. No indirect-exposure depth tuning beyond a fixed BFS. No ML.
- **TRM/Chainalysis:** multi-hop indirect-exposure scoring with per-hop decay, ML-based clustering to attribute unknown addresses to known entities, peer-flow-pattern detection (typology engines for "looks like mixer," "looks like layering," "looks like drainer payout"), graph-neural-net entity inference. Years of supervised training data from labeled cases.

**Gap:** we have a screener; they have a risk-intelligence engine. Different category of product.

### Time-series / historical labeling

- **Recupero:** seed entries carry `added_at` but no `last_verified_at`. No historical-state index — we can't answer "was address X labeled-as-CEX on date Y?" because we always look at current labels.
- **TRM/Chainalysis:** point-in-time labels (critical for forensics: an address that became a CEX deposit in 2024 was a personal wallet in 2022, and your trace report needs to reflect what was true at incident time).

**Gap:** structural. We don't model time on labels at all.

### Ingestion infrastructure

- **Recupero:** OFAC has an automated sync. **Every other label is hand-keyed via PR.** See `docs/LABEL_DB_GAPS_DIAGNOSTIC.md` — pre-v0.28 the bridge file grew by one row per case. There is no scheduled diff against L2Beat / DefiLlama / Dune.
- **TRM/Chainalysis:** multiple ingestion lanes — protocol-team feeds, on-chain heuristic auto-flagging, crawled docs sites, customer feedback loops, dedicated curation team.

**Gap:** we do hours of manual work where they do hours of analyst review on top of an automated pipeline that does the discovery for them.

### Curation team size

- **Recupero:** 1 (the founder, part-time, when a case demands a label).
- **TRM Labs:** ~50–100 intelligence analysts (public LinkedIn count).
- **Chainalysis:** 100+ analysts on the data team alone; thousands of employees total.

**Gap:** ~50–100× on headcount.

---

## Section 2: What it would actually take

### Phase 1 — 1 week, solo, WebFetch + scripts (~$0)

Ship the `recupero-ops bridge-sync` job laid out in `LABEL_DB_GAPS_DIAGNOSTIC.md`. Diff against L2Beat + DefiLlama bridge directories weekly; output a triage queue. Same for top-200 CEX deposits via DeBank / Arkham public endpoints. Add `chain` field migration. Add coverage-matrix tests. **Expected outcome: ~500–2,000 labels, ~5–10× growth, still 5 orders of magnitude behind TRM but no longer embarrassing on bridges and major CEXs.**

### Phase 2 — 1 month, solo or +1 contractor (~$5K–$20K)

Build the ingestion pipeline as a real product surface: (a) scheduled cron syncs from Dune, Allium, Flipside public dashboards; (b) on-chain heuristic auto-flagging (any address receiving >$10M from a known bridge in 24h → triage queue); (c) confidence decay job; (d) basic 2-hop clustering on the deposit-rotation heuristic for CEXs; (e) point-in-time label history table. **Expected outcome: ~20K–100K labels, automated freshness, still ~10,000× behind on scale but at parity on workflow shape for top-50 services.**

### Phase 3 — 3–6 months, +2 to +5 analysts (~$200K–$1M)

Data partnerships: pay for one of Coin Metrics / Allium / Dune Enterprise to backfill historical clusters. Hire 2 forensic analysts to do manual attribution on darknet markets, ransomware, scam categories. Build a typology engine (rule-based pattern detector for layering/peeling/mixing signatures). Add point-in-time label resolution end-to-end. **Expected outcome: low-millions of labels, recognizable risk-scoring engine, defensible "TRM-lite" positioning for SMB customers.**

### Phase 4 — 12+ months, ~$5M–$20M raise

This is where real parity work begins. Hire a 10–20 person curation team. License Chainalysis-grade clustering datasets or build the ML pipeline (graph neural nets on transaction graphs, supervised training on labeled exits, anomaly detectors). Build the typology engine into a full graph DB with sub-second multi-hop indirect-exposure traversal across billions of edges. Negotiate exchange data-sharing agreements. Hire compliance staff to validate sanctions screening at MSB / FinCEN audit level. **Expected outcome: maybe 80% of TRM/Chainalysis utility on top-10 chains, missing the long tail.**

True parity (every chain, every typology, every regulator-grade audit trail, real-time alerting at SaaS-product scale) is a $50M+ investment over multiple years. It is not a one-engineer-with-good-taste project.

---

## Section 3: What we CAN claim right now

Recupero is not a TRM competitor. It is a different product. We should sell it as such.

### Forensic depth, not breadth

We do the **last-mile work** TRM does poorly. TRM tells you "address X is risky." We produce a freeze-letter-ready PDF with: full source-of-funds graph, per-hop USD valuation at block timestamp, role-tagged counterparty list with confidence stratification, OFAC exposure summary, and a one-page LE brief naming the depositing exchange + deposit-account heuristic. That last-mile narrative is something analysts at TRM customer organizations *build themselves on top of* TRM's data. We ship it.

### Operator-grade outputs

Freeze briefs, full HTML/PDF reports, structured `case.json` archives, audit-trail invariants (INVARIANTS A/B), provenance metadata on every label hit. The output discipline is competitive with anything in the space. Our v0.28.4 confidence-downgrade audit and v0.28.5 re-promotion is the kind of process discipline a regulator likes to see.

### Open architecture / self-host

TRM and Chainalysis are closed SaaS at $50K–$500K/year minimums. Recupero is OSS-friendly, self-hostable, runs on a laptop. For a fraud unit at a non-US exchange, a regional law-enforcement task force, or a small recovery practice, the price-performance is real even with our 1000×-smaller label DB — because their alternative isn't TRM, it's nothing.

### Case-driven label depth on the cases we touch

When a Zigha-shape case runs through Recupero, the bridge labels for *that* incident's protocols are as good as TRM's, because we deep-verified them. The breadth is missing; the depth on covered protocols is competitive.

### Honest provenance

We don't black-box our risk scores. Every label has a `source` URL, a `confidence` tier, and a `last_updated` date. A defense attorney can audit our DB; they can't audit TRM's.

### Realistic positioning

**"Recupero is a focused forensic toolkit for stolen-crypto cases that need an LE-ready package fast. We are not a sanctions-screening platform, not an enterprise risk-intelligence product, and not a substitute for Chainalysis when your compliance team needs continuous monitoring of millions of customer wallets."** That sentence is something we can defend in any conversation. Anything stronger is over-claim.

---

## Bottom line

The honest answer to "why aren't we the same as TRM" is: **scale, team, and time.** They have 100× the people, 1,000,000× the labels, a decade head start, and tens of millions in cumulative R&D. We have ~213 labels and one part-time curator. We will never close that gap on the current resource base. We *can* be the best forensic-output tool in a narrow segment if we lean into operator workflows, output quality, and open architecture — and refuse to oversell the label DB.
