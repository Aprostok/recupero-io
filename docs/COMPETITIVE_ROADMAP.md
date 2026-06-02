# Recupero → beyond TRM / Chainalysis / Elliptic — full capability roadmap

**Purpose:** an exhaustive, cost-no-object list of everything needed to *match* and then *surpass* the
incumbents (Chainalysis, TRM Labs, Elliptic). Each item: what it is, who has it, what we have today,
the **data source / vendor + rough cost**, build effort, and priority. Costs are order-of-magnitude
(annual unless noted) to support "pay for more data" decisions — exact pricing is quote-only/NDA.

**Where we already WIN (lean into these — the incumbents are compliance/enforcement-first, not
recovery-first):** law-firm-grade legal deliverables (LE handoff, freeze letters, subpoena/MLAT/FinCEN
314(b), engagement-letter e-sign portal), per-issuer **recovery-probability scoring**, **cross-case
correlation moat** (`address_observations`), issuer-freeze outreach workflow, answer-key-free
cryptographic bridge confirmation, TRACKED/watch category + watchlist dashboard. *Strategy to "go
past": reach data/coverage/real-time/UI parity, then compound our recovery-outcome moat they don't have.*

Legend — Priority: **P0** unblocks core accuracy/coverage now · **P1** clear competitive gap · **P2**
parity polish · **P3** moonshot/long-tail. Effort: S<1wk · M 1–4wk · L 1–3mo · XL 3mo+.

---

## A. Chain & asset coverage  (they: 40–75+ chains; us: ~22)

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| A1 | Wire the 3 label-only EVM chains into BFS (Polygon zkEVM, opBNB, Manta — were enum-only → cross-chain trace silently dead-ended) | all | **opBNB DONE (v0.35.3)** — verified on the live Etherscan V2 chainlist + wired (factory/profile/watch_tick/explorer/tests). **Polygon zkEVM (1101) + Manta (169) are NOT on Etherscan V2** (verified 2026-06-02) → remain label-only; need a non-Etherscan backend (Alchemy / native explorer) | per-chain backend adapter (Alchemy ~$ / native RPC free) | S→M | **P0** (opBNB ✓; zkEVM/Manta pending backend) |
| A2 | TON (Telegram) — major USDT-jetton laundering rail | TRM, Chainalysis | none | new adapter | Toncenter / TONAPI (~$0–2k) | M | **P1** |
| A3 | Sui + Aptos (Move chains) | TRM, Chainalysis | none | 2 adapters | native RPC + indexers (free–$5k) | M | P1 |
| A4 | XRPL + XRPL-EVM, Stellar | TRM | none | adapter | public RPC / Ripple Data (free) | M | P1 |
| A5 | Cosmos/IBC fully wired into BFS (adapter exists, not in tracer) + Osmosis/Injective/Celestia/dYdX-chain | TRM | partial | wire + IBC hop-pairing | Mintscan API (~$0–5k) | M | P1 |
| A6 | More L2s/L1s: Starknet, Hedera, Sei, Berachain, Unichain, Sonic, zkSync-Lite, Hyperliquid-L1 | all (TRM +23 in 2025) | partial | adapters | mix of explorers (~$5–20k) | L | P2 |
| A7 | **Privacy coins — Monero** (probabilistic + off-chain): ring-decoy heuristics, exchange deposit/withdraw correlation, timing/amount analysis, CT-decoy guessing; surfaced LOW-confidence "leads", never proof | Chainalysis (gov), CipherTrace legacy | none | research + module | licensed Monero tracing data / xmr node + research (HIGH $; gov-grade) | XL | P3 |
| A8 | Privacy coins — Zcash (shielded-pool entry/exit), Dash (PrivateSend), Secret Network | Chainalysis | none | adapters + heuristics | node + research ($$) | L | P3 |
| A9 | Bitcoin: extend co-spend clustering (have) with change-address heuristics, peeling, exchange-cluster attribution; Lightning channel-graph tracing (have detection only) | Chainalysis, Elliptic | partial | clustering + LN graph | 1ML / Amboss LN data (~$0–5k); BTC archive node | L | P1 |
| A10 | Stablecoin issuer reach: expand `issuers.json` (have ~9) to every freezable issuer + per-chain deploys (USDT/USDC/PYUSD/USDe/FDUSD/agEUR/EURC, etc.) + verified freeze contacts | n/a (our moat) | partial | data curation | issuer compliance contacts (free, manual) | M | **P0** |

---

## B. Attribution data at scale  (the single biggest "pay for data" lever)

The incumbents' real moat is **hundreds of millions of attributed entities** + dark-web/threat intel.
We have ~300KB of curated seeds + the live OFAC feed + a compounding cross-case index. To compete we
must license and/or harvest attribution at scale.

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| B1 | **Bulk exchange/service attribution DB** (CEX hot+deposit wallets, every major VASP, OTC desks, payment processors) | all (100M+ entities) | ~hundreds of seeds | ingest pipeline + store | **license a feed** OR harvest: Arkham (API, ~$ negotiable), Breadcrumbs, Nansen (~$1.8k+/yr), Etherscan public name-tags (scrape/ToS), 0xScope, Bitquery (~$/use) | L | **P1** |
| B2 | **Open-source label ingestion** — automate harvest of public tag sets: OFAC (have), Etherscan/Arbiscan name tags, Tron labels, MetaSleuth/Misttrack public, Chainabuse scam reports, ScamSniffer/CryptoScamDB, GitHub label repos (e.g. `ethereum-lists`), Ofac, walletlabels | partial of all | OFAC only | scrapers + dedup + confidence | mostly free (ToS-aware) + Chainabuse API | M | **P1** |
| B3 | **Dark-web / threat intel** — ransomware wallets, darknet-market deposit addresses, fraud-shop wallets, pig-butchering/“romance” clusters | TRM (300M sources/mo), Chainalysis | tiny `ransomware.json` | feed + ingest | Chainabuse, Crystal, intel vendors, IC3/FBI bulletins, Telegram-OSINT (HIGH $ for premium dark-web) | L | P1 |
| B4 | **Scam/drainer signature DB** kept current (Inferno/Pink/Angel/Ace drainers, approval-phishing) + auto-classify drainer contracts | Chainalysis (Alterya), TRM | static `high_risk.json` + `drainer_detection.py` | live feed + signature updates | ScamSniffer (~$), Scam-database, Forta (free/$) | M | P1 |
| B5 | **Attribution provenance/“glass-box”** — every label/cluster carries source + confidence + plain-language reason, court-reconstructable (TRM “glass-box”) | TRM, Elliptic | partial (confidence yes; per-source reason partial) | extend Label model + UI | internal | M | **P1** |
| B6 | **Token metadata + scam-token DB** (honeypots, rug pulls, spoof-symbol tokens — we already defeat symbol-spoofing) | all | partial (token_risk) | enrich | GoPlus (free/$), Token Sniffer, Honeypot.is | M | P2 |
| B7 | **Entity directory / “org graph”** (group addresses → entity → parent org, like Arkham/TRM custom entities) | all | role taxonomy only | entity table + clustering join | internal + B1 | L | P1 |
| B8 | **NFT/collection attribution** (wash-trade rings, stolen-NFT marketplaces) | Chainalysis (Storyline), TRM | none | module | Reservoir/OpenSea API (free/$) | M | P2 |

---

## C. Behavioral entity clustering & demixing  (algorithmic attribution)

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| C1 | **EVM behavioral wallet clustering** — group many addresses to one actor | TRM custom entities, Chainalysis, Arkham | **DONE** — `clustering.py` H1 common-funder + H2 common-withdrawal + H3 direct-transfer connected-component clustering, per-cluster confidence + glass-box evidence/heuristics, shared-infra guard, wired into brief (ENTITY_CLUSTERS → trace_report). Same-EVM-address-multichain = `high` (cryptographic) in `address_clustering.py`. **Remaining (deferred):** gas/nonce ML fingerprint + UTXO co-spend + Safe-owner graph — need extra on-chain data / ML | internal compute + archive node (for fingerprint) | done; fingerprint L | ✅ (fingerprint P2) |
| C2 | **Tornado/mixer demixing** — link deposits↔withdrawals via address-reuse, equal-denomination + FIFO timing, gas-price/relayer fingerprint, multi-deposit correlation; LOW-confidence candidate leads (≈5–35% recoverable per research, never “proof”) | Chainalysis Reactor, TRM | label-terminal stop-and-flag (v0.34.7); no demix | demix module + leads | Tornado event index (own archive node) | L | **P1** |
| C3 | **Automatic peel-chain & layering detection surfaced engine-wide** (have `peel_chains.py` for BTC; generalize to EVM + auto-flag in trace, like TRM) | TRM (automatic) | partial | wire into tracer | internal | M | **P1** |
| C4 | **Dormancy-aware value-match window** (#257 — the 72h cap blocks deep dormant Ronin reach; the cross-chain window already fixed in v0.34.4) | all (no time cap) | gap (#257 filed) | lower-bound window knob | internal | S | **P0** |
| C5 | **Cross-asset / USD value-flow matching across swaps & bridges** (have value_matching; deepen with priced multi-asset correlation) | all | partial | deepen | pricing feed (have) | M | P2 |
| C6 | **Graph algorithms** — strongly-connected-component collapse, max-flow “how much of the tainted dollar reached X” (taint propagation: poison/haircut/FIFO/LIFO models), shortest-path attribution | Chainalysis (taint), Elliptic | BFS + visited-set only | graph layer | internal compute | L | P1 |
| C7 | **Taint/“exposure” scoring models** — choose & document a taint model (haircut vs poison vs FIFO) for "% of these funds are sanctioned-exposed" (regulatory standard) | all (direct/indirect exposure) | indirect_exposure (hop-based) | formal taint engine | internal | M | P1 |

---

## D. Real-time monitoring, threat detection & alerting

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| D1 | **Live authenticated watchlist route** (in-browser, auto-refresh, "run check now") — the live operator view (in progress) | all (web app) | rendered HTML + ops CLI (v0.35.0) | FastAPI route + auth + poll | internal | M | **P0** |
| D2 | **Streaming/mempool monitoring** — sub-second movement alerts (not 5–60s poll); pending-tx watch for imminent moves on watched wallets | TRM, Chainalysis | poll loop (watch_tick) | websocket/mempool ingest | Alchemy/QuickNode WSS + mempool (Blocknative ~$, bloXroute $$) | L | P1 |
| D3 | **Real-time exploit/threat detection** (Hexagate-class) — detect key-compromise, approval-drain, governance attack, anomalous outflow on monitored protocols/wallets *as it happens* | Chainalysis Hexagate, TRM | none | detection rules + ML | Forta (free/$), own heuristics, sim (Tenderly $) | XL | P2 |
| D4 | **Auto-incident response** — on a confirmed move, auto-refresh trace, auto-draft freeze letter to the receiving CEX/issuer, auto-notify LE | n/a (our moat extension) | manual | wire monitor→trace→letter | internal | M | **P1** |
| D5 | **Risk-rules engine** (TRM has 80+ categories; configurable thresholds/rules per tenant) | TRM, Chainalysis KYT | fixed triggers (any_movement/ofac_contact) | rules DSL + UI | internal | L | P2 |
| D6 | **Proactive recovery alerts** — when dormant TRACKED funds finally move toward a freezable venue, fire a "freeze NOW" alert (extends our TRACKED moat) | n/a | watchlist surfaces it | alert rule | internal | S | **P1** |

---

## E. Screening, compliance & regulatory  (KYT parity + filings)

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| E1 | **Travel Rule / VASP** — counterparty VASP identification + IVMS101 payloads + Travel-Rule protocol interop (TRP, Notabene, Sygna, Shyft) | all (Elliptic Navigator, TRM) | none | module + protocol adapter | Notabene/Sygna network (~$$), VASP directory | L | P1 |
| E2 | **High-throughput screening API** (Elliptic: 300M screenings/qtr, P99 1.6s; bulk + webhook) — scale our `/v1/screen` (have single+bulk-100) | all | have basic | perf + queue + caching | infra | M | P1 |
| E3 | **SAR / STR auto-filing** — generate FinCEN SAR, EU STR, UK SAR formats from a case (we already produce 314(b)/MLAT) | Chainalysis, TRM (regulatory) | 314(b)+MLAT only | templates + e-file | FinCEN BSA E-Filing, goAML (free APIs) | M | **P1** |
| E4 | **MiCA / FATF / jurisdiction rule packs** (configurable per-jurisdiction compliance posture) | Elliptic (MiCA), all | jurisdiction multipliers (recovery only) | rule packs | internal + legal | M | P2 |
| E5 | **Sanctions beyond OFAC** — EU, UN, UK OFSI, OFAC SDN+CAPTA, plus per-country lists | all | OFAC live feed | multi-list ingest | public lists (free) + OpenSanctions API (free/$) | S | **P1** |
| E6 | **KYT for businesses** — exchange-side deposit/withdrawal pre-screening with risk appetite config (Chainalysis KYT core) | Chainalysis KYT, TRM | screening API exists | productize + config | internal | M | P2 |

---

## F. Live analyst workspace & UI  (their rich web app vs our rendered HTML)

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| F1 | **Interactive investigation graph** — explore/expand nodes, add hops on click, annotate, save graph, multi-chain on one canvas (Reactor/Investigator/Holistic) | all | static D3 `interactive_graph.html.j2` | live graph SPA (cytoscape/D3) backed by API | internal | XL | **P1** |
| F2 | **Authenticated operator console (SPA)** — login, case list, search any address, live trace launch, watchlist, alerts inbox | all | rendered HTML + portal token | React/Svelte SPA + session auth | internal | XL | P1 |
| F3 | **Address/entity search + profile page** (type any address → instant risk, labels, exposure, cluster, sighting history) | all | API only (`/v1/screen`, `/correlation`) | UI on existing APIs | internal | M | **P1** |
| F4 | **Collaboration** — multi-analyst case sharing, comments, assignment, audit log, saved searches | all | single-operator | multi-user model + RBAC | internal | L | P2 |
| F5 | **Case-management workspace** (queue, status board, SLA timers) — extend law-firm dashboard into live workspace | all | dashboards (HTML) | live workspace | internal | L | P2 |

---

## G. AI / automation  (2025 frontier — TRM Agents, Chainalysis Rapid)

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| G1 | **AI triage / "explain this case in plain English + next steps"** (Chainalysis *Rapid* for LE; no crypto expertise needed) | Chainalysis Rapid | `ai_editorial.py` (narrative) | triage agent over case JSON | Anthropic API (have key) | M | **P1** |
| G2 | **Agentic investigation** — LLM agent proposes next hops/subpoena targets, drafts the LE narrative, flags anomalies (TRM "Agents") | TRM Agents | none | agent loop on trace tools | Anthropic (have) | L | P2 |
| G3 | **ML risk/cluster scoring** — supervised models for entity-type classification, scam likelihood, cluster confidence (research: ~55% faster tracing) | all | heuristic scores | train models on labeled corpus | training data (from B1/B3) + GPU ($) | L | P2 |
| G4 | **Seed-phrase / key analysis** — given a recovered seed, derive + scan billions of addresses across chains for activity (TRM Seed Analysis — LE use) | TRM | none | HD-derivation scanner | own archive index | L | P3 |
| G5 | **Natural-language query** ("show all USDT that left X to a CEX in March") over our data | TRM, Chainalysis Workflows | none | NL→query layer | Anthropic (have) | M | P3 |

---

## H. Court / expert-witness / evidence  (extend our existing strength)

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| H1 | **Court-admissible exhibit pack** — paginated PDF with hashes, methodology appendix, per-edge evidence receipts, declaration/affidavit template, Daubert-ready methodology writeup | all (expert testimony) | evidence receipts + HTML→PDF | exhibit generator + methodology doc | WeasyPrint+GTK (prod has) | M | **P1** |
| H2 | **Glass-box reproducibility** — every claim links to source data + the exact heuristic + confidence, so a defense expert can reproduce (TRM "parallel reconstruction") | TRM | partial (coverage/provenance) | extend provenance | internal | M | P1 |
| H3 | **Expert-witness certification / methodology validation** — published accuracy benchmarks, peer-review-grade methodology | all (court track records) | answer-key-free validators | benchmark + writeup | internal | L | P2 |
| H4 | **Tamper-evident audit log** — append-only, signed case timeline (who ran what, when) for chain-of-custody | all | evidence receipts | signed audit log | internal (KMS ~$) | M | P2 |

---

## I. Data infrastructure  (the expensive backbone that powers everything above)

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| I1 | **Own archive/full nodes** per chain (no per-call explorer rate limits; enables clustering, demixing, taint, mempool, seed-scan, full-history) | all (own infra) | 3rd-party explorers (Etherscan/Helius/etc.) | node fleet + indexer | self-host (ETH archive ~$, multi-chain $$$) or Erigon/Reth + QuickNode/Blockdaemon archive ($$$/yr) | XL | P1 |
| I2 | **Full historical transfer index / data lake** (every transfer all chains, queryable) — powers clustering + analytics at scale | all | per-case fetch | ETL → columnar store (ClickHouse/BigQuery) | Allium / Goldsky / Dune / Bitquery ($$–$$$) or self-ETL | XL | P1 |
| I3 | **Redundant multi-provider failover** per chain (have Etherscan+Alchemy dual) — extend to all chains, with health-based routing | all | partial (EVM dual) | provider router | QuickNode/Ankr/Blockdaemon ($$) | M | P2 |
| I4 | **Price oracle depth** — historical + low-liquidity token pricing, on-chain DEX TWAP fallback (have CoinGecko) | all | CoinGecko | add DEX-pricing + paid tier | CoinGecko Pro ($$), DefiLlama (free), Amberdata ($$) | M | P2 |
| I5 | **Scale store off single Postgres** for label/observation volume at 100M+ entities | all | Supabase/Postgres | partition / OLAP tier | managed OLAP ($$) | L | P2 |

---

## J. Quality, benchmarking & trust

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| J1 | **Ground-truth benchmark suite** — score trace recall/precision vs a battery of known public hacks (Ronin, Zigha, Harmony, Nomad, FTX, Bybit, etc.) every release | internal QA at all | Zigha 4/4 fixture + answer-key-free validators | benchmark harness + public-case fixtures | public incident data (free) | M | **P1** |
| J2 | **Accuracy/coverage metrics dashboard** — published recall, false-positive rate, label freshness, chain coverage | all (trust = sales) | coverage in case JSON | metrics rollup | internal | M | P2 |
| J3 | **Label freshness SLAs + monitoring** (we have bridge-staleness monitor; generalize to all label classes + OFAC feed age alarm) | all | bridge-staleness monitor | generalize | internal | S | P1 |

---

## K. Integrations & ecosystem

| # | Capability | Incumbent | Us today | Build | Data / vendor + cost | Eff | Pri |
|---|---|---|---|---|---|---|---|
| K1 | **Public-private intel network** (TRM Beacon-style: share/receive stolen-fund intel with exchanges + LE in real time) | TRM Beacon | one-way LE handoff | network + opt-in sharing | partnerships (free–$) | XL | P2 |
| K2 | **Exchange/VASP direct freeze API integrations** (programmatic freeze requests + status, not just email) — extends our issuer-outreach moat | partial | email + filing-status | per-exchange API adapters | exchange compliance APIs (partnership) | L | **P1** |
| K3 | **SIEM / case-mgmt connectors** (Splunk, ELK, Chainalysis-style webhooks into customer stacks) | all | webhook dispatcher | connectors | internal | M | P2 |
| K4 | **Read APIs for partners** (let law firms / exchanges query our intel) — productize existing APIs | all | screening/correlation APIs | expand + SDK | internal | M | P2 |
| K5 | **IC3 / law-enforcement portal integration** (direct case referral to FBI IC3, Secret Service, Europol) | TRM/Chainalysis (gov ties) | LE handoff docs | integration | gov partnerships | L | P3 |

---

## Suggested execution order (down-payment → moat)

1. **Now / P0 (accuracy + the asks):** A1 (wire dead-end EVM chains) · C4 (#257 dormancy window) ·
   D1 (live authenticated watchlist route) · A10 + E5 (issuer reach + multi-sanctions) · J1 (benchmark suite).
2. **Quarter 1 / P1 data + clustering:** B1+B2 (attribution feed + OSS label harvest) · C1 (EVM behavioral
   clustering) · C2 (Tornado demixing leads) · C3 (auto peel/layering) · G1 (AI triage) · F3 (address/entity
   search UI) · D4+D6 (auto-incident response, proactive recovery alerts) · H1 (court exhibit pack).
3. **Quarter 2 / P1 platform:** F1+F2 (interactive graph + operator SPA) · I1+I2 (own archive nodes + data
   lake — unlocks clustering/demixing/mempool at scale) · D2 (streaming) · E1+E3 (Travel Rule, SAR/STR) ·
   K2 (exchange freeze APIs) · A2–A5 (TON/Sui/Aptos/Cosmos).
4. **Beyond / P2–P3:** D3 (real-time exploit detection) · A7–A8 (privacy coins) · G2–G4 (agentic + seed
   analysis) · K1 (public-private network) · C6 (taint/max-flow graph models).

**Biggest cost levers (pay-for-data):** B1/B3 attribution + dark-web feeds; I1/I2 archive nodes + data
lake; A7 privacy-coin tracing data. These three are what actually separate us from the incumbents — the
algorithms we can build; the *data at scale* is what costs money.

**Where we surpass, not just match:** keep compounding the recovery-outcome engine the incumbents don't
have — auto-incident-response (D4), proactive freeze-now alerts (D6), exchange freeze APIs (K2),
recovery-probability scoring, and the cross-case correlation moat. They find the money; we get it back.
