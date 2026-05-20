# Hack-Tracker — Design & Methodology

**Owner:** ops / growth
**Status:** v0.20.0 — scaffolding committed, scrapers stubbed, feature-flagged OFF
**Module:** `src/recupero/hack_tracker/`
**CLI:** `recupero-ops hack-tracker daily`
**Companion code:** `models.py` (HackEvent / HackEventSource / HackEventSeverity), `aggregator.py` (rank + dedupe), `sources/x_feed.py`, `sources/government_feeds.py`, `digest_cli.py`

This doc is the strategic methodology that the live scraper integrations
will be measured against. It exists to answer one question:
**"of all the public crypto-hack signal flowing past us every day, which
slivers actually translate into Recupero recoveries or Recupero
revenue?"** If a source/signal/event-type doesn't move recovery odds or
outreach pipeline, it doesn't belong in the digest.

The design is opinionated. We are a recovery business, not a research
publisher. That biases every ranking decision below.

---

## Section 1 — Source taxonomy

Six source families. Each gets a Recupero-specific priority rank
(CRIT / HIGH / MED / LOW). The rank is **not** "biggest publisher" — it
is "highest actionable-signal-per-noise for our recovery business."

### 1.1 X / Twitter hack-watcher accounts — **HIGH**

Canonical handles (already wired in `x_feed._X_HANDLES`):

* `@PeckShieldAlert` — autopost on detected on-chain exploits.
  Typical latency: **2–15 minutes** from exploit-tx confirmation.
  Post shape: one-liner with USD loss, victim protocol, perpetrator
  address(es), often a screenshot of the exploit-tx call trace.
  *This is the highest-leverage feed Recupero touches.* Fresh
  perpetrator addresses minutes after the theft is the difference
  between "issuer freeze possible" and "funds already in mixer."
* `@SlowMist_Team` — DPRK / Lazarus attribution specialty. Latency
  hours-to-days; depth tradeoff. Less time-critical, more
  compliance-critical (their attribution work seeds OFAC SDNs
  weeks–months later).
* `@CertiK` — postmortem + Hack3D leaderboard. Latency hours.
  Editorial weight matters when we need a cite for a freeze letter.
* `@beosin` (`beosinAlert`) — Asia-time-zone DEX incidents. Often
  first-to-publish on BSC / Polygon / TRON exploits where the
  Western researchers are asleep.
* `@BlockSecTeam` — protocol-side forensics, often with
  call-trace reconstructions. Useful for the rare case where we
  need to characterize the exploit mechanism for a legal narrative.

**Recupero rank: HIGH (not CRIT).** Why not CRIT? Because the signal
is noisy — PeckShield posts a lot of <$100K incidents that aren't
worth opening a case file on. The aggregator must filter on
`estimated_loss_usd ≥ $250K` AND `has_identifiable_victim=True` to
keep the digest signal-dense.

### 1.2 Postmortem blogs — **MED**

`rekt.news`, Immunefi PIR posts, Halborn / CertiK blogs, Trail of
Bits / OpenZeppelin write-ups.

Latency vs depth: these arrive **24h to weeks** after the incident,
but with full attribution, address graphs, and (often) the victim
contact channel. For Recupero this is mostly **confirmation /
enrichment data** — we should have caught the incident on X already;
the postmortem fills in the address graph + tells us whether the
victim has already retained someone else.

The exception that promotes rekt.news's marginal value: it
publishes rugpulls and slow-burn protocol failures that don't trip
PeckShield's automation. About 20% of rekt's output is "new to us."

**Recupero rank: MED.** Read for context; rarely the
first-touch signal.

### 1.3 Government feeds — **CRIT (compliance) + MED (marketing)**

OFAC SDN updates, OFAC cyber-advisories, FBI IC3 PSAs, CISA
advisories, FinCEN guidance.

Cadence is irregular but bursty:
* **OFAC SDN cyber additions:** ~6–18 per year. Each one
  retroactively reclassifies every Recupero case that touched the
  newly-listed addresses. **This is the only signal-type that can
  un-collect an already-collected case.** Must be processed within
  24h of publication and back-applied to the watchlist.
* **OFAC advisories** (e.g., "ransomware payment advisory") —
  quarterly-ish; changes our intake script for ransomware victims.
* **IC3 PSAs** — ~10–20 per year; the most important ones for us
  are recovery-scam advisories (impersonators in our market) and
  pig-butchering alerts (cohort outreach opportunities).
* **CISA** — high volume, low Recupero-specificity. Most CISA
  advisories are critical-infrastructure stuff that isn't crypto.
  We filter aggressively on the keyword set: "crypto" /
  "cryptocurrency" / "digital asset" / "wallet" / "DeFi" /
  "blockchain" / "DPRK".

**Recupero rank:**
* OFAC SDN: **CRIT** (compliance — has to be processed today).
* IC3 PSA: **HIGH** when it's recovery-scam or pig-butchering;
  LOW otherwise.
* CISA: **MED**, filtered.

The aggregator already weights OFAC SDN at 10.0 (top of
`_SOURCE_WEIGHT`); this is correct.

### 1.4 Industry research — **LOW (operationally), HIGH (strategically)**

Chainalysis Crypto Crime Report (annual), TRM Insights, Elliptic
quarterly reports, Inca Digital, Coinfirm, AnChain.AI reports.

These are bulk + quarterly + high-trust, but they don't tell you
about anything you can act on **today**. Their value is calibrating
the playbook: "is pig-butchering still the dominant retail-loss
vector?" "is Tron USDT still the dominant off-ramp?" "what
percentage of stolen funds are reaching CEXes within 72h?" — the
shape of the playbook, not the daily queue.

**Recupero rank: LOW for digest, HIGH for quarterly strategy review.**
Don't put quarterly Chainalysis reports in the daily-digest top-20;
do summarize them in a quarterly internal memo.

We are **not** building a scraper for these. Operator reads them
manually once per quarter.

### 1.5 Reddit + Discord — **LOW (high noise)**

`r/CryptoCurrency`, `r/scams`, `r/CryptoScams`, DeFiSafety Discord,
BlockSec Discord, occasional Telegram channels.

Signal-to-noise is awful (~95% off-topic for our purposes). Occasional
CRIT signal — sometimes a victim posts to Reddit before any
researcher has noticed the theft, especially for niche-chain or
small-protocol incidents. But ingesting Reddit at scale means
moderating spam and impersonator content.

**Recupero rank: LOW.** **Do not scrape in v1.** Revisit when the
core sources are productionized and we have ML-based spam filtering
budget.

If we **do** build it later, the right shape is *outbound search*
(operator searches `/r/scams` for "stolen USDC" once a day) rather
than *inbound feed* (full subreddit ingestion).

### 1.6 On-chain whale alerts — **MED**

Whale Alert (whale-alert.io), Lookonchain, Arkham flag feeds,
Etherscan label-watch.

Catches **flow** rather than **stories** — a $20M USDT transfer to a
fresh wallet, a large unstake from a protocol's treasury, a known
mixer-output cluster activating. The Recupero use case is
**confirmatory**: when X says "$50M exploit", whale-alert tells us
*which exact addresses* moved when, which is the watchlist entry.

**Recupero rank: MED-leaning-HIGH.** Genuinely useful but
dependency-heavy (requires us to maintain address labels). Defer to
v0.20.2 or later; in v0.20.1 we lean on PeckShield + rekt to
include the addresses inline.

---

## Section 2 — Signal taxonomy

The `HackEventSource` enum values are *where* events come from. This
section is the **what** — what kinds of events the aggregator
encounters, and how Recupero responds to each.

### 2.1 Live exploit alert (PeckShield-style)

* **Wild shape:** "🚨 @PeckShieldAlert: $42M drained from Protocol X
  on Arbitrum, attacker addr 0xabc…, exploit-tx 0xdef…, funds
  bridged to Ethereum."
* **Aggregator severity drivers:** `estimated_loss_usd` (≥$10M →
  critical; ≥$1M → high; ≥$100K → medium), presence of perpetrator
  addresses (boost), chain liquidity / off-ramp velocity (Tron /
  BSC / Solana = faster off-ramp = lower recoverability but higher
  urgency).
* **Recupero response (within 1h):**
  1. Add perpetrator address(es) to `high_risk.json` /
     watchlist.
  2. Open speculative case file flagged
     `marketing_outreach=pending`.
  3. If the victim is a **protocol** (DeFi DAO, DEX, bridge): the
     operator drafts a B2B outreach to the protocol's security
     contact — Recupero offers victim-coordination services for
     their affected users.
  4. If the victim is a **set of retail users** (drainer campaign,
     phishing site, NFT-mint heist): operator sets up cohort
     monitoring — extracted victim addresses go into a recipient
     pool for cold-email reverse-lookup outreach.

### 2.2 Postmortem (rekt-style)

* **Wild shape:** ~2,500-word writeup, 24h to weeks after the
  incident, with full address graph and attribution.
* **Aggregator severity drivers:** *Demote* if `content_hash`
  matches a prior X-feed event (we already saw this). Promote if
  the postmortem reveals victim-cohort details not in the original
  alert (e.g., the alert said "DEX hacked" but the postmortem
  enumerates 1,200 LP addresses that lost funds).
* **Recupero response:**
  1. If a fresh address graph appears: re-screen any existing
     Recupero case for indirect exposure.
  2. If retail victims are enumerated and not already
     out-reached: queue for cohort outreach.
  3. Otherwise: archive for context. No active step.

### 2.3 OFAC SDN designation

* **Wild shape:** Treasury publishes addresses + entity-name
  attributions. Press release usually accompanies via OFAC Recent
  Actions page.
* **Aggregator severity drivers:** Always `critical`. Source weight
  10.0. Recency irrelevant — even a 30-day-old SDN we missed is
  still urgent.
* **Recupero response (within 24h, compliance-mandatory):**
  1. Bulk-add to `high_risk.json` with `tag=ofac_sdn`.
  2. Re-screen the last 90 days of cases against the new addresses;
     any direct/indirect-1-hop exposure → flag the case for legal
     review before any further freeze letters go out.
  3. If a US-person Recupero customer's funds touched a now-SDN'd
     address **before** the designation: this is a known-good
     posture (sanctions are not retroactive criminal liability),
     but Recupero documents the timing in the case file.

### 2.4 Federal advisory (IC3 / CISA / FinCEN / FBI)

* **Wild shape:** PSA or advisory PDF + RSS. Most are TTPs +
  victim-protection guidance; a few are recovery-scam warnings.
* **Aggregator severity drivers:** Default `high`. Promote to
  `critical` if it names a TTP currently active in Recupero's case
  pipeline.
* **Recupero response:**
  1. Recovery-scam PSA → competitive-defense content (we write a
     blog post + LinkedIn explaining how to distinguish legit
     recovery from impersonators; SEO + reputation play).
  2. Pig-butchering surge advisory → re-engagement campaign for
     stale pig-butchering victims (those who hit our intake 3+
     months ago and didn't convert).
  3. Ransomware payment advisory → revise intake script.

### 2.5 Off-ramp seizure (exchange-side freeze publishing)

* **Wild shape:** Chainalysis Reactor / Elliptic Investigator / TRM
  Labs occasionally publish "$X seized" press releases coordinating
  with exchange compliance teams.
* **Aggregator severity drivers:** `high`. Promote `critical` if
  seizure correlates with an in-flight Recupero case (rare but
  high-value).
* **Recupero response:**
  1. Cross-check seized addresses against Recupero's active case
     ledger. A 1-hop hit is grounds for the operator to contact
     the case's victim with "good news, here's how restitution
     usually flows in these joint actions."
  2. Use as content marketing: "exchange-side freeze achieved $X
     restitution for victims of Y" — positions Recupero as
     proximate to the cases that actually recover.

### 2.6 Drainer-attribution change

* **Wild shape:** SlowMist or PeckShield tweets "Inferno Drainer
  shut down, operator moved infrastructure to Pink Drainer" or
  "AngelX is now Brand-Y on a new contract."
* **Aggregator severity drivers:** Always `high`; tag
  `drainer_attribution_change`.
* **Recupero response:**
  1. Update contract-label store — relabel old drainer contracts;
     add new ones.
  2. Update intake script for retail-phishing victims (the public
     "drainer X is back" claim affects intake questions).
  3. Content marketing: drainer-attribution write-ups attract
     organic search traffic from "drainer-X stole my crypto"
     queries → top of victim funnel.

### 2.7 Stale-victim re-engagement

* **Wild shape:** Not an external event — this is **internal
  ETL** synthesizing "victims who hit our intake N months ago and
  didn't retain" against new context (e.g., new SDN designation,
  new postmortem, new off-ramp seizure).
* **Aggregator severity drivers:** Synthetic — emitted as `info`
  severity but with `has_identifiable_victim=True`, which makes the
  ranking kicker (+5.0) fire.
* **Recupero response:** Re-engagement email — "we noticed your
  case from N months ago involved Drainer X, which OFAC just
  sanctioned. Here's what changed."

This is a v0.20.3+ feature; for v0.20.1 we focus on inbound
external sources.

---

## Section 3 — Recoverability framework

For every hack-tracker event with a victim address or victim cohort,
Recupero has to make a fast triage call: **realistic recovery odds,
0–60%**, given what we can observe. Below is the decision tree.
Numbers are operator priors based on Recupero's historical book
through v0.17.x; refine quarterly.

```
START: New hack-tracker event with victim address(es) or cohort
│
├── 1. Chain identifiable?
│   ├── NO  → UNRECOVERABLE-FROM-SIGNAL (need more data)
│   └── YES → continue
│
├── 2. Time since incident?
│   ├── < 6 hours   → bonus +10pp recovery odds (live window)
│   ├── 6–72 hours  → baseline odds
│   ├── 72h–30 days → −15pp (off-ramp likely cleared)
│   └── > 30 days   → typically advisory-only; check 4 below first
│
├── 3. Chain bucket:
│   │
│   ├── EVM (ETH / Arbitrum / Optimism / Base / Polygon / Avalanche)
│   │   ├── Funds still in stablecoin (USDC / USDT / DAI / PYUSD)?
│   │   │   ├── In an EOA / unfrozen wallet      → HIGH (~30–50%)
│   │   │   │                                       (issuer-freeze
│   │   │   │                                       path: Circle /
│   │   │   │                                       Tether / Paxos)
│   │   │   └── In a DEX/CEX deposit address     → MED (~20–35%)
│   │   │                                            (exchange-side
│   │   │                                            freeze, slower
│   │   │                                            but standard
│   │   │                                            playbook)
│   │   ├── Funds in ETH / WETH (native)?
│   │   │   └── MED-LOW (~10–20%) — no issuer freeze; depends on
│   │   │       voluntary CEX freeze at off-ramp
│   │   ├── Funds in mixer (Tornado Cash / Railgun)
│   │   │   ├── Mixed < 24h ago, attacker hasn't withdrawn yet?
│   │   │   │   → LOW-MED (~10%) — possibly traceable via timing
│   │   │   │     heuristics + Chainalysis Reactor + Zachxbt-style
│   │   │   │     correlation, but Recupero rarely wins these
│   │   │   └── Mixed > 24h ago                       → UNRECOVERABLE
│   │   ├── Funds in privacy L2 (Aztec, Polygon zkEVM private)?
│   │   │   └── UNRECOVERABLE (no on-chain visibility)
│   │   └── Funds bridged to chain Recupero doesn't track?
│   │       └── UNRECOVERABLE-FROM-SIGNAL (queue for
│   │            chain-expansion eval)
│   │
│   ├── Solana
│   │   ├── Funds in USDC (Circle-issued, freezable)?
│   │   │   → HIGH (~30–50%) — same Circle path as EVM
│   │   ├── Funds in USDT-SOL (Tether-issued)?
│   │   │   → MED-HIGH (~25–40%) — Tether will freeze given a
│   │   │     court order or reputable LE referral; slower than
│   │   │     Circle
│   │   ├── Funds in SOL / SPL non-stable?
│   │   │   → LOW (~5–15%) — depends on Magic-Eden / Phantom /
│   │   │     CEX off-ramp posture; no issuer-freeze recourse
│   │   └── Funds in privacy-mixer (Solana Tornado-Cash equivalent)?
│   │       → UNRECOVERABLE
│   │
│   ├── Tron (USDT-TRC20)
│   │   ├── Funds still in Tether-controlled freezable contract?
│   │   │   → HIGH (~40–55%) — Tether's TRC-20 freeze is the
│   │   │     single most reliable recovery path in the entire
│   │   │     Recupero playbook; this is why pig-butchering rings
│   │   │     terminate on Tron and why Recupero specializes here
│   │   ├── Funds off-ramped through Huobi/Binance/OKX deposit
│   │   │   address?
│   │   │   → MED (~15–30%) — exchange-side response varies; OKX
│   │   │     and HTX are inconsistent
│   │   └── Funds converted to TRX / non-stablecoin?
│   │       → LOW (~5–10%) — no issuer freeze; off-ramp dependent
│   │
│   ├── BSC (BEP-20)
│   │   ├── USDT-BEP20 / USDC-BEP20?
│   │   │   → MED-HIGH (~25–40%) — issuer freezes apply; Binance
│   │   │     custody adds complication (faster but more
│   │   │     paperwork)
│   │   ├── BNB / non-stable BEP-20?
│   │   │   → LOW (~5–15%) — Binance off-ramp dependent
│   │
│   ├── Bitcoin
│   │   ├── BTC in a non-custodial wallet?
│   │   │   → LOW (~5–15%) — only path is voluntary exchange
│   │   │     freeze at off-ramp; no issuer freeze; no smart-
│   │   │     contract intervention
│   │   ├── BTC ransomware ransom (already paid)?
│   │   │   → typically UNRECOVERABLE (funds reached an exchange
│   │   │     and converted within hours of payment)
│   │   └── BTC + lightning network?
│   │       → UNRECOVERABLE (no on-chain visibility post-LN)
│   │
│   └── TON / Cardano / Polkadot / Cosmos / niche
│       → UNRECOVERABLE-FROM-SIGNAL (queue for chain-expansion
│           evaluation; Recupero currently does not run these)
│
├── 4. Attack vector adjustments:
│   ├── Phishing / drainer (extracted seed via signed approval)
│   │   → use chain-bucket odds as-is
│   ├── Bridge exploit (protocol-level)
│   │   → +5pp (protocol is reachable, often coordinates)
│   ├── Smart-contract exploit (e.g., reentrancy on a DeFi protocol)
│   │   → +0pp; protocol usually communicates with exchanges itself
│   ├── Hardware-wallet seed compromise where perpetrator just
│   │   holds the funds and doesn't move them?
│   │   → UNRECOVERABLE (no off-ramp event to intercept)
│   ├── Pig-butchering (social engineering, victim sent voluntarily)
│   │   → use Tron-USDT odds (95% terminate on Tron-USDT)
│   ├── Ransomware ($BTC paid)
│   │   → typically UNRECOVERABLE; rare wins via voluntary CEX
│   │     freeze at off-ramp
│   └── Insider / rugpull (deployer extracted treasury)
│       → MED (~15–30%) if recent + traceable; depends on whether
│         the deployer has cashed out yet
│
└── 5. Victim type:
    ├── Protocol / DAO / treasury        → outreach: B2B
    ├── Whale (single 7-figure+ holder)  → outreach: direct (high-LTV)
    ├── Retail cohort (drainer victims)  → outreach: cohort email
    └── Anonymous / no contactable victim → advisory-only
```

**Honest "we can't help" list — codify these into the operator
runbook so we don't take engagements we'll lose:**

1. Funds mixed through Tornado Cash / Railgun / Aztec **more than
   24 hours** before the victim contacts us. The trace breaks; the
   funds are anonymized; we have no actor to chase.
2. Funds bridged to a chain Recupero doesn't currently track
   (Polkadot, Cardano, Cosmos, Algorand, ICP, Aptos, Sui). Re-eval
   on chain-expansion roadmap.
3. Hardware-wallet seed compromise where the attacker is patient
   and just **holds** the stolen funds. No off-ramp = no
   intercept point.
4. BTC ransomware where the ransom was paid >72 hours ago.
   Ransomware operators run tight off-ramp pipelines; the funds
   are gone.
5. Privacy-coin theft (Monero, Zcash shielded). No on-chain
   visibility.
6. Hack older than 12 months **with no fresh signal**. Statute of
   limitations on goodwill at issuers + exchanges effectively
   resets after ~9–12 months; we politely decline new engagements
   on stale, signal-less hacks unless a new development (OFAC
   designation, off-ramp seizure, attacker-address reactivation)
   resurrects the file.

---

## Section 4 — Marketing-priority signal

Not every event in the digest converts to outreach. Below is the
priority ranking, with the outreach motion for each.

The `has_identifiable_victim` boolean on `HackEvent` is the gate —
it already triggers a +5.0 ranking kicker in
`aggregator._rank_key`. This section is *what the operator does*
once that flag is set.

| Rank | Signal class | Outreach motion | Expected conversion |
|------|--------------|-----------------|---------------------|
| **1 (CRIT)** | Fresh hack <24h, victim address(es) extracted, chain Recupero supports, funds still in freezable stablecoin | **Direct outreach within 1h** — operator drafts a personalized email/X-DM to the victim or protocol. This is the highest-leverage moment in the entire pipeline | 5–15% reply, 1–3% close |
| **2 (HIGH)** | Pattern alert — drainer-X resumed, new TTP, new phishing wave | **Content marketing** — operator publishes a 600–1200 word post on recupero.io within 48h, includes "if you were affected, here's how to assess recoverability" CTA | Organic search traffic + reputation; long-tail intake |
| **3 (HIGH)** | OFAC SDN cyber designation | **Operator-internal compliance pull** — re-screen the case ledger, notify affected case-leads. No external outreach unless an existing customer is affected, in which case a "here's what this means for your case" email | Retention play, not acquisition |
| **4 (MED)** | Stale-victim cohort (3+ month old intake leads, no conversion) + new contextual signal (OFAC, postmortem, off-ramp seizure) | **Re-engagement email** with the new context. Operator-tooling generates a personalized snippet citing the new development | 2–8% reactivation |
| **5 (MED-HIGH)** | Recovery-scam advisory (IC3 / FTC / state AG warning about impersonators in our space) | **Competitive-defense content** — publish "how to verify a legit recovery firm" post, ensure Recupero is on the short list of vetted firms. Optional: paid Google ad targeting "recovery scam" intent keywords | Reputation + defense; no direct conversion goal |
| **6 (MED)** | Off-ramp seizure announcement | **Press / partner outreach** — operator pitches Chainalysis / Elliptic / the involved exchange on a referral relationship: "we're the recovery-side complement to your seizure work" | Partner pipeline (lumpy) |
| **7 (LOW)** | Generic CISA / CERT advisory (not crypto-specific) | **Read & archive**. No outreach. | None |

**Outreach motion by channel:**

* **Cold email** — for B2B (protocol / DAO) and identified-whale
  outreach. Always personalized, always cites the specific
  incident, always includes a "no obligation, free triage call"
  CTA.
* **X reply / X DM** — for victims who publicly posted about being
  hacked. Reply publicly with a tasteful "DM if you want a
  no-cost recoverability assessment"; never solicit funds in the
  public reply.
* **Blog post on recupero.io** — for pattern alerts + competitive
  defense. Mid-funnel content; SEO long-tail.
* **Paid search ad** — for the recovery-scam advisory motion only.
  Bid on the impersonator brand-names that are actively running
  scams; redirect victims to a vetted-firm comparison page.
* **Partner referral** — for off-ramp seizure events.

---

## Section 5 — Implementation priority

The current scrapers in `sources/x_feed.py` and
`sources/government_feeds.py` are stubs (each fetcher logs
"stub — returns empty pending v0.20.1"). Below is the order we
should productionize them.

The ordering criterion is **(actionable-signal-per-engineer-hour) ×
(cost-multiplier)**, not "biggest source."

### Priority 1 — OFAC SDN sync — **S effort, FREE**

* **Why first:** Free, public, no auth, low volume, highest
  signal-to-noise of any source (every SDN cyber addition is
  actionable). Compliance-mandatory regardless of marketing value.
* **Endpoint:** `https://ofac.treasury.gov/recent-actions` HTML +
  `https://ofac.treasury.gov/specially-designated-nationals-list-data-formats`
  (the SDN.XML / SDN.CSV bulk download).
* **Effort:** ~1 day. Parse the XML, diff against the prior
  snapshot, emit a `HackEvent(source=ofac_sdn, severity=critical)`
  for each new cyber-tagged entry.
* **Key needed:** None.
* **Failure mode:** OFAC's XML schema is stable but they have
  changed file URLs historically; pin to two fallback URLs and
  alert if both 404.

### Priority 2 — IC3 + CISA RSS — **S effort, FREE**

* **Why second:** Free RSS, low volume, high editorial weight.
  IC3's recovery-scam advisories alone justify the integration.
* **Endpoints:** `https://www.ic3.gov/PSA/PSARss` and
  `https://www.cisa.gov/news.xml` (both already wired as
  constants in `government_feeds.py`).
* **Effort:** ~1 day combined. Parse RSS, filter by keyword set,
  emit events.
* **Key needed:** None.
* **Filter aggressively** — CISA in particular emits high volume;
  the keyword filter is the difference between a clean digest
  and noise spam.

### Priority 3 — rekt.news RSS — **S effort, FREE**

* **Why third:** Free RSS, low volume, very high editorial trust.
  Postmortems frequently surface victim cohorts our X-feed missed.
* **Endpoint:** `https://rekt.news/feed/`.
* **Effort:** ~half-day. RSS parser, extract addresses from
  article body via the same regex we use for X.
* **Key needed:** None.

### Priority 4 — X (Twitter) v2 API — **M effort, FREE up to 500K reads/month**

* **Why fourth despite being the highest-signal source:** Auth
  complexity, rate-limit management, retweet/quote-tweet
  deduplication, the on-going risk that X changes API pricing
  again. Sources 1–3 are zero-maintenance; X requires care.
* **Endpoint:** `https://api.x.com/2/users/by/username/{handle}`
  then `/2/users/{id}/tweets`.
* **Effort:** ~3 days including:
  - Auth + retry/backoff on 429.
  - Per-handle since-id tracking so we don't re-fetch full
    histories.
  - Severity inference refinement (the current
    `_infer_severity` regex is a placeholder).
  - Retweet / quote-tweet dedup.
* **Key needed:** `RECUPERO_X_BEARER_TOKEN` from
  `developer.x.com`. Free tier (500K reads/month) is more than
  enough for 5 handles polled every 15 minutes.
* **Risk:** X has historically changed the free-tier ceiling
  without notice. Build with the assumption that we might have to
  downgrade to once-per-hour polling.

### Priority 5 — Whale Alert / Lookonchain — **L effort, FREE-to-PAID**

* **Why fifth:** High value but high dependency footprint
  (address-label maintenance). Defer until 1–4 are stable.
* **Endpoint:** Whale Alert has a paid API; Lookonchain is X-only
  (so it folds into the X integration if we add their handle).
* **Effort:** ~5 days for a real integration.
* **Key needed:** Whale Alert API key (paid tier ~$30/mo) **OR**
  scrape via `@lookonchain` X handle (free; redundant work).
* **Recommendation:** Add `@lookonchain` to `_X_HANDLES` as a
  cheap proxy; defer Whale Alert paid integration to v0.20.3+.

### Priority 6 — Stale-victim re-engagement synthesizer — **M effort, internal-only**

* **Why last:** This is internal ETL, not an external scraper.
  Depends on the other sources being live so it has something to
  cross-reference against.
* **Effort:** ~2 days. Query the case ledger for intake leads
  that didn't convert; for each, evaluate whether any new
  hack-tracker event in the last 24h provides new context;
  emit synthetic `HackEvent(source=manual)` if so.
* **Key needed:** None (internal data).

**Cumulative build estimate:** ~9 engineering-days for v0.20.1
through v0.20.3 covering items 1–4. Items 5–6 are post-v0.21.

---

## Section 6 — Top-20 hack table (TEMPLATE)

Below is the structure. A later research pass with web access
fills in the rows. Time window: most-impactful hacks of the
2020–2025 cycle, ranked by combined criteria of (USD stolen) ×
(victim contactability) × (Recupero-chain-coverage).

| # | Date | Name | Chain | USD | Vector | Attribution | Status | Recupero opportunity |
|---|------|------|-------|------|--------|-------------|--------|----------------------|
| 1 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 2 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 3 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 4 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 5 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 6 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 7 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 8 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 9 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 10 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 11 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 12 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 13 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 14 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 15 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 16 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 17 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 18 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 19 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |
| 20 | [FILL IN VIA WEB RESEARCH] | [FILL IN VIA WEB RESEARCH] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] |

**Column definitions for the research pass:**

* **Date:** YYYY-MM-DD of the publicly-known exploit / disclosure.
* **Name:** the canonical name (e.g., the protocol that was
  exploited, or the perpetrator group + month).
* **Chain:** primary chain(s) the theft occurred on. Use the
  same vocabulary as `x_feed._extract_chains_mentioned`.
* **USD:** estimated USD value at time of theft.
* **Vector:** one of `phishing_drainer`, `bridge_exploit`,
  `smart_contract_exploit`, `pig_butchering`, `rugpull`,
  `private_key_compromise`, `social_engineering`, `ransomware`,
  `exchange_hack`, `validator_compromise`, `supply_chain`,
  `flash_loan`, `oracle_manipulation`.
* **Attribution:** DPRK/Lazarus, Drainer-X, anonymous, insider,
  etc.
* **Status:** `recovered_fully` / `recovered_partial` /
  `unrecovered` / `mixed` / `frozen_pending`.
* **Recupero opportunity:** one-line characterization — does this
  hack-shape match a Recupero engagement we'd take?
  Examples: "exemplar — Tron-USDT pig-butchering, our core
  motion"; "out-of-scope — Monero shielded txs";
  "advisory-only — funds reached privacy mixer within hours."

---

## Closing — what this doc is for

This is the **methodology that the v0.20.1 scrapers and v0.21
operator workflows will be built against.** Three operating
principles:

1. **Signal > volume.** A daily digest with 8 high-signal events
   beats one with 80 mixed-quality events. The aggregator's job
   is ruthless filtering.
2. **Recovery odds drive ranking.** Hack-tracker exists to feed
   Recupero's recovery business, not to be a research feed.
   Events that can't translate to either a customer engagement
   or a compliance posture change are demoted regardless of
   newsworthiness.
3. **Be honest about what we can't help with.** Section 3's
   UNRECOVERABLE list is as important as the HIGH list. Better
   to decline early than collect intake fees on a case that
   structurally can't be won.

When ambiguity arises during the v0.20.1 build, default to the
choice that makes the digest **shorter, denser, and more
actionable**.
