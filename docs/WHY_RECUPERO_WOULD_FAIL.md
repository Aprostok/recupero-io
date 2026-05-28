# Why Recupero Would Fail in Production — and What to Fix Before Shipping

HEAD: `0cb3bb4` (v0.31.5). The code is in solid shape: 4453 tests pass,
43/43 mutations detected, every honest-gap from `V031_3_HONEST_GAPS.md`
closed. But "the code works" is not the same as "the product works."
This document is the pre-mortem that the regression suite cannot run.

The failure modes below are ranked by company-killing severity, not by
how interesting they are to fix.

---

## Tier 0 — Failures that end the company

### 0.1. ONE wrong brief, in a real legal proceeding

The biggest existential risk. Recupero generates documents that go to
exchanges, law enforcement, courts. If a brief contains a forensic
error — labels Address X as "Binance hot wallet" when it isn't, names
a third party as "perpetrator" with high confidence and they aren't,
mis-attributes flow through a contract proxy — the resulting fallout
is:

  * Defamation suit from the falsely-named party
  * Loss of LE trust ("their last brief was wrong; we can't use them")
  * One published news cycle and the brand is done

**What's missing:**

  - There is no MANDATORY HUMAN REVIEW GATE before a brief leaves the
    system. The `UNSIGNED` watermark is a disclaimer, not a workflow
    enforcement. Operators can — and will — send briefs unreviewed.
  - We have no E&O insurance policy of record. We need it before the
    first paid case.
  - We have no formal disclaimer language vetted by counsel. The brief
    template's caveat sections are author-written, not lawyer-written.
  - INVARIANTS A-E catch SHAPE errors (manifest SHA, address-key
    canonicalization, USD conservation). They do not catch SEMANTIC
    errors ("this address is labeled but the label is wrong").

**What to fix before going live:**

  1. Add a `brief.review_status` column. Default `awaiting_review`.
     The dispatcher refuses to send any brief whose status is not
     `human_reviewed_approved`. Time-box review at 24h with operator
     escalation.
  2. Sign an E&O policy. Range: $1M-$5M coverage at our case volume.
  3. Have an attorney write the disclaimer footer. Update every
     12 months as case law evolves around crypto-forensics output.
  4. Add a "confidence threshold for issuer outreach" — DON'T send a
     freeze letter naming an address unless the label confidence is
     `high` AND there are >= 2 independent sources for it.

### 0.2. The first time a paid customer recovers $0

Crypto theft recovery has a statistical base rate around 2-5% in
ideal cases (Chainalysis 2024 report). Most victims who pay $499
will NOT recover funds. When word spreads that "Recupero doesn't get
your money back," the funnel collapses.

**What's missing:**

  - The intake portal makes no quantitative recovery promise, but it
    also makes no quantitative WARNING. A victim paying $499 in panic
    is not in a state to read fine print.
  - We do not measure our recovery rate. We measure brief-generation
    success and freeze-letter-sent counts. THOSE ARE NOT RECOVERIES.
  - The v0.21.0 outcome-intake API exists; nothing forces operators to
    actually capture outcomes when they happen. We have no SLA on
    outcome-reporting.

**What to fix:**

  1. Add a pre-checkout calculator: "Cases with your shape recover
     funds X% of the time within Y months." Show actual historical
     base rates computed from `freeze_outcomes` table. If the table
     is empty, show the Chainalysis published rate (~3%) and label
     it as such.
  2. Make outcome-reporting MANDATORY for the operator. The case
     can't be marked `closed` until outcome is captured (success,
     partial, no-recovery, dropped). Even `no-recovery` is a valid
     outcome we MUST record so the calculator works.
  3. Publish a quarterly recovery-rate report. Include sample size,
     median time to recovery, recovery-rate by exchange. This is
     simultaneously a sales tool AND honesty.
  4. Refund policy: at minimum, partial refund if no LE handoff
     attempted within 7 days. Industry standard for diagnostic
     services.

### 0.3. The product becomes a "what to avoid" manual

If Recupero becomes well-known (which is the goal), the codebase +
`labels/seeds/bridges.json` + `cex_deposits.json` are an open-source
blueprint for adversaries: "here's exactly what Recupero detects;
route around it." A sophisticated perpetrator with $250K of stolen
funds will pay $5K for a security consultant who reads our README.

**Specific routes already documented in the repo:**

  - Sub-`min_fanout` dust attacks: 9 destinations instead of 10
  - Bridges not yet in our DB (any post-v0.31.5 protocol launch)
  - Mercury Layer / Penumbra / other statechain protocols (we detect
    shape but can't unwrap)
  - CEX → atomic-swap to another CEX (no native bridge)
  - PFP-laundering: trade BTC for an NFT for ETH for stablecoin in
    4 swaps via 4 different DEXes
  - Privacy-pool aggregators (Privacy Pools, Nocturne v2 if it ships)

**What to fix:**

  1. Internal-only threat-intel deltas. Maintain a private
     supplementary `bridges_private.json` + `cex_deposits_private.json`
     that ships only inside the production container, never in the
     public repo. The public seed file becomes the "trailing 90 days
     behind production" version.
  2. Heuristic randomization. Don't ship the dust-attack thresholds
     (`min_fanout=10`, `threshold=$1`) as defaults that anyone can
     read. Add a per-deploy salt so adversaries who guess them by
     measuring our output can't generalize across deployments.
  3. Decoy-detection layer: run multiple alternative heuristics
     simultaneously and only surface the highest-confidence one. A
     perpetrator who routes around heuristic A but not B still gets
     caught.
  4. Active intel ingestion. v0.31.5's cron scheduler only refreshes
     OFAC sanctions. We also need to pull from Chainalysis Reactor
     (paid), TRM Tagged Data, and emerging-bridge feeds. Daily.

---

## Tier 1 — Failures that cripple but don't kill

### 1.1. Adversary adaptation faster than label-DB updates

A new bridge launches Monday. We add it to `bridges.json` Friday.
Five days of cases pass through it undetected. By the time we
backfill (v0.31.2 cron does this), the funds have moved 3 hops
further and are unrecoverable.

**What's missing:**

  - The v0.31.2 retrace backfill cron runs DAILY. New bridge
    detection-to-coverage SLA needs to be HOURS, not days.
  - We have no automated "new bridge contract detected" alert from
    DeFi monitoring.
  - The label DB only updates from our manual seed additions. No
    pipeline ingests from Tronscan / Etherscan / Solscan public tags
    automatically.

**What to fix:**

  1. Implement an auto-ingest cron job that pulls Etherscan address
     tags hourly (it's a free API with a small rate limit) and
     proposes additions to `bridges.json` / `cex_deposits.json`.
     Operator approves via a one-click dashboard.
  2. Subscribe to DeFiLlama's "new protocol" feed; flag any new
     "Bridges" category protocol for same-day review.
  3. Run the retrace backfill cron HOURLY for cases < 30 days old
     (when funds are most likely still moving) and DAILY for older.

### 1.2. CEX hot-wallet rotation makes our labels stale

Binance rotates hot wallets quarterly. Our v0.31.2 Tron entries are
all dated `2026-05-26`. By Q3 2026 they're stale; by Q4 they're
addresses owned by someone else entirely. The brief mis-labels and
the operator unknowingly sends a freeze letter to the wrong issuer.

**What's missing:**

  - The v0.31.4 `stale_label_alert` cron job FLAGS labels > 90 days
    old. It does NOT auto-refresh them. An operator has to act on
    the report.
  - The cron job report goes to `data/stale_labels.json` — there is
    no email/Slack alert wired.

**What to fix:**

  1. Auto-refresh from Etherscan/Tronscan/Solscan tags before the
     90-day deadline. The auto-ingest pipeline from 1.1 covers this.
  2. Wire the stale-label cron to email/Slack the on-call operator
     when stale_count > 0.
  3. Label expiration policy: any label > 180 days old without a
     refresh has its confidence DOWNGRADED automatically (high → med,
     med → low). The brief still surfaces it but operators see the
     decay.

### 1.3. Single-instance cron, no high availability

The v0.31.4 cron scheduler runs as ONE process on ONE Railway
service. If that container restarts mid-OFAC-sync, sanctions data
goes stale silently for up to 24h. No leader election, no fallback
runner, no alerting.

**What's missing:**

  - We have no Postgres-backed leader election. Adding a second
    cron instance would double-fire every job.
  - We have no Sentry / Honeybadger / OpsGenie wiring for job
    failures. The cron's `try/except Exception → log.exception`
    just dumps to stdout.
  - We have no health endpoint that an external monitor can hit
    to verify "last cron success was < 25h ago."

**What to fix:**

  1. Add a `cron_jobs_lock` Postgres table with `(job_name,
     leader_id, expires_at)` row. Use `SELECT … FOR UPDATE SKIP
     LOCKED` to elect one leader per job.
  2. Wire structured-log alerting. The cron scheduler's per-job
     ERROR log should fire a webhook to the on-call channel.
  3. Add `/cron/healthz` endpoint to the worker that reports
     `{job_name: last_success_utc}` for each scheduled job. External
     uptime monitor (Better Uptime, Pingdom) hits it every 5 min.

### 1.4. API rate limits at customer scale

Etherscan V2 free tier: 5 req/s, 100k req/day. Helius free: 100k/day.
CoinGecko free: 5-15 req/min. A single multi-chain Zigha-shape trace
makes 50-200 API calls. At 50 cases/day we burn the free tiers by
noon.

**What's missing:**

  - No upgrade path documented for moving Etherscan / Helius /
    Alchemy / CoinGecko / DeFiLlama to paid tiers in a single config
    flip.
  - No per-customer rate budgeting. One whale case (10k transfers)
    burns the day's budget for everyone.

**What to fix:**

  1. Document `ETHERSCAN_API_KEY` provider migration (free →
     Etherscan Pro $399/mo unlocks 10x quota). Same for Helius, etc.
  2. Add a per-case "API budget cap" gate: case stops fetching if
     it consumes > $0.50 in API costs (using the existing
     RECUPERO_AI_MAX_USD_PER_CALL pattern). Operator can override.
  3. Add a daily budget dashboard showing per-provider usage so
     operators see the burn-down before the cliff.

---

## Tier 2 — Operational decay that compounds

### 2.1. Cooperation Dashboard tracks but doesn't act

We measure issuer responsiveness (Tether says yes 65% of the time;
Binance silence_14d 30%) but we have no automated escalation. The
brief recommends "next step: subpoena via AUSA" — and then the
operator has to manually go find an AUSA who'll sign it. Most don't.

**What's missing:**

  - No AUSA contact directory by jurisdiction.
  - No prefill of the subpoena form for the operator.
  - No tracking of subpoena outcomes beyond "letter sent."

**What to fix:**

  1. Build the AUSA contact directory (it's public per district).
     Surface "your closest AUSA" in the brief.
  2. Pre-render a subpoena template + Exhibit C package for each
     case where the freeze letter went unanswered after 14 days.
  3. Recovery snapshot quarterly report should include "subpoena
     conversion rate" — i.e., of cases where we issued a subpoena
     recommendation, how often did funds actually freeze.

### 2.2. PDF rendering is fragile

WeasyPrint depends on libgobject / cairo / pango. Operators have
already hit "PDF generation skipped" errors on Windows (logged in
test runs). When a lawyer client requests a "signed PDF" and gets
"HTML only," it reads as unprofessional.

**What's missing:**

  - The fallback when WeasyPrint fails is to skip PDF entirely.
    Lawyers don't accept HTML.
  - We have no formally-formatted "executive summary" PDF that's
    distinct from the operational brief. Lawyers want 3-5 page
    summaries, not 50-page traces.

**What to fix:**

  1. Move PDF rendering off WeasyPrint to a hosted service (DocRaptor,
     PrinceXML) for the production deploy. Keep WeasyPrint as the
     local-dev fallback. The cost is ~$0.05/PDF — well within margin.
  2. Add an `executive_summary.pdf` artifact: 5 pages, 12-point font,
     legal-style formatting. Generated alongside the operational
     brief.
  3. Pre-flight every brief through a real PDF renderer in CI so we
     catch render failures before they hit operators.

### 2.3. Time-zone drift

`Case.incident_time` is UTC. The intake form lets victims enter
local time. We coerce to UTC but the conversion isn't always
unambiguous (DST transitions, victim who flew across timezones
between theft and reporting). A 3-hour shift moves which transfers
are "within incident window" vs "noise."

**What's missing:**

  - The intake form doesn't ask for the victim's timezone explicitly.
    It infers from browser TZ which can be wrong (VPN).
  - The brief renders incident_time as UTC only. Lawyers read in
    local court time.

**What to fix:**

  1. Mandatory timezone-picker on intake. Default to victim's
     browser TZ but require confirmation.
  2. Brief renders incident_time in BOTH UTC and the victim's local
     time, with the conversion explicit.
  3. Cross-chain time window (RECUPERO_CROSSCHAIN_WINDOW_HOURS)
     should round up by 1 hour to absorb timezone drift uncertainty.

### 2.4. Onboarding burden

The codebase is now ~1M tokens, ~200 markdown docs, 4453 tests, 6
years of "v0.X.Y" decisions documented in docstrings. A new
engineer needs WEEKS to be productive.

**What's missing:**

  - No architectural overview doc that says "here's the call graph,
    here's where to start, here's the invariants you must preserve."
  - The "Jacob-style" punishing-test pattern requires senior judgment
    to apply. Junior engineers will write happy-path tests that
    don't catch regressions.
  - Bus factor of 1.

**What to fix:**

  1. Write `docs/ARCHITECTURE.md` — 5000 words max, with a call
     graph, the invariants A-E plain-English, and the v0.31.x
     additions explained.
  2. Pair every senior engineer with a junior on punishing-test
     reviews. The pattern is the value, not the test count.
  3. Hire a second senior engineer before the first one wants
     vacation.

---

## Tier 3 — Issues to monitor (won't kill but compound)

### 3.1. AI editorial quality
  - GPT-4 calls cost real money per case ($2 cap).
  - The editorial can hallucinate. Mitigation: the JSON-only
    contract + INVARIANT D (no AI output without source citation).
    But hallucinations within a citation are not caught.

### 3.2. Cross-chain via non-bridge mechanisms
  - Circle CCTP, Tether redemption, atomic swaps via centralized
    OTC desks — none are "bridges" but all move value cross-chain.
  - Currently invisible to our trace.

### 3.3. Smart-contract proxy upgrades
  - A bridge contract whose implementation changes mid-trace
    can shift its calldata layout. We'd silently mis-decode.

### 3.4. State-tax / IRS-CI handoff
  - The Subpoena artifact family targets DOJ/AUSA. State AGs
    and IRS-CI have different evidentiary formats.

### 3.5. International issuers
  - We have US-centric coverage. EU issuers (Bitstamp,
    Kraken-EU), Asia issuers (Coincheck, Bitflyer), have
    different compliance posture and different forms.

### 3.6. Mobile / accessibility
  - The brief HTML is desktop-only. Lawyers read on iPads. The
    portal intake form should be mobile-first.

---

## The five things to fix BEFORE the first paid customer

If we had a week of executive attention, the highest-ROI items are:

  1. **Mandatory human-review gate on every outbound artifact.**
     `brief.review_status` column + dispatcher gate. Zero code
     complexity, removes the single biggest legal risk.

  2. **E&O insurance + lawyer-vetted disclaimer.** Operational
     decision, not engineering.

  3. **Honest recovery-rate disclosure on intake.** Compute from
     `freeze_outcomes`; show the historical base rate; require
     informed consent before payment.

  4. **Cron leader election + ERROR webhook.** Two-day engineering
     spike; closes the single-point-of-failure on data freshness.

  5. **Auto-ingest pipeline for new bridges + CEX wallets.** A
     monthly seed-data refresh job using Etherscan/Tronscan public
     tag APIs. Closes the label-DB-staleness cliff.

Everything below this line is post-launch optimization.

---

## What we have actually done well

This is the honest-flip-side that v0.31.x earned the right to claim:

  - INVARIANTS A-E catch shape errors before any artifact ships
  - Adversarial-input + property-based + mutation testing layers
  - 43/43 mutations detected, 4453 tests passing, 0 xfailed
  - Point-in-time labels (closed in v0.31.4) — the forensic claim
    "this was a known mixer at the time of theft" is now actually
    enforceable in court
  - 13 bridge decoders covering 11+ protocols
  - 19 chain adapters
  - Real OFAC sync with strict-mode failure + last_synced_utc
  - Mercury Layer + Wasabi + Whirlpool shape detection
  - Cron scheduler with three real jobs and a documented deploy
    pattern
  - Zigha golden-case E2E fixture catching pipeline regressions in
    CI
  - Honest gap-audit cadence — every six months an outside-eye
    review surfaces and closes 15-20 gaps

The code is in a good place. The PRODUCT — pricing, distribution,
legal posture, customer-success — is where the failure modes live.

That's the work for v0.32.x and beyond.
