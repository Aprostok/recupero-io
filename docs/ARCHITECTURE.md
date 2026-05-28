# Recupero Architecture

This is the document a new engineer reads on day one. It is intentionally
terse — five thousand words, not fifty thousand. Every section points at
the modules and tables so you can drop into source and find the real
thing fast.

See `docs/WHY_RECUPERO_WOULD_FAIL.md` for the pre-mortem this doc
deliberately does NOT cover — that file is where the philosophical
"what's missing" lives.

---

## 1. What Recupero is

Recupero is a crypto-theft recovery pipeline. A victim files an intake
form; the system traces the stolen funds across one or more chains
(Ethereum, BSC, Arbitrum, Polygon, Base, Optimism, Solana, Tron,
Bitcoin, plus 14 more EVM chains via Etherscan V2 multichain),
identifies destination wallets, generates freeze letters to exchanges,
hands off to law enforcement, and tracks the recovery outcome. The
deliverable is a packet of documents — a forensic brief, a freeze
letter per exchange, an LE handoff package, an executive summary —
that an operator reviews, signs, and dispatches.

```
intake → trace → enrich → emit_brief → review-gate → dispatch → outcome-tracking
  |        |        |          |             |           |             |
portal/  trace/  trace/      reports/   v0.32 brief_   dispatcher/  freeze_outcomes
server   tracer  cross_chain emit_brief  reviews                    + monitoring
  +     + chain/ clustering   + ai_       gate                       /watch_tick
  v0.25 adapters indirect_    editorial
  intake          exposure   + output_
  form           cex_         integrity
                 continuity   validator
```

Single-process Python service. Postgres (Supabase) for state. Optional
Sentry + Prometheus exporters. One worker replica on Railway with HA
cron leader-election in v0.32.

---

## 2. The pipeline

### 2.1 Intake (`src/recupero/portal/server.py`, `api/app.py`)

The customer-facing portal is a FastAPI app. `POST /v1/intake` accepts
an unauthenticated form with theft narrative + addresses + tokens.
v0.25 added the form; v0.32 adds the `recovery_disclosures` table that
makes the customer ACK the published recovery-rate base rate before
the engagement can move forward.

Pre-checkout: the disclosure layer (`src/recupero/monitoring/recovery_rate.py`)
computes the Recupero historical recovery rate from `freeze_outcomes`
and surfaces it to the intake form. If the table is empty the
Chainalysis ~3% public figure is shown with explicit attribution. The
customer's checkbox click is stored alongside the case row.

Stripe webhooks at `payments/webhook.py` carry the diagnostic ($499) /
engagement ($10K) payment events; on confirmation the case advances
to `state=traced_pending` and the worker picks it up.

The intake-form CSRF allow-list lives in `RECUPERO_INTAKE_ALLOWED_ORIGINS`.
Empty / unset falls back to same-origin against the request Host
header. The 21-day portal token (HMAC-pepper'd via `RECUPERO_TOKEN_PEPPER`)
is what lets the victim view their case status.

### 2.2 Trace (`src/recupero/trace/tracer.py`)

A wave-based BFS. Starts at the seed address, fans out per-depth
through a `ThreadPoolExecutor` (`RECUPERO_TRACE_CONCURRENCY`, default
5), terminates on any of: max-depth hit, deadline elapsed
(`RECUPERO_TRACE_TIMEOUT_SEC`), transfer cap hit
(`RECUPERO_MAX_TRANSFERS_PER_CASE`), v0.32 API-budget cap hit
(`RECUPERO_API_BUDGET_USD_PER_CASE`), or natural BFS exhaustion.
Partial-trace status is recorded on `case.config_used.trace_status`.

Chain adapters live under `src/recupero/chains/`. Each adapter
implements the `ChainAdapter` interface (`chains/base.py`) and wraps a
thin HTTP client: EVM via `chains/ethereum/etherscan.py` (Etherscan V2
multichain — one endpoint, different `chain_id`), Solana via Helius
(`chains/solana/helius.py`), Tron via TronGrid (`chains/tron/client.py`),
Bitcoin via Esplora (`chains/bitcoin/esplora.py`). The EVM adapter
optionally swaps in Alchemy via `--prefer-alchemy` (`chains/evm/alchemy_client.py`).

Bridge calldata decoders for cross-chain handoff live at
`trace/bridge_calldata.py` (v0.31.0 added Connext, Axelar, LiFi
alongside Wormhole, Stargate, Hop, Across, deBridge). When the trace
hits a bridge contract, the decoder pulls the destination
chain + recipient address and the cross-chain continuation pass
re-traces on the destination chain bounded by
`RECUPERO_CROSSCHAIN_WINDOW_HOURS`.

DEX-swap continuation (`trace/dex_swaps.py`) does the same for
in-chain DEX hops — without it the trace dead-ends at the 1inch /
Uniswap router and never reaches the swap output recipient. Both
continuation passes share the budget tracker so the cap holds.

Pass 2 — perpetrator trace (`trace/perpetrator_trace.py`) — runs an
adjacent BFS rooted at consolidation-hub candidates the primary
trace surfaced. Gated by ratio + balance thresholds.

### 2.3 Enrichment

After the BFS returns, several passes run over `case.transfers`:

* `trace/cross_chain.py` — surfaces cross-chain handoffs into the
  brief's CROSS_CHAIN_HANDOFFS list using the bridge-label DB
  (`labels/seeds/bridges.json`, ~178 entries as of v0.31).
* `trace/indirect_exposure.py` (v0.31.0) — MVP scorer for
  N-hop-removed perpetrator exposure with per-hop decay
  (`RECUPERO_INDIRECT_DECAY`).
* `trace/clustering.py` (v0.31.0) — shared-infrastructure address
  clustering (gas funder + UTXO co-spend heuristic).
* `trace/mev_detection.py` — flags MEV-bot interactions.
* Dust-attack filter (in `tracer.py`, gated by
  `RECUPERO_DUST_ATTACK_FILTER`) — strips dust-shower fan-out from
  Section 5 of the brief without losing the audit trail.
* `trace/cex_continuity.py` — opt-in heuristic
  (`RECUPERO_CEX_CONTINUITY`) matching CEX-deposit ↔ CEX-withdrawal
  pairs in a configurable time window for cross-CEX continuity leads.

### 2.4 Brief assembly (`src/recupero/reports/emit_brief.py`)

Builds `freeze_brief.json` — the canonical structured case payload —
then renders the operator-facing HTML/PDF deliverables. Lives under
`reports/`:

* `brief.py` — the master forensic brief.
* `_le_handoff.py` — DOJ/AUSA-shape handoff document.
* `_victim_summary.py` — plain-English summary.
* `_engagement_letter.py` / `_recovery_snapshot.py` — pre-engagement
  packet.
* `_issuer_freeze_request.py` — per-issuer freeze-letter rendering.
* `ai_editorial.py` — Claude API calls for the AI-drafted prose
  fields. JSON-only contract; INVARIANT D enforces no AI output
  ships without a source citation. Per-call USD ceiling via
  `RECUPERO_AI_MAX_USD_PER_CALL`.

Every deliverable runs through `validators/output_integrity.py` —
the 25+ INVARIANTS that catch SHAPE bugs (manifest SHA, canonical
address keys, USD conservation, no NaN/Inf in totals, etc.). See §3.

PDF rendering uses WeasyPrint. `RECUPERO_DISABLE_PDF_RENDER=1` is the
OOM kill switch on Railway. v0.32 will likely move this to a hosted
service (DocRaptor) — see pre-mortem §2.2.

### 2.5 Review gate (v0.32 — `migrations/028_brief_review_status.sql`)

Tier-0 gap closure from `docs/WHY_RECUPERO_WOULD_FAIL.md` §0.1. The
`brief_reviews` table tracks every deliverable's review state
(`awaiting_review` / `approved` / `rejected`). The dispatcher refuses
to send any brief whose row is not `approved`. INVARIANT F (added
v0.32) makes this a hard fail in the validator chain so the gate
can't be bypassed by an operator monkey-patching `state=...`.

The hourly `review_sla_scan` cron job (see §5) flags any
`awaiting_review` row older than `RECUPERO_REVIEW_SLA_HOURS` (default
24h) so the dashboard surfaces overdue reviews to ops.

### 2.6 Dispatch (`src/recupero/dispatcher/`)

Sends approved deliverables to recipients. Three channels:

* `email` — Resend transactional API, gated by
  `RECUPERO_EMAIL_FROM` + `RESEND_API_KEY`. Outbound to
  exchange compliance teams (CEX deposit addresses) and the
  victim's LE point-of-contact.
* `webhook` — partner integrations (compliance APIs, monitoring
  feeds). SSRF allow-list at `RECUPERO_WEBHOOK_ALLOWLIST_HOSTS`.
* `bucket upload` — Supabase Storage for the signed PDF deliverable
  bundle the lawyer downloads.

The dispatcher logs every send to `freeze_letters_sent` and stamps
the `letter_tier` (S/M/L based on case size — renamed from
`letter_language` in v0.31.x for clarity).

### 2.7 Outcome tracking (`src/recupero/api/app.py` — `/v1/freeze-outcomes`)

The post-dispatch loop. Exchanges and LE partners POST back when funds
are frozen / unfrozen / wired-back / declined; the outcome lands in
`freeze_outcomes`. Per-key authorization is deny-by-default via
`RECUPERO_API_KEY_ISSUERS` (issuer-scoped) + `RECUPERO_API_KEY_ADMINS`
(universal).

The recovery-rate calculator (`monitoring/recovery_rate.py`) reads
this table to compute the published historical base rate the intake
disclosure surfaces. Recovery rate is computed quarterly and exposed
via the `recupero-ops recovery-rate` CLI command.

---

## 3. Invariants (`src/recupero/validators/output_integrity.py`)

The brief renderer can produce shape-correct nonsense. INVARIANTS A-F
catch the most damaging shape errors at write time so a poisoned brief
never reaches the operator.

* **INVARIANT A — manifest SHA**: every artifact in a deliverable
  bundle has its SHA-256 in the manifest. A tampered or truncated
  PDF can never silently slip in. Catches: filesystem corruption,
  partial writes, malicious modification post-render.
* **INVARIANT B — canonical address keys**: every address in the
  brief is stored in canonical form (EVM lowercase, base58
  case-preserved). Pre-v0.20.x bugs treated `0xABCD...` and
  `0xabcd...` as different addresses and double-counted. Catches:
  forensic-double-count, dedup misses.
* **INVARIANT C — USD conservation**: per-issuer freeze-target
  USD figures sum to ≤ total stolen USD. Catches: over-claiming
  in freeze letters (which can constitute fraud).
* **INVARIANT D — no AI output without source citation**: every
  AI-drafted field in the brief must point to a source `case.json`
  field. Catches: editorial hallucinations that don't trace to
  case evidence.
* **INVARIANT E — finite USD**: no NaN, no ±Infinity, no negative
  USD in any rendered total. Catches: poisoned upstream prices
  (CoinGecko NaN, DeFiLlama bad cache), arithmetic overflow.
* **INVARIANT F — review-gate enforcement (v0.32)**: dispatcher
  refuses to send a brief whose `brief_reviews.status` is not
  `approved`. Catches: rogue operator dispatching unsigned.

What invariants do NOT catch is SEMANTIC error: a label is wrong, a
contract proxy upgrade silently changed calldata layout, a forensic
heuristic produced a confident-but-incorrect attribution. The
mandatory human-review gate exists because shape-correctness is not
semantic-correctness. See pre-mortem §0.1.

---

## 4. Where state lives

### 4.1 Filesystem (`<RECUPERO_DATA_DIR>/cases/<case_id>/`)

* `case.json` — the canonical case state (transfers, exchange
  endpoints, config_used, trace_status). This is the source of
  truth for one case.
* `transfers.csv` — same data flattened for spreadsheets. v0.x
  hardened the formula-injection vector (CWE-1236).
* `briefs/` — every rendered deliverable. HTML primary, PDF
  optional. Manifest carries SHAs.
* `evidence/` — per-transaction `EvidenceReceipt` JSON bundles
  with raw RPC responses for the chain-of-custody trail.
* `tx_evidence/` — per-hop normalized transfer evidence written
  during the BFS walk.

`RECUPERO_DATA_DIR` defaults to `./data` — operators mounting a
persistent volume on Railway point this at the mount point so
data survives container restarts.

### 4.2 Postgres (Supabase) — the durable state

* `investigations` — one row per case (intake metadata, state, the
  worker-claim heartbeat).
* `freeze_letters_sent` — every freeze letter, with `letter_tier`,
  channel, dispatch timestamp.
* `freeze_outcomes` — every outcome reported back from an issuer
  or LE partner.
* `brief_reviews` (v0.32) — the review-gate state machine.
* `cron_jobs_lock` (v0.32) — leader-election + per-job heartbeat
  for the cron scheduler.
* `label_candidates` (v0.32) — operator-curation queue for new
  labels surfaced by the auto-ingest cron.
* `recovery_disclosures` (v0.32) — customer-ACK rows for the
  recovery-rate disclosure on intake.
* `cases_clusters` — case-to-cluster mapping for aggregated
  LE handoffs.
* Helper tables: `price_cache`, `subscriptions` (monitoring),
  `audit_log` (append-only ops audit).

Migrations live under `migrations/NNN_name.sql`. Always additive;
breaking changes get a paired backfill script.

### 4.3 Storage bucket (Supabase)

Persistent artifacts go up to the bucket via `storage/supabase.py` —
PDF deliverables, evidence bundles, the signed manifest. Lifecycle:
public read for the disclosed PDF, private for evidence and
case.json mirror.

### 4.4 Label DB

`src/recupero/labels/seeds/*.json` carries the curated label
ground-truth (bridges, exchanges, mixers, OFAC, dust-attack,
ransomware, etc.). `LabelStore` (`labels/store.py`) loads + does
point-in-time lookups (`lookup_pit_safe`, v0.31.4).

`label_candidates` Postgres table holds the operator-curation queue.
v0.32's `label_auto_ingest` cron pulls candidate labels from
upstream tag APIs (Etherscan tags, Solscan tags) and writes them
here — `RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP` (default 100) limits
the daily flush so the review queue doesn't get buried.

Confidence decays at lookup time (`RECUPERO_LABEL_DECAY_DAYS`,
default 180d): a stored `high` not refreshed in 180d reads as
`medium` to callers; the seed file itself is never mutated.

---

## 5. The cron stack (`src/recupero/worker/cron_scheduler.py`)

v0.31.4 added the in-process scheduler; v0.32 added HA + alerting.
Five jobs ship:

* **`ofac_sync`** — 04:00 UTC daily. Downloads OFAC SDN list,
  parses XML, refreshes `labels/seeds/ofac_crypto_live.csv`. XXE
  + billion-laughs hardened (v0.31.x RIGOR-2a).
* **`retrace_backfill`** — 05:00 UTC daily. Re-traces stale
  monitored cases against the current label DB so freshly-labeled
  perpetrator addresses surface.
* **`stale_label_alert`** — Mon 06:00 UTC weekly. Flags labels >
  90 days unrefreshed; writes
  `<RECUPERO_DATA_DIR>/stale_labels.json`.
* **`review_sla_scan`** — hourly :15. Surfaces overdue
  `awaiting_review` brief rows; sends ops alert.
* **`label_auto_ingest`** — 02:00 UTC daily. Pulls candidate
  labels from upstream tag APIs into `label_candidates`.

Leader election uses `cron_jobs_lock` (v0.32). One replica acquires
the per-job row lease for `RECUPERO_CRON_LEASE_SECONDS` (default
300s); the others poll and pick up if the leader dies. On 2
consecutive failures the scheduler POSTs to
`RECUPERO_CRON_ALERT_WEBHOOK_URL` (Slack-shape webhook accepted by
Discord/PagerDuty/OpsGenie too). The `/cron/healthz` endpoint
exposes per-job freshness so the alarm catches a silently-stuck
leader.

---

## 6. Where to start for new engineers

* **"I want to add a new chain"** — `src/recupero/chains/<chain>/`.
  Subclass `ChainAdapter` (see `chains/base.py`). The EVM family
  is generic over Etherscan V2 — for a new EVM chain just add a
  `_profile_for` entry in `chains/evm/adapter.py`. Non-EVM needs
  a new RPC client + adapter (see `chains/solana/`, `chains/tron/`).
  Add the chain to `models.Chain` and to the labels/pricing
  platform maps.
* **"I want to add a new bridge decoder"** — `trace/bridge_calldata.py`.
  Function-selector → decoder fn map. Add the bridge to
  `labels/seeds/bridges.json` so the BFS knows to follow the hop.
  Tests under `test_bridge_calldata.py` + `test_bridge_mapping_completeness.py`
  lock the parity.
* **"I want to fix a brief rendering bug"** — start at
  `reports/emit_brief.py` (the orchestrator). The Jinja templates
  live in `reports/templates/`. Run the Zigha integration test
  (`tests/integration/test_trace_to_brief.py`) before/after — it's
  the highest-signal regression in the suite.
* **"I want to add a new label source"** — `labels/seeds/*.json`
  for static, or wire into `labels/auto_ingest.py` for dynamic.
  Always extend with `(chain, address, label, confidence, source,
  acquired_at)` tuples — `LabelStore` enforces the schema.
* **"I want to debug a stuck case"** — `recupero-ops investigate
  <case_id>` prints the worker-claim heartbeat, last error, and
  `case.json`'s `trace_status`. `recupero-ops envvars` prints the
  resolved env at startup. The worker journals every state
  transition under `audit_log`.

---

## 7. The "Jacob-style" punishing-test pattern

Jacob is the external auditor. The validation pattern that shaped
v0.20.x onwards: write tests that EXPECT the bug, then fix until
green. The pattern is the value, not the count.

Three rules:

1. **Fixture-driven**. The test loads a real-shape case fixture
   (e.g., the Zigha golden case) and asserts on the rendered
   artifact's content. NOT on internal data structures. Bugs that
   pass shape but fail content are the ones that ship.
2. **Adversarial inputs**. NaN, ±Inf, negative, oversized, bidi
   control chars, malformed hex, malformed base58, truncated
   responses. Every external boundary (CoinGecko, Etherscan,
   Helius, TronGrid) gets a defensive test that confirms the
   bad input is REJECTED at the boundary — never poisons
   downstream.
3. **Property tests over example tests for invariants**. Use
   Hypothesis. The clustering / canonical-key / USD-conservation
   invariants are property-tested because example tests can't
   cover the input space.

What NOT to do: a test that asserts `case.trace_status == "complete"`
is a happy-path canary — it catches "everything broke" but not
"silently wrong". A test that asserts the rendered freeze letter's
$USD column sums to `case.total_usd_out` is a forensic-correctness
test. Write the second one.

---

## 8. Invariants the regression suite CAN NOT catch

The forensic-correctness gap is real. Tests catch shape; they don't
catch semantics. The full list lives in
`docs/WHY_RECUPERO_WOULD_FAIL.md` — read that before going to prod.
Key categories:

* **Label-wrongness**. A label says "Binance hot wallet" but Binance
  rotated cold storage on day N+1; the label is now wrong. No
  regression test can know that without re-querying the issuer.
* **Bridge proxy upgrade**. The bridge contract's implementation
  changes mid-trace; calldata layout shifts; the decoder silently
  produces garbage. Tests against a frozen fixture never catch a
  live-chain implementation swap.
* **AI editorial hallucination within a citation**. INVARIANT D
  forces a source citation, but the AI can produce prose that
  CITES the right field while INTERPRETING it wrong.
* **Statistical base-rate vs individual case**. Recovery rate is a
  population statistic. Telling THIS victim "you have a 3%
  chance" is not the same as the population's 3%.

The mandatory human-review gate (v0.32) exists because of this. The
operator's signature is the gate that shape-correctness can't
substitute for. See `docs/WHY_RECUPERO_WOULD_FAIL.md` for the full
pre-mortem and the five things to fix before the first paid customer.
