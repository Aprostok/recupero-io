# Recupero

Crypto-forensics platform that takes a victim wallet, traces stolen
funds across 22 chains, and produces a packet of law-enforcement-ready
deliverables — forensic brief, freeze letters to exchanges, LE handoff
package, executive summary — fast enough that funds can still be frozen
while they sit on a centralized exchange. Each artifact passes through
a mandatory human-review gate before it ships, and every customer
intake records a Wilson-95%-CI recovery-rate disclosure that the
customer must acknowledge before the engagement begins.

---

## What Recupero does NOT promise

Recovery rates in crypto-theft work are bounded by physics, not effort.
The industry baseline reported by Chainalysis is roughly 3%. Recupero
publishes its own recovery rate from `freeze_outcomes` as a Wilson 95%
confidence interval once n ≥ 30 closed cases; below that threshold the
intake portal shows the industry baseline with explicit attribution.
The customer-facing disclosure is the canonical statement of what
Recupero can and cannot do — see
`src/recupero/monitoring/recovery_rate.py` and
`src/recupero/portal/templates/intake.html.j2`.

If a vendor promises a fixed recovery percentage, they are either
lying or hiding the denominator. We don't.

---

## Quickstart

```bash
# 1. Clone and enter the repo
git clone https://github.com/recupero-io/recupero-io.git
cd recupero-io

# 2. Create a venv and install editable
python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"

# 3. Set up env vars
cp .env.example .env
# Edit .env and fill in at minimum:
#   ETHERSCAN_API_KEY            (required for any EVM chain)
#   COINGECKO_API_KEY            (historical USD valuation)
#   RECUPERO_TOKEN_PEPPER        (REQUIRED — 32-byte hex; portal tokens fail without it)
#   SUPABASE_DB_URL              (required for any flow touching the worker / portal / dispatcher)
#   ANTHROPIC_API_KEY            (required for the editorial-drafting stage)
#   HELIUS_API_KEY               (required only when tracing Solana)
#   RECUPERO_ADMIN_KEY           (required for the review API + labels API)

# 4. Verify the install — fast offline regression suite
pytest -q

# 5. Trace a real address end-to-end
recupero trace \
    --chain ethereum \
    --address 0x0cdC902f4448b51289398261DB41E8ADC99bE955 \
    --incident-time "2025-10-09T00:00:00Z" \
    --case-id DEMO-001
```

Output lands in `data/cases/DEMO-001/` — `case.json`, `transfers.csv`,
per-tx evidence under `evidence/`, and the trace manifest.

For an end-to-end pipeline (intake → trace → enrich → brief → review →
dispatch) you also need the worker running: `recupero-worker` against a
Postgres instance with migrations 001-030 applied. See
`docs/DEV_ONBOARDING.md` for the 30-minute setup path.

---

## Architecture

The canonical architecture document is `docs/ARCHITECTURE.md`. Read it
before writing code. The high-level pipeline:

```
intake → trace → enrich → emit_brief → review-gate → dispatch → outcome-tracking
  |        |        |          |             |           |             |
portal/  trace/  trace/      reports/    v0.32      dispatcher/   freeze_outcomes
server   tracer  cross_chain emit_brief  brief_     review_api    + monitoring/
  +     + chain/ + clustering + ai_      reviews                  watch_tick
  v0.25 adapters + indirect_  editorial  gate
  intake          exposure   + output_
  form           + cex_      integrity
                  continuity  validator
```

Single-process Python service. Postgres (Supabase) for state. Optional
Sentry + Prometheus exporters. One worker replica on Railway with HA
cron leader-election added in v0.32.

Supporting documents:

- `docs/ARCHITECTURE.md` — the day-one read.
- `docs/DEPLOY_v0_32_0_RUNBOOK.md` — production deploy procedure (with
  v0.32.1 deltas appended).
- `docs/ENV_VARS.md` — every `RECUPERO_*` env var, type-checked against
  source by `tests/test_v031_4_env_vars_doc.py`.
- `docs/DEV_ONBOARDING.md` — 30-minute new-contributor setup.
- `docs/JACOB_v032_TRIAGE.md` — the rolling audit-driven backlog.
- `docs/WHY_RECUPERO_WOULD_FAIL.md` — pre-mortem and known limits.

---

## For operators

A typical case is operator-driven only at three points: intake review,
human review of the dispatch artifacts, and post-send outcome
tracking.

1. **Intake.** Victim submits the portal form
   (`POST /v1/intake`). The form requires acknowledgment of the
   recovery-rate disclosure (v0.32). The case row is created in
   `state='intake'` and a `recovery_disclosures` row records the
   ACK. Stripe payment events advance the case to
   `state='traced_pending'`.
2. **Worker trace.** `recupero-worker` claims the case, runs the BFS
   trace, the cross-chain bridge continuations, the DEX-swap
   continuations, the perpetrator-trace, the CEX-continuity pass, and
   the indirect-exposure pass. In v0.32.1+ industry-best mode the
   per-case API budget cap is DISABLED by default (set
   `RECUPERO_API_BUDGET_USD_PER_CASE` to a positive value to opt in).
   See `docs/INDUSTRY_BEST_MODE.md` for the trade-offs.
3. **Build deliverables.** The worker emits the forensic brief,
   per-exchange freeze letters, the LE handoff package, and the
   executive summary. Each artifact passes through `validators/`
   (INVARIANTS A–P) before it lands on disk + Supabase Storage.
4. **Human review.** Every artifact lands in `brief_reviews` with
   `status='awaiting_review'`. The dispatcher refuses to send anything
   until an admin-key-authenticated operator approves via
   `POST /v1/reviews/{id}/approve`. Override path exists for legal
   risk (`/override`) but it is logged and time-stamped.
5. **Dispatch.** On approval the worker tick sends the brief, the
   freeze letters land in counterparty inboxes, the LE handoff PDF
   ships to the assigned agency contact. Every send is recorded with
   `emails_sent` + audit log.
6. **Outcome tracking.** `monitoring/watch_tick.py` and
   `monitoring/cooperation_intelligence.py` follow the case until a
   freeze, recovery, or drop is recorded. The closed case feeds the
   recovery-rate disclosure for future intakes.

Frequent operator commands (full reference: `recupero-ops --help`):

```bash
recupero-ops close-case --case <id> --outcome {full_recovery,partial_recovery,no_recovery,dropped}
recupero-ops retrace-scan
recupero-ops followup-now --case <id>
recupero-ops list-payments
recupero-ops send-freeze-letters --case <id>
recupero-ops generate-payment-link --case <id>
recupero-ops bridge-sync
```

---

## For LE / compliance

Recupero is built around the assumption that LE acts only on documents
they can read in five minutes and act on the same day.

- **Freeze letters** (`reports/templates/freeze_letter.html.j2`) name
  the destination exchange-deposit address, the source-of-funds
  evidence chain, and the relevant ML/structuring statutes. The
  v0.32.1 cycle reworked these around the correct 18 USC § 3486
  citation and added per-issuer salutation handling.
- **LE handoff** (`reports/templates/le.html.j2`) is the artifact
  designed for an AUSA / agent to drop into a search-warrant
  application or a § 1957 grand-jury referral. Every cited address
  links out to the chain's block explorer; every USD figure carries a
  point-in-time price source citation; the chain-of-custody section
  carries the Ed25519-signed manifest hash that proves the artifact
  was not tampered with after the worker built it.
- **Citations everywhere.** Every dollar figure traces back to either
  a chain-of-custody-verified on-chain price source (CoinGecko PIT
  lookup at the block timestamp) or to a public benchmark with the
  source URL embedded. No "trust us" numbers.

If you are an agent / AUSA / compliance officer evaluating Recupero
output: the brief contains the headline numbers; the LE handoff
contains the case you will actually file; the freeze letter is the
artifact you sign and forward. The three should reconcile dollar-for-
dollar and address-for-address — INVARIANT-K verifies this at build
time.

---

## For developers

This is a senior-Python codebase with no test-shortcut culture. Three
things bind it together:

1. **The INVARIANT framework** (`src/recupero/validators/`). Every
   artifact emit passes through 16 invariants A–P that catch the kinds
   of cross-document inconsistencies a senior law-firm partner would
   wince at. Adding a new artifact type means adding the invariant
   that guards its consistency with the rest of the packet.
2. **The mutation harness** (`scripts/mutation_smoke.py`). 43+
   strategically-placed source mutations must each be killed by at
   least one test. CI runs this on every PR. New code without
   mutation coverage is a deferred-merge signal.
3. **The branch model.** `main` is the production-deploy branch
   (Railway auto-deploys on push). `pdf-deliverables` is the
   active-development branch. Feature work happens in worktrees off
   `pdf-deliverables`; the audit cycle (six parallel Jacob-style
   reviewers) gates the merge back to `main`.

Day-one developer checklist:

```bash
# Run the fast offline suite
pytest -q
# Expected: 4598 passed, 10 skipped, 0 failed (v0.32.0 baseline)

# Run the mutation harness
python scripts/mutation_smoke.py
# Expected: 43/43 mutations detected

# Type-check
mypy src/recupero

# Lint
ruff check src/recupero
```

Read `docs/DEV_ONBOARDING.md` for the full 30-minute path.

---

## Versioning — v0.32.1 changes

v0.32.0 closed all Tier-0 and Tier-1 pre-mortem gaps. v0.32.1 is the
remediation cycle from the round-2 Jacob-style audit. It introduces no
new migrations beyond the 027-030 set already applied for v0.32.0; the
deploy procedure is therefore a code-only revision.

Changes shipping in v0.32.1:

- **Rollup-canonical bridge decoders** for Polygon PoS, Optimism,
  Arbitrum, zkSync Era, and Base. Collapses the adversary "rollup
  escape" route — destination chain + recipient now extracted from
  the canonical bridge calldata, not heuristically inferred.
- **CEX continuity cross-token parity match** — USDT↔USDC, ETH↔stETH,
  WBTC↔cbBTC. Deposit-in-one-token / withdraw-in-another at the same
  exchange now produces a tier-2 lead instead of a dead end.
- **Trace dst-chain anchor fix.** The cross-chain continuation pass
  now correctly anchors at the dst-chain seed; the v0.32.0 bug that
  truncated some destination-chain traces is closed.
- **Cron-scheduler secret redactor expansion.** The HA cron's stderr
  now redacts a wider set of secret-shaped tokens; SEC CRIT-2 closed.
- **Auto-ingest promote validation + `confirm_sha256`.** Promoting a
  candidate label requires the caller to echo back the candidate's
  content SHA-256; closes SEC CRIT-1 (label-promote JSON injection).
- **Admin-gated `/v1/cron/jobs`.** The cron status endpoint now
  requires `X-Recupero-Admin-Key`; SEC HIGH-5 closed.
- **Validator INVARIANTS G–P** ship for v0.32.1. Semantic coverage
  moves from ~30% to ≥90%: intra-artifact sum coherence,
  address↔chain↔explorer URL coherence, time-window coherence,
  PIT-render verification, AI-editorial grounding,
  brief↔freeze-letter consistency, and parent-link/disclosure
  metadata checks all land.

For the deploy procedure see the **v0.32.1 deltas** section appended
to `docs/DEPLOY_v0_32_0_RUNBOOK.md`.

---

## Limitations

These are the top-five known unsupported scenarios. The intent of
publishing them in the README is to be honest with operators and
counsel before they discover the limit on a live case.

1. **Bitcoin Lightning-channel exits.** Forensics community treats
   Lightning settlement as a known dead end. Recupero traces the
   on-chain channel-open / channel-close but not in-channel
   intermediate hops.
2. **Cosmos / IBC chains.** Zero chains supported as of v0.32.1
   (Osmosis, Cosmos Hub, Juno, etc.). Planned for v0.33+.
3. **ERC-4337 user-operation decomposition** (pre-v0.32.1 fix).
   v0.32.1 ships a partial fix at the entry-point level; full inner-
   call decomposition is v0.33+.
4. **Bitcoin peel-chain and CoinJoin recombination.** Single-input /
   single-output peel detection ships; multi-input CoinJoin
   recombination heuristics are partial — closed in v0.32.1's W3-K
   pass but parity with Chainalysis Reactor is not yet there.
5. **$50M+ tier APT-class exploits.** The per-case API budget cap and
   the BFS scaling limits mean a 50-fanout, 4-bridge, privacy-pool
   exit by a state-actor APT will surface a `partial_deadline_hit`
   marker on the case rather than a complete trace. The operator
   knows it's incomplete; the brief carries the marker; the case is
   still actionable but the "tail" of the laundering may be beyond
   v0.32.1's reach.

If a case touches one of the above, the worker emits a partial-trace
marker on `case.config_used.trace_status` and the operator UI surfaces
it as a banner on the case page.

---

## Console scripts

Five console scripts are installed by `pip install -e .`. Each is a
named entry point in `pyproject.toml` and is discoverable on PATH
after the editable install.

| Script | Purpose |
|---|---|
| `recupero` | The forensic CLI. Subcommands: `trace`, `show`, `screen`, `brief`, `victim`, `emit-brief`, `ai-editorial`, `aggregate`, `legal-requests`, `token-risk`, `find-dormant`, `list-freeze-targets`, `inspect`, `hyperliquid-scrape`, `graph-ui`. |
| `recupero-ops` | The operator CLI for the worker-driven flow. Subcommands include `close-case`, `retrace-scan`, `followup-now`, `list-payments`, `send-freeze-letters`, `generate-payment-link`, `bridge-sync`, `dispatch-brief`. |
| `recupero-worker` | The Phase 2 worker process. Polls the queue, claims cases, runs the trace, builds deliverables, dispatches through the review gate. |
| `recupero-api` | The FastAPI service surface. Exposes intake portal, screen / token-risk / monitoring endpoints, dispatcher review API, labels admin API, and cron healthz. |
| `recupero-cron` | The HA cron service (v0.32). Postgres-leader-elected scheduler that runs `ofac_sync`, `retrace_backfill`, `stale_label_alert`, and `label_auto_ingest`. |

`--help` on any of the above lists the subcommands and the available
options.

---

## Repository layout

```
recupero/
├── README.md                       This file
├── pyproject.toml                  Package metadata + dependencies
├── .env.example                    Env-var template (see docs/ENV_VARS.md)
├── Dockerfile, railway.json        Production deploy config
├── docs/                           Operator + developer documentation
├── migrations/                     SQL migrations (001-030 as of v0.32.1)
├── scripts/                        Standalone scripts (apply_migration, mutation_smoke, etc.)
├── src/recupero/
│   ├── _common.py                  Shared helpers (short_addr, db_connect, atomic_write_text)
│   ├── api/                        FastAPI service (intake, screen, dispatcher, cron admin)
│   ├── chains/                     Per-chain adapters (ethereum/, solana/, tron/, bitcoin/, hyperliquid/, evm/)
│   ├── cli.py                      The `recupero` CLI
│   ├── dispatcher/                 Review gate + review API
│   ├── freeze/                     Freeze-letter generation
│   ├── labels/                     Label store + auto-ingest + API
│   ├── monitoring/                 Cooperation intel + recovery-rate + watch tick
│   ├── ops/                        The `recupero-ops` CLI
│   ├── payments/                   Stripe webhook + dispatcher
│   ├── portal/                     Customer-facing intake portal
│   ├── reports/                    Brief + LE handoff + freeze letter + AI editorial
│   ├── trace/                      BFS tracer + bridge decoders + DEX swaps + CEX continuity
│   ├── validators/                 INVARIANTS A-P
│   └── worker/                     The worker process + HA cron scheduler
└── tests/                          Offline unit + integration tests (4598+ at v0.32.1)
```

---

## License

Proprietary. See `pyproject.toml` for the license declaration.
