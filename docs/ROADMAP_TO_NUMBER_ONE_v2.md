# Road to #1 — Recupero (v2, 2026-06-08)

Supersedes `ROADMAP_TO_NUMBER_ONE.md` (2026-06-03). Synthesized from a fresh
4-domain parallel gap audit (Tracing/forensics · Recovery/legal · Data/attribution/
monitoring · Code-health/UX/ops) against the current checkout (post v0.35–v0.39).

**Headline finding:** correctness, artifact quality, bridge-pairing, and
cooperation intelligence are already **at or beyond** TRM Reactor / Chainalysis.
The biggest wins are **ACTIVATION, not invention** — capabilities that are fully
built + tested but ship **disabled, unwired, or with empty data**. We get most of
the way to #1 by *turning on what we already own*, then layer novel capabilities
no competitor has.

Standing constraints (never relax): never fabricate addresses/contacts/
destinations; `high` confidence ONLY on cryptographic match or direct label hit;
gate every commit on the real pytest summary; zero new ruff; never weaken a test;
never bulk-arm unverified data into an alerting/freeze path.

Severity: **P0** credibility/revenue/correctness · **P1** real moat gap · **P2**
polish. Effort S/M/L.

---

## PHASE 1 — ACTIVATION SPRINT (built but dormant; highest ROI)

These already exist + are tested; they just aren't on. Lowest effort, highest impact.

1. **P0 | CCTP (Circle) oracle rail is MISSING** despite being marked done — absent
   from `trace/bridge_pairings.py` + `bridge_calldata.py`. Highest-volume USDC bridge;
   `DepositForBurn` nonce↔`MessageReceived` is a clean cryptographic pair. Restore. **M**
2. **P0 | `demix_candidates` is DEAD CODE** — built/tested (`trace/demixing.py`) but never
   called. Wire into the BFS frontier + brief + a console; opt-in same-pool withdrawal
   scoring on a mixer hit. **M**
3. **P0 | Deep-reach ships OFF by default** — `RECUPERO_VALUE_TRACE`, `_FOLLOW_SPLITS`,
   `_BRIDGE_CONFIRM`, dormancy window. A default run is materially shallower than a tuned
   one. Promote to default-on with budget guards. **S**
4. **P0 | Litigation artifacts default-OFF** — exhibit pack, SAR/STR, MLAT/314b,
   exchange-freeze, time-sensitivity, signed custody only emit when
   `RECUPERO_AUTO_LITIGATION_ARTIFACTS=1` (`worker/_deliverables.py`). Auto-enable when
   FREEZABLE/EXCHANGES non-empty + provision a custody key per deploy. **S**
5. **P0 | Freeze-followup + refresh_priors NOT in the managed scheduler** — only fire via a
   manual `recupero-worker --freeze-followups` flag; `cron_scheduler._build_default_jobs`
   doesn't register them. Silent SPOF: the recovery loop may never run in prod. Register
   with leader-election like the other jobs. **S**
6. **P0 | Cosmos adapter unwired** — `chains/cosmos/adapter.py` exists but isn't in
   `for_chain`; the Axelar oracle resolves Cosmos/IBC dests the BFS then can't follow.
   Wire it + bech32 validation. **M**
7. **P0 | Empty seed data** — `scam_drainers.json`=0, `ransomware.json`=0,
   `internal_blacklist_seed.json`=0 armed, `sanctions_intl_live.csv` absent in prod.
   Populate from authoritative/verified feeds via the existing review-gated pipeline;
   ship a committed intl-sanctions snapshot. **S–M**

## PHASE 2 — RECOVERY AUTOMATION (the thing that actually freezes funds fast)

The #1 *recovery* gap: detection→freeze is advisory-only. Funds move in minutes.

8. **P0 | Alert → auto-draft → human-gate freeze** — on a `freezable_inflow/outflow`
   recovery alert, auto-draft the freeze request into the existing `brief_reviews`
   human-approval queue (artifacts + review row already exist; bridge them). Turns
   "tells you to act" into "the freeze letter is waiting for one-click approval." **M**
9. **P1 | Confirmed-win auto-arm loop** (compounding moat) — on a freeze outcome marked
   recovered/seized, auto-arm the perpetrator + current-holder addresses into the v0.39
   internal blacklist with outcome provenance. Every future case through them fires. **S–M**
10. **P1 | Cooperation-driven adaptive freeze routing** — make `recommend_legal_instrument`
    *drive* dispatch (skip a known black-hole exchange → straight to AUSA subpoena; LE-backed
    to fast cooperators), not just annotate. **M**
11. **P1 | Inbound outcome ingest** — parse issuer/exchange replies → `record_outcome` so
    priors reach n≥20 and the cooperation moat stops being data-starved. **M**
12. **P1 | Verified exchange-freeze contact DB** (top ~20 CEX: real LE-portal URLs +
    response-time priors) + extend followup past 14d (30d/90d stages already valid). **M**
13. **P1 | Victim status portal** — "track my case" page off the existing portal token
    (freeze stage, outcome timeline) + proactive victim notifications on material events. **M**

## PHASE 3 — DATA SCALE & REAL-TIME (the durable moat)

14. **P0 | Live mempool / pending-tx pre-freeze watch** — `hot`+freezable rows via
    Alchemy/Helius pending subscriptions → CRITICAL alert + pre-drafted freeze BEFORE the
    block confirms. The only pre-confirmation freeze trigger in the market. **L**
15. **P1 | Bulk attribution backfill** — the review-gated harvest plumbing exists but seeds
    are tiny (bridges 242 / CEX 53 / mixers 29). Run the OSS dumps (brianleect 6-chain,
    ethereum-lists, OFAC recent-actions) as provenance-scored medium-confidence; add a
    batch-approve-by-source-trust review tool; schedule the daily pull. 10–100× the corpus. **M–L**
16. **P1 | Cross-victim attribution network** — surface the existing `address_observations`
    correlation as a private cluster graph ("this drainer hit 14 of your prior victims; here
    are the shared cash-out deposits"). Turns the customer base into a private feed. **M**
17. **P1 | Async bulk-screen for exchange customers** — current bulk cap = 100 addrs (a
    compliance desk screens 10k+). Add an async job endpoint (upload→job id→poll/webhook),
    per-customer API keys + quotas, Redis result cache for multi-worker. **M**
18. **P2 | Sanctions/label-drift diff alerts** — OFAC delta → auto-re-screen open cases
    ("OFAC added 4 ETH wallets today; 1 is in active case X"). **S**

## PHASE 4 — NOVEL CAPABILITIES (no competitor has these)

19. **Predictive laundering-path modeling** — train on our own benchmark traces to score, at
    any frontier node, the next-hop archetype distribution ("75% likely to bridge to
    Tron→CEX within 6h") so LE pre-positions freeze asks. Forward prediction; competitors
    only show the past. **L**
20. **Time-to-freeze SLA countdown** — statute clocks + rail speeds + dormancy → a live
    "funds reach an unfreezable state in ~X hours" deadline driving triage. **S**
21. **Multi-jurisdiction freeze + SAR/STR orchestration in one pass** — auto-detect every
    jurisdiction touched (issuer incorporation, CEX domicile, victim country) → emit the
    correct freeze + FinCEN/NCA/goAML filing bundle for each, sequenced by statute clock. **M**
22. **Victim-cosigned, LE-countersigned signed freeze request** — extend the Ed25519 custody
    chain so a freeze ask carries a multi-party-attested signature chain — tamper-evident,
    far stronger than "trust this email." **M**
23. **Cross-chain behavioral fingerprinting** — gas-price/nonce/timing/funding-topology
    signals (glass-box, ≤medium) to link a perp's *different* addresses across chains. **L**

## PHASE 5 — CLEANUP / FLATTEN / TIGHTEN (product polish)

24. **P1 | Operator console hub** (#273 in progress) — 21 consoles, no landing page. Unified
    `/v1/console` hub + shared design-system CSS (drift across per-console inline styles). **S**
25. **P1 | Decompose monoliths** — `validators/output_integrity.py` (5,442 LOC),
    `trace/tracer.py` (3,242), `bridge_calldata.py` (2,830), `reports/emit_brief.py` (2,830,
    26 TODOs), `api/app.py` (2,455). Split behind regression locks. **M each**
26. **P1 | Chain-adapter unit tests** — 36 adapters, ~6% direct coverage (integration-only).
    Address-parse + client-init units per adapter. **M**
27. **P2 | Observability** — structured logging + correlation IDs across worker/api/cron;
    export `observability/metrics.py` to Prometheus; ensure Sentry inits in API `main()`. **S**
28. **P2 | Multi-provider RPC failover** — single Alchemy/Etherscan per chain; add fallback. **M**
29. **P2 | Finish #206** — ruff 0 / mypy strict / vulture dead-code purge (739 noqa/ignore). **M**

---

## Top-10 execution order (impact × effort, dependency-aware)
1. Deep-reach default-on (#3, S) · 2. Litigation-on-by-default (#4, S) ·
3. Scheduler-register freeze loop (#5, S) · 4. Restore CCTP rail (#1, M) ·
5. Wire demixing (#2, M) · 6. Confirmed-win auto-arm (#9, S–M) ·
7. Alert→freeze-draft (#8, M) · 8. Populate seed data (#7, S–M) ·
9. Wire Cosmos (#6, M) · 10. Console hub (#24, S).

Each lands as its own gated commit (real pytest summary, zero new ruff), FF to main.
