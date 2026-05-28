# Recupero v0.32.1 Risk Register

Audience: operators dispatching cases, law-firm partners reviewing
engagement contracts, AUSAs evaluating LE handoff quality, and the
internal team's go-live decision-makers.

This register is the structured form of the pre-mortem in
`docs/WHY_RECUPERO_WOULD_FAIL.md` plus every CRIT and HIGH finding
the 6-agent + 1-adversary audit cycle surfaced in v0.32.0. Each entry
identifies the residual risk *after* the v0.32.1 mitigations land.

**Reading the matrix**:

* **Likelihood**: low / medium / high — frequency we expect this risk
  to materialize in routine operations.
* **Impact**: low / medium / high / critical — severity if it does.
  Critical = case-killing, brand-damaging, or legally exposing.
* **Mitigation**: the specific code path, document, or process that
  reduces this risk in v0.32.1.
* **Residual risk**: what remains after mitigation. This is the number
  the go-live decision should rest on.
* **Owner**: the role accountable for the residual risk.
* **Version-closed**: the Recupero version that landed the mitigation.
  "Open" means the residual risk persists past v0.32.1.

---

## Category A — Trace incompleteness

The trace pipeline can silently under-report the path of stolen funds.
The brief still looks shape-correct; downstream consumers (LE handoff,
freeze letters) inherit the under-reporting.

### R-001 — Rollup-canonical bridge destinations not extracted (pre-v0.32.1)

- **Description**: Pre-v0.32.1 the bridge calldata decoder dispatch
  table at `trace/bridge_calldata.py:460-705` did not include
  Polygon PoS RootChainManager, Optimism L1StandardBridge, Arbitrum
  Inbox, zkSync Era requestL2Transaction, or Base canonical bridge.
  A perpetrator using these bridges produced a brief with destination
  chain candidate but no concrete destination address. Adversary
  Route 1 ($5M USDC, Polygon PoS escape) escapes via this gap.
- **Likelihood**: high (pre-v0.32.1). The rollup-canonical bridges
  are the most common L1↔L2 bridge surface; a 2026 case-mix study
  would show 30%+ of EVM cases touch one of these.
- **Impact**: critical (the trace dies; the operator cannot issue a
  freeze letter at the destination).
- **Mitigation**: W2-E Wave 2 fix added all 5 rollup-canonical
  decoders to `bridge_calldata.py:2348+` (Polygon PoS `depositFor`,
  `depositEtherFor`), `bridge_calldata.py:2392+` (Optimism / Base
  shared `depositERC20To` + `depositETH{To}` selectors), plus
  Arbitrum Inbox and zkSync Era.
- **Residual risk**: low. The 5 rollup-canonical bridges cover the
  bulk of L2 escape patterns. A new L2 launching post-v0.32.1 with
  a novel canonical-bridge ABI would not be covered until a Wave-style
  cycle adds it. Test:
  `tests/test_bridge_calldata_canonical.py`.
- **Owner**: trace lead.
- **Version-closed**: v0.32.1 (W2-E).

### R-002 — Smart-wallet ownership-swap not detected

- **Description**: Gnosis Safe / EIP-7702 ownership transfer via
  `swapOwner(prevOwner, oldOwner, newOwner)` emits no ERC-20
  Transfer event. The BFS walks Transfer-event lists; the funds
  appear to be "delivered to a DeFi contract" when in fact control
  of the Safe has been transferred. Adversary Route 1 Hop 2 exploits
  this.
- **Likelihood**: medium. Common for sophisticated drainer kits to
  use Safe-pattern smart wallets; rare for unsophisticated thieves.
- **Impact**: critical. The trace terminates at the Safe address;
  the freeze letter never goes out.
- **Mitigation**: NOT IMPLEMENTED in v0.32.1. Listed as v0.33 item
  in `JACOB_v032_TRIAGE.md` § 5.2.
- **Residual risk**: high (open). For cases involving Safe-pattern
  smart wallets, the brief renders "trace terminated at unlabeled
  contract" with no further guidance. README's Limitations section
  must call this out explicitly.
- **Owner**: trace lead.
- **Version-closed**: open (deferred to v0.33).

### R-003 — Bitcoin Lightning Network exits

- **Description**: Lightning channel state transitions are off-chain.
  No coverage in Recupero (or in the industry generally).
- **Likelihood**: medium. Lightning is used by professional money
  launderers more than retail.
- **Impact**: high. Funds entering Lightning are effectively lost to
  forensics.
- **Mitigation**: documentation gap acknowledged in
  `WHY_RECUPERO_WOULD_FAIL.md` and `PROMISES_AND_LIMITS.md`. The brief
  explicitly states "Lightning Network exits are not traceable" when
  the destination is a known Lightning-channel-open transaction.
- **Residual risk**: medium (open). For Lightning-exit cases the
  trace stops at the channel-open tx and the brief discloses the
  limit.
- **Owner**: product lead.
- **Version-closed**: open (industry-level gap).

### R-004 — Cosmos / IBC zero coverage

- **Description**: No adapter for Cosmos Hub, Osmosis, Injective, or
  any IBC zone. Funds bridged to a Cosmos zone disappear from the
  trace at the bridge.
- **Likelihood**: low (today). Cosmos volumes are a small fraction
  of cross-chain laundering. Rising with the cross-chain IBC
  expansion.
- **Impact**: high (when it happens, the trace is dead).
- **Mitigation**: NOT IMPLEMENTED. Listed as v0.33+ in triage § 5.4.
- **Residual risk**: medium (open). Mitigated by the brief
  surfacing "destination chain: cosmos — out of supported chain set"
  per HIGH-2 of the trace audit.
- **Owner**: product lead.
- **Version-closed**: open.

### R-005 — ERC-4337 user-operation decomposition (pre-fix and post-fix)

- **Description**: ERC-4337 account-abstraction transactions package
  the user's intent inside a `UserOperation` blob. The actual asset
  transfers happen inside the bundler's `handleOps` call. Without
  decomposition, the trace sees the transfer from the bundler, not
  from the perpetrator's smart account.
- **Likelihood**: medium and rising. ERC-4337 adoption is at ~3%
  of Ethereum daily transactions in 2026 and rising 1-2 percentage
  points per quarter.
- **Impact**: high (perpetrator attribution incorrect — brief names
  the bundler instead of the perpetrator).
- **Mitigation**: partial coverage in v0.32.1 via
  `aa-userop-decomposer` module. Full decomposition deferred to v0.33.
- **Residual risk**: medium. Partial coverage handles the common
  ERC-4337 patterns; novel paymaster setups slip.
- **Owner**: trace lead.
- **Version-closed**: partial v0.32.1; full deferred.

### R-006 — Bitcoin peel-chain coverage incomplete

- **Description**: Peel-chain laundering (large UTXO → small change +
  large remainder, iterated dozens of times) requires special
  detection. The detector in `trace/coinjoin_unwrap.py` handles the
  simple case but degrades against adversarial peel patterns with
  varying step sizes.
- **Likelihood**: medium for ransomware-style Bitcoin cases.
- **Impact**: high. A 30-step peel chain that goes undetected makes
  the trace look like it terminates at the first peel destination.
- **Mitigation**: W3-K Wave 3 fix tightens detector + handles
  variable-step peel patterns. Bitcoin multi-input collapse (R-007
  / CRIT-1) is the precondition for co-spending clustering which
  is the strongest signal against peel chains.
- **Residual risk**: medium. Bitcoin peel patterns are an active
  laundering art; new techniques emerge.
- **Owner**: trace lead.
- **Version-closed**: v0.32.1 (W3-K) for the common patterns.

### R-007 — Bitcoin multi-input UTXO collapse (pre-W1-C)

- **Description**: Pre-W1-C the Bitcoin adapter at
  `chains/bitcoin/adapter.py:333` discarded all but the first input
  address per transaction. Multi-input transactions (the normal
  shape for any wallet with fragmented UTXOs) emitted Transfer records
  keyed to ONE input address; the others looked like they never
  moved funds. The trace silently under-reported outflows for N-1
  addresses on every multi-input tx.
- **Likelihood**: very high (pre-fix). Any case with > 1 UTXO per
  wallet — virtually every Bitcoin case.
- **Impact**: critical for clustering (co-spending H1 heuristic
  doesn't fire). Forensic.
- **Mitigation**: W1-C Wave 1 fix emits one Transfer record per
  (input_addr, output_addr) pair OR carries `all_input_addresses`
  metadata on every Transfer so clustering can use the full set.
- **Residual risk**: low. Test:
  `tests/integration/test_trace_to_brief.py` + a new BTC-multi-input
  regression case landed in W1-C.
- **Owner**: trace lead.
- **Version-closed**: v0.32.1 (W1-C / CRIT-1).

### R-008 — Solana CPI / inner-instruction transfers lost (pre-fix)

- **Description**: Solana DeFi (Jupiter → Raydium → Orca chains)
  emits transfers inside `innerInstructions`. Pre-v0.32.1 the adapter
  at `chains/solana/adapter.py:148-165` only read top-level
  `nativeTransfers` / `tokenTransfers`. CPI-routed laundering
  appeared to dead-end at Jupiter.
- **Likelihood**: high for Solana-DeFi cases.
- **Impact**: critical (trace dies at the first DEX aggregator).
- **Mitigation**: W3-L Wave 3 fix walks `innerInstructions` and
  merges CPI transfers into the BFS input.
- **Residual risk**: low for the common Jupiter / Raydium / Orca
  patterns; medium for novel program designs.
- **Owner**: trace lead.
- **Version-closed**: v0.32.1 (W3-L / HIGH-4).

### R-009 — NFT 721 / 1155 transfers (pre-fix)

- **Description**: NFT transfers do not emit ERC-20 Transfer events
  with token amounts; they emit a different event signature. The
  pre-v0.32.1 adapter did not pick up NFT transfers as outflows,
  so NFT-laundered funds (perpetrator buys an NFT, transfers it
  to a fresh wallet, sells back to USDC) were invisible.
- **Likelihood**: medium for high-value cases where the perp wants
  to obfuscate via the NFT market.
- **Impact**: high. Perpetrator-controlled wallet looks empty post-
  NFT-purchase; the funds appear to have evaporated.
- **Mitigation**: W3-L Wave 3 fix adds `fetch_nft_outflows` to the
  EVM adapter and surfaces NFT transfers as a separate brief
  section with provenance trail.
- **Residual risk**: low for vanilla ERC-721 / 1155; medium for
  on-chain royalty splits and complex NFT-marketplace router
  patterns.
- **Owner**: trace lead.
- **Version-closed**: v0.32.1 (W3-L).

### R-010 — Address-poisoning attack detection

- **Description**: Address-poisoning is the inverse of dust-attack:
  the attacker sends a 0-value tx to the victim from a lookalike
  address, hoping the victim copies the lookalike from their wallet
  history and pastes it as a destination in a real transfer.
- **Likelihood**: medium. Common against high-net-worth victims.
- **Impact**: high. If the victim falls for it, the trace shows
  the victim's funds going to the lookalike — the actual perpetrator
  hop, not a contamination signal.
- **Mitigation**: dust-attack detector at `trace/dust_attack.py`
  with W3-I expansion to detect lookalike-address poisoning patterns
  (Levenshtein distance to victim address < threshold, sent within
  a 7-day window prior to incident).
- **Residual risk**: medium. Address-poisoning patterns evolve; the
  current detector handles the common ones.
- **Owner**: trace lead.
- **Version-closed**: v0.32.1 (W3-I).

### R-011 — ERC-4337 paymaster decomposition

- **Description**: Paymaster contracts in ERC-4337 obscure who paid
  the gas, which sometimes obscures the perpetrator identity. A
  bundler executing a UserOp uses paymaster funds for gas; the
  paymaster's depositor is sometimes the perpetrator obfuscating
  via a paymaster deposit.
- **Likelihood**: low (paymaster usage is still rare).
- **Impact**: medium. When it happens, attribution is fuzzy.
- **Mitigation**: deferred to v0.33.
- **Residual risk**: medium (open). Disclosed in README Limitations.
- **Owner**: trace lead.
- **Version-closed**: open.

---

## Category B — Adversary evasion

These risks correspond to the three adversary routes in
`JACOB_ADVERSARY_AUDIT_v032.md`. The audit assumed the adversary had
read the source code on GitHub and designed laundering specifically
to evade Recupero.

### R-012 — Adversary Route 1: $5M USDC, Polygon PoS escape

- **Description**: Polygon PoS RootChainManager + Safe ownership swap
  + 12-tranche off-ramp via Bybit Tron. Full route in adversary
  audit § 1.
- **Likelihood**: medium-high for a Lazarus-tier APT with source-
  code access.
- **Impact**: critical (clean escape with brief naming wrong
  destination).
- **Mitigation**: W2-E (rollup-canonical decoders) collapses the
  Polygon PoS hop. Safe ownership-swap (R-002) still open — the
  adversary still has one major escape vector. CEX-continuity
  cross-token at parity (W2-F) catches the off-ramp.
- **Residual risk**: low if adversary uses Polygon PoS;
  medium if adversary uses Safe ownership-swap.
- **Owner**: adversary lead.
- **Version-closed**: partial v0.32.1.

### R-013 — Adversary Route 2: $500K USDT-TRC20, 9-fanout sub-threshold

- **Description**: 9 destinations (just below `min_fanout=10`),
  each goes to USDD PSM (treated as terminal bridge), funds
  re-emerge on the other side of the swap to Bybit Tron. Full
  route in adversary audit § 2.
- **Likelihood**: high for Tron-USDT cases.
- **Impact**: critical (9 dead ends in the brief; operator
  subpoenas USDD operator in non-cooperative jurisdiction).
- **Mitigation**: W3-I per-case randomized thresholds make the
  fanout threshold unpredictable to source-code-reading adversaries.
  M-7 expands Tron bridge coverage including marking USDD PSM as
  `category="swap"` so the trace continues past it. Cross-token CEX
  continuity (W2-F) catches the Bybit off-ramp.
- **Residual risk**: low for the canonical Route 2 pattern; medium
  for novel offshore-stablecoin PSM patterns.
- **Owner**: adversary lead.
- **Version-closed**: v0.32.1 (W3-I + W3-M).

### R-014 — Adversary Route 3: $50M Arbitrum exploit, speed laundering

- **Description**: 50-way fanout + 4 parallel bridges + privacy pools
  + Symbiosis second-bridge + 5th-chain consolidation. Full route in
  adversary audit § 3.
- **Likelihood**: low-medium. Requires sophisticated infrastructure
  and significant theft size.
- **Impact**: critical (case incomplete; funds unrecoverable).
- **Mitigation**: budget bump from $0.50 → $10,000 per case (W2-H
  item 1) extends the trace deadline runway. `partial_deadline_hit`
  marker discloses incompleteness explicitly. Multi-bridge alarm
  (M-9) flags multi-bridge cases as high-suspicion.
- **Residual risk**: medium (open at architectural level). $50M+
  speed-laundered cases hit the budget cap or deadline regardless.
  Disclosed in README Limitations.
- **Owner**: adversary lead.
- **Version-closed**: partial v0.32.1.

### R-015 — Pre-incident funding chain attribution

- **Description**: Adversaries often pre-fund the laundering
  infrastructure days or weeks before the incident. A wallet that
  appears in the trace as a destination may have been provisioned
  by another adversary-controlled wallet that itself received funds
  from a labeled CEX. Tracing backwards from the incident attribution
  point is not part of the standard BFS.
- **Likelihood**: medium.
- **Impact**: medium (attribution-strength signal missed; not case-
  killing).
- **Mitigation**: indirect-exposure scorer at
  `trace/indirect_exposure.py` does N-hop-backward exposure with
  decay. W3-J bumps default max_hops from 3 to 5.
- **Residual risk**: low.
- **Owner**: trace lead.
- **Version-closed**: v0.32.1.

### R-016 — Mixer-exit lead detection

- **Description**: Funds entering a mixer (Tornado, Sinbad, Railway)
  are followed by exits at a later time. The BFS stops at the mixer.
  The forensic question is: did funds exit, and if so, when and to
  where?
- **Likelihood**: high for mixer-touched cases.
- **Impact**: medium-high (recovery probability drops sharply after
  mixer).
- **Mitigation**: M-3 (re-emergence visibility) refactors
  `cex_continuity.py` to a general `re_emergence.py` module that
  surfaces mixer-exit leads with `confidence='very_low'` and explicit
  "LEAD ONLY" caveat. Targeted for v0.33; partial in v0.32.1.
- **Residual risk**: medium (open). Disclosed in brief.
- **Owner**: trace lead.
- **Version-closed**: partial v0.32.1.

### R-017 — Privacy-pool exit (Privacy Pools, RAILGUN multi-chain)

- **Description**: Privacy Pools (0xbow) and RAILGUN on non-mainnet
  chains have incomplete labeling. Funds entering on Optimism / Base
  / Arbitrum where the labeled contract address is not in the seed
  produce a trace that does not even mark the entry as a mixer.
- **Likelihood**: medium for sophisticated cases.
- **Impact**: high (trace continues past the mixer without recognizing
  it as a mixer, leading to false attribution downstream).
- **Mitigation**: M-3 + per-chain mixer-seed expansion in
  `labels/seeds/mixers.json`.
- **Residual risk**: low for the common chains; medium for novel
  privacy-pool deployments.
- **Owner**: labels lead.
- **Version-closed**: v0.32.1 + ongoing label maintenance.

---

## Category C — Operational

### R-018 — Cron HA dual-leader race

- **Description**: v0.32 added Postgres-backed cron leader election
  via `cron_jobs_lock` table. A clock skew between Railway replicas
  could in theory cause two replicas to both think they hold the
  lease.
- **Likelihood**: low. Railway clocks are NTP-synced.
- **Impact**: medium (double-fired job; idempotent jobs survive,
  non-idempotent could double-write).
- **Mitigation**: `worker/cron_scheduler.py` uses fencing tokens
  in the lease check + per-job idempotency keys for the OFAC sync
  and retrace backfill.
- **Residual risk**: low.
- **Owner**: ops lead.
- **Version-closed**: v0.32.0.

### R-019 — Railway redeploy mid-case

- **Description**: A worker pod gets recycled mid-trace. The case
  state is partially persisted; the next worker pod picks it up but
  doesn't know which wave was in progress.
- **Likelihood**: medium (Railway redeploys happen daily).
- **Impact**: medium (case status stuck; operator must manually
  re-kick).
- **Mitigation**: worker-claim heartbeat in `investigations` table
  with `RECUPERO_WORKER_CLAIM_TIMEOUT_SEC`; stuck cases get re-claimed
  after the heartbeat expires. Per-wave checkpointing in `case.json`
  (`stage_checkpointing` design doc).
- **Residual risk**: low.
- **Owner**: ops lead.
- **Version-closed**: v0.31.x.

### R-020 — Supabase outage during case write

- **Description**: Postgres backend goes down mid-write. Case state
  in Postgres is partially updated; filesystem state on the worker
  pod is more recent.
- **Likelihood**: low. Supabase has 99.9%+ SLA.
- **Impact**: high (case state divergence between Postgres and
  filesystem).
- **Mitigation**: filesystem is the source of truth for one case;
  Postgres carries durable metadata. On Supabase recovery the worker
  replays the audit log to reconcile.
- **Residual risk**: low.
- **Owner**: ops lead.
- **Version-closed**: v0.31.x.

### R-021 — Etherscan V2 rate-limit during case

- **Description**: Free-tier Etherscan rate limit is 5 calls/sec.
  A multi-wave BFS easily hits this. Pre-fix the
  `is_contract_cache` defaulted to True on lookup failure (HIGH-6 in
  trace audit), causing silent BFS truncation.
- **Likelihood**: high if running on free-tier keys.
- **Impact**: medium. Cases silently truncate.
- **Mitigation**: HIGH-6 fix changes `is_contract_cache` to use a
  sentinel `None` for "unknown" and re-probes. `RECUPERO_CONTRACT_CHECK_FAILURES_SOFT_CAP`
  surfaces the count in the brief footer.
- **Residual risk**: low (with paid Etherscan key); medium (on
  free tier — disclosed in `.env.example`).
- **Owner**: ops lead.
- **Version-closed**: v0.32.1 (HIGH-6).

### R-022 — Helius / Alchemy outage mid-case (Solana / EVM)

- **Description**: Solana traces depend on Helius; EVM optionally
  uses Alchemy. Either upstream going down mid-case truncates the
  trace.
- **Likelihood**: low-medium. Helius has had public outages 1-2x
  per quarter historically.
- **Impact**: high (trace silently incomplete on the affected chain).
- **Mitigation**: per-adapter circuit breaker with `partial_chain_outage`
  marker in `case.config_used`. Brief renders an explicit footer
  warning.
- **Residual risk**: low.
- **Owner**: ops lead.
- **Version-closed**: v0.31.x.

### R-023 — API budget exhaustion mid-case

- **Description**: `RECUPERO_API_BUDGET_USD_PER_CASE` limits per-case
  external API spend. Pre-v0.32.0 default was $0.50 — adversary
  Route 3 exploits this directly. v0.32.0 raised default to $10,000
  (W2-H item 1).
- **Likelihood**: medium for cases > $25M.
- **Impact**: high (partial trace; brief carries `partial_budget_hit`
  marker).
- **Mitigation**: budget bump + explicit operator override at runtime.
- **Residual risk**: medium (architectural). $50M+ speed-laundered
  cases still hit budgets.
- **Owner**: ops lead.
- **Version-closed**: v0.32.0 (budget bump); residual disclosed.

---

## Category D — Compliance / legal

### R-024 — Subpoena issued to wrong corporate entity

- **Description**: Pre-v0.32.1 the freeze letter rendered `issuer.name`
  as the un-suffixed key from `freeze_brief.json` — "Tether" instead
  of "Tether Operations Limited", "Circle" instead of "Circle Internet
  Group, Inc.", "Coinbase" instead of "Coinbase Custody Trust Company,
  LLC". Freeze letter goes to the wrong legal entity; compliance
  ignores or routes to unverified-sender bin.
- **Likelihood**: very high (pre-fix; affects every freeze letter).
- **Impact**: critical (no freeze action; case dies).
- **Mitigation**: W1-B Wave 1 fix populates `legal_entity_name` and
  `corporate_jurisdiction` fields in `issuers.json` and reads them in
  `_issuer_info_for` (`worker/_deliverables.py:1711-1726`).
- **Residual risk**: low.
- **Owner**: legal lead.
- **Version-closed**: v0.32.1 (W1-B / CRIT-FR-2).

### R-025 — Freeze letter to dissolved or restructured entity

- **Description**: A previously-correct corporate entity dissolves
  or restructures (e.g. Circle Internet Financial → Circle Internet
  Group post-IPO). Stale data in `issuers.json` directs the freeze
  letter to a non-entity.
- **Likelihood**: low but rising as the industry consolidates.
- **Impact**: high (freeze letter bounces).
- **Mitigation**: `stale_label_alert` cron job (`worker/cron_scheduler.py`)
  also flags stale issuer-entity records older than 90 days; manual
  refresh process; documented in operator runbook.
- **Residual risk**: low.
- **Owner**: legal + ops.
- **Version-closed**: v0.32.1.

### R-026 — Wrong statutory citation (§ 3486 was wrong pre-fix)

- **Description**: Pre-W1-B the freeze letter cited 18 U.S.C. § 3486
  for subpoena authority. § 3486 is the Internal Revenue Service
  administrative-summons statute, not the appropriate subpoena
  citation for crypto-theft freeze requests. Correct citation is
  18 U.S.C. § 2703(d) (Stored Communications Act) or § 1956 (money
  laundering) depending on context.
- **Likelihood**: high (pre-fix; every freeze letter).
- **Impact**: critical (compliance teams immediately flag the wrong
  citation; brief credibility destroyed).
- **Mitigation**: W1-B fix replaces § 3486 with the correct citation
  per use case. New `IssuerInfo.statutory_citation` field selects
  per issuer + case shape.
- **Residual risk**: low.
- **Owner**: legal lead.
- **Version-closed**: v0.32.1 (W1-B / FR-CRIT-3).

### R-027 — Victim-name attribution in public deliverables

- **Description**: The brief, freeze letter, and LE handoff carry
  the victim's name. If these documents are accidentally posted
  publicly (e.g. an analyst uploads them to a shared drive without
  ACLs), victim privacy is breached.
- **Likelihood**: low (operator discipline).
- **Impact**: high (privacy breach; reputational; possible PII-
  regulation exposure).
- **Mitigation**: every deliverable carries an "UNSIGNED — DO NOT
  TRANSMIT" watermark until reviewed; the bucket-upload path is
  ACL-gated by Supabase Storage policies; victim PII is redacted from
  certain log lines (PII_REDACT pattern).
- **Residual risk**: medium (operator discipline). README
  explicitly warns against external sharing.
- **Owner**: ops lead.
- **Version-closed**: v0.31.x.

### R-028 — Recovery disclosure becomes stale

- **Description**: The published Wilson 95% CI recovery rate is
  computed quarterly from `freeze_outcomes`. If the table grows
  faster than the quarterly recompute, the published figure is stale.
- **Likelihood**: medium.
- **Impact**: medium (misrepresentation risk; could be argued as
  unfair or deceptive trade practice if egregiously stale).
- **Mitigation**: `monitoring/recovery_rate.py` recomputes monthly;
  the quarterly publication uses the most-recent monthly snapshot.
  Disclosure carries `as_of_date`.
- **Residual risk**: low.
- **Owner**: product + legal.
- **Version-closed**: v0.32.0.

---

## Category E — Security

### R-029 — Label-promote JSON injection (CRIT-1 of security audit)

- **Description**: Pre-W1-D `_append_to_seed_file` wrote attacker-
  controlled JSON to `bridges.json` / `cex_deposits.json` with no
  address-shape validation, no chain-allow-list check, no name-charset
  sanitization. Admin-key compromise (or even an over-permissive
  operator) injects `{"address": "0xLegitCoinbase…", "category":
  "mixer"}` and the next-day briefs mis-target Coinbase as a mixer.
- **Likelihood**: low (admin-key access required); high impact if
  it happens.
- **Impact**: critical.
- **Mitigation**: W1-D fix adds address-shape validation per chain
  (EVM 0xhex / Solana base58 / Tron T-prefix base58 / BTC bech32),
  chain-allow-list check, name-charset sanitization (alphanumeric +
  limited punctuation), and category-allow-list enforcement.
- **Residual risk**: low.
- **Owner**: security lead.
- **Version-closed**: v0.32.1 (W1-D / SEC-CRIT-1).

### R-030 — SSRF via auto-ingest HTTP redirects

- **Description**: `auto_ingest._safe_http_get_json` runs against
  operator-influenceable upstream URLs. A DNS-rebinding attack
  could pivot a Recupero cron into an SSRF probe of the Railway
  internal network.
- **Likelihood**: low (sophisticated attack required).
- **Impact**: high (internal network reconnaissance).
- **Mitigation**: W1-D fix adds private-IP block, scheme allow-list
  (https only), DNS-resolve-once-then-pin pattern, explicit
  `follow_redirects=False`.
- **Residual risk**: low.
- **Owner**: security lead.
- **Version-closed**: v0.32.1 (W1-D / SEC-HIGH-1).

### R-031 — CSRF gate bypass on intake

- **Description**: `_intake_post_csrf_ok` was bypassed by requests
  with no Origin AND no Referer header. Bots strip both; spam-create
  case rows at 5/min/IP rate limit.
- **Likelihood**: medium.
- **Impact**: medium (spam DB load; case-id collisions).
- **Mitigation**: W1-D fix requires either Origin OR Referer header
  present; both-absent requests are rejected.
- **Residual risk**: low.
- **Owner**: security lead.
- **Version-closed**: v0.32.1 (W1-D / SEC-HIGH-3).

### R-032 — Admin-key compromise

- **Description**: Single `RECUPERO_ADMIN_KEY` for all admin
  operations. If it leaks once, attacker approves every pending
  brief AND promotes arbitrary labels AND reads every investigation
  row.
- **Likelihood**: low (operator discipline + key rotation).
- **Impact**: critical.
- **Mitigation**: minimum entropy requirement; rate limit on
  promote endpoint (10/hour per admin key — M-8); second-reviewer
  requirement on promote (M-2 deferred to v0.33; soft check in
  v0.32.1 via audit log + Slack alert on every promote).
- **Residual risk**: medium (open at single-key-compromise level).
  Two-key signing deferred to v0.33.
- **Owner**: security lead.
- **Version-closed**: partial v0.32.1.

### R-033 — Single-reviewer promote

- **Description**: One operator can promote a label candidate without
  second-reviewer sign-off. Operator fatigue + 800-entry seed file =
  ~0.5% review-error rate. A poisoned candidate that gets promoted
  becomes a self-labeled "bridge" the adversary controls.
- **Likelihood**: medium.
- **Impact**: high (trace gets consumed at the fake bridge).
- **Mitigation**: M-1 multi-source confirmation (two independent
  upstream sources required before promote) lands in v0.32.1 via
  W1-D follow-on. M-2 two-key signing deferred to v0.33.
- **Residual risk**: medium (M-1 lands, M-2 deferred). Disclosed.
- **Owner**: security lead.
- **Version-closed**: partial v0.32.1.

---

## Category F — Output integrity

### R-034 — Mixed-asset row contradiction (CRIT LE-1)

- **Description**: Pre-W1-A the LE handoff "Stolen Asset Details"
  table rendered self-contradictory rows on mixed-asset drains:
  `Asset symbol: USDT`, `Amount: 2 events, mixed assets`,
  `USD value: $21,317.94`. Lawyer reads, frowns, closes laptop.
- **Likelihood**: very high (pre-fix; every mixed-asset case).
- **Impact**: critical (credibility destroyed in first 10 seconds).
- **Mitigation**: W1-A Wave 1 fix splits the table into per-asset
  breakdown rows when `theft_assets_mixed=True`.
- **Residual risk**: low.
- **Owner**: brief lead.
- **Version-closed**: v0.32.1 (W1-A / LE-CRIT-1).

### R-035 — Operator-name fallback in signature block

- **Description**: When `investigator.name` was missing the LE handoff
  signature block fell back to "Recupero Investigations" — under the
  diagonal "UNSIGNED" watermark, in three locations. A real lawyer
  reads it as a hobbyist self-publication.
- **Likelihood**: medium (depended on operator config).
- **Impact**: high.
- **Mitigation**: W1-A fix requires explicit `investigator.name`;
  validator INVARIANT G (W2-G) enforces it as a hard check.
- **Residual risk**: low.
- **Owner**: brief lead.
- **Version-closed**: v0.32.1 (W1-A / LE-CRIT-2).

### R-036 — Cross-document divergence (G/H/I/J/K invariants)

- **Description**: The brief, LE handoff, and freeze letter for the
  same case can carry different USD totals, different destination
  address sets, and different recipient lists. Pre-v0.32.1 only the
  engagement letter's headline figure was cross-checked. The
  "3.6M drained / 3.55M destinations / 4.1M asks" pattern slipped
  silently.
- **Likelihood**: medium (depended on case shape).
- **Impact**: high (lawyer reading both sees inconsistency).
- **Mitigation**: W2-G adds INVARIANTS G (indirect-exposure
  scores), H (cluster IDs), I (CEX continuity leads). W3-L adds
  INVARIANTS J (intra-artifact cross-section sum coherence), K
  (brief ↔ freeze-letter token/amount/recipient consistency), L
  (address ↔ chain ↔ explorer URL coherence), M (time-window
  coherence).
- **Residual risk**: low post-W3-L.
- **Owner**: validator lead.
- **Version-closed**: v0.32.1 (W2-G + W3-L).

### R-037 — Stale-label PIT render

- **Description**: A label was set when the incident happened but
  the seed file has been updated since. The brief should render the
  label as-of incident time (PIT), not as-of render time. Pre-v0.32.1
  INVARIANT N did not exist; PIT render verification was 0% covered.
- **Likelihood**: medium (rising as label DB churns).
- **Impact**: high (forensically incorrect brief; PII / label
  attribution drift).
- **Mitigation**: W3-L adds INVARIANT N — every label cited in the
  brief must round-trip through `lookup_pit_safe(case.incident_time)`
  and match.
- **Residual risk**: low.
- **Owner**: validator lead.
- **Version-closed**: v0.32.1 (W3-L).

### R-038 — Determinism drift (3× build check)

- **Description**: A change to the brief renderer that introduces
  a non-deterministic ordering (e.g. dict iteration on Python < 3.7)
  produces different bytes on re-render. Court filings months later
  cannot be reproduced.
- **Likelihood**: low (Python 3.10+ minimum; ordered dicts).
- **Impact**: critical (chain-of-custody breaks).
- **Mitigation**: 3× determinism check in CI
  (`tests/test_brief_determinism.py` + `freeze_brief_determinism.py`).
  Wave 3 expands to include the LE handoff + freeze letter.
- **Residual risk**: low.
- **Owner**: brief lead.
- **Version-closed**: v0.32.0; ongoing CI gate.

---

## Category G — Financial

### R-039 — Recovery rate communication

- **Description**: A victim reads "Recupero may recover your funds"
  and infers a high probability. The historical rate is ~3% across
  the industry; even our best case is 10-15% for ideal shapes.
- **Likelihood**: high (this is the dominant failure mode of
  competitor products).
- **Impact**: high (refund pressure; reputational; possible UDAP
  exposure).
- **Mitigation**: pre-checkout Wilson 95% CI disclosure
  (`monitoring/recovery_rate.py`) shown on the intake form with
  explicit ACK checkbox. Customer signature on `recovery_disclosures`
  table.
- **Residual risk**: low.
- **Owner**: product + legal.
- **Version-closed**: v0.32.0.

### R-040 — ROI expectation drift

- **Description**: A customer pays $499 diagnostic + $10K engagement
  expecting funds back. Even with full freeze + LE engagement, partial
  recovery is the norm.
- **Likelihood**: high.
- **Impact**: medium-high.
- **Mitigation**: explicit disclosure pre-engagement of the
  "diagnostic" vs "recovery" distinction. Engagement letter
  (`engagement_letter.html.j2`) frames the service as evidence
  production, not recovery.
- **Residual risk**: medium. Customer expectations are hard to
  fully calibrate.
- **Owner**: product + legal.
- **Version-closed**: v0.32.0; ongoing.

### R-041 — Partial recovery accounting

- **Description**: An exchange freezes 50% of the perpetrator's
  hot-wallet balance. The brief claimed $1M freezable; $500K is
  actually frozen; the customer expects $1M back. Communication
  failure.
- **Likelihood**: medium-high.
- **Impact**: medium.
- **Mitigation**: `freeze_outcomes` table captures exact amount
  per outcome with `outcome_amount_usd`; the post-engagement summary
  is computed from this. Operator runbook documents partial-recovery
  communication script.
- **Residual risk**: low.
- **Owner**: ops + product.
- **Version-closed**: v0.31.x.

### R-042 — Refund handling

- **Description**: Customer demands refund when no LE handoff
  occurred within 7 days. Industry standard for diagnostic services
  is at least partial refund.
- **Likelihood**: medium.
- **Impact**: medium.
- **Mitigation**: refund policy documented; partial refund offered
  if no LE handoff within 7 days. Tracked in `freeze_outcomes` as
  `outcome=dropped` with refund metadata.
- **Residual risk**: low.
- **Owner**: ops + legal.
- **Version-closed**: v0.31.x.

---

## Category H — Reputational

### R-043 — Wrong destination on brief → freeze returns "no such address"

- **Description**: The brief identifies the wrong destination (R-024
  + R-029 dual failure). Operator sends freeze letter naming
  address 0xABC at Binance. Binance responds: "we have no record of
  this deposit." Operator looks unprofessional. Worse: if media
  picks it up, a "Recupero misidentified the destination, sent
  freeze letter to wrong exchange" headline ends the company.
- **Likelihood**: low post-v0.32.1 mitigations.
- **Impact**: critical (existential).
- **Mitigation**: R-024 (legal entity name) + R-029 (label-promote
  validation) + R-036 (cross-document consistency) all close in
  v0.32.1. Mandatory human-review gate (INVARIANT F) is the final
  defense — an operator catches the wrong destination before send.
- **Residual risk**: low post-v0.32.1. The mitigations work
  individually and the review gate is defense-in-depth.
- **Owner**: brief + legal + ops.
- **Version-closed**: v0.32.1 (combined).

---

## Summary table — top 10 residual risks at v0.32.1 ship

These are the risks that remain non-trivial after v0.32.1 lands. Used
for the Jacob handoff conversation.

| Rank | ID | Description | Residual likelihood × impact |
|---|---|---|---|
| 1 | R-002 | Smart-wallet ownership swap (Safe `swapOwner`) | medium × critical |
| 2 | R-014 | Adversary Route 3 (speed-laundered $50M+) | low × critical |
| 3 | R-005 | ERC-4337 full user-op decomposition | medium × high |
| 4 | R-003 | Bitcoin Lightning exits | medium × high |
| 5 | R-004 | Cosmos / IBC zero coverage | low × high |
| 6 | R-016 | Mixer-exit lead detection (full M-3) | medium × medium-high |
| 7 | R-032 | Admin-key compromise (two-key signing deferred) | low × critical |
| 8 | R-033 | Single-reviewer promote (M-2 deferred) | medium × high |
| 9 | R-040 | ROI expectation drift on partial recovery | high × medium-high |
| 10 | R-027 | Victim-name attribution in public deliverables | low × high |

All other risks (R-001, R-006 through R-013, R-015, R-017 through R-026,
R-028, R-029 through R-031, R-034 through R-039, R-041 through R-043)
are mitigated to "low × ≤ medium" by v0.32.1.

---

*End of RISK_REGISTER.*
