# Road to #1 — v3 (post-activation-sweep gap audit, 2026-06-09)

A fresh, **verified** net-new gap audit run after the v0.39 Activation Sprint +
dormant-capability sweep. Every gap below was confirmed missing by code search
(the repo is far more mature than its TODOs imply — many v2 "Phase 1" items have
since shipped and are explicitly **excluded** here).

## Already shipped since roadmap v2 (excluded from the gap list)
- Deep-reach is **default-ON** (`tracer._deep_reach_enabled`, opt-out `RECUPERO_DEEP_REACH=0`).
- Litigation artifacts **default-ON** (`_deliverables._auto_litigation_enabled`).
- CCTP medium-follow decoder wired (`bridge_calldata._decode_cctp`).
- Demixing auto-runs in the worker pipeline (`pipeline._maybe_write_demix_leads`) + trace-report §8.
- Cosmos / TON / Stellar adapters wired into `ChainAdapter.for_chain`.
- mev_builders 14-registry + burn-sink surfacing (trace-report §9) activated.
- erc4337 `execute()` + `executeBatch` unwrap (decoder correctness).
- Cross-victim clustering surfaced in LE handoff; AA ERC-20/native flows already
  captured via event-based `tokentx` + `txlistinternal`.

## Ranked net-new gaps (highest recovery value first)

| # | Gap | Verified-missing (what was checked) | Recovery value | Effort | Net-new data/decoder/adapter | Forensic constraint |
|---|-----|-------------------------------------|:--:|:--:|---|---|
| 1 | **Verified exchange-freeze contact DB is empty** | `labels/seeds/exchange_freeze_contacts.json` has only `_README`/`_schema`/`_example`; loader `freeze/exchange_contacts.py` falls back to unverified `compliance@<exchange>` guesses | **HIGH** | M | **Data** (research top-20 CEX LE-portal URLs + freeze-capability + response-time priors) | Never `verified=true` without a real channel + source; a wrong contact wastes the freeze window |
| 2 | **Inbound outcome/reply ingest absent** — outcome capture is 100% manual | `freeze_learning/recorder.py` has `record_outcome` but no IMAP/webhook reply parser feeds it; priors never reach the n≥20 learned threshold → cooperation moat data-starved | **HIGH** | M | Net-new ingest (reply parser → `record_outcome_by_target`) | Auto-recorded outcomes stay human-reviewable; never auto-mark "recovered" from an ambiguous reply |
| 3 | **Alert → auto-draft → human-gate freeze loop** — detection is advisory-only | `monitoring/recovery_alerts.py` emits a `freezable_inflow` alert with a *text* recommendation; nothing auto-drafts a freeze into `brief_reviews`. For stablecoin theft (minutes) this is the #1 time-to-freeze gap | **HIGH** | M | Pure code (bridge alert + freeze artifact + review row) | Must land in the human-approval queue, not auto-send (INVARIANT F) |
| 4 | **Cooperation intelligence doesn't DRIVE dispatch** — only annotates | `cooperation_intelligence.py` computes `is_black_hole`/`recommend_legal_instrument`, but `ops/commands/send_freeze_letters.py` ignores it (a known black-hole exchange still gets an email instead of routing to AUSA subpoena) | **HIGH** | M | Pure code (wire signal into `_build_dispatch_plan`) | Routing decision must be explainable + logged; never silently drop a freeze ask |
| 5 | **Live mempool / pending-tx pre-freeze watch** | All "mempool" refs are explorer URLs; no `eth_subscribe`/Alchemy/Helius pending subscriptions; poller is poll-based. The only pre-confirmation freeze trigger in the market | **HIGH** | L | Net-new data (pending-tx websockets) + adapter | Pending tx can be dropped/replaced — mark "unconfirmed — may not land", never settled fact |
| 6 | **Cross-chain IBC continuation OUT of Cosmos** | `chains/cosmos/adapter.py` TODO(wave-8): `MsgRecvPacket`/`MsgTransfer` decode absent; BFS dead-ends at the IBC hop after an Axelar→Cosmos resolve | MED-HIGH | M | Decoder (IBC packet/`denom_trace`; adapters present) | Per-zone counterparty-channel mapping verified before asserting continuation; ≤medium |
| 7 | **Async bulk-screen for compliance desks** | `/v1/screen/bulk` is sync, capped at 100, no job-id/poll/webhook or per-key quota/cache | MED-HIGH | M | Pure code (async job + quota + cache) | No correctness risk; keep per-row error containment |
| 8 | **Cross-asset DEX swap-chain depth** — stops after first swap hop | `dex_swaps.py` resolves ONE swap's output recipient; doesn't recursively trace the swapped asset through 3+ pairs (USDT→WBTC→ETH→SHIB) | MED-HIGH | M-L | Pure code (recursive re-seed BFS on swap-output token) | Confidence decay per swap hop |
| 9 | **Sanctions/label-drift re-screen of OPEN cases** | OFAC daily sync exists, but no "OFAC added wallet X today; it's in active case Y" delta→alert | MED | S | Pure code (OFAC delta ⋈ open-case address set) | Point-in-time discipline: forward-looking alert only; must not rewrite the brief's historical label |
| 10 | **New Move-VM chains (Sui / Aptos)** | `models.Chain` enum has no `sui`/`aptos`/`cardano`/`near`/`monero` (verified full enum read); rising 2025 drainer destinations | MED | L (each) | **New adapter** (object/coin model ≠ account model) | Verify address codec + transfer semantics before trusting traces |

## Themes / recommendation
- **Highest ROI is recovery-automation + data, not new chains.** #1–#4 turn "tells
  you to act" into "the freeze is one click away" and are mostly code/data, not
  new decoders. **#1 (empty contact DB) is the single cheapest high-value win** —
  pure verified-data research.
- **#5 (mempool pre-confirmation freeze) is the one true greenfield differentiator** —
  no competitor offers it — but it's the largest build (streaming infra + an
  "unconfirmed" forensic caveat).
- Deferred (need proprietary data / out-of-scope by doctrine): predictive
  next-hop modeling (needs a trained model); behavioral fingerprinting (glass-box
  ≤medium-confidence hard to make litigation-grade).

_This roadmap is the successor to ROADMAP_TO_NUMBER_ONE_v2.md; v2's Phase-1
activation items are now shipped (see top)._
