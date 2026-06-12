# Road to #1 — v4 (post roadmap-v3 completion + tri-domain audit, 2026-06)

Successor to v3. All ten v3 items shipped (verified freeze-contact DB, reply-ingest,
alert→auto-draft, cooperation→dispatch, OFAC-delta re-screen, mempool pre-freeze +
reconnect, recursive DEX-swap depth, Sui/Aptos address-codec foundation). This v4 is
built from three **code-verified** audits run after v3: an adversarial review of every
v3 module, a net-new tracer-moat audit, and a recovery-automation/data-scale audit.

## Already fixed in this cycle (adversarial review of the v3 modules)
Real forensic-correctness defects found + fixed (with tests):
- `reply_parser`: negated phrases ("no funds were returned") no longer become
  `returned_to_victim`; mixed "froze $X but can't freeze the rest" → `partial_freeze`
  (not `declined`); `$`-amounts attach to the matched verb (not the theft figure);
  "will not freeze" → `declined`.
- `ofac_delta_rescreen`: an empty/collapsed OFAC CSV no longer clobbers the snapshot
  baseline (prevents a restore-after-hiccup alert flood).
- `mempool_watch`: reconnect counter is now CONSECUTIVE (a healthy drain resets it) —
  a long-lived race watch survives sporadic drops.
- `cli parse-freeze-reply`: a recorder miss (no prior freeze letter) prints a clear
  message instead of a traceback + losing the parse.
Verified CLEAN by the same review: `move_address`, `freeze_draft` rendering (XSS-safe,
no auto-send path), `_continue_dex_swap_chain` (byte-identical no-op at default).

## SHIPPED in v0.41 (this cycle — all FF-pushed to main, prod-deployed)
The "dormant capability → wire into the act path" theme paid off: every
S/M-effort Tier-1 item and the strongest pure-code Tier-2 builds are live.
- **#1** verified freeze-contacts reach dispatch (`ba66eea`) — verified LE email
  replaces the unverified guess; portal-only majors → a manual-portal prompt.
- **#2** dispatch ESCALATE advisory points at the rendered MLAT/314b/subpoena
  artifact in `legal_requests/`, or prints the render command (`38ceb7b`).
- **#3** OFAC-delta alerts persist to the `/v1/recovery-alerts` console queue
  (`84257b6`, `alerts_to_recovery_rows` → `persist_alerts`).
- **#4** freeze drafts to the durable `RECUPERO_DATA_DIR` + per-case filename
  (no more dangling review-gate path) (`5cd7dc0`).
- **#6** NFT-transfer coverage activated as a gated artifact (`a4059fe`,
  `RECUPERO_NFT_FLOWS`) — live-verified tokennfttx/token1155tx shapes.
- **#7** Uniswap V3 LP park-and-withdraw via position-id continuity (`53d9b88`,
  `RECUPERO_LP_LEADS`) — 6 NPM addresses chain-verified.
- **#11** DeFi lending/vault park-and-withdraw — Aave V3 (`36d52a7`,
  `RECUPERO_LENDING_LEADS`) + ERC-4626 vaults (`18ea621`, `RECUPERO_VAULT_LEADS`,
  protocol-agnostic via the indexed owner-topic).
- **DeFi-reach pack is operator-accessible on-demand**: `recupero-ops defi-leads
  --case <id> [--only nft,lp,lending,vault]` runs all four runners against a
  finished case without a worker re-run. Every lead is review-only, never a
  followed destination; the recoverable total is never touched.

The proven RUNNER RECIPE (4×): keccak topic0 → live-log layout check →
per-chain address verification via the Etherscan v2 multichain API → runner
module → gated pipeline hook → artifact + guarded trace-report section →
ENV row → real-log-fixture tests → full regression → FF-push.

### Non-EVM trace-coverage gaps closed this cycle (the three keyless builds)
All three were unblocked by live-probing the public endpoints (TronGrid,
Cosmos LCD, Hyperliquid info API are keyless/reachable — no procurement),
then built on already-verified on-chain shapes (no fabrication):
- **#8 Cosmos IBC-out** (`05de15c`) — `trace/ibc_decode.py` + `ibc_runner.py`:
  ICS-20 `send_packet` decode, denom-prefix strip, channel→zone registry,
  `(src_channel,dst_channel,sequence)` pair-id; Circle-USDC sends flagged
  freezable. Gated `RECUPERO_IBC_LEADS`. (Public Osmosis LCD 500s on the
  `message.sender` tx-search — a pre-existing fetch-layer limit the Cosmos
  trace already shares; decoder verified vs a real captured packet.)
- **#12 Hyperliquid `for_chain`** (`9fd07f3`) — `chains/hyperliquid/adapter.py`:
  `HyperliquidAdapter` exposes withdraw/deposit ledger events as Transfer-shaped
  rows so a bridge-IN continuation no longer dead-ends; reuses the proven
  scraper's `get_non_funding_ledger_updates` + ARBITRUM_USDC mapping; no
  per-event receipt → `fetch_evidence_receipt` raises rather than fabricate.
- **#10 Tron freeze-race watcher** (`3f96e1c`) — `monitoring/tron_watch.py` +
  `recupero-ops tron-watch`: polls watched wallets' recently-SETTLED outbound
  USDT-TRC20; flags FREEZABLE when the destination resolves to a known exchange
  label. Base58check is CASE-SENSITIVE (never lowercased). Gated
  `RECUPERO_TRON_WATCH`. Live path verified end-to-end against TronGrid.

## Tier 1 — highest recovery value, mostly CODE, buildable now

| # | Gap | Why it matters | Effort | Notes |
|---|-----|----------------|:--:|---|
| 1 | ✅ SHIPPED (`ba66eea`) — **Verified freeze-contacts are DORMANT in the send path** | `send_freeze_letters._build_dispatch_plan` dispatches to the issuer-DB's *unverified* `compliance@` guess, NOT `resolve_exchange_freeze_contact`. Portal-only majors (Binance/Coinbase/Crypto.com, `compliance_email: null`) hit `SKIP: missing contact_email` → the verified channel never reaches dispatch. **This silently defeats the v3 freeze-contact DB.** | **S–M** | Resolve each issuer through the verified resolver; portal-only → a "submit via Kodex <url>" plan item instead of SKIP. THE top fix. |
| 2 | ✅ SHIPPED (`38ceb7b`) — **Black-hole recommendation doesn't auto-GENERATE the escalation artifact** | `cooperation_intelligence` flags `escalate_beyond_email`/`recommended_instrument` (subpoena/MLAT/314b) and `silence_14d` advises it — but nothing renders the named instrument; the operator triggers it by hand. | **M** | Recommendation → auto-render the subpoena/MLAT/314(b) deliverable, still human-gated by the dispatcher. |
| 3 | ✅ SHIPPED (`84257b6`) — **OFAC-delta alerts are log-only** | `screen_ofac_additions` returns alerts but the cron discards them (logs the count); the "race a freeze" prompt lives only in Railway logs. | **S** | Persist via `recovery_alerts_store.persist_alerts` (or a table) + surface in the operator console. |
| 4 | ✅ SHIPPED (`5cd7dc0`) — **Freeze-draft artifacts written to `tempfile.mkdtemp()`** | `watch_tick` auto-draft writes to a per-tick temp dir; the `brief_reviews` row stores that path → leaks + dangles on restart, so the human-gate artifact can't be opened. | **S** | Write under the case's durable deliverables dir (or store the draft body in the DB). |
| 5 | **MistTrack attribution enrichment is fully DORMANT** | `labels/providers/misttrack.py` is a complete by-address enrichment provider; `attribution_coverage.py` computes prioritized labeling targets — but NOTHING calls the provider (zero call sites). Attribution still depends on manual research (the #1 gap vs Chainalysis). | **M** (code) + **DATA** (API key) | Wire the provider on the top-N coverage targets → candidate→review→promote. Needs a MistTrack key (procurement). |

## Tier 2 — net-new tracer moat (verified "decoded/exists-but-not-continued" gaps)

| # | Gap | Why | Effort | Confidence constraint |
|---|-----|-----|:--:|---|
| 6 | ✅ SHIPPED (`a4059fe`) — **NFT-transfer hops never followed in BFS** — `nft_transfers.py` parses+prices ERC-721/1155 but is wired into no BFS path (`TODO(wave-4)` live) | NFT-sale laundering / mint-and-flip value vanishes from the recoverable total | M | follow the fungible *proceeds* at high; NFT→identity inference ≤medium |
| 7 | ✅ SHIPPED (`53d9b88`) — **DEX LP-provision laundering** — no `addLiquidity`/`removeLiquidity`/V3 `mint` handling (`dex_swaps` is swaps only) | deposit→pool→later-remove-to-fresh-wallet dead-ends at the router/PositionManager | M | same-owner add→remove via position-id = high; V2 LP-token share ≤medium |
| 8 | ✅ SHIPPED (`05de15c`) — **Cosmos IBC continuation OUT of a zone** — `MsgRecvPacket`/`MsgTransfer` decode absent | Osmosis/Noble-USDC (Circle-freezable) routing dead-ends at the first IBC hop | M | packet seq+src/dst-channel matched both sides = high; denom-hash-only ≤medium |
| 9 | **BTC (and other no-log chains) pool-bridge inbound** — `BitcoinAdapter` has no `fetch_native_inflows`/`fetch_logs` | THORChain/Maya EVM→BTC pool disbursements (non-memo) lose the BTC leg | M | amount+time on a no-log chain = low (INVESTIGATE lead, never auto-proof) |
| 10 | ✅ SHIPPED (`3f96e1c`, Tron) — **Settled-tx freeze-race watcher for Tron/BTC** — mempool watch is ETH/Polygon-only; watch_tick is once-nightly balance-delta | Tron is half of USDT laundering; no near-real-time outbound alert there | M–L | settled-outbound detection = high; "heading to a freezable CEX" ≤medium. _BTC half deferred (no-log chain, see #9)._ |
| 11 | ✅ SHIPPED (`36d52a7`+`18ea621`) — **DeFi lending/vault park-and-withdraw** — no Aave/Compound/ERC-4626 `supply`/`withdraw`/`redeem` following | deposit→withdraw-to-fresh-wallet is clean parking; dead-ends at the pool | M | same-owner via receipt-token (aToken/share) = high; pooled inference ≤medium |
| 12 | ✅ SHIPPED (`9fd07f3`) — **Hyperliquid as a native venue** — currently synthetic-Arbitrum-USDC bridge edges only; no `for_chain` | top perps venue; internal routing invisible, weakening withdrawal attribution | S–M | in/out USDC edges high; internal HL ledger ≤medium |
| 13 | **Lightning-gateway dead-end labels empty** — `KNOWN_LIGHTNING_GATEWAYS` purged; `detect_lightning_exit`→None | BTC→Lightning custodial gateway is unrecoverable on-chain; mislabel wastes effort | S | DATA: a checksum-verified maintained gateway list (anti-fabrication) |

## Tier 3 — data scale (operator/procurement, not code)
- **Intl-sanctions data not loaded**: `sanctions_intl_live.csv` absent → only OFAC screens today. Download the OpenSanctions crypto bulk + run `recupero-ops import-sanctions` (commercial use = data licence).
- **Exchange LE-channel breadth**: 14 exchanges today; missing Upbit/Bithumb/HTX/Poloniex/Bitvavo/regional + stablecoin-issuer (Tether/Circle) freeze channels. Each = operator research keyed to the exchange's published LE page.
- **Ransomware IOC feed**: `ransomware.json` is intentionally empty (anti-fabrication). Source a verified CISA/FBI IOC feed + importer for BTC/XMR addresses.
- **IMAP/webhook reply auto-ingest**: `reply_parser.ingest_reply` exists; no inbound channel feeds it (operator pastes each reply). An SES-inbound/IMAP poller → `ingest_reply` accelerates the learned-prior moat.
- **Richer victim intake**: `portal/intake.py` collects only wallet/name/email/chain — add scam-type, counterparty platform, loss timeline, IC3/police report #; + proactive cross-victim cluster outreach.

## Sui / Aptos LIVE adapters
The address-codec foundation shipped (`chains/move_address.py`). These were deferred
because the live transfer adapters require verifying decimals + event shapes against REAL
RPC responses (hardcoding unverified decimals into the evidence core = fabrication risk).

- **Sui** — ✅ SHIPPED (`8064a7a`). `chains/sui/{client,adapter}.py`: keyless full-node
  JSON-RPC `suix_queryTransactionBlocks` (From/ToAddress, `showBalanceChanges` +
  `showInput`) + cached `suix_getCoinMetadata`. Sui has no per-transfer event; the adapter
  reconstructs honest from→to edges from the NET per-owner per-coin `balanceChanges` delta
  (sender's negative ↔ other AddressOwners' positive of the SAME coinType). A DEX swap
  (coin → a pool OBJECT, not an address) emits NO edge — correct, it's not a transfer.
  Decimals from LIVE-VERIFIED pinned coins (SUI=9, USDC=6, USDT=6) or a real metadata
  lookup; unresolvable coins are skipped, never guessed. Wired `for_chain(sui)` + CoinGecko
  platform `"sui"` + Suiscan explorer. 15 tests on the live shape; live end-to-end verified
  (reconstructed a real 0.228 SUI transfer edge). Sui-native USDC/USDT are issuer-freezable.
- **Aptos** — still deferred. REST `/v1/accounts/{addr}/transactions` (sender-side; the
  Indexer for inbound); parse BOTH coin `Withdraw/DepositEvent` AND fungible-asset events
  (the store-object→owner resolution is the key correctness trap); decimals from FA metadata
  (native `0x1::aptos_coin::AptosCoin`=8). `for_chain(aptos)`. Verify against ≥1 real tx
  before trusting in evidence — the same live-shape discipline that unblocked Sui.

## Themes
- **The cheapest highest-value wins are "dormant capability → wire into the act path"**
  (#1, #3, #4, #5) — the resolvers/data exist; they just don't reach dispatch/surface.
- **The real moat is DATA SCALE** (Tier 3): attribution feeds, LE-channel breadth,
  outcome history. Mostly procurement/operator work, not engineering.
- Tier-2 tracer gaps are genuine value leaks on chains we already cover; #6 (NFT) and
  #7 (LP) are the strongest pure-code, can-reach-high-confidence builds.
- **Tier-2 is now nearly clear**: #6, #7, #11 (EVM runners) + #8, #10, #12 (the three
  keyless non-EVM builds) all shipped. Remaining Tier-2 are DATA/limit-bound, not new
  architecture: #9 BTC/no-log pool-bridge inbound (amount+time = INVESTIGATE-only on a
  no-log chain) and #13 Lightning gateways (needs a checksum-verified maintained list —
  anti-fabrication). #5 (MistTrack) is the last Tier-1, gated on an API key (procurement).

_Successor to ROADMAP_TO_NUMBER_ONE_v3.md; v3's items are shipped (see top)._
