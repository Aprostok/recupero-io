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

## Tier 1 — highest recovery value, mostly CODE, buildable now

| # | Gap | Why it matters | Effort | Notes |
|---|-----|----------------|:--:|---|
| 1 | **Verified freeze-contacts are DORMANT in the send path** | `send_freeze_letters._build_dispatch_plan` dispatches to the issuer-DB's *unverified* `compliance@` guess, NOT `resolve_exchange_freeze_contact`. Portal-only majors (Binance/Coinbase/Crypto.com, `compliance_email: null`) hit `SKIP: missing contact_email` → the verified channel never reaches dispatch. **This silently defeats the v3 freeze-contact DB.** | **S–M** | Resolve each issuer through the verified resolver; portal-only → a "submit via Kodex <url>" plan item instead of SKIP. THE top fix. |
| 2 | **Black-hole recommendation doesn't auto-GENERATE the escalation artifact** | `cooperation_intelligence` flags `escalate_beyond_email`/`recommended_instrument` (subpoena/MLAT/314b) and `silence_14d` advises it — but nothing renders the named instrument; the operator triggers it by hand. | **M** | Recommendation → auto-render the subpoena/MLAT/314(b) deliverable, still human-gated by the dispatcher. |
| 3 | **OFAC-delta alerts are log-only** | `screen_ofac_additions` returns alerts but the cron discards them (logs the count); the "race a freeze" prompt lives only in Railway logs. | **S** | Persist via `recovery_alerts_store.persist_alerts` (or a table) + surface in the operator console. |
| 4 | **Freeze-draft artifacts written to `tempfile.mkdtemp()`** | `watch_tick` auto-draft writes to a per-tick temp dir; the `brief_reviews` row stores that path → leaks + dangles on restart, so the human-gate artifact can't be opened. | **S** | Write under the case's durable deliverables dir (or store the draft body in the DB). |
| 5 | **MistTrack attribution enrichment is fully DORMANT** | `labels/providers/misttrack.py` is a complete by-address enrichment provider; `attribution_coverage.py` computes prioritized labeling targets — but NOTHING calls the provider (zero call sites). Attribution still depends on manual research (the #1 gap vs Chainalysis). | **M** (code) + **DATA** (API key) | Wire the provider on the top-N coverage targets → candidate→review→promote. Needs a MistTrack key (procurement). |

## Tier 2 — net-new tracer moat (verified "decoded/exists-but-not-continued" gaps)

| # | Gap | Why | Effort | Confidence constraint |
|---|-----|-----|:--:|---|
| 6 | **NFT-transfer hops never followed in BFS** — `nft_transfers.py` parses+prices ERC-721/1155 but is wired into no BFS path (`TODO(wave-4)` live) | NFT-sale laundering / mint-and-flip value vanishes from the recoverable total | M | follow the fungible *proceeds* at high; NFT→identity inference ≤medium |
| 7 | **DEX LP-provision laundering** — no `addLiquidity`/`removeLiquidity`/V3 `mint` handling (`dex_swaps` is swaps only) | deposit→pool→later-remove-to-fresh-wallet dead-ends at the router/PositionManager | M | same-owner add→remove via position-id = high; V2 LP-token share ≤medium |
| 8 | **Cosmos IBC continuation OUT of a zone** — `MsgRecvPacket`/`MsgTransfer` decode absent | Osmosis/Noble-USDC (Circle-freezable) routing dead-ends at the first IBC hop | M | packet seq+src/dst-channel matched both sides = high; denom-hash-only ≤medium |
| 9 | **BTC (and other no-log chains) pool-bridge inbound** — `BitcoinAdapter` has no `fetch_native_inflows`/`fetch_logs` | THORChain/Maya EVM→BTC pool disbursements (non-memo) lose the BTC leg | M | amount+time on a no-log chain = low (INVESTIGATE lead, never auto-proof) |
| 10 | **Settled-tx freeze-race watcher for Tron/BTC** — mempool watch is ETH/Polygon-only; watch_tick is once-nightly balance-delta | Tron is half of USDT laundering; no near-real-time outbound alert there | M–L | settled-outbound detection = high; "heading to a freezable CEX" ≤medium |
| 11 | **DeFi lending/vault park-and-withdraw** — no Aave/Compound/ERC-4626 `supply`/`withdraw`/`redeem` following | deposit→withdraw-to-fresh-wallet is clean parking; dead-ends at the pool | M | same-owner via receipt-token (aToken/share) = high; pooled inference ≤medium |
| 12 | **Hyperliquid as a native venue** — currently synthetic-Arbitrum-USDC bridge edges only; no `for_chain` | top perps venue; internal routing invisible, weakening withdrawal attribution | S–M | in/out USDC edges high; internal HL ledger ≤medium |
| 13 | **Lightning-gateway dead-end labels empty** — `KNOWN_LIGHTNING_GATEWAYS` purged; `detect_lightning_exit`→None | BTC→Lightning custodial gateway is unrecoverable on-chain; mislabel wastes effort | S | DATA: a checksum-verified maintained gateway list (anti-fabrication) |

## Tier 3 — data scale (operator/procurement, not code)
- **Intl-sanctions data not loaded**: `sanctions_intl_live.csv` absent → only OFAC screens today. Download the OpenSanctions crypto bulk + run `recupero-ops import-sanctions` (commercial use = data licence).
- **Exchange LE-channel breadth**: 14 exchanges today; missing Upbit/Bithumb/HTX/Poloniex/Bitvavo/regional + stablecoin-issuer (Tether/Circle) freeze channels. Each = operator research keyed to the exchange's published LE page.
- **Ransomware IOC feed**: `ransomware.json` is intentionally empty (anti-fabrication). Source a verified CISA/FBI IOC feed + importer for BTC/XMR addresses.
- **IMAP/webhook reply auto-ingest**: `reply_parser.ingest_reply` exists; no inbound channel feeds it (operator pastes each reply). An SES-inbound/IMAP poller → `ingest_reply` accelerates the learned-prior moat.
- **Richer victim intake**: `portal/intake.py` collects only wallet/name/email/chain — add scam-type, counterparty platform, loss timeline, IC3/police report #; + proactive cross-victim cluster outreach.

## Sui / Aptos LIVE adapters (deferred — needs live RPC verification)
The address-codec foundation shipped (`chains/move_address.py`). The live transfer
adapters are deferred because they require verifying decimals + event shapes against
REAL RPC responses (hardcoding unverified decimals into the evidence core = fabrication
risk). Build plan for a session with RPC access:
- **Sui**: httpx client → `suix_queryTransactionBlocks` (filter `FromAddress`/`ToAddress`,
  query BOTH) with `showBalanceChanges`; parse `balanceChanges[]` (owner/coinType/amount);
  decimals from `suix_getCoinMetadata` (native `0x2::sui::SUI`=9). `for_chain(sui)`.
- **Aptos**: REST `/v1/accounts/{addr}/transactions` (sender-side; use the Indexer for
  inbound); parse BOTH coin `Withdraw/DepositEvent` AND fungible-asset events (the
  store-object→owner resolution is the key correctness trap); decimals from FA metadata
  (native `0x1::aptos_coin::AptosCoin`=8). `for_chain(aptos)`. Verify against ≥1 real tx
  per chain before trusting in evidence.

## Themes
- **The cheapest highest-value wins are "dormant capability → wire into the act path"**
  (#1, #3, #4, #5) — the resolvers/data exist; they just don't reach dispatch/surface.
- **The real moat is DATA SCALE** (Tier 3): attribution feeds, LE-channel breadth,
  outcome history. Mostly procurement/operator work, not engineering.
- Tier-2 tracer gaps are genuine value leaks on chains we already cover; #6 (NFT) and
  #7 (LP) are the strongest pure-code, can-reach-high-confidence builds.

_Successor to ROADMAP_TO_NUMBER_ONE_v3.md; v3's items are shipped (see top)._
