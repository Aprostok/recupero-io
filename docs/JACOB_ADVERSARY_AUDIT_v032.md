# Jacob-style ADVERSARY audit — v0.32.0 (HEAD 7613281 on pdf-deliverables, sourced from main c43be19)

Prepared 2026-05-28. Scope: an adversary who has READ THE SOURCE CODE on
GitHub designs a laundering route SPECIFICALLY engineered to evade Recupero.
This is the inverted threat model — every other audit asks "where does
Recupero fail by accident?" This one asks "where does Recupero fail when
the perpetrator is reading the code while they launder?"

**Bottom line up top**: a $5K-consultant adversary can design a route that
gives Recupero **a coherent-looking but completely wrong destination**
on the brief. The operator reads "funds reached Binance hot wallet 0xABC,
issue Exhibit C subpoena" and never learns the funds are actually sitting
in a Tron USDD position via a path that touched zero labeled bridges. The
freeze letter goes to Binance, Binance answers "no such deposit recorded,"
the case dies. Across the three routes designed below, **3 of 3 evade**
end-to-end. Two of them also poison the auto-ingest pipeline.

This is the most important audit-cycle finding. We are shippable for
honest perpetrators (most of the long tail). We are NOT shippable against
a sophisticated APT that has read the repo, and we should not market the
product as such.

---

## STEP 1 — Route 1: $5M USDC from an Ethereum victim, designed for evasion

**Adversary knowledge**: source code. Knows:
- `min_fanout=10`, `dust_threshold_usd=$1` (dust-attack detector default,
  `src/recupero/trace/dust_attack.py:97-99`)
- `max_depth=4` default + `[1, 8]` clamp (`tracer.py:163-171`)
- `crosschain_window=24h` (`src/recupero/trace/cex_continuity.py:56` for
  the CEX continuity heuristic, similar 24h windows in clustering)
- `RECUPERO_API_BUDGET_USD_PER_CASE=$0.50` (per env-vars doc)
- `service_wallet_outflow_threshold=200` (`config.py:68`)
- `_SHARED_INFRA_PARTNER_THRESHOLD=5` (`clustering.py:130`)
- `_MIN_CLUSTERING_USD=$100` (`clustering.py:121`)
- `_COMMON_FUNDING_WINDOW=24h`, `_COMMON_WITHDRAWAL_WINDOW=12h`
  (`clustering.py:110-115`)
- `_DEFAULT_NOISY_TOKENS = {USDT, USDC, DAI, ETH, WETH}` (`cex_continuity.py:63`)
- `_DEFAULT_MIN_USD = $100k` for CEX continuity (`cex_continuity.py:57`)
- Confidence decay window = 180 days (`labels/confidence_decay.py:35`)
- Bridge calldata decoded for 13 protocols + Stargate v2; **NOT** decoded
  for Polygon PoS RootChainManager `depositFor`, Optimism L1StandardBridge
  `depositERC20To`, Arbitrum Inbox `depositEth`, zkSync `requestL2Transaction`,
  Base canonical bridge `depositTransaction`. (`trace/bridge_calldata.py`
  has Connext/Axelar/LiFi/Wormhole/Across/Stargate/Hop/Squid/Celer/Synapse/
  Symbiosis/DeBridge/LayerZero/CCIP/Multichain/Stargate-v2 but no
  rollup-canonical bridges)

### Route 1 — the actual hops

**T+0 (theft moment)**: Drainer signs over $5M USDC at victim address
`V`. Hardcoded recipient `H` (Hop 0 → 1).

**Hop 1 — Approval-then-pull, not direct transfer**. `V` is induced
(phishing) to call `USDC.approve(SiphonContract, MAX_UINT256)`. The
SiphonContract then calls `USDC.transferFrom(V, S1, $5M)`. Recupero
indexes Transfer events (via `tokentx` action on Etherscan), so the
Transfer FROM V TO S1 IS observed and the trace starts. **No evasion
here** — but the perpetrator-controlled SiphonContract is the *signer*
of the tx; the Transfer events show V→S1. Recupero never surfaces the
contract that signed, only `from_address=V, to_address=S1`. The adversary
gets to redact the very tool used. Minor signal loss; documented for
completeness.

**Hop 2 — Smart wallet (EIP-7702 / Safe) ownership change**. S1 is a
Gnosis Safe whose ownership is transferred via `swapOwner(prevOwner,
oldOwner=H, newOwner=H_new)`. **No ERC-20 Transfer event fires.** The
funds remain inside S1; control of S1 changed hands. Recupero's BFS
walks Transfer-event lists; it sees S1 received $5M and S1 is a contract.
`policy.stop_at_contract = True` (default). **BFS terminates at S1.**
The Safe-ownership-change is a regular tx with no Transfer log, so it
never enters the case. The funds appear to have been "delivered to a
DeFi contract" in the brief. Adversary owns the Safe under a different
key now.

* **Recupero sees**: Section 5 — "Destination: 0xS1 (unlabeled contract).
  Trace terminated at contract."
* **Recupero misses**: The Safe is still adversary-controlled; ownership
  was swapped. The funds are not "delivered to DeFi" — they are sitting
  in the adversary's continued custody. The brief implies a dead end.

**Hop 3 — Polygon PoS canonical bridge, NOT in the decoder list**. The
adversary, controlling the Safe under the new key, calls
`RootChainManager.depositFor(user=adversary_polygon_address, rootToken=USDC,
depositData=abi.encode($5M))` on Ethereum. `RootChainManager` IS labeled
in `bridges.json` (line ~215 "Polygon: RootChainManager") so the BFS sees
the destination as a labeled bridge and applies `stop_at_bridge=True`.
The brief reports "Bridged via Polygon: RootChainManager — follow up at
polygonscan.com." But:

* The Polygon RootChainManager calldata format is NOT in
  `_decode_bridge_calldata` dispatch (`bridge_calldata.py:460-705`). No
  destination address is extracted. The handoff renders as "destination
  candidates: polygon" with no concrete address.
* The trace's "continuation past bridges" logic in `tracer.py:478-493`
  attempts a cross-chain continuation, but only when the bridge decoder
  returned a `destination_address`. Since `_decode_bridge_calldata`
  returns `None` for Polygon PoS, the continuation does NOT run on the
  destination side.

**Adversary deliberately picked Polygon PoS because there is no decoder.**
There is also no Optimism `L1StandardBridge.depositERC20To`, no Arbitrum
`Inbox.depositEth` / `L1ERC20Gateway.outboundTransfer`, no zkSync, no
Base canonical bridge decoder. Any of these would have worked. The
adversary picked the one with the highest USDC liquidity.

* **Recupero sees**: "Bridged to Polygon — follow-up URL: polygonscan.com"
* **Recupero misses**: The exact Polygon address. Operator now has to
  manually subpoena Polygon and reconstruct.

**Hop 4 — On Polygon, the funds land at adversary's address P1**. P1 is
*not* in the case at all because the destination-address decode failed.
The continuation pass in `tracer.py` cannot run without an
address-on-destination-chain. End of trace.

But the adversary continues laundering on Polygon, **invisible to Recupero**:
- Swap USDC → USDC.e via Polygon's QuickSwap (a labeled DeFi protocol;
  stop_at_contract terminates BFS instantly — but BFS is no longer running
  here because we lost the address).
- Bridge USDC.e via SunSwap on Tron (**Tron bridge entries on bridges.json
  are exactly 3** — SunSwap, JustLend jTRX, USDD PSM; no canonical
  Tron-Ethereum bridge entries despite Wormhole, Allbridge, JustLink
  existing). Even if SunSwap were caught, SunSwap's calldata format is
  not in any decoder.

**Hop 5 — Layer privacy**: On Polygon, the adversary deposits to
RAILGUN's Smart Wallet. RAILGUN IS in `mixers.json` (lines 136-220, multi-
chain entries). The trace would stop there — but we never had the
Polygon address. So this section never renders.

**Hop 6 — Off-ramp**: Withdraw from RAILGUN to a fresh Polygon address P3.
Bridge P3 → Tron via Allbridge (NOT in bridges.json for the Polygon-side
contract — quickly verified by grepping for "allbridge" in bridges.json
returns only the Ethereum entry; Polygon Allbridge contract is absent).
Land on Tron at T1. Deposit T1 → Binance Tron hot wallet, but **NOT** in
a single transfer — split as 12 transfers of varying amounts of USDT-TRC20
($416,667 each, all just above the $100k CEX-continuity floor but
de-coupled in time across 36 hours so the 6h CEX-continuity window
(`cex_continuity.py:56`) doesn't link them, AND each is USDT (in the
noisy-token list `cex_continuity.py:63`, so CEX-continuity skips it
EVEN IF the window matched).

### Why each evasion works (the heuristic-by-heuristic table)

| Hop | Evasion Tactic | Heuristic Bypassed | Recupero's Limitation |
| --- | --- | --- | --- |
| 1 | Approval-then-transferFrom | None — Transfer IS detected | The signer-contract not surfaced; `tracer._trace_one_hop` only walks Transfer logs (`tokentx` action), not call traces. |
| 2 | Safe ownership swap | `stop_at_contract=True` | No `Transfer` event from S1 means no edge; Safe ownership swap leaves an `AddedOwner` event but Recupero doesn't index it. The case ends at S1. |
| 3 | Polygon PoS bridge, no decoder | Bridge calldata extraction | `_decode_bridge_calldata` has 13 decoders; Polygon PoS RootChainManager / Optimism L1Standard / Arbitrum Inbox / zkSync / Base canonical are **all** missing. The L1 bridge is the labelmost simple bridge in the universe but we don't extract its destination. |
| 3-cont | Continuation can't run without dst address | `_continue_past_dex_and_bridges` requires `destination_address` | Trace dies even though we know the destination CHAIN. |
| 4 | Tron BFS bridge-side blindness | `bridges.json` has 3 Tron entries; no canonical bridge inbound | Even if we knew the Polygon address, the Polygon→Tron bridge (Allbridge Polygon-side) is unlabeled. |
| 5 | Privacy pool on Polygon | None — RAILGUN labeled in `mixers.json` | But the address never reached this stage in the case; this is a follow-up problem. |
| 6 | 12 transfers of $416,667 USDT-TRC20 spread 36h | CEX continuity: window=6h AND token in noisy list | The 6h window + noisy-token exclusion BOTH fire to skip these; we never check whether the SUM of inbound transfers in a long window matches a known outbound CEX hot-wallet withdrawal. |

### What the brief actually says

```
SECTION 5 — DESTINATIONS:
  Destination 1: 0xS1 (unlabeled contract) — $5,000,000 USDC
    Status: TRACE TERMINATED AT CONTRACT
    Recommended: Manual investigation of 0xS1 transaction history.

SECTION 7 — CROSS-CHAIN HANDOFFS:
  Handoff 1: Polygon: RootChainManager
    Source tx: 0x... (etherscan link)
    Destination chain: polygon (candidate)
    Destination address: (extraction failed)
    Follow-up URL: polygonscan.com
```

A real operator reading this thinks: "we lost it at the contract.
RootChainManager handoff is also opaque. This is a tough one — operator
files Exhibit B-blank, no addresses to act on."

The operator has no idea the funds eventually landed at Binance Tron.
The freeze letter never goes out. Adversary keeps $5M.

---

## STEP 2 — Route 2: $500K USDT-TRC20 from a Tron victim

**Adversary's Tron-specific advantage**:

* `bridges.json` has 3 Tron rows (SunSwap, JustLend, USDD PSM —
  bridges.json:3855-3905). **NONE** of the actual canonical Tron bridges
  are labeled (JustLink, BTTC bridge, Allbridge Tron-side, Wormhole-on-
  Tron Token Bridge address `TWaP...`). Cross-chain handoff detection
  only fires when a bridge contract is in `bridges.json`.
* `chains/tron/adapter.py` per the trace audit doc (`JACOB_TRACE_AUDIT_v032.md`
  CRIT-2 "Tron native dropped"): TRX-native transfers come back empty.
  Only TRC-20 token transfers are indexed. The adversary uses native TRX
  + USDT-TRC20 in alternating hops.
* `cex_continuity.py:63` noisy-token list excludes USDT, USDC, DAI, ETH,
  WETH — but **NOT** USDD, USDJ, TUSD, or any Tron-native stablecoin.
  CEX continuity would fire on those, IF Recupero had Tron CEX hot-wallet
  labels. `cex_deposits.json` Tron entries (per v0.31.2 expansion) cover
  Binance/OKX/Bybit hot wallets but the audit found these are a starter
  set, not exhaustive. Adversary uses a Coinbase or Kraken Tron hot
  wallet — neither is labeled on Tron (Coinbase doesn't have an on-chain
  presence on Tron; Kraken does but the addresses aren't all in the seed).

### The route

T+0: $500K USDT-TRC20 at victim wallet V_T. Drained to S1_T via standard
`USDT.transfer(S1_T, 500_000_000_000)` (USDT has 6 decimals on Tron).

Hop 1: S1_T → 9 destinations of $55,555 each — **just under min_fanout=10**.
The dust-attack detector (`dust_attack.py:99`) wants `min_fanout >= 10`
AND each transfer < $1 dust threshold. The adversary's $55,555 transfers
are NEITHER condition (not 10, not <$1) so this is NOT a "dust shower"
attack — but it ALSO is not the "single perpetrator with one consolidation
hub" Recupero models. It's a wide fanout below the detector. Each
destination is an independent EOA that the BFS visits as a separate
hop-1 destination, splitting the $500K across 9 brief sections.

Hop 2: Each of the 9 destinations swaps USDT → USDD via the USDD PSM
(this IS labeled, bridges.json:3887). `stop_at_bridge=True` terminates
the BFS at each. **9 dead ends.** The brief renders 9 separate
"trace terminated at USDD PSM" entries.

Hop 3 (invisible): The adversary controls a 10th wallet receiving USDD
from the PSM (the PSM is a swap, not a custodial bridge — funds come out
the other side). But Recupero treats USDD PSM as a bridge / DeFi terminal,
not as a swap, so BFS doesn't continue. The 10th wallet receives USDD,
swaps back to USDT-TRC20, deposits at Bybit Tron hot wallet (which IS
labeled in `cex_deposits.json` but at a confidence the v0.31.2 expansion
left at "medium" — and per the confidence-decay policy at
`labels/confidence_decay.py`, a "medium" label added >180 days ago decays
to "low," which the brief still renders but with a footer caveat that
operators tend to skip).

Hop 4 (still invisible): Within Bybit, the adversary moves funds via
internal transfer (off-chain) to a Bybit account in a non-treaty
jurisdiction, then withdraws to a fresh address with full KYC fraud.

### What the brief actually says

```
SECTION 5 — DESTINATIONS (9 rows):
  Destination 1: T...A (unlabeled EOA) — $55,555.56 USDT
    Bridged via USDD: Peg Stability Module → Tron-internal
    Status: TRACE TERMINATED AT BRIDGE
  Destination 2: T...B (unlabeled EOA) — $55,555.56 USDT
    Bridged via USDD: Peg Stability Module
    Status: TRACE TERMINATED AT BRIDGE
  [...7 more identical rows...]
```

The operator looks at 9 rows of $55K stops at the same USDD PSM and
thinks: "structured laundering — issue subpoenas to USDD operator." The
USDD operator (the JUST Foundation, based in Singapore historically,
moved to a more opaque jurisdiction in 2024) responds slowly if at all.
Adversary keeps $500K.

### Gaps that allow Route 2

* **G-T1**: `dust_attack.py:99` fires only on `min_fanout >= 10`. Adversary
  picks 9. **No mitigation today.**
* **G-T2**: `bridges.json` Tron coverage is 3 rows; missing JustLink,
  BTTC, Wormhole-on-Tron Token Bridge, Allbridge Tron-side, multiple
  PolyNetwork remnants. (v0.31.2 audit closed Tron seeds for Binance/OKX/
  Bybit on the CEX side; the bridge side is still thin.)
* **G-T3**: USDD PSM treated as a labeled bridge but it's a **swap**.
  The trace should continue past a PSM swap to the same address holding
  the swapped stable. Today: stops.
* **G-T4**: Tron-native TRX adapter is `return []` per the trace audit's
  CRIT-2. Adversary uses TRX → USDT swaps mid-laundering and the TRX
  hops are completely invisible.
* **G-T5**: `cex_continuity.py:63` noisy-token list is EVM-centric (USDT,
  USDC, DAI, ETH, WETH). Tron-specific noisy tokens (USDD, USDJ, TUSD,
  TRX itself) are NOT in the list — so the continuity heuristic over-fires
  on Tron when a CEX hot wallet outbounds in those. Conversely, if the
  adversary uses USDT, continuity NEVER fires.

---

## STEP 3 — Route 3: $50M DEX exploit on Arbitrum, speed + scale evasion

**Adversary advantage at scale**:

* `RECUPERO_API_BUDGET_USD_PER_CASE=$0.50`. At Etherscan paid pricing
  (~$0.00001/req on the Enterprise tier, ~$0.0001/req on Pro), $0.50 ≈
  5,000-50,000 requests. The adversary fans out to 50 addresses on Arbitrum,
  each receiving $1M, each with 100+ child txs. Total wallets in the BFS
  tree at depth 4: 50 * (average 20 outflows per wallet)^4 = 8M wallet
  positions. **The budget cap fires long before BFS completes.**
* `max_depth` clamp `[1, 8]` (`tracer.py:166`). At depth 8 with fanout 20:
  20^8 = 25.6B positions. Even depth 4 with fanout 50 is 6.25M. The
  budget cap saves us from OOM but ALSO truncates the trace.
* `trace_deadline_sec=540` (`tracer.py:226`). 50 fan-out addresses each
  requiring multiple Etherscan paged calls, plus CoinGecko price lookups,
  plus contract-detection RPCs — the deadline hits before BFS even
  finishes wave 2.

### The route

T+0: $50M USDT/USDC drained from a major Arbitrum DEX (Camelot, GMX
analog) to a single attacker EOA A.

T+30s: A splits to 50 fresh wallets on Arbitrum, each $1M. Speed matters
— before any monitoring fires.

T+5min: From each of the 50 wallets, in parallel, fire four different
bridges:
* 12 wallets → Stargate v2 to Avalanche
* 12 wallets → Across V3 to Optimism
* 12 wallets → LiFi Diamond to Base (LiFi calldata decode confidence='low'
  for half its facets per `bridge_calldata.py:325-335`)
* 14 wallets → Squid Router (axelar wrapper) to Polygon

T+10min: On each of the 4 destination chains, deposit to a privacy pool:
* Avalanche: Aztec Connect deployment (NOT labeled — Aztec multi-chain
  entries in `mixers.json` are Ethereum-only)
* Optimism: Railgun Smart Wallet (IS labeled on Optimism? Let's check —
  mixers.json's RAILGUN entries name the chain, line 172 says
  "Smart Wallet Implementation (multi-chain)" but the per-chain Optimism
  Railgun contract address is not separately labeled. Confidence dependent
  on whether the deployment address equals the multi-chain one. In
  practice, adversary picks the chain where RAILGUN's specific contract
  is NOT in the seed.)
* Base: Privacy Pools (0xbow) — only Ethereum entry in `mixers.json:292`,
  Base deployment unlabeled
* Polygon: Tornado Cash deployment on Polygon — NOT in `mixers.json`
  (Polygon-side Tornado entries: `grep -n polygon mixers.json` shows only
  RAILGUN, not Tornado)

T+30min: From each privacy pool, withdraw to fresh address. Bridge again
— **second bridge** through Symbiosis MetaRouter to a 5th chain. Symbiosis
decoder confidence is medium (`bridge_calldata.py:289`, `_SYMBIOSIS_METHODS`
returns medium confidence because the destination chain ID lives inside
nested calldata that isn't reliably extracted). The destination on the
5th chain becomes "destination_chain_candidates: [list of guesses]" with
no concrete address.

T+1 hour: On the 5th chain (different per source), funds aggregate into 8
consolidation wallets, each holding ~$6.25M.

T+6 hours (BFS deadline already hit at this point — case marked
`partial_deadline_hit`): Funds reach the actual destination — a mix of
OTC desks, lightly-KYC'd exchanges in non-treaty jurisdictions, and a
nontrivial amount sent back to Lazarus-style hot wallets.

### What the brief actually says

```
TRACE STATUS: partial_deadline_hit
  trace_deadline_sec: 540
  trace_waves_completed: 2
  trace_transfers: 47,891
  trace_addresses_processed: 1,247

SECTION 5 — DESTINATIONS (truncated; deadline hit at wave 2):
  [50 rows of "bridged via Stargate/Across/LiFi/Squid — destination chain
   candidate but address extraction inconclusive"]
```

The operator reads "partial_deadline_hit" and knows the trace is
incomplete. The brief technically discloses incompleteness — but it does
NOT disclose where the funds went or what fraction was lost in the
truncation. The operator's options are:

1. Re-run with `RECUPERO_TRACE_TIMEOUT_SEC=3600` (1h). **The budget cap
   fires first** ($0.50 / call ratio). Adversary wins by budget exhaustion.
2. Increase `RECUPERO_API_BUDGET_USD_PER_CASE` — the operator may not have
   permission. Default is $0.50; adversary's calculation: each additional
   wallet to process = ~$0.001 of budget; 50 fanout × 4 hops × 4 chains
   × privacy pool x 5th chain = ~$2-5 to actually complete. Operator
   would need to bump 10x.
3. Manually drill into the 50 fan-out addresses. Each requires its own
   sub-case. 50 sub-cases × $499/case = $25K of recovery cost before
   you've even started. Government LE units won't pay that.

### Gaps that allow Route 3

* **G-S1**: `RECUPERO_API_BUDGET_USD_PER_CASE=$0.50` is the speed-laundering
  defeat. Adversary spends $5K consultant fee; Recupero must spend $5+ of
  API budget per case to keep up; **business model loses**.
* **G-S2**: `trace_deadline_sec=540` is set against worker reaper window
  (10min). Speed-laundering exploits this hard cap directly.
* **G-S3**: Privacy pool labels chain-incomplete. RAILGUN labeled on
  Ethereum + BSC + Polygon + Arbitrum but Optimism/Base entries are
  partial. Aztec only labeled on Ethereum.
* **G-S4**: Symbiosis decoder returns medium confidence with no concrete
  destination address. Adversary picks Symbiosis specifically.
* **G-S5**: LiFi has 6 facet selectors in `_LIFI_METHODS` (`bridge_calldata.py:325-335`).
  LiFi actually has 40+ facets (per LiFi docs). Adversary picks a facet
  selector not in the dict — falls to "low confidence recognition."
* **G-S6**: No second-bridge alarm. Funds passing through 2+ labeled
  bridges in a single case should be a HIGH-confidence laundering
  signal, but Recupero doesn't surface "multi-bridge hop count" as a
  forensic flag.
* **G-S7**: 50-way fan-out from a single source is a clear laundering
  pattern but doesn't trigger anything — the dust-attack detector wants
  `<$1` per transfer; service-wallet detector wants `>200` outflows; this
  is between both thresholds. **No detector covers the middle ground.**

---

## STEP 4 — Per-route trace simulation summary

### Route 1 ($5M USDC Ethereum)

| Stage | BFS sees? | Heuristic catches? | Result |
| --- | --- | --- | --- |
| Approval+transferFrom | Yes (Transfer event) | n/a (no detector for this pattern) | Detected, signer not surfaced |
| Safe ownership change | No (no Transfer) | n/a | Trace ends at S1 |
| Polygon PoS bridge | Bridge labeled, no decoder | Cross-chain handoff lists candidate | No destination address |
| Polygon-side actions | No (continuation dead) | n/a | Invisible |
| Off-ramp 12-tranche USDT | n/a (not seen) | CEX continuity skips USDT in noisy list | Invisible |

**Prosecutor reading the brief**: "Hit a contract, hit Polygon PoS,
trail ends. Subpoena Polygon? File a generic suspicious-activity report.
We don't know where to send the freeze letter."

### Route 2 ($500K USDT-TRC20)

| Stage | BFS sees? | Heuristic catches? | Result |
| --- | --- | --- | --- |
| 9-way fanout @ $55K each | Yes (each Transfer) | Dust-attack: 9<10 fanout | Misses the fan-out signal |
| USDD PSM swap | Bridge labeled | Stop_at_bridge=True | 9 dead ends |
| USDD → USDT swap downstream | No (continuation dead) | n/a | Invisible |
| Bybit deposit (final) | Would be seen if traced | CEX continuity might fire IF window matched | Window doesn't match |

**Prosecutor reading the brief**: "9 wallets each $55K, all hit USDD
PSM. Subpoena USDD operator (in non-cooperative jurisdiction). Maybe."

### Route 3 ($50M Arbitrum exploit)

| Stage | BFS sees? | Heuristic catches? | Result |
| --- | --- | --- | --- |
| 50-way fanout | Yes initially | Service-wallet (200), not 50 | Misses |
| 4 bridges in parallel | Yes (50 bridge txs) | Bridges labeled but mixed confidence | Half catches, half drops |
| Privacy pool entry | Partial (Ethereum-labeled pools only) | Some labeled, some not | Some hops lost |
| Second bridge (Symbiosis) | Yes | Symbiosis decoder=medium, no dest | Loses 100% of destinations |
| Deadline hit | n/a | partial_deadline_hit marker shown | Operator sees "incomplete" |

**Prosecutor reading the brief**: "Trace cut off at deadline. 50 fanout
wallets, 4 bridges, partial only. We need Reactor / TRM to complete." — and
that's where the money was needed for in the first place.

---

## STEP 5 — Auto-ingest poisoning attacks (v0.32.0 attack surface)

The auto-ingest pipeline (`src/recupero/labels/auto_ingest.py`) pulls from:

* DeFiLlama (`/protocols` endpoint) — community-edited
* Tronscan contracts API — public-tag scraped
* Solscan account labels — public-tag scraped
* Etherscan tags (planned) — public-tag scraped (still semi-stub per the
  module docstring)

**Defenses today**:

1. All candidates land as `proposed_confidence='low'` with
   `status='pending_review'`. The seed JSON files are NOT touched until
   an operator hits `POST /v1/labels/candidates/{id}/promote`. Good.
2. The operator-promote endpoint is gated by `RECUPERO_ADMIN_KEY` and
   accepts a candidate ID + reviewer email + `confidence` body
   (`labels/api.py:165-213`).
3. `daily_cap=100` (env-tunable up to 10000). A single source can't
   inject millions of candidates per day. Good.
4. `proposed_category` schema-enforced to bridge / exchange_hot_wallet /
   exchange_deposit (`auto_ingest.py:125-131`). No 'victim' or 'burn'
   injection.
5. The cron driver `run_daily_pull()` (`auto_ingest.py:676`) catches all
   source failures (`_safe_http_get_json` returns None on any error
   and the loop continues). Sources can be down without harming us.

### Attack vectors

**Poisoning Attack 1 — DeFiLlama submission**: Submit a new
"protocol" to DeFiLlama with `category="Bridge"` and `address=<arbitrary
EOA we want to falsely-label>`. DeFiLlama's submission review is loose
(community PRs against their TheGraph subgraph; review process documented
but informal). Within a week, our `defillama_new_protocol` source picks
it up. An operator on the review queue sees "Bridge candidate:
0xABC...123 (named 'SuperBridge'), source: defillama_new_protocol,
confidence='low'". If the operator promotes (default confidence='medium'
in the request body — `labels/api.py:93`), now 0xABC is labeled as a
bridge in `bridges.json`.

**Consequence**: A real future case where the perp DOES route funds
through 0xABC will see "Bridged via SuperBridge — trace terminated at
bridge." The trace dies at an EOA the adversary owns. **The adversary
controls a self-labeled "bridge" that swallows the trace.**

Mitigation strength today: operator review is the only defense. Operators
are humans + tired + the seed file has 800+ entries. A 0.5% review error
rate = poisoning succeeds.

**Poisoning Attack 2 — Etherscan public-tag injection**: Etherscan's
public-tag submission has historically had limited gatekeeping. The
auto-ingest docstring says the module reads "the simpler interim: read
Etherscan V2's contract-source endpoint for known protocol routers and
parse the `ContractName` field." That's a contract-source field, not
the public-tag, so this specific attack vector against Etherscan IS
partially mitigated by ContractName being set in the original deploy
(not editable post-deploy). **However**, the module docstring also lists
`https://api.etherscan.io/api?module=label&action=getlabels` as a planned
source. Once that lands, this attack opens up fully.

**Poisoning Attack 3 — Tronscan**: Tronscan tag1/tag2/tag3 fields are
operator-editable via the Tronscan UI (require account + manual approval
historically, but not constant-monitor). Submit "Binance Hot Wallet"
as a Tronscan tag for an EOA controlled by the adversary. Within a week,
`fetch_candidate_cex_deposits()` picks it up. An operator reviewing
sees `proposed_name="Binance Hot Wallet"`, `source="tronscan_tag"`,
`confidence="low"`. Operator promotes (because it sounds legitimate).
Now the address is in `cex_deposits.json` as an exchange hot wallet.

**Consequence**: Recupero now sees this address as a CEX. When a victim
gets drained and (by coincidence — adversary doesn't even need to set
this up) the funds touch this address, the trace stops there and the
brief generates an Exhibit C: subpoena Binance for these funds. **The
subpoena goes to Binance.** Binance responds: "we have no record of this
deposit." The case dies because the wrong entity was contacted; the
funds were never at Binance. Adversary did this to a victim, not for
profit — to demonstrate the system is poisonable.

**Poisoning Attack 4 — Solscan**: Same as Tronscan. Solscan's label
system has had similar editability issues. Adversary submits "FTX Cold
Wallet" tag on a Solana account they control. Auto-ingest picks up.
Same downstream consequences.

**Poisoning Attack 5 — Promote-endpoint replay**: The
`POST /v1/labels/candidates/{id}/promote` endpoint requires the
admin key. If the admin key leaks (logs, GitHub Actions environment
variable visible to a malicious dependency, etc.), the adversary can
batch-promote candidates without operator review. **There is no rate
limit on the promote endpoint** and no second-reviewer check.

### Severity ranking of poisoning attacks

| ID | Source | Effort | Required visibility | Impact |
| --- | --- | --- | --- | --- |
| P1 | DeFiLlama new-protocol | LOW (submit PR to DefiLlama) | 7-14 days | **CRIT** — adversary self-labels arbitrary EOA as a bridge that consumes traces |
| P2 | Etherscan public-tag (when shipped) | MEDIUM (submit tag, wait approval) | 7-30 days | **HIGH** — currently partially mitigated by contract-source-only reading |
| P3 | Tronscan tag1/2/3 | LOW (Tronscan UI) | 7-14 days | **CRIT** — adversary causes freeze letters to go to wrong entity (Binance/OKX) |
| P4 | Solscan account labels | LOW | 7-14 days | **CRIT** — same as P3 on Solana |
| P5 | Promote-endpoint replay (admin key leak) | DEPENDS (key exfil) | Immediate on key exfil | **CRIT** — bypasses operator review entirely |

---

## STEP 6 — Mitigation design

Mitigations grouped by attack class.

### M-1: Multi-source confirmation before promotion (defeats P1-P4)

**Today**: Operator review is single-source — they see "DeFiLlama said
this is a bridge" and decide.

**Proposed**: A candidate cannot be promoted unless at least **two
independent sources** confirm it. Define independence: (a) different
upstream API root domain, (b) different submitter / IP on the upstream
where available. When a new candidate lands, the persister checks if any
other pending candidate exists for the same (chain, address); promotion
is GATED until that's true. Adversary now needs to poison TWO upstream
sources within the same review window — much higher cost.

**Implementation sketch**:
- `auto_ingest.persist_candidates` already de-dupes on `(chain, address)`.
  Change the schema: track a `confirmations` JSON array of `{source,
  source_url, observed_at}`. On a duplicate insert (currently silently
  skipped), instead APPEND to confirmations.
- `promote_candidate` checks `len(confirmations) >= 2` before allowing
  the promotion. Operator sees both source URLs.
- File: `src/recupero/labels/auto_ingest.py:384-459` (persist_candidates)
  and `:504-593` (promote_candidate).

### M-2: Cryptographic provenance (defeats P5 admin-key leak + raises bar on P1-P4)

**Today**: One admin key. Anyone with it can promote anything.

**Proposed**: Two-key signing. Each promotion requires a primary-signer
key + a secondary-reviewer key, distinct accounts. The promote endpoint
checks for two signatures on the request body (HMAC-SHA256 from two
distinct keys held by different humans). Persist both signer identities
in the audit log.

**Implementation sketch**:
- New schema column: `secondary_reviewer_email`,
  `primary_signature`, `secondary_signature`.
- `PromoteRequest` adds `primary_signature` field; a separate confirm
  endpoint `POST /v1/labels/candidates/{id}/confirm` takes
  `secondary_signature` and finalizes the promotion.
- File: `src/recupero/labels/api.py:165-213`.

### M-3: Reverse the trace — outbound visibility from labeled addresses
(defeats Routes 1, 2 in part)

**Today**: A trace ENDS at a labeled bridge / CEX. The trace doesn't
explicitly check that the inbound funds eventually come back out of
the same address — which is the most basic forensic question
("did Binance custody these funds or did they pass through?").

**Proposed**: For every transfer with `to_address` ∈ labeled_set, fetch
the address's outbound transfers in a TUNABLE window. Match by amount
(±5%, ±10%, ±15% for confidence tiers) and surface them as
"PROBABLE_RE_EMERGENCE" leads, not as conclusions. This already exists
for CEX continuity (`cex_continuity.py`); extend it to BRIDGES as well,
and ADD it for mixers (which are currently a hard stop).

**Implementation sketch**:
- File: `src/recupero/trace/cex_continuity.py` — refactor to
  `re_emergence.py`, add `re_emergence_bridges` + `re_emergence_mixers`.
- Brief renders these as SECTION 8 "RE-EMERGENCE LEADS" with explicit
  "LEAD ONLY — not proven re-emergence" caveat.
- Tunable per-category: bridge re-emergence window 24h (longer than CEX
  6h because bridges have asynchronous settlement), mixer window 30 days
  with confidence='very_low' (you can re-emerge from Tornado at any
  time).

### M-4: Detect mid-fanout patterns (defeats Routes 2, 3)

**Today**: Dust-attack detector fires only on fanout≥10 AND <$1. Service-
wallet detector fires only on outflows>200. The 9-fanout-at-$55K and
the 50-fanout-at-$1M cases fall through.

**Proposed**: A "structured fanout" detector. For each source, compute:
- `n_distinct_dests` — count of unique destinations
- `value_concentration_gini` — Gini coefficient of the value distribution
  across destinations
- `time_concentration_pct` — what % of the outflow happened in the first
  10 minutes

A source qualifies as STRUCTURED_FANOUT if:
- `n_distinct_dests >= 5` (configurable; below current min_fanout)
- `value_concentration_gini < 0.3` (i.e. values fairly even — laundering
  signature) — Gini > 0.7 = one big + many small, which is the legit
  consolidation pattern Recupero already handles
- `time_concentration_pct > 80%` (most outflows in first 10min — speed
  laundering signature)

**Implementation sketch**:
- New module: `src/recupero/trace/structured_fanout.py`.
- Brief renders as SECTION 9 "STRUCTURED FANOUT DETECTIONS" with the
  source address, fanout shape, and a confidence score.
- The fanout's destinations themselves get a `_fanout_member` flag in
  `case.unlabeled_counterparties` so the brief can render them grouped.

### M-5: Per-case random threshold ranges (raises bar on every route)

**Today**: Adversary reads `min_fanout=10` from source and picks 9.

**Proposed**: Per-case, deterministically derive randomized thresholds
from a stable seed (e.g., HMAC-SHA256 of case_id + a server-side secret).
Adversary doesn't know the per-case threshold even with source access.

```python
def per_case_threshold(case_id: str, secret: str, name: str,
                       low: int, high: int) -> int:
    h = hmac.new(secret.encode(), f"{case_id}:{name}".encode(),
                 hashlib.sha256).digest()
    return low + int.from_bytes(h[:4], "big") % (high - low + 1)
```

So `min_fanout = per_case_threshold(case_id, secret, "fanout", 8, 15)`.
Persist the resolved value in `case.config_used["resolved_thresholds"]`
so reviewers can audit. Adversary can no longer game any single
threshold; they have to design against the worst case.

**Implementation sketch**:
- New module: `src/recupero/_common.py` extended with `per_case_threshold`.
- All threshold-using sites read from a `ThresholdResolver(case_id,
  secret)` object instead of module-level constants. Migrate:
  - `dust_attack.py:99` (min_fanout)
  - `clustering.py:121,130` (MIN_CLUSTERING_USD, SHARED_INFRA_THRESHOLD)
  - `cex_continuity.py:57-69` (MIN_USD, WINDOW_HOURS, NOISY_TOKENS — at
    least the WINDOW_HOURS)
- Operator/reviewer sees the resolved thresholds in the brief footer.
- Caveat: changes deterministic-output property; mitigated by including
  resolved_thresholds in the case JSON.

### M-6: Decode the rollup-canonical bridges (defeats Route 1)

**Today**: Polygon PoS RootChainManager / Optimism L1StandardBridge /
Arbitrum Inbox / zkSync requestL2Transaction / Base canonical bridge —
ALL labeled in `bridges.json` but NONE have decoders. The bridge is
detected as a terminal but no destination address is extracted.

**Proposed**: Add decoders for the 5 rollup-canonical bridges.

**Implementation sketch**:
- File: `src/recupero/trace/bridge_calldata.py`.
- Polygon PoS: `RootChainManager.depositFor(user, rootToken, depositData)`.
  user is the destination address; rootToken is the token; depositData
  is `abi.encode(amount)`. Method selector: `0xe3dec8fb`.
- Optimism L1StandardBridge: `depositERC20To(l1Token, l2Token, to, amount,
  minGasLimit, extraData)`. `to` is the destination. Selector: `0x838b2520`.
- Arbitrum Inbox: `depositEth()` + Bridge.executeCall pattern, plus
  L1ERC20Gateway.outboundTransfer.
- zkSync Era: `requestL2Transaction(contractL2, l2Value, calldata,
  l2GasLimit, l2GasPerPubdataByteLimit, factoryDeps, refundRecipient)`.
- Base canonical: identical to Optimism (it's an Optimism Bedrock fork).

The rollup-canonical bridges are by far the SIMPLEST decode in the
universe — the destination address is a plain argument. Skipping these
in favor of the more exotic Connext/Axelar/Symbiosis decodes is a
prioritization mistake.

### M-7: Tron bridge / DeFi coverage expansion (defeats Route 2)

- Add JustLink, BTTC bridge, Allbridge Tron-side, Wormhole Token Bridge
  on Tron (canonical address `TWaPgHKf...`), PolyNetwork legacy.
- Tag USDD PSM with `category="swap"` not `bridge`, and make the trace
  continue past category="swap" labels (treat as a swap, follow the
  output address).
- Fix the Tron-native TRX adapter `return []` per the trace audit's
  CRIT-2.

### M-8: Hard rate limit on promote endpoint + second-reviewer
(defeats P5)

- `POST /v1/labels/candidates/{id}/promote` — max 10/hour per admin key,
  enforced server-side via a token-bucket counter.
- Second-reviewer requirement (overlaps with M-2 but is a less-intrusive
  weak version): even with one admin key, the promote endpoint logs the
  request and requires a second `POST /v1/labels/candidates/{id}/confirm`
  before the seed file is touched. Operator who promoted CAN confirm,
  but the confirm is a separate API call to a logged endpoint — leaves
  an audit trail that a key-exfiltrated adversary still triggers.

### M-9: Multi-bridge case alarm (defeats Route 3)

A case in which funds pass through ≥2 distinct labeled bridges should
fire a SUSPICION_LEVEL=HIGH flag in the brief. Currently each bridge
hop renders independently; there's no top-level "this case has 4
bridges, which is laundering signature."

### M-10: Service-wallet threshold randomized AND lowered for speed
patterns

Current 200 outflows is high. Add a secondary detector: any source
that emits >5 outflows within 60 seconds is treated as service-like
REGARDLESS of total outflow count. Mitigates Route 3's speed laundering.

---

## STEP 7 — Audit summary table (gaps ranked by attacker utility)

### Top gaps by adversary value

| Rank | Gap | File | Severity | Lets which routes? |
| --- | --- | --- | --- | --- |
| 1 | Rollup-canonical bridge decoders missing (Polygon PoS, Optimism, Arbitrum, zkSync, Base) | `trace/bridge_calldata.py` | **CRIT** | R1 |
| 2 | Safe / smart-wallet ownership change leaves no Transfer event; stop_at_contract terminates | `trace/policies.py`, no detector for non-Transfer events | **CRIT** | R1 |
| 3 | Per-case API budget $0.50 + 540s deadline = adversary wins by scale | `tracer.py:226`, `RECUPERO_API_BUDGET_USD_PER_CASE` env | **CRIT** | R3 |
| 4 | Dust-attack fanout=10 threshold known to adversary (picks 9) | `trace/dust_attack.py:99` | **HIGH** | R2 |
| 5 | Tron bridge coverage = 3 entries; canonical bridges missing | `labels/seeds/bridges.json` | **HIGH** | R2 |
| 6 | CEX-continuity noisy-token list excludes USDT (the actual money-laundering token) | `trace/cex_continuity.py:63` | **HIGH** | R1 (off-ramp), R2 |
| 7 | Tron-native TRX adapter returns empty | `chains/tron/adapter.py` (per trace audit CRIT-2) | **HIGH** | R2 |
| 8 | LiFi has 40+ facets; decoder has 6 | `bridge_calldata.py:325-335` | **HIGH** | R3 |
| 9 | Symbiosis MetaRouter destination chain extraction is heuristic + medium-confidence by design | `bridge_calldata.py:289` | **HIGH** | R3 |
| 10 | No multi-bridge case-level alarm | `reports/brief.py` | **HIGH** | R3 |
| 11 | USDD PSM and other Tron stablecoin swaps treated as terminal bridges | `bridges.json` schema | **MED** | R2 |
| 12 | Privacy pool labels chain-incomplete (Aztec on Avalanche, RAILGUN per-chain Optimism, Privacy Pools on Base, Tornado Polygon-side) | `labels/seeds/mixers.json` | **MED** | R3 |
| 13 | Confidence-decay decays to 'low' silently while keeping label live | `labels/confidence_decay.py` | **MED** | R2 |
| 14 | Cross-chain BFS continuation requires extracted address, fails silently when decoder confidence=low | `tracer.py:478-493`, `bridge_calldata.py` | **MED** | R1, R3 |
| 15 | `service_wallet_outflow_threshold=200` is high vs. observed laundering (50 fanout) | `config.py:68` | **MED** | R3 |

### Top auto-ingest poisoning vectors

| Rank | Vector | Effort | Required time | Impact | Mitigation |
| --- | --- | --- | --- | --- | --- |
| 1 | Tronscan tag1/tag2/tag3 submission ("Binance Hot Wallet" on attacker EOA) | LOW (UI submit) | 7-14 days | CRIT — wrong-entity freeze letter | M-1 (two-source) |
| 2 | DeFiLlama protocol submission (fake "bridge" with attacker EOA) | LOW (DefiLlama PR) | 7-14 days | CRIT — trace consumed by fake bridge | M-1 |
| 3 | Solscan account label submission | LOW | 7-14 days | CRIT — Solana variant of #1 | M-1 |
| 4 | Promote-endpoint replay (admin key exfil) | DEPENDS | Immediate | CRIT — bypasses review | M-2, M-8 |
| 5 | Etherscan public-tag (planned source, not yet shipped) | MEDIUM | 7-30 days | HIGH | M-1 |

---

## STEP 8 — Honest assessment

> **If Recupero shipped tomorrow and a Lazarus-tier APT used the published
> source code to design their evasion, would the perpetrator get away?**

**Partially / fully escape, depending on case size and chain.**

* For a $5M+ Ethereum case routed via a rollup-canonical bridge they
  understand we can't decode: **clean escape**. Route 1 is the proof.
  The brief generates a "trace terminated at contract / bridge handoff
  to candidate chain" output that gives the operator no actionable
  destination. The funds reach the adversary's off-ramp invisibly.
  Recupero generates a paper trail that justifies the case being declined
  for further investigation.

* For a Tron USDT case structured as a 9-fanout below our 10-threshold:
  **clean escape**. Route 2 is the proof. The brief renders 9 stops at
  USDD PSM, the operator subpoenas an offshore stablecoin operator,
  the case dies of slow-jurisdiction friction.

* For a $50M speed-laundering Arbitrum exploit: **mostly escape**, with
  the operator KNOWING they failed (partial_deadline_hit / partial_budget_hit
  markers). The case is honestly disclosed as incomplete, which is morally
  better than Routes 1-2's silent failure, but operationally the same
  outcome — funds are gone.

* For the auto-ingest poisoning: **shippable as long as operators
  are vigilant**, but a single mistake by an operator promoting a
  Tronscan-tagged Binance Hot Wallet that's actually an attacker EOA
  causes a real freeze letter to go to the wrong entity. **No tech
  defense for operator fatigue today.** Auto-ingest is a known
  attack surface that we shipped without multi-source confirmation.

### The marketing claim we cannot make

We CANNOT claim to be Reactor / TRM-equivalent against a sophisticated
adversary who has read the source. We CAN claim:
- 95% effective against unsophisticated thieves (drainer kits, single-bridge
  off-ramps, single-CEX deposits)
- Disclosed-partial against scale / speed laundering (the markers fire)
- Operator-mediated against label-poisoning (relies on careful review)

### What to ship before claiming production-LE-grade

* M-1 (multi-source confirmation): 1-2 weeks of work, full schema migration
  required.
* M-6 (5 rollup-canonical bridge decoders): 1-2 weeks. THIS IS THE SINGLE
  HIGHEST-LEVERAGE FIX. Rollup-canonical bridges are the simplest decode
  in the codebase; their absence is the load-bearing single gap of
  Route 1.
* M-3 (re-emergence visibility): 2-3 weeks; refactor `cex_continuity.py`
  to a general re-emergence module.
* M-5 (per-case random thresholds): 1 week to implement; ongoing risk
  with the determinism-of-output property — needs explicit operator
  documentation.

After those four, the routes become 1-of-3 escape (Route 3 still
escapes via scale; the speed / budget limits are architectural).

---

## Appendix A — Specific implementation pointers

| Mitigation | Files to touch | LOC estimate |
| --- | --- | --- |
| M-1 multi-source confirmation | `labels/auto_ingest.py`, schema migration | ~150 LOC + migration |
| M-2 two-key signing | `labels/api.py`, schema | ~80 LOC + migration |
| M-3 re-emergence visibility | new `trace/re_emergence.py`, `reports/brief.py` | ~400 LOC |
| M-4 structured fanout detector | new `trace/structured_fanout.py` | ~200 LOC |
| M-5 per-case random thresholds | `_common.py`, all threshold sites | ~250 LOC distributed |
| M-6 rollup-canonical bridge decoders | `trace/bridge_calldata.py` | ~400 LOC (80 LOC × 5 decoders) |
| M-7 Tron expansion | `labels/seeds/bridges.json`, `chains/tron/adapter.py` | ~100 LOC + label seed updates |
| M-8 rate limit + second-reviewer | `labels/api.py` | ~100 LOC |
| M-9 multi-bridge alarm | `reports/brief.py` | ~50 LOC |
| M-10 speed service-wallet detector | `trace/tracer.py` or new module | ~80 LOC |

Total: ~1800 LOC of net new code. ~4 engineer-weeks at high quality.

## Appendix B — Tests that would catch these gaps in regression

Each mitigation should be matched by a regression test that simulates the
adversarial route.

- `tests/test_v032_adversary_route1.py` — simulate the full Route 1 with
  mock chain adapters; assert that after M-6, the Polygon-side address
  appears in the case + a continuation pass reaches the Tron off-ramp.
- `tests/test_v032_adversary_route2.py` — simulate Route 2; assert that
  after M-4, the 9-fanout fires STRUCTURED_FANOUT; after M-7, USDD PSM
  is treated as swap and trace continues.
- `tests/test_v032_adversary_route3.py` — simulate Route 3; assert that
  the multi-bridge alarm fires; the structured fanout detector flags
  the 50-way fanout; the brief surfaces "MULTI_BRIDGE_LAUNDERING".
- `tests/test_v032_auto_ingest_poisoning.py` — submit a single-source
  candidate, attempt to promote, assert that promotion is REJECTED with
  "requires N>=2 confirmations" after M-1.

---

*— end of adversary audit*
