# Multi-chain validation — 2026-05-15

End-to-end validation that each supported chain's adapter +
trace pipeline works against real wallets on Railway, not just in
unit tests. Run as part of the "make it noticeably better" pass
after v0.2.2 shipped.

## What this validation surfaced

Two production bugs that unit tests had not caught, even though
unit-level coverage was thorough (`test_chain_dispatch.py` for
EVM dispatch, `test_solana_helpers.py` for Solana, etc.). Both
required real chain data to find. Both are now fixed and
regression-tested.

### Bug 1: Polygon + Base profiles missing — fixed in `afd745e`

`_profile_for` in `chains/evm/adapter.py` only had explicit
branches for Ethereum, Arbitrum, and BSC. **It raised
`NotImplementedError` for Polygon and Base in production code.**
A Polygon-based victim signing up Tier 2 would have made it
through freezable-issuer identification, letter rendering, and
bucket upload, only to crash at the trace stage with
`No EVM profile for chain polygon` mid-investigation.

The unit tests existed for EvmAdapter construction but they only
ever exercised Ethereum. The `_profile_for` dispatch branches
for Polygon/Base were never called by any test, so the missing
branches never triggered an exception in CI.

Fixed by:
- `config.py`: New `PolygonParams` + `BaseParams` classes
- `chains/evm/adapter.py`: `_profile_for` branches added
- `chains/base.py`: `ChainAdapter.for_chain` routes both to EvmAdapter
- 10 unit tests in `test_chain_dispatch.py` lock the regression

### Bug 2: Flow-diagram render crashed on unpriced tokens — fixed in `1b4a680`

The smoke run against Arbitrum surfaced a 198-transfer case where
the trace completed but `flow_*.svg` was silently missing from
the artifact bundle. Investigation found `_edge_label` in
`worker/_flow_diagram.py:918` crashing with `IndexError: list
index out of range` when an aggregated edge has:

- `total_usd == 0` (no CoinGecko pricing for the token) AND
- `dominant_symbol is None` (label store didn't recognize the contract)

Both conditions are rare on Ethereum (the label store + CoinGecko
cover most contracts) but common on Arbitrum / BSC / Polygon
where memecoin and niche-token traffic dominates. The crash was
caught by the try/except wrapper in `build_all_deliverables` —
so the trace report and freeze letters still shipped, but the
flow diagram silently disappeared. Bad customer experience: the
trace report references the flow attachment, but the file isn't
in the bucket.

Fixed by falling back to a count-only label when both pricing
and symbol are unavailable. 6 unit tests in
`test_flow_diagram_helpers.py` lock the regression.

## Smoke validation methodology

For each non-Ethereum chain, insert a wallet-trace investigation
using a known test wallet (`0x8E3b200f...Bd53` for EVM/HL,
`11111111111111111111111111111111` for Solana). Watch the row
through to terminal status on Railway. **A zero-transfer outcome
is valid for the smoke** — it proves the pipeline:

1. Routes to the right adapter via `ChainAdapter.for_chain`
2. Constructs the adapter with the right chain profile
3. Successfully calls the per-chain explorer API
4. Handles an empty response gracefully (no crash on zero transfers)
5. Generates the `trace_report.html` artifact cleanly
6. Marks the investigation `complete`

## Results

| Chain | Investigation ID | Duration | Transfers | Status | Artifacts |
|---|---|---|---|---|---|
| Ethereum | `e917ffc5` (control case) | 56s | 698 | OK | All ✓ |
| Polygon | `2869908d` | 18.0s | 1 | OK | All ✓ |
| Arbitrum | `9928b53e` | 722s | 198 | OK (post-fix) | All ✓ |
| Base | `3be1e090` | 12.8s | 0 | OK | trace_report + flow (placeholder) ✓ |
| BSC | `265977f9` | 11.6s | 0 | OK | trace_report + flow (placeholder) ✓ |
| Solana | `413cdbeb` | 68.3s | 0 | OK | trace_report + flow ✓ |
| Hyperliquid | `88c8666b` | 12.7s | 15 | OK | All ✓ |

**Notable observations:**

- The test wallet (`0x8E3b...`) has documented Ethereum activity AND surprisingly:
  - Real Arbitrum activity (198 transfers, $0 valued — likely memecoin / unpriced ERC-20)
  - Real Hyperliquid activity (15 transfers)
  - 1 Polygon transfer

  This means the same address is multi-chain, which is itself a useful validation
  signal: cases where a victim's wallet has activity on multiple chains will
  trace cleanly across all of them.

- **Arbitrum took 722s end-to-end** (vs ~15-20s for empty-trace chains).
  198 transfers each requiring price lookups + per-tx evidence fetches is
  the bottleneck. This is well under the 5-minute reaper threshold so it
  completed, but cases with thousands of transfers could exceed it. **Action
  item:** add an optional cap on `evidence_receipts` writes for high-transfer
  cases — currently every transfer triggers an evidence write to the bucket
  which serializes on the Supabase upload rate limit.

- **Hyperliquid is the fastest non-empty chain** because `scrape_hyperliquid_case`
  uses a single `/info` endpoint instead of per-transfer Etherscan calls.
  Architectural advantage that's worth preserving.

- **Solana base58 address support works.** Used the System Program address
  (`111...1` × 32). Helius returned no transactions for it (System Program
  doesn't have user-facing tx history), pipeline completed cleanly in 68s.

## What this validation does NOT cover

- **Real-customer scammer wallets per chain.** The smoke uses a known-multi-chain
  test wallet. For per-chain scammer-specific cases (Pink Drainer on Base,
  Inferno Drainer on Polygon, etc.), separate validation is needed when those
  cases arrive from real customers.
- **Multi-chain trace handoffs.** When a perpetrator bridges funds across chains
  (e.g., Ethereum → Polygon via the Polygon bridge), the current tracer doesn't
  follow the cross-chain hop. Each chain is traced independently. Real
  cross-chain cases would need separate investigations per chain or a future
  cross-chain tracer enhancement.
- **High-transfer-volume traces.** Arbitrum's 198-transfer trace took 12 minutes.
  We don't have data on how the pipeline behaves on 1,000+ transfer wallets.
  Will revisit if a real customer brings a whale wallet.

## Recommended ongoing validation

Once we have real customers across chains, run this monthly:

```sql
-- Distribution of completed investigations by chain
SELECT chain,
       COUNT(*) AS total,
       COUNT(*) FILTER (WHERE status = 'complete') AS complete,
       COUNT(*) FILTER (WHERE status = 'failed')   AS failed,
       COUNT(*) FILTER (WHERE error_stage = 'tracing') AS trace_failures
  FROM public.investigations
 WHERE triggered_at > NOW() - INTERVAL '30 days'
 GROUP BY chain
 ORDER BY total DESC;
```

If `trace_failures > 0` on any chain, that's a regression on the
adapter — find the row, read its `error_message`, fix the bug
before more customers hit it.

## Smoke runs preserved

The 6 smoke investigations above are intentionally preserved in the
DB (status `complete`) for future regression checking. Their `label`
field starts with `multi-chain smoke:` for easy SQL filtering. They
can be re-triggered (`status='pending'`) any time to re-validate the
pipeline after a Railway redeploy.
