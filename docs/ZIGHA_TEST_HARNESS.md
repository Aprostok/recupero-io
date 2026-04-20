# Zigha Test Harness

Zigha is our Phase 1 acceptance case. It's an active investigation, ~$20M in stolen funds spanning Hyperliquid, Arbitrum, Ethereum, Solana, BSC, and Bitcoin. The CFI report is our ground truth — when our tool runs against the Ethereum portion, our `case.json` should reconcile with what's documented in CFI's Attachment 08.

## Why Zigha

Three reasons:
1. **It's real.** Building tracing tools against synthetic data is a known failure mode — you encode assumptions that don't survive contact with reality. Zigha exposes the messy stuff: bridges, swaps, weird tokens, multiple chains.
2. **We have ground truth.** CFI did the work manually. We can check our output against theirs.
3. **It's still active.** If our tool surfaces something CFI missed (or vice versa), that's signal — not just for the tool but potentially for the case itself.

## What Phase 1 verifies

We are not trying to reproduce the entire Zigha report in Phase 1. We are verifying the *foundation*:
- Can we identify the first-hop outbound transfers from the Ethereum-side victim address?
- Do those transfers correctly resolve token, amount, USD value, timestamp?
- Do we correctly label MEXC deposits as `exchange_deposit`?
- Are evidence receipts present for every transfer surfaced?
- Does the operator (you) trust the output enough to send a freeze request to a government contact based on it?

If yes to all five, Phase 1 is done.

## Inputs

The Zigha victim Ethereum address (from prior chat context):
```
0x0cdC902f4448b51289398261DB41E8ADC99bE955
```

Incident timestamp: **TO BE CONFIRMED** from the Zigha report — for now use the earliest outbound transfer from this address as a proxy. The verify script reads this from `tests/fixtures/zigha_inputs.json`, which we update once you confirm the actual timestamp.

Known MEXC deposit address from the Zigha report (for label seeding):
```
0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d
```

This address goes into `src/recupero/labels/seeds/cex_deposits.json` with:
```json
{
  "address": "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
  "name": "MEXC Deposit (observed Zigha)",
  "category": "exchange_deposit",
  "exchange": "MEXC",
  "source": "manual:zigha_report_2025",
  "confidence": "high",
  "notes": "Identified by CFI in Zigha case report"
}
```

## Running the harness

```bash
python scripts/verify_zigha.py
```

The script:
1. Loads inputs from `tests/fixtures/zigha_inputs.json`.
2. Runs a full trace into `data/cases/ZIGHA-VERIFY/`.
3. Loads expected anchors from `tests/fixtures/zigha_expected.json` — a list of "we expect to see at least these transfers" (specific tx hashes, destination addresses, approximate USD values).
4. Diffs the actual `case.json` against expected anchors.
5. Prints a pass/fail report.

Anchors are deliberately loose — exact USD values shift slightly with price source — so we assert "within 5% of expected" rather than exact match. The point is sanity, not bit-equality.

## Manual review step

Even when the script passes, do this:
1. Open `data/cases/ZIGHA-VERIFY/transfers.csv` in a spreadsheet.
2. Pick three transfers at random.
3. Click the explorer URL, confirm the on-chain data matches what we wrote.
4. Pick the largest-USD transfer to a labeled exchange. Confirm the label is correct.

If any of those fail, the tool is not done regardless of what `pytest` says.

## Building the expected-anchors fixture

`tests/fixtures/zigha_expected.json` starts empty and gets populated as we work through the Zigha report. Each anchor:

```json
{
  "tx_hash": "0x...",
  "from": "0x0cdC902f4448b51289398261DB41E8ADC99bE955",
  "to": "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
  "token_symbol": "USDT",
  "approx_usd": 1234567.89,
  "approx_usd_tolerance_pct": 5.0,
  "expected_label_category": "exchange_deposit",
  "expected_exchange": "MEXC",
  "source_in_zigha_report": "Section 3.2, Attachment 08 row 14"
}
```

Building this fixture is partly manual investigative work — you and Claude Code together work through the Zigha PDF and pull out the anchor transactions. Aim for ~10 anchors covering: largest dollar moves, exchange endpoints, swaps (DEX), and at least one transfer with an obscure/illiquid token (to test the `pricing_error` path).
