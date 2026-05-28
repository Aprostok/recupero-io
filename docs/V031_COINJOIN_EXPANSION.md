# V0.31 CoinJoin Protocol Expansion

**Date:** 2026-05-26 · **Branch:** `pdf-deliverables` · **Module:** `src/recupero/trace/coinjoin_unwrap.py`

The v0.14.0 unwrap module only knew two coinjoin shapes: Wasabi 1.0 (fixed-denomination equal-output rounds) and JoinMarket (variable-participant equal-output rounds). v0.31.0 extends the detector to recognize **Wasabi 2.0 (WabiSabi)** and **Samourai Whirlpool** — and explicitly documents why **Mercury Layer** cannot be detected from on-chain data alone.

---

## What ships in v0.31.0

| Protocol | Status | Detection signal | Confidence |
|---|---|---|---|
| Wasabi 1.0 | Shipped (was shipped pre-v0.31, regression-covered) | 10+ inputs, 10+ outputs at the same value | 0.90 |
| Wasabi 2.0 / WabiSabi | **Shipped (new)** | 10+ inputs, 10+ outputs, no single output amount carries >20% of total value, no fixed-denom cluster | 0.75 |
| Samourai Whirlpool | **Shipped (new strict detector)** | Exactly 5 inputs and 5 outputs, all outputs equal, value matches one of the four published pool denominations (0.001 / 0.01 / 0.05 / 0.5 BTC) | 0.95 |
| Mercury Layer (statechain) | **DEFERRED** | Not detectable on-chain — see below | — |

The new entry point is `detect_coinjoin(*, tx_hash, input_address, inputs, outputs) -> CoinjoinDetection | None`. The legacy `unwrap_coinjoin()` participant-hypothesis enumerator is unchanged and continues to fire for Wasabi 1.0 / Whirlpool / JoinMarket shapes via the round-amount path.

## Why `most_likely_output` is always `None`

Every shipped detector returns `most_likely_output=None` with a forensic note in the brief that explains why. This is **deliberate** — pretending to identify the post-mix output would be worse than admitting the limitation. The forensic floor of what can be claimed honestly from on-chain data:

- **Whirlpool**: the input/output pairing is intentionally indeterminate by design. The anonymity set within a single Tx0/Tx5 round is exactly 5. There is no on-chain signal that distinguishes the "right" output from the other four.
- **Wasabi 2.0**: post-mix recovery requires the coordinator's per-round credential-issuance graph, which Wasabi does not publish and is destroyed after the round. Even subpoenaing the coordinator would only yield the active session — not historical mixes.
- **Wasabi 1.0**: the `unwrap_coinjoin()` participant enumerator can RANK input/output pairings by amount-fit + cardinality + self-mix signals (this is the v0.14.0 capability and matches what TRM Labs publicly documents). The output is "top-N hypotheses for operator review," not "the answer."

The brief surfaces detection at the hop boundary with text like:

> Funds entered Wasabi 2.0 (WabiSabi) at tx `0xabc...` — post-mix recovery requires off-chain solver data and is flagged for operator manual review.

This is the same posture TRM Labs takes in their published methodology for Whirlpool, and it is the right call: false post-mix attribution would mislead the investigator far more than admitting the limitation.

## Why Mercury Layer is deferred

Mercury Layer is a **statechain** protocol, not a coinjoin. The state transitions ("transferring" the UTXO to a new owner) happen **off-chain**, mediated by a statechain entity (SE) server that holds one half of a 2-of-2 key. The on-chain footprint is:

1. **`state_init`**: a single 1-in / 1-out P2TR transaction that funds the statechain UTXO. Indistinguishable from any other taproot funding tx.
2. **Transfer**: ZERO on-chain footprint. The transfer is recorded only in the SE's database and the new owner's wallet. The same UTXO sits unmoved on-chain through arbitrarily many ownership changes.
3. **`state_withdraw`**: a single 1-in / 1-out P2TR transaction that spends the statechain UTXO to the current owner's address. Indistinguishable from any other taproot spend.

**There is no tx-shape signal to match.** The 1-in/1-out P2TR pattern occurs in millions of ordinary transactions per year. Detecting Mercury requires:

- The Mercury Layer SE's database (private to the SE operator, e.g. CommerceBlock).
- OR a curated allow-list of known SE deposit/withdrawal addresses (Mercury does not publish one; clustering would be heuristic-on-heuristic).

Both options are off-chain. v0.31.0 explicitly excludes Mercury from the detector and documents this in the module docstring so future readers don't try to add a shape-based detector that would only false-positive on ordinary P2TR transfers.

If a real customer case lands on a Mercury Layer transfer, the investigative path is:

1. Identify the UTXO as a Mercury statechain UTXO via off-chain intelligence (exchange labels, SE operator subpoena, victim's wallet metadata).
2. Subpoena the SE operator for the transfer history. The SE retains it for KYC purposes.
3. Treat the result as off-chain forensic evidence in the brief, **not** as an on-chain trace.

This is the same posture every commercial chain-analysis vendor takes on Mercury Layer.

## Test coverage

`tests/test_v031_coinjoin_unwrap.py`:

- Wasabi 1.0 fixed-denomination → detected (regression).
- Wasabi 2.0 / WabiSabi (10-in/10-out, non-uniform) → detected.
- Wasabi 2.0 rejected when one output dominates (>20% of total value).
- Wasabi 2.0 rejected below the 10-input floor.
- Whirlpool at the 0.001 BTC pool denomination → detected.
- Whirlpool at the 0.5 BTC pool denomination → detected.
- Whirlpool at a NON-pool 5/5 shape (0.1 BTC) → rejected (the v0.14.0 loose classifier would have called it Whirlpool; the v0.31 strict detector does not).
- Pool denomination membership unit tests.
- 2-in/3-out ordinary transfer → None.
- 1-in/1-out → None.
- Empty inputs / outputs → None, no exceptions.
- `_dominant_output_fraction` math: uniform → 1.0, spread → expected ratio, no NaN.
- `detect_coinjoin` is pure: same inputs → same output.
- Brief serializer shape (`detection_to_brief_section`).

## Backward compatibility

- `unwrap_coinjoin()`, `unwrap_to_brief_section()`, `classify_coinjoin_pattern()`, `detect_round_amounts()`, `UnwrapResult`, `CoinJoinHypothesis`, `UTXOInput`, `UTXOOutput` — **unchanged**.
- All existing tests in `tests/test_coinjoin_unwrap.py` continue to pass.
- The v0.14.0 `classify_coinjoin_pattern()` keeps its loose semantics (5/5 → "whirlpool" regardless of denomination) so the existing hypothesis enumerator pipeline is unaffected.
- The strict pool-denomination check lives only in the new `_is_strict_whirlpool()` / `detect_coinjoin()` path.

## Adding a future protocol

If a new coinjoin shape lands (e.g. an Ark-style covenant mix), follow this template:

1. Add a `PROTOCOL_FOO = "foo"` constant alongside the existing ones.
2. Write a `_is_foo(inputs, outputs) -> bool` predicate. Keep it pure and side-effect-free.
3. Wire it into `detect_coinjoin()` AFTER the more-specific detectors. Order matters — the first match wins.
4. Add a regression test family modeled on the Wasabi 2.0 cases.
5. Update this doc with the detection signal and confidence.
6. If post-mix recovery is infeasible (as it always has been so far), leave `most_likely_output=None` and explain in `forensic_note`. Do not pretend.
