# V0.31.0 — MEV / Sandwich-Attack Obfuscation DETECTION (Gap #9)

**Date:** 2026-05-26 · **Branch:** `pdf-deliverables` · **Status:** Ships

A perpetrator using MEV bundle services (Flashbots Protect / MEV-Boost
/ Eden) or sandwich attacks can launder funds through the MEV
builder's wallet, breaking the on-chain trace continuity. Pre-v0.31.0
a Recupero brief silently reported "funds moved to 0xdAFE…" without
flagging that this address is a known Flashbots builder controlling
block construction — not a controllable wallet to subpoena.

v0.31.0 ships **detection, not unwrap**. The brief now surfaces an
honest forensic flag: *"this hop is MEV-obfuscated, manual
investigator follow-up needed."* That's the MVP value — keep the
brief defensible against the misleading-destination failure mode
without pretending to follow trails we can't follow.

---

## What ships

| Surface | Where |
| --- | --- |
| Detection module | `src/recupero/trace/mev_detection.py` |
| Brief wiring | `src/recupero/reports/emit_brief.py::_build_mev_signals_section` |
| Brief JSON field | `MEV_SIGNALS` (top-level) |
| Tests | `tests/test_v031_mev_detection.py` |
| This doc | `docs/V031_MEV_DETECTION.md` |

API:

```python
from recupero.trace.mev_detection import detect_mev_signals, MEVSignal

signals: list[MEVSignal] = detect_mev_signals(
    case,
    tx_metadata={"0xabc...": {"gas_price": 0, "builder": "0xdAFE..."}},  # optional
)
```

Each `MEVSignal` carries `tx_hash`, `signal_type`, `confidence` (0.0-1.0),
`forensic_note`, and (when applicable) `address` and `builder_name`.

---

## Heuristics

### 1. Flashbots / MEV-Boost bundle — `flashbots_bundle`

**Test:** `tx_metadata[tx]["gas_price"] <= 1 gwei`, OR
`tx_metadata[tx]["builder"]` ∈ known builder set.

**Why it works:** A Flashbots bundle tx pays the validator via a
direct `coinbase.transfer()` rather than via gas fees, so the tx
itself has `gas_price = 0`. The ≤1-gwei buffer absorbs L1
system-tx edge cases that are also non-paying. When the builder
field is populated (e.g. from a future Etherscan API plumb-in),
the direct-match is stronger.

**Confidence:**
* `0.8` when `tx_metadata.builder` matches a known builder address
* `0.7` when `gas_price ≤ 1 gwei` alone

Why not 1.0: some L1 system txs and L2 sequencer ops also have
gas_price=0 without being MEV bundles. The 0.7 confidence is high
enough to render (≥ 0.5 threshold) but explicit about the noise
floor.

### 2. Sandwich attack — `sandwich`

**Test:** in the same `block_number`, three transfers ordered by
`log_index` where positions 0 and 2 share `from_address` AND
position 1's `from_address` equals `case.seed_address`.

**Why it works:** classic sandwich shape — searcher front-runs the
victim's swap, the victim's swap executes at the moved price, the
searcher back-runs. Same-address flanking on either side of the
victim's tx, in one block, is a tight on-chain signature.

**Confidence:** `0.85`. Could be 1.0 if we additionally verified
that all three txs hit the same pool/router — without pool-context
data the rare false positive is "victim's tx happens to be
sandwiched in log-index ordering by an unrelated batch
transaction by the same address." Documented as such; lower
confidence rather than disabling.

### 3. JIT (Just-In-Time) liquidity — `jit_lp`

**Test:** in the same block, three transfers around the victim's
swap where the outer two interact with the **same** counterparty
(pool) but from **different** addresses (LP-add and LP-remove
operations are typically routed through different relayer
contracts).

**Why it works (weakly):** the structural shape of a JIT-LP attack
is "add liquidity right before the victim's swap, remove right
after." Without per-pool LP-event ingestion (out of v0.31.0 scope —
requires decoding Uniswap V3 `Mint`/`Burn` events) we can only
detect the *structural* shape.

**Confidence:** `0.4` — **deliberately below the 0.5 brief-render
threshold.** The signal is enumerated and counted in the
`suppressed_low_confidence_count` summary but does not render its
own section. The operator sees "3 sub-threshold MEV signals also
detected" so the absence isn't silent. Per the spec: lower
confidence rather than disabling. When LP-event decoding ships,
confidence rises to 0.7+.

### 4. MEV-builder-sourced funds — `mev_source`

**Test:** `case.seed_address` received a transfer where
`from_address` ∈ known builder set.

**Why it works:** when a perpetrator's wallet was funded directly
by a builder's MEV-profit distribution, the entry point of the
case is *itself* MEV-source funds. Tells the investigator the
"funds came from somewhere" question has a known starting point
(the builder paying out accumulated profits) but the *original*
searcher attribution requires off-chain (MEV-Boost relay
operator) data.

**Confidence:** `0.9` — builder addresses are deterministic
(Etherscan-labeled, externally verified). The only failure mode
is "builder address rotated and the constant is stale" — covered
by the periodic constant-refresh discipline (next section).

---

## Hardcoded builder addresses (verified)

All four addresses verified against Etherscan May 2026:

| Address | Label | Verification |
| --- | --- | --- |
| `0xdAFEA492D9c6733ae3d56b7Ed1ADB60692c98Bc5` | Flashbots: Builder | Etherscan name tag; 530K+ txs; cited in [flashbots/builder README](https://github.com/flashbots/builder) |
| `0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5` | beaverbuild | Etherscan name tag; live block production per relayscan.io |
| `0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97` | Titan Builder (titanbuilder.eth) | ENS-verified; docs.titanbuilder.xyz |
| `0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326` | rsync-builder.eth | ENS-verified; rsync-builder.xyz; ~514 blocks / 7d per relayscan.io |

Stored lowercased in `_MEV_BUILDERS`; comparison is case-insensitive
via `_canonical()`. **Refresh cadence:** quarterly check against
[relayscan.io](https://www.relayscan.io/builder-profit?t=7d) and
[awesome-block-builders](https://github.com/blue-searcher/awesome-block-builders);
add new builders as they reach >5% market share. Removing or
renaming a builder constant is a v0.31.x point release.

---

## What TRM / Chainalysis do that we don't

| Capability | TRM | Recupero v0.31.0 |
| --- | --- | --- |
| Detect MEV-shaped txs | Yes | **Yes** |
| Full block-shape reconstruction (every tx, internal trace, state delta) | Yes | No — we only see the case's transfer rows |
| Private mempool subscription (Flashbots Protect, MEV-Share enterprise) | Yes | No |
| Searcher attribution (e.g. `jaredfromsubway.eth`) | Yes — via bundle-submission signature clustering | No — we flag "MEV-shaped" but don't name the searcher |
| Unwrap bundle → individual flows | Partial | **No (intentional)** — we flag the discontinuity, not pretend to unwrap |

Recupero's bet: the *honest flag* is more useful for a $499
diagnostic than a bundle-unwrap heuristic that produces false
attributions. The brief renders "investigator follow-up needed
here" with the specific txhash so manual triage can take over
with an explicit handoff, not a silent dead-end.

---

## Brief render contract

Section name: `MEV_SIGNALS` (top-level field on the brief JSON).

Shape:

```json
{
  "detected": true,
  "signal_count": 2,
  "suppressed_low_confidence_count": 1,
  "signals": [
    {
      "tx_hash": "0xabc…",
      "signal_type": "flashbots_bundle",
      "confidence": 0.7,
      "forensic_note": "Tx gas_price = 0 wei (≤ 1 gwei). Characteristic of MEV bundle txs paid via coinbase.transfer() to the validator rather than gas fees. Investigator follow-up recommended.",
      "address": null,
      "builder_name": null
    }
  ]
}
```

`detected` flips true iff at least one signal clears confidence
0.5. The triage Jinja template renders the "MEV-obfuscated
transfers" panel only when `detected == true`. The
`suppressed_low_confidence_count` is rolled into a one-line
diagnostic ("3 sub-threshold MEV signals also detected — review
the case JSON for full enumeration") so the operator sees the
silent suppression rather than a confusing absence.

---

## Defensive contracts

* `detect_mev_signals(case=None)` → `[]` (no crash)
* `detect_mev_signals(case)` where `case.transfers == []` → `[]`
* NaN / Inf / garbage in `tx_metadata[tx]["gas_price"]` → skip that
  row, don't flag, don't raise
* Missing `block_number` / `log_index` / `tx_hash` on individual
  transfers → skip that transfer in the same-block grouping
* Case-insensitive builder address comparison (checksum vs lower)
* Same `(tx_hash, signal_type)` → dedupe to highest confidence

Tested in `tests/test_v031_mev_detection.py`:

* `test_nan_in_tx_metadata_does_not_crash`
* `test_nan_amount_in_transfer_does_not_crash`
* `test_missing_block_number_does_not_crash`
* `test_mev_source_case_insensitive_builder_address`
* `test_signals_dedupe_keep_highest_confidence`

---

## Out-of-scope (deliberately deferred)

* **Bundle-unwrap** — full block-shape reconstruction. Needs new
  RPC + private mempool data; not a v0.31.x deliverable.
* **Pool-context enrichment for sandwich/JIT signals** — needs
  Uniswap V3/V4 Mint/Burn decode in the chain adapter. When it
  ships, JIT confidence rises from 0.4 to 0.7+ and the sandwich
  signal narrows.
* **Bridge-MEV (cross-chain sandwich) detection** — non-trivial;
  cross-chain timing windows are wider and require multi-chain
  block alignment. Tracked separately.
* **Searcher-wallet attribution** — naming
  `jaredfromsubway.eth`-style actors. Useful but needs a curated
  searcher-cluster DB; not blocking.

---

## References

* Daian et al. (2019) ["Flash Boys 2.0: Frontrunning, Transaction
  Reordering, and Consensus Instability in Decentralized
  Exchanges"](https://arxiv.org/abs/1904.05234)
* Flashbots Docs — [MEV-Boost overview](https://docs.flashbots.net/)
* [awesome-block-builders](https://github.com/blue-searcher/awesome-block-builders)
  — community-maintained builder registry
* [relayscan.io](https://www.relayscan.io/) — live builder market
  share, used to validate the hardcoded constant set
