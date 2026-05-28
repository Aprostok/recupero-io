# v0.30.2 forensic-correctness audit

Read-only sweep of the money / math / time corridor from
`pricing/coingecko.py` → `trace/*` → `reports/emit_brief.py` →
`reports/brief.py` → templates. Excludes findings already catalogued in
`V029_AUDIT_FINDINGS.md`, `V030_ROUND_N_AUDIT.md`, and
`BRIEF_READTHROUGH_FINDINGS_v030.md`.

## TIER-1 CRITICAL — math error visible to AUSA / customer

**T1-A. Section 4 cross-token amount sum still ships.**
`src/recupero/reports/brief.py:588-595` (`total_amount_human`) sums
`t.amount_decimal` across every entry in `theft_events` without grouping
by token symbol. `_find_theft_events` (`brief.py:1029-1108`) clusters
purely on a 168-hour `block_time` window around the primary event, so an
ETH drain + a USDT sweep within 7 days both land in the cluster. The
template `le.html.j2:378` then renders `0.210815 + 20,610.336829 =
20,611.547644` with no unit label. This is exactly the F10 finding from
`BRIEF_READTHROUGH_FINDINGS_v030.md` — the read-through caught it for
v0.30.0, but no code change landed. Same bug also fires in
`maple.html.j2:85` and `issuer_freeze_request.html.j2:271`. Attack: any
case where the perpetrator drains a native-asset transfer in addition to
the headline ERC-20. **Fix:** group `theft_events` by `token.symbol` and
render one row per symbol; suppress `total_amount_human` when the cluster
spans >1 distinct symbol.

**T1-B. `NaN` USD propagation through 8 aggregators that lack
`.is_finite()` guards.** `_trace_report.py:209` correctly screens
`t.usd_value_at_tx.is_finite()` before `+=`; every other aggregator
trusts the value:
- `reports/emit_brief.py:247` (`_extract_perp_hub` per-counterparty USD)
- `reports/emit_brief.py:379` (`_extract_destinations` per-counterparty USD)
- `reports/emit_brief.py:907` (`_compute_total_drained`)
- `reports/brief.py:1503-1505` (`_build_identified_wallets` agg["usd_in"])
- `reports/ai_editorial.py:606-607` (drain + first-hop USD)
- `reports/ai_editorial.py:855` (`per_addr_received`)
- `freeze/asks.py:348` (`flow_usd_value` onward-flow bucket)
- `freeze/asks.py:732` (`total_usd` historical-inflow bucket)

A single `Decimal("NaN")` reaching any of these poisons the running sum.
`_extract_perp_hub` is the most damaging — its NaN bucket sorts as the
"largest outflow" (NaN comparisons are False, but `max()` on a list with
a NaN can return either side depending on order), producing a randomly-
chosen perp-hub on the LE cover. v0.20.x added the
`_safe_finite_nonneg_decimal` guard at the CoinGecko entry point, but
the cache file format + hand-edited freeze_asks.json + any future
non-CoinGecko adapter can still inject a NaN downstream — defence in
depth is missing. **Fix:** mirror `_trace_report.py:209`'s pattern at
every callsite. Cheap (`if not d.is_finite(): continue`) and idempotent.

**T1-C. `total_loss_usd` Decimal NaN bypasses LE escalation thresholds.**
`src/recupero/worker/_le_routing.py:402-411` — the `>=
_FBI_VAU_THRESHOLD_USD` and `>= _SECRET_SERVICE_THRESHOLD_USD` checks use
raw Decimal comparisons. `Decimal("NaN") >= Decimal("1000000")` returns
False per IEEE 754 semantics, so a NaN loss silently *skips* both FBI
VAU and Secret Service ECTF escalation paths on a >$1M case. Caller in
`brief.py:1818` (`_build_le_routing_ctx`) passes `estimated_loss_usd`
through with no finite-check. Worse, line 406's f-string
`${total_loss_usd:,.2f}` would render literal "$NaN" into the LE
handoff's Suggested Filing Routes note when the threshold IS crossed
(via Inf, which compares True). **Fix:** add
`if total_loss_usd is None or not total_loss_usd.is_finite(): return
plan` after line 401, with a logged warning. Defence in depth against
T1-B's upstream cousins.

## TIER-2 HIGH — degrades report quality

**T2-A. `cluster_handoff.py:106` bypasses SOURCE_DATE_EPOCH.**
`render_cluster_handoff` uses `datetime.now(UTC).strftime(...)` directly,
unlike `recovery_snapshot.py:82` and `brief.py:478` which route through
`_resolve_render_time()`. Re-rendering the same cluster on a CI pin
produces a different `generated_at` than the per-case briefs in the same
build, breaking byte-reproducibility of the multi-victim handoff bundle.
Same bug at `aggregate.py:241`, `ai_editorial.py:475`,
`cooperation_dashboard.py:202`, `legal_requests.py:233`,
`subpoena_renderer.py:104`, `law_firm_dashboard.py:188`. **Fix:** move
`_resolve_render_time` to `_common.py` and route all 7 renderers through
it.

**T2-B. `cross_chain.py:329-330` renders `$NaN` into LE brief.**
`handoffs_to_brief_section` formats `f"${h.amount_usd:,.2f}"` without
`.is_finite()` guard. A poisoned `usd_value_at_tx` on the bridge
transfer (T1-B feeder) reaches the LE handoff's section-3 "Cross-chain
handoffs" table as literal `$NaN`. Sort at line 302 also doesn't filter
NaN (defaults to `Decimal("0")`, but the unguarded format still leaks
the live value). **Fix:** finite-check before the f-string; render
`(unpriced)` on NaN. The companion narrative builder at line 358 has
the same gap.

**T2-C. `aggregate.py:259` `out_path.write_text` is not atomic.**
Every other report writer uses `_common.atomic_write_text`; the
aggregate JSON ships through bare `Path.write_text`. A worker SIGKILL
mid-write leaves a truncated `aggregate_<timestamp>.json` on disk that
the next CLI invocation reads and treats as authoritative. Same
pattern, same fix as the v0.20.13 R17-C fix to `emit_editorial_template`.

**T2-D. Recovery scorer headline uses raw float chain for "P(freeze)".**
`recovery/scorer.py:1000` `top_effective = top[2] * top[3]` is
`float * float`. The percentage is rendered as `:.0%` so display is
fine, but the same `top` tuple feeds `_build_headline_summary` which
also computes `top_effective` independently for the driver narrative
(`scorer.py:431`) — and both sides go through float, not Decimal. A
two-issuer case with `base_prior=0.73`, `discount=0.75` produces
`0.5475` on one path and `0.547499999...` on the other depending on
intermediate roundings. Both render to "55%" so it's invisible today,
but the moment we expose the underlying float in JSON
(`per_issuer.effective_prior` in `to_json_safe`) the two values diverge
visibly. **Fix:** use the existing `Decimal(str(prior)) *
evidence_discount` path everywhere (the scorer already does it for
`contribution` at line 397 — the headline and driver shouldn't depart).

## TIER-3 MEDIUM — polish + hardening

**T3-A. F11 "7-day window" still hardcoded.** `le.html.j2:269` and
`_find_theft_events`'s 168-hour default are decoupled — the template
prose claims 7 days regardless of actual elapsed time. The
`BRIEF_READTHROUGH_FINDINGS_v030.md` F11 finding flagged this; not
fixed. Trivial: pass `theft_event_span_human` (max - min `block_time`)
through to the template and render the actual span.

**T3-B. `_extract_destinations` dust threshold parsed at call time.**
`emit_brief.py:289-300` re-parses `RECUPERO_DESTINATION_DUST_USD` every
call (intended — see the v0.20.11 comment). Two-issue chain: (1)
negative values raise + fall back to $1000 default — but if the env var
is set to `"NaN"`, `Decimal("NaN")` parses successfully, `val < 0` is
False (NaN comparisons), `return val` ships a NaN threshold, which
then makes `received >= threshold` False for every legitimate
destination → destination list collapses to freeze-target-only entries.
**Fix:** add `if not val.is_finite()` to the guard at line 293.

**T3-C. `_compute_perpetrator_holdings` regex parses asset USD from
free-form text.** `emit_brief.py:973` extracts dollars from the
UNRECOVERABLE_ITEMS' `asset` string via `re.search(r"\$([0-9,]+(?:\.[0-9]+)?)", asset)`.
A hand-edited editorial entry like `"3.2 ETH (~$6,780.50 at time of
theft; currently worth $7,420)"` matches the FIRST `$X` (6,780.50). If
the operator means the second figure, the rollup is wrong. Not a math
bug per se, just a fragile parse contract. **Fix:** add a structured
`usd_value_decimal` field to `UNRECOVERABLE_ITEMS` (the editorial
schema), keep regex as fallback for legacy entries.

**T3-D. `_lookup_issuer_prior` first-word collision.**
`recovery/scorer.py:88-90` falls back to first-word match. A future
issuer named `"Tether Investments LLC (defunct)"` resolves to base
`"Tether"` → 0.73 freeze prior, which would be wrong for a defunct
issuer that has zero freeze capability. Today's issuer name list
doesn't exhibit this, but the heuristic is brittle. **Fix:**
explicit alias map keyed by issuer ID rather than name.

## Surfaces examined with NO findings

- `pricing/coingecko.py::_safe_finite_nonneg_decimal` (l.260-281)
  correctly rejects NaN/Inf/negative at the CoinGecko entry point.
- `pricing/coingecko.py::_PER_TRANSFER_USD_SANITY_CEILING` at $2B is
  reasoned; the canonical stablecoin map covers all 16 chains in
  `_CHAIN_TO_CG_PLATFORM`. The 6 destination-only chains
  (`fantom/celo/gnosis/moonbeam/metis/kava` in `models.py:88-93`) have
  no adapter so pricing absence is by design.
- `trace/tracer.py:947-949` token-amount conversion uses Decimal
  throughout; no float drift.
- `reports/aggregate.py::aggregate_stolen` (l.105-119) screens NaN/Inf
  on both `amount_decimal` AND `usd_value_at_tx` before accumulating.
- `recovery/scorer.py::_parse_usd` (l.746-776) rejects non-finite +
  negative; `_compute_recovery_ci::use_learned` (l.882-896) rejects
  NaN/Inf/out-of-range learned priors.
- `_pricing.fmt_usd` (l.83-110) is the canonical USD formatter; clamps
  NaN/Inf to `$0.00`, handles negative as `-$X` not `$-X`.
- `_le_routing._parse_citizenship_country_state` correctly extracts
  `("USA", "Texas")` from `"USA (Texas)"` for F3 routing.
- Decimal context is never mutated (`getcontext` grep clean except a
  defensive comment in `scorer.py:918`).
- `datetime.now()` / `datetime.utcnow()` grep clean across `src/` —
  every renderer uses `now(UTC)`. The remaining issue (T2-A) is
  SOURCE_DATE_EPOCH coverage, not naive-datetime escape.
