# Reply to Jacob — V-CFI01 findings + Phase A/B/C plan

> Response to the v0.7.3 gap-analysis email. Paste-or-link as
> needed.

---

Hey Jacob —

Strong catch and the strategic framing makes the priority
unambiguous. Read the code before responding so the sizing
below is grounded. Three quick code-level corrections that
change the picture in your favor, then a phased plan.

## Three things to correct in the inference

| You said | Actual |
|---|---|
| `max_depth=2` consumed reaching the hub | Default is `max_depth=1` (`config.py:26`). We never walk past the hub. **A one-line config change probably surfaces most of what V-CFI01 should have produced.** |
| `dust_threshold_usd=1.0` | Default is `50.0`. So even at depth=2, the dust filter is the second guillotine for any proportional-split downstream destinations. |
| Attributable-share filtering | There IS no attribution-share computation today. Code records transfers as-is, no proportional re-attribution downstream. The missing destinations result from (a) depth=1 cutoff + (b) dust=$50, NOT from share-splitting. |

One pleasant surprise: **mSyrupUSDp is already in
`labels/seeds/issuers.json` with `freeze_capability: "yes"`**.
The $3.27M miss isn't a mapping gap — it's a trace-enumeration
gap. The moment we walk past depth=1, that destination
surfaces with the right capability tag automatically.

## Phased plan

### Phase A — Framing + immediate fixes (half-day, ship as v0.7.4)

The lift that gets V-CFI01 from "$153 useless trace" to
"perpetrator hub plus four downstream destinations including
$3.27M Maple" without any architectural work:

1. **Bump `max_depth` default from 1 to 2.** This alone walks
   the hub's outflows. Cost impact: ~2x explorer API calls
   per trace, still under $0.50/case at v0.7.3 baselines.
2. **Lower `dust_threshold_usd` default from 50 to 10.** Catches
   the dormant DAI destinations that would otherwise dust-filter.
3. **Flip the brief headline.** "Total perpetrator-controlled
   holdings" → primary; "Attributable inflow" → secondary
   scoping section. Same trace data, very different perception
   by a downstream lawyer.

This is independent of pass-2 architecture. Ship as soon as
the tests pass.

### Phase B — Capability mapping adds (1 day, ship as v0.7.5)

The genuinely missing entries from `issuers.json`:

| Token | Reason | Capability |
|---|---|---|
| FRAX, sFRAX | Frax governance blacklist exists | `"limited"` |
| syrupUSDC, syrupUSDT | Companion to mSyrupUSDp (already in) | `"yes"` |
| PYUSD | Paxos issuer freeze | `"yes"` |
| aUSDC, aUSDT, aDAI (Aave aTokens) | Chain-through to underlying | `"delegates_to"` + underlying |

The Aave `delegates_to` field is new — Aave aTokens themselves
aren't issuer-frozen, but their underlying (USDC, USDT) is
freezable at the issuer level. When a perpetrator holds 1M
aUSDC and Circle freezes the underlying USDC, the aUSDC
position becomes worthless on redeem. So the capability is
inherited. ~20 LOC extension to `freeze/asks.py` to follow
the delegation.

Cleanly independent — can ship even if Phase C is in
progress.

### Phase C — Pass-2 perpetrator-forward trace (3–4 days, ship as v0.8.0)

The architectural change that gets us robust on every
Zigha-shape case, not just the ones where depth=2 happens to
be enough.

**Design sketch:**

1. **New entrypoint** — `run_perpetrator_trace(*, chain,
   hub_address, hub_classification, ...)`. Re-uses
   `run_trace()` underneath. The existing trace function
   already accepts arbitrary `seed_address` (no victim-baked
   assumptions in `tracer.py:52-61`).

2. **Phase-tag transfers** — new column `trace_phase int`
   (1=victim-forward, 2=perpetrator-forward). Existing
   `_compute_total_drained()` keeps reading phase=1 only so
   backwards compat is preserved.

3. **Hub-trigger heuristic** — auto-trigger pass-2 when a
   destination has BOTH:
   - `balance_to_inflow_ratio > 100` (holds-and-redistributes
     pattern, like the 6,479x you saw on V-CFI01), AND
   - `current_balance_usd > 5_000` (avoid burning API budget
     on dust-balance hubs).

   Both numbers operator-tunable per investigation. Manual
   override: `--force-perpetrator-trace <address>` flag for
   cases where the heuristic doesn't fire.

4. **Brief integration** —
   - New `pass2_destinations` array in `freeze_brief.json`
     mirroring `FREEZABLE` shape, sourced from pass-2.
   - `DESTINATION_NOTES` merges pass-1 + pass-2 with a
     `source: "victim_trace" | "perpetrator_trace"` field
     per entry.
   - AI editorial prompt gets a new section
     "PERPETRATOR-CONTROLLED HOLDINGS (pass 2)" alongside
     the attribution section.

5. **Cross-chain handoff** — when pass-2 detects a known-bridge
   address with material outflow to another chain (the Solana
   bridge transaction on V-CFI01), emit a separate
   `cross_chain_handoffs` entry in the brief: not a freezable
   destination, but a flagged investigation item per your
   acceptance criteria.

**API-cost impact:** pass-2 adds roughly 1 additional trace per
investigation that triggers the heuristic. For typical Zigha-
shape cases this is ~$0.20 added to the $0.50 victim trace —
material but not blocking.

## Recommended order

A first (today's work).  
B independently in parallel.  
C as v0.8.0 once A + B are validated against V-CFI01.

The case for shipping A first: bumping max_depth=2 +
lowering dust=$10 may, by itself, surface the four downstream
destinations and the Maple position. If that's true, your
acceptance bar is mostly cleared without pass-2 architecture
work. We then layer C on top to make the same outcome
robust against deeper-walk cases.

The case against deferring C: cases worse than V-CFI01 exist —
a 3-hop perpetrator structure where depth=2 isn't enough.
Without pass-2, we'd keep tuning depth + dust per-case and
chase that tail forever. Pass-2 is the right answer; the
question is whether we ship the immediate-relief patch first
or do the architectural fix once.

My gut: A → B → C, in that order, over ~5 days total. **A is
the half-day lift you're asking for; C is the v0.8.0 build.**

## On the framing change specifically

Worth flagging — even today's brief (with depth=2) would
still lead with attribution numbers unless we flip the
headline logic in `_compute_total_drained()` and the brief
template. The framing fix in Phase A is independent of
whether downstream destinations are present. So shipping A
moves the brief from:

> "$101.21 in 426 attributable transfers, $101.21 reaching the consolidation hub."

to:

> "$655K+ at perpetrator-controlled consolidation hub plus $X
> at four further downstream destinations (attribution scope:
> $101 directly traced from victim wallet)."

Same trace data, very different lawyer-desk impact.

## Acceptance test

After A+B+C all land, re-run V-CFI01:

```bash
recupero-ops retrigger 74f2acf9-db52-471c-ae8b-0d5c1473e53f
```

Brief should clear your acceptance bar:
- Lead with total perpetrator-controlled holdings
- DESTINATION_NOTES contains pass-2 entries for the 4
  downstream addresses
- 0x3e2E66af... flagged as freezable (mSyrupUSDp,
  capability="yes" via Maple admin pause)
- Three DAI dormant addresses flagged as
  "not issuer-freezable, subject to seizure"
- Solana bridge surfaced as cross_chain_handoff

Will send the CFI report PDF over if it'd help me cross-check
the four downstream addresses + the Solana bridge tx hash
against the trace output. Or pull the investigation row
directly — 74f2acf9-db52-471c-ae8b-0d5c1473e53f.

## Sizing summary

| Phase | Effort | Tag | Self-contained? |
|---|---|---|---|
| A — framing + max_depth + dust | half-day | v0.7.4 | Yes |
| B — capability mapping audit + adds | 1 day | v0.7.5 | Yes |
| C — pass-2 perpetrator-forward | 3–4 days | v0.8.0 | Builds on A+B |

Starting on A this session. C goes into design before
implementation — will write up a 1-pager design doc before
the build for the same reason as the stage-checkpointing one
(cross-team coordination items easier when scope is on paper
first).

— Alec
