# Client fund-flow map — roadmap toward TRM / Chainalysis-grade visualization

_Status as of v0.35 · branch `feat/client-journey-graph`_

**Shipped:** Phase 2 (client map: tx drill-down, exposure donuts, mini-map,
export, radial, persistence) · Phase 3 anchor (operator graph web view with
risk + indirect-exposure overlays + investigator notes) · Phase 4 layouts
(Force/Flow/Radial/Value-flow) · **on-demand hop expansion (3.6)** — the
core TRM/Chainalysis "grow the graph" loop. **Remaining:** DB-backed
shareable graphs (3.9), watch (3.10), WebGL (4.11), ribbon-Sankey (4.12),
real-time (4.13), non-stablecoin USD pricing on expansion ·
**annotations + saved/shareable graphs (3.9)** · expansion cache.

**Genuinely remaining:** address watch (3.10), WebGL renderer (4.11),
ribbon-Sankey (4.12), real-time streaming (4.13), non-stablecoin USD on
expanded edges. Each needs the worker scheduler, a streaming channel, a
canvas-renderer rewrite, or the live price oracle — infrastructure best
verified against a running deploy, not added blind.

This document tracks the client-facing interactive graph in the portal
(`/portal/<token>/graph`) and the work remaining to bring it as close as
practical to the investigation-graph experience of **Chainalysis
Reactor** and **TRM**. It is deliberately split into what is **client-safe**
(belongs in the victim portal) vs **operator-grade** (belongs in the
internal investigator tooling), because not everything those products do
should be exposed to a victim.

## Reference: what Reactor / TRM actually do

The flagship investigator products center on an interactive entity graph
with, broadly:

- **Unlimited multi-hop tracing** with **on-demand node expansion** —
  click a node to pull in its next-hop counterparties live, rather than
  viewing a single precomputed graph. ([Chainalysis Reactor](https://www.chainalysis.com/product/reactor/))
- **Automated pathfinding** — start from an address and let the tool find
  the path to an attributed service/entity; find the path between two
  selected nodes. ([Reactor](https://www.chainalysis.com/product/reactor/))
- **Exposure analysis** — direct vs **indirect exposure** rendered as
  "exposure wheels" (received-side vs sent-side breakdown of which
  services funds came from / went to). ([Indirect exposure](https://www.chainalysis.com/blog/cryptocurrency-risk-blockchain-analysis-indirect-exposure/))
- **Date filtering + path expansion + per-node annotations** that feed the
  final evidence report. ([Reactor on AWS / reviews](https://www.chainalysis.com/product/reactor/))
- **Watch / monitoring** of an address for future activity.
- **Real-world entity attribution** with categories and confidence.
- Cross-chain / cross-asset tracing, saved & shareable graphs, exports.

## What we have now (shipped in this build)

The portal map is a **sanitized, client-safe projection** of the same
node/edge model that powers the operator graph (built via the shared
`worker._flow_diagram._aggregate`, so the two never drift). Implemented:

| Capability | Notes |
|---|---|
| Force-directed graph, pan / zoom / drag | Vanilla JS, no third-party libs (portal CSP is `script-src 'none'`; served under a per-response nonce) |
| **Recoverability coloring** | origin / freeze-eligible issuer / exchange / bridged / DeFi / suspect / mixer-unrecoverable / intermediary — derived from existing classifier categories, never fabricated |
| **Entity clustering** (open/close groups) | Same-issuer / same-named-entity addresses collapse into one expandable bubble |
| **Flow layout** (hop-depth columns) ↔ Force layout | BFS hop-depth from the victim drives a left-to-right "where did it go" view |
| **Detail panel** | Click a node/edge → label, status, address, received/sent **exposure split bar**, hops-from-you, connection count, explorer link; cluster member list |
| **Pathfinding** | "Find path" mode → click two points → shortest connecting path highlighted + listed |
| **Filters** | Min-value slider, asset dropdown, clickable legend (show/hide a status) |
| **Time scrubber + playback** | Slider + ▶ Play animates fund flow over the case's date range |
| **Edge transaction drill-down** | Click an edge → top-N transactions (date, USD, token, explorer link) + remainder count |
| **Exposure donuts** | Node panel: received-from / sent-to split by neighbor category (client-safe exposure wheel) |
| **Mini-map**, **Radial layout** (+ Force/Flow) | Viewport rect + click-to-recenter; three layouts |
| **Export** PNG / CSV / Print-PDF | Self-contained, CSP-safe |
| **Persisted view state** | layout / groups / filters per case via `localStorage` |
| Hover tooltips, search, fit / reset | — |
| **"Where your funds are"** breakdown + **Case activity** timeline | Server-rendered (works without JS); timeline reads existing `investigations` run timestamps |
| Truncation to a clean view | Victim + all endpoints always kept; top intermediary wallets by value fill the rest; remainder count disclosed |

Security/correctness: raw `case.json` never reaches the browser; only the
sanitized projection. XSS-hardened (JSON-in-`<script type=application/json>`,
`textContent`-only tooltips/panel, http(s)-only explorer links). Per-route
nonce CSP keeps `connect-src 'none'`.

## Gap analysis & phased roadmap

### Phase 2 — client-safe depth ✅ SHIPPED (v0.35)

All client-safe; no new backend (reuses the `case.json` the portal already
loads; persistence via browser `localStorage`).

1. ✅ **Transaction-level drill-down on an edge.** Each edge carries a
   capped, sanitized `transfers[]` (date, USD, token, explorer link) with a
   disclosed remainder count; rendered as a list in the edge panel.
2. ✅ **Exposure wheel.** Node panel shows **received-from** and
   **sent-to** donuts, each split by the neighbor's recoverability category
   (`inByCategory` / `outByCategory`) — the client-safe analogue of
   Reactor's exposure wheel.
3. ✅ **Mini-map** with viewport rectangle + click-to-recenter.
4. ✅ **Export** — PNG (SVG→canvas, works under the `img-src data:` CSP),
   CSV (edge list), and Print / Save-as-PDF (`window.print()` + print CSS).
5. ✅ **Persisted view state** (layout, open groups, status filters,
   min-value, asset) per case via `localStorage` — no backend, no PII.

### Phase 3 — operator-grade graph (internal tool, not the victim portal)

Higher-value for investigators; some are sensitive and should **not** be
client-exposed.

> **Anchor — ✅ SHIPPED (v0.35).** The operator graph web view now exists:
> - `client_journey.build_operator_graph_data(case)` — un-sanitized,
>   journey-shaped, larger node budget, **risk verdict/score** + **indirect
>   exposure** per node (reuses `trace.risk_scoring` + `trace.indirect_exposure`).
> - `GET /v1/operator/graph/{investigation_id}` — **admin-gated** JSON
>   (`X-Recupero-Admin-Key`), loads the case from the bucket.
> - `GET /operator-graph` — unauthenticated HTML shell (review-gate
>   pattern): prompts for the admin key + investigation id and fetches the
>   JSON. Full interactive engine with **colour-by recoverability/risk**,
>   risk legend, **risk + indirect-exposure + investigator notes** in the
>   detail panel, **value-flow layout**, plus everything the client map has.
>
> 7. ✅ **Risk / heat scoring on nodes** — colour-by-risk overlay + legend +
>    panel verdict/score (operator only; client view stays recoverability-framed).
> 8. ✅ **Indirect-exposure** surfaced per node in the operator panel.
> 9. ✅ **Annotations + saved/shareable graphs (SHIPPED v0.35)** — notes
>    persist **server-side** per (investigation, node); named saved **views**
>    (layout/filters/groups/colour-by) are shareable across operators with the
>    admin key. `migrations/032_operator_graph_annotations.sql` +
>    `reports/operator_store.py` + admin-gated CRUD under
>    `/v1/operator/graph/{id}/annotations` and `/snapshots`. Endpoints degrade
>    gracefully pre-migration (notes read empty; writes 503). _Snapshots store
>    view config, not live-expanded hops or node positions._
> - Also shipped: **expansion result cache** (in-process TTL on the
>   constructed-adapter path) so repeat "expand" clicks don't re-hit the chain API.
>
6. ✅ **On-demand hop expansion (SHIPPED v0.35)** — the single biggest
   Reactor/TRM differentiator. Click a node → **Funds out ▸ / ◂ Funds in**
   in the panel pulls its next-hop counterparties live and merges them into
   the canvas (`reports/graph_expand.py` + admin-gated
   `GET /v1/operator/expand?chain&address&direction&limit`). Counterparties
   are ranked by value and **capped (40 default / 150 hard)** so one click
   can't dump a hairball; USD uses a conservative **stablecoin face-value**
   estimate (never overstated). Already-expanded (address, direction) pairs
   are remembered. _Remaining polish: live price oracle for non-stablecoin
   USD; server-side result caching; auto-trace-to-next-service._

> **Still requiring new infrastructure (not built — designs below):**

10. **Address "watch" / monitoring** — alert on future movement of a flagged
    address. _Design:_ a `watched_addresses` table + a periodic worker job
    (reuse the existing scheduler) that re-queries balances/transfers and
    emits a notification on change. _Effort: L._

### Phase 4 — scale & polish

11. **WebGL/canvas renderer** for >1k nodes. Current SVG comfortably handles
    the client (≤80) and operator (≤250) views; only needed once on-demand
    expansion (3.6) lets operators grow graphs past a few hundred nodes.
    _Effort: L._
12. **Multiple layouts** — ✅ **Force + Flow + Radial** (both views) and
    ✅ **Value-flow** (operator: depth columns ordered vertically by value —
    the Sankey-style read). True ribbon-Sankey remaining. _Effort: M._
13. **Real-time updates** — push new hops/labels as a trace progresses
    (SSE/websocket). _Effort: L. Needs streaming during the trace run._

## Data / infrastructure prerequisites

- **Per-edge transfer detail** (Phase 2.1) and **category exposure**
  (2.2): already derivable from `case.json`; just project more fields.
- **On-demand expansion** (3.6): the largest dependency — a guarded
  expansion API over chain adapters + label store, with result caching,
  so a click doesn't trigger an unbounded crawl.
- **Annotations / saved graphs / watch** (3.9, 3.10): new persistence.
  None require schema changes for the *current* client map; they do for
  these features.
- Keep the **client-safe boundary**: risk scores, raw vendor label
  internals, and operator notes stay in the operator tool. The victim
  portal stays framed around *recoverability and where their money went*.

## Suggested sequencing

Shipped: Phase 2 (client), the Phase 3 operator anchor + risk/exposure,
**on-demand hop expansion (3.6)** + result cache, and **annotations +
saved/shareable views (3.9)**. The operator graph now matches the core
TRM/Chainalysis explore-grow-annotate-save loop. Remaining, in value order:

1. ✅ **Non-stablecoin USD on expanded edges (SHIPPED v0.35)** — `graph_expand`
   takes an optional `price_fn`; `expand_address(with_pricing=True)` builds it
   best-effort from `pricing/coingecko.price_now` (per-token memoized, degrades
   to stablecoin-only on any failure — never overstated). The expand endpoint
   requests it.
2. **3.10 Address watch** and **4.13 real-time** — both ride the worker
   scheduler / a streaming channel.
3. **4.11 WebGL** and **4.12 ribbon-Sankey** — polish, once graphs routinely
   exceed a few hundred nodes (expansion makes that reachable).

### Known tech-debt

The graph engine is currently implemented **twice** — inline (nonce-CSP) in
the portal `journey.html.j2` and inline in the operator `operator_graph.html`.
They share the same data schema and logic; extract to one served static
`graph.js` (operator: `<script src>`; portal: relax that route's CSP to
`script-src 'self'`) so new features land once. Until then, keep feature
changes in sync across both.

---

Sources: [Chainalysis Reactor](https://www.chainalysis.com/product/reactor/) ·
[Indirect exposure](https://www.chainalysis.com/blog/cryptocurrency-risk-blockchain-analysis-indirect-exposure/)
