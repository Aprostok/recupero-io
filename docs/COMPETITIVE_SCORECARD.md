# Recupero vs Chainalysis / TRM / Elliptic — honest scorecard

Assessed 2026-06-03, reflecting everything shipped through this session. Scale:
**WIN** (we lead) · **MATCH** (at parity / close) · **LAG** (clearly behind) ·
**GAP** (largely absent). Judged from the actual codebase, not aspiration.

## Scorecard

| Capability | Chainalysis / TRM / Elliptic | Recupero | Verdict |
|---|---|---|---|
| **Attribution data scale** | Hundreds of millions of attributed addresses; hundreds of thousands of named entities | ~1.5k seed + 6 harvest sources feeding review→promote + paid-API plumbing (MistTrack keyed provider) + a coverage→target growth loop | **LAG** (the core moat — data, not code) |
| **Address clustering** | Continuous, chain-wide | Per-case multi-heuristic (co-spend, common-funding, same-multichain, shared-CEX) + cross-case victim clustering | **MATCH** (algorithm) / **LAG** (scale) |
| **Tracing engine (depth/recursion)** | Deep multi-hop | Deep-reach default, value-directed, 1:N peel-follow, dormancy-aware | **MATCH** |
| **Cross-chain / bridge tracing** | Broad bridge coverage | Cryptographic source↔dest bridge-pairing ORACLE (8 protocols, answer-key-free) + lock-mint matching + THORChain EVM→BTC | **MATCH** — arguably **WIN** on rigor (we confirm by the protocol's own cross-chain id, not inference) |
| **Demixing (Tornado/CoinJoin)** | Yes | demixing.py + coinjoin_unwrap (probabilistic, always low-conf) | **MATCH** |
| **Chain coverage** | ~25+ chains | ~13 functional: EVM family + Solana + Tron + Bitcoin + **TON (new)** | **LAG** (breadth) — closed TON this session |
| **Token coverage** | Thousands | Generic contract→coingecko_id resolution (any ERC-20/SPL/TRC-20/Jetton) | **MATCH** |
| **Real-time screening / KYT** | Mature KYT APIs | /v1/screen + on-chain 1-hop exposure probe + streaming webhook dispatch (HMAC, SSRF-guarded) | **MATCH** (capability) / **LAG** (scale, SLAs) |
| **Exposure %** | KYT headline | TRM-style exposure_summary + attribution-coverage report (% attributed + ranked labeling targets) | **MATCH** |
| **Investigation graph UI** | Reactor / TRM graph | Interactive graph: risk-coloured nodes, Chain↔Risk toggle, entity tooltips, expand/filter; 20-surface operator console | **MATCH** |
| **Behavioral / ML attribution** | ML clustering, Storyline | Heuristic only | **LAG** |
| **Freeze workflow** (issuer/exchange asset-freeze letters) | Largely **absent** — they're intel, not recovery | Issuer-freeze + exchange-freeze letters, contact DB, $0-freezable guards, INVESTIGATE exclusions | **WIN** |
| **Legal / litigation artifacts** | Limited | SAR/STR (US/UK/EU), MLAT/314(b), court exhibit pack, Ed25519 signed custody chain, statute-of-limitations advisory, AUSA handoff | **WIN** |
| **Recovery focus** (victim→freeze→file) | Not the product | The entire product thesis | **WIN** |
| **Forensic-correctness doctrine** | Trust the vendor | No fabrication; `high` only on cryptographic match / direct DB hit; build-failing validators (INVESTIGATE-not-billed, etc.) | **WIN** (auditability) |
| **Enterprise posture** (SOC2, RBAC, SSO, multi-tenant, SLAs) | Mature | Single admin-key console | **GAP** |
| **Court track record / brand** | Decade of accepted evidence, expert witnesses | New | **GAP** |

## Net read

**Where we genuinely WIN:** the *recovery* half of the problem — freeze letters,
issuer/exchange contact routing, SAR/MLAT/exhibit-pack/custody-chain litigation
artifacts, and a no-fabrication, validator-enforced correctness posture. The big
three are **intelligence** platforms; they hand you a graph and a risk score but
do **not** generate the freeze letter, the SAR, or the signed evidence pack.
That is recupero's product, and it's a real, defensible differentiator for the
victim-recovery / law-firm market they don't serve.

**Where we MATCH:** the analytical primitives — tracing depth, cross-chain
(arguably ahead on rigor via the pairing oracle), demixing, clustering
heuristics, token coverage, exposure %, screening, and the investigation graph.
Engineering is not the gap.

**Where we LAG / GAP — all reduce to two things:**
1. **Attribution data SCALE** — the moat. We shipped the *machinery* this
   session (6 free harvest sources, the scam/drainer high-risk path, the
   coverage→target→promote loop, and keyed paid-provider plumbing), but the
   labeled universe is still ~4 orders of magnitude smaller. Closing it is a
   data-acquisition + partnership program (`ATTRIBUTION_STRATEGY.md`), not code.
2. **Enterprise maturity + brand** — SOC2/RBAC/SLAs and a court track record
   come with time, customers, and process, not a feature.

**One-line verdict:** *On the engine and especially on freeze + litigation,
recupero is competitive-to-leading. On attribution-data scale and enterprise/
brand maturity, it trails — and those are the two things money and time buy, not
code.* The fastest credibility jump is a paid attribution feed (MistTrack/Bitrace
for the Tron/scam surface we actually trace) plugged into the keyed provider that
now exists — turning a code-complete engine into a data-complete one.
