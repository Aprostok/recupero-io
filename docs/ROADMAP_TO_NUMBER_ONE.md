# Road to #1 — Recupero tracer · freeze · legal

Synthesized 2026-06-03 from a 5-domain parallel gap audit (trace engine, freeze
workflow, legal/LE, code quality, deploy/ops/UI) against the canonical checkout.
Goal: the #1 crypto-forensics tracer for **freezing** stolen funds and producing
**litigation-grade, legally-actionable** output — at or beyond TRM Reactor /
Chainalysis.

Standing constraints (never relax): never fabricate addresses/contacts/destinations
(real on-chain / real verified data or nothing); `high` confidence ONLY on
cryptographic cross-chain-ID match or direct label-DB hit, never inference; gate
every commit on the real pytest summary line; zero new ruff; never weaken a test.

Severity: **P0** = credibility/revenue/correctness-critical · **P1** = real moat gap
· **P2** = polish/coverage. Effort S/M/L.

---

## TRACK 0 — Make it LIVE (deploy enablement)  [in progress]

- **[DONE-pending-gate] API honors PaaS `$PORT`** — `api/app.py main()` precedence
  `RECUPERO_API_PORT → PORT → 8000`. Without it a `recupero-api` service binds 8000,
  fails Railway healthcheck.
- **[DONE-pending-gate] `/healthz` alias on API** — railway.json + Dockerfile both probe
  `/healthz`; API only had `/v1/health`. Added (schema-hidden) so an api service boots
  clean with no override.
- **P1 | API `main()` lacks Sentry / Prometheus / `setup_logging`** — worker has them; API
  runs blind. `api/app.py`. **S**
- **P1 | No CORS / TrustedHost middleware on API** — only body-size guard. `api/app.py`. **S/M**
- **P1 | api-service deploy runbook** — `RAILWAY_DEPLOY.md` is worker-only; document the
  3-service topology (worker/cron/api), `recupero-api` start cmd, `/v1/health`,
  `RECUPERO_ADMIN_KEY`. **M**
- **USER ACTION** — create the Railway `recupero-api` service (or flip the existing
  service's start command) → `<domain>/v1/console`.

## TRACK 1 — Tracing engine (beat Reactor on reach)

- **P0 | Bitcoin UTXO common-input-ownership (co-spend) clustering** — strongest BTC
  heuristic, currently out of scope (`trace/clustering.py:55`, `address_clustering.py:29`).
  Reactor's core BTC capability. `chains/bitcoin/inputs_registry.py`. **L**
- **P0 | Missing high-value chains** — TON (top DPRK/scam off-ramp), Sui/Aptos, UTXO
  altcoins (LTC/BCH/DOGE). Prioritize **TON** first. New `chains/<c>/`, `models.py` Chain,
  `chains/base.py:for_chain`. **L**
- **P1 | Calldata decoders emit `high` on pure ABI inference** (Across/Wormhole/Stargate/DLN
  in `bridge_calldata.py`) — surfaces `high` in briefs even with no cryptographic pairing.
  Violates confidence doctrine at the brief layer. Demote calldata-only to ≤`medium`; reserve
  `high` for `bridge_pairings` oracle confirmation. `bridge_calldata.py`, `cross_chain.py`. **M**
- **P1 | `cosmos` + `hyperliquid` adapters exist but unwired in `for_chain`** — BFS silently
  dead-ends into Cosmos/IBC (Axelar destination). `chains/base.py`. **M**
- **P1 | More bridges need cryptographic dest confirmation** — Symbiosis, Squid, LiFi,
  Multichain, THORChain, Orbiter, rollup-canonical. Add `BridgePairSpec` via the verified-tx
  recipe. `trace/bridge_pairings.py`. **M-L**
- **P2 | Mixer registry not wired into BFS/policies/brief** (`mixer_detection.py:47`); add
  Wasabi 2.0/WabiSabi, CryptoMixer. **M**
- **P2 | ML/behavioral fingerprinting** (gas/timing/nonce) — heuristic-only today. **L**
- **P2 | Pairing-rail decay monitoring** — DLN sig already drifted once; continuous re-verify. **S**

## TRACK 2 — Freeze workflow (the revenue core)

- **P0 | Exchange-FREEZE artifact (not just subpoena)** — CEX deposits only get a KYC
  subpoena; exchanges freeze on a documented theft trail within hours. Need exchange-freeze
  letter + exchange freeze-capability/contact DB + learning loop. "Half the freeze business."
  new `exchange_freeze_request.html.j2`, `freeze/asks.py`, `_deliverables.py`,
  `send_freeze_letters.py`. **L**
- **P0 | Detection→freeze-request not automated** — letters auto-generate but send is manual
  y/n; monitoring only *recommends*. For stablecoin theft (funds move in minutes) this is the
  #1 time-to-freeze gap. Auto-draft/queue a freeze request on an inflow-to-freezable alert.
  `monitoring/recovery_alerts.py`, `worker/_freeze_followup.py`. **M**
- **P1 | Outcome capture 100% manual** — no reply ingest; priors never reach n≥20 learned
  threshold, so the compounding moat stalls. Inbound-reply ingest → `freeze_learning/recorder.py`. **M**
- **P1 | Email-only dispatch; LE portals unactioned** — Tether/Circle/Coinbase use portals
  (in `issuers.json`); we email a generic inbox. `send_freeze_letters.py`. **M**
- **P1 | `issuers.json` contacts unverified + hand-maintained** — no freshness check; missing
  Base/Optimism/Avalanche stables. Validator + freshness. **S-M**
- **P2 | Followup stops at 14d** (enum has 30d/90d, cron never emits). **S**
- **P2 | Scorer heuristic priors stale** — only 8 issuers seeded (`recovery/scorer.py:47`). **S**

## TRACK 3 — Legal / LE / actionable legal guidance

- **P0 | Signed custody chain (Ed25519) + exhibit pack built but NEVER auto-invoked** — the
  pipeline writes only an unsigned SHA-256 manifest. Litigation-grade artifacts don't exist for
  a real case unless run by hand. Wire `render_exhibit_pack` + custody `append_attestation`
  into `worker/_deliverables.py`. **M**
- **P0 | No statute-of-limitations / filing-deadline guidance** — "statute" appears only as SAR
  labels; output never tells the victim a deadline (IC3 promptness, civil SoL by jurisdiction,
  freeze-window urgency). Core to actionable legal next-steps. Deadline table in
  `worker/_le_routing.py` + `le.html.j2`/victim summary. **M**
- **P1 | SAR/STR + MLAT/314(b) drafts not in pipeline** (CLI-only). Wire into `_deliverables.py`. **S**
- **P1 | Jurisdiction tailoring US-centric** — 6 hard-coded US states; non-US → one generic
  fallback. Add perp-jurisdiction + per-country counsel/channel. `worker/_le_routing.py`. **M**
- **P1 | No single bundled handoff package** (zip + AUSA cover/index). `_deliverables.py`. **M**
- **P2 | AI triage "next steps" lack a "not legal advice" disclaimer** (`ai_triage.py` `_DISCLAIMER`). **S**
- **P2 | Unverified `cryptocurrency@fbi.gov` injected into escalation prose** (`_le_routing.py:~437`). **S**

## TRACK 4 — Operator UI (see + drive EVERYTHING)

Operator console `_NAV` has 21 entries; these backend phases have **no** console view:
demixing (C2), clustering, multi-sanctions (E5), attribution feed (B1/B2), subpoena targets,
freeze letters/asks, LE handoff, victim intake, customer portal, recovery scorer, MEV/drainer/
peel/lightning detection, hack tracker, payments, monitor subscriptions, correlation lookup.
→ Add a console per unsurfaced phase (the established secure-shell batch pattern). Mostly **S** each.
- **P1 | Admin auth duplicated + no rate-limit on admin routes; SSE accepts key as query param.** `api/auth.py`. **M**

## TRACK 5 — Cleanliness / pristine

- **P1 | Capture live ruff / mypy-strict / vulture baselines** (sub-agent was sandboxed). Confirm green; fix any. **S**
- **P1 | Split god-modules** — `validators/output_integrity.py` **5443 LOC**, `trace/tracer.py` 3234. **L**
- **P2 | Stale version `0.32.0` in pyproject** (dynamic `__version__` resolves from it) vs v0.35.x. Bump. **S**
- **P2 | Python-version drift** — runtime 3.14 but `requires-python>=3.11` / ruff+mypy target py311. **S**
- **P2 | Oversized report/worker modules** (`emit_brief` 2766, `brief` 2323, `app` 2290, `_deliverables` 1822). **M-L**
- **P2 | "TODO:" template placeholders trip debt scanners** — switch to a distinct token. **M**

---

## Execution order (build sequence)

1. **TRACK 0** — land $PORT + /healthz (gating) → push → live. *(in flight)*
2. **TRACK 3 P0a** — auto-wire signed custody + exhibit pack (litigation credibility; bounded; offline-testable).
3. **TRACK 1 P1a** — calldata-`high` confidence-discipline demotion (forensic correctness; aligns with #1 constraint).
4. **TRACK 1 P1b** — wire cosmos/hyperliquid into `for_chain` (quick reach win).
5. **TRACK 3 P0b** — statute-of-limitations / deadline guidance (legal-advice value).
6. **TRACK 2 P0b** — auto-draft freeze request on inflow alert (time-to-freeze).
7. **TRACK 0 P1** — API Sentry/metrics/logging + CORS/TrustedHost + api runbook.
8. **TRACK 2 P0a** — exchange-freeze artifact + verified contact DB (large; staged).
9. … remaining P1s, then UI consoles (TRACK 4), then cleanliness (TRACK 5).

Each item = isolated change, gated on the real pytest summary line, zero new ruff,
real-data-only, `high` only on cryptographic proof.
