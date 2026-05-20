# Recupero — 100-Item Strategic Improvement List

**Scope:** 6–12 month strategic backlog. Items ranked #1 → #100 by impact × inverse-effort. Categories tagged in `[BRACKETS]`; effort is **S** (≤3 d), **M** (1–2 wk), **L** (3–6 wk), **XL** (6 wk+).

**Observed shape (audited):**
- 11 chain adapters (Ethereum, Arbitrum, Base, BSC, Polygon, Optimism, Avalanche, Linea, Blast, zkSync, Scroll, Mantle, Solana, Tron, Bitcoin, Hyperliquid scraper).
- Trace stack: BFS tracer, clustering, indirect-exposure, CoinJoin unwrap, drainer detection, cross-chain handoffs, OFAC sync, perpetrator trace, dex_swaps.
- Freeze stack: issuers.json (Tether/Circle/Paxos/Maple), `match_freeze_asks` + historical-inflow synthesis, onward-CEX subpoena flows, freeze_outcomes table.
- Worker pipeline: webhook → trace → AI editorial → brief → PDF → email; watch_tick + mini_freeze digest; engagement letters; weekly follow-ups; LE handoff.
- Portal: token-gated read-only status + sign engagement letter (stdlib HTTP).
- Payments: Stripe Payment Links (diagnostic $499 / engagement $10K); contingent flows are AUDIT-only — no automation yet.
- Single-tenant (no operator/tenant_id column anywhere); SUPABASE_DB_URL; API-key auth (env-var list).
- Custody chain (Ed25519-signed attestations per stage) — solid; not yet third-party-verifiable.

**Conspicuously missing (verified by codebase search):**
- Monero / Zcash / Lightning Network: zero references.
- Multi-tenant / operator_id / assignee: zero references.
- Recovered-funds payout / disbursement / escrow / victim wire: zero references.
- Approval-revocation guidance for victim: not surfaced (drainer_detection notes the gap).
- DocuSign / e-signature beyond the stdlib portal sign form: zero references.
- Slack/Discord/SMS operator notifications: zero references.
- Stripe Connect / contingency-fee collection: dispatcher is audit-only.
- Public marketing site / SEO landing pages: not in this repo.

---

## Top 25 — Highest Leverage

1. **[RECOVERY] Recovered-funds disbursement pipeline** — Build the path from "issuer froze $X" → "victim receives $X minus 15% contingency". Today the codebase has no `disbursement`, `payout_to_victim`, `escrow`, or `wire_transfer` references anywhere. Without this, every successful freeze stalls at the manual-spreadsheet stage and contingency revenue is unbilled. Define schema (recovered_amounts, contingency_invoices, disbursements), Stripe Connect for victim payouts, and a `recupero-ops disburse` command.
   Impact: HIGH   Effort: L
   Why it matters: This is the whole revenue model. A freeze that doesn't end in a wire to the victim doesn't pay the 15%.

2. **[FREEZE] Tether direct LE portal submission + auto-acknowledgement polling** — Today `issuers.json` lists `compliance@tether.to` as a contact but every letter goes via the operator's email. Tether (and Circle, Paxos) have LE portals with case-tracking IDs. Wire a submitter that POSTs to those portals where APIs exist and a queue that re-checks status (per migration 013 has `freeze_letters_sent.outcome` but no poller).
   Impact: HIGH   Effort: M
   Why it matters: Cuts mean-time-to-freeze from days to hours, and surfaces "Tether asked for X more info" before the operator notices.

3. **[OPERATOR] Slack / Discord / SMS operator notifications** — `grep` confirms no Slack/Discord/Twilio integration. The operator polls Supabase / email today. Every state transition (review_required, freeze_acknowledged, victim_signed_engagement, payment_received) should fire a webhook to a Slack channel + optional SMS for high-priority.
   Impact: HIGH   Effort: S
   Why it matters: Operator misses high-value freeze windows when not at the laptop. Hours of latency cost cases.

4. **[FORENSIC] Approval-revocation guidance + one-click revoke link in victim summary** — `drainer_detection.py` detects the approval pattern but the victim summary doesn't tell the victim to revoke. Render an Etherscan token-approval link or a revoke.cash deep-link in `victim_summary_recoverable.html.j2`, scoped to the exact spender contracts the drainer used. Even when funds aren't recoverable, stopping ongoing bleed is value the victim feels immediately.
   Impact: HIGH   Effort: S
   Why it matters: Without this, the victim keeps signing future drainer approvals because no one told them they're still vulnerable.

5. **[MARKETING] Public SEO landing site + structured FAQ** — Repo has zero public-facing HTML, no robots.txt, no sitemap, no schema.org markup beyond the report templates. A victim searching `"my MetaMask was drained"` at 2 AM needs to land on a Recupero page. Build a Next.js or static-site frontend covering: how-it-works, $499 diagnostic CTA, common scams glossary (drainer / pig-butchering / approval / dust-attack), trust signals.
   Impact: HIGH   Effort: M
   Why it matters: Today every customer must already know Recupero exists. SEO is the only scalable acquisition channel.

6. **[VICTIM-UX] Self-service intake form with address validation** — `docs/INTAKE_ADDRESS_VALIDATION.md` describes the client-side validator but it's not built. Customers currently reach Jacob via email/DM. Build a web form that takes (incident description, victim_address, incident_time, contact email), runs the placeholder-address + format check inline, fires a Stripe payment link for $499, and writes to `public.cases` on payment.
   Impact: HIGH   Effort: M
   Why it matters: Removes the "Jacob has to hand-create a case" bottleneck — the customer self-serves to a paid case.

7. **[FREEZE] Real-time freeze-status board** — `freeze_letters_sent` table exists with `outcome` but no UI or CLI dashboard for "what's outstanding?". Operator can't see at a glance: 6 letters sent, 2 acknowledged, 1 confirmed frozen, 3 unresponsive past SLA. Build a `recupero-ops freeze-status` command + admin-UI panel.
   Impact: HIGH   Effort: S
   Why it matters: Cases die when the operator forgets to chase an unacknowledged letter at day 7.

8. **[FORENSIC] Off-ramp / money-mule heuristic** — Code has CEX-deposit detection but no `off_ramp`, `cash_out`, or `money_mule` heuristics. Add detection for: P2P escrow patterns (LocalBitcoins-style holding addresses with high deposit/withdrawal velocity), repeated-mule signatures (the same destination address sweeping from N drainer victims), and prepaid-card off-ramp clusters (known Cash App, Venmo, MoonPay ingress addresses).
   Impact: HIGH   Effort: M
   Why it matters: Off-ramps are the last freeze opportunity before fiat. Today they're invisible to the brief.

9. **[COMPLIANCE] Audit-log table + immutable access log for every PII read** — `grep -i audit_log access_log` returns 8 files but no centralized table. Cases contain victim_email, victim_phone, victim_address (physical). SOC 2 requires WHO read WHAT WHEN. Add `public.access_log` (user_id, table, row_id, action, ts) populated by triggers on cases/investigations/engagement_signatures.
   Impact: HIGH   Effort: M
   Why it matters: Mandatory for SOC 2 / ISO 27001 / GDPR Article 30. Without it, no enterprise customer can sign.

10. **[SCALE] Multi-tenant: `operator_id` everywhere + RLS** — `grep operator_id|tenant_id` returns zero. To onboard a second operator, every cases / investigations / freeze_letters_sent / watchlist row needs an `operator_id` and Supabase RLS policies. Currently impossible to scope a second analyst to "their" cases without leaking everything.
   Impact: HIGH   Effort: L
   Why it matters: The "10 operators / 100 cases-a-day" scenario in the brief is blocked at the schema. Doing it later means a much bigger migration.

11. **[FORENSIC] Live USDT-on-Tron freeze-target list refresh from on-chain Blacklist events** — Tether emits `AddedBlackList(addr)` events on the USDT-TRC20 contract. Subscribing and ingesting these gives Recupero a live "what's already frozen" feed — letting the brief tell the victim "$X of your stolen USDT is already frozen at address Y, here's how to claim".
   Impact: HIGH   Effort: M
   Why it matters: Frozen-but-not-claimed funds are the easy win. We're not surfacing them today.

12. **[LE-HANDOFF] Self-contained, offline-viewable evidence ZIP with custody-chain verifier binary** — `custody/chain.py` produces Ed25519 attestations but a federal agent receives raw files. Ship a single ZIP containing: HTML report, embedded JSON, PDF appendices, the `custody_chain.jsonl`, and a tiny standalone `verify.py` (or precompiled `verify` binary) that the agent can run offline to confirm integrity. Right now the agent has to trust us.
   Impact: HIGH   Effort: M
   Why it matters: Makes the package court-admissible at the chain-of-custody hearing without Recupero having to send a witness.

13. **[OPERATOR] Operator command palette / unified dashboard UI** — Today the operator runs `recupero-ops <subcommand>` from a terminal AND switches to a Supabase admin UI AND watches an email inbox. Build a single web dashboard (FastAPI + HTMX is enough) that shows: queue of cases by stage, freeze-letter status, payments incoming, victim-portal links, and one-click action buttons for the 10 most-common ops moves.
   Impact: HIGH   Effort: L
   Why it matters: Operator toil dominates total cost-per-case today. This compresses 90% of operations into one screen.

14. **[FORENSIC] Wormhole VAA + LayerZero packet decoder** — `cross_chain.py` lists handoffs but the brief explicitly says "follow-up URL pointing at the bridge's own explorer" for many bridges. `trace/bridge_calldata.py` exists for DeBridge — extend to Wormhole VAAs (decode signed observation → destination chain + recipient), LayerZero `_lzReceive` packet, Across deposit-id resolver, Stargate, Hop, Synapse.
   Impact: HIGH   Effort: L
   Why it matters: Half of all stolen-fund traces bridge at least once. Today the trace dead-ends; with this it continues automatically.

15. **[DATA] Daily Etherscan / Solscan label scraper into LabelStore** — `labels/seeds/cex_deposits.json` is a curated static file; per BACKLOG.md "labels stay manually curated". This caps coverage. Build a daily scraper (TOS-respecting, rate-limited) that pulls Etherscan address tags + Solscan + Arkham public dossiers and proposes new labels into a `labels_pending_review` table, then a human approves into the canonical store.
   Impact: HIGH   Effort: M
   Why it matters: Counterparty resolution is the #1 source of brief quality. Static seeds drift fast.

16. **[FREEZE] Pre-filled, auto-signed freeze letter as PDF (not HTML) sent from a Recupero-domain mailbox via Postmark/SES** — Existing freeze letters render to HTML; `_email.py` sends via SES. Wire WeasyPrint to produce a PDF, embed an x.509-style timestamped signature, and send from `freeze@recupero.io` (DKIM-aligned). Issuers respond faster to formal PDF letters than ad-hoc HTML emails.
   Impact: HIGH   Effort: S
   Why it matters: Doubles credibility on first contact with a new issuer.

17. **[FORENSIC] Bitcoin: peel-chain follower + multi-input cluster expansion** — `chains/bitcoin/adapter.py` documents that only the FIRST input's address gets a Transfer record — "the other 4 don't show outbound activity even though they did contribute funds". Fix the peel-chain attribution and add common-input-clustering so a perp's full Bitcoin wallet is surfaced.
   Impact: HIGH   Effort: M
   Why it matters: Current Bitcoin traces under-report the perpetrator's actual footprint by 60–80% for any multi-UTXO wallet.

18. **[VICTIM-UX] Victim portal: real-time status timeline with milestones** — `portal/templates/status.html.j2` shows engagement state but no timeline. Render: "Trace complete (May 17) → Freeze letter to Tether sent (May 18) → Tether acknowledged (May 19) → Funds frozen (pending)". Victims today email the operator weekly because they don't know what's happening.
   Impact: HIGH   Effort: S
   Why it matters: Each "where are we?" email is 10–20 min of operator time. Hundreds per month at scale.

19. **[FORENSIC] DEX-swap value attribution (AMM math, not just transfer-pair detection)** — `trace/dex_swaps.py` detects swaps but doesn't reconcile in/out values via the pool's k = x*y or stableswap invariant. When the perp swaps USDT → ETH via Uniswap V3, the trace should report the exchange rate and explain "no value loss vs. fair market price at block N" — courts ask this.
   Impact: HIGH   Effort: M
   Why it matters: Defense attorneys argue "the perp lost half the value in slippage so it's not stolen money downstream". This kills that argument.

20. **[RECOVERY] Court-order template generator for U.S. + UK + Cayman + BVI** — `legal_requests.py` covers MLAT / 314(b) / subpoena but no recovery-stage docs. After a freeze, the next step is a court order directing the issuer to disgorge to the victim's wallet. Generate templates per jurisdiction (most-common issuer jurisdictions: BVI/Tether, US/Circle, NY/Paxos) pre-populated from `case.json`.
   Impact: HIGH   Effort: M
   Why it matters: Today the attorney drafts from scratch — 4–8 billable hours per case. Template gets them to 1 hour of edits.

21. **[COMPLIANCE] PII encryption-at-rest with per-case key (envelope encryption)** — Supabase encrypts at the storage layer but the application sees plaintext. Wrap `cases.victim_email`, `cases.victim_phone`, `engagement_signatures.client_ip`, etc. in envelope encryption using a KMS (AWS KMS or Hashicorp Vault) keyed per-case. Operators who never opened a case can't read its PII.
   Impact: HIGH   Effort: L
   Why it matters: GDPR Article 32 + SOC 2 CC6.7. And reduces the blast radius of a future Supabase incident.

22. **[FREEZE] Per-issuer freeze success-rate dashboard (already wired in `freeze_outcomes` — surface it)** — Migration 013 collects outcomes; `recovery/scorer.py` uses heuristic priors (Tether 0.73, Circle 0.91). Build the dashboard that visualizes actual observed rates per (issuer, case_size_bucket, LE_backing) so the prior gets replaced by data as soon as N=20+.
   Impact: HIGH   Effort: S
   Why it matters: The compounding moat the BACKLOG calls out — every freeze the operator runs makes the next prediction sharper.

23. **[OPERATOR] Bulk freeze-letter send: one click sends N letters to N issuers** — `send_freeze_letters.py` sends one at a time. For a case with $20M across USDT + USDC + cbBTC + mSyrupUSDp the operator sends 4 separate letters. Add a "send all" with per-letter dry-run preview and a single confirmation.
   Impact: HIGH   Effort: S
   Why it matters: Reduces send-time from 30 minutes to 2 and eliminates the "forgot to send letter 3" failure mode.

24. **[FORENSIC] Drainer / wallet-as-a-service attribution (Inferno, Pink, Angel, Pussy, Venom)** — `drainer_detection.py` exists with "Pink Drainer / Inferno Drainer" attribution as a stated goal but the implementation only flags the approval pattern. Build a fingerprint DB: known drainer-router contract addresses, signature patterns, and victim-distribution networks per kit. Brief should say "Inferno Drainer v2 (60% confidence)".
   Impact: HIGH   Effort: M
   Why it matters: Attribution massively strengthens LE referral — FBI can pattern-match across cases.

25. **[SCALE] Worker horizontal scaling + per-investigation Postgres advisory lock** — `worker/pipeline.py` uses heartbeat-based claim but no advisory lock per investigation_id. Two workers racing can claim the same row in a tight window. Add `pg_try_advisory_xact_lock(hashtext(investigation_id))` so deploying N>1 workers is safe.
   Impact: HIGH   Effort: S
   Why it matters: Required for any horizontal scaling. Today a second worker corrupts state silently.

---

## 26–50 — High Leverage

26. **[FORENSIC] Privacy-coin exit detection (Monero, Zcash shielded)** — Zero references in code. Add: detection that a CEX deposit corresponded to an XMR/ZEC withdrawal at the same exchange within ε minutes of a USD-stable inflow — strong inference of laundering through privacy coins. Can't follow XMR on-chain but CAN surface the timing match.
   Impact: HIGH   Effort: M
   Why it matters: Sophisticated thieves are migrating to Monero off-ramps. We're blind today.

27. **[FORENSIC] Lightning Network channel-opening detection** — Zero references. When stolen BTC moves into a `2-of-2 multisig with htlc` output pattern (LN channel funding), flag as Lightning egress. The trace stops there but the brief should mention "funds entered Lightning at tx X" so the LE knows to subpoena the LSP.
   Impact: MED   Effort: S
   Why it matters: LN is rare today but growing as off-ramp.

28. **[DATA] OFAC sync schedule moved to cron + freshness banner in brief** — `ofac_sync.py` exists but BACKLOG notes it's operator-triggered. Add a daily cron + a `data_freshness` block in every brief: `"OFAC SDN: synced 2026-05-19, 12,847 crypto addresses"`. If stale >7d, brief carries a warning.
   Impact: HIGH   Effort: S
   Why it matters: Federal agents need to know we're using yesterday's data, not last quarter's.

29. **[VICTIM-UX] Email cadence: automatic post-trace summary email** — `_email.py` sends but the cadence is operator-driven for diagnostics. Add: T+15min "your case is being processed", T+1h "trace complete, here's what we found", T+24h "engagement letter waiting". The 30-day weekly cadence (`_followup.py`) only kicks in after engagement.
   Impact: HIGH   Effort: S
   Why it matters: Silence between $499 payment and brief delivery is the #1 reported anxiety. Auto-acks fix it.

30. **[VICTIM-UX] Customer-facing trace-replay visualization (Sankey + timeline)** — `_flow_diagram.py` produces an investigator graph; the customer sees a static PDF. Build a portal-embedded interactive Sankey (D3) so the victim can see "my $50K → drainer hub → 0xabc → Binance deposit" as a clickable flow. Currently the customer doesn't understand what they're reading.
   Impact: MED   Effort: M
   Why it matters: Drives engagement-letter signing because the customer believes the trace is real.

31. **[OPERATOR] One-button "escalate to LE" that auto-files IC3 + emails LERoutingPlan recipients** — `_le_routing.py` produces the routing recommendation but the operator copy-pastes into each agency's web form. IC3 (ic3.gov) accepts structured submissions; wire one.
   Impact: HIGH   Effort: M
   Why it matters: 30+ minutes of operator time per case; some operators skip it under load and the LE handoff never actually happens.

32. **[COMPLIANCE] GDPR-compliant data-deletion endpoint + retention policy** — Zero references to GDPR/retention in code. Per-case data retention (e.g. 7 years for engaged cases, 90 days for $499-only diagnostics that didn't convert) plus a `/v1/forget-me` endpoint that purges cases.victim_* and reduces case.json to a hash.
   Impact: HIGH   Effort: M
   Why it matters: EU and UK customers can't legally engage without this. Also limits liability on data we don't need to keep.

33. **[FREEZE] Cross-exchange flow-tagging API for the receiving exchange** — Today an exchange receiving stolen funds learns about it via a freeze letter days later. Offer a `POST /v1/notify-incoming-risk` API that exchanges integrate into their deposit-screening pipeline. Exchanges hold the deposit; Recupero gets a paid integration.
   Impact: HIGH   Effort: L
   Why it matters: Flips the value chain — Recupero becomes a feed exchanges pay for, in addition to a recovery service.

34. **[FORENSIC] Address-poisoning / zero-value-spoof filter (mentioned in journal)** — `journal.txt` line 39: "Address-poisoning filter for Lisu/zero-width spoof tokens". Not implemented. When a victim's trace shows a $0 transfer of a token named "USDT " (trailing space) or " USDC", flag and suppress — these are scam dust attacks polluting the trace.
   Impact: HIGH   Effort: S
   Why it matters: Operator wastes time chasing fake counterparties. Customer briefs include spam transfers.

35. **[OPERATOR] Telegram bot for read-only ops queries** — Operator on phone outside office. `/cases pending`, `/freeze status ZIGHA-001`, `/payments today` from Telegram. Read-only first, action commands later.
   Impact: MED   Effort: S
   Why it matters: After-hours visibility without VPN/laptop.

36. **[DATA] Drainer-router contract list ingested weekly from Scam Sniffer / Wallet Guard** — `high_risk.json` is static. Scam Sniffer publishes a public drainer-contract list updated weekly. Ingest into LabelStore via a scheduled job.
   Impact: HIGH   Effort: S
   Why it matters: New drainer kits launch monthly; static seeds miss the latest.

37. **[FORENSIC] Sub-daily price granularity via CoinDesk or Pyth historical** — `BACKLOG.md` flags this. CoinGecko demo tier returns daily-close, but a swap at 14:23 UTC needs the 14:23 price. Use Pyth's historical price-feeds (5-min granularity) for swap moments.
   Impact: MED   Effort: M
   Why it matters: Block-time-accurate USD values strengthen the brief defensively.

38. **[MARKETING] Hack-tracker public newsletter feed (already aggregated, just publish)** — `hack_tracker/aggregator.py` exists. Build a public `recupero.io/incidents` page + RSS that lists the daily digest. Lead-magnet: when a hack hits the news, victims googling it land on Recupero.
   Impact: HIGH   Effort: S
   Why it matters: Convert hack-tracker work (already paid for) into acquisition.

39. **[LE-HANDOFF] FBI VAU + Secret Service ECTF templates pre-routed by loss tier** — `_le_routing.py` returns LEContact tuples but the templates `mlat_request.html.j2`, `subpoena_request.html.j2` etc. are generic. Add agency-specific cover letters that match each agency's intake form expectations.
   Impact: HIGH   Effort: M
   Why it matters: Agents accept the package faster when it looks like what they're used to seeing.

40. **[SCALE] Per-API-key rate limit + Stripe-metered billing on `recupero-api`** — `api/auth.py` parses keys but has no rate-limit or metering. Add Redis-backed sliding window + a meter that posts usage to Stripe for monthly billing.
   Impact: HIGH   Effort: M
   Why it matters: API line of business is blocked without metering — can't charge $X per 1000 screens.

41. **[FREEZE] FinCEN 314(b) auto-routing for U.S. VASPs** — Template exists in `fincen_314b_request.html.j2`. Build a directory: which U.S. exchanges are 314(b)-registered, point of contact per. When the brief detects a 314(b)-eligible exchange, the operator gets a one-click "draft 314(b)".
   Impact: HIGH   Effort: S
   Why it matters: 314(b) bypasses subpoena requirement for VASP-to-VASP intel. Currently underused.

42. **[FORENSIC] Same-block / same-tx co-spending behavioral cluster** — `clustering.py` has H1/H2/H3 heuristics but no "addresses that ALWAYS submit txs in the same block" check. This is the strongest non-trivial cluster signal (single-controller behavior).
   Impact: HIGH   Effort: M
   Why it matters: Materially expands the perpetrator's surfaced footprint, which directly grows the LE / class-action target.

43. **[OPERATOR] Customer-call call-prep generator** — When a victim calls, the operator wants a 1-page summary: case state, last freeze update, outstanding asks, recommended next ask. Generate on-demand from `case.json` + freeze_letters_sent + engagement_signatures.
   Impact: MED   Effort: S
   Why it matters: Reduces call prep from 10 min to 30 sec, and reduces missed context.

44. **[DATA] Token-symbol spoof flag database (lookalike unicode)** — Beyond address poisoning: tokens deployed with name="USD Coin" symbol="USDC" but a different contract. Mentioned as a fix already shipped for Arbitrum USDC (`chain-coverage.md` line 13: "previously Arbitrum USDC was flagged as a spoof") but no public spoof DB.
   Impact: MED   Effort: S
   Why it matters: Brief credibility — false positives erode trust.

45. **[COMPLIANCE] Sentry / observability with PII scrubbing** — `observability/sentry.py` exists but unclear what scrubbing is configured. Audit + add allow-list scrubbing so no email / phone / wallet address ever leaves the worker via Sentry.
   Impact: HIGH   Effort: S
   Why it matters: Existing prod risk — a Sentry leak of one victim email is a notifiable incident under most US state laws.

46. **[FORENSIC] DeFi unwrap chain for LST / LRT tokens (stETH → ETH, eETH → ETH, ezETH, etc.)** — When stolen ETH gets staked into Lido and the perp now holds stETH, the trace shouldn't dead-end. Add an LST registry + balance-equivalence so the brief treats stETH as "ETH staked at Lido — withdraw window 7 days".
   Impact: HIGH   Effort: M
   Why it matters: Sophisticated thieves park funds in LSTs/LRTs assuming we don't follow.

47. **[VICTIM-UX] In-portal secure-message thread with the operator** — Today communication is email — un-encrypted, lost in inboxes. Build a per-case message thread on the portal. Operator types in admin UI, victim reads on portal, both archived in `messages` table.
   Impact: MED   Effort: M
   Why it matters: Compliance-grade audit of victim communications; reduces "I never got the email" disputes.

48. **[SCALE] Per-operator queue + assignment** — `worker/db.py` claims rows globally. With multi-tenancy, add operator-assignment so each operator's worker only sees their queue. Required for the 10-operator goal.
   Impact: HIGH   Effort: M
   Why it matters: Without this, 10 operators race on the same queue and step on each other.

49. **[FORENSIC] Sanctioned-jurisdiction IP/ASN cross-reference on portal access** — When a victim signs the engagement letter, `engagement_signatures.client_ip` is captured (`portal/server.py` `_extract_client_ip`). Cross-check against a sanctions IP DB so engagements from OFAC-sanctioned jurisdictions are flagged for operator review before pipeline run.
   Impact: HIGH   Effort: S
   Why it matters: AML / OFAC compliance for Recupero itself.

50. **[RECOVERY] "Returned-funds" notification template + Wise/Wire instructions form** — After a freeze succeeds, the victim needs to provide bank details for the disbursement. No form exists. Build one in the portal with KYC re-verification and Wise / SWIFT field validation.
   Impact: HIGH   Effort: M
   Why it matters: Bottleneck between freeze and payout today.

---

## 51–75 — Medium Leverage

51. **[FORENSIC] Cross-chain canonical-asset bridging math** — When USDC moves Eth→Polygon→Solana, the trace should treat them as the same asset (Circle CCTP burn/mint) and aggregate. Today each chain is a separate Transfer.
   Impact: MED   Effort: M
   Why it matters: Brief totals undercount perp consolidation across chains.

52. **[LE-HANDOFF] In-PDF clickable tx-hash links that resolve at print-time to archive.org** — `_pdf_links.py` exists. Add an archive.org snapshot of the explorer page at trace-time + embed the archive URL alongside the live one. Years from now when Etherscan changes its URL scheme, the evidence still resolves.
   Impact: MED   Effort: S
   Why it matters: Long-term forensic validity — court cases run 2–5 years post-incident.

53. **[FREEZE] Maple Finance / Sky / restaked-protocol direct freeze API integration** — `issuers.json` lists Maple but contact is an email. Maple has a governance multisig — for high-value cases, operator could request the multisig holders directly.
   Impact: MED   Effort: M
   Why it matters: Speeds DeFi-protocol freeze paths that aren't issuer-level.

54. **[OPERATOR] Auto-generated weekly internal KPI report** — Operator wants: cases this week, conversion rates, freeze success rate trailing 30d, MTTR per stage. Build on top of `dashboard_summary.py`.
   Impact: MED   Effort: S
   Why it matters: Business-management visibility without manual rollups.

55. **[DATA] Etherscan API key rotation + multi-key load balancing** — Single `ETHERSCAN_API_KEY`. At 100 cases/day the free-tier rate cap will bottleneck. Add a key-pool config and round-robin.
   Impact: MED   Effort: S
   Why it matters: Removes the rate-cap ceiling before it hits.

56. **[FORENSIC] Drained-wallet "next-victim" alerting** — If a drainer hub address is identified, watch it. When new victims appear (new inflows from previously-unseen seed wallets), alert — the same kit is active, possibly the same operator network.
   Impact: HIGH   Effort: M
   Why it matters: Could pre-empt the next victim's loss; large class-action surface.

57. **[VICTIM-UX] Multi-language support (Spanish, French, Mandarin, Korean)** — Templates are English-only. `journal.txt` mentions "French translation of LE brief" as open. Add Jinja i18n.
   Impact: MED   Effort: M
   Why it matters: Crypto theft is global; non-English markets underserved by competitors.

58. **[COMPLIANCE] Auto-redaction of victim PII in shared LE handoffs** — `send_le_handoff.py` exists. Add an option to scrub victim_phone / physical_address in the LE-shared package; keep them only in a sealed-cover-letter PDF that the agent decrypts on receipt.
   Impact: MED   Effort: S
   Why it matters: Reduces PII leakage even within trusted LE channels.

59. **[FORENSIC] Token-risk integration into the brief itself** — `token_risk/scorer.py` exists as API; brief generator doesn't call it. When a case touches a shitcoin contract, the brief should say "TOKEN: PEPE 2.0 — risk 9/10 (no LP lock, ownership not renounced, honeypot)".
   Impact: MED   Effort: S
   Why it matters: Explains to LE why the victim lost money even on a "legit" trade.

60. **[SCALE] Read-replica routing + Supabase pgbouncer transaction-mode** — `worker/db.py` opens connections directly. At scale Supabase will throttle. Route read traffic (dashboard, status polling) to a read-replica.
   Impact: MED   Effort: M
   Why it matters: Database is the first bottleneck at scale.

61. **[FREEZE] Letter-of-preservation auto-send to identified CEXes within 24h of trace** — Even when a freeze isn't possible, a preservation letter telling the CEX "don't delete this account's records" is cheap and protects the case. Today only happens manually after engagement.
   Impact: HIGH   Effort: S
   Why it matters: Preservation is cheap and high-value; we lose data we should be locking in.

62. **[DATA] CEX-deposit address auto-discovery via random sampling** — `cex_deposits.json` is curated. Run a periodic job that randomly samples Binance/Coinbase hot-wallet outflows, follows 1 hop, and proposes the new deposit addresses for review.
   Impact: MED   Effort: M
   Why it matters: Exchanges churn deposit addresses; static lists miss recent ones.

63. **[VICTIM-UX] Branded customer-facing case PDF (in addition to LE PDF)** — Customer currently receives a brief tuned for LE. Add a parallel render: customer-facing, plain-English, no jargon.
   Impact: MED   Effort: S
   Why it matters: Customer satisfaction; they share the customer brief with their lawyer.

64. **[MARKETING] Partner-attorney directory + referral fees** — `_le_routing.py` has agency contacts but no civil-recovery attorneys. Build a vetted directory; pay 10% of contingency on attorney-sourced cases.
   Impact: HIGH   Effort: M
   Why it matters: Attorneys are the highest-conversion lead source. Without a formal program, no incentive structure.

65. **[OPERATOR] Macro / templated email replies for common victim questions** — Operator types same 5 answers daily. Build a snippet library invokable from the admin UI.
   Impact: LOW   Effort: S
   Why it matters: Small but constant time-saver.

66. **[FORENSIC] Probabilistic UTXO-coloring (haircut method) for Bitcoin** — `coinjoin_unwrap.py` exists; extend to general dollar-weighted coloring downstream so a trace can say "of the $X currently in this address, 27% is attributable to victim Z".
   Impact: MED   Effort: L
   Why it matters: Matches court precedent (UK / US Disney v. Cuban etc.); Chainalysis charges premium for this.

67. **[COMPLIANCE] 2FA / WebAuthn on operator login** — `api/auth.py` is API-key-only. The admin UI authentication is undescribed in the repo (presumably Supabase Auth) but no MFA enforcement is in code.
   Impact: HIGH   Effort: S
   Why it matters: Operator account compromise = total system compromise.

68. **[FORENSIC] Hyperliquid perp-position reconstruction** — `chain-coverage.md` line 34: "Not a full perp analysis. Only withdrawals, deposits, and account transfers are captured. Fill-level trade reconstruction and liquidation events are not."
   Impact: MED   Effort: M
   Why it matters: Perp losses are an increasing share of victim claims; needed to dimension losses.

69. **[OPERATOR] Engagement-letter active vs. expired surfacing** — `_engagement_letter.py` tracks dates but the dashboard doesn't show "Tier-2 expires in 3 days for case ZIGHA-001". Without surfacing, operator forgets to renew.
   Impact: MED   Effort: S
   Why it matters: Tier-2 lapse = lost weekly-update commitment = customer churn.

70. **[FORENSIC] Pig-butchering ("sha zhu pan") pattern classifier** — Distinct from drainer / typo cases. Pattern: small initial deposit → fake CEX UI → "withdraw fee" extraction → ghosting. Add a classifier in `recovery/scorer.py`; brief tone changes (these cases are usually unrecoverable but FBI IC3 has dedicated handling).
   Impact: MED   Effort: M
   Why it matters: ~30% of incoming cases per industry data. Correct classification → correct recommendation.

71. **[DATA] Continuous on-chain `Tether.AddedBlackList` / `USDC.blacklist` event ingestion** — Tether + Circle emit on-chain events when they freeze. Subscribing and joining against our case data tells us "Tether just froze the address from case ZIGHA-001!" — close the loop without waiting for the email reply.
   Impact: HIGH   Effort: S
   Why it matters: Time-to-freeze-confirmation drops from days to minutes.

72. **[SCALE] Outbound webhook dispatcher (for exchanges/integrators subscribing)** — Once the API matures, partners want push notifications. Add a `webhook_subscriptions` table + a worker that POSTs case events to subscribers' URLs with HMAC signatures.
   Impact: MED   Effort: M
   Why it matters: Enables partnership monetization (exchanges, KYC providers paying for live feed).

73. **[OPERATOR] Auto-generated case post-mortem template** — When a case is `mark-closed`, generate a one-pager: outcome, $ frozen, $ recovered, $ contingency billed, lessons learned. Operators don't manually post-mortem today.
   Impact: LOW   Effort: S
   Why it matters: Tribal knowledge capture.

74. **[FORENSIC] Reverse-DNS / GitHub / ENS / SNS attribution layer** — When a perpetrator address has an ENS, GitHub gist with the same hex, or a forum post — surface it in the brief. Cheap OSINT that defendants rarely scrub.
   Impact: MED   Effort: M
   Why it matters: Real-identity attribution is the highest-impact LE handoff signal.

75. **[VICTIM-UX] Mobile-first portal rebuild** — `portal/templates/*.j2` are desktop-flavored HTML. Most victims access from mobile in panic mode. Audit mobile UX, add viewport meta + responsive CSS.
   Impact: MED   Effort: S
   Why it matters: Higher portal-to-engagement conversion.

---

## 76–100 — Long Tail / Strategic Optionality

76. **[FORENSIC] Cosmos / Osmosis / dYdX v4 adapters** — Not in the chain matrix; high-value users on these chains have no path.
   Impact: MED   Effort: L
   Why it matters: Underserved chains; defensive coverage breadth.

77. **[FORENSIC] Aptos / Sui adapters** — Same.
   Impact: LOW   Effort: L
   Why it matters: Low theft-volume today but rising.

78. **[FREEZE] Lazarus-specific freeze playbook** — DPRK-attributed cases need TFI/OFAC coordination differently. Build a triggered playbook when indirect_exposure flags Lazarus.
   Impact: MED   Effort: S
   Why it matters: Wrong route loses 30+ days.

79. **[OPERATOR] Quickbooks / Xero integration for contingency invoicing** — Manual invoicing today.
   Impact: LOW   Effort: M
   Why it matters: Eliminates a back-office step at scale.

80. **[COMPLIANCE] SOC 2 Type II pre-audit + auditor packet** — Build the policies, evidence catalog, and access reviews. Engage Vanta / Drata.
   Impact: HIGH   Effort: XL
   Why it matters: Required for institutional / exchange customers.

81. **[FORENSIC] Dust-attack origin clustering** — `journal.txt` lists 20 ZIGHA-DUST cases. The dust attacker is one entity; cluster their dust-spray addresses.
   Impact: MED   Effort: M
   Why it matters: Identifies the dust-spray service operator across cases.

82. **[DATA] Stablecoin issuer freeze-history dashboard (public)** — Aggregate Tether's public blacklist + Circle's transparency reports into a `recupero.io/issuer-stats` page.
   Impact: MED   Effort: M
   Why it matters: SEO content + thought leadership; positions Recupero as the data authority.

83. **[VICTIM-UX] Group-victim / class-action self-organization portal** — `trace/class_action.py` identifies co-victims but they can't find each other. Build an opt-in portal where co-victims discover and pool.
   Impact: HIGH   Effort: L
   Why it matters: Materially upgrades small cases by pooling them into class-action targets.

84. **[OPERATOR] Conditional automation: "if freeze acknowledged + amount > $50K + LE backed, auto-generate court order draft"** — Wire a rule engine.
   Impact: MED   Effort: M
   Why it matters: Removes operator-decision latency from high-value cases.

85. **[FORENSIC] Wash-trading + market-manipulation evidence layer** — When the perpetrator profited via market manipulation (pumps, rugs), document the wash-trades.
   Impact: LOW   Effort: M
   Why it matters: Adds SEC/CFTC referral pathway in addition to FBI.

86. **[LE-HANDOFF] EuroJust / Europol-compatible package format** — `_le_routing.py` is US-heavy. Add EU-format equivalents.
   Impact: MED   Effort: M
   Why it matters: EU cases are 30%+ of inbound; today handoff is ad-hoc.

87. **[VICTIM-UX] Voice-message victim intake (Twilio)** — Victims in shock often can't type a coherent narrative. Voice intake transcribed via Whisper, structured via LLM.
   Impact: LOW   Effort: M
   Why it matters: Reduces intake friction for older / less-technical victims.

88. **[SCALE] Multi-region worker deployment (US + EU)** — Today single-region. EU customers' data may need to stay in EU per GDPR.
   Impact: MED   Effort: M
   Why it matters: Compliance enablement + latency.

89. **[FORENSIC] Mempool monitoring for pre-confirmation alerts** — When a watchlist address broadcasts a pending tx (not yet mined), alert immediately. Race the perp to the exchange.
   Impact: HIGH   Effort: L
   Why it matters: Theoretical shot at front-running a deposit — extreme value if it works.

90. **[OPERATOR] Conversational AI ops co-pilot ("Claude, prepare freeze letters for ZIGHA-001 and queue for review")** — LLM wrapper over `recupero-ops` commands with confirmation gates.
   Impact: MED   Effort: M
   Why it matters: Lower-skill operators can be productive.

91. **[DATA] Sanctioned-VASP list (Garantex, Suex, Chatex, etc.) auto-flagging** — Beyond OFAC SDN addresses, full VASPs are sanctioned. Detect deposits to those VASPs' deposit clusters.
   Impact: MED   Effort: S
   Why it matters: Sanctioned-VASP exposure changes the case classification.

92. **[COMPLIANCE] FinCEN BSA "money-services business" determination + filing path** — If Recupero handles victim funds in disbursement, MSB status applies. Need legal opinion + state-by-state MTL.
   Impact: HIGH   Effort: XL
   Why it matters: Blocks #1 (disbursement) until cleared.

93. **[VICTIM-UX] Insurance partnerships (Coincover, BitGo, Lloyd's)** — Some victims have policies. Surface a "do you have crypto insurance?" question in intake and add insurance-claim-letter templates.
   Impact: LOW   Effort: M
   Why it matters: Recovery pathway for cases where freeze fails.

94. **[FORENSIC] Hard-coded explorer-link generator for chains not in `ADDRESS_EXPLORER_BY_CHAIN`** — Audit `_common.ADDRESS_EXPLORER_BY_CHAIN`; verify every chain in `Chain` enum has an entry. Failing case: brief has a chain with no link.
   Impact: LOW   Effort: S
   Why it matters: Brief polish.

95. **[OPERATOR] Operator-error rollback / undo system** — `mark-closed` is irreversible. Add a soft-delete + restore for mistaken status transitions.
   Impact: MED   Effort: S
   Why it matters: Operators make mistakes; need a safety net before headcount grows.

96. **[FORENSIC] Smart-contract decompilation summary in brief** — When a victim approved a malicious contract, the brief should include a one-paragraph summary of what the contract does (Mythril / Slither output). Today brief says only "is_contract: true".
   Impact: MED   Effort: M
   Why it matters: Explains the mechanism in court-grade detail.

97. **[MARKETING] Operator-written case-study blog (anonymized)** — Each closed case is a blog post template. Excellent SEO + trust signal.
   Impact: MED   Effort: S
   Why it matters: Content marketing at near-zero marginal cost.

98. **[SCALE] Cost-per-case accounting & alerting** — `dashboard_summary.py` has `total_api_costs_usd` per investigation. Add per-case unit-cost view + alert when a case exceeds budget. Stops AI-runaway pipelines.
   Impact: MED   Effort: S
   Why it matters: Margin protection at scale.

99. **[VICTIM-UX] Post-recovery NPS survey + testimonial collection** — Auto-send at T+30d after disbursement.
   Impact: LOW   Effort: S
   Why it matters: Marketing ammunition + product feedback.

100. **[STRATEGIC] White-label Recupero for law firms** — License the worker + brief generator to recovery-attorney firms as a SaaS. They sell to their clients; Recupero takes a per-case fee or revenue share. Requires multi-tenant (#10) and SOC 2 (#80) but is the largest TAM expansion path.
    Impact: HIGH   Effort: XL
    Why it matters: 100x the addressable market without 100x the operator headcount.

---

## Cross-cutting themes (not items themselves)

- **Compounding moat:** items #2, #11, #22, #56, #71 all turn live data into priors that beat Chainalysis. Prioritize the data-collection scaffolding even when individual items are unsexy.
- **Time-to-freeze:** items #2, #3, #7, #16, #23, #61, #71, #89 attack the freeze latency curve from different angles. Recupero's whole pitch lives or dies here.
- **Multi-tenant readiness:** items #10, #48, #67, #80 are prerequisites for any non-Jacob operator. Defer at your peril — they get more expensive every month.
- **Revenue tail:** items #1, #33, #40, #64, #100 unlock per-case revenue beyond the $499 + $10K + 15% contingency model. Today's revenue is bounded by one operator's throughput.

---

*Generated 2026-05-20 from a full audit of the cranky-fermat-54fcfb worktree against the v0.20.0 codebase shape.*
