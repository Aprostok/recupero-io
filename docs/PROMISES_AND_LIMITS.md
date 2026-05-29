# Recupero v0.32.1 — Promises and Limits

This document is the calibrated language reference for three audiences:

1. The **operator** pitching a victim at the intake stage.
2. The **law-firm partner** reviewing the engagement contract.
3. The **AUSA / FBI-CD / IRS-CI agent** receiving the LE handoff.

Each audience expects different calibration. The operator must not
oversell. The partner needs disclosable limits and chain-of-custody
guarantees. The AUSA needs to know which claims are defensible in
court and which are heuristic leads.

We split the document into:

* § 1 — what Recupero **does** promise (10 promises, each grounded
  in code or process)
* § 2 — what Recupero **does not** promise (10 explicit non-promises)
* § 3 — calibrated language samples per audience

This is the source of truth for sales, legal, and operator-runbook
language. If you say something in customer-facing copy that isn't
in here, either it's wrong or this document needs updating.

---

## 1. What Recupero promises (v0.32.1)

### 1.1 Wilson 95% confidence interval recovery rate disclosure

Recupero publishes its historical recovery rate to every victim at
intake, before payment. The rate is computed with a Wilson 95%
confidence interval over the `freeze_outcomes` table
(`src/recupero/monitoring/recovery_rate.py`). When the table is empty
or below statistical significance, the published Chainalysis ~3%
industry figure is shown with explicit attribution.

The victim acknowledges the disclosure via a checkbox click that is
persisted in the `recovery_disclosures` table alongside the case row.
Engagement cannot proceed without this ACK.

This is the closure of Tier-0 risk 0.2 in
`docs/WHY_RECUPERO_WOULD_FAIL.md` ("the first time a paid customer
recovers $0").

### 1.2 Deterministic byte-identical artifact builds

Re-rendering a Recupero brief, freeze letter, LE handoff, or
victim summary from the same case data produces a byte-identical
output. This is enforced by the 3× determinism check in CI
(`tests/test_brief_determinism.py`, `freeze_brief_determinism.py`,
plus W3 expansion to LE handoff and freeze letter determinism).

**What this means for the court filing**: months after a brief is
sent, the firm can re-render it and prove that the rendered output
is byte-identical to the original. Chain-of-custody is preserved
without storing the original artifact bytes — only the manifest
SHA-256 hash needs to survive.

### 1.3 Point-in-time label resolution (INVARIANT N)

Every label cited in a brief is resolved as of the case's
`incident_time`, not as of render time
(`labels/store.lookup_pit_safe`). An address that is labeled today
as a Coinbase deposit but was unlabeled at the time of the incident
renders as unlabeled in the brief.

INVARIANT N (added v0.32.1 in W3-L) enforces this — the validator
round-trips every cited label through `lookup_pit_safe(incident_time)`
and fails the build if there is a mismatch. Confidence decays at
180 days (`labels/confidence_decay.py`); decayed labels render with
explicit footnote text.

### 1.4 Mandatory human-review gate (INVARIANT F)

No brief, freeze letter, or LE handoff leaves the system until a
human reviewer marks `brief_reviews.status='approved'`. The
dispatcher refuses to send any deliverable whose review status is
not `approved`. INVARIANT F (added v0.32) in
`output_integrity.py:4305+` makes this a hard fail in the validator
chain so the gate cannot be bypassed by an operator monkey-patching
state values.

This is the closure of Tier-0 risk 0.1 in
`docs/WHY_RECUPERO_WOULD_FAIL.md` ("one wrong brief in a real legal
proceeding").

### 1.5 Cross-chain BFS across 22+ chains with 13 + 5 bridge decoders

The trace pipeline walks BFS across 22 chains: Ethereum, BSC,
Polygon, Arbitrum, Optimism, Base, zkSync Era, Linea, Blast, Scroll,
Mantle, Fantom, Celo, Gnosis, Avalanche, plus 7 other EVM via the
Etherscan V2 multichain endpoint, plus Solana (Helius), Tron
(TronGrid), Bitcoin (Esplora), and Hyperliquid.

Cross-chain handoffs are followed via 13 app-layer bridge decoders
(`bridge_calldata.py`: Connext, Axelar, LiFi, Wormhole, Across,
Stargate / Stargate v2, Hop, Squid, Celer, Synapse, Symbiosis,
DeBridge, LayerZero) plus 5 rollup-canonical bridge decoders added
in v0.32.1 W2-E (Polygon PoS RootChainManager, Optimism
L1StandardBridge, Arbitrum Inbox, zkSync Era requestL2Transaction,
Base canonical bridge — Optimism Bedrock fork).

The continuation pass at `tracer.py:478-493` re-runs BFS on the
destination chain bounded by `RECUPERO_CROSSCHAIN_WINDOW_HOURS`.

### 1.6 Chain-of-custody completeness (INVARIANT G)

Every transaction the brief references has an `EvidenceReceipt` JSON
file with the raw RPC response under `evidence/`. The manifest
SHA-256 chain links each receipt to the brief that cites it.
INVARIANT G (added v0.32.1 W2-G) verifies that every cited
transaction hash in the brief, LE handoff, and freeze letter resolves
to an evidence receipt on disk.

If a receipt is missing or corrupted, the validator fails the build.
The brief cannot ship referencing evidence that doesn't exist.

### 1.7 Cross-document consistency (INVARIANTS I and K)

The brief, LE handoff, freeze letter, victim summary, and engagement
letter for one case carry consistent values for:

* Total stolen USD (INVARIANT C, K)
* Total freezable USD per issuer (INVARIANT 7, K)
* Recovery target addresses (INVARIANT B, K)
* Token symbols and contract addresses (INVARIANT K)
* Investigator and victim identity (INVARIANT I)
* Cross-chain handoff destinations (INVARIANT J)

If any pair of documents disagrees on any of these, the validator
fails the build. INVARIANTS I (W2-G) and K (W3-L) together close
the "documents disagree" failure mode the validator audit identified
at ~10% coverage pre-v0.32.1.

### 1.8 Mutation-test kill rate ≥ 90%

The mutation-test harness (`tests/mutation/`) injects deliberate
mutations into the core forensic modules and verifies the regression
suite catches them. v0.32.1's kill rate is ≥ 90% across the targeted
modules (tracer, bridge_calldata, dust_attack, clustering,
cex_continuity, drainer_detection, output_integrity).

This is a defense against silent-test-decay: a passing test suite
that no longer catches the bug it was written for. The mutation
harness fails the build if the kill rate drops below 90%.

### 1.9 Cryptographic artifact chaining (INVARIANT P)

Every artifact in a deliverable bundle (HTML brief, PDF, evidence
receipts, manifest) has its SHA-256 hash recorded in a signed
manifest. The manifest itself is signed by `RECUPERO_MANIFEST_KEY`.
INVARIANT P (added v0.32.1 W3-L) verifies the entire chain end-to-end
on every render and on every re-render. A tampered or truncated PDF
cannot silently slip in.

This is the technical foundation for the chain-of-custody promise
in § 1.6.

### 1.10 Open-source auditable codebase

The entire pipeline — chain adapters, BFS tracer, bridge decoders,
clustering heuristics, brief renderer, freeze-letter templates,
validators, dispatcher, review gate — is in a public repository.
An AUSA, defense counsel, or independent auditor can read the code
that produced any brief and confirm the cited heuristic does what
it claims.

This is operationally meaningful: a defense attorney challenging a
brief's attribution gets pre-discovery access to the algorithm. No
"proprietary forensic black box" defensive posture.

---

## 2. What Recupero does NOT promise

These are the limits. They appear in the engagement letter, the
freeze letter footer, the LE handoff disclaimer, and (in plain
English) on the intake form. If you communicate a promise outside
this list, either it's wrong or this list needs updating.

### 2.1 Recovery of funds

Recupero produces forensic evidence. Recovery requires action by
the issuer (Tether, Circle, Coinbase Custody, Paxos, etc.), the
exchange (Binance, OKX, Bybit, etc.), or law enforcement. None of
those entities is bound to act on a Recupero brief. Industry-wide
crypto-theft recovery rate is ~3% (Chainalysis 2024); our
historical Wilson 95% CI is published on intake.

### 2.2 100% trace completeness

The trace pipeline has named, documented gaps:

* **Bitcoin Lightning Network exits**: out of scope. Industry-wide
  dead-end.
* **Cosmos / IBC**: zero coverage in v0.32.1. v0.33+.
* **ERC-4337 user-operation decomposition**: partial coverage in
  v0.32.1; full decomposition v0.33+.
* **Bitcoin peel-chain**: simple patterns covered in v0.32.1; novel
  variable-step peels degrade.
* **Solana CPI / inner-instruction**: covered in v0.32.1 for the
  common Jupiter / Raydium / Orca patterns; novel program designs
  may slip.
* **Smart-wallet ownership swap (Safe `swapOwner`)**: not detected.
  v0.33+.

When the trace hits one of these gaps, the brief carries an explicit
marker (`trace_status: lightning_exit`, `trace_status:
unsupported_chain`, `trace_status: stop_at_contract_safe`, etc.) so
the operator knows the case is incomplete.

### 2.3 Real-time freeze

Legal process is days to weeks. Even a successful freeze letter sent
to a cooperative compliance team takes hours-to-days to act on. By
the time funds reach an exchange, the perpetrator has typically had
hours of additional movement opportunity. Recupero does not promise
real-time freeze and does not market a "stop the funds before they
move" capability.

### 2.4 Detection of every laundering pattern

A sophisticated adversary who has read the Recupero source code can
design a laundering route that evades us. The
`JACOB_ADVERSARY_AUDIT_v032.md` documents three such routes; v0.32.1
collapses Routes 1 and 2 (with caveats) but Route 3 ($50M speed-
laundered Arbitrum exploit) still partially escapes via budget
exhaustion.

We are shippable against unsophisticated thieves (the long tail).
We are not shippable as a sole defense against a Lazarus-tier APT
who has read the repo and has $5K of consultant budget.

### 2.5 Legal advice

Recupero is not a law firm. Briefs, freeze letters, and LE handoffs
are forensic deliverables, not legal advice. The engagement letter
explicitly disclaims attorney-client relationship. Victims who need
legal advice are referred to the firm's panel of crypto-litigation
attorneys.

### 2.6 Cooperation by every exchange

Cooperation varies by issuer. Tether and Circle have established
LE-cooperation programs and respond to credible freeze requests
within 24-72 hours. Smaller offshore exchanges in non-treaty
jurisdictions may not respond at all. Recupero publishes per-issuer
historical cooperation rates in the engagement letter and the
operator runbook.

A freeze letter that goes to a non-cooperative issuer produces no
freeze action. We disclose this risk pre-engagement.

### 2.7 Privacy beyond industry standard

Victim PII (name, contact, narrative) is stored in Supabase and on
worker pod filesystems for the duration of the case. We do not
provide additional encryption-at-rest beyond Supabase's default,
which is industry standard. PII is not transmitted to third parties
except as part of the freeze letter / LE handoff (which is the
explicit purpose of the engagement).

Victims with elevated privacy concerns (HNW, political exposure,
ongoing-threat scenarios) should disclose to the operator before
engagement so the case can be handled with appropriate
compartmentalization.

### 2.8 Coverage of every chain

Current chain set in v0.32.1: 22 chains.

**Not supported**: Cosmos and IBC zones, Lightning Network,
Aleo, Mina, Stacks, Aptos, Sui, Near, Algorand, Hedera, Polkadot
and parachains, Cardano. Any case with a meaningful hop into one
of these chains is partially traceable; the brief carries an
explicit `trace_status: unsupported_chain` marker per HIGH-2 of the
trace audit.

### 2.9 Detection of label-DB poisoning attacks

Our auto-ingest pipeline (`labels/auto_ingest.py`) pulls candidate
labels from DeFiLlama, Tronscan, Solscan, and (planned) Etherscan
tags. A sophisticated adversary can poison these upstream sources
(submit a fake "Binance Hot Wallet" tag on a Tronscan address they
control) and wait for our operator to promote it. The poisoned label
then directs future freeze letters to the wrong entity.

Defenses in v0.32.1: operator review is mandatory, multi-source
confirmation (M-1) requires two independent upstreams before
promotion, and the promote endpoint is rate-limited. But operator
fatigue across 800-entry seed files is a real residual risk
(R-033 in `RISK_REGISTER.md`). Two-key signing (M-2) is deferred
to v0.33.

### 2.10 Continuous monitoring of every wallet forever

Recupero traces a case at the time of engagement. We do not
continuously monitor every wallet in the case forever. The
`watch_tick` cron (`worker/cron_scheduler.py`) re-traces stale
monitored cases against the current label DB so freshly-labeled
perpetrator addresses surface — but this is a daily backfill, not
real-time. The retrace SLA is daily, not minutes.

A victim who needs continuous wallet monitoring is referred to a
paid monitoring SaaS (Chainalysis Kryptos, TRM Forensics, etc.).

---

## 3. Calibrated language samples per audience

These are the exact phrases. Use them. Do not paraphrase them in
customer copy without legal review.

### 3.1 Operator → victim (intake / pre-checkout)

**Use this**:

> "Recupero builds the forensic case file for your stolen crypto. We
> trace the funds across the blockchain, identify the destination
> wallets, and prepare freeze letters to the exchanges and a handoff
> packet for law enforcement. We don't recover the funds directly —
> the exchange or law enforcement does that, if they choose to act.
>
> Industry-wide crypto-theft recovery is about 3% on average; our
> own historical recovery rate is shown here [link to disclosure
> page]. Some cases recover everything; most recover nothing. Before
> you pay, you'll see a calculator with our recovery rate for cases
> shaped like yours."

**Do not use**:

* "We will get your money back."
* "Our recovery rate is over X%."
* "We have a partnership with [exchange]."
* "We can freeze the funds immediately."

### 3.2 Operator → victim (after engagement letter signed)

**Use this**:

> "I'm running the trace now. You'll get a draft brief within 48
> hours; my colleague reviews it before it goes out. Once the brief
> is reviewed, I'll dispatch the freeze letter to the exchanges
> where the funds are held, and the law-enforcement handoff to the
> AUSA or FBI field office you designate. From there, the speed of
> response is up to them — typically 24 to 72 hours for compliance
> teams to acknowledge, weeks to months for any freeze action."

**Do not use**:

* "The funds will be frozen by Friday."
* "We have a hotline at [exchange]."
* "I can guarantee a response."

### 3.3 Law-firm partner → engagement letter

The engagement letter (`reports/templates/engagement_letter.html.j2`)
already contains the calibrated language. Key clauses:

**Scope of engagement** (verbatim):

> "Engagement covers the production of one Forensic Brief, one
> Law-Enforcement Handoff Packet, and up to N Issuer Freeze Letters
> as identified by the trace. Engagement does not include legal
> representation, court filing, or follow-up correspondence with
> exchanges or law enforcement beyond the initial handoff."

**No attorney-client relationship**:

> "Recupero is not a law firm. This engagement does not create an
> attorney-client relationship. For legal advice regarding your case,
> consult independent counsel."

**Recovery disclaimer**:

> "Recupero does not guarantee recovery of stolen funds. Recovery
> depends on action by the issuer, exchange, or law-enforcement
> agency, none of which is bound by Recupero's deliverables. The
> historical Recupero recovery rate is published quarterly and
> reflected in the pre-engagement disclosure you acknowledged at
> intake."

**Refund**:

> "Partial refund of the engagement fee is available if no Law-
> Enforcement Handoff Packet is dispatched within seven (7) days
> of engagement signature, subject to the conditions in Schedule B."

### 3.4 Brief / LE handoff → AUSA

The LE handoff (`reports/templates/le.html.j2`) is the primary
document the AUSA reads. Key calibrated phrases:

**Section 1 / Executive Summary** (verbatim language):

> "This handoff packet documents an asset-trace investigation
> conducted by Recupero on behalf of [VICTIM]. The traced
> destinations, freeze candidates, and supporting evidence are
> presented for the recipient agency's evaluation. Recupero does
> not represent that the destinations identified are dispositive;
> they are the highest-confidence destinations identified by the
> trace heuristics documented in Section 7 / Methodology."

**Section 4 / Freeze candidates** (verbatim language for the table
caption):

> "The addresses listed below are identified by the trace as holding
> proceeds traceable to the incident. Label attribution is recorded
> as of [INCIDENT_TIME] (point-in-time); current labels may differ.
> Confidence per destination is reported in column 5 (HIGH /
> MEDIUM / LOW)."

**Section 5 / Identified wallets**:

> "The wallet enumeration below is the BFS frontier of the trace at
> depth N. Each wallet is either: (a) a labeled exchange or
> protocol destination, (b) a perpetrator-controlled wallet
> identified by clustering, (c) an unlabeled wallet under
> investigation. Categories (a) and (b) are reported with high
> confidence. Category (c) is reported as 'under investigation' and
> should not be treated as a freeze target without independent
> verification."

**Section 7 / Methodology** (the credibility-load section):

> "The trace was executed by Recupero v0.32.1 [GIT_SHA]. The
> heuristics applied are documented in the open-source codebase at
> [REPO_URL]; the specific code paths cited per finding are
> available in Section 8 / Chain of Custody. Re-rendering this
> packet from the same case data produces a byte-identical document
> (validated by the 3× determinism check in CI). The manifest
> SHA-256 chain documented in Section 8 cryptographically links
> every cited transaction to a stored evidence receipt."

**Disclaimer footer** (verbatim):

> "This document is forensic evidence prepared by Recupero. It is
> not legal advice. Recipient agencies are not bound to act on the
> findings. Recupero does not represent that the perpetrator
> attribution is dispositive; clustering and labeling heuristics
> are documented in the open-source codebase and are subject to the
> known limits enumerated in PROMISES_AND_LIMITS.md."

### 3.5 Freeze letter → compliance team

The freeze letter (`reports/templates/issuer_freeze_request.html.j2`,
post-W1-B fix) is calibrated for compliance triage. Key phrases:

**Subject line** (verbatim):

> "RE: URGENT — Freeze request, $[TOTAL] in [TOKEN] at [N_ADDRESSES]
> address(es) — Case [CASE_ID]"

**Salutation** (verbatim):

> "Dear [ISSUER_LEGAL_ENTITY_NAME] Compliance Team,"

(Note: legal entity name, not bare tag. "Tether Operations Limited"
not "Tether". W1-B fix.)

**Posture statement** (verbatim, lines ~70 of rendered letter):

> "This is a voluntary precautionary freeze request pending
> law-enforcement engagement. Recupero is not a law firm and this
> letter is not a legal demand. The matching law-enforcement
> handoff packet for this case has been dispatched to [AGENCY] under
> case identifier [LE_CASE_ID] (see Schedule C / LE Coordination).
> We are not alleging wrongdoing by the holder of the listed
> addresses; we are asking that funds be preserved pending
> investigation."

**Statutory citation** (verbatim, post-W1-B fix):

> "This request is made in support of an investigation under
> [APPLICABLE_STATUTE — typically 18 U.S.C. § 1956 / 1957 (money
> laundering) or 18 U.S.C. § 2703(d) (Stored Communications Act)
> depending on case context]."

(Note: NOT 18 U.S.C. § 3486, which was the wrong citation pre-W1-B.)

**Disclaimer footer** (verbatim):

> "Recupero is not a law firm. This letter does not constitute
> legal advice and does not create an attorney-client relationship.
> Recipient is not legally compelled to act on this letter; we
> respectfully request voluntary cooperation pending law-enforcement
> engagement. Forensic methodology and chain-of-custody documentation
> are available on request."

---

## 4. When in doubt

When customer-facing language is unclear:

1. Check this document first.
2. If the phrase you want to use isn't here, **do not use it**.
3. Escalate to product + legal for new calibrated language.
4. Once approved, update this document.

The downside of overpromising is existential
(`WHY_RECUPERO_WOULD_FAIL.md` Tier-0 risk 0.2 + UDAP exposure +
defamation if attribution is later contested). The downside of
underpromising is the customer goes to a competitor who overpromises.
That competitor's failure becomes our credibility win.

---

*End of PROMISES_AND_LIMITS.*
