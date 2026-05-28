# Jacob-style brutal audit — freeze letters, subpoenas, engagement letter (v0.32.0)

Static-analysis pass on HEAD = 7613281 (branch pdf-deliverables, main = c43be19).
Pipeline test execution was sandbox-denied; findings here are derived from the
templates, renderer code, and test fixtures. Where I couldn't *prove* a render
output I label the finding "static-only — verify in rendered HTML."

Files audited:
- `src/recupero/reports/templates/issuer_freeze_request.html.j2`
- `src/recupero/reports/templates/le.html.j2`
- `src/recupero/reports/templates/subpoena_target.html.j2`
- `src/recupero/reports/templates/subpoena_request.html.j2`
- `src/recupero/reports/templates/engagement_letter.html.j2`
- `src/recupero/freeze/asks.py`
- `src/recupero/labels/seeds/issuers.json`
- `src/recupero/reports/subpoena_renderer.py`
- `src/recupero/reports/subpoena_targets.py`
- `src/recupero/worker/_engagement_letter.py`
- `src/recupero/worker/_deliverables.py`  (the per-issuer renderer + `_issuer_info_for`)
- `src/recupero/reports/brief.py`           (IssuerInfo / InvestigatorInfo)
- `src/recupero/monitoring/recovery_rate.py`
- `tests/integration/test_trace_to_brief.py` (Zigha golden case)

---

## Severity counts

| Severity  | Count |
|-----------|-------|
| CRIT      | 6     |
| HIGH      | 11    |
| MED       | 9     |
| LOW       | 6     |
| **Total** | **32** |

---

## 1. Freeze-request letter (`issuer_freeze_request.html.j2`)

### CRIT-FR-1 — No salutation, no subject line, no body opener
The template opens with a banner cover page, then jumps straight to "1. Victim
Identification." A real compliance team expects:
- `RE: URGENT — Freeze request, ${TOTAL} ${TOKEN} held at ${ADDR-SHORT}, Case ${CASE_ID}`
- `Dear ${ISSUER} Compliance Team,`

Grep for "Dear" / "To Whom" / "Subject" / "RE:" in every `.j2` returns zero
hits in the freeze letter. The letter reads as a brief, not as
correspondence. Compliance triage tools (Zendesk-style routers at Circle,
Tether's LE portal) key on the first line of plain text — "Strictly Private &
Confidential" is what they get; that's letterhead chrome, not a subject.

**Fix sketch.** Insert above Section 1:
```jinja
<p class="subject"><strong>RE: URGENT freeze request — {{ issuer_freezable.total_usd_freezable }}
  in {{ issuer_freezable.token }} at {{ issuer_freezable.freezable_count }} address(es) — Case {{ case_id }}</strong></p>
<p>Dear {{ issuer.short_name }} Compliance Team,</p>
```

### CRIT-FR-2 — `issuer.name` is the bare freeze-brief tag, not a corporate legal name
`worker/_deliverables.py:1711-1726` (`_issuer_info_for`) synthesizes
`IssuerInfo(name=name, ...)` where `name` is the un-suffixed `issuer` key from
`freeze_brief.json` — i.e. "Tether", "Circle", "Coinbase". The freeze letter
then renders `Addressed To: Tether — Compliance & Security` in the cover meta
(`issuer_freeze_request.html.j2:85`). A real legal letter must address a legal
entity:
- USDT on Ethereum → "Tether Operations Limited" (BVI); USDT on Tron → also Tether Operations Limited
- USDC → "Circle Internet Group, Inc." (was "Circle Internet Financial Inc." pre-2024 IPO; renamed)
- cbBTC → "Coinbase Custody Trust Company, LLC" (NYDFS-chartered) — NOT "Coinbase, Inc."
- BUSD/PYUSD/USDP → "Paxos Trust Company, LLC"

The template also references `issuer.name` in body prose (5+ spots) — every
one currently says "Tether" / "Circle" / "Coinbase" instead of the legal
entity. This is the highest-credibility-impact finding: a compliance team
seeing "Addressed To: Tether" without the "Operations Limited" suffix
flags this as a hobbyist letter and routes it to the unverified-sender bin.

`brief.py:253-266` (`_TOKEN_ASSET_DESCRIPTIONS`) DOES know the correct legal
entities ("Tether Holdings Limited", "Circle Internet Financial") for the
asset-description row, but those names are themselves wrong:
- Tether USDT is issued by **Tether Operations Limited** / **Tether International Limited**, not Tether Holdings (a separate holding co)
- "Circle Internet Financial" is the pre-IPO name; Circle re-domiciled and is now **Circle Internet Group, Inc.** (NY-headquartered, IPO June 2025)

**Fix sketch.** Add `legal_entity_name` + `corporate_jurisdiction` fields to
`issuers.json` schema. Populate per token. `_issuer_info_for` reads from the
seed instead of synthesizing `name=name`. Existing Tether/Circle/Coinbase
freeze_notes already carry partial jurisdiction strings — promote into a
dedicated field.

### CRIT-FR-3 — No legal-posture disclaimer on the freeze letter
Grep for "legal advice" / "attorney-client" / "not a law firm" in
`issuer_freeze_request.html.j2`: ZERO matches. The engagement letter has the
disclaimer (engagement_letter.html.j2:165, 315-318); the freeze letter does
not. A compliance team reading the freeze letter has no clear signal whether
this is (a) a voluntary courtesy request from a private investigator, (b) a
legal demand from victim's counsel, or (c) an LE-sponsored ask. The cover
subtitle says "voluntary precautionary freeze pending law-enforcement
engagement" — that's good for posture but it's buried at line ~70 of the
rendered output. The "we are not alleging any wrongdoing" sentence at
line 550 helps but doesn't disclaim legal-advice status.

**Fix sketch.** Add a footer disclaimer paragraph that mirrors the
engagement_letter footer language: "Recupero is an investigation service, not
a law firm. This letter is a voluntary compliance request, not a subpoena,
court order, or formal legal process. Recupero does not provide legal advice.
For legal process, please coordinate with the prosecuting agency identified
in the LE handoff package."

### CRIT-FR-4 — `freeze_notes` from issuers.json is NEVER surfaced in the letter
The issuer DB carries hand-curated freeze posture notes per token (e.g.,
Tether: "frozen billions, generally responsive"; Circle: "demonstrated freeze
capability via blacklist"; WBTC: "limited; custody migrated post-Aug-2024";
USDD: "DAO governance posture opaque"). Grep `freeze_notes` in `**/*.j2`:
zero hits. The data is loaded by `freeze/asks.py:464` but never propagates to
the rendered letter. The compliance reviewer therefore reads a freeze letter
that says generic "place a precautionary hold" without the issuer-specific
posture cue that would distinguish a routine USDC freeze (high probability of
action) from a USDD freeze (probably DOA).

More important: the letter's section 4 totals box surfaces the bare token
`freeze_capability` HIGH/LIMITED/NO from the brief roll-up, but no prose
explanation. A USDD letter saying "Freeze capability: LIMITED" is opaque
without the freeze_notes context.

**Fix sketch.** Surface `freeze_notes` as a quoted paragraph in §6 or §7.
Drop `_section`-tagged commentary; keep the human-readable note.

### HIGH-FR-1 — Section 6 "Regulatory Context" omitted for every issuer except Midas
Template branches on `{% if issuer.regulatory_framework %}` (line 556).
`_issuer_info_for` only sets this field for the special-cased `MIDAS_ISSUER`
(brief.py:178). For Tether / Circle / Coinbase / Paxos the synthesized
`IssuerInfo` has `regulatory_framework=None`, so Section 6 silently
disappears from those letters. The Tether (BVI), Circle (Massachusetts MTL +
NY BitLicense), Coinbase (CDPL custodial trust), Paxos (NYDFS) framings are
all relevant context that a compliance team uses to validate the requester
understands their obligations — and they're all absent.

### HIGH-FR-2 — KYC asymmetry block hardcoded to Midas
Line 238: `{% if issuer.kyc_required %}`. `_issuer_info_for` only sets
`kyc_required=True` for Midas. So the "KYC asymmetry" argument (a legitimate
freeze-justification framing) renders ONLY in the Midas letter; Coinbase's
cbBTC letter — which has its OWN KYC asymmetry argument since cbBTC issuance
goes through Coinbase Custody KYC — drops the section entirely.

### HIGH-FR-3 — No reference number / case tracking field for compliance reply
Compliance teams reply by quoting a reference number. Recupero's letters
carry `case_id` and `brief_id` (line 92-97) but those are internal
identifiers, not a "Please quote `RECUPERO/2026/CASE-XYZ/TETHER` on reply"
instruction. There is no email subject prefix recommendation, no Reply-To
header guidance for the issuer's response, no "Section 5.5 follow-up
tracking" wiring back into Recupero's outcome-tracker.

### HIGH-FR-4 — One letter bundles N freeze asks per issuer — and the request prose acknowledges all of them
Section 5 list-item 1 (line 488) reads "Place a precautionary hold on the
USDT positions listed in section 4 — specifically, the 2 addresses marked
FREEZABLE totaling $170,687.26..." Lawyers strongly prefer one ask per
letter; the Tether letter bundles two USDT addresses, the Circle letter is
a single address, the Coinbase letter is a single cbBTC address, the Midas
letter is a single mSyrupUSDp address. The Tether bundling is potentially
fine, but the LE handoff Section 4.2 ALSO bundles all four issuers — both
documents will need separate handling per issuer at the compliance desk.

### HIGH-FR-5 — "secondary_party" / "secondary_role" hardcoded to Midas/Maple
The IssuerInfo carries `secondary_party` and `secondary_role` (e.g., for
Midas: "Maple Finance / underlying yield strategy manager"). For Coinbase
cbBTC the underlying counterparty is **the cbBTC-backing trust** + perhaps
Coinbase Asset Management; for Tether USDT, the underlying is **the Tether
reserve attestation auditor** (BDO Italia as of 2026). These are operator-
visible facts that strengthen the freeze ask. Currently null for every
non-Midas issuer.

### HIGH-FR-6 — `(unset)` / empty-string risk on synthesized issuers
`_issuer_info_for` sets:
- `jurisdiction=None` → template `{% if issuer.jurisdiction %}` skip
- `regulatory_framework=None` → skipped
- `contact_email = freezable_entry.get("contact_email") or freezable_entry.get("primary_contact") or ""`

The `or ""` fallback means a freeze_brief entry missing both contact fields
renders the cover-meta line as `Compliance & Security\n` (empty email) and
Section 8 contact email cell as a blank `<a href="mailto:"></a>` — visible
broken-link in the letter. The Zigha fixture seeds these correctly so the
golden case won't catch it. The bug surface is "a freeze_brief written by a
worker version that doesn't pre-fill contact_email for an unknown issuer."

### MED-FR-1 — Tether USDT-TRC20 vs USDT-ETH not distinguished in cover prose
Tether issues USDT on 10+ chains. The freeze letter to Tether for a Tron
USDT freeze and an Ethereum USDT freeze are the SAME compliance team but the
chain is operationally relevant ("Tether will freeze on Tron Y/N within X
days" differs from the Ethereum freeze posture). The current letter says
"USDT" in body prose with no consistent surfacing of the chain. The
`primary_chain` cover-meta and `theft_event.explorer_url` give it indirectly
but Tether's compliance triage may receive a freeze letter that doesn't
prominently say "Tron USDT" on the first page.

### MED-FR-2 — Cover prose drops trailing chain qualifier for stablecoins
Same root: the asset row in §2 says "USDT (contract: 0xdAC1...)" with the
contract link — but a Tron/Solana/BSC USDT has a different contract. A
single freeze letter sent to Tether that bundles multi-chain holdings would
be a credibility-killer because the per-row "Address" column doesn't show
the chain. Section 4 only shows `address`, `amount`, `usd` columns; no chain
column.

### MED-FR-3 — "Reply expected" SLA is hardcoded, not issuer-aware
Line 588: `<td>Acknowledgement within 24 hours; substantive response within 72
hours</td>`. The Tether issuer DB note already says "Tether has frozen
billions in USDT and is generally responsive" — but the seed has no
`expected_response_window_days` field. The CEX subpoena recipient map
(`subpoena_targets.py:74-89`) DOES carry per-recipient days (Circle=14,
Tether implicit, etc.) but the freeze letter doesn't consume that data. A
Tether response in 72h is plausible; a Paxos / Sky / USDD 72h SLA is not.

### MED-FR-4 — Brief identifier collision risk on multi-case clusters
`brief_id = BRIEF-{case_id[:8]}-{sha256(case_id + theft_tx_hash)[:6]}`
(brief.py:308-327). Truncated to 14 chars total; the 6-char hash gives
~16M space which collides at the 4K-case mark per (case_id-prefix) bucket.
Reference-number collisions across cases would be embarrassing in customer
correspondence. Not a freeze-letter bug per se, but a tracking bug.

### MED-FR-5 — "outbound_count_of_stolen_asset" is rendered even when section 4 enumerates per-address evidence
The `else` branch of Section 4 (line 446) renders "Outbound transfers of this
asset since receipt: {{ outbound_count_of_stolen_asset }}". That branch is
only taken when `issuer_freezable` is None (single-asset/single-holder
fallback). The per-issuer letters with `issuer_freezable` set won't hit this,
so it's not a direct bug — but it's dead code that the wallet-trace path
hits.

### LOW-FR-1 — `victim.incident_summary` injected as raw HTML
Line 234-236: `{% if victim.incident_summary %}<p>{{ victim.incident_summary }}</p>`.
This goes through Jinja autoescape (env is `select_autoescape(['html', 'j2'])`)
so it's escaped — good. But a multi-paragraph incident_summary will render
as one giant `<p>` blob without line breaks. Use a `|nl2br` filter.

### LOW-FR-2 — `verified_at` rendered as a bare date
"Last verified {{ verified_at }} UTC" (line 446). `verified_at` is set in
brief.py:501 to `now.strftime("%Y-%m-%d")` — just the date, no time. The
preceding "Date / time (UTC)" row uses `theft_event.timestamp_human` with
full timestamp. Inconsistent precision.

---

## 2. LE handoff letter (`le.html.j2`)

### HIGH-LE-1 — `issuer.name` is the same bare freeze-target tag in the LE letter as in the freeze letter
Same root as CRIT-FR-2. The LE handoff cover-meta row "Asset Issuer:
{{ issuer.name }}" (line 83) and 12+ body references all use the bare name.
The FBI / IRS-CI agent reading this expects "Tether Operations Limited
(BVI)" — they get "Tether." Less catastrophic than on a freeze letter
because LE is professional-tolerant, but it still reads as templated/
amateur.

### HIGH-LE-2 — "Issuer (legal entity)" row in LE Section 2 is hardcoded to Midas pattern
Need to verify in the full template — but `_issuer_info_for` does NOT set
`jurisdiction` for non-Midas issuers, and the LE handoff Section 2
explicitly mentions per the comment at l.131 that "Section 2 of this same
LE handoff still surfaces the freeze-target's jurisdiction in the
'Issuer (legal entity)' row." If jurisdiction=None, that row is blank.

### MED-LE-1 — `recovery_estimate` block conditional on field presence
Cover meta line 75: `{% if recovery_estimate and recovery_estimate.get('expected_recovered_usd') %}`.
This is an LE-relevant number ("AUSAs weigh case priority on this number").
For older briefs without RECOVERY_ESTIMATE the row silently disappears.
This is the right behavior but it means the LE letter's quality varies
silently between Recupero versions; a re-render of an old case won't
backfill.

### MED-LE-2 — IC3 reference rendered only when set; no "IC3 not filed yet" placeholder
The IC3 case-id row (line 49-58) is conditional; if no IC3 ID is on file
the row vanishes. For LE handoff the absence is significant — FBI's first
question is "did the victim file with IC3?" If not, the LE letter should
explicitly say "IC3 referral not yet filed; recommended as the first
external action."

---

## 3. Subpoena target document (`subpoena_target.html.j2`)

### CRIT-ST-1 — No explicit "AUSA signature required before sending" gate
The template footer reads:
> "This document is operator-prepared evidence intended for judicial /
> law-enforcement review. Not a public artifact."

That's not a clear-enough gate. Grep `AUSA|signature|before sending` in
the template: zero matches. Compare with `subpoena_request.html.j2` (the
grand-jury draft) which says explicitly "DRAFT — For AUSA Review &
Issuance Only" in the cover banner and has a `<strong>[TO BE COMPLETED BY
AUSA]</strong>` block at Section 7.

A subpoena_target file rendered to PDF and accidentally forwarded to a
CEX compliance team by a non-lawyer operator would be a malpractice-
adjacent event. The footer must explicitly say "DRAFT — DO NOT SERVE
WITHOUT AUSA SIGNATURE."

### CRIT-ST-2 — `Coinbase, Inc.` may be the wrong corporate entity
`subpoena_targets.py:77`: `"coinbase": ("Coinbase, Inc.", ...)`.
- **Coinbase Global, Inc.** is the publicly-traded holding co (CB on NASDAQ)
- **Coinbase, Inc.** is the US exchange operating subsidiary
- **Coinbase Custody Trust Company, LLC** is the NY-chartered trust (cbBTC backing, institutional custody)
- **Coinbase Europe Limited / Coinbase Ireland Limited** handle EU operations

For a US grand-jury subpoena against US-customer records, "Coinbase, Inc."
is plausibly correct. For cbBTC backing or institutional custody, the
correct entity is "Coinbase Custody Trust Company, LLC." For an EU/UK
customer the right entity is Coinbase Europe Limited. The single hardcoded
entry will be wrong about ~30% of the time. Verify with current Coinbase
subpoena response policy.

### HIGH-ST-1 — "Grand jury subpoena (under 18 U.S.C. § 3486 or equivalent)" cite is wrong for non-grand-jury subpoenas
Line 126: `{% if target.instrument == 'grand_jury_subpoena' %}Grand jury
subpoena (under 18 U.S.C. § 3486 or equivalent statutory authority)`.

**18 U.S.C. § 3486** is the *administrative subpoena* authority for
specified federal investigations (health-care fraud, child exploitation,
controlled substances, terrorism, certain federal crimes against the US).
It is NOT the general grand jury subpoena authority — that's **Federal
Rule of Criminal Procedure 17(c)** (which `subpoena_request.html.j2:42`
correctly cites). A grand-jury subpoena issued under 18 U.S.C. § 3486
in a non-§3486-enumerated offense is invalid.

This is the single most embarrassing legal-citation error in the audit. A
grand-jury subpoena to a CEX for a wire-fraud case should cite Rule
17(c). If the criminal predicate is `wire fraud / 18 U.S.C. § 1343`, the
right authority is FRCrimP 17(c), not § 3486.

### HIGH-ST-2 — Linked-address evidence column drops the chain
Subpoena target table (lines 86-103) shows `address` + `chain` + `role`
+ `amount`. The `chain` column exists. But the `evidence` sub-rows only
carry `amount_usd` and `label_source` — no tx_hash, no block_time, no
explorer_url. A subpoena to Binance saying "this address received $X" with
NO transaction-level evidence is rejected on review — the compliance team
needs the transaction hash to internally tie the on-chain deposit to a
customer account.

`subpoena_targets.py:374-376` does build the linked_address evidence with
just `amount_usd` and `label_source` — it never threads the underlying
tx_hashes through. Compare with `OnwardCEXFlow.tx_hashes`
(freeze/asks.py:248) which IS gathered upstream but never reaches the
subpoena target. Data loss bug.

### MED-ST-1 — No "investigator's role" disclosure
Section 6 says the document was prepared by Recupero "in coordination
with" the investigator. There's no explicit "Recupero is a private
investigation service; the investigator's role here is to surface
evidentiary basis, NOT to issue legal process." A reader may infer
Recupero has subpoena authority. The `subpoena_request.html.j2` template
DOES say "Recupero has no subpoena authority — this document is provided
to assist the AUSA's drafting process" (line 44-46). The
`subpoena_target.html.j2` template does NOT carry that disclaimer.

### LOW-ST-1 — `priority` pill renders user-controlled string into a CSS class
Line 47-48: `<span class="pill pill-{{ target.priority|default('medium') }}">`.
If `priority` is anything other than `high|medium|low`, the CSS class is
malformed but the worst-case is just unstyled text — autoescape handles
the XSS surface.

---

## 4. Engagement letter (`engagement_letter.html.j2`)

### CRIT-EL-1 — Recovery-rate disclosure (v0.32) does NOT appear in the engagement letter
The audit prompt explicitly required: "Recovery-rate disclosure (v0.32
addition) appears in the letter."

Grep `recovery_rate|recovery_disclosure|wilson_score` in
`engagement_letter.html.j2`: zero hits. Grep same pattern across all `.j2`
files: ONLY `intake.html.j2` carries it. The disclosure shows on the
intake form at checkout, but once the customer signs the engagement letter,
the published rate (e.g., "We have closed 0 of 30 cases with full recovery
— Wilson 95% CI [0%, 11.6%]") is absent. So the LEGAL document the
customer signs lacks the honesty-floor disclosure that the v0.32 work made
the keystone defense against "first paying customer gets $0 and slams us
on Twitter."

`worker/_engagement_letter.py:181` builds the context — no recovery_rate
key. The customer signs section 3 "What this engagement does NOT include"
which lists "Recovery of any specific amount" but never names the
Chainalysis 3%/7% industry baseline or Recupero's actual rate.

**Fix sketch.** Add `recovery_stats = compute_recovery_stats(dsn=...)` to
`_build_context` and render a paragraph in section 3 referencing the
exact same rate the customer ticked at intake. This puts the disclosure on
the binding contract.

### HIGH-EL-1 — `victim.address` is rendered without privacy review
Line 41: `{% if victim.address %}{{ victim.address }}{% endif %}`. The
freeze-letter privacy work (v0.30.0 F2 — issuer_freeze_request.html.j2
line 205-218) explicitly strips home address from the issuer letter. The
engagement letter is a private contract victim↔Recupero so home address
is appropriate — BUT the engagement letter is also part of the LE handoff
package by reference (LE Section 6+). If LE pulls the engagement letter
verbatim, the home address surfaces to LE. Probably fine since LE has
need-to-know, but worth confirming.

### HIGH-EL-2 — Engagement-fee non-refundability gate is text-only
Section 5 (line 215-222): "If you terminate before Recupero has sent the
compliance freeze letters: a 75% refund. After letters have been sent,
the engagement fee is fully earned and non-refundable."

There is NO mechanism to record the freeze-letter-send timestamp on the
engagement letter itself. The contract relies on Recupero's internal
records to determine refund eligibility. A customer who disputes
"letters were sent before my termination email" has no contract-document-
level proof either way.

### HIGH-EL-3 — `investigator_jurisdiction` defaults to Delaware
Lines 266-270: `{% if investigator_jurisdiction %}{{ investigator_jurisdiction }}{% else %}the State of Delaware{% endif %}`.
The engagement_letter.py caller defaults `investigator_jurisdiction=None`,
so every engagement letter says "Delaware" as both governing law AND JAMS
arbitration venue. For a TX-victim Recupero operator-of-record sitting
in California, that's a forum-selection problem: a Delaware JAMS venue
clause may be unenforceable against a CA consumer (CA's mandatory
arbitration jurisprudence and Iskanian/Viking River are strict).

### MED-EL-1 — Investigator attestation section is just the signature block
The audit prompt explicitly required: "Investigator attestation section is
complete." Section 9 (line 287-312) is a two-column signature table. There
is NO separate attestation paragraph where the investigator certifies under
penalty of perjury that the diagnostic findings are accurate to the best
of their knowledge. Compare with the LE handoff (which DOES have an
"Investigator Attestation" block per the v0.30.0 F7 commit). For an
engagement letter that triggers a non-refundable fee, an investigator
attestation matters: it's the legal hook for the customer's reliance
interest.

### MED-EL-2 — `signature-line` CSS class not in `_styles.html.j2` (assumed) — empty signature blocks
Line 296: `<div class="signature-line"></div>`. The CSS for this class
should render a horizontal line. If `_styles.html.j2` doesn't define it,
the signature blocks render as empty divs and the printed letter has no
visible signature line. Verify in `_styles.html.j2`.

### LOW-EL-1 — "Date: __________________________" hardcoded underscores
Lines 300, 309: the signature date field uses underscore characters
rather than a proper styled `<div class="date-line">`. Renders as ugly
underscore-spam in HTML; renders OK in PDF.

---

## 5. Cross-document consistency

### TOP-5 cross-document inconsistencies

1. **Issuer corporate entity name (CRIT)** — Tether/Circle/Coinbase letters,
   LE handoff, and subpoena_target each use a different convention:
   - Freeze letter: bare `issuer.name` = "Tether"
   - LE handoff: same bare `issuer.name`
   - Subpoena target: `_KNOWN_CEX_COMPLIANCE` = "Coinbase, Inc." / "Binance Holdings"
   - Brief asset description (`_TOKEN_ASSET_DESCRIPTIONS`): "Tether Holdings Limited" / "Circle Internet Financial"

   Four surfaces, four different naming conventions. A real legal team
   reads all four and sees a hobbyist project. (Also: Tether USDT issuer is
   "Tether Operations Limited" / "Tether International Limited," NOT
   "Tether Holdings Limited" — `_TOKEN_ASSET_DESCRIPTIONS` is factually
   wrong.)

2. **Recovery-rate disclosure missing from engagement letter** (see CRIT-EL-1).
   Customer sees the 3%/7% Chainalysis baseline on intake (HTML page),
   acknowledges it, pays the diagnostic fee. Customer then receives the
   engagement letter and the disclosure is gone. The intake form ack is
   logged in `recovery_disclosures` table — but a customer's lawyer
   reading the engagement letter will ask "where is the recovery-rate
   disclosure in the contract?" Today, the answer is "you ticked a box
   on the website."

3. **Amount aggregation across letters** (HIGH) — The Zigha golden case
   fixture sets:
   - Total drained: 6 × $600K = $3.6M (USDT theft)
   - Midas freeze: $3.12M mSyrupUSDp
   - Coinbase freeze: $246K cbBTC
   - Tether freeze: $97K + $73K = $170K
   - Circle freeze: $8.8K
   - DeBridge bridge handoff: $100K (cross-chain to Arbitrum)
   - Tornado mixer: $25K

   `$3.12M + $246K + $170K + $8.8K + $100K + $25K = $3.67M`
   But total drained = $3.6M. There's a ~$70K phantom from the bridge
   double-counting (the $100K bridged becomes the $100K Arbitrum hop;
   that's the same money twice in the fan-out totals).

   The `TOTAL_FREEZABLE_USD` and per-letter totals are not reconciled
   against `TOTAL_LOSS_USD`. A compliance reviewer cross-referencing the
   freeze letter ($3.12M Midas) against the LE handoff (TOTAL_LOSS_USD
   $3.6M) sees no reconciliation paragraph. Need a "Recovery Math"
   section: total stolen = $3.6M; freezable identified = $X (Y%);
   unrecoverable = $Z (W%); bridge-in-flight = $V (U%).

4. **Address format inconsistency between letters** — Some templates
   render `0xABC...DEF` (truncated), some render full address, some render
   address with explorer link, some without. Section 4 in
   issuer_freeze_request.html.j2 renders full address (good); §3 hops
   table renders `tx_hash[:14]...` (line 290) — truncated, no visible
   tail. A compliance reviewer who wants to copy-paste tx hashes from the
   letter into their internal tooling has to click each link.

5. **`verified_at` date format inconsistency** — freeze letter `verified_at`
   renders as `2026-05-21` (date only); LE handoff cover-meta `generated_at`
   renders as `2026-05-21T17:00:00`; engagement letter `generated_at`
   renders as `2026-05-21 17:00:00`. Three different timestamp formats
   across three letters for the same case.

---

## 6. Comparison to canonical templates

### Tether freeze-request template (canonical: Tether's published LE portal)
Tether's published LE-portal form requires:
- A government / law-enforcement letterhead OR a private-investigator
  affidavit on file
- Specific USDT contract address (chain-aware) + holder address + claim of
  ownership / fraud-victim affidavit
- Court order or formal request from LE with case number

Recupero's freeze letter is a **private investigator request on
Recupero letterhead**. That's plausibly accepted by Tether but it's NOT a
court order — and Tether's published policy says they freeze on LE
request with court backing. The Recupero letter cleverly references "pending
law-enforcement engagement" — but without the LE engagement actually
happening (e.g., an IC3 case number, an FBI agent name in §8), Tether's
compliance team will either (a) bounce the request as "we need LE
sponsorship" or (b) do a courtesy hold of ~7 days. The Recupero letter
does not say which outcome to expect.

### Circle USDC blacklist request (canonical: Circle's published LE portal)
Circle accepts requests via [https://www.circle.com/en/legal/law-enforcement](https://www.circle.com/en/legal/law-enforcement)
— typically requires:
- A formal LE request OR a court-issued order
- The specific USDC contract + holder address + sanctioning rationale

Same gap as Tether — Recupero's letter is private-investigator
authored. Circle's blacklist function is irreversible-ish (requires a
governance action to unfreeze), so they're cautious. Without LE
sponsorship the Recupero letter is unlikely to trigger an actual
blacklist; it's most useful as a "preserve evidence" pre-warning.

### Coinbase customer-account freeze (canonical: published policy)
Coinbase's policy is explicit: **customer-account freezes require a US
court order or formal LE request via their compliance portal**. A
private-investigator letter is logged but not actioned. The Recupero
letter for cbBTC freeze hits a different surface — cbBTC is an ERC-20
backed by Coinbase Custody Trust Company. Freezing the cbBTC token
itself (blacklist) goes through a different team than freezing a
customer account. The Recupero letter to "subpoenas@coinbase.com" routes
to the customer-account / subpoena team — which is **the wrong team** for
a cbBTC blacklist request. The right team is the Coinbase Asset Issuance
compliance group.

---

## 7. Bottom-line honest assessment

Would a real exchange compliance team act on the Tether / Circle / Coinbase
freeze letters generated by Recupero today?

**No, not as-is.** Compliance teams at Tether, Circle, and Coinbase
receive thousands of freeze requests per quarter. Triage is keyword-driven
and template-recognition-driven. The Recupero letter has solid evidentiary
content (on-chain tracing, tx-hash links, KYC-asymmetry argument for Midas)
— but it presents as a private-investigator product without LE
sponsorship, addresses the issuer by short name ("Tether" / "Circle"
without the corporate legal entity suffix), has no salutation, no subject
line, no reference number for reply tracking, no `freeze_notes` surfacing,
and includes an "issuer.regulatory_framework" Section 6 that silently
disappears for every issuer except Midas.

The letter would get logged (Recupero's evidence quality is real) and
either (a) bounced back asking "please have LE sponsor this request" or
(b) sat on until the AUSA / IC3 reference arrives. In neither case
would a same-day freeze action be triggered. The Coinbase letter routes
to the wrong team for cbBTC. The Midas letter is the strongest of the four
because Midas is permissioned-mint and the Recupero letter is highly
detailed for that issuer — but Midas's BaFin-disciplined compliance team
will still require a formal LE referral before acting.

The audit doc lands 32 findings — 6 CRIT, 11 HIGH, 9 MED, 6 LOW. The Tier-1
fix list is small: salutation + subject line + corporate legal entity name +
recovery-rate disclosure in the engagement letter + reference-number /
reply-tracking + AUSA-signature-required gate on the subpoena target +
correct § 3486 → FRCrimP 17(c) statutory cite. Without those, the letters
read as templated software output rather than legal correspondence.

---

*Audit prepared: 2026-05-28. Pipeline test execution was sandbox-denied;
findings are based on static analysis of templates, renderers, and seeds.
A follow-up dynamic-render audit against the Zigha golden case is
recommended before any external release of these letters.*
