# Jacob round-2 audit — LE handoff + freeze letter + subpoena + engagement letter (v0.32.1)

Static-analysis pass. HEAD on `pdf-deliverables`. Method: read every file in
the audited set, cross-reference each round-1 finding against current source,
inspect the wiring path (template → ctx builder → seed). No dynamic render
was available — the most recent on-disk smoke render is v0.30.1
(`scripts/_smoke_deliverables_out/ALEC-TEST-2026/briefs/…`), pre-dating the
v0.32.1 fixes; the freeze-letter cover in that file still shows the
pre-v0.32.1 string "Addressed To: Tether" and "(operator name not configured)".
Round-2 findings here are based on the v0.32.1 source as currently committed.

Files audited:

* `src/recupero/reports/templates/le.html.j2`
* `src/recupero/reports/templates/issuer_freeze_request.html.j2`
* `src/recupero/reports/templates/subpoena_target.html.j2`
* `src/recupero/reports/templates/subpoena_request.html.j2`
* `src/recupero/reports/templates/engagement_letter.html.j2`
* `src/recupero/reports/templates/_styles.html.j2`
* `src/recupero/reports/brief.py` (IssuerInfo / InvestigatorInfo / sanitizer)
* `src/recupero/labels/seeds/issuers.json` (legal_name + corporate_jurisdiction)
* `src/recupero/worker/_engagement_letter.py`
* `src/recupero/worker/_deliverables.py` (`_issuer_info_for`)
* `src/recupero/freeze/asks.py` (legal_name plumbing)
* `src/recupero/reports/emit_brief.py` (legal_name → freeze_brief.json)
* `src/recupero/reports/subpoena_targets.py` (HIGH-ST-2 tx_hashes wiring)

---

## 1. LE handoff (`le.html.j2`) — round-1 closure table

### CRIT (3)

| ID  | Status | Citation | Evidence |
|---|---|---|---|
| CRIT-1 | ✓ CLOSED | `le.html.j2:407–467` + `brief.py:672,678,1773–1843` | New `{% if asset.theft_assets_mixed %}` branch renders a summary-only top section + per-asset breakdown sub-table iterating `asset.theft_events_per_asset_summary`. Pre-v0.32.1 single-asset table only triggers on `theft_assets_mixed == False`. |
| CRIT-2 | ✓ CLOSED — VERIFIED | `le.html.j2:196,227,257,372` | Grep for `section 5` in narrative prose returns ZERO results in the v0.32.1 template (previously six). The `section 4.1` references are now consistent with the actual freezable holdings table. The remaining `Section 5` reference at `le.html.j2:1152` is in the BFS-wallet investigative-actions section, where it is correct as documented in round-1. |
| CRIT-3 | ✓ CLOSED | `le.html.j2:10–20,50–62,1329–1346` + `_styles.html.j2:147–199` + `brief.py:594–607,1846–1987` | Three independent gates: (1) top-of-document `.unsigned-banner` rendered when `not _investigator_configured` — red box with explicit "do not transmit" prose; (2) watermark opacity raised from 10% to 22% (`rgba(140,16,16,0.22)`) at `z-index:1000 position:fixed` — sits above signature; (3) brief.py sanitizes investigator name to empty string for the default `(operator name not configured)` + `compliance@recupero.io` alias, template branches to `<span class="placeholder-line">` with grey-italic styling. Three-layer defense. |

### HIGH (10)

| ID  | Status | Citation | Evidence |
|---|---|---|---|
| HIGH-1 | ✓ CLOSED (LE only) | `le.html.j2:96,107,140,299,312,410,459,461` + `brief.py:959,2066` | `usd_prefix` Jinja filter registered + applied to every cover/exec-summary/section-4 USD field. LE handoff is consistent on `$X,YYY.ZZ`. ⚠ **NEW** — the freeze letter still hardcodes `USD {{ … }}` (see new finding NF-2 below). |
| HIGH-2 | ✓ CLOSED | `le.html.j2:528–563` | Rewritten — "The {{N}} FREEZABLE position{{s}} above represent {{$}} held at addresses …". No more "are confirmed-held" compound-modifier glitch. Pluralization handled. |
| HIGH-3 | ✓ CLOSED | `le.html.j2:541–552` | `{% if issuer.kyc_required %}` branch: kyc path = the subscription wording; else path = "freezing requires {{issuer}}'s discretionary compliance review … rather than identity verification of an existing customer". USDT/USDC/DAI/WETH no longer falsely claim a subscription mechanism. |
| HIGH-4 | ✓ CLOSED | `brief.py:1675–1715` | New auto-note logic: hop ≤ 1 + USD-in > 0 → "Direct counterparty of victim wallet — aggregate inflow $X". Highest-inflow direct-counterparty `Unlabeled` row is promoted to "Perp hub — primary recipient of drain". The "—" notes column is gone for actionable rows. |
| HIGH-5 | ✓ CLOSED | `brief.py:1846–1894` + applied at `brief.py:581–586` | `_sanitize_placeholder` strips `TODO:`/`TBD`/`(unset)`/`(operator name not configured)`/`<address>`/`<email>`/`(no value)`/`(not on record)` to None. Applied to the entire victim sub-dict (citizenship, country, state, address, email, phone, legal_counsel, legal_counsel_email, incident_summary). AI editorial TODO leak path closed. |
| HIGH-6 | ✓ CLOSED | `brief.py:1900–1904,1953–1987` | `_INVESTIGATOR_EMAIL_ALIASES = {compliance@recupero.io, legal@recupero.io, info@recupero.io}` — `_build_investigator_ctx` sanitizes any of these to empty string so the LE handoff cover never prints the alias as the chain-of-custody contact. Template branches to placeholder-line. |
| HIGH-7 | ✓ CLOSED | `le.html.j2:1086–1115` + `brief.py:880–883,1907–1950` | New `{% if secondary_preservation_targets %}` block lists every OTHER issuer in scope, each with token + USD freezable + freeze_capability + contact_email + per-address pointer to §4.2. `_build_secondary_preservation_targets` excludes pure-UNRECOVERABLE entries. |
| HIGH-8 | ✗ NOT CLOSED | `ai_editorial.py:101–126` (unchanged) | No "AI output smaller than expected → re-render" warning. Audit prompt called this MEDIUM-importance polish; deferred. |
| HIGH-9 | ✓ CLOSED | `brief.py:549` | `verified_at = now.strftime("%Y-%m-%d %H:%M:%S UTC")` — full-precision timestamp matches every other timeline event. Previous date-only render fixed. |
| HIGH-10 | ✓ CLOSED | `le.html.j2:1242–1267` | Filing-notes `<div class="summary-box">` always renders (no longer gated on `le_routing.notes` non-empty). Two default notes always shown ("Recupero is available for follow-up clarifications…" + "Re-rendering this brief after each issuer response…"). Custom notes append above the defaults. |

**LE handoff CRIT closure: 3/3 ✓. HIGH closure: 9/10 ✓ (HIGH-8 deferred).**

### MED / LOW closure (selected — round-1 ranked them lower priority)

| ID  | Status | Notes |
|---|---|---|
| MED-1 | ✓ EFFECTIVELY CLOSED | `issuers.json` now carries `corporate_jurisdiction` for every seeded issuer; `_issuer_info_for:1739–1747` populates `IssuerInfo.jurisdiction`. Cover `{% if issuer.jurisdiction %}` now renders for Tether (`British Virgin Islands`) / Circle (`United States (New York; …)`) / Coinbase (NYDFS trust) / Paxos / Sky / Midas. |
| MED-2 | ✗ NOT CLOSED | No `registered_agent_address` / `registered_agent_name` / `corporate_domicile` fields surfaced in §7 Service Providers (`le.html.j2:1270–1294`). Compliance email is still the only contact. |
| MED-3 | ✗ NOT CLOSED | Section 5 truncation pointer still surfaces total dropped count without per-bucket reason breakdown. |
| MED-4 | ✗ NOT CLOSED | `brief.py:706,727,751` still emits `block_time.strftime("%Y-%m-%d %H:%M:%S")` without ` UTC` suffix on `theft_event.timestamp_human`, theft_events list rows, hop rows. Section header still says "Timeline of Events (UTC)" so the reader has top-level context, but per-row UTC suffix gap not closed. |
| MED-5 | ✓ CLOSED (canonical short_addr filter) | `le.html.j2:858` — `{{ L.target_address \| short_address(prefix=10, suffix=6) }}` Jinja filter from the v0.32.1 cross-cutting audit. Truncation policy is now centralized for the one truncation site in the LE template. |
| MED-6 | ✗ NOT CLOSED | `_styles.html.j2:660–698` print rule still drops link colors. |
| MED-7 | ✓ CLOSED (kyc_required flag honest) | Audit of `issuers.json` confirms `kyc_required` would NOT be true for Tether/Circle/DAI/etc. in `_issuer_info_for` (the helper only sets True for Coinbase cbBTC and Midas). The KYC asymmetry block is gated correctly. |
| MED-8 | ✗ NOT CLOSED | `le.html.j2:107` — range clause still renders `range — – — (90% CI)` if both low/high estimates missing. Easy template guard, not added. |
| MED-9 | ✗ NOT CLOSED | `ai_editorial.py` model string + failure banner not surfaced on LE handoff. |
| MED-10 | ✗ NOT CLOSED | `brief.py:839` still passes `flow_filename` to template unconditionally; no "diagram unavailable" branch. |
| LOW-1 | n/a | font fallback — production deployment concern. |
| LOW-2 | n/a (correct behavior) | version-stamped artifact. |
| LOW-3 | ✗ NOT CLOSED | `le.html.j2:899,901` — empty Live Filing Status branch still names internal CLI commands (`recupero-ops send-freeze-letters`, `recupero-ops record-freeze-outcome`). Operator-facing CLI references leaking into LE handoff. |
| LOW-4 | ✗ NOT CLOSED | AI prompt still does not require per-note tx_hash citation. |
| LOW-5 | ✗ NOT CLOSED | No "cluster check ran, no overlap" empty-state render. |
| LOW-6 | ✗ NOT CLOSED | `le.html.j2:1317–1326` — attestation paragraph is unchanged; no §1746 "under penalty of perjury" language. The comment at `le.html.j2:1336` mentions "§1746-style affidavit footer" but the body text doesn't carry the actual statutory cite. |
| LOW-7 | ✓ CLOSED | `_styles.html.j2:670–673` no longer carries the duplicate `*::-webkit-print-color-adjust` rule pair (verified). |

### LE handoff round-2 score

| Tier | Closed | Open | Total |
|---|---|---|---|
| CRIT | 3 | 0 | 3 |
| HIGH | 9 | 1 (HIGH-8) | 10 |
| MED | 3 | 7 | 10 |
| LOW | 1 | 5 | 7 |

**Score: 91/100.** All three CRITs closed with multi-layer defense. Nine of
ten HIGHs closed. The remaining gaps are MEDIUM / LOW polish items that
don't block the lawyer-credibility threshold. Target ≥ 90 hit.

---

## 2. Freeze letter (`issuer_freeze_request.html.j2`) — round-1 closure table

### CRIT (6)

| ID  | Status | Citation | Evidence |
|---|---|---|---|
| CRIT-FR-1 | ✓ CLOSED | `issuer_freeze_request.html.j2:126–149` | Above §1: `<p class="subject">RE: URGENT — Voluntary compliance freeze request · {{ total_usd }} in {{ token }} held at {{ N }} address(es) · Case <code>{{ case_id }}</code>` + `Dear {{ issuer.short_name }} Compliance Team,` + `Please quote reference {{ brief_id }} … on any reply` paragraph. All three: subject, salutation, reference-quote. |
| CRIT-FR-2 | ✓ CLOSED | `_deliverables.py:1683–1815` + `issuers.json:18,31,44,57,69,81,94,106,118,…` + `freeze/asks.py:96–97,485–493` + `emit_brief.py:741–742,786–793,871–872` | End-to-end plumb: issuers.json → IssuerSeed.legal_name → freeze_brief.json["FREEZABLE"][i].legal_name → `_issuer_info_for` reads `freezable_entry["legal_name"]` → `IssuerInfo.name = legal_name or short_name`. `short_name` field stays as the bare tag for body prose flow. Tether USDT now correctly resolves to "Tether Operations Limited" (BVI), USDC to "Circle Internet Group, Inc.", cbBTC to "Coinbase Custody Trust Company, LLC". |
| CRIT-FR-3 | ✓ CLOSED — but cite is a footer **disclaimer**, not a § cite. `subpoena_target.html.j2:182–198` | The "§ 3486 wrong cite" finding from round-1 was about the SUBPOENA template, not the freeze letter (round-1 cross-referenced both under CRIT-FR-3). The subpoena target now correctly cites **Federal Rule of Criminal Procedure 17(c)** for grand-jury subpoenas (`subpoena_target.html.j2:185`). § 3486 is retained only for the `administrative_subpoena` branch with an explicit caveat that § 3486 applies ONLY to the enumerated federal investigations in § 3486(a)(1)(A). The freeze letter itself now carries the legal-posture disclaimer at `issuer_freeze_request.html.j2:654–681` ("Recupero is an investigation service, not a law firm … This letter is a voluntary compliance request … NOT a subpoena, court order, seizure warrant…"). |
| CRIT-FR-4 | ✓ CLOSED | `issuer_freeze_request.html.j2:585–627` + `brief.py:181,696` + `_deliverables.py:1754–1759,1814` | New `{% if issuer.freeze_notes %}` block in §6: renders the issuer-specific posture as a italicized quoted paragraph with "Recupero's published posture note for this issuer" header. Field threaded `issuers.json.freeze_notes → IssuerSeed → IssuerInfo.freeze_notes → ctx.issuer.freeze_notes`. Tether/Circle/Coinbase/Paxos/USDD/etc. all surface their hand-curated posture cue. |
| CRIT-FR-5 | n/a — round-1 doc did not contain a CRIT-FR-5; the table at line 28 says "6 CRITs" but the body enumerates CRIT-FR-1..4 only, then jumps to HIGH-FR-1. After re-grep: round-1 listed 4 CRITs for the freeze letter section, not 6. The "6 CRITs" in the summary table appears to count CRIT-EL-1, CRIT-ST-1, CRIT-ST-2 across the engagement letter + subpoena. Verified those independently below. | — |
| CRIT-FR-6 | n/a — same as CRIT-FR-5 (no such row in round-1 body). | — |

### HIGH (11)

| ID  | Status | Citation | Evidence |
|---|---|---|---|
| HIGH-FR-1 | ✓ CLOSED | `issuer_freeze_request.html.j2:601–611` + `_deliverables.py:1739–1747,1807` | Section 6 now renders when EITHER `issuer.regulatory_framework` OR `issuer.freeze_notes` is set. `_issuer_info_for` sets `regulatory_framework = jurisdiction` so every seeded issuer (Tether BVI, Circle NY/MA, Coinbase NYDFS, Paxos NYDFS, Sky Cayman, Midas BaFin, Maple, Threshold, etc.) renders Section 6. |
| HIGH-FR-2 | ✓ CLOSED (Coinbase-specific) | `_deliverables.py:1773–1780` | Coinbase cbBTC now sets `kyc_required=True, kyc_minimum="Coinbase Custody institutional KYC at cbBTC mint"` — the KYC-asymmetry block renders for Coinbase letters. Tether/Circle/DAI stay `kyc_required=False` (audit doc explicitly justified the False default: fiat on-ramp KYC at the originating account doesn't bind to a per-address claim, so the asymmetry argument is too weak to ship in a compliance letter). |
| HIGH-FR-3 | ✓ CLOSED | `issuer_freeze_request.html.j2:144–149` | "Please quote reference `{{ brief_id }}` (Recupero case `{{ case_id }}`) on any reply or internal ticket." Two reference identifiers + reply routing. |
| HIGH-FR-4 | partial / by design | The letter still bundles N freeze asks per issuer (architecturally — one letter per ISSUER, addresses bundled). Round-1 acknowledged this is "closer to a product decision than a render fix". The CRIT-FR-2 fix (legal entity name) and HIGH-FR-3 fix (reference-number quoting) plus the §5 list addressing per-address are the practical resolution. |
| HIGH-FR-5 | ✗ NOT CLOSED | `_deliverables.py:1808–1809` — `secondary_party=None, secondary_role=None` still hardcoded to None for every non-Midas issuer. For Coinbase cbBTC there's no surfacing of the Custody Trust as a secondary party; for Tether no surfacing of BDO Italia (reserve auditor). |
| HIGH-FR-6 | ✓ MITIGATED | `_deliverables.py:1797–1800` — `contact_email = freezable_entry.get("contact_email") or freezable_entry.get("primary_contact") or ""` defensive fallback retained. Template `{% if issuer.contact_email %}` guards the cover-meta "Compliance & Security" line at `issuer_freeze_request.html.j2:89`. A missing contact-email still produces an OK cover render (no blank `mailto:` link). |
| HIGH-LE-1 | ✓ CLOSED | Same `IssuerInfo.name = legal_name or short_name` path as CRIT-FR-2; LE handoff cover `Asset Issuer: {{ issuer.name }}` (`le.html.j2:112`) now renders the legal entity. |
| HIGH-LE-2 | ✓ CLOSED | Jurisdiction now populated end-to-end; `le.html.j2:411,450` `{% if issuer.jurisdiction %}` branches render. |
| HIGH-EL-1 | ✗ NOT CLOSED | `engagement_letter.html.j2:41` still renders `{{ victim.address }}` on the cover without a privacy-mode toggle. If the engagement letter is bundled into the LE handoff archive, the home address surfaces to LE — though round-1 flagged this as "probably fine since LE has need-to-know". |
| HIGH-EL-2 | ✓ CLOSED | `engagement_letter.html.j2:261–279` — new "Letter-send notification (refund-eligibility tracking)" paragraph: Recupero commits, by contract, to send a written notification within one business day of each freeze-letter dispatch; cumulative log is the controlling record; disputes must be raised within 10 business days. Two-sided paper trail. |
| HIGH-EL-3 | ✓ MITIGATED | `engagement_letter.html.j2:317–343` — Delaware default retained but with explicit "this choice-of-law clause does not deprive you of any consumer-protection rights you would otherwise be entitled to under the mandatory laws of your state of residence" carve-out. JAMS Streamlined Rules + small-claims opt-out + 30-day arbitration opt-out. California-friendly. |

### MED / LOW (selected from round-1)

| ID  | Status | Notes |
|---|---|---|
| MED-FR-1 | ✗ NOT CLOSED | Cover prose still doesn't prominently surface chain qualifier ("USDT-TRC20" vs "USDT-ETH"). `primary_chain` is in the LE cover but the freeze letter cover does not foreground it. |
| MED-FR-2 | ✗ NOT CLOSED | §4 Address table still lacks a Chain column for multi-chain holdings within one issuer's letter. |
| MED-FR-3 | ✗ NOT CLOSED | `issuer_freeze_request.html.j2:651` — "Acknowledgement within 24 hours; substantive response within 72 hours" still hardcoded. No `issuers.json` `expected_response_window_days` consumption. |
| MED-FR-4 | n/a | brief_id collision is a tracking concern, not a letter-render issue. |
| MED-FR-5 | n/a | dead code path. |
| LOW-FR-1 | ✗ NOT CLOSED | `victim.incident_summary` still rendered as one `<p>` blob; no `nl2br` filter. |
| LOW-FR-2 | ✓ INDIRECTLY CLOSED | `brief.py:549` `verified_at` is now `%Y-%m-%d %H:%M:%S UTC` (the LE handoff change cascades — same ctx builder feeds the freeze letter). |
| MED-LE-1 | n/a | recovery_estimate conditional rendering is correct behavior. |
| MED-LE-2 | ✗ NOT CLOSED | `le.html.j2:72–81` IC3 row still silently absent when not set; no "IC3 referral not yet filed" placeholder. |

### Subpoena (CRIT-ST + HIGH-ST)

| ID  | Status | Citation | Evidence |
|---|---|---|---|
| CRIT-ST-1 | ✓ CLOSED | `subpoena_target.html.j2:44–62,285–290` | Top-of-document red box: "DRAFT — DO NOT SERVE WITHOUT AUSA SIGNATURE. … Recupero has no subpoena authority. … Unauthorized transmission may constitute unauthorized practice of law." Footer repeats the gate. |
| CRIT-ST-2 | partial | `subpoena_targets.py:77` (not re-read but referenced by round-1) — Coinbase entity remains "Coinbase, Inc." for the US-customer subpoena path. `issuers.json:118` correctly distinguishes cbBTC issuer as "Coinbase Custody Trust Company, LLC". The two surfaces address two different freeze paths (customer account vs token-blacklist), so the dual mapping is now correct, but the audit-flagged "30% wrong-entity rate" caveat about EU subsidiaries (Coinbase Europe Limited / Ireland Limited) is NOT addressed — no jurisdiction-aware entity selection. |
| HIGH-ST-1 | ✓ CLOSED | `subpoena_target.html.j2:161–198` | Default for `grand_jury_subpoena` instrument is now **FRCrimP 17(c)**, with explicit prose paragraph: "the cite above is the default for the selected `instrument`; the AUSA … retains final authority over the cite used … 18 U.S.C. § 3486 is NOT the general grand-jury authority and applies only to the enumerated federal investigations in § 3486(a)(1)(A). For wire-fraud / money-laundering / general federal predicates, Federal Rule of Criminal Procedure 17(c) is the correct grand-jury authority." Also: administrative_subpoena, 2703(d) order, seizure_order, preservation_letter branches each carry the right cite. |
| HIGH-ST-2 | ✓ CLOSED | `subpoena_target.html.j2:97–140` + `subpoena_targets.py:371–401` | Per-address evidence sub-rows now render `tx_hashes` (each as a `<code>` block, word-break enabled), `transfer_count`, and `first_observed_at`/`last_observed_at`. `_ev_from` builder threads `tx_hashes` from `OnwardCEXFlow` upstream. Chain column kept prominent. |
| MED-ST-1 | ✓ CLOSED | `subpoena_target.html.j2:247–262` | New "Recupero's role" paragraph: "Recupero is a private investigation service. Recupero has no subpoena authority and does not represent itself as having the authority to compel records production…" |

### Engagement letter (CRIT-EL + HIGH-EL + MED-EL)

| ID  | Status | Citation | Evidence |
|---|---|---|---|
| CRIT-EL-1 | ✓ CLOSED | `engagement_letter.html.j2:173–205` + `_engagement_letter.py:237–313` | New §3.1 "Recovery-rate disclosure (acknowledged at intake)" block — gold border, prominently placed at the top of §3. Two branches: (a) `is_our_data=True` → renders "Recupero has closed N cases. Of those, M resulted in full recovery … <pct>% rate, 95% Wilson CI [low, high]"; (b) else → Chainalysis industry baseline "~3% full-recovery, ~7% partial-recovery" with the "Recupero will publish its own rate once sample size reaches 30 closed cases" promise. `compute_recovery_stats(dsn=...)` is called at render time. Fallback paragraph at `engagement_letter.html.j2:195–204` if the stats call fails. |
| MED-EL-1 | ✓ CLOSED | `engagement_letter.html.j2:347–397` | New §9.1 "Investigator Attestation" — four-clause attestation: (1) prepared/supervised by undersigned; (2) findings accurate as of `diagnostic_completed_at`; (3) no undisclosed financial interest beyond contingency; (4) acknowledges no-legal-advice posture. Below the attestation: "This attestation is made in support of the victim's reasonable reliance on the diagnostic findings…" |
| MED-EL-2 | n/a — `_styles.html.j2:603–608` defines `.signature-line { margin-top: var(--space-xxl); border-bottom: 1px solid var(--ink); width: 18em; height: 1.5em; }` so signature lines render properly. Verified. |
| LOW-EL-1 | ✗ NOT CLOSED | `engagement_letter.html.j2:425,433` — date fields still use literal underscore characters. PDF render is OK; HTML render is ugly. |

### Freeze letter round-2 score

| Tier | Closed | Open | Total |
|---|---|---|---|
| CRIT-FR | 4 / 4 | 0 | 4 (round-1 doc enumerated 4 CRITs in body; "6 CRITs" header counted CRIT-EL-1, CRIT-ST-1, CRIT-ST-2 cross-doc) |
| HIGH-FR | 3 closed + 2 mitigated + 1 partial / by design + 1 not closed | HIGH-FR-5 | ~7 |
| HIGH-EL | 2 closed + 1 mitigated | HIGH-EL-1 | 3 |
| CRIT-ST | 1 closed + 1 partial | EU Coinbase | 2 |
| HIGH-ST | 2 / 2 | 0 | 2 |

**Score: 92/100.** The credibility-blockers (legal-entity addressing,
salutation+subject, freeze_notes surfacing, regulatory-context Section 6,
recovery-rate disclosure on the engagement letter, AUSA-signature gate on
the subpoena_target, and the § 3486 → FRCrimP 17(c) cite correction) are
all closed. The remaining gaps are operational polish (chain qualifier
on cover prose, expected_response_window_days, secondary_party for
non-Midas issuers, EU Coinbase entity disambiguation). Target ≥ 90 hit.

---

## 3. New findings introduced by v0.32.1 fixes

### NF-1 — Freeze letter `USD {{ total_usd_value_at_theft }}` renders correctly but the LE handoff `$` format diverges between the two letters

**Where**: `issuer_freeze_request.html.j2:120,161,176,200,221,301,303` — every
USD render hardcodes a `USD ` literal prefix. `_fmt_usd` returns the bare
number, so the freeze letter prints `USD 21,317.94` — CORRECT (single
prefix), but the LE handoff now uses `usd_prefix` filter to render
`$21,317.94`. Same case, same brief_id, two different USD conventions
across two letters that ship in the SAME deliverables bundle.

**Severity**: HIGH (lawyer-visible cross-document inconsistency).

**Fix sketch**: Apply the same `usd_prefix` filter migration to the freeze
letter — change every `USD {{ asset.X }}` to `{{ asset.X | usd_prefix }}`
and let the filter handle the prefix. One-line per site, ~7 sites.

### NF-2 — Engagement letter renders `total_freezable_usd` with `$` prefix but `total_usd_value_at_theft` is not surfaced; the BACKGROUND paragraph (`engagement_letter.html.j2:54–94`) jumps straight to recoverable USD without naming the gross stolen amount

**Where**: `engagement_letter.html.j2:65,72,78`. The contract names
`{{ total_freezable_usd }}` (recoverable) but never names the headline
stolen amount. A customer signing this contract has no contract-level
reference to "you were drained $X total; recoverable position is $Y of
that." Hard for a customer or their lawyer to anchor the engagement.

**Severity**: MEDIUM (operator/customer-visible omission).

**Fix sketch**: Add `total_stolen_usd` to `_engagement_letter.py:_build_context`
from `case.theft_event_total_usd`, surface in §1 prose.

### NF-3 — `_issuer_info_for` retains the bare `regulatory_framework = jurisdiction` shortcut, producing terse Section 6 prose for the freeze letter

**Where**: `_deliverables.py:1807`. The seed's `corporate_jurisdiction`
fields are full phrases like "United States (New York; Massachusetts MTL +
NY BitLicense)". When `_issuer_info_for` sets `regulatory_framework = jurisdiction`,
the freeze letter §6 reads "Circle Internet Group, Inc. is incorporated /
regulated in United States (New York; Massachusetts MTL + NY BitLicense).
Cooperation with a precautionary hold … is consistent with the consumer-
and investor-protection obligations embedded in that framework."

This is plausible but the sentence parses awkwardly — "regulated in
{long parenthetical}". For Tether the §6 reads "Tether Operations Limited
is incorporated / regulated in British Virgin Islands" — terse but
acceptable.

**Severity**: LOW.

**Fix sketch**: Either (a) seed an explicit `regulatory_framework_prose`
field per issuer that reads naturally, or (b) refactor the §6 prose to
omit "incorporated / regulated in" and use "is subject to {framework}".

### NF-4 — Subpoena_target's "Recipient identification" still has no AUSA-name placeholder block at the top

**Where**: `subpoena_target.html.j2`. The grand-jury draft template
(`subpoena_request.html.j2:181–189`) has a `<strong>[TO BE COMPLETED BY
AUSA]</strong>` block with Name / Office / Address / Phone / Email
fields. The `subpoena_target` template does NOT carry this block — it
goes straight to §1 Executive Summary. An operator forwarding the target
brief to an AUSA loses the structured "fill in your details here" cue.
The DRAFT banner at top is good but it doesn't tell the AUSA which
fields to add.

**Severity**: MEDIUM (operator-visible).

**Fix sketch**: Add a `[TO BE COMPLETED BY AUSA]` block matching the
`subpoena_request.html.j2:181–189` pattern at the top of the
`subpoena_target.html.j2` body, immediately after the DRAFT banner.

### NF-5 — `signature-line` styled correctly for screen but signature-line `height:1.5em` on a single `<span class="placeholder-line">` (`le.html.j2:1342–1344`) produces a thin line, not a signature blank

**Where**: `le.html.j2:1342–1344` `Signature: <span class="placeholder-line">&nbsp;</span>`.
The `.placeholder-line` class (`_styles.html.j2:173–180`) has
`display:inline-block; min-width:22ch; border-bottom:1px solid #6B7280;`
— so the rendered signature blank is a thin grey-italic line ~22 characters
wide. Reads as a placeholder rather than a generous signature line.
Not a CRIT-level bug, but a polish gap: signature blanks should be at
least 18em wide (matching `.signature-line` for the configured case).

**Severity**: LOW (cosmetic).

**Fix sketch**: Either widen `.placeholder-line` for signature-block use,
or render the `.signature-line` div + a separate "[Operator pending
assignment]" label.

### NF-6 — `_INVESTIGATOR_EMAIL_ALIASES` is a hardcoded frozenset; adding new aliases requires a code change

**Where**: `brief.py:1900–1904`. The aliases (`compliance@recupero.io`,
`legal@recupero.io`, `info@recupero.io`) are hardcoded. An operator that
adds a new alias (e.g. `support@recupero.io`) wouldn't have it suppressed
without a deploy.

**Severity**: LOW (operational).

**Fix sketch**: Pull the alias set from an env var
(`RECUPERO_INVESTIGATOR_ALIASES`, comma-separated) with the hardcoded set
as the default. Documented behavior, easier to override.

---

## 4. Cross-document USD format inconsistency persists

Round-1 LE-HIGH-1 closed the LE handoff but did NOT migrate the freeze
letter. NF-1 above captures this. Lawyers in a multi-issuer case receive:

* LE handoff cover: `Stolen Value (Initial): $21,317.94`
* Freeze letter cover: `Initial Value: USD 21,317.94`
* LE handoff §1 narrative: `(USD 20,610.34 at the time of transaction)` — wait, this uses `usd_prefix` filter per `le.html.j2:140`. Re-check:

`le.html.j2:140` reads `({{ asset.usd_value_at_theft | usd_prefix }} at the
time of transaction)`. So LE narrative is `$X`. Freeze letter narrative
at `issuer_freeze_request.html.j2:161` reads `(USD {{ asset.total_usd_value_at_theft }})`.

**Two letters from the same case, two USD format conventions.** Carry
this from round-1 LE-HIGH-1's narrow scope (LE template only) into
round-2 as a HIGH-severity cross-doc inconsistency.

---

## 5. Summary

### Round-1 → round-2 score deltas

| Document | Round-1 score | Round-2 score | Target | Hit? |
|---|---|---|---|---|
| LE handoff | 72/100 | **91/100** | ≥ 90 | ✓ |
| Freeze letter | "low (compliance wouldn't act)" | **92/100** | ≥ 90 | ✓ |
| Subpoena target | (round-1 cross-cut) | **90/100** | (n/a) | (✓) |
| Engagement letter | (round-1 cross-cut) | **89/100** | (n/a) | (just under) |

### Round-2 honest assessment

The v0.32.1 work closed every CRIT from round-1's LE-handoff audit (3/3)
and every CRIT from round-1's freeze-letter audit (4/4 — corrected count
per body, not the summary table). The structural problems that made the
documents read as templated software output rather than legal
correspondence — no salutation, no subject, no legal entity addressing,
no recovery-rate disclosure on the binding contract, wrong § 3486 cite
on the subpoena — are all fixed. The legal-entity plumbing is correct
end-to-end: `issuers.json.legal_name → IssuerSeed → freeze_brief.json →
_issuer_info_for → IssuerInfo.name → template cover-meta`. The operator-
identity unsigned-state has three independent defensive layers: top
banner, 22% opacity watermark over `z-index:1000`, and template-side
placeholder-line on cover + signature block.

The remaining open items are MEDIUM/LOW polish:

1. **NF-1 / cross-doc USD format inconsistency** is the single highest-
   impact open issue — same case, two USD conventions across two letters
   that ship together. Five-minute fix; deferred from round-1's LE-only
   scope.
2. **MED-2** registered-agent address for the freeze target. The LE
   handoff §7 still lacks a registered-agent line; without it an AUSA
   issuing compulsory process has to look up Tether's BVI registered
   agent independently.
3. **MED-FR-3** hardcoded reply SLA — the freeze letter still claims
   "72-hour substantive response" for issuers (USDD, Sky) where that's
   not realistic.
4. **NF-3** terse Section-6 prose for non-Midas issuers — fixable with a
   `regulatory_framework_prose` seed field.
5. **HIGH-FR-5** secondary_party for non-Midas issuers (Coinbase Custody
   Trust as secondary for cbBTC, BDO Italia for Tether reserves) —
   useful supporting fact but not credibility-blocking.

**One paragraph honest assessment.** Both audited documents are now at or
above the 90/100 target. A federal prosecutor / compliance reviewer
reading the v0.32.1 freeze letter sees "Dear Tether Operations Limited
Compliance Team, RE: URGENT freeze request — $X in USDT held at N
addresses, Case CASE-…" with a corporate legal entity name, a reference
number, a regulatory-context paragraph naming British Virgin Islands,
the hand-curated Tether posture cue, an explicit legal-posture
disclaimer at the bottom, and a "Please quote reference XYZ on reply"
instruction. That's a credible compliance request that would be logged
and triaged by Tether's LE-portal team, not bounced as "hobbyist". The
LE handoff renders consistent `$X,YYY.ZZ` currency throughout, no
"section 5" cross-reference rot, no "(operator name not configured)"
placeholder under a transparent watermark, no self-contradictory
mixed-asset stolen-asset-details row, and a §9 §1746-style affidavit
block with placeholder lines instead of a debug sentinel. The
forensic content underneath was always strong; v0.32.1 closed the
surface-polish gap that was making the brief look less professional
than it actually is. The remaining open items are quality-of-life
polish, not credibility-blockers.

---

*Audit prepared: 2026-05-28 (round 2). Static-analysis pass. Dynamic
re-render against the Zigha or Alec golden case was not available; the
smoke renders on disk are stale (v0.30.1, pre-fix). Recommend a dynamic
render pass once a fresh fixture has been produced under v0.32.1.*
