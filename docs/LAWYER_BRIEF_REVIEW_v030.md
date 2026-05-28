# Lawyer's Brutal Review — Recupero Deliverables v0.16.4

Posture: I am an AUSA / compliance counsel reading these cold. I am skipping the cosmetic issues you already catalogued (footer version, operator stub, victim PII bleed, jurisdiction misdetection, "yield-bearing wrapper", 407/414 unlabeled). What follows is what would make me close the PDF or roll my eyes.

---

## 1. Document-by-document review

### 1.1 Issuer Freeze Request (Circle / Tether)

The cover subtitle is the first thing the compliance lead reads and it is hedged into uselessness:

> *"Stolen funds traced from the victim's wallet have been laundered into USDC and are currently held at 7 wallets under Circle's issuance authority. We respectfully request a voluntary precautionary freeze pending law-enforcement engagement."*

**WRONG (three failures in two sentences):**
1. "have been laundered into" — passive voice + a legal conclusion ("laundered" implies 18 USC §1956) you have not pleaded. Compliance will redline you.
2. "respectfully request a voluntary" — telegraphs that they can ignore you. Circle's TRM team triages on enforceability; "voluntary" puts this letter in the courtesy bin.
3. "pending law-enforcement engagement" — admits no LE is engaged yet, which is the single biggest "why should we act" red flag.

**FIX (active, posture-forward):**
> *"This letter places Circle on actual notice that 7 USDC addresses under Circle's burn/blacklist authority hold proceeds of an identified wire-fraud and computer-intrusion event (18 USC §§ 1030, 1343). Recupero, on behalf of Alec Prostok, demands that Circle preserve the addresses listed in §4 in accordance with Circle's published Stablecoin Policy and the constructive-trust principles that attach to traceable stolen property under Texas law. An IC3 complaint and FBI Dallas Field Office referral are concurrently filed (reference numbers in §8)."*

That sentence cites a statute, names a doctrine, gives the issuer a face-saving reason ("their own policy"), and signals that LE is on the other end of the wire.

**Other freeze-letter defects:**

- Section 5 ("Specific Request") buries the ask under "We ask that Circle:" with three bullets. **Compliance teams skim. The dollar figure and address count belong in a bolded callout in the first 10 lines of the body, not in §5.**
- > *"We are not alleging any wrongdoing on the part of Circle."* — This is good defensively but is currently the *last* sentence of §5, where it reads as an apology. Move to §1 (it's reassurance, not a takeaway), and add: "Circle is not a target of any present or contemplated legal action. This letter requests cooperation only."
- **No legal basis cited.** Nowhere does the letter invoke 31 CFR §1010 (BSA suspicious-activity preservation), the Stored Communications Act preservation rule (18 USC §2703(f) — the closest analog compliance teams recognize), Circle's own Acceptable Use Policy, or any state UCFA/conversion tort. A freeze letter without a hook is a wish.
- **No service-of-process info.** No statement of who is authorized to receive Circle's reply on behalf of the victim, no fax/USPS address for formal response, no "this letter is sent under penalty of perjury per 28 USC §1746" attestation.
- **No threat-actor profile.** Compliance wants to know: is this a known SIM-swap crew? A North Korea-linked address? An OFAC adjacent counterparty? Section 5 of the LE handoff has 407 "Unlabeled (under investigation)" entries — but the freeze letter doesn't surface the *one* labeled phishing address (`0x107A...4c6`) prominently as "known phishing infrastructure per Recupero's cross-case database, observed in N prior victim files." That's the credibility lever.
- "Reply expected: Acknowledgement within 24 hours; substantive response within 72 hours" is in §8 with no consequence specified. A real demand letter says: *"Failure to acknowledge within 72 hours will be documented in the federal complaint and referenced in any subsequent subpoena duces tecum."* Toothless asks get filed.

### 1.2 LE Handoff Package

The Executive Summary opens with:

> *"On 2026-01-16 21:18:47 UTC, 20,610.336829 USDT (USD 20,610.34 at the time of transaction) was removed without authorization from Alec Prostok's wallet (citizen of USA (Texas))."*

**WRONG:**
- Passive voice ("was removed without authorization") obscures the actor. An AUSA reads this and thinks "removed by what — a smart contract bug? gas?" Use: *"At 2026-01-16 21:18:47 UTC, an unauthorized third party executed transaction 0xf771...93e8 from victim wallet 0x8E3b...Bd53, draining 20,610.34 USDT to known phishing address 0x107A...4c6."*
- "(citizen of USA (Texas))" — double parens, awkward, and Texas is a state of residency, not citizenship. Should be: *"a U.S. citizen residing in Tarrant County, Texas — venue proper in N.D. Tex."*

**§9 Investigator Attestation is the single most legally significant paragraph in the package and it is wrong:**

> *"I prepared this package on behalf of {{victim.name}} from public Ethereum on-chain data fetched between {{trace_started_at or generated_at}} and {{generated_at}} UTC. The transaction hashes, addresses, timestamps, and amounts set out in this brief are accurate to the best of my knowledge and were independently verified at the time of fetch."*

**WRONG:** This is not a perjury attestation. It is not Rule 26(a)(2) compliant. It does not assert independence, methodology, qualifications, or compensation arrangement. Defense counsel would shred this on cross. The model paragraph should be:

> *"I, [Name], declare under penalty of perjury pursuant to 28 U.S.C. § 1746 that the foregoing is true and correct to the best of my knowledge. I am [title], with [N years] of digital-forensics experience and [credential]. I have no personal, financial, or familial relationship to the victim, the perpetrator, or any counterparty named herein, and Recupero LLC's compensation in this matter is not contingent on the outcome of any criminal or civil proceeding [or: is structured as disclosed in the engagement letter dated XXXX, attached as Exhibit B]. The on-chain data underlying this report was retrieved via [RPC provider] and [chain-explorer API] between [t0] and [t1] UTC; raw transaction objects, receipts, and block headers are retained on file and available for production. Executed this [day] of [month], 2026, at [city, state]."*

**Other LE handoff defects:**

- §1 narrative claims *"$62,447.55 of stolen funds is held in USDC at 4 wallets"* — but cover meta says **7 wallets** ("USDC at 4 wallets (HIGH freeze capability)" + "$660,938.20 incl. 3 wallets pending KYC verification"). Internal arithmetic the AUSA *will* check. Pick one phrasing and use it everywhere.
- §6 "Recommended Actions / Immediate" tells *the AUSA* what to do. Reasonable in tone but reads bossy without a "respectfully recommend" qualifier; more importantly, the action list does not include a single statutory cite. Every "Issue legal process" bullet should say *"via 18 USC §2703(d) order"* or *"via grand jury subpoena under FRCrP 17"* — that's the language LE actually files under.
- **No statement of independence / no-conflict.** Standard professional-report boilerplate. Absent here.
- **No chain-of-custody declaration.** §8 says raw transactions are "retained on file" but never says *who* has access, what hashing is used to attest integrity, how long they will be retained, or whether they are produced in native or PDF form. Federal Rules of Evidence 901/902(13)-(14) self-authentication is the gold standard for chain-traced data; the package should claim it.
- **No methodology section.** What hop-depth was used? What was the de-minimis filter? What sweep algorithm? An opposing expert will ask. This is a Daubert pre-requisite.
- §5 Identified Wallets: 407 rows labeled "Unlabeled (under investigation)" with "—" notes. This isn't just a labeling failure (which you flagged) — it *actively damages credibility*. The reader concludes Recupero ran a generic crawler and dumped its output. **At a minimum the table should be sorted by USD flow-through descending, and addresses with zero relevance to the trace should be cut.**

### 1.3 Engagement Letter

This one is the strongest of the lot. Some hits:

- §3 "What this engagement does NOT include" is excellent. Specifically:
  > *"Issuer cooperation is voluntary outside formal legal process. Even with a credible compliance request, an issuer may decline to act until law enforcement engages with formal subpoena or seizure order."*

  That's the kind of language that survives a TX DTPA complaint. Keep it.
- §4 fee structure ($10K engagement + 15% contingency, separated cleanly from $499 diagnostic) is clean.
- §5 termination ladder (75% refund before letters / 100% if Recupero terminates) is fair-dealing-clause-defensible.

**WRONG:**

- The closing disclaimer is buried at the bottom in `<p class="small">`:
  > *"Recupero is not a law firm and does not provide legal advice. Nothing in this engagement letter constitutes the formation of an attorney-client relationship."*

  **This belongs in §1 or as a banner above the signature block, not in 9pt gray text below the footer.** State bar UPL (unauthorized practice of law) committees go after recovery-services shops for exactly this. The disclaimer needs to be impossible to miss.
- No confidentiality clause covers *Recupero's* breach (only victim PII handling). Add a mutual NDA paragraph.
- No "no-press / no-public-statements" clause. Victims often want to tweet about their case; this exposes Recupero.
- §6 Authority & Consent grants Recupero permission to "Communicate with stablecoin issuers ... regarding this matter on your behalf" — but does not grant a **limited power of attorney** to receive responses or sign acknowledgements. Issuers will ask for one.
- No conflict-of-interest disclosure (e.g., "Recupero has not previously represented any party adverse to you in this matter and is not retained by any issuer named in §2").

### 1.4 Victim Summary (Recoverable)

Reasonable tone. But:

- Bottom-line callout opens with:
  > *"Your wallet was traced across 410 addresses on Ethereum."*

  **WRONG:** A victim reads "410 addresses" and panics — they think their *own* wallet touched 410 strangers. The sentence reads like a brag stat. Replace with: *"We identified $91,721 of your stolen money in 7 wallets that Circle and Tether can technically freeze. Here is what you do next."*
- "Bottom line" callout immediately conflates **$91,721** (recoverable) with **$660,938** (under investigation) in the same paragraph. Lay readers walk away thinking they will get $752K back. Separate visually.
- No glossary. "FREEZABLE", "INVESTIGATE", "issuance authority", "KYC" all undefined for a non-technical victim.
- No filing-helper checklist. The victim summary tells them to file with IC3 / FBI but does not provide the URL, the form name, the data they need to copy-paste, or a sample narrative. Easy win.
- §5 caveat *"perpetrators often launder a portion through paths we cannot trace"* — the word "launder" appears here without the legal weight it carries elsewhere. Use "obfuscate" or "move through mixers" in the victim doc; reserve "launder" for the LE handoff where you actually intend the statutory invocation.

---

## 2. Top 10 prioritized changes (highest leverage first)

1. **Rewrite the §9 Investigator Attestation as a 28 USC §1746 perjury declaration with no-conflict, methodology, and credential paragraphs.** Without this the LE package is not Daubert-defensible. (One paragraph fix, biggest legal upside.)
2. **Cite statutes in the freeze letter and the LE handoff.** 18 USC §§1030, 1343, 1956, 1957; state UCFA / TX Bus. & Com. Code §17.46; constructive trust under common law. "Voluntary precautionary freeze" must become "preservation demand citing [specific authority]."
3. **Move the disclaimer in the engagement letter from 9pt footer to a banner above the signature block.** Mandatory under most state UPL rules. Add the words: *"This is not a legal services agreement."*
4. **Active voice throughout.** "Funds were forwarded by the perpetrator" → "The perpetrator forwarded the funds." "Was removed without authorization" → "An unauthorized third party drained." Pass three on every passive verb.
5. **Tighten Section 5 of the LE handoff** — sort by USD flow-through, cap at top 25 plus a "full appendix on request" pointer. Current 407-row dump screams "auto-generated."
6. **Add a "Legal Basis" §3.5 (or new §6) to the freeze letter** with one paragraph per cited authority. This is what compliance teams forward to in-house counsel for approval.
7. **Reconcile the numbers across docs.** Cover meta says 4 freezable / 7 total; summary box says 7 wallets and then 4; victim summary says 410 wallets. Pick one source of truth and propagate.
8. **Add a "Demand and Deadline" closing paragraph** to the freeze letter. Acknowledgment in 72h, substantive response in 10 business days, failure documented in federal complaint. Today's letter has no teeth.
9. **Add chain-of-custody / FRE 902(13)-(14) self-authentication block** to the LE handoff §8. One paragraph claiming hashed evidence retention with timestamps. Forensic gold standard.
10. **Promote the headline figure ($62,447.55 FREEZABLE) above the fold using the `.headline-figure` block already defined in the stylesheet** — it exists at line 678 of the CSS but isn't used. Compliance reads the first 10 lines; make those count.

---

## 3. Three sample rewrites

### 3a. Freeze-letter Executive Summary (replaces current `summary-box urgent`)

> **Demand for preservation of stolen-asset proceeds — Case ALEC-TEST-2026.**
>
> Circle is hereby placed on actual notice that four USDC addresses under its burn/blacklist authority — listed at §4, totaling **$62,447.55** — hold direct proceeds of a computer-fraud and wire-fraud event committed against Alec Prostok, a U.S. citizen residing in Tarrant County, Texas, on 2026-01-16 (Tx 0xf771...93e8). Recupero LLC, retained by the victim, demands that Circle preserve those balances under (i) its published Stablecoin Policy, (ii) the constructive-trust doctrine applied to traceable stolen property under *Newby v. Enron Corp.*, 188 F. Supp. 2d 684, and (iii) Circle's BSA/AML obligations under 31 CFR §1010.320. An IC3 complaint (ref: [#]) and FBI Dallas Field Office referral are concurrently filed. **Acknowledgment is requested within 72 hours; substantive response within 10 business days.** Failure to respond will be documented in the federal complaint and referenced in any subsequent subpoena duces tecum.

### 3b. LE Handoff §9 Investigator Attestation (replaces current 2-sentence stub)

> **§9. Investigator Attestation under 28 U.S.C. § 1746.**
>
> I, [Name], declare under penalty of perjury that the foregoing is true and correct to the best of my knowledge and belief.
>
> (1) **Qualifications.** I am [title] at Recupero LLC. I hold [credentials]; I have [N] years of digital-forensics and on-chain-investigation experience. A full CV is attached as Exhibit A.
>
> (2) **Independence.** I have no personal, financial, business, or familial relationship to the victim Alec Prostok, to any wallet identified in §5, or to any issuer named in §7. Recupero LLC's compensation in this matter is structured per the engagement letter dated [date] and is not contingent on the outcome of any criminal or civil proceeding arising from this report.
>
> (3) **Methodology.** On-chain data was retrieved from the Ethereum mainnet via [provider] JSON-RPC and the Etherscan API between [t0] and [t1] UTC. Trace depth: [N] hops outbound from the victim wallet, terminating at exchange-deposit, mixer, dust-floor, or chain-bridge nodes. Historical USD values are CoinGecko closes at block-timestamp. Entity attribution draws on Recupero's internal label database (currently [N] labeled entities), Arkham public labels, and Etherscan public labels — cross-referenced and date-stamped.
>
> (4) **Chain of custody.** Raw transaction objects, receipts, and block headers are retained on Recupero LLC's evidence server under SHA-256 hash, with timestamps maintained per FRE 902(13). Native exports are available for production on receipt of a preservation letter or subpoena.
>
> Executed this 26th day of May, 2026, at [city, state].
>
> _________________________________
> [Name] · Recupero LLC

### 3c. Victim Summary Bottom-Line callout

> **What you need to know in one paragraph.** Out of the $21,318 originally stolen, we have located **$91,721** of perpetrator-controlled stablecoins that Circle and Tether — the companies that issue USDC and USDT — can technically freeze with a single internal action. Of that, **$62,447 sits in addresses we believe Circle can freeze immediately**; the remaining $29,274 is in addresses Tether can act on. We have also identified $660,938 in additional Circle-issued balances that may belong to the perpetrator — Circle has to check their customer records to confirm. Your next steps are on page 4 ("Your Options"); the first one — filing an IC3 complaint at *complaintdesk.ic3.gov* — takes 20 minutes and meaningfully raises the chance that Circle and Tether will act on our freeze letters.

---

*End of review. The freeze letters are the highest-priority rewrite — they are the only document a stranger ever reads.*
