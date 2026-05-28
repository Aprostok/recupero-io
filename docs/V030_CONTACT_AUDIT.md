# V0.30 Contact Audit — Issuer & Law-Enforcement Channels

**Audited:** 2026-05-26. **Scope:** every issuer address in `src/recupero/labels/seeds/issuers.json`, every LE contact in `src/recupero/worker/_le_routing.py`, plus `MIDAS_ISSUER` in `src/recupero/reports/brief.py`. Sources are WebSearch results against the publishing org's own domain unless noted; `WebFetch` was permission-blocked, so deep page text was not directly retrieved for circle.com / tether.to / paxos.com — those addresses are corroborated via search snippets and adjacent published material.

---

## VERIFIED

- **`https://www.ic3.gov`** — IC3 is live, FBI-run, accepts crypto complaints; `complaint.ic3.gov` is the active intake. (ic3.gov, fbi.gov, 2026)
- **`subpoenas@paxos.com`** — Paxos's own terms page directs LE to this address. (paxos.com /terms-and-conditions/illegal-activity, 2026)
- **`subpoenas@coinbase.com`** — Coinbase help center "Who do I contact for a subpoena" lists this for LE; Kodex portal `https://app.kodexglobal.com/gov/signup` is the structured channel. (help.coinbase.com, 2026)
- **`https://www.secretservice.gov/investigations/cyber`** and **`/contact/ectf-fctf`** — live; ECTF/FCTF have merged into Cyber Fraud Task Forces (CFTF), 42 domestic offices. (secretservice.gov, 2026)
- **`https://oag.ca.gov/ecrime`** + **`/report-crime`** + **`/cybercrime`** — all live; California eCrime Unit + Cybercrime Section both active. (oag.ca.gov, 2026)
- **NY AG cryptocurrency intake** — `investor.complaints@ag.ny.gov` and 1-800-771-7755 confirmed on ag.ny.gov 2026 press releases (Coinbase/Gemini suit, $5M Uphold settlement).
- **TX AG consumer complaint portal** — `https://consumerprotection.texasattorneygeneral.gov/consumercomplaintportal/s/` is the actual submit URL (the codebase points only at the landing page).
- **FL AG Cyber Fraud Enforcement Unit** — `https://www.myfloridalegal.com/node/26642` + hotline `1-866-9-NO-SCAM`; the codebase URL `/consumer-protection` is reachable but the CFEU page is the correct intake.
- **`wbtc@bitgo.com`** — published as the WBTC-specific contact on bitgo.com.

## STALE / UNVERIFIED

- **`compliance@circle.com`** — could NOT be located on circle.com via search; Circle's current LE page redirects through generic support / Privacy Policy. **High confidence the right address is `lawenforcement@circle.com`** (industry-standard for Circle per SEARCH.org ISP guides; the codebase's own `validators/output_integrity.py:518` already distinguishes "compliance@coinbase.com vs law-enforcement@coinbase.com" suggesting awareness of this split). Treat `compliance@circle.com` as unverified.
- **`compliance@tether.to`** — Tether's LE page (`tether.to/en/legal/?tab=law-enforcement-requests`) describes a "Tether Information requests team" but does NOT publish an open email; Tether's actual intake is via a webform/CS portal (`cs.tether.to`). `compliance@tether.to` may be a deliverable mailbox but is not the published channel.
- **`compliance@paxos.com`** — `subpoenas@paxos.com` is the published address (see VERIFIED). `compliance@paxos.com` is likely deliverable internally but NOT the documented LE channel — see WRONG CHANNEL.
- **`law-enforcement@coinbase.com`** — Coinbase publishes `subpoenas@coinbase.com`, not this. The hyphenated form is plausibly aliased but not published.
- **`security@makerdao.com`** — only public reference found is `press@makerdao.com`; given the Maker→Sky rebrand, `security@makerdao.com` is questionable. The `forum.sky.money` secondary is live.
- **`compliance@maple.finance`** / `support@maple.finance` — no public page on maple.finance documents either address; both are plausible but unverified.
- **`team@frax.finance`** — Frax's published email format is `{first_initial}{last}@frax.finance`; `team@` is unconfirmed. Plus FRAX/FXS contracts have NO blacklist/pause — see WRONG CHANNEL note below.
- **`compliance@midas.app`** / `team@midas.app` — no Midas public page surfaces either. Plausible (Zigha case used `team@midas.app`) but not independently verifiable from outside.
- **`compliance@bitgo.com`** — bitgo.com surfaces `wbtc@bitgo.com` and `privacy@bitgo.com`; generic `compliance@` is not on the legal-regulatory page returned.
- **`compliance@trueusd.com`** — TUSD/Techteryx is currently mired in a Dubai DIFC $456M reserve freeze (Oct 2025 → ongoing 2026). Their compliance posture is unstable; whatever inbox exists may not be responsive.
- **`compliance@firstdigitalgroup.com`** — First Digital's domain on their LE/contact pages is `1stdigital.com`, NOT `firstdigitalgroup.com`. **This is almost certainly a wrong/dead domain.** See WRONG CHANNEL.
- **`compliance@trondao.org`** — TRON DAO Reserve published `service@tron.network` (general) and `press@tron.network`; `compliance@trondao.org` is not published anywhere indexed. TRON DAO governance has additionally been documented as effectively defunct.

## WRONG CHANNEL

- **Paxos**: codebase uses `compliance@paxos.com` in 5 token entries (BUSD-eth, PYUSD, USDP, BUSD-bsc, USDP-eth) — should be `subpoenas@paxos.com` for LE-backed freeze requests.
- **Coinbase / cbBTC**: `law-enforcement@coinbase.com` should be `subpoenas@coinbase.com` (or routed through Kodex portal).
- **First Digital / FDUSD**: `compliance@firstdigitalgroup.com` — domain mismatch with `1stdigital.com`. Likely undeliverable; the correct domain needs to be confirmed via 1stdigital.com directly.
- **Frax**: `freeze_capability: "limited"` is misleading — FRAX/FXS contracts have NO blacklist or pause primitives per Frax's own docs. The contact may resolve but the freeze ask is impossible at the contract level; reframe as "governance-only, no contract freeze."
- **FBI VAU `cryptocurrency@fbi.gov`**: not corroborated in 2026 search results; FBI's published channel for crypto crime is IC3, and the VAU itself is internal. If this address exists as a back-channel, it's not publicly verifiable — treat as aspirational pending direct FBI VAU confirmation.

## MISSING

- **State AGs**: codebase covers CA / NY / TX / FL / MA / IL. Missing high-volume states: **WA, GA, AZ, NJ, PA, OH, NC, VA, CO** (all top-15 by crypto-fraud complaint volume per IC3 2024 report).
- **Federal channels not represented**: **DOJ NCET** (National Cryptocurrency Enforcement Team — `https://www.justice.gov/criminal/national-cryptocurrency-enforcement-team`); **FinCEN SAR referral channel**; **CFTF/FCTF** (Secret Service merged-task-force intake, distinct from ECTF page already linked).
- **Issuer rows without contacts**: every Aave aToken row, rETH, stETH, tBTC, WETH have `primary_contact: null`. This is correct for permissionless tokens, but the brief generator should explicitly suppress "send freeze letter" UI for these rather than leaving operators wondering.
- **No Sky/MakerDAO LE channel** (only `security@makerdao.com` for vuln disclosure + the Sky forum). Sky has no contract-level freeze for DAI, but for governance courtesy notification a `lawenforcement@sky.money` style address — if it exists — should be sourced.
- **Tether LE intake URL**: codebase points at `tether.to/en/contact-law-enforcement`; the actually-published page is `tether.to/en/legal/?tab=law-enforcement-requests`. Update the URL.
- **No Bitstamp / Gemini / Crypto.com / Kraken issuer rows** for the stablecoins they custody on behalf of partners (e.g., Gemini Dollar GUSD).
- **`secondary_contact` for Tron USDD**: missing. TRON DAO governance forum or `service@tron.network` should be added.

## DO-NOT-CONTACT

- **No personal/named-individual emails were found in the audited surface.** All addresses are role-based (`compliance@`, `subpoenas@`, `team@`, `lawenforcement@`, `support@`, `security@`, `press@`) — good. **Do NOT add named-individual emails** (e.g., a specific Circle compliance officer's address) sourced from LinkedIn / leaked directories — they're operationally fragile, rotate when staff leave, and risk privacy claims under GDPR / CCPA.
- **Avoid the ContactOut-style guesses** for Frax (`{first_initial}{last}@frax.finance`) surfaced in search; these are scraped, not published.

---

## Recommended 1-hour operator update

1. `issuers.json` line 51, 61, 273, 357: `compliance@paxos.com` → `subpoenas@paxos.com`.
2. `issuers.json` line 102: `law-enforcement@coinbase.com` → `subpoenas@coinbase.com`.
3. `issuers.json` lines 29, 122, 134, 314, 346, 390 (all Circle): verify with circle.com directly; if their LE page lists a distinct `lawenforcement@circle.com`, switch.
4. `issuers.json` line 293: confirm `firstdigitalgroup.com` vs `1stdigital.com` — the latter is the live corporate domain.
5. `issuers.json` line 41: update Tether LE URL to `https://tether.to/en/legal/?tab=law-enforcement-requests`.
6. `issuers.json` line 184: rewrite FRAX `freeze_notes` to "no contract freeze; governance-only, courtesy notification."
7. `_le_routing.py` FBI_VAU: confirm `cryptocurrency@fbi.gov` is real or replace with IC3-only routing + a note that VAU engagement happens via the FBI field office after IC3 filing.
8. Add DOJ NCET as a federal escalation route for >$1M cases.

Each change requires a one-line confirmation source from the issuer's own published page. Budget ~5 min per address; total ~1 hour.
