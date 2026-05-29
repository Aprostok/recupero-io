"""Law-enforcement filing-route recommendations.

The LE handoff is professionally formatted but a victim or their
attorney still has to decide WHICH agency to file with. This module
generates a recommended-routes section based on:

  * Victim's country (US-specific vs international fallback)
  * Victim's US state (if known) — drives state-AG / state-cyber-unit
    contact lookup
  * Loss amount — drives escalation thresholds (state-level vs IC3
    vs FBI field office vs Secret Service)

The output is a structured ``LERoutingPlan`` that the LE-handoff
template renders into a "Suggested Filing Routes" section. The plan
is always populated — at minimum every US case gets IC3, every
non-US case gets the generic "consult an attorney in your
jurisdiction" fallback. State-specific data is filled in
opportunistically.

Operator note
-------------

The state-specific contacts in ``_STATE_LE_CONTACTS`` are starting
data for the most-populous US states; extend the table as new
states come up in real cases. The federal entries (IC3, FBI VAU,
Secret Service ECTF) are canonical and won't change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal


@dataclass(frozen=True)
class LEContact:
    """One law-enforcement filing channel."""
    name: str                       # Display name ("IC3", "FBI Cybercrime Division")
    jurisdiction: str               # "Federal (US)", "California", "United Kingdom"
    url: str | None = None
    phone: str | None = None
    email: str | None = None
    description: str | None = None  # Why file here / what they do
    expected_response: str | None = None  # "30-90 days", "48 hours acknowledgement"


@dataclass(frozen=True)
class LERoutingPlan:
    """Structured recommendation for which law-enforcement channels
    a victim (or their attorney) should file with."""
    # Always-applicable federal-level filings (e.g., IC3 for US victims)
    primary_routes: list[LEContact] = field(default_factory=list)
    # State-level filings when state is known
    state_routes: list[LEContact] = field(default_factory=list)
    # Loss-tier escalations (FBI field office, Secret Service for $1M+, etc.)
    escalation_routes: list[LEContact] = field(default_factory=list)
    # Free-form notes the template surfaces (e.g., "your loss size
    # qualifies for FBI VAU direct contact")
    notes: list[str] = field(default_factory=list)


# ----- Federal (always applies for US victims) ----- #

IC3 = LEContact(
    name="IC3 — FBI Internet Crime Complaint Center",
    jurisdiction="Federal (US)",
    url="https://www.ic3.gov",
    description=(
        "The canonical federal filing channel for cryptocurrency theft. "
        "Free, takes 20-40 minutes to file online. Generates a complaint "
        "number that's referenceable in compliance freeze requests, "
        "insurance claims, and tax-loss deductions. Even when no other "
        "filing is pursued, IC3 should always be filed."
    ),
    expected_response=(
        "Acknowledgement immediately; substantive investigation only "
        "if the case is grouped with others matching the same "
        "perpetrator pattern. IC3 feeds the FBI's larger pattern-tracking."
    ),
)

# v0.30.1 (go-live preflight item #5 — contact audit V030_CONTACT_AUDIT.md):
# `cryptocurrency@fbi.gov` could not be corroborated against any 2026 FBI/IC3
# published source. The VAU is an internal FBI unit; the publicly-documented
# intake channel for crypto cases is IC3. We retain the FBI_VAU contact card
# as guidance for the >$100K escalation path (operators historically use it),
# but mark the email as unverified and route operators to the IC3 +
# field-office combo as the published channel. Treat as a SOFTER, NOT
# OFFICIAL handoff — never claim this is the official VAU email in client
# correspondence.
FBI_VAU = LEContact(
    name="FBI Virtual Assets Unit (VAU) — informal escalation",
    jurisdiction="Federal (US)",
    email="cryptocurrency@fbi.gov",
    description=(
        "Informal escalation path for high-value cases (>$100K). The "
        "officially-published FBI cryptocurrency intake channel is IC3 "
        "(complaint.ic3.gov), and the VAU is an internal FBI unit "
        "rather than a public intake; "
        "`cryptocurrency@fbi.gov` is commonly cited by industry but "
        "we have NOT independently verified it via an FBI publication "
        "in 2026. Use this contact only AFTER an IC3 filing exists, "
        "and pair it with engaging the FBI field office geographically "
        "closest to the victim or to the perpetrator's identified "
        "service providers. If the address bounces, do not retry — "
        "fall back to field-office direct contact."
    ),
    expected_response=(
        "Unspecified. IC3 acknowledgement is immediate; VAU follow-up "
        "is best-effort and dependent on whether the case clusters "
        "with active investigations."
    ),
)

SECRET_SERVICE_ECTF = LEContact(
    name="Secret Service — Electronic Crimes Task Force",
    jurisdiction="Federal (US)",
    url="https://www.secretservice.gov/investigation",
    description=(
        "For cases involving high-value financial crime or where the "
        "perpetrator is linked to a structured fraud operation (not a "
        "one-off scam). Each major US city has a local ECTF office — "
        "see secretservice.gov for the office covering your area."
    ),
    expected_response=(
        "Variable. Typically engages when the loss is part of a larger "
        "pattern they're already tracking."
    ),
)


# ----- State-specific contacts (extend as new cases come in) ----- #

_STATE_LE_CONTACTS: dict[str, list[LEContact]] = {
    # California — high crypto-fraud frequency
    "CA": [
        LEContact(
            name="California Attorney General — eCrime Unit",
            jurisdiction="California",
            url="https://oag.ca.gov/ecrime",
            description=(
                "The California AG's eCrime Unit prosecutes cybercrime "
                "including cryptocurrency theft. Submit the LE handoff "
                "via their online complaint portal."
            ),
        ),
        LEContact(
            name="California Department of Financial Protection (DFPI)",
            jurisdiction="California",
            url="https://dfpi.ca.gov/file-a-complaint/",
            description=(
                "DFPI tracks cryptocurrency scams under the state's "
                "Consumer Financial Protection Law. Filing here can "
                "trigger consumer-protection enforcement separate from "
                "criminal pursuit."
            ),
        ),
    ],
    # New York — second-highest crypto-fraud frequency
    "NY": [
        LEContact(
            name="New York Attorney General — Bureau of Internet & Technology",
            jurisdiction="New York",
            url="https://ag.ny.gov/internet-and-technology",
            description=(
                "NYAG's BIT actively investigates cryptocurrency fraud. "
                "BitLicense-holding exchanges (Coinbase, Gemini) are "
                "regulated through this office, which makes NY filings "
                "particularly effective when the perpetrator routed "
                "funds through those exchanges."
            ),
        ),
    ],
    # Texas
    "TX": [
        LEContact(
            name="Texas Attorney General — Consumer Protection Division",
            jurisdiction="Texas",
            url="https://www.texasattorneygeneral.gov/consumer-protection",
            description=(
                "Texas AG's Consumer Protection Division accepts crypto "
                "fraud complaints and has a dedicated cybercrime unit."
            ),
        ),
        LEContact(
            name="Texas State Securities Board",
            jurisdiction="Texas",
            url="https://www.ssb.texas.gov/",
            description=(
                "If the case involves any investment-fraud element "
                "(unauthorized trading, fake investment promises), the "
                "Texas SSB has crypto-specific enforcement authority."
            ),
        ),
    ],
    # Florida
    "FL": [
        LEContact(
            name="Florida Attorney General — Cybercrime",
            jurisdiction="Florida",
            url="https://www.myfloridalegal.com/consumer-protection",
            description=(
                "Florida AG's cybercrime unit accepts cryptocurrency "
                "theft complaints. The state also has FDLE (Florida "
                "Department of Law Enforcement) for cases involving "
                "in-state perpetrators."
            ),
        ),
    ],
    # Massachusetts
    "MA": [
        LEContact(
            name="Massachusetts Attorney General — Cyber, Tech, and Privacy",
            jurisdiction="Massachusetts",
            url="https://www.mass.gov/ago",
            description=(
                "Massachusetts has been an early enforcer on crypto-fraud "
                "matters. The AG's office actively pursues these cases."
            ),
        ),
    ],
    # Illinois
    "IL": [
        LEContact(
            name="Illinois Attorney General — Consumer Fraud",
            jurisdiction="Illinois",
            url="https://www.illinoisattorneygeneral.gov/consumers/file-a-complaint/",
            description=(
                "Illinois AG accepts cybercrime / crypto-fraud "
                "complaints. The state's Secretary of State office "
                "also handles investment-fraud matters via the "
                "Securities Department."
            ),
        ),
    ],
}


# Mapping of state names → ISO codes for normalization. Limited to
# the states with explicit entries above; unknown states fall through
# to the generic state-AG fallback.
_STATE_NAME_TO_CODE: dict[str, str] = {
    "california": "CA",
    "new york": "NY",
    "texas": "TX",
    "florida": "FL",
    "massachusetts": "MA",
    "illinois": "IL",
}


# Generic fallback for any US state without explicit data
GENERIC_STATE_AG = LEContact(
    name="Your State Attorney General — Consumer Protection / Cyber Unit",
    jurisdiction="State (US)",
    description=(
        "Most US state AG offices have a consumer-protection unit that "
        "accepts cybercrime complaints, and many now have dedicated "
        "crypto-fraud contacts. Search '<your state> attorney general "
        "cybercrime' or '<your state> AG consumer protection crypto'. "
        "Filing at the state level in addition to IC3 establishes a "
        "local record and can engage state-prosecutorial resources "
        "the FBI doesn't have."
    ),
)

# Non-US generic fallback
INTERNATIONAL_FALLBACK = LEContact(
    name="National cybercrime / financial-crime authority",
    jurisdiction="Non-US (consult attorney)",
    description=(
        "Cryptocurrency-fraud filing channels vary substantially by "
        "country. UK: Action Fraud (actionfraud.police.uk). Canada: "
        "CAFC (antifraudcentre.ca). Australia: ReportCyber "
        "(cyber.gov.au). EU: national CSIRT + local police. We "
        "strongly recommend consulting an attorney in your "
        "jurisdiction before filing — they can advise on which "
        "channel(s) maximize enforcement-action probability for your "
        "specific country."
    ),
)


# ----- Loss-tier thresholds ----- #

_FBI_VAU_THRESHOLD_USD = Decimal("100000")    # >= $100k loss → recommend FBI VAU direct
_SECRET_SERVICE_THRESHOLD_USD = Decimal("1000000")  # >= $1M → add Secret Service ECTF


def _parse_citizenship_country_state(
    raw: str | None,
) -> tuple[str | None, str | None]:
    """Parse a free-form citizenship/country string into (country, state).

    Intake captures `citizenship` as a single free-form field like:
      "USA (Texas)"          → ("USA", "Texas")
      "United States (CA)"   → ("United States", "CA")
      "Germany"              → ("Germany", None)
      "USA"                  → ("USA", None)

    Pre-v0.30.0 the LE-routing logic compared `citizenship` directly
    against a fixed set of US synonyms — so "USA (Texas)" was
    classified as non-US and a US victim got the international-fallback
    routing with an empty contact column. This helper closes the gap.
    """
    if not isinstance(raw, str):
        return (None, None)
    text = raw.strip()
    if not text:
        return (None, None)
    # Pull a parenthesized suffix as state.
    state: str | None = None
    if "(" in text and text.endswith(")"):
        head, _, tail = text.rpartition("(")
        candidate_state = tail[:-1].strip()
        head = head.strip()
        if candidate_state and head:
            text = head
            state = candidate_state
    return (text, state)


def recommend_le_routes(
    *,
    state: str | None,
    country: str | None,
    total_loss_usd: Decimal | None,
) -> LERoutingPlan:
    """Build a structured LE-routing recommendation for the LE handoff
    template's "Suggested Filing Routes" section.

    All inputs are optional — the function returns a sensible plan
    even with no victim location data + no loss amount.

    v0.30.0 (F3/F4 — brief read-through): country is now parsed via
    `_parse_citizenship_country_state` so a victim record with
    `citizenship="USA (Texas)"` and `country=None`, `state=None`
    correctly resolves to US + Texas — pre-v0.30.0 the literal-string
    compare misclassified US victims as international and emitted an
    empty-contact-column INTERNATIONAL_FALLBACK route.
    """
    plan = LERoutingPlan()

    parsed_country, parsed_state = _parse_citizenship_country_state(country)
    effective_country = parsed_country or country
    # `state` arg always wins over a parenthesized state extracted from
    # the country string — operator-set fields are more authoritative
    # than parsed free-form input.
    if not state and parsed_state:
        state = parsed_state

    # Country normalization. Default to US (most cases). Anything that
    # doesn't look like the US gets the international fallback.
    country_norm = (effective_country or "US").strip().upper()
    is_us = country_norm in (
        "US", "USA", "U.S.", "U.S.A.",
        "UNITED STATES", "UNITED STATES OF AMERICA", "AMERICA",
    )

    if not is_us:
        plan.primary_routes.append(INTERNATIONAL_FALLBACK)
        # v0.30.1 (round-N T1-D): pre-v0.30.1 the note formatted with
        # the RAW `country` arg, which could be None, "Germany (Berlin)"
        # (re-rendering the parenthesized state inside the note), or
        # other unparsed shapes. Use the parsed country with a graceful
        # "(unspecified)" fallback so the rendered note never says
        # "outside the US (None)" or doubles up the parens.
        # v0.32.1 (LE-HIGH-5): drop unconfirmed-placeholder citizenship so
        # a victim record with an unresolved location never typesets a raw
        # work-marker sentinel into the law-enforcement handoff. Reuse the
        # canonical brief sanitizer (single source of truth for the
        # placeholder patterns) rather than re-listing them here. An
        # unresolved placeholder renders as "(unspecified)" like a blank.
        from recupero.reports.brief import _sanitize_placeholder
        _cand = _sanitize_placeholder((parsed_country or country or "").strip()) or ""
        display_country = _cand or "(unspecified)"
        plan.notes.append(
            f"Victim located outside the US ({display_country}). Filing "
            "channels are country-specific; this report's generic "
            "guidance is a starting point only."
        )
        return plan

    # US baseline: always IC3
    plan.primary_routes.append(IC3)

    # State-specific recommendations
    state_code = _normalize_state(state) if state else None
    if state_code and state_code in _STATE_LE_CONTACTS:
        plan.state_routes.extend(_STATE_LE_CONTACTS[state_code])
    elif state:
        # State provided but no explicit data — use generic fallback
        plan.state_routes.append(GENERIC_STATE_AG)
        plan.notes.append(
            f"State '{state}' does not have specific contact data in "
            "our routing table. Generic state-AG guidance provided; "
            "consult your state's AG website for the specific "
            "cybercrime / consumer-protection unit."
        )
    else:
        # No state at all — encourage the operator to follow up
        plan.notes.append(
            "Victim's US state is not on file. Strongly recommend "
            "adding state-level filing to the package — most US states "
            "have a consumer-protection or cybercrime unit that "
            "supplements IC3."
        )

    # v0.30.3 (V030_2_CORRECTNESS_AUDIT T1-C): NaN/Inf guard.
    # `Decimal('NaN') >= 1000000` returns False per IEEE 754, so a
    # NaN total_loss_usd silently SKIPS both FBI VAU and Secret Service
    # ECTF escalation on a high-value case. Symmetrically,
    # `Decimal('Infinity') >= 1000000` returns True and the f-string
    # then renders 'Loss of $Infinity' into the LE handoff note. Both
    # paths leak forensic garbage; the only safe behavior is to refuse
    # to escalate on non-finite loss and leave a diagnostic breadcrumb
    # in the routing notes so an operator sees why.
    if total_loss_usd is not None and not total_loss_usd.is_finite():
        plan.notes.append(
            "Loss-tier escalation skipped: total_loss_usd is non-finite "
            "(NaN/Inf), likely a pricing-cache poison or a hand-edited "
            "case file. Investigator should manually decide whether the "
            "case warrants FBI VAU / Secret Service ECTF engagement and "
            "verify the underlying USD math before transmitting this "
            "handoff package."
        )
        return plan

    # Loss-tier escalations
    if total_loss_usd is not None:
        if total_loss_usd >= _FBI_VAU_THRESHOLD_USD:
            plan.escalation_routes.append(FBI_VAU)
            plan.notes.append(
                f"Loss of ${total_loss_usd:,.2f} qualifies for FBI VAU "
                f"direct contact (threshold: ${_FBI_VAU_THRESHOLD_USD:,.0f}). "
                "Recommend forwarding the LE handoff package directly "
                "to cryptocurrency@fbi.gov in parallel with IC3."
            )
        if total_loss_usd >= _SECRET_SERVICE_THRESHOLD_USD:
            plan.escalation_routes.append(SECRET_SERVICE_ECTF)
            plan.notes.append(
                f"Loss of ${total_loss_usd:,.2f} also qualifies for "
                "Secret Service ECTF engagement. High-value financial "
                "crime is squarely within their remit; recommend "
                "contacting the local field office in parallel with "
                "FBI VAU."
            )

    return plan


def _normalize_state(state: str) -> str:
    """Normalize a state input to two-letter postal code. Accepts
    either the postal code ("CA", "ca") or the full name
    ("California", "california"). Returns the original input
    uppercased if no normalization applies."""
    s = state.strip().lower()
    if s in _STATE_NAME_TO_CODE:
        return _STATE_NAME_TO_CODE[s]
    if len(s) == 2 and s.upper() in _STATE_LE_CONTACTS:
        return s.upper()
    return state.strip().upper()


__all__ = (
    "LEContact",
    "LERoutingPlan",
    "recommend_le_routes",
)
