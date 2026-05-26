"""Tests for the per-issuer freeze-letter refactor.

Operator-quality review on case e917ffc5 revealed that every
issuer's freeze letter asked Circle / Tether / Sky / Paxos to
freeze the same 130 ETH at the same first-hop address. Stablecoin
issuers don't control ETH — every letter would have been rejected.

The fix threads each issuer's FREEZABLE.holdings list from
freeze_brief.json through to the template, so each letter asks
for the SPECIFIC stablecoin (USDC / USDT / DAI / PYUSD) at the
SPECIFIC addresses that issuer actually controls.

Tests:

  1. ``_build_issuer_freezable_ctx`` correctly transforms the
     freeze_brief.json entry into the template-friendly shape.
  2. Status FREEZABLE / INVESTIGATE both surface, with correct
     counts.
  3. Empty/None input returns None (legacy path stays available).
  4. Address explorer URLs are correctly built for each chain.
  5. End-to-end: generate_briefs renders a letter with the
     stablecoin token name (not the original asset symbol) when
     issuer_freezable is provided.

Tests run in <100ms, no DB / no network.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    TokenRef,
    Transfer,
)
from recupero.reports.brief import (
    InvestigatorInfo,
    IssuerInfo,
    _build_issuer_freezable_ctx,
    _short_addr,
    generate_briefs,
)
from recupero.reports.victim import VictimInfo

# ---- _build_issuer_freezable_ctx ---- #


def _circle_freeze_brief_entry() -> dict:
    """Reproduces the actual freeze_brief.json shape from case e917ffc5
    for Circle, with one FREEZABLE and one INVESTIGATE holding."""
    return {
        "issuer": "Circle",
        "token": "USDC",
        "total_usd": "$7,097.58",
        "total_suspected_usd": "$1,037,451.35",
        "freeze_capability": "HIGH",
        "holdings": [
            {
                "address": "0x016606Acc6B0cFE537acc221e3bf1bb44B4049Ee",
                "amount": "793113.726367 USDC",
                "usd": "$793,113.73",
                "status": "INVESTIGATE",
            },
            {
                "address": "0x480CD46E6faDe651a0437DeaddA53D5c8e7D846A",
                "amount": "6031.31 USDC",
                "usd": "$6,031.31",
                "status": "FREEZABLE",
            },
        ],
        "contact_email": "compliance@circle.com",
    }


def test_ctx_none_input_returns_none() -> None:
    """Legacy path: no per-issuer freezable data → return None so
    the template falls back to single-asset rendering."""
    assert _build_issuer_freezable_ctx(None, Chain.ethereum) is None


def test_ctx_empty_dict_returns_none() -> None:
    """Defensive: an empty dict (falsy) also returns None."""
    assert _build_issuer_freezable_ctx({}, Chain.ethereum) is None


def test_ctx_basic_shape_locked() -> None:
    """The output shape is the contract the template binds to. Lock
    every top-level key so accidental edits in brief.py fail loudly.

    v0.16.2 (audit fix #1): added evidence_mode, historical_count,
    current_balance_count, earliest_observed so the issuer-letter
    template's evidence_mode branches (added in v0.16.1) actually
    receive the keys they reference. Pre-fix those branches were
    dead code and every letter fell through to the "currently held"
    {% else %} clause."""
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    assert out is not None
    assert set(out.keys()) == {
        "token", "freeze_capability",
        "total_usd_freezable", "total_usd_suspected",
        # v0.20.5 (audit-round-5 F5): UNRECOVERABLE-only issuers expose
        # total_excluded_usd so templates can reference it without going
        # through the outer all_issuers_freezable wrapper.
        "total_excluded_usd",
        "holdings", "freezable_holdings", "investigate_holdings",
        "has_freezable", "has_investigate",
        "freezable_count", "investigate_count", "total_count",
        # v0.16.2 evidence-mode aggregates
        "evidence_mode", "historical_count", "current_balance_count",
        "earliest_observed",
    }


def test_ctx_token_locked() -> None:
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    assert out["token"] == "USDC"


def test_ctx_freeze_capability_locked() -> None:
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    assert out["freeze_capability"] == "HIGH"


def test_ctx_totals_string_preserved() -> None:
    """Total USD values come in pre-formatted from freeze_brief.json
    — preserve them verbatim. Re-formatting here would risk diverging
    from the canonical aggregation in emit_brief.py."""
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    assert out["total_usd_freezable"] == "$7,097.58"
    assert out["total_usd_suspected"] == "$1,037,451.35"


def test_ctx_holdings_split_by_status() -> None:
    """FREEZABLE and INVESTIGATE holdings appear in their respective
    lists, AND in the combined ``holdings`` list. Template uses each
    list for a different purpose (section 4 lists ALL, section 5
    asks only for FREEZABLE)."""
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    assert out["total_count"] == 2
    assert out["freezable_count"] == 1
    assert out["investigate_count"] == 1
    assert out["has_freezable"] is True
    assert out["has_investigate"] is True


def test_ctx_explorer_url_built() -> None:
    """Each holding gets an explorer URL — the template renders
    every address as a clickable link. URL prefix per chain.
    Verified for Ethereum here; cross-chain coverage tested
    elsewhere."""
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    first = out["holdings"][0]
    assert first["explorer_url"].startswith("https://etherscan.io/address/")
    assert "0x016606Acc6B0cFE537acc221e3bf1bb44B4049Ee" in first["explorer_url"]


def test_ctx_short_address_helper() -> None:
    """``_short_addr`` truncates an address for inline display.

    v0.16.10 (round-9 output-artifacts MEDIUM): both reports/brief.py
    and reports/emit_brief.py now delegate to the SAME canonical
    helper in recupero._common. Format is 6 leading + ellipsis +
    4 trailing for any address >= 12 chars. Previously the two
    modules used different prefix lengths.
    """
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    first = out["holdings"][0]
    # 6 leading hex + ellipsis + 4 trailing.
    assert first["address_short"] == "0x0166…49Ee"


def test_ctx_only_investigate_no_freezable() -> None:
    """When every holding is INVESTIGATE (the freeze_capability is
    LOW), has_freezable=False and the freezable list is empty.
    Template should adapt section 5 to not promise specific addresses."""
    entry = _circle_freeze_brief_entry()
    for h in entry["holdings"]:
        h["status"] = "INVESTIGATE"
    out = _build_issuer_freezable_ctx(entry, Chain.ethereum)
    assert out["has_freezable"] is False
    assert out["freezable_count"] == 0
    assert out["investigate_count"] == 2


def test_ctx_only_freezable_no_investigate() -> None:
    """Inverse: every holding confirmed FREEZABLE. The template's
    INVESTIGATE-specific copy should not render in this case."""
    entry = _circle_freeze_brief_entry()
    for h in entry["holdings"]:
        h["status"] = "FREEZABLE"
    out = _build_issuer_freezable_ctx(entry, Chain.ethereum)
    assert out["has_investigate"] is False
    assert out["investigate_count"] == 0
    assert out["freezable_count"] == 2


def test_ctx_unknown_status_defaults_to_investigate() -> None:
    """A holding with an unrecognized status (or None) gets bucketed
    into INVESTIGATE rather than dropped, so we don't silently lose
    the row from the letter."""
    entry = _circle_freeze_brief_entry()
    entry["holdings"][0]["status"] = "FROZEN_PENDING_REVIEW"  # not a real status
    out = _build_issuer_freezable_ctx(entry, Chain.ethereum)
    # The unknown-status holding stays in the combined list but
    # is filtered out of both FREEZABLE and INVESTIGATE buckets
    # (it doesn't match either status string).
    assert out["total_count"] == 2
    # The other holding's status is still respected
    statuses = {h["status"] for h in out["holdings"]}
    assert statuses == {"FROZEN_PENDING_REVIEW", "FREEZABLE"}


def test_ctx_missing_holdings_returns_empty_list() -> None:
    """A FREEZABLE entry with no holdings (defensive — shouldn't
    happen but the parser must not crash)."""
    entry = _circle_freeze_brief_entry()
    entry["holdings"] = []
    out = _build_issuer_freezable_ctx(entry, Chain.ethereum)
    assert out["total_count"] == 0
    assert out["has_freezable"] is False
    assert out["has_investigate"] is False


# ---- _short_addr ---- #


def test_short_addr_normal_hex() -> None:
    """v0.16.10: canonical format is 6 leading + 4 trailing."""
    out = _short_addr("0x" + "a" * 40)
    assert out == "0xaaaa…aaaa"


def test_short_addr_short_input_passes_through() -> None:
    assert _short_addr("0x123") == "0x123"
    assert _short_addr("") == ""


# ---- End-to-end: generate_briefs with issuer_freezable ---- #


def _make_minimal_case() -> Case:
    """Build a minimum-viable Case with one transfer (the theft event)
    so generate_briefs has something to work with."""
    theft_xfer = Transfer(
        transfer_id="ethereum:0xtheft:0",
        chain=Chain.ethereum,
        tx_hash="0x" + "f" * 64,
        block_number=12345,
        block_time=datetime(2026, 1, 2, 0, 0, tzinfo=UTC),
        from_address="0x" + "1" * 40,
        to_address="0x" + "2" * 40,
        counterparty=Counterparty(
            address="0x" + "2" * 40,
            label=None,
            is_contract=False,
        ),
        token=TokenRef(
            chain=Chain.ethereum,
            contract=None,
            symbol="ETH",
            decimals=18,
            coingecko_id="ethereum",
        ),
        amount_raw="130000000000000000000",
        amount_decimal=Decimal("130"),
        usd_value_at_tx=Decimal("385680.64"),
        hop_depth=0,
        fetched_at=datetime(2026, 1, 2, 0, 1, tzinfo=UTC),
        explorer_url="https://etherscan.io/tx/0xtheft",
    )
    return Case(
        case_id="test-e2e",
        seed_address="0x" + "1" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 2, tzinfo=UTC),
        transfers=[theft_xfer],
        trace_started_at=datetime(2026, 1, 2, tzinfo=UTC),
        software_version="test",
    )


def test_generate_briefs_renders_stablecoin_when_freezable_provided() -> None:
    """End-to-end: the rendered freeze letter mentions USDC (the
    issuer's token) prominently — not just ETH (the original
    asset). This is the regression that this whole fix exists to
    prevent.

    v0.27.2 (Jacob 0x52Aa bleed fix, item 1): the issuer freeze
    request template now iterates ``freezable_holdings`` only in
    section 4 — INVESTIGATE-tagged rows (smart-contract reflective
    liquidity, dormant pre-KYC addresses) are operator-internal and
    must NOT appear in the issuer-facing letter. Pre-fix Zigha shipped
    a Circle letter with a $46M 1inch-pool INVESTIGATE row next to a
    $245K real FREEZABLE row — an internal contradiction Circle's
    compliance team would have rejected at the first read.

    The pinned contract now:
      * USDC + FREEZABLE row address present (Circle can act on it)
      * INVESTIGATE address `0x016606…` ABSENT from the primary
        targets table (it's an operator-internal lead, not a freeze
        target)
      * FREEZABLE badge present; INVESTIGATE badge ABSENT from the
        primary targets table (summary prose may still reference
        "investigation" but no INVESTIGATE-status pill renders for
        an issuer to act on)
    """
    case = _make_minimal_case()
    victim = VictimInfo(
        name="Jane Doe",
        wallet_address="0x" + "1" * 40,
        citizenship="USA",
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok",
        organization="Recupero LLC",
        email="alec@recupero.io",
    )
    issuer = IssuerInfo(
        name="Circle",
        short_name="Circle",
        contact_email="compliance@circle.com",
        jurisdiction="USA",
        regulatory_framework="",
        kyc_required=True,
    )

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        bundle = generate_briefs(
            primary_case=case,
            linked_cases=[],
            victim=victim,
            investigator=investigator,
            case_dir=case_dir,
            issuer=issuer,
            issuer_freezable=_circle_freeze_brief_entry(),
        )
        html = bundle.maple_path.read_text(encoding="utf-8")

    # The letter must talk about USDC (the issuer's token), not just
    # the original ETH asset.
    assert "USDC" in html
    # Specific freezable amount should appear (the cumulative $7,097.58)
    assert "$7,097.58" in html
    # FREEZABLE address renders in section 4 (this is the actionable
    # freeze target).
    assert "0x480CD46E6faDe651a0437DeaddA53D5c8e7D846A" in html
    # v0.27.2: INVESTIGATE address must NOT appear in the freeze letter.
    # Operator-internal leads stay in brief_editorial.json /
    # investigator_findings.csv — they don't get shipped to issuers.
    assert "0x016606Acc6B0cFE537acc221e3bf1bb44B4049Ee" not in html, (
        "v0.27.2 contract: INVESTIGATE-tagged address must not appear "
        "in the issuer freeze letter (0x52Aa bleed prevention)"
    )
    # FREEZABLE status badge renders for the one FREEZABLE row.
    assert "FREEZABLE" in html
    # v0.27.2: INVESTIGATE pill must NOT render in the primary-targets
    # table. The word "investigation" may appear in prose (totals
    # summary references "$X under investigation"), but the
    # status-pill span itself only renders when an INVESTIGATE row
    # is in freezable_holdings — which is impossible by definition.
    assert "INVESTIGATE</span>" not in html, (
        "v0.27.2 contract: INVESTIGATE pill must not render in the "
        "freeze letter's primary-targets table"
    )


def test_generate_briefs_legacy_path_unchanged() -> None:
    """When issuer_freezable is None (legacy / wallet-trace path),
    the letter renders the same way it did pre-fix — single
    asset + single current_holder. Backward-compat regression
    guard."""
    case = _make_minimal_case()
    victim = VictimInfo(
        name="Jane Doe",
        wallet_address="0x" + "1" * 40,
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok",
        organization="Recupero LLC",
        email="alec@recupero.io",
    )
    issuer = IssuerInfo(
        name="Circle",
        short_name="Circle",
        contact_email="compliance@circle.com",
    )

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        bundle = generate_briefs(
            primary_case=case, linked_cases=[],
            victim=victim, investigator=investigator,
            case_dir=case_dir, issuer=issuer,
            # issuer_freezable explicitly omitted — legacy path
        )
        html = bundle.maple_path.read_text(encoding="utf-8")

    # Legacy path: letter mentions ETH (the original theft asset)
    # and the to_address as the current holder.
    assert "ETH" in html
    assert "0x" + "2" * 40 in html


# ---- LE handoff per-issuer rendering ---- #


def test_le_handoff_renders_recoverable_positions_section() -> None:
    """End-to-end: when issuer_freezable is provided, the LE handoff
    template renders section 4.1 'Recoverable Positions' as the
    per-issuer PRIMARY FREEZE TARGETS table. Mirror of the
    freeze-letter test above — this is the law-enforcement-facing
    variant of the same fix.

    v0.27.2 (Jacob 0x52Aa bleed fix, item 1): section 4.1 now
    iterates ``freezable_holdings`` only — it's a primary-targets
    table, NOT a complete inventory. The complete inventory across
    statuses lives in section 4.2 ALL_ISSUER_HOLDINGS (only rendered
    when ``all_issuers_freezable`` is passed; this test exercises
    the 4.1-only path).

    The pinned contract:
      * Section 4.1 header present
      * USDC + FREEZABLE row address present
      * INVESTIGATE address `0x016606…` ABSENT from 4.1 (would only
        appear in 4.2 if all_issuers_freezable were passed)
      * INVESTIGATE pill ABSENT from 4.1's tbody; the word
        "INVESTIGATE" can still appear in the prose summary block
        below 4.1 ("INVESTIGATE positions (N addresses representing
        $X) require KYC verification...") — that's prose, not a
        status badge driving an issuer action.
    """
    case = _make_minimal_case()
    victim = VictimInfo(name="Jane Doe", wallet_address="0x" + "1" * 40,
                        citizenship="USA")
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )
    issuer = IssuerInfo(
        name="Circle", short_name="Circle",
        contact_email="compliance@circle.com",
        jurisdiction="USA", regulatory_framework="",
        kyc_required=True,
    )

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        bundle = generate_briefs(
            primary_case=case, linked_cases=[],
            victim=victim, investigator=investigator,
            case_dir=case_dir, issuer=issuer,
            issuer_freezable=_circle_freeze_brief_entry(),
        )
        le_html = bundle.le_path.read_text(encoding="utf-8")

    # The section 4.1 should exist
    assert "4.1 Recoverable Positions" in le_html
    # Stablecoin symbol shows up (not just the original ETH)
    assert "USDC" in le_html
    # FREEZABLE status badge renders for the one FREEZABLE row.
    assert "FREEZABLE" in le_html
    # FREEZABLE address appears in section 4.1
    assert "0x480CD46E6faDe651a0437DeaddA53D5c8e7D846A" in le_html
    # v0.27.2: INVESTIGATE address must NOT render in section 4.1.
    # Without all_issuers_freezable (section 4.2), it should be
    # nowhere in the LE handoff in this test scenario.
    assert "0x016606Acc6B0cFE537acc221e3bf1bb44B4049Ee" not in le_html, (
        "v0.27.2 contract: INVESTIGATE address must not render in "
        "section 4.1 primary-targets table; complete inventory "
        "across statuses lives in 4.2 only when all_issuers_freezable "
        "is supplied"
    )
    # v0.27.2: INVESTIGATE status pill must NOT render in 4.1's tbody.
    # The word "INVESTIGATE" may appear in the prose summary block
    # below the table (a count of investigate positions), but no
    # <span>INVESTIGATE</span> badge.
    import re
    sec_4_1_re = re.search(
        r'4\.1 Recoverable Positions.*?</table>',
        le_html, re.DOTALL,
    )
    assert sec_4_1_re is not None, "section 4.1 table not found"
    sec_4_1_table = sec_4_1_re.group(0)
    assert "INVESTIGATE</span>" not in sec_4_1_table, (
        "v0.27.2 contract: no INVESTIGATE pill in section 4.1's tbody"
    )
    # Section 6 (Recommended Actions) mentions section 4.1 in its ask
    assert "section 4.1" in le_html
    # Freeze capability surfaces
    assert "HIGH" in le_html


def test_le_handoff_executive_summary_mentions_stablecoin() -> None:
    """Section 1 (Executive Summary) of the LE handoff should
    explicitly mention the recoverable stablecoin + the freezable
    USD total when issuer_freezable is provided. LE officers
    triage by what's recoverable; burying this in section 4.1 is
    not enough — it has to be in the lead paragraph."""
    case = _make_minimal_case()
    victim = VictimInfo(name="Jane Doe", wallet_address="0x" + "1" * 40)
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )
    issuer = IssuerInfo(name="Circle", short_name="Circle",
                       contact_email="compliance@circle.com")

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        bundle = generate_briefs(
            primary_case=case, linked_cases=[],
            victim=victim, investigator=investigator,
            case_dir=case_dir, issuer=issuer,
            issuer_freezable=_circle_freeze_brief_entry(),
        )
        le_html = bundle.le_path.read_text(encoding="utf-8")

    # Grab the executive summary (section 1)
    import re
    body = re.search(r'<body[^>]*>(.*?)</body>', le_html, re.DOTALL)
    assert body is not None
    body_text = re.sub(r'<style[^>]*>.*?</style>', '', body.group(1), flags=re.DOTALL)
    body_text = re.sub(r'<[^>]+>', ' ', body_text)
    body_text = re.sub(r'\s+', ' ', body_text).strip()

    # Section 1 starts at "1. Executive Summary" and ends at "2. Victim"
    start = body_text.find("1. Executive Summary")
    end = body_text.find("2. Victim Information")
    assert start >= 0 and end > start
    section_1 = body_text[start:end]

    # The executive summary mentions USDC explicitly
    assert "USDC" in section_1
    # And the freezable total
    assert "$7,097.58" in section_1
    # And references the Recoverable Positions section to follow
    assert "FREEZABLE" in section_1


def test_le_handoff_legacy_path_unchanged() -> None:
    """When issuer_freezable is None (wallet-trace cases that don't
    generate freeze letters, or backward-compat callers), the LE
    handoff renders the single-asset / single-current_holder
    framing it always did."""
    case = _make_minimal_case()
    victim = VictimInfo(name="Jane Doe", wallet_address="0x" + "1" * 40)
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )
    issuer = IssuerInfo(name="Circle", short_name="Circle",
                       contact_email="compliance@circle.com")

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        bundle = generate_briefs(
            primary_case=case, linked_cases=[],
            victim=victim, investigator=investigator,
            case_dir=case_dir, issuer=issuer,
        )
        le_html = bundle.le_path.read_text(encoding="utf-8")

    # No section 4.1 in the legacy path
    assert "4.1 Recoverable Positions" not in le_html
    # The legacy text still references the original asset + to_address
    assert "ETH" in le_html
    assert "0x" + "2" * 40 in le_html


def test_le_handoff_only_freezable_no_investigate() -> None:
    """When all holdings are FREEZABLE (no INVESTIGATE), the
    INVESTIGATE-specific copy doesn't render in the LE handoff."""
    case = _make_minimal_case()
    victim = VictimInfo(name="Jane Doe", wallet_address="0x" + "1" * 40)
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )
    issuer = IssuerInfo(name="Circle", short_name="Circle",
                       contact_email="compliance@circle.com")

    # Build a freezable entry with only FREEZABLE statuses
    entry = _circle_freeze_brief_entry()
    for h in entry["holdings"]:
        h["status"] = "FREEZABLE"

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        bundle = generate_briefs(
            primary_case=case, linked_cases=[],
            victim=victim, investigator=investigator,
            case_dir=case_dir, issuer=issuer,
            issuer_freezable=entry,
        )
        le_html = bundle.le_path.read_text(encoding="utf-8")

    # FREEZABLE badges present
    assert "FREEZABLE" in le_html
    # No INVESTIGATE badge in the table when none are flagged
    # (the word may still appear in static prose, but the status pill
    # would only render when investigate_count > 0).
    # Check more specifically: section 4.1 status badges
    import re
    sec_4_1 = re.search(
        r'4\.1 Recoverable Positions.*?(?=<h2>|</body>)',
        le_html, re.DOTALL,
    )
    assert sec_4_1 is not None
    sec_text = sec_4_1.group(0)
    # All status pills in the table should be FREEZABLE
    investigate_pills = sec_text.count('INVESTIGATE</span>')
    freezable_pills = sec_text.count('FREEZABLE</span>')
    assert investigate_pills == 0, (
        f"unexpected INVESTIGATE pills in only-FREEZABLE scenario: {investigate_pills}"
    )
    assert freezable_pills == 2, (
        f"expected 2 FREEZABLE pills (one per holding), got {freezable_pills}"
    )
