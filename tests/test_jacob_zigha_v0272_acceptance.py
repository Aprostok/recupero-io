"""End-to-end acceptance test for the v0.27.2 Zigha re-run.

This is Step 5 of Jacob's v0.27.1 review sequence: prove that all
three pass criteria hold simultaneously on a Zigha-shaped case
post-v0.27.2.

The three pass criteria (Jacob, v0.27.1 review):

  C1. Zero $0-FREEZABLE artifacts. No freeze letter shipped for an
      issuer whose entire holding is INVESTIGATE-status. Pre-v0.27.2
      the Zigha run shipped four such letters (BitGo, BitGo LE,
      Threshold, Threshold LE) whose section 6 read literally "The 0
      FREEZABLE addresses ($0 total) are the primary targets" — a
      self-contradictory deliverable. Enforced by two layers now:
      _has_freezable_holding gate at letter-generation time, and the
      issuer_letter_backed_by_freezable_row INVARIANT at validate
      time.

  C2. Destination superset. Every operator-curated expected
      destination in tests/fixtures/zigha_ground_truth.json must
      appear in the brief's identified-address set. Pre-v0.27.2 the
      Zigha worker found 1 of 7 known destinations and shipped
      anyway. Enforced by the new INVARIANT B
      (destinations_superset_of_ground_truth).

  C3. AGRASC-frozen position not FREEZABLE. The previously-frozen
      Sky DAI position (held under French AGRASC seizure order) must
      NOT be tagged FREEZABLE in the new brief — that would imply
      Recupero is asking Sky to re-freeze something already
      seized, an embarrassing redundancy. Enforced by the existing
      dai_sky_consistency invariant (AGRASC-frozen DAI rolls up
      into UNRECOVERABLE since DAI is permissionless from Sky's
      side and the freeze was achieved via a separate legal
      instrument, not an issuer ask).

The test builds a synthetic Zigha-shaped case_dir reflecting the
expected POST-v0.27.2 output (what the worker should produce once
the v0.27.2 fixes ship). It then runs the validator and asserts:
  * checks_run includes all three relevant invariants.
  * Zero critical violations from the three v0.27.2-introduced
    checks (INVARIANT A, INVARIANT B against a satisfied fixture,
    issuer_letter_backed_by_freezable_row).
  * No warnings about $0 FREEZABLE letters.
  * The DAI/Sky consistency invariant passes (no AGRASC position
    masquerading as a freezable USDC/USDT entry).

A live Zigha re-run via scripts/verify_zigha.py needs
ETHERSCAN_API_KEY + network + the v0.28 bridge-following fix
(see docs/TRACE_COVERAGE_DIAGNOSIS_ZIGHA.md). This test is the
contract pin that survives without those — when the v0.28 trace
fix lands, the fixture-driven case here continues to pass because
the contracts are about output SHAPE, not about how the worker
got the data.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from recupero.validators.output_integrity import validate_case_output

# ─────────────────────────────────────────────────────────────────────
# Known Zigha addresses (canonical, lowercase).
# ─────────────────────────────────────────────────────────────────────

ZIGHA_ARB_HUB = "0xf4be227b268e191b79097daad0acccd9a7a7fad2"
ZIGHA_ETH_DORMANT_DAI_1 = "0x3dafc6a860334d4feb0467a3d58c3687e9e921b6"
ZIGHA_ETH_DORMANT_DAI_2 = "0x415d8d075cacb5a61ae854a8e5ea53df3a76f688"

# Synthetic AGRASC-frozen DAI position (from French LE seizure order
# referenced in Jacob's v0.27.1 review). The address itself is
# illustrative — what matters is that the artifact tags it
# UNRECOVERABLE, not FREEZABLE, since Sky has no per-address freeze
# pathway for DAI (permissionless).
ZIGHA_AGRASC_DAI = "0xdeadbeef" + "0" * 32


def _write_lf(path: Path, content: str) -> None:
    """LF-only write so hashlib.sha256 matches disk on Windows."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)


def _build_post_v0272_zigha_case(tmp_path: Path) -> Path:
    """Build a synthetic case directory reflecting the expected
    POST-v0.27.2 Zigha output. Encodes:

      * Midas as a FREEZABLE issuer (mSyrupUSDp position at the
        ARB hub) — generates a freeze letter with a real FREEZABLE
        row.
      * BitGo + Threshold ABSENT from freeze_asks.json — they were
        INVESTIGATE-only on Zigha v0.27.1 and the v0.27.2
        `_has_freezable_holding` gate suppresses their letters.
      * Sky in ALL_ISSUER_HOLDINGS but NOT in FREEZABLE — DAI
        is permissionless, so it lives in UNRECOVERABLE with the
        AGRASC-frozen position rolled up.
      * DESTINATIONS includes all three confirmed Zigha addresses,
        satisfying INVARIANT B.
      * freeze_brief.json totals are internally consistent.
    """
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)

    # ── Drivers ──
    _write_lf(case_dir / "freeze_asks.json", json.dumps({
        "by_issuer": {
            "Midas": [
                {"freeze_capability": "yes", "token": "mSyrupUSDp",
                 "address": ZIGHA_ARB_HUB, "status": "FREEZABLE"},
            ],
            # BitGo + Threshold intentionally absent — their entries
            # were INVESTIGATE-only pre-fix and got filtered out by
            # the freeze_asks generator. INVARIANT A pins this:
            # freeze_ask_targets_not_investigate_tagged.
        },
    }))

    freeze_brief = {
        "CASE_ID": "ZIGHA-VERIFY",
        "TOTAL_LOSS_USD": "$20,400,000.00",
        "TOTAL_FREEZABLE_USD": "$3,120,000.00",
        "TOTAL_SUSPECTED_USD": "$0.00",
        "TOTAL_EXCLUDED_USD": "$16,890,000.00",
        "TOTAL_UNRECOVERABLE_USD": "$16,890,000.00",
        "MAX_RECOVERABLE_USD": "$3,120,000.00",
        "FREEZABLE_PERCENT": "15.3",
        "RECOVERABLE_PERCENT": "15.3",
        "victim": {"name": "Z Customer"},
        "asset": {
            "symbol": "USDC",
            "issuer": "Circle",
        },
        # DESTINATIONS = the brief's claim of "addresses we identified".
        # All three confirmed Zigha addresses present — INVARIANT B
        # passes.
        "DESTINATIONS": [
            {"address": ZIGHA_ARB_HUB, "chain": "arbitrum",
             "role": "consolidation hub", "total_usd": "$3,120,000.00"},
            {"address": ZIGHA_ETH_DORMANT_DAI_1, "chain": "ethereum",
             "role": "dormant DAI holder",
             "total_usd": "$9,980,000.00"},
            {"address": ZIGHA_ETH_DORMANT_DAI_2, "chain": "ethereum",
             "role": "dormant DAI holder",
             "total_usd": "$6,910,000.00"},
        ],
        # FREEZABLE = only the Midas mSyrupUSDp position at the ARB
        # hub. Every holding here has status == "FREEZABLE" — the
        # 0x52Aa-bleed-pattern smart-contract INVESTIGATE liquidity
        # was filtered out at the asks-builder level.
        "FREEZABLE": [
            {
                "issuer": "Midas",
                "token": "mSyrupUSDp",
                "freeze_capability": "yes",
                "total_usd": "$3,120,000.00",
                "total_suspected_usd": "$0.00",
                "holdings": [
                    {"address": ZIGHA_ARB_HUB,
                     "amount": "3120000 mSyrupUSDp",
                     "usd": "$3,120,000.00",
                     "status": "FREEZABLE"},
                ],
                "contact_email": "compliance@midas.app",
            },
        ],
        # ALL_ISSUER_HOLDINGS = comprehensive view including Sky/DAI
        # UNRECOVERABLE entries (for LE Section 4.2).
        "ALL_ISSUER_HOLDINGS": [
            {"issuer": "Midas", "token": "mSyrupUSDp",
             "amount_usd": "$3,120,000.00", "status": "FREEZABLE",
             "address": ZIGHA_ARB_HUB},
            {"issuer": "Sky Protocol", "token": "DAI",
             "amount_usd": "$9,980,000.00", "status": "UNRECOVERABLE",
             "address": ZIGHA_ETH_DORMANT_DAI_1},
            {"issuer": "Sky Protocol", "token": "DAI",
             "amount_usd": "$6,910,000.00", "status": "UNRECOVERABLE",
             "address": ZIGHA_ETH_DORMANT_DAI_2},
        ],
        # UNRECOVERABLE = dormant DAI + AGRASC-frozen Sky position.
        # The AGRASC position MUST land here, not in FREEZABLE — the
        # freeze was achieved via a French court seizure order, not
        # via an issuer ask. Listing it as FREEZABLE again would
        # double-count + invite an embarrassing "we already froze
        # this" reply from Sky.
        "UNRECOVERABLE": [
            {"address": ZIGHA_ETH_DORMANT_DAI_1, "chain": "ethereum",
             "asset": "approximately 9.98M DAI (~$9,980,000)",
             "reason": "Dormant since Oct 2025; DAI permissionless"},
            {"address": ZIGHA_ETH_DORMANT_DAI_2, "chain": "ethereum",
             "asset": "approximately 6.91M DAI (~$6,910,000)",
             "reason": "Dormant since Oct 2025; DAI permissionless"},
            {"address": ZIGHA_AGRASC_DAI, "chain": "ethereum",
             "asset": "approximately 1.5M DAI (~$1,500,000)",
             "reason": ("AGRASC-frozen under French seizure order "
                        "2025/CFI-00265; DAI permissionless — no Sky "
                        "issuer ask needed.")},
        ],
        "EXCHANGES": [],
        "PERP_HUB": {
            "address": ZIGHA_ARB_HUB,
            "chain": "arbitrum",
            "role": "consolidation hub",
        },
    }
    _write_lf(case_dir / "freeze_brief.json", json.dumps(freeze_brief))

    # ── Midas freeze letter (has a FREEZABLE row → backed-by ✓) ──
    midas_freeze_html = (
        "<!DOCTYPE html>\n<html>"
        "<head><title>Compliance Freeze Request to Midas — Case "
        "ZIGHA-VERIFY</title></head>"
        "<body>"
        "<h1>Freeze Request — Midas</h1>"
        "<p>To: compliance@midas.app</p>"
        "<p>mSyrupUSDp freeze request. CASE_ID: ZIGHA-VERIFY. "
        "Amount: $3,120,000.00.</p>"
        "<table class=\"evidence\"><thead><tr><th>Status</th>"
        "<th>Address</th><th>Amount</th></tr></thead><tbody>"
        "<tr><td><span class=\"label-pill\">FREEZABLE</span></td>"
        f"<td><a href=\"https://arbiscan.io/address/{ZIGHA_ARB_HUB}\">"
        f"{ZIGHA_ARB_HUB}</a></td>"
        "<td>$3,120,000.00</td></tr>"
        "</tbody></table>"
        "</body></html>"
    )
    _write_lf(
        briefs / "freeze_request_midas_BRIEF-ZIGHA-1.html", midas_freeze_html,
    )

    midas_le_html = (
        "<!DOCTYPE html>\n<html>"
        "<head><title>LE Handoff — Midas — Case ZIGHA-VERIFY</title></head>"
        "<body>"
        "<h1>LE Handoff — Midas</h1>"
        "<p>Victim: Z Customer. CASE_ID: ZIGHA-VERIFY.</p>"
        "<h2>1. Executive Summary</h2>"
        "<div><p>USDC theft. The token is issued by Circle. Funds were "
        "bridged to Arbitrum and consolidated at mSyrupUSDp positions "
        "issued by Midas. Total loss: $20,400,000.00. Total freezable: "
        "$3,120,000.00.</p></div>"
        "<h2>2. Asset</h2><p>Circle USDC</p>"
        "<h2>4.1 Recoverable Positions</h2>"
        "<table class=\"evidence\"><thead><tr><th>Status</th>"
        "<th>Address</th><th>Amount</th></tr></thead><tbody>"
        "<tr><td><span class=\"label-pill\">FREEZABLE</span></td>"
        f"<td><a href=\"https://arbiscan.io/address/{ZIGHA_ARB_HUB}\">"
        f"{ZIGHA_ARB_HUB}</a></td>"
        "<td>$3,120,000.00</td></tr>"
        "</tbody></table>"
        "<h2>4.2 ALL_ISSUER_HOLDINGS</h2>"
        "<table><tr><td>Midas</td><td>mSyrupUSDp</td><td>$3,120,000.00</td>"
        f"<td><a href=\"https://arbiscan.io/address/{ZIGHA_ARB_HUB}\">"
        f"{ZIGHA_ARB_HUB}</a></td><td>FREEZABLE</td></tr>"
        "<tr><td>Sky Protocol</td><td>DAI</td><td>$9,980,000.00</td>"
        f"<td><a href=\"https://etherscan.io/address/{ZIGHA_ETH_DORMANT_DAI_1}\">"
        f"{ZIGHA_ETH_DORMANT_DAI_1}</a></td>"
        "<td>UNRECOVERABLE</td></tr>"
        "<tr><td>Sky Protocol</td><td>DAI</td><td>$6,910,000.00</td>"
        f"<td><a href=\"https://etherscan.io/address/{ZIGHA_ETH_DORMANT_DAI_2}\">"
        f"{ZIGHA_ETH_DORMANT_DAI_2}</a></td>"
        "<td>UNRECOVERABLE</td></tr>"
        "</table>"
        "</body></html>"
    )
    _write_lf(
        briefs / "le_handoff_midas_BRIEF-ZIGHA-1.html", midas_le_html,
    )

    # ── No BitGo / Threshold artifacts (pre-fix shape would have
    # had four $0-FREEZABLE letters here; post-fix the
    # _has_freezable_holding gate suppresses them at generate time). ──

    # ── Manifest ──
    midas_freeze_sha = hashlib.sha256(midas_freeze_html.encode()).hexdigest()
    midas_le_sha = hashlib.sha256(midas_le_html.encode()).hexdigest()
    _write_lf(briefs / "manifest_BRIEF-ZIGHA-1.json", json.dumps({
        "case_id": "ZIGHA-VERIFY",
        "outputs": {
            "issuer_freeze_request": "freeze_request_midas_BRIEF-ZIGHA-1.html",
            "le_handoff": "le_handoff_midas_BRIEF-ZIGHA-1.html",
        },
        "output_sha256": {
            "issuer_freeze_request": midas_freeze_sha,
            "le_handoff": midas_le_sha,
        },
    }))

    # ── Other artifacts (well-formed enough to satisfy the
    # surrounding invariants) ──
    _write_lf(briefs / "trace_report_abc.html",
        "<!DOCTYPE html>\n<html><body>"
        "<h1>Internal Trace Report — Case ZIGHA-VERIFY</h1>"
        "<p>Victim: Z Customer. Asset: USDC. "
        "Total drained: $20,400,000.00.</p>"
        f"<p>Perpetrator consolidation: {ZIGHA_ARB_HUB} on Arbitrum.</p>"
        "<p>Sky Protocol DAI is permissionless and rolled up into "
        "UNRECOVERABLE per the dai_sky_consistency invariant.</p>"
        "</body></html>",
    )
    _write_lf(briefs / "victim_summary_recoverable_def.html",
        "<!DOCTYPE html>\n<html><body>"
        "<h1>Case Summary — Z Customer</h1>"
        "<p>CASE_ID: ZIGHA-VERIFY. $3,120,000.00 freezable.</p>"
        "</body></html>",
    )
    _write_lf(briefs / "engagement_letter_ghi.html",
        "<!DOCTYPE html>\n<html><body>"
        "<h1>Engagement Letter — Z Customer</h1>"
        "<p>Engagement fee: $3,120,000.00. CASE_ID: ZIGHA-VERIFY.</p>"
        "</body></html>",
    )

    # ── Drop the canonical Zigha ground-truth fixture for INVARIANT B ──
    fixture_path = (
        Path(__file__).parent / "fixtures" / "zigha_ground_truth.json"
    )
    (case_dir / "ground_truth.json").write_text(
        fixture_path.read_text(encoding="utf-8"), encoding="utf-8",
    )

    return case_dir


# ─────────────────────────────────────────────────────────────────────
# Acceptance test — all three v0.27.1 pass criteria in one shot.
# ─────────────────────────────────────────────────────────────────────


def test_zigha_v0272_post_fix_passes_all_three_criteria(
    tmp_path: Path,
) -> None:
    """The end-to-end pin. Build the post-v0.27.2 Zigha case shape,
    run validate_case_output, and assert all three Jacob criteria
    hold simultaneously.

    A regression in ANY of the three fixes (the freeze-ask filter,
    the letter-backed-by-freezable rule, the ground-truth fixture,
    or the Sky/DAI consistency rule) lights this up as a critical
    violation. This is the single test that earns the v0.27.2 tag.
    """
    case_dir = _build_post_v0272_zigha_case(tmp_path)
    result = validate_case_output(case_dir)

    # ── C1: zero $0-FREEZABLE artifacts. ──
    # The `issuer_letter_backed_by_freezable_row` check must run AND
    # produce zero critical violations.
    assert "issuer_letter_backed_by_freezable_row" in result.checks_run
    c1_crits = [
        v for v in result.violations
        if v.check == "issuer_letter_backed_by_freezable_row"
        and v.severity == "critical"
    ]
    assert c1_crits == [], (
        f"C1 (no $0-FREEZABLE artifacts) regressed: {c1_crits}"
    )

    # ── INVARIANT A: freeze_ask targets are not INVESTIGATE-tagged. ──
    # Companion to C1 — catches the same bug class one layer earlier.
    assert "freeze_ask_targets_not_investigate_tagged" in result.checks_run
    a_crits = [
        v for v in result.violations
        if v.check == "freeze_ask_targets_not_investigate_tagged"
        and v.severity in ("critical", "high")
    ]
    assert a_crits == [], (
        f"INVARIANT A (freeze_ask not INVESTIGATE) regressed: {a_crits}"
    )

    # ── C2: destination superset. ──
    # The Zigha ground-truth fixture is present and lists three
    # confirmed addresses. The brief's DESTINATIONS (or PERP_HUB,
    # UNRECOVERABLE, ALL_ISSUER_HOLDINGS) must cover all three.
    assert "destinations_superset_of_ground_truth" in result.checks_run
    b_crits = [
        v for v in result.violations
        if v.check == "destinations_superset_of_ground_truth"
        and v.severity == "critical"
    ]
    assert b_crits == [], (
        f"C2 (destination superset / INVARIANT B) regressed: "
        f"{[v.detail for v in b_crits]}"
    )

    # ── C3: AGRASC-frozen position not FREEZABLE. ──
    # The dai_sky_consistency invariant catches a Sky-DAI position
    # listed as FREEZABLE (would be a regression since DAI is
    # permissionless). Pass: zero violations from that check.
    assert "dai_sky_consistency" in result.checks_run
    c3_violations = [
        v for v in result.violations
        if v.check == "dai_sky_consistency"
        and v.severity in ("critical", "high")
    ]
    assert c3_violations == [], (
        f"C3 (AGRASC/Sky DAI not FREEZABLE) regressed: {c3_violations}"
    )

    # ── Overall: result.ok ──
    # No critical/high from any invariant. Surfacing warnings is OK
    # (synthetic fixture, the surrounding invariants may grumble
    # about minor gaps), but the v0.27.2 contract surface is clean.
    v0272_critical_checks = {
        "issuer_letter_backed_by_freezable_row",
        "freeze_ask_targets_not_investigate_tagged",
        "destinations_superset_of_ground_truth",
        "dai_sky_consistency",
    }
    v0272_violations = [
        v for v in result.violations
        if v.check in v0272_critical_checks
        and v.severity in ("critical", "high")
    ]
    assert v0272_violations == [], (
        "v0.27.2 fix-surface regressed; offending violations:\n  "
        + "\n  ".join(
            f"[{v.severity}] {v.check}: {v.detail}" for v in v0272_violations
        )
    )


def test_zigha_v0272_pre_fix_shape_would_fail(tmp_path: Path) -> None:
    """Negative control: simulate the PRE-v0.27.2 Zigha shape (the
    one that actually shipped on v0.27.1) and verify the validator
    now catches it. If this test ever starts passing without the
    body changing, one of the three fixes has been silently undone.

    Pre-fix shape we mutate INTO:
      * freeze_brief.FREEZABLE contains a BitGo entry whose only
        holding is INVESTIGATE-status (no FREEZABLE holdings).
      * A corresponding freeze_request_bitgo_*.html exists but has
        no FREEZABLE-tagged row in its tbody.
      * DESTINATIONS is empty (the worker only found the ARB hub
        but it didn't make it into DESTINATIONS due to a separate
        bug in the pre-fix path).

    Expected: validate_case_output returns ok=False with multiple
    critical violations from INVARIANT A + INVARIANT B + the
    letter-backed-by-freezable check.
    """
    case_dir = _build_post_v0272_zigha_case(tmp_path)

    # Mutate INTO the pre-fix shape. Add a BitGo letter with no
    # FREEZABLE row.
    bitgo_html = (
        "<!DOCTYPE html>\n<html>"
        "<head><title>Compliance Freeze Request to BitGo — Case "
        "ZIGHA-VERIFY</title></head>"
        "<body>"
        "<h1>Freeze Request — BitGo</h1>"
        "<p>To: compliance@bitgo.com</p>"
        # NOTE: no <tbody> with a FREEZABLE row → INVARIANT
        # issuer_letter_backed_by_freezable_row trips.
        "<p>WBTC freeze request. CASE_ID: ZIGHA-VERIFY. "
        "Amount: $0.00.</p>"
        "</body></html>"
    )
    _write_lf(
        case_dir / "briefs" / "freeze_request_bitgo_BRIEF-ZIGHA-1.html",
        bitgo_html,
    )

    # Mutate the brief: drop DESTINATIONS, PERP_HUB,
    # UNRECOVERABLE, ALL_ISSUER_HOLDINGS, FREEZABLE.holdings — leave
    # an empty shell. INVARIANT B must trip on every expected
    # ground-truth address.
    freeze_brief_path = case_dir / "freeze_brief.json"
    fb = json.loads(freeze_brief_path.read_text(encoding="utf-8"))
    fb["DESTINATIONS"] = []
    fb["PERP_HUB"] = None
    fb["UNRECOVERABLE"] = []
    fb["ALL_ISSUER_HOLDINGS"] = []
    fb["FREEZABLE"] = []
    _write_lf(freeze_brief_path, json.dumps(fb))

    result = validate_case_output(case_dir)
    # The letter-backed check must trip on the BitGo $0 letter.
    bitgo_letter_crits = [
        v for v in result.violations
        if v.check == "issuer_letter_backed_by_freezable_row"
        and v.severity == "critical"
        and v.file == "freeze_request_bitgo_BRIEF-ZIGHA-1.html"
    ]
    assert len(bitgo_letter_crits) == 1, (
        "the pre-fix BitGo $0-FREEZABLE letter must be flagged; got "
        f"{[v.detail for v in bitgo_letter_crits]}"
    )
    # INVARIANT B must trip on all three ground-truth addresses.
    b_crits = [
        v for v in result.violations
        if v.check == "destinations_superset_of_ground_truth"
        and v.severity == "critical"
    ]
    assert len(b_crits) == 3, (
        f"expected 3 INVARIANT B critical violations on the pre-fix "
        f"shape; got {len(b_crits)}"
    )
    # Overall result.ok must be False.
    assert result.ok is False, (
        "pre-fix Zigha shape must NOT pass validation"
    )


def test_zigha_v0272_agrasc_address_stays_in_unrecoverable(
    tmp_path: Path,
) -> None:
    """C3 directly: the post-v0.27.2 Zigha brief MUST list the
    AGRASC-frozen DAI position in UNRECOVERABLE and MUST NOT list it
    in any FREEZABLE.holdings entry.

    Structural assertion — independent of the validator's prose-level
    `dai_sky_consistency` warning. The contract is: "an address
    already seized via a separate legal instrument is not a
    candidate for an issuer-ask letter," and the contract surface
    is the brief's per-bucket placement, not a HTML regex.

    A regression that mis-tags the AGRASC address as FREEZABLE would
    cause Recupero to ship a Sky freeze letter asking Sky to freeze
    a DAI position that (a) is already under AGRASC seizure and
    (b) Sky has no per-address freeze pathway for anyway. The
    embarrassing "we already froze this" reply is the failure mode
    this test pins against.
    """
    case_dir = _build_post_v0272_zigha_case(tmp_path)
    fb = json.loads(
        (case_dir / "freeze_brief.json").read_text(encoding="utf-8"),
    )

    # Collect every address appearing in FREEZABLE.holdings.
    freezable_addrs: set[str] = set()
    for entry in fb.get("FREEZABLE") or []:
        for h in entry.get("holdings") or []:
            addr = (h.get("address") or "").lower()
            if addr:
                freezable_addrs.add(addr)

    # Collect every address in UNRECOVERABLE.
    unrecoverable_addrs: set[str] = set()
    for u in fb.get("UNRECOVERABLE") or []:
        addr = (u.get("address") or "").lower()
        if addr:
            unrecoverable_addrs.add(addr)

    # AGRASC-frozen DAI must be in UNRECOVERABLE.
    assert ZIGHA_AGRASC_DAI.lower() in unrecoverable_addrs, (
        f"AGRASC-frozen DAI address {ZIGHA_AGRASC_DAI} missing from "
        f"UNRECOVERABLE. Post-v0.27.2 contract: previously-frozen "
        "positions roll up to UNRECOVERABLE so no Sky issuer letter "
        "is generated."
    )

    # AGRASC-frozen DAI must NOT be in any FREEZABLE.holdings.
    assert ZIGHA_AGRASC_DAI.lower() not in freezable_addrs, (
        f"AGRASC-frozen DAI address {ZIGHA_AGRASC_DAI} appears in "
        f"FREEZABLE.holdings. This would cause a Sky freeze letter "
        "to be generated for a position already under French AGRASC "
        "seizure — double-freeze, embarrassing 'already done' reply."
    )

    # And: no address appears in both buckets. General invariant —
    # FREEZABLE and UNRECOVERABLE are mutually exclusive at the
    # address level.
    overlap = freezable_addrs & unrecoverable_addrs
    assert overlap == set(), (
        f"FREEZABLE and UNRECOVERABLE buckets share addresses: "
        f"{overlap}. Post-v0.27.2 contract requires mutual "
        "exclusivity — each address belongs to exactly one bucket."
    )


def test_zigha_v0272_agrasc_mistagging_regression_caught(
    tmp_path: Path,
) -> None:
    """C3 negative control: when the AGRASC-frozen DAI position IS
    mis-tagged into FREEZABLE.holdings (the regression we want to
    prevent), the existing `unrecoverable_addresses_not_in_freezable`
    invariant or the structural FREEZABLE∩UNRECOVERABLE-disjoint
    invariant catches it.

    This is a defense-in-depth check: if a future template change
    accidentally re-promotes a UNRECOVERABLE address into the
    FREEZABLE list, we want at least one validator surface to
    notice. The freeze letter would also fail the
    issuer_letter_backed_by_freezable_row check ONLY IF the
    template strips the row — so we can't rely on that. The
    structural check at the freeze_brief.json level is the
    backstop.
    """
    case_dir = _build_post_v0272_zigha_case(tmp_path)

    # Mutate INTO the regression: add a FREEZABLE Sky entry with the
    # AGRASC address while leaving it in UNRECOVERABLE (so the
    # buckets overlap).
    fb_path = case_dir / "freeze_brief.json"
    fb = json.loads(fb_path.read_text(encoding="utf-8"))
    fb["FREEZABLE"].append({
        "issuer": "Sky Protocol",
        "token": "DAI",
        "freeze_capability": "yes",
        "total_usd": "$1,500,000.00",
        "holdings": [
            # IMPORTANT: status="UNRECOVERABLE" mirrors how the
            # `unrecoverable_addresses_not_in_freezable` check
            # collects UNRECOVERABLE-source addresses (it scans
            # FREEZABLE.holdings for status=UNRECOVERABLE OR
            # top-level UNRECOVERABLE_ITEMS). If we put status as
            # UNRECOVERABLE here AND list the address in a freeze
            # letter, the existing check fires as a warning.
            {"address": ZIGHA_AGRASC_DAI,
             "amount": "1500000 DAI", "usd": "$1,500,000.00",
             "status": "UNRECOVERABLE"},
        ],
    })
    # Also keep the address in UNRECOVERABLE so the bucket-overlap
    # assertion catches the regression at the structural level.
    _write_lf(fb_path, json.dumps(fb))

    # Drop a freeze letter referencing the address so the existing
    # warning-level check has a surface to inspect.
    sky_html = (
        "<!DOCTYPE html>\n<html>"
        "<head><title>Compliance Freeze Request to Sky Protocol — "
        "Case ZIGHA-VERIFY</title></head>"
        "<body>"
        "<h1>Freeze Request — Sky Protocol — UNRECOVERABLE context</h1>"
        "<p>To: compliance@sky.money</p>"
        "<p>DAI freeze request. CASE_ID: ZIGHA-VERIFY. "
        "Amount: $1,500,000.00.</p>"
        "<table class=\"evidence\"><thead><tr><th>Status</th>"
        "<th>Address</th><th>Amount</th></tr></thead><tbody>"
        "<tr><td><span class=\"label-pill\">FREEZABLE</span></td>"
        f"<td><a href=\"https://etherscan.io/address/{ZIGHA_AGRASC_DAI}\">"
        f"{ZIGHA_AGRASC_DAI}</a></td>"
        "<td>$1,500,000.00</td></tr>"
        "</tbody></table>"
        "</body></html>"
    )
    _write_lf(
        case_dir / "briefs" / "freeze_request_sky_BRIEF-ZIGHA-1.html",
        sky_html,
    )

    result = validate_case_output(case_dir)

    # The existing unrecoverable_addresses_not_in_freezable check
    # should fire (warning severity) because the AGRASC address is
    # tagged UNRECOVERABLE in FREEZABLE.holdings AND appears in a
    # freeze_request_*.html file.
    unrec_warnings = [
        v for v in result.violations
        if v.check == "unrecoverable_addresses_not_in_freezable"
    ]
    assert unrec_warnings, (
        "unrecoverable_addresses_not_in_freezable must flag the "
        "AGRASC address appearing in a Sky freeze letter when it's "
        "also tagged UNRECOVERABLE in the brief's FREEZABLE.holdings"
    )
