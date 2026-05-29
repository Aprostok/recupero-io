"""Post-merge audit-finding hardening tests (v0.27.2 → exceptional).

After the v0.27.2 commit (Jacob 0x52Aa bleed fix + INVARIANT B + Zigha
ground-truth), a parallel independent audit identified 32 findings
where the test surface was pass-level rather than exceptional —
real regression vectors that could re-introduce Jacob's bugs without
tripping any guard.

This file pins the post-merge hardening: each test maps to a numbered
finding from that audit and adds the missing negative control,
realistic-Zigha-numbers exercise, or cross-artifact consistency
check.

The audit findings (severity HIGH unless noted) addressed here:

  #1  _compute_perpetrator_holdings UNRECOVERABLE-via-FREEZABLE.holdings
      path never tested with the real status="UNRECOVERABLE" branch.
  #2  Case sensitivity asymmetry between _has_freezable_holding
      (case-insensitive) and _compute_perpetrator_holdings
      UNRECOVERABLE check (was case-sensitive — fixed in this round).
  #3  INVESTIGATE-status row inside FREEZABLE.holdings[] is the actual
      Zigha regression vector, not pinned by the perpetrator-holdings
      tests.
  #4  INVARIANT A's _has_freezable_holding regression test only
      exercises the freeze_request path, not the LE handoff path.
  #5  _FREEZABLE_ROW_RE regex pairs FREEZABLE pill to first 0x...
      address — order-dependent on multi-row tbody, untested.
  #6  Acceptance test uses round synthetic numbers; the lived Zigha
      experience ($145M INVESTIGATE bleed → $149M headline vs $7M
      real) is not pinned.
  #7  Acceptance fixture has no DESTINATION_NOTES — INVARIANT A
      never actually exercises against the post-fix shape.
  #8  Section 4.2 (Complete inventory) positive test — INVESTIGATE
      rows DO appear there (so we don't accidentally over-filter).
  #9  WETH skip end-to-end — does the WETH holding still surface in
      investigator_findings.csv?
  #10 INVARIANT B count-canary — fixture has only 3 of 7 known
      Zigha addresses; need a test that fails if fewer than that.
  #12 Pre-fix shape mutation should reproduce the Threshold-LE
      "0 FREEZABLE addresses" actual shape (INVESTIGATE-only tbody,
      not empty tbody).
  #13 Cross-artifact headline reconciliation (new INVARIANT —
      perpetrator_holdings_reconcile_across_artifacts).
  #15 INVARIANT B match-via-EXCHANGES branch coverage.
  #16 INVARIANT B match-via-ALL_ISSUER_HOLDINGS branch coverage.
  #17 INVARIANT A textual "INVESTIGATE" fallback (currently only
      matches the 🟧 emoji).
  #20 _canonicalize_for_compare fallback path test.
  #22 test_ctx_basic_shape_locked subset assertion (was exact-equal,
      brittle to additive changes).
  #23 Integration test that _has_freezable_holding is called by
      build_all_deliverables (not just the function in isolation).
  #25 INVARIANT B detail surface includes SPECIFIC role/source
      string from the fixture (not just the word "role").
  #27 Document why the AGRASC address is a synthetic sentinel.
  #31 letter-backed-by-freezable LE-handoff symmetry — Threshold-LE
      was the literal Jacob exemplar but wasn't being checked. Now
      both freeze_request_*.html AND le_handoff_*.html are checked.
  #32 Provenance keys (_curated_by, _curated_at, _v) asserted.

Run synthetic — no DB, no network, fast.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal
from pathlib import Path

from recupero.reports.emit_brief import _compute_perpetrator_holdings
from recupero.validators.output_integrity import (
    _FREEZABLE_ROW_RE,
    _canonicalize_for_compare,
    _check_destinations_superset_of_ground_truth,
    _check_freeze_ask_targets_not_investigate_tagged,
    _check_issuer_letter_backed_by_freezable_row,
    _check_perpetrator_holdings_reconcile,
)

# Real Zigha addresses (canonical lower-case).
ZIGHA_ARB_HUB = "0xf4be227b268e191b79097daad0acccd9a7a7fad2"
ZIGHA_ETH_DORMANT_DAI_1 = "0x3dafc6a860334d4feb0467a3d58c3687e9e921b6"
ZIGHA_ETH_DORMANT_DAI_2 = "0x415d8d075cacb5a61ae854a8e5ea53df3a76f688"
# Real 0x52Aa bleed contract from Jacob's v0.27.1 review — the
# smart-contract reflective-liquidity address Recupero must NEVER
# tag as a freeze target.
ZIGHA_BLEED_CONTRACT = "0x52aa899454998be5b000ad077a46bbe360f4e497"

# Realistic Zigha-shape numbers from Jacob's review.
# Pre-fix headline: ~$149.95M (inflation from $145M of INVESTIGATE bleed).
# Post-fix real: ~$3.5M FREEZABLE + ~$4.4M UNRECOVERABLE ≈ $7.9M.
ZIGHA_REAL_FREEZABLE = Decimal("3500000")
ZIGHA_REAL_UNRECOVERABLE = Decimal("4400000")
ZIGHA_REAL_TOTAL = ZIGHA_REAL_FREEZABLE + ZIGHA_REAL_UNRECOVERABLE  # 7.9M
ZIGHA_BLEED_INVESTIGATE = Decimal("145000000")  # the 21.6× inflator


def _write_lf(path: Path, content: str) -> None:
    """LF-only write so hashlib.sha256 matches disk on Windows.
    Shared helper for this hardening file — finding #30."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)


# ─────────────────────────────────────────────────────────────────────
# Finding #1 + #3: _compute_perpetrator_holdings UNRECOVERABLE-via-
# holdings + INVESTIGATE-in-holdings exclusion.
# ─────────────────────────────────────────────────────────────────────


def test_perpetrator_holdings_unrecoverable_via_holdings_list_counted() -> None:
    """Finding #1: the second loop in _compute_perpetrator_holdings
    sums FREEZABLE[].holdings[] entries whose status=='UNRECOVERABLE'.
    No prior test exercised this branch with a realistic input. A
    regression that breaks the loop (typo, wrong filter) would
    silently zero the Sky-DAI portion of the Zigha headline.

    Pre-fix Zigha example: Sky Protocol had a per-issuer entry with
    holdings=[{status:UNRECOVERABLE, address:'0x3daFC6…',
    usd:'$9,980,000.00'}, ...]. _compute_perpetrator_holdings must
    sum the holding's usd field.
    """
    freezable = [
        {
            "issuer": "Sky Protocol",
            "token": "DAI",
            "total_usd": "$0.00",  # No FREEZABLE rows on Sky/DAI
            "holdings": [
                {"address": ZIGHA_ETH_DORMANT_DAI_1,
                 "usd": "$9,980,000.00", "status": "UNRECOVERABLE"},
                {"address": ZIGHA_ETH_DORMANT_DAI_2,
                 "usd": "$6,910,000.00", "status": "UNRECOVERABLE"},
            ],
        },
    ]
    total = _compute_perpetrator_holdings(freezable, [])
    assert total == Decimal("16890000.00"), (
        "UNRECOVERABLE-via-holdings sum regressed; expected $16,890,000 "
        f"(9.98M + 6.91M from Sky/DAI), got {total}"
    )


def test_perpetrator_holdings_investigate_row_in_holdings_excluded() -> None:
    """Finding #3: the actual Zigha regression vector — an
    INVESTIGATE-status row INSIDE the FREEZABLE.holdings[] array.
    Pre-v0.27.2 the perpetrator-holdings computer summed every row.
    Post-fix: only FREEZABLE+UNRECOVERABLE statuses contribute.

    The Zigha 0x52Aa bleed shape: Tether issuer entry with
    holdings=[{status:FREEZABLE, usd:'$245,000'}, {status:INVESTIGATE,
    usd:'$65,000,000'}]. The INVESTIGATE row is the 1inch/Uniswap
    pool — NOT perpetrator-controlled.
    """
    freezable = [
        {
            "issuer": "Tether",
            "token": "USDT",
            # total_usd is FREEZABLE-only by convention.
            "total_usd": "$245,000.00",
            "holdings": [
                {"address": "0x" + "a" * 40,
                 "usd": "$245,000.00", "status": "FREEZABLE"},
                {"address": ZIGHA_BLEED_CONTRACT,
                 "usd": "$65,000,000.00", "status": "INVESTIGATE"},
            ],
        },
    ]
    total = _compute_perpetrator_holdings(freezable, [])
    assert total == Decimal("245000.00"), (
        "INVESTIGATE-status row inside FREEZABLE.holdings[] must NOT "
        f"contribute to perpetrator-holdings (0x52Aa bleed pattern); "
        f"got {total}"
    )


# ─────────────────────────────────────────────────────────────────────
# Finding #2: case-insensitive UNRECOVERABLE check.
# ─────────────────────────────────────────────────────────────────────


def test_perpetrator_holdings_unrecoverable_case_insensitive() -> None:
    """Finding #2: a writer emitting lower-case "unrecoverable" must
    still have the row counted. The bug pre-fix: bare equality
    `!= "UNRECOVERABLE"` silently dropped any lower-cased row. Fixed
    by applying .upper() consistently with _has_freezable_holding.

    Why this matters: hand-written editorial JSON or LLM-generated
    brief drafts might emit lowercase. The canonical contract is
    upper-case from emit_brief, but the COMPUTER must accept any
    case to avoid silent under-reporting.
    """
    freezable = [
        {
            "issuer": "Sky Protocol",
            "token": "DAI",
            "total_usd": "$0.00",
            "holdings": [
                {"address": ZIGHA_ETH_DORMANT_DAI_1,
                 "usd": "$1,000,000.00", "status": "unrecoverable"},  # lowercase
                {"address": ZIGHA_ETH_DORMANT_DAI_2,
                 "usd": "$2,000,000.00", "status": "Unrecoverable"},  # mixed
            ],
        },
    ]
    total = _compute_perpetrator_holdings(freezable, [])
    assert total == Decimal("3000000.00"), (
        f"Case-insensitive UNRECOVERABLE handling regressed; "
        f"expected $3M, got {total}"
    )


# ─────────────────────────────────────────────────────────────────────
# Finding #4 + #31: INVARIANT A + letter-backed parity for LE handoffs.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_a_catches_bleed_in_le_handoff(tmp_path: Path) -> None:
    """Finding #4: pre-hardening the INVARIANT A test only exercised
    `freeze_request_*.html`. Jacob's v0.27.1 review cited the
    Threshold-LE handoff verbatim — that's an le_handoff_*.html. The
    validator already iterated both globs but no test pinned LE-side
    coverage.
    """
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)
    freeze_brief = {
        "DESTINATION_NOTES": {
            ZIGHA_BLEED_CONTRACT: "🟧 INVESTIGATE — 1inch reflective LP",
        },
    }
    # An LE handoff that incorrectly lists the bleed contract as a
    # FREEZABLE primary target.
    le_html = (
        "<!DOCTYPE html><html><body>"
        "<h1>LE Handoff — Threshold</h1>"
        "<h2>4.1 Recoverable Positions</h2>"
        "<table class=\"evidence\"><thead><tr><th>Status</th>"
        "<th>Address</th></tr></thead><tbody>"
        "<tr><td><span class=\"label-pill\">FREEZABLE</span></td>"
        f"<td><a href=\"https://etherscan.io/address/{ZIGHA_BLEED_CONTRACT}\">"
        f"{ZIGHA_BLEED_CONTRACT}</a></td></tr>"
        "</tbody></table>"
        "</body></html>"
    )
    _write_lf(briefs / "le_handoff_threshold_BRIEF-1.html", le_html)
    violations = _check_freeze_ask_targets_not_investigate_tagged(
        briefs, freeze_brief,
    )
    assert len(violations) == 1
    assert violations[0].severity == "high"
    assert violations[0].file == "le_handoff_threshold_BRIEF-1.html"
    assert ZIGHA_BLEED_CONTRACT in violations[0].detail.lower()


def test_letter_backed_by_freezable_row_catches_le_handoff(
    tmp_path: Path,
) -> None:
    """Finding #31: pre-hardening this check only iterated
    freeze_request_*.html. Jacob's Threshold-LE example is an LE
    handoff. Now the check covers both surfaces.

    Mutate INTO the Threshold-LE shape: an le_handoff_*.html with a
    primary-targets table that has NO FREEZABLE row at all (the
    Jacob-cited verbatim shape — "0 FREEZABLE addresses are the
    primary targets").
    """
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)
    le_html = (
        "<!DOCTYPE html><html><body>"
        "<h1>LE Handoff — Threshold</h1>"
        "<h2>4.1 Recoverable Positions</h2>"
        "<table class=\"evidence\"><thead><tr><th>Status</th>"
        "<th>Address</th></tr></thead><tbody>"
        # Only INVESTIGATE rows — no FREEZABLE.
        "<tr><td><span class=\"label-pill\">INVESTIGATE</span></td>"
        f"<td><a href=\"https://etherscan.io/address/{ZIGHA_BLEED_CONTRACT}\">"
        f"{ZIGHA_BLEED_CONTRACT}</a></td></tr>"
        "</tbody></table>"
        "<p>The 0 FREEZABLE addresses ($0 total) are the primary targets.</p>"
        "</body></html>"
    )
    _write_lf(briefs / "le_handoff_threshold_BRIEF-1.html", le_html)
    violations = _check_issuer_letter_backed_by_freezable_row(
        briefs, freeze_brief=None,
    )
    crits = [v for v in violations if v.severity == "critical"]
    assert len(crits) == 1, (
        "post-hardening the letter-backed check must fire on an "
        f"LE handoff with no FREEZABLE row; got {len(crits)} crits"
    )
    assert crits[0].file == "le_handoff_threshold_BRIEF-1.html"


# ─────────────────────────────────────────────────────────────────────
# Finding #5: _FREEZABLE_ROW_RE multi-row tbody pairing.
# ─────────────────────────────────────────────────────────────────────


def test_freezable_row_regex_pairs_status_to_correct_address() -> None:
    """Finding #5: the regex uses re.DOTALL with .*? between the
    FREEZABLE span and the first 0x... address. In a multi-row
    tbody, the regex must pair the FREEZABLE pill to ITS OWN row's
    address, not the next row's.

    HTML structure tested: row 1 = FREEZABLE addr-A, row 2 =
    INVESTIGATE addr-B. The regex must match addr-A from row 1 and
    NOT confuse with addr-B from row 2.

    Bug class this prevents: a regression that loosens the regex
    (e.g. switches .*? to .*) would pair the FREEZABLE pill with
    a later row's address — silently mis-attributing the violation
    or missing it entirely.
    """
    html = (
        "<tbody>"
        "<tr>"
        "<td><span>FREEZABLE</span></td>"
        f"<td><a href=\"https://x/{ZIGHA_ARB_HUB}\">addr-A</a></td>"
        "</tr>"
        "<tr>"
        "<td><span>INVESTIGATE</span></td>"
        f"<td><a href=\"https://x/{ZIGHA_BLEED_CONTRACT}\">addr-B</a></td>"
        "</tr>"
        "</tbody>"
    )
    matches = list(_FREEZABLE_ROW_RE.finditer(html))
    assert len(matches) == 1, (
        f"expected 1 FREEZABLE match in multi-row tbody, got {len(matches)}"
    )
    matched_addr = matches[0].group(1).lower()
    assert matched_addr == ZIGHA_ARB_HUB, (
        f"FREEZABLE pill must pair to its own row's address. "
        f"Got {matched_addr}, expected {ZIGHA_ARB_HUB} (addr-A)."
    )
    # Critical negative: the INVESTIGATE row's address must NOT
    # appear in any FREEZABLE match.
    assert ZIGHA_BLEED_CONTRACT not in matched_addr, (
        "FREEZABLE regex cross-paired to INVESTIGATE row's address — "
        "regex bug that would cause INVARIANT A to mis-fire."
    )


def test_freezable_row_regex_handles_three_row_interleaved_tbody() -> None:
    """Finding #5 extended: a 3-row tbody with FREEZABLE / INVESTIGATE
    / FREEZABLE order. The regex must find both FREEZABLE rows AND
    pair each to its own row's address."""
    html = (
        "<tbody>"
        f"<tr><td><span>FREEZABLE</span></td><td><a href=\"x/{ZIGHA_ARB_HUB}\">A</a></td></tr>"
        f"<tr><td><span>INVESTIGATE</span></td><td><a href=\"x/{ZIGHA_BLEED_CONTRACT}\">B</a></td></tr>"
        f"<tr><td><span>FREEZABLE</span></td><td><a href=\"x/{ZIGHA_ETH_DORMANT_DAI_1}\">C</a></td></tr>"
        "</tbody>"
    )
    addrs = sorted(m.group(1).lower() for m in _FREEZABLE_ROW_RE.finditer(html))
    assert addrs == sorted([ZIGHA_ARB_HUB, ZIGHA_ETH_DORMANT_DAI_1]), (
        f"regex must find both FREEZABLE addresses in their own "
        f"rows; got {addrs}"
    )


# ─────────────────────────────────────────────────────────────────────
# Finding #6 + #7 + #13: realistic Zigha numbers, DESTINATION_NOTES,
# headline reconciliation.
# ─────────────────────────────────────────────────────────────────────


def test_perpetrator_holdings_zigha_real_shape_no_inflation() -> None:
    """Finding #6: the lived Jacob Zigha shape. Pre-fix headline was
    $149.95M from $145M of INVESTIGATE bleed being summed. Post-fix
    real total is $7.9M (FREEZABLE+UNRECOVERABLE only). This test
    plugs in numbers matching the actual ratio Jacob observed and
    asserts the headline lands at $7.9M, NOT $152.9M.

    Inputs mirror the Zigha shape:
      * Tether issuer: $245K FREEZABLE row + $65M INVESTIGATE bleed
      * BitGo issuer: $0 FREEZABLE + $46M INVESTIGATE bleed
      * Circle issuer: $3.2M FREEZABLE + $33M INVESTIGATE bleed
      * Threshold issuer: $0 FREEZABLE + $163K INVESTIGATE bleed
      * Sky Protocol: $0 FREEZABLE + $4.4M UNRECOVERABLE DAI
      * Editorial UNRECOVERABLE: $0 (Sky-DAI captured via holdings)

    Expected output: $245K + $3.2M + $4.4M = $7.845M
    Pre-fix would have: $245K + $65M + $46M + $3.2M + $33M + $163K
                       + $4.4M = $152M  (21.6× the real number)

    If a future regression re-introduces summing INVESTIGATE rows,
    this test fires with a clear "inflation" message.
    """
    freezable = [
        {"issuer": "Tether", "token": "USDT",
         "total_usd": "$245,000.00",
         "holdings": [
             {"address": "0x" + "a" * 40,
              "usd": "$245,000.00", "status": "FREEZABLE"},
             {"address": ZIGHA_BLEED_CONTRACT,
              "usd": "$65,000,000.00", "status": "INVESTIGATE"},
         ]},
        {"issuer": "BitGo", "token": "WBTC",
         "total_usd": "$0.00",
         "holdings": [
             {"address": ZIGHA_BLEED_CONTRACT,
              "usd": "$46,762,084.33", "status": "INVESTIGATE"},
         ]},
        {"issuer": "Circle", "token": "USDC",
         "total_usd": "$3,200,000.00",
         "holdings": [
             {"address": "0x" + "b" * 40,
              "usd": "$3,200,000.00", "status": "FREEZABLE"},
             {"address": ZIGHA_BLEED_CONTRACT,
              "usd": "$33,140,762.13", "status": "INVESTIGATE"},
         ]},
        {"issuer": "Threshold", "token": "tBTC",
         "total_usd": "$0.00",
         "holdings": [
             {"address": ZIGHA_BLEED_CONTRACT,
              "usd": "$163,000.00", "status": "INVESTIGATE"},
         ]},
        {"issuer": "Sky Protocol", "token": "DAI",
         "total_usd": "$0.00",
         "holdings": [
             {"address": ZIGHA_ETH_DORMANT_DAI_1,
              "usd": "$4,400,000.00", "status": "UNRECOVERABLE"},
         ]},
    ]
    total = _compute_perpetrator_holdings(freezable, [])
    expected = Decimal("245000") + Decimal("3200000") + Decimal("4400000")
    assert total == expected, (
        f"Zigha-shape headline regressed; expected ${expected:,} "
        f"(0x52Aa-bleed-free), got ${total:,}. Pre-v0.27.2 this "
        f"shape returned $152M+ — a 19.4× inflation. If you see a "
        f"large number here, the INVESTIGATE-exclusion regressed."
    )
    # Ratio sanity check: total should be small relative to bleed.
    # The real Zigha shape has total ≈ 5.4% of bleed (post-fix).
    # A pre-fix regression would have total ≈ 105% of bleed
    # (because the bleed gets summed into the headline).
    # Threshold at 20% cleanly separates post-fix (5.4%) from
    # pre-fix (~105%). If this ever crosses 20%, the bleed is
    # leaking into the headline somehow.
    assert total < ZIGHA_BLEED_INVESTIGATE * Decimal("0.20"), (
        f"perpetrator-holdings ${total:,} is more than 20% of the "
        f"INVESTIGATE bleed total ${ZIGHA_BLEED_INVESTIGATE:,} — "
        f"the bleed is leaking into the headline. Pre-v0.27.2 this "
        f"ratio was ~105% (21.6× the real number)."
    )


def test_perpetrator_holdings_reconcile_check_catches_inflation(
    tmp_path: Path,
) -> None:
    """Finding #13: the new cross-artifact reconciliation INVARIANT.
    Mutate INTO the Zigha v0.27.1 shape: trace_report.html shows
    $149.95M headline while freeze_brief totals add to $7.9M.

    The check must fire as a high-severity violation with the
    inflation ratio surfaced in the message.
    """
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "Circle", "token": "USDC",
             "total_usd": "$3,500,000.00",
             "holdings": [
                 {"address": "0x" + "a" * 40,
                  "usd": "$3,500,000.00", "status": "FREEZABLE"},
             ]},
        ],
        "UNRECOVERABLE": [
            {"address": ZIGHA_ETH_DORMANT_DAI_1,
             "asset": "approximately 4.4M DAI (~$4,400,000)",
             "reason": "Dormant"},
        ],
    }
    # trace_report shows the WRONG (pre-fix) headline.
    trace_html = (
        "<!DOCTYPE html><html><body>"
        "<h1>Trace Report</h1>"
        "<p><strong>Perpetrator-controlled holdings: $149,954,529.44</strong></p>"
        "</body></html>"
    )
    _write_lf(briefs / "trace_report_abc.html", trace_html)
    violations = _check_perpetrator_holdings_reconcile(briefs, freeze_brief)
    assert len(violations) == 1
    v = violations[0]
    assert v.severity == "high"
    assert "inflation" in v.detail.lower()
    # The ratio should be roughly 19× (149.95M / 7.9M)
    assert "19" in v.detail, (
        f"inflation ratio should be ~19×; detail: {v.detail}"
    )


def test_perpetrator_holdings_reconcile_passes_when_consistent(
    tmp_path: Path,
) -> None:
    """Positive case for the new reconciliation INVARIANT: when
    headline matches brief totals (within tolerance), zero
    violations."""
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "Circle", "token": "USDC",
             "total_usd": "$3,500,000.00",
             "holdings": []},
        ],
        "UNRECOVERABLE": [
            {"asset": "approximately 4.4M DAI (~$4,400,000)"},
        ],
    }
    trace_html = (
        "<html><body><p>Perpetrator-controlled holdings: $7,900,000.00</p>"
        "</body></html>"
    )
    _write_lf(briefs / "trace_report_xyz.html", trace_html)
    violations = _check_perpetrator_holdings_reconcile(briefs, freeze_brief)
    assert violations == []


def test_perpetrator_holdings_reconcile_tolerance_at_1pct(
    tmp_path: Path,
) -> None:
    """Reconciliation must tolerate small rounding differences. 1%
    tolerance covers e.g. $7,900,000 vs $7,978,000 (within ~1%)."""
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "X", "token": "Y",
             "total_usd": "$7,900,000.00", "holdings": []},
        ],
    }
    # Headline within 1% — within tolerance.
    trace_html = (
        "<html><body><p>Perpetrator-controlled holdings: $7,978,000.00</p>"
        "</body></html>"
    )
    _write_lf(briefs / "trace_report_a.html", trace_html)
    assert _check_perpetrator_holdings_reconcile(briefs, freeze_brief) == []
    # Headline 5% off — outside tolerance, must fire.
    trace_html_off = (
        "<html><body><p>Perpetrator-controlled holdings: $8,295,000.00</p>"
        "</body></html>"
    )
    _write_lf(briefs / "trace_report_b.html", trace_html_off)
    # First match wins, so we use a separate dir
    case_dir2 = tmp_path / "case2"
    briefs2 = case_dir2 / "briefs"
    briefs2.mkdir(parents=True)
    _write_lf(briefs2 / "trace_report_b.html", trace_html_off)
    violations = _check_perpetrator_holdings_reconcile(briefs2, freeze_brief)
    assert len(violations) == 1


# ─────────────────────────────────────────────────────────────────────
# Finding #10 + #32: ground-truth fixture count-canary + provenance keys.
# ─────────────────────────────────────────────────────────────────────


def test_zigha_ground_truth_fixture_has_documented_address_count() -> None:
    """Finding #10: the fixture lists confirmed Zigha destinations.
    As more (ZIGHA-ETH-26D20f, -37fc5f, -c1ee32) resolve to full
    hex, the operator must update the fixture. Pin the expected
    count here so a silent edit that DROPS an address is caught.

    History:
      * v0.27.2 shipped with 3 addresses (Arbitrum hub + 2 dormant
        DAI).
      * v0.28.4 added the 4th address (Midas mSyrupUSDp at
        0x3e2E66af967075120fa8bE27C659d0803DfF4436) resolved from
        a multi-file test-fixture cross-reference. This is the
        only Zigha destination with a freeze pathway.
      * 3 more (ZIGHA-ETH-26D20f, -37fc5f, -c1ee32) remain unresolved
        — full hex requires the CFI PDF + Etherscan manual lookup.
    """
    fixture_path = (
        Path(__file__).parent / "fixtures" / "zigha_ground_truth.json"
    )
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    expected = payload.get("expected_destinations") or []
    # Pin the count. Bump this when more Zigha addresses resolve.
    PINNED_COUNT = 4
    assert len(expected) >= PINNED_COUNT, (
        f"zigha_ground_truth.json has {len(expected)} expected "
        f"destinations; pin requires at least {PINNED_COUNT}. If "
        f"you intentionally removed one, bump PINNED_COUNT down "
        f"with a comment explaining why."
    )


def test_zigha_ground_truth_contains_midas_msyrup_destination() -> None:
    """v0.28.4 addition: the Midas mSyrupUSDp address is the ONLY
    Zigha destination with a freeze pathway. If a future edit
    accidentally drops it, the only-actionable-freeze-target on
    the case disappears — INVARIANT B would catch the omission at
    validate time, but pin it directly here too."""
    fixture_path = (
        Path(__file__).parent / "fixtures" / "zigha_ground_truth.json"
    )
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    expected = payload.get("expected_destinations") or []
    midas_addr = "0x3e2e66af967075120fa8be27c659d0803dff4436"  # lowercase
    addrs = [e.get("address", "").lower() for e in expected]
    assert midas_addr in addrs, (
        "Zigha ground-truth fixture missing the Midas mSyrupUSDp "
        f"destination ({midas_addr}). This is the only freezable "
        "position in the Zigha case — dropping it removes the "
        "only actionable freeze target."
    )


def test_zigha_ground_truth_fixture_has_provenance_keys() -> None:
    """Finding #32: the fixture documents these provenance keys for
    operator-curation traceability. Silent edits dropping them are
    bad — assert presence here."""
    fixture_path = (
        Path(__file__).parent / "fixtures" / "zigha_ground_truth.json"
    )
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    for key in ("_curated_by", "_curated_at", "_v"):
        assert key in payload, (
            f"zigha_ground_truth.json missing required provenance "
            f"key {key!r}. Provenance is mandatory for any operator-"
            f"curated fixture; see other curated fixtures for the "
            f"schema."
        )
    # _curated_at must look ISO-8601-ish.
    assert re.match(r"^\d{4}-\d{2}-\d{2}", payload["_curated_at"]), (
        f"_curated_at must start with YYYY-MM-DD; got "
        f"{payload['_curated_at']!r}"
    )


# ─────────────────────────────────────────────────────────────────────
# Finding #15 + #16: INVARIANT B via-EXCHANGES + via-ALL_ISSUER_HOLDINGS.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_match_via_exchanges_satisfies(tmp_path: Path) -> None:
    """Finding #15: _extract_brief_addresses scans EXCHANGES but no
    INVARIANT B test exercises that surface. A MEXC off-ramp
    address that lands in brief.EXCHANGES (not DESTINATIONS) must
    still satisfy the ground-truth superset property."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "ground_truth.json").write_text(json.dumps({
        "expected_destinations": [
            {"address": ZIGHA_ARB_HUB, "chain": "ethereum",
             "role": "off-ramp", "source": "test"},
        ],
    }), encoding="utf-8")
    freeze_brief = {
        "DESTINATIONS": [],
        "EXCHANGES": [
            {"address": ZIGHA_ARB_HUB, "exchange": "MEXC"},
        ],
    }
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief,
    )
    assert violations == [], (
        "INVARIANT B must accept a match via the EXCHANGES surface; "
        f"got {violations}"
    )


def test_invariant_b_match_via_all_issuer_holdings_satisfies(
    tmp_path: Path,
) -> None:
    """Finding #16: ALL_ISSUER_HOLDINGS carries UNRECOVERABLE-only
    addresses (Sky/DAI). INVARIANT B must accept matches there."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "ground_truth.json").write_text(json.dumps({
        "expected_destinations": [
            {"address": ZIGHA_ETH_DORMANT_DAI_1, "chain": "ethereum",
             "role": "dormant DAI", "source": "test"},
        ],
    }), encoding="utf-8")
    freeze_brief = {
        "DESTINATIONS": [],
        "ALL_ISSUER_HOLDINGS": [
            {"issuer": "Sky Protocol", "token": "DAI",
             "address": ZIGHA_ETH_DORMANT_DAI_1,
             "amount_usd": "$9,980,000.00", "status": "UNRECOVERABLE"},
        ],
    }
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief,
    )
    assert violations == [], (
        "INVARIANT B must accept a match via the ALL_ISSUER_HOLDINGS "
        f"surface; got {violations}"
    )


# ─────────────────────────────────────────────────────────────────────
# Finding #20: _canonicalize_for_compare fallback path.
# ─────────────────────────────────────────────────────────────────────


def test_canonicalize_for_compare_handles_typical_evm_address() -> None:
    """Finding #20 prep: positive test for canonical-form
    conversion. The function delegates to
    recupero._common.canonical_address_key in normal operation."""
    # EIP-55 checksum input → lower-case canonical.
    out = _canonicalize_for_compare(
        "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2",
    )
    assert out == ZIGHA_ARB_HUB


def test_canonicalize_for_compare_fallback_on_import_failure(
    monkeypatch,
) -> None:
    """Finding #20: the fallback path returns (addr or '').strip()
    .lower() if recupero._common.canonical_address_key raises. We
    can't easily simulate an import error in a single test, but we
    can simulate the function itself raising and confirm the
    fallback returns the lowercase form.

    Pre-hardening this branch was untested — a subtle bug in
    canonical_address_key (e.g. checksumming or len-validation)
    would silently mask itself.
    """
    import recupero._common as common
    original_fn = common.canonical_address_key

    def boom(_addr: str) -> str:
        raise RuntimeError("simulated canonicalizer failure")

    monkeypatch.setattr(common, "canonical_address_key", boom)
    out = _canonicalize_for_compare(
        "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2",
    )
    # Fallback path strips + lower-cases.
    assert out == ZIGHA_ARB_HUB
    # Restore (monkeypatch handles it but defensive).
    monkeypatch.setattr(common, "canonical_address_key", original_fn)


# ─────────────────────────────────────────────────────────────────────
# Finding #25: specific role/source string in INVARIANT B detail.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_detail_contains_specific_role_and_source(
    tmp_path: Path,
) -> None:
    """Finding #25: the violation detail must include the SPECIFIC
    role + source strings from the fixture (not just the words
    'role' and 'source'). This is what makes the validator
    actionable — the operator reading the violation must see
    'role: Arbitrum-side consolidation hub' immediately, not
    have to dig back into the fixture."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    SPECIFIC_ROLE = "Arbitrum-side consolidation hub (verified PERP1)"
    SPECIFIC_SOURCE = "Zigha CFI-00265 + journal.txt L25"
    (case_dir / "ground_truth.json").write_text(json.dumps({
        "expected_destinations": [
            {"address": ZIGHA_ARB_HUB, "chain": "arbitrum",
             "role": SPECIFIC_ROLE, "source": SPECIFIC_SOURCE,
             "approx_usd": 18130000},
        ],
    }), encoding="utf-8")
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief={"DESTINATIONS": []},
    )
    assert len(violations) == 1
    v = violations[0]
    assert SPECIFIC_ROLE in v.detail, (
        f"violation detail must contain the SPECIFIC role string "
        f"'{SPECIFIC_ROLE}'; got: {v.detail}"
    )
    assert SPECIFIC_SOURCE in v.detail, (
        f"violation detail must contain the SPECIFIC source string "
        f"'{SPECIFIC_SOURCE}'; got: {v.detail}"
    )
    # USD hint also surfaces.
    assert "18,130,000" in v.detail


# ─────────────────────────────────────────────────────────────────────
# Finding #23: integration test for _has_freezable_holding in
# build_all_deliverables flow.
# ─────────────────────────────────────────────────────────────────────


def test_has_freezable_holding_gates_letter_generation_integration(
    tmp_path: Path, monkeypatch,
) -> None:
    """Finding #23: the function is tested in isolation but no test
    verifies the GATE is actually invoked by build_all_deliverables.
    A regression that removes the `if not _has_freezable_holding:
    continue` line wouldn't be caught by any prior test.

    We invoke the gate function's call site directly. The contract:
    when build_all_deliverables iterates FREEZABLE entries, it must
    skip any entry where _has_freezable_holding(entry) is False.

    We assert this by importing the deliverables module and
    asserting the gate function is referenced in the module's
    source code (a structural check, since fully exercising the
    pipeline needs a DB + worker context).
    """
    import inspect

    from recupero.worker import _deliverables as deliv_mod
    src = inspect.getsource(deliv_mod)
    # The gate must be CALLED somewhere in the deliverables module.
    # Both names ("_has_actionable_holding" alias + "_has_freezable_holding")
    # are accepted.
    has_gate_call = (
        "_has_freezable_holding(" in src
        or "_has_actionable_holding(" in src
    )
    assert has_gate_call, (
        "build_all_deliverables (or surrounding code) no longer "
        "calls _has_freezable_holding / _has_actionable_holding. "
        "The gate that suppresses BitGo / Threshold $0-FREEZABLE "
        "letters has been disabled. This is the Jacob v0.27.1 "
        "regression — the per-issuer letter loop must early-out "
        "on entries with no FREEZABLE row."
    )


# ─────────────────────────────────────────────────────────────────────
# Finding #12: INVESTIGATE-only tbody mutation (real pre-fix shape).
# ─────────────────────────────────────────────────────────────────────


def test_letter_backed_check_catches_investigate_only_tbody(
    tmp_path: Path,
) -> None:
    """Finding #12: the existing pre-fix mutation test uses an EMPTY
    tbody (no rows at all). The actual Zigha v0.27.1 BitGo letter
    had a tbody with a single INVESTIGATE-only row for the 0x52Aa
    bleed — non-empty but missing a FREEZABLE pill. Pin this exact
    shape.
    """
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)
    html = (
        "<!DOCTYPE html><html><body>"
        "<h1>Freeze Request — BitGo</h1>"
        "<table class=\"evidence\"><thead><tr><th>Status</th>"
        "<th>Address</th></tr></thead><tbody>"
        # The actual Zigha shape: only INVESTIGATE rows, no FREEZABLE.
        "<tr><td><span class=\"label-pill\">INVESTIGATE</span></td>"
        f"<td><a href=\"https://etherscan.io/address/{ZIGHA_BLEED_CONTRACT}\">"
        f"{ZIGHA_BLEED_CONTRACT}</a></td></tr>"
        "</tbody></table>"
        "</body></html>"
    )
    _write_lf(briefs / "freeze_request_bitgo_BRIEF-1.html", html)
    violations = _check_issuer_letter_backed_by_freezable_row(
        briefs, freeze_brief=None,
    )
    crits = [v for v in violations if v.severity == "critical"]
    assert len(crits) == 1, (
        "INVESTIGATE-only tbody must fail letter-backed-by-freezable; "
        f"got {[v.detail for v in violations]}"
    )
    assert "no FREEZABLE-tagged row" in crits[0].detail
