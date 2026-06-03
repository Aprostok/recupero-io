"""Regression tests for Jacob's V-CFI02 review — the 0x52Aa INVESTIGATE
bleed into the freeze-ask path.

Context (Jacob, V-CFI02 on v0.32.0):
  The trace-report headline fix landed ($3.5M perpetrator-controlled,
  not $150M) and the $0-FREEZABLE standalone-letter guard worked
  (BitGo + Threshold got no standalone letter). But the smart-contract
  bleed address 0x52Aa…e497 — correctly tagged 🟧 INVESTIGATE in the
  brief's DESTINATION_NOTES ("protocol liquidity; do not include in
  freeze requests") — STILL leaked into:

    1. freeze_asks.json as a per-issuer freeze target
       (Tether $38.9M / BitGo $35.6M / Circle $14.3M / Threshold $151K)
    2. the Tether + Circle freeze letters' "under investigation" totals
    3. the LE handoff "Recommended Actions → parallel preservation
       requests" block recommending BitGo ($0 FREEZABLE + $35.6M
       INVESTIGATE) and Threshold ($0 + $151K INVESTIGATE)

The fix (v0.36.0):
  * emit_brief._extract_freezable drops INVESTIGATE holdings from the
    letter-facing FREEZABLE list (keep_all=False); they remain in
    ALL_ISSUER_HOLDINGS (keep_all=True) for the LE Section 4.2
    complete-inventory disclosure only.
  * brief._build_secondary_preservation_targets requires CONFIRMED
    FREEZABLE > $0 (was: FREEZABLE OR suspected > $0).
  * run_emit_brief partitions INVESTIGATE asks out of freeze_asks.json
    by_issuer into excluded_investigate (idempotent via
    _fold_excluded_investigate).
  * validators.output_integrity INVARIANT A2
    (investigate_not_billed_as_freeze_target) fails the build on any
    regression across all three surfaces, and INVARIANT A now actually
    fires (it previously sourced its INVESTIGATE set from the absent
    freeze_brief.DESTINATION_NOTES).

Validator invariant (Jacob's words): "no address tagged INVESTIGATE in
DESTINATION_NOTES may appear as a freeze target in freeze_asks.json, any
freeze_request_*, or any le_handoff_* recommended-action block. Fail the
build, not warn."
"""

from __future__ import annotations

import json
from pathlib import Path

from recupero.reports.brief import _build_secondary_preservation_targets
from recupero.reports.emit_brief import (
    _extract_freezable,
    _fold_excluded_investigate,
    _partition_investigate_asks,
)
from recupero.validators.output_integrity import (
    _check_investigate_not_billed_as_freeze_target,
    _investigate_tagged_addresses,
    validate_case_output,
)

# ── Real V-CFI02 addresses (canonical lowercase used for asks/notes) ──
BLEED = "0x52aa899454998be5b000ad077a46bbe360f4e497"  # 0x52Aa pool contract
TETHER_FREEZABLE = "0x00000688768803bbd44095770895ad27ad6b0d95"
CIRCLE_FREEZABLE = "0x6482e8fb42130b3cce53096bb035ebe79435e2d4"
MIDAS_FREEZABLE = "0x3e2e66af967075120fa8be27c659d0803dff4436"

_NOTE_INVESTIGATE = (
    "🟧 INVESTIGATE — Smart contract (is_contract=true) holding very "
    "large aggregate balances with 200x–546x balance-to-inflow ratios; "
    "protocol liquidity, do NOT include in freeze requests."
)
_NOTE_FREEZABLE = "🟩 FREEZABLE — issuer can freeze this holder."


def _vcfi02_freeze_asks() -> dict:
    """The raw freeze_asks.json shape the freeze stage emits BEFORE the
    INVESTIGATE partition — 0x52Aa under four issuers, plus the real
    freezable holdings."""
    return {
        "case_id": "VCFI02",
        "total_asks": 6,
        "by_issuer": {
            "Tether": [
                {"address": BLEED, "chain": "ethereum", "symbol": "USDT",
                 "amount": "38892365.236045", "usd_value": "38892365.24",
                 "freeze_capability": "yes", "evidence_type": "current_balance"},
                {"address": TETHER_FREEZABLE, "chain": "ethereum",
                 "symbol": "USDT", "amount": "170687.256795",
                 "usd_value": "170687.26", "freeze_capability": "yes",
                 "evidence_type": "historical_inflow"},
            ],
            "BitGo / BiT Global": [
                {"address": BLEED, "chain": "ethereum", "symbol": "WBTC",
                 "amount": "513.23478962", "usd_value": "35588213.55",
                 "freeze_capability": "limited",
                 "evidence_type": "current_balance"},
            ],
            "Circle": [
                {"address": BLEED, "chain": "ethereum", "symbol": "USDC",
                 "amount": "14271503.635252", "usd_value": "14271503.64",
                 "freeze_capability": "yes", "evidence_type": "current_balance"},
                {"address": CIRCLE_FREEZABLE, "chain": "ethereum",
                 "symbol": "USDC", "amount": "8881.313349",
                 "usd_value": "8881.31", "freeze_capability": "yes",
                 "evidence_type": "historical_inflow"},
            ],
            "Midas": [
                {"address": MIDAS_FREEZABLE, "chain": "ethereum",
                 "symbol": "msyrupUSDp", "amount": "3109861.71576",
                 "usd_value": "3271574.52", "freeze_capability": "yes",
                 "evidence_type": "current_balance"},
            ],
        },
        "exchange_deposits": [],
        "onward_cex_flows": [],
    }


def _vcfi02_editorial_notes() -> dict:
    return {
        BLEED: _NOTE_INVESTIGATE,
        TETHER_FREEZABLE: _NOTE_FREEZABLE,
        CIRCLE_FREEZABLE: _NOTE_FREEZABLE,
        MIDAS_FREEZABLE: _NOTE_FREEZABLE,
    }


# ─────────────────────────────────────────────────────────────────────
# Fix A — _extract_freezable excludes INVESTIGATE from the letter list.
# ─────────────────────────────────────────────────────────────────────

def test_extract_freezable_drops_investigate_from_letter_list() -> None:
    notes = _vcfi02_editorial_notes()
    letters = _extract_freezable(_vcfi02_freeze_asks(), {}, notes)
    by_issuer = {e["issuer"]: e for e in letters}

    # Tether: 0x52Aa dropped; only the real $170K historical FREEZABLE
    # holding remains; suspected total is $0 (no "under investigation").
    assert "Tether" in by_issuer
    tether = by_issuer["Tether"]
    tether_addrs = {h["address"] for h in tether["holdings"]}
    assert BLEED not in tether_addrs, "0x52Aa bleed must not reach the letter"
    assert TETHER_FREEZABLE in tether_addrs
    assert tether["total_suspected_usd"] in ("$0", "$0.00")
    assert tether["total_usd"] not in ("$0", "$0.00")

    # Circle: same — bleed gone, real $8.9K FREEZABLE kept, $0 suspected.
    circle = by_issuer["Circle"]
    assert BLEED not in {h["address"] for h in circle["holdings"]}
    assert circle["total_suspected_usd"] in ("$0", "$0.00")

    # BitGo: its ONLY holding was the 0x52Aa bleed → the issuer drops
    # out of the letter list entirely (no $0-FREEZABLE outreach letter).
    assert "BitGo / BiT Global" not in by_issuer

    # Midas: untouched — real $3.27M FREEZABLE.
    assert "Midas" in by_issuer


def test_extract_freezable_keeps_investigate_in_all_issuer_view() -> None:
    """ALL_ISSUER_HOLDINGS (keep_all=True) is the LE Section 4.2
    complete-inventory disclosure — it MUST still list the INVESTIGATE
    bleed (labeled), so law enforcement sees the full picture."""
    notes = _vcfi02_editorial_notes()
    all_view = _extract_freezable(
        _vcfi02_freeze_asks(), {}, notes, keep_all=True,
    )
    by_issuer = {e["issuer"]: e for e in all_view}
    # BitGo survives in the complete inventory...
    assert "BitGo / BiT Global" in by_issuer
    # ...and the bleed holding is present, tagged INVESTIGATE.
    bitgo_holdings = by_issuer["BitGo / BiT Global"]["holdings"]
    bleed_rows = [h for h in bitgo_holdings if h["address"] == BLEED]
    assert bleed_rows and bleed_rows[0]["status"] == "INVESTIGATE"


# ─────────────────────────────────────────────────────────────────────
# Fix B — secondary preservation targets require real FREEZABLE > $0.
# ─────────────────────────────────────────────────────────────────────

def test_secondary_preservation_excludes_zero_freezable_issuers() -> None:
    all_issuers = [
        {"issuer": "Midas", "token": "msyrupUSDp",
         "total_usd": "$3,271,574.52", "total_suspected_usd": "$0",
         "freeze_capability": "HIGH", "contact_email": "compliance@midas.app"},
        {"issuer": "Tether", "token": "USDT",
         "total_usd": "$245,436.64", "total_suspected_usd": "$0",
         "freeze_capability": "HIGH", "contact_email": "compliance@tether.to"},
        # Zero confirmed FREEZABLE, only INVESTIGATE bleed — must NOT be
        # recommended as a parallel preservation target.
        {"issuer": "BitGo / BiT Global", "token": "WBTC",
         "total_usd": "$0", "total_suspected_usd": "$35,588,213.55",
         "freeze_capability": "MEDIUM", "contact_email": "compliance@bitgo.com"},
        {"issuer": "Threshold Network", "token": "TBTC",
         "total_usd": "$0", "total_suspected_usd": "$151,042.04",
         "freeze_capability": "LOW", "contact_email": ""},
    ]
    secondaries = _build_secondary_preservation_targets(
        primary_issuer_name="Midas", all_issuers_freezable=all_issuers,
    )
    names = {s["issuer_name"] for s in secondaries}
    assert names == {"Tether"}, (
        "only confirmed-FREEZABLE issuers may be recommended; got "
        f"{names}"
    )


# ─────────────────────────────────────────────────────────────────────
# Fix C — freeze_asks.json partition + idempotent fold-back.
# ─────────────────────────────────────────────────────────────────────

def test_partition_moves_investigate_out_of_by_issuer() -> None:
    notes = _vcfi02_editorial_notes()
    cleaned = _partition_investigate_asks(_vcfi02_freeze_asks(), notes)

    # No issuer's by_issuer list may contain the bleed.
    for issuer, asks in cleaned["by_issuer"].items():
        assert all(a["address"] != BLEED for a in asks), (
            f"{issuer} still lists the 0x52Aa bleed as a freeze target"
        )
    # BitGo had ONLY the bleed → it disappears from by_issuer entirely.
    assert "BitGo / BiT Global" not in cleaned["by_issuer"]
    # The excluded_investigate section captures every bleed ask (one per
    # issuer that listed it: Tether, BitGo, Circle = 3).
    excluded = cleaned["excluded_investigate"]
    assert cleaned["excluded_investigate_count"] == len(excluded) == 3
    assert all(e["address"] == BLEED for e in excluded)
    assert {e["issuer"] for e in excluded} == {
        "Tether", "BitGo / BiT Global", "Circle",
    }
    # total_asks recounts only the kept asks (3 real freezable holdings).
    assert cleaned["total_asks"] == 3


def test_partition_then_fold_is_idempotent() -> None:
    notes = _vcfi02_editorial_notes()
    original = _vcfi02_freeze_asks()
    cleaned = _partition_investigate_asks(original, notes)
    # Folding the excluded section back reconstructs the full set, so a
    # re-emit re-partitions to the same result (no data loss on re-run).
    folded = _fold_excluded_investigate(cleaned)
    re_cleaned = _partition_investigate_asks(folded, notes)
    assert "excluded_investigate" not in folded
    assert re_cleaned["by_issuer"] == cleaned["by_issuer"]
    assert re_cleaned["excluded_investigate_count"] == 3
    # The folded set restores BitGo (had only the bleed) to by_issuer.
    assert "BitGo / BiT Global" in folded["by_issuer"]


# ─────────────────────────────────────────────────────────────────────
# INVARIANT A2 — the build-failing validator.
# ─────────────────────────────────────────────────────────────────────

def _clean_brief() -> dict:
    """A POST-fix freeze_brief: FREEZABLE carries only real freezable
    holdings ($0 suspected); ALL_ISSUER_HOLDINGS discloses the bleed as
    INVESTIGATE; DESTINATIONS tags the bleed INVESTIGATE."""
    return {
        "CASE_ID": "VCFI02",
        "DESTINATIONS": [
            {"address": BLEED, "status": "INVESTIGATE",
             "role": "Smart contract — protocol liquidity"},
            {"address": MIDAS_FREEZABLE, "status": "FREEZABLE"},
        ],
        "FREEZABLE": [
            {"issuer": "Tether", "token": "USDT",
             "total_usd": "$245,436.64", "total_suspected_usd": "$0",
             "holdings": [
                 {"address": TETHER_FREEZABLE, "usd": "$170,687.26",
                  "status": "FREEZABLE"},
             ]},
            {"issuer": "Midas", "token": "msyrupUSDp",
             "total_usd": "$3,271,574.52", "total_suspected_usd": "$0",
             "holdings": [
                 {"address": MIDAS_FREEZABLE, "usd": "$3,271,574.52",
                  "status": "FREEZABLE"},
             ]},
        ],
        "ALL_ISSUER_HOLDINGS": [
            {"issuer": "Tether", "token": "USDT", "total_usd": "$245,436.64",
             "holdings": [
                 {"address": BLEED, "usd": "$38,892,365.24",
                  "status": "INVESTIGATE"},
                 {"address": TETHER_FREEZABLE, "usd": "$170,687.26",
                  "status": "FREEZABLE"},
             ]},
        ],
    }


def test_invariant_a2_passes_on_clean_bundle(tmp_path: Path) -> None:
    briefs = tmp_path / "briefs"
    briefs.mkdir(parents=True)
    cleaned_asks = _partition_investigate_asks(
        _vcfi02_freeze_asks(), _vcfi02_editorial_notes(),
    )
    violations = _check_investigate_not_billed_as_freeze_target(
        briefs, cleaned_asks, _clean_brief(),
    )
    assert violations == [], (
        "clean V-CFI02 bundle must produce zero violations; got: "
        + "; ".join(v.detail for v in violations)
    )


def test_invariant_a2_catches_dirty_freeze_asks(tmp_path: Path) -> None:
    """freeze_asks.json still listing the bleed in by_issuer → critical."""
    briefs = tmp_path / "briefs"
    briefs.mkdir(parents=True)
    dirty_asks = _vcfi02_freeze_asks()  # un-partitioned: bleed in by_issuer
    violations = _check_investigate_not_billed_as_freeze_target(
        briefs, dirty_asks, _clean_brief(),
    )
    freeze_asks_crits = [
        v for v in violations
        if v.file == "freeze_asks.json" and v.severity == "critical"
    ]
    assert freeze_asks_crits, "dirty freeze_asks.json by_issuer must fail"


def test_invariant_a2_catches_investigate_in_freezable_and_suspected(
    tmp_path: Path,
) -> None:
    """FREEZABLE list carrying an INVESTIGATE holding OR a non-zero
    suspected total → critical (both are letter-rendering surfaces)."""
    briefs = tmp_path / "briefs"
    briefs.mkdir(parents=True)
    bad_brief = _clean_brief()
    bad_brief["FREEZABLE"][0]["holdings"].append(
        {"address": BLEED, "usd": "$38,892,365.24", "status": "INVESTIGATE"},
    )
    bad_brief["FREEZABLE"][0]["total_suspected_usd"] = "$38,892,365.24"
    cleaned_asks = _partition_investigate_asks(
        _vcfi02_freeze_asks(), _vcfi02_editorial_notes(),
    )
    violations = _check_investigate_not_billed_as_freeze_target(
        briefs, cleaned_asks, bad_brief,
    )
    crits = [v for v in violations if v.severity == "critical"]
    details = " ".join(v.detail for v in crits)
    assert "INVESTIGATE-status" in details
    assert "under investigation" in details


def test_invariant_a2_catches_zero_freezable_in_le_preservation(
    tmp_path: Path,
) -> None:
    """LE handoff parallel-preservation block recommending a
    '$0 FREEZABLE' issuer → critical."""
    briefs = tmp_path / "briefs"
    briefs.mkdir(parents=True)
    (briefs / "le_handoff_tether_BRIEF-VCFI02-1.html").write_text(
        "<html><body><h2>6. Recommended Actions</h2>"
        "<li><strong>Parallel preservation requests:</strong> issue to:"
        "<ul><li><strong>BitGo / BiT Global</strong> (WBTC; $0 FREEZABLE "
        "+ $35,588,213.55 INVESTIGATE) — freeze capability MEDIUM.</li>"
        "</ul></li></body></html>",
        encoding="utf-8",
    )
    cleaned_asks = _partition_investigate_asks(
        _vcfi02_freeze_asks(), _vcfi02_editorial_notes(),
    )
    violations = _check_investigate_not_billed_as_freeze_target(
        briefs, cleaned_asks, _clean_brief(),
    )
    le_crits = [
        v for v in violations
        if v.file.startswith("le_handoff_") and v.severity == "critical"
    ]
    assert le_crits, "the '$0 FREEZABLE' preservation recommendation must fail"


def test_investigate_tagged_addresses_reads_destination_status() -> None:
    """The shared extractor must surface INVESTIGATE from DESTINATIONS
    status (emit_brief does not write DESTINATION_NOTES into the brief —
    the pre-v0.36.0 INVARIANT A sourced only that and silently no-op'd)."""
    canon = _investigate_tagged_addresses(_clean_brief())
    assert BLEED in canon
    assert MIDAS_FREEZABLE not in canon


def test_invariant_a2_registered_in_validate_case_output(tmp_path: Path) -> None:
    """Smoke: the new check is wired into the dispatcher so it gates the
    build, not just callable in isolation."""
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)
    cleaned_asks = _partition_investigate_asks(
        _vcfi02_freeze_asks(), _vcfi02_editorial_notes(),
    )
    (case_dir / "freeze_asks.json").write_text(
        json.dumps(cleaned_asks), encoding="utf-8",
    )
    (case_dir / "freeze_brief.json").write_text(
        json.dumps(_clean_brief()), encoding="utf-8",
    )
    result = validate_case_output(case_dir)
    assert "investigate_not_billed_as_freeze_target" in result.checks_run
    a2 = [
        v for v in result.violations
        if v.check == "investigate_not_billed_as_freeze_target"
    ]
    assert a2 == [], f"clean bundle must not trip A2; got {[v.detail for v in a2]}"
