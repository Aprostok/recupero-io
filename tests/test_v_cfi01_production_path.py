"""V-CFI01 production path test — exercises build_all_deliverables().

This is the test Jacob actually runs: it simulates the FULL production
worker path (emit_brief → build_all_deliverables → verify output files)
NOT just the render functions in isolation.

The render unit tests (test_v_cfi01_full_render.py) call generate_briefs()
directly. The PRODUCTION worker calls build_all_deliverables(), which
wraps generate_briefs() in a try/except that swallows errors silently.
This test exercises that path so silent failures in production are caught.

Pipeline under test:
  1. emit_brief()            — assembles freeze_brief dict (no file I/O)
  2. build_all_deliverables() — calls generate_briefs() per issuer, writes
                                HTML + SVG + CSV/JSON to case_dir/briefs/
  3. Assertions              — verify every expected file was written and
                                contains the correct content
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from tests.test_v_cfi01_full_render import (
    _build_editorial,
    _build_freeze_asks_dict,
    _build_issuer_metadata,
    _build_v_cfi01_case,
    VICTIM,
)
from recupero.reports.brief import InvestigatorInfo
from recupero.reports.emit_brief import emit_brief
from recupero.reports.victim import VictimInfo
from recupero.worker._deliverables import build_all_deliverables


# ─────────────────────────────────────────────────────────────────────────────
# Module-scoped fixture: run the full production path ONCE, share results
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def production_run() -> dict:
    """Run emit_brief → build_all_deliverables with V-CFI01 data.

    Returns a dict with:
      briefs_dir   — Path to the written briefs/ directory
      brief_data   — the emit_brief() output dict
      le_htmls     — list of LE handoff HTML strings
      freeze_htmls — list of issuer freeze letter HTML strings
      warnings     — list of warning messages captured from recupero logger
    """
    import logging

    case = _build_v_cfi01_case()
    editorial = _build_editorial()
    freeze_asks = _build_freeze_asks_dict()
    issuer_metadata = _build_issuer_metadata()

    victim = VictimInfo(
        name="V-CFI01 Test Victim",
        wallet_address=VICTIM,
        state="NY",
        country="US",
        email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test Investigator",
        organization="Recupero Forensics Ltd.",
        email="investigator@test.com",
    )

    # Step 1: emit_brief (pure function — returns dict, no file I/O)
    brief_data = emit_brief(
        case=case,
        victim=victim,
        editorial=editorial,
        freeze_asks=freeze_asks,
        issuer_metadata=issuer_metadata,
    )

    # Capture any WARNING+ logs from recupero during build_all_deliverables.
    # Silent failures (generate_briefs crash → log.warning + continue) would
    # appear here so the test can assert on them.
    captured_warnings: list[str] = []

    class _CapturingHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if record.levelno >= logging.WARNING:
                msg = record.getMessage()
                # Skip the expected WeasyPrint-not-installed warning on dev
                if "WeasyPrint" not in msg and "libgobject" not in msg:
                    captured_warnings.append(msg)

    handler = _CapturingHandler()
    recupero_logger = logging.getLogger("recupero")
    recupero_logger.addHandler(handler)

    tmpdir = tempfile.mkdtemp(prefix="v_cfi01_prod_")
    case_dir = Path(tmpdir)
    try:
        # Step 2: build_all_deliverables — FULL PRODUCTION PATH
        build_all_deliverables(
            case=case,
            victim=victim,
            freeze_brief=brief_data,
            case_dir=case_dir,
            investigator=investigator,
            skip_freeze_briefs=False,
        )
    finally:
        recupero_logger.removeHandler(handler)

    briefs_dir = case_dir / "briefs"
    le_files = sorted(briefs_dir.glob("le_handoff_*.html"))
    freeze_files = sorted(briefs_dir.glob("freeze_request_*.html"))
    le_htmls = [f.read_text(encoding="utf-8") for f in le_files]
    freeze_htmls = [f.read_text(encoding="utf-8") for f in freeze_files]

    return {
        "briefs_dir": briefs_dir,
        "brief_data": brief_data,
        "le_htmls": le_htmls,
        "freeze_htmls": freeze_htmls,
        # Stem names (e.g. "freeze_request_midas_BRIEF-V-...") for issuer lookup
        "freeze_names": [f.stem for f in freeze_files],
        "warnings": captured_warnings,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_prod_no_silent_errors(production_run):
    """No WARNING-level messages from recupero during build_all_deliverables.

    Silent failures (e.g. generate_briefs crash swallowed by try/except)
    surface here. A warning means a deliverable may be missing or corrupt.
    """
    warnings = production_run["warnings"]
    assert not warnings, (
        f"build_all_deliverables logged {len(warnings)} warning(s) — "
        f"likely a silent failure in generate_briefs: {warnings}"
    )


def test_prod_4_le_handoffs_written(production_run):
    """One LE handoff per freezable issuer (Midas, Coinbase, Tether, Circle)."""
    le_htmls = production_run["le_htmls"]
    assert len(le_htmls) == 4, (
        f"Expected 4 LE handoff files (one per issuer), got {len(le_htmls)}. "
        "build_all_deliverables may have silently skipped some issuers."
    )


def test_prod_4_freeze_letters_written(production_run):
    """One freeze request letter per freezable issuer."""
    freeze_htmls = production_run["freeze_htmls"]
    assert len(freeze_htmls) == 4, (
        f"Expected 4 freeze request letters, got {len(freeze_htmls)}."
    )


def test_prod_trace_report_written(production_run):
    """trace_report HTML must always be emitted."""
    briefs_dir = production_run["briefs_dir"]
    reports = list(briefs_dir.glob("trace_report_*.html"))
    assert reports, "trace_report_*.html not found in briefs/"


def test_prod_flow_diagram_written(production_run):
    """Fund-flow SVG must be present."""
    briefs_dir = production_run["briefs_dir"]
    svgs = list(briefs_dir.glob("flow_*.svg"))
    assert svgs, "flow_*.svg not found in briefs/"


def test_prod_victim_summary_written(production_run):
    """Victim summary HTML must be written for a recoverable case."""
    briefs_dir = production_run["briefs_dir"]
    summaries = list(briefs_dir.glob("victim_summary_*.html"))
    assert summaries, "victim_summary_*.html not found in briefs/"


def test_prod_le_section_42_present(production_run):
    """Every LE handoff must contain Section 4.2 Complete Holdings Inventory."""
    for i, le_html in enumerate(production_run["le_htmls"]):
        assert "4.2" in le_html and "Complete Holdings" in le_html, (
            f"LE handoff #{i+1}: Section 4.2 Complete Holdings Inventory missing. "
            "all_issuers_freezable was not wired through build_all_deliverables."
        )


def test_prod_le_contains_unrecoverable_dai(production_run):
    """Every LE handoff must show Sky Protocol / DAI as UNRECOVERABLE."""
    for i, le_html in enumerate(production_run["le_htmls"]):
        assert "UNRECOVERABLE" in le_html, (
            f"LE handoff #{i+1}: UNRECOVERABLE pill missing."
        )
        assert "Sky Protocol" in le_html, (
            f"LE handoff #{i+1}: Sky Protocol missing from Section 4.2."
        )


def test_prod_le_contains_all_issuers(production_run):
    """Every LE handoff Section 4.2 must list all 5 issuers."""
    issuers = ["Midas", "Coinbase", "Tether", "Circle", "Sky Protocol"]
    for i, le_html in enumerate(production_run["le_htmls"]):
        for issuer in issuers:
            assert issuer in le_html, (
                f"LE handoff #{i+1}: issuer '{issuer}' missing from Section 4.2."
            )


def test_prod_le_total_theft_3_6m(production_run):
    """Every LE handoff must display the $3,600,000 total theft amount."""
    for i, le_html in enumerate(production_run["le_htmls"]):
        assert "3,600,000" in le_html, (
            f"LE handoff #{i+1}: $3,600,000 total theft not shown. "
            "Multi-event rollup (6 × $600K) may be broken."
        )


def test_prod_freeze_letters_contain_correct_amounts(production_run):
    """Midas letter must show $3.1M mSyrupUSDp amount."""
    # Use filename stems (e.g. "freeze_request_midas_BRIEF-V-...") for reliable lookup.
    names = production_run["freeze_names"]
    htmls = production_run["freeze_htmls"]
    midas_idx = next(
        (i for i, n in enumerate(names) if "midas" in n.lower()),
        None,
    )
    assert midas_idx is not None, (
        f"Midas freeze letter not found. Files: {names}"
    )
    midas_letter = htmls[midas_idx]
    assert "3,119,023" in midas_letter, (
        "Midas freeze letter missing $3,119,023 mSyrupUSDp amount."
    )


def test_prod_no_jinja_tags_leaked(production_run):
    """No unrendered Jinja2 {{ }} tags in any output file."""
    for i, html in enumerate(production_run["le_htmls"] + production_run["freeze_htmls"]):
        assert "{{ " not in html, f"Unrendered Jinja tag in output file #{i+1}"
        assert " }}" not in html, f"Unrendered Jinja tag in output file #{i+1}"
        assert "Undefined" not in html, f"'Undefined' context var in output file #{i+1}"


def test_prod_brief_data_all_issuer_holdings_present(production_run):
    """emit_brief() must produce ALL_ISSUER_HOLDINGS with 5 entries (4 freezable + Sky)."""
    all_holdings = production_run["brief_data"].get("ALL_ISSUER_HOLDINGS", [])
    assert len(all_holdings) == 5, (
        f"ALL_ISSUER_HOLDINGS has {len(all_holdings)} entries, expected 5 "
        "(Midas, Coinbase, Tether, Circle, Sky Protocol)."
    )


def test_prod_brief_data_freezable_excludes_sky_protocol(production_run):
    """FREEZABLE list must NOT include Sky Protocol (freeze_capability=no)."""
    freezable_issuers = [
        e.get("issuer") for e in production_run["brief_data"].get("FREEZABLE", [])
    ]
    assert "Sky Protocol" not in freezable_issuers, (
        "Sky Protocol incorrectly in FREEZABLE list — "
        "freeze_capability=no must route to ALL_ISSUER_HOLDINGS only."
    )


def test_prod_theft_event_count_is_6(production_run):
    """THEFT_EVENT_COUNT must be 6 for the V-CFI01 multi-event drain."""
    count = production_run["brief_data"].get("THEFT_EVENT_COUNT")
    assert count == 6, f"THEFT_EVENT_COUNT={count!r}, expected 6."


def test_prod_total_loss_is_3_6m(production_run):
    """TOTAL_LOSS_USD must show $3,600,000 (6 × $600K)."""
    total = production_run["brief_data"].get("TOTAL_LOSS_USD", "")
    assert "3,600,000" in total, (
        f"TOTAL_LOSS_USD={total!r}, expected to contain '3,600,000'."
    )


def test_prod_victim_summary_is_recoverable_variant(production_run):
    """victim_summary must use the 'recoverable' template variant for V-CFI01.

    R14-E MEDIUM: test_prod_victim_summary_written only asserts the file
    exists — a misclassified case (UNRECOVERABLE) would still pass.
    This test additionally verifies the correct variant was chosen.
    """
    briefs_dir = production_run["briefs_dir"]
    summaries = list(briefs_dir.glob("victim_summary_*.html"))
    assert summaries, "victim_summary_*.html not found"
    for path in summaries:
        assert "unrecoverable" not in path.stem, (
            f"V-CFI01 case was classified as UNRECOVERABLE but should be "
            f"RECOVERABLE (4 freezable issuers present). File: {path.name}"
        )
        assert "recoverable" in path.stem, (
            f"Expected 'recoverable' in victim summary filename, got: {path.name}"
        )


def test_prod_total_freezable_excludes_dai(production_run):
    """TOTAL_FREEZABLE_USD must not count Sky Protocol / DAI (freeze_capability=no).

    R14-E MEDIUM: assert total freezable is < total loss (Sky DAI is excluded).
    """
    from decimal import Decimal
    brief = production_run["brief_data"]
    total_loss = brief.get("TOTAL_LOSS_USD", "")
    total_freezable = brief.get("TOTAL_FREEZABLE_USD", "")
    # V-CFI01: $3.6M total loss, but Sky DAI (~$655K) is unrecoverable.
    # Freezable should be less than total loss.
    assert total_freezable, "TOTAL_FREEZABLE_USD is missing from brief_data"
    # Both are formatted strings like "$3,549,001.40" — confirm freezable < loss
    # by checking that loss amount contains 3,600,000 but freezable does not.
    assert "3,600,000" not in total_freezable, (
        f"TOTAL_FREEZABLE_USD={total_freezable!r} equals TOTAL_LOSS_USD — "
        "Sky Protocol DAI should be excluded from freezable total."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests for private helpers (R14-E HIGH)
# ─────────────────────────────────────────────────────────────────────────────

def test_has_actionable_holding_all_unrecoverable():
    """_has_actionable_holding must return False when every holding is UNRECOVERABLE.

    R14-E HIGH: this is the guard that prevents generating a freeze letter
    to Sky Protocol. Without a direct test, a regression (returning True
    for all-UNRECOVERABLE) would silently generate a nonsense letter.
    """
    from recupero.worker._deliverables import _has_actionable_holding

    all_unrecoverable = {
        "issuer": "Sky Protocol",
        "holdings": [
            {"status": "UNRECOVERABLE", "address": "0xAAA"},
            {"status": "UNRECOVERABLE", "address": "0xBBB"},
        ],
    }
    assert not _has_actionable_holding(all_unrecoverable), (
        "_has_actionable_holding returned True for all-UNRECOVERABLE entry"
    )


def test_has_actionable_holding_mixed():
    """_has_actionable_holding must return True when any holding is FREEZABLE."""
    from recupero.worker._deliverables import _has_actionable_holding

    mixed = {
        "issuer": "Circle",
        "holdings": [
            {"status": "UNRECOVERABLE", "address": "0xAAA"},
            {"status": "FREEZABLE", "address": "0xBBB"},
        ],
    }
    assert _has_actionable_holding(mixed)


def test_has_actionable_holding_empty_holdings():
    """_has_actionable_holding must return False for an entry with no holdings."""
    from recupero.worker._deliverables import _has_actionable_holding

    assert not _has_actionable_holding({"issuer": "Orphan", "holdings": []})
    assert not _has_actionable_holding({"issuer": "Orphan"})  # missing holdings key


def test_issuer_info_for_non_midas_contact_email():
    """_issuer_info_for must resolve contact_email from the freeze_brief entry.

    R14-E HIGH: a regression (reading wrong key) would produce freeze letters
    with blank contact emails — Circle's compliance team would receive 'Dear ()'
    with no routing address. Previously was reading 'primary_contact' instead
    of 'contact_email'.
    """
    from recupero.worker._deliverables import _issuer_info_for

    entry = {
        "issuer": "Circle Internet Financial",
        "contact_email": "compliance@circle.com",
        "primary_contact": "old-key@circle.com",
    }
    info = _issuer_info_for("Circle Internet Financial", entry)
    assert info.contact_email == "compliance@circle.com", (
        f"Expected 'compliance@circle.com' from contact_email key, "
        f"got {info.contact_email!r}. Key lookup may be wrong."
    )


def test_issuer_info_for_falls_back_to_primary_contact():
    """_issuer_info_for falls back to primary_contact if contact_email absent."""
    from recupero.worker._deliverables import _issuer_info_for

    entry = {
        "issuer": "SomeNewIssuer",
        "primary_contact": "fallback@issuer.com",
    }
    info = _issuer_info_for("SomeNewIssuer", entry)
    assert info.contact_email == "fallback@issuer.com", (
        f"Expected fallback to primary_contact, got {info.contact_email!r}."
    )


def test_issuer_info_for_empty_contact():
    """_issuer_info_for returns empty contact_email rather than crashing when both keys absent."""
    from recupero.worker._deliverables import _issuer_info_for

    info = _issuer_info_for("UnknownIssuer", {})
    assert info.contact_email == "", (
        f"Expected empty string when neither key present, got {info.contact_email!r}."
    )


# ─────────────────────────────────────────────────────────────────────────────
# All-issuers-fail resilience path (R14-E HIGH)
# ─────────────────────────────────────────────────────────────────────────────

def test_all_issuers_fail_pipeline_still_writes_trace_report():
    """build_all_deliverables must write trace_report.html even if every
    generate_briefs() call raises.

    R14-E HIGH: the try/except around generate_briefs is claimed to be
    silent-swallow. This test directly verifies the claim — if the guard
    were removed or broken, the stage would raise and no trace report
    would be written, leaving the admin UI with no primary artifact.
    """
    import tempfile
    from pathlib import Path
    from unittest.mock import patch

    from tests.test_v_cfi01_full_render import (
        _build_editorial,
        _build_freeze_asks_dict,
        _build_issuer_metadata,
        _build_v_cfi01_case,
        VICTIM,
    )
    from recupero.reports.brief import InvestigatorInfo
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo
    from recupero.worker._deliverables import build_all_deliverables

    case = _build_v_cfi01_case()
    editorial = _build_editorial()
    freeze_asks = _build_freeze_asks_dict()
    issuer_metadata = _build_issuer_metadata()

    victim = VictimInfo(
        name="Resilience Test Victim",
        wallet_address=VICTIM,
        state="CA",
        country="US",
    )
    investigator = InvestigatorInfo(
        name="Test Investigator",
        organization="Recupero Forensics Ltd.",
        email="investigator@test.com",
    )

    brief_data = emit_brief(
        case=case,
        victim=victim,
        editorial=editorial,
        freeze_asks=freeze_asks,
        issuer_metadata=issuer_metadata,
    )

    with tempfile.TemporaryDirectory(prefix="v_cfi01_fail_") as tmpdir:
        case_dir = Path(tmpdir)
        # Patch generate_briefs to always raise
        with patch(
            "recupero.worker._deliverables.generate_briefs",
            side_effect=RuntimeError("Simulated generate_briefs failure"),
        ):
            # Must NOT raise
            build_all_deliverables(
                case=case,
                victim=victim,
                freeze_brief=brief_data,
                case_dir=case_dir,
                investigator=investigator,
                skip_freeze_briefs=False,
            )

        briefs_dir = case_dir / "briefs"
        # trace_report must still be written despite all generate_briefs failures
        trace_reports = list(briefs_dir.glob("trace_report_*.html"))
        assert trace_reports, (
            "trace_report_*.html was NOT written after all generate_briefs() calls "
            "raised — the silent-swallow guard is broken or trace_report rendering "
            "depends on generate_briefs output."
        )
        # No freeze letters should exist (all failed)
        freeze_letters = list(briefs_dir.glob("freeze_request_*.html"))
        assert not freeze_letters, (
            f"freeze_request letters unexpectedly present after all-fail: {freeze_letters}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests for emit_brief helpers (R16-E)
# ─────────────────────────────────────────────────────────────────────────────

def test_issuer_sort_key_freezable_before_unrecoverable():
    """_issuer_sort_key must return 0 for FREEZABLE/INVESTIGATE and 1 for LOW/NO.

    R16-E: the sort determines LE Section 4.2 table order — actionable entries
    must always precede unrecoverable-only entries regardless of insertion order.
    """
    from recupero.reports.emit_brief import _issuer_sort_key

    assert _issuer_sort_key({"freeze_capability": "YES"}) == 0
    assert _issuer_sort_key({"freeze_capability": "HIGH"}) == 0
    assert _issuer_sort_key({"freeze_capability": "INVESTIGATE"}) == 0
    assert _issuer_sort_key({"freeze_capability": "MEDIUM"}) == 0
    # LOW and NO are the only cases that should be ordered last
    assert _issuer_sort_key({"freeze_capability": "LOW"}) == 1
    assert _issuer_sort_key({"freeze_capability": "NO"}) == 1
    # Case-insensitive: "no" from freeze_asks.json should also sort last
    assert _issuer_sort_key({"freeze_capability": "no"}) == 1
    # Missing key defaults to 0 (actionable)
    assert _issuer_sort_key({}) == 0


def test_issuer_sort_key_sorts_sky_protocol_last():
    """Sky Protocol (freeze_capability=no) must sort after all actionable issuers."""
    from recupero.reports.emit_brief import _issuer_sort_key

    entries = [
        {"issuer": "Sky Protocol", "freeze_capability": "no"},
        {"issuer": "Tether", "freeze_capability": "YES"},
        {"issuer": "Circle", "freeze_capability": "YES"},
    ]
    sorted_entries = sorted(entries, key=_issuer_sort_key)
    assert sorted_entries[0]["issuer"] in ("Tether", "Circle"), (
        "Sky Protocol sorted before actionable issuers"
    )
    assert sorted_entries[-1]["issuer"] == "Sky Protocol", (
        "Sky Protocol did not sort last"
    )


def test_count_theft_events_single_event():
    """_count_theft_events must return 1 for a simple single-transfer case.

    Uses SimpleNamespace so this test stays decoupled from the Transfer
    model's required-field list — _count_theft_events only reads
    `from_address` and `usd_value_at_tx` from each transfer.
    """
    from decimal import Decimal
    from types import SimpleNamespace
    from recupero.reports.emit_brief import _count_theft_events

    victim = "0xvictim000000000000000000000000000000001"
    perp   = "0xperp0000000000000000000000000000000002"
    case = SimpleNamespace(
        seed_address=victim,
        transfers=[
            SimpleNamespace(from_address=victim, usd_value_at_tx=Decimal("1000")),
            # downstream hop — from_address is perp, must not count
            SimpleNamespace(from_address=perp, usd_value_at_tx=Decimal("1000")),
        ],
    )
    assert _count_theft_events(case) == 1


def test_count_theft_events_multi_event():
    """_count_theft_events must return 6 for the V-CFI01-shape 6-drain case."""
    from decimal import Decimal
    from types import SimpleNamespace
    from recupero.reports.emit_brief import _count_theft_events

    victim = "0xvictim000000000000000000000000000000001"
    perp   = "0xperp0000000000000000000000000000000002"

    theft_transfers = [
        SimpleNamespace(from_address=victim, usd_value_at_tx=Decimal("600000"))
        for _ in range(6)
    ]
    # A transfer where victim is NOT the sender must not be counted
    non_theft = SimpleNamespace(from_address=perp, usd_value_at_tx=Decimal("600000"))
    case = SimpleNamespace(
        seed_address=victim,
        transfers=theft_transfers + [non_theft],
    )
    assert _count_theft_events(case) == 6


def test_count_theft_events_includes_unpriced():
    """_count_theft_events must count ALL outbound transfers from seed, priced or not.

    v0.20.13 (R17-E): previously filtered by `usd_value_at_tx is not None`,
    which caused THEFT_EVENT_COUNT=0 for unpriced drains while the template
    context produced is_multi_event=True — contradictory signals for AI editorial.
    Aligns with _find_theft_events which includes all outbound transfers.
    """
    from decimal import Decimal
    from types import SimpleNamespace
    from recupero.reports.emit_brief import _count_theft_events

    victim = "0xvictim000000000000000000000000000000001"
    case = SimpleNamespace(
        seed_address=victim,
        transfers=[
            SimpleNamespace(from_address=victim, usd_value_at_tx=Decimal("1000")),
            # unpriced transfer — MUST be counted (v0.20.13 behaviour change)
            SimpleNamespace(from_address=victim, usd_value_at_tx=None),
        ],
    )
    assert _count_theft_events(case) == 2
