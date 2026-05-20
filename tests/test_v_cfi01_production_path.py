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
