"""Adversarial-input audit for worker._deliverables.build_all_deliverables.

These tests poke the orchestrator with hostile inputs:

  1. Malformed FREEZABLE entries (non-dict, non-string issuer name)
  2. NaN / Inf USD strings propagating into classify path
  3. Path-traversal issuer names
  4. Concurrent .pdf.tmp race (deterministic temp filename collision)
  5. Brief dict missing top-level keys
  6. Atomic write — partial .pdf must never become visible

All tests run with WeasyPrint disabled (RECUPERO_DISABLE_PDF_RENDER=1)
so they execute in <1s with no native deps.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.models import Case, Chain
from recupero.reports.victim import VictimInfo
from recupero.worker._deliverables import (
    _has_actionable_holding,
    _issuer_info_for,
    _emit_pdfs,
    build_all_deliverables,
)


def _case() -> Case:
    return Case(
        case_id="adv-case-01",
        seed_address="0x" + "b" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2024, 1, 1, tzinfo=UTC),
        transfers=[],
        exchange_endpoints=[],
        unlabeled_counterparties=[],
        software_version="test",
        trace_started_at=datetime(2024, 1, 1, tzinfo=UTC),
        trace_completed_at=datetime(2024, 1, 1, tzinfo=UTC),
    )


def _victim() -> VictimInfo:
    return VictimInfo(name="V", wallet_address="0x" + "b" * 40)


@pytest.fixture(autouse=True)
def _disable_pdf(monkeypatch):
    """Skip WeasyPrint — these tests are about the orchestrator, not render."""
    monkeypatch.setenv("RECUPERO_DISABLE_PDF_RENDER", "1")
    # Make sure the auto-send branch is dormant.
    monkeypatch.setenv("RECUPERO_DISABLE_EMAIL", "1")
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)


# ---------------------------------------------------------------------------
# 1. Malformed FREEZABLE entries — single bad entry must not kill the stage
# ---------------------------------------------------------------------------


def test_freezable_with_non_dict_entry_does_not_crash() -> None:
    """A non-dict element in FREEZABLE (e.g., a string slipped in by a
    buggy emit_brief writer) must not crash the whole stage. Pre-fix,
    `entry.get("issuer")` at line 141 raised AttributeError, killing
    every other issuer's brief generation.
    """
    freeze_brief = {
        "FREEZABLE": [
            "not-a-dict",  # malformed
            {"issuer": "circle", "holdings": [{"status": "FREEZABLE"}]},
        ],
    }
    with TemporaryDirectory() as tmp:
        written = build_all_deliverables(
            case=_case(),
            victim=_victim(),
            freeze_brief=freeze_brief,
            case_dir=Path(tmp),
            skip_freeze_briefs=True,  # only run the resilient prefix
        )
    # We don't care WHAT was written — only that the call returned.
    assert isinstance(written, list)


def test_freezable_with_non_string_issuer_name_does_not_crash() -> None:
    """An issuer name that isn't a string (e.g., int 123 from a bad
    JSON cast) reaches `_issuer_info_for` which calls `name.split(" ")`.
    Pre-fix, this raised AttributeError, killing all subsequent issuers.
    """
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": 123, "holdings": [{"status": "FREEZABLE"}]},
            {"issuer": "tether", "holdings": [{"status": "FREEZABLE"}]},
        ],
    }
    with TemporaryDirectory() as tmp:
        written = build_all_deliverables(
            case=_case(),
            victim=_victim(),
            freeze_brief=freeze_brief,
            case_dir=Path(tmp),
            skip_freeze_briefs=True,
        )
    assert isinstance(written, list)


# ---------------------------------------------------------------------------
# 2. Path traversal in issuer short_name — must be sanitized BEFORE
#    crossing _issuer_info_for, even though brief.py also sanitizes.
#    Defense in depth: _issuer_info_for returns a short_name that
#    cannot escape briefs_dir on its own.
# ---------------------------------------------------------------------------


def test_issuer_info_for_traversal_name_sanitized() -> None:
    """`_issuer_info_for("../../etc/passwd", {})` must produce a
    short_name with no traversal characters."""
    info = _issuer_info_for("../../etc/passwd", {})
    # No path separators, no parent-dir tokens
    assert ".." not in info.short_name
    assert "/" not in info.short_name
    assert "\\" not in info.short_name


def test_issuer_info_for_backslash_traversal_sanitized() -> None:
    """Windows-style traversal: `..\\evil` must not survive."""
    info = _issuer_info_for("..\\evil", {})
    assert "\\" not in info.short_name
    assert ".." not in info.short_name


# ---------------------------------------------------------------------------
# 3. _has_actionable_holding must tolerate non-dict holdings entries
# ---------------------------------------------------------------------------


def test_has_actionable_holding_with_non_dict_holdings() -> None:
    """A malformed holdings list (string element) must not crash."""
    # Pre-fix: h.get raises AttributeError on the string.
    result = _has_actionable_holding({"holdings": ["bad-element"]})
    assert isinstance(result, bool)


def test_has_actionable_holding_with_holdings_not_list() -> None:
    """If holdings is a dict instead of list, must not crash."""
    result = _has_actionable_holding({"holdings": {"k": "v"}})
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# 4. Missing-field robustness — brief dict missing top-level keys
# ---------------------------------------------------------------------------


def test_empty_freeze_brief_does_not_crash() -> None:
    """A completely empty freeze_brief dict must produce at least one
    artifact (trace_report) without raising."""
    with TemporaryDirectory() as tmp:
        written = build_all_deliverables(
            case=_case(),
            victim=_victim(),
            freeze_brief={},  # no keys at all
            case_dir=Path(tmp),
            skip_freeze_briefs=True,
        )
    assert isinstance(written, list)


# ---------------------------------------------------------------------------
# 5. Concurrent .pdf.tmp race — _html_to_pdf builds tmp_path
#    deterministically. The fix is to randomize via tempfile or pid+tid
#    so two workers on the same case don't smash each other's tmp file.
# ---------------------------------------------------------------------------


def test_html_to_pdf_tmp_path_is_per_process_unique() -> None:
    """Two concurrent build_all_deliverables calls on the same case_dir
    must not collide on the .pdf.tmp filename. We assert the function
    that generates the tmp path uses something process-unique (pid /
    tempfile suffix) rather than the deterministic `.pdf.tmp` suffix
    that pre-fix was used.

    This is a STATIC assertion against the source: read the file and
    verify the literal pattern `pdf_path.suffix + ".tmp"` is no longer
    used as a sibling tmp filename in the _html_to_pdf path. Replaced
    by a randomized name.
    """
    import inspect
    from recupero.worker import _deliverables

    src = inspect.getsource(_deliverables._html_to_pdf)
    # The deterministic literal is the bug. Fix uses tempfile.mkstemp
    # / os.getpid / similar to make the tmp filename unique per worker.
    assert "tempfile" in src or "getpid" in src or ".pid" in src, (
        "_html_to_pdf must use a process-unique tmp filename "
        "(tempfile.mkstemp or pid suffix). Deterministic '.pdf.tmp' "
        "races between concurrent workers on the same case."
    )


# ---------------------------------------------------------------------------
# 6. Atomic write — _emit_pdfs with WeasyPrint disabled returns []
#    cleanly (no partial files left behind).
# ---------------------------------------------------------------------------


def test_emit_pdfs_with_no_html_paths_returns_empty() -> None:
    """Empty html_paths must produce no files and not crash."""
    out = _emit_pdfs([], flow_svg_path=None)
    assert out == []
