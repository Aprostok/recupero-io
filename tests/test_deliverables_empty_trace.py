"""Regression test for the wallet-trace empty-transfers path.

The bug this guards against:

  * Pre-fix, ``build_all_deliverables`` early-returned an empty list
    when ``case.transfers`` was empty. That meant wallet-trace runs
    against newly-created or low-activity wallets produced zero
    deliverables — including the ``trace_report.html`` that Jacob's
    spec requires as the primary artifact of every wallet-trace
    investigation.
  * The function's own docstring contradicted this: "Also
    unconditionally emits trace_report_<hash>.html — the new
    internal-facing data summary every investigation ships." The
    code didn't match the doc.

After the fix, ``trace_report.html`` is always written even when
transfers is empty. Freeze letters / LE handoffs are still skipped
on the empty-transfers path because there are no destinations to
address — but the trace report's "found nothing" finding still
ships and gets surfaced in the admin UI's wallet-trace detail view.

Test runs in ~50ms; uses a tempdir, no DB or network.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.models import Case, Chain
from recupero.reports.victim import VictimInfo
from recupero.worker._deliverables import build_all_deliverables


def _make_empty_case() -> Case:
    """Build a Case with zero transfers — what a wallet-trace produces
    when the seed wallet has no on-chain activity in the trace window."""
    return Case(
        case_id="test-empty-trace",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2024, 1, 1, tzinfo=UTC),
        transfers=[],
        exchange_endpoints=[],
        unlabeled_counterparties=[],
        software_version="test",
        trace_started_at=datetime(2024, 1, 1, tzinfo=UTC),
        trace_completed_at=datetime(2024, 1, 1, tzinfo=UTC),
    )


def _make_wallet_trace_victim() -> VictimInfo:
    """Synthetic placeholder VictimInfo as used by the pipeline on
    wallet-trace investigations where there's no backing cases row."""
    return VictimInfo(
        name="Wallet trace (no case)",
        wallet_address="0x" + "a" * 40,
    )


def test_empty_transfers_still_emits_trace_report() -> None:
    """Regression: trace_report.html must ship even when transfers=0.

    Pre-fix, build_all_deliverables returned [] on empty transfers,
    leaving the wallet-trace investigation with zero artifacts. The
    admin UI's wallet-trace detail view would have nothing to surface.
    """
    case = _make_empty_case()
    victim = _make_wallet_trace_victim()
    freeze_brief: dict = {"FREEZABLE": [], "DESTINATIONS": []}

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        written = build_all_deliverables(
            case=case,
            victim=victim,
            freeze_brief=freeze_brief,
            case_dir=case_dir,
            # Wallet trace shape: both skip flags on
            skip_freeze_briefs=True,
            investigation_id="test-investigation-id",
            label="empty-wallet-test",
        )

    # At least one file written — the trace report. Pre-fix this was 0.
    assert len(written) >= 1, (
        f"build_all_deliverables returned no files on empty-transfers case; "
        f"trace_report.html should ship unconditionally. written={written}"
    )

    # Confirm a trace_report.html is among the written files.
    names = [p.name for p in written]
    trace_reports = [n for n in names if n.startswith("trace_report_") and n.endswith(".html")]
    assert len(trace_reports) == 1, (
        f"expected exactly one trace_report_*.html in output, got: {names}"
    )

    # NO freeze letters should be written — wallet trace + skip flag set.
    freeze_letters = [n for n in names if n.startswith("freeze_request_")]
    assert freeze_letters == [], (
        f"freeze letters shouldn't ship on skip_freeze_briefs=True wallet "
        f"traces; got: {freeze_letters}"
    )


def test_empty_transfers_skips_freeze_letters_but_emits_trace_report() -> None:
    """Same as above but with skip_freeze_briefs=False — freeze letters
    should STILL be skipped (no destinations to name), but trace_report
    still ships.

    This is the "case-driven row with an unexpectedly-empty trace"
    edge case: e.g., the seed wallet was inactive in the buffer
    window, or the trace ran on a wallet that turned out to be the
    wrong address. The operator still wants the trace_report on
    record showing the trace was attempted and returned no activity.
    """
    case = _make_empty_case()
    victim = _make_wallet_trace_victim()
    freeze_brief: dict = {"FREEZABLE": [], "DESTINATIONS": []}

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        written = build_all_deliverables(
            case=case,
            victim=victim,
            freeze_brief=freeze_brief,
            case_dir=case_dir,
            skip_freeze_briefs=False,  # case-driven, but empty trace
            investigation_id="test-investigation-id",
        )

    names = [p.name for p in written]
    assert any(n.startswith("trace_report_") for n in names), (
        f"trace_report missing on empty-transfer case-driven run: {names}"
    )
    # No freeze letters because case.transfers is empty — there are no
    # destinations to address, even though skip_freeze_briefs=False.
    assert not any(n.startswith("freeze_request_") for n in names), (
        f"freeze letters should be skipped on empty-transfer cases: {names}"
    )


def test_trace_report_is_html_not_empty() -> None:
    """The emitted trace_report.html should be non-trivial — not just
    a 0-byte placeholder. Validates the Jinja render actually ran."""
    case = _make_empty_case()
    victim = _make_wallet_trace_victim()
    freeze_brief: dict = {"FREEZABLE": [], "DESTINATIONS": []}

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        written = build_all_deliverables(
            case=case, victim=victim, freeze_brief=freeze_brief,
            case_dir=case_dir, skip_freeze_briefs=True,
            investigation_id="test-investigation-id",
        )

        # IMPORTANT: read inside the `with` block — TemporaryDirectory
        # deletes the tree on __exit__, so paths in `written` become
        # invalid the moment we leave this scope.
        report = next((p for p in written if p.name.startswith("trace_report_")), None)
        assert report is not None
        content = report.read_text(encoding="utf-8")
        # Sanity: real HTML, real content, NOT an empty file.
        assert len(content) > 500, f"trace_report.html suspiciously small: {len(content)} bytes"
        assert "<html" in content.lower() or "<!doctype" in content.lower()
        # The wallet address should appear somewhere — that's the whole point of the report.
        assert ("0x" + "a" * 40).lower() in content.lower()
