"""v0.36 real-case pipeline fixes (surfaced by the live Ronin trace).

Two gaps closed:

  #2  worker.sync.upload_case_dir mirrored ONLY top-level files + briefs/ +
      tx_evidence/, and a blanket `if len(parts) != 1: skip` dropped every
      other nested deliverable subdir — so a CLI-run case's exchange-freeze
      letters / time-sensitivity advisory / SAR draft / exhibit pack never
      reached the operator console. Now ALL non-skipped nested subdirs mirror
      verbatim (logs/ + prices_cache/ still skipped).

  #3  `recupero trace` had no CLI cap on total transfers — only the
      RECUPERO_MAX_TRANSFERS_PER_CASE env var (default 50000), so a whale /
      mega-hack trace ran effectively unbounded. New `--max-transfers` flag
      surfaces the cap (and rejects non-positive values).
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import typer
from typer.testing import CliRunner

from recupero.worker import sync as worker_sync


def _stub_store() -> MagicMock:
    store = MagicMock()
    store.storage_prefix = "investigations/00000000-0000-0000-0000-000000000000/"
    return store


# ----- #2: full deliverable tree mirrors, not just briefs/ -----

def test_upload_case_dir_mirrors_all_nested_deliverable_dirs(tmp_path: Path) -> None:
    case = tmp_path / "case"
    (case / "briefs").mkdir(parents=True)
    (case / "legal_requests").mkdir()
    (case / "regulatory_filing").mkdir()
    (case / "exhibit_pack").mkdir()
    (case / "logs").mkdir()
    (case / "case.json").write_text('{"case_id":"x"}', encoding="utf-8")
    (case / "briefs" / "le_handoff.html").write_text("<html>le</html>", encoding="utf-8")
    (case / "legal_requests" / "legal_time_sensitivity.html").write_text("<html>ts</html>", encoding="utf-8")
    (case / "legal_requests" / "exchange_freeze_binance.html").write_text("<html>fz</html>", encoding="utf-8")
    (case / "regulatory_filing" / "us_fincen_sar.html").write_text("<html>sar</html>", encoding="utf-8")
    (case / "exhibit_pack" / "exhibit_pack.html").write_text("<html>ex</html>", encoding="utf-8")
    (case / "logs" / "trace.log").write_text("noisy", encoding="utf-8")

    store = _stub_store()
    n = worker_sync.upload_case_dir(case, store)

    # Nested deliverables go through _upload_to_subpath -> store._upload(full, ...)
    uploaded_paths = {c.args[0] for c in store._upload.call_args_list}
    pfx = store.storage_prefix
    for rel in (
        "briefs/le_handoff.html",
        "legal_requests/legal_time_sensitivity.html",
        "legal_requests/exchange_freeze_binance.html",
        "regulatory_filing/us_fincen_sar.html",
        "exhibit_pack/exhibit_pack.html",
    ):
        assert pfx + rel in uploaded_paths, f"{rel} not mirrored to bucket"
    # logs/ is skipped — never uploaded.
    assert not any("logs/" in p for p in uploaded_paths)
    # top-level case.json went via write_json, not _upload.
    store.write_json.assert_called_once()
    assert store.write_json.call_args.args[0] == "case.json"
    # 6 files uploaded (5 nested + 1 top-level), logs skipped.
    assert n == 6


# ----- #3: --max-transfers CLI flag -----

def _import_app():  # noqa: ANN202
    from recupero.cli import app
    return app


def test_trace_max_transfers_sets_cap(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setenv("RECUPERO_DATA_DIR", str(tmp_path))
    # Track so teardown restores whatever the CLI overwrites.
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_CASE", "50000")

    captured: dict[str, str | None] = {}

    def fake_run_trace(**kwargs):  # noqa: ANN003
        captured["cap"] = os.environ.get("RECUPERO_MAX_TRANSFERS_PER_CASE")
        raise typer.Exit(code=0)  # stop before pivot/sync/summary

    monkeypatch.setattr("recupero.cli.run_trace", fake_run_trace)

    res = CliRunner().invoke(_import_app(), [
        "trace", "--chain", "ethereum",
        "--address", "0x" + "a" * 40,
        "--incident-time", "2022-01-01T00:00:00Z",
        "--case-id", "cap-test",
        "--max-transfers", "300",
    ])
    assert res.exit_code == 0, res.output
    assert captured.get("cap") == "300"


# ----- recovery_snapshot_iff_recoverable gate (Jacob round finding) -----

def test_max_recoverable_usd_resolution() -> None:
    """The recovery-snapshot emission gate parses the recoverable figure with
    the SAME field resolution the output_integrity validator uses, so a $0
    case never ships a (misleading) recovery snapshot."""
    from decimal import Decimal

    from recupero.worker._deliverables import _max_recoverable_usd

    assert _max_recoverable_usd({}) == Decimal(0)
    assert _max_recoverable_usd({"MAX_RECOVERABLE_USD": "$0.00"}) == Decimal(0)
    assert _max_recoverable_usd({"max_recoverable_usd": "$100,000.00"}) == Decimal("100000.00")
    assert _max_recoverable_usd({"TOTAL_FREEZABLE_USD": "$50,000"}) == Decimal("50000")
    # Unparseable / hostile value degrades to 0 (never raises) → no snapshot.
    assert _max_recoverable_usd({"MAX_RECOVERABLE_USD": "garbage"}) == Decimal(0)


def test_recovery_snapshot_suppressed_at_zero_recoverable(tmp_path) -> None:
    """Regression for the Jacob-round HIGH: a recovery snapshot must NOT be
    emitted when nothing is recoverable, even though RECOVERY_ESTIMATE exists —
    shipping it would mislead the victim (recovery_snapshot_iff_recoverable)."""
    from datetime import UTC, datetime

    from recupero.models import Case, Chain
    from recupero.reports.victim import VictimInfo
    from recupero.worker._deliverables import build_all_deliverables

    case = Case(
        case_id="rs-zero", seed_address="0x" + "a" * 40, chain=Chain.ethereum,
        incident_time=datetime(2024, 1, 1, tzinfo=UTC), transfers=[],
        exchange_endpoints=[], unlabeled_counterparties=[], software_version="t",
        trace_started_at=datetime(2024, 1, 1, tzinfo=UTC),
        trace_completed_at=datetime(2024, 1, 1, tzinfo=UTC),
    )
    victim = VictimInfo(name="V", wallet_address="0x" + "a" * 40)
    fb = {
        "FREEZABLE": [], "DESTINATIONS": [], "MAX_RECOVERABLE_USD": "$0.00",
        "RECOVERY_ESTIMATE": {"realistic_recovery_usd": "$0.00"},
    }
    written = build_all_deliverables(
        case=case, victim=victim, freeze_brief=fb, case_dir=tmp_path,
        skip_freeze_briefs=False, investigation_id="t",
    )
    assert not any(p.name.startswith("recovery_snapshot_") for p in written), (
        "recovery snapshot must not ship at $0 recoverable"
    )


def test_trace_max_transfers_rejects_nonpositive(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setenv("RECUPERO_DATA_DIR", str(tmp_path))
    # Should never reach the tracer — guard rejects <= 0 first.
    monkeypatch.setattr(
        "recupero.cli.run_trace",
        lambda **k: (_ for _ in ()).throw(AssertionError("run_trace should not run")),
    )
    res = CliRunner().invoke(_import_app(), [
        "trace", "--chain", "ethereum",
        "--address", "0x" + "a" * 40,
        "--incident-time", "2022-01-01T00:00:00Z",
        "--case-id", "cap-test",
        "--max-transfers", "0",
    ])
    assert res.exit_code == 2, res.output
