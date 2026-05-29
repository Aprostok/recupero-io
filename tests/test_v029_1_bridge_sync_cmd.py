"""v0.29.1 Recommendation #5 — bridge-sync command end-to-end test.

Pins the `recupero-ops bridge-sync` contract:

  1. Runs in --offline mode without needing network access (CI safe).
  2. Writes a well-formed bridges_diff.json containing the expected
     top-level keys.
  3. Reports the local bridges.json coverage relative to the bundled
     external-source snapshots — non-empty list is fine, empty list
     would prove the diff actually found anything is fine, but a
     missing or malformed payload is the failure mode we want to
     catch.
  4. Surfaces stale high-confidence entries (confidence-decay
     Recommendation #6 surface).

These tests don't pin the EXACT gap list because that list shifts
naturally as the team adds rows. They DO pin the shape so a
refactor that breaks the diff format trips a test.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from recupero.ops.commands import bridge_sync_cmd as bs


def _run_offline(tmp_path: Path) -> tuple[int, dict]:
    diff_path = tmp_path / "bridges_diff.json"
    exit_code = bs.run(
        output_path=diff_path,
        offline=True,
        today=datetime(2026, 5, 26, tzinfo=UTC),
    )
    payload = json.loads(diff_path.read_text(encoding="utf-8"))
    return exit_code, payload


def test_bridge_sync_offline_run_exits_zero(tmp_path: Path) -> None:
    """The happy-path: offline mode must succeed and write a diff."""
    exit_code, _ = _run_offline(tmp_path)
    assert exit_code == 0


def test_bridge_sync_diff_has_expected_top_level_keys(tmp_path: Path) -> None:
    """The diff payload format is part of the operational contract —
    cron output gets ingested by ops dashboards. Pin the keys."""
    _, payload = _run_offline(tmp_path)
    expected_keys = {
        "schema_version",
        "fetched_at",
        "sources_used",
        "sources_unavailable",
        "coverage_gaps",
        "coverage_gap_summary",
        "stale_high_confidence",
        "stale_high_confidence_count",
    }
    actual = set(payload.keys())
    assert expected_keys.issubset(actual), (
        f"bridges_diff.json missing keys: {expected_keys - actual}. "
        f"Cron consumers downstream depend on this layout."
    )


def test_bridge_sync_reports_sources_used(tmp_path: Path) -> None:
    """In offline mode the bundled snapshots count as reachable —
    both L2Beat and DefiLlama appear in sources_used."""
    _, payload = _run_offline(tmp_path)
    assert "l2beat" in payload["sources_used"]
    assert "defillama" in payload["sources_used"]
    assert payload["sources_unavailable"] == []


def test_bridge_sync_coverage_gap_summary_groups_by_protocol(tmp_path: Path) -> None:
    """The grouped view makes the diff human-readable. Each gap
    must also appear in coverage_gap_summary[protocol]."""
    _, payload = _run_offline(tmp_path)
    grouped = payload["coverage_gap_summary"]
    for gap in payload["coverage_gaps"]:
        assert gap["protocol"] in grouped, (
            f"Gap {gap!r} not in grouped summary"
        )
        assert gap["chain"] in grouped[gap["protocol"]]


def test_bridge_sync_stale_high_confidence_excludes_externally_verified(tmp_path: Path) -> None:
    """Recommendation #6: entries with an externally_verified
    _audit_status carry proof-of-life and must NOT appear in the
    stale list. The semantic key is (address, chain) — the same
    address can legitimately exist on multiple chains with
    different audit status (e.g., a v0.29 deterministic-deploy
    BSC entry with externally_verified next to a pre-v0.28
    Ethereum entry that pre-dated the audit). The filter must
    distinguish them."""
    _, payload = _run_offline(tmp_path)
    bridges = json.loads(
        (Path(__file__).parent.parent / "src" / "recupero" /
         "labels" / "seeds" / "bridges.json").read_text(encoding="utf-8")
    )
    externally_verified_keys = {
        (str(e.get("address", "")).lower(),
         str(e.get("chain", "ethereum")).lower())
        for e in bridges
        if isinstance(e, dict)
        and "externally_verified" in (e.get("_audit_status") or "")
    }
    for stale in payload["stale_high_confidence"]:
        key = (stale["address"].lower(), stale["chain"].lower())
        assert key not in externally_verified_keys, (
            f"Externally-verified entry surfaced as stale: {stale}"
        )


def test_bridge_sync_handles_malformed_bridges_json(tmp_path: Path) -> None:
    """Defensive: if bridges.json is corrupt, return exit code 2
    rather than crashing."""
    bad = tmp_path / "bridges_bad.json"
    bad.write_text("not valid json{", encoding="utf-8")
    exit_code = bs.run(
        bridges_path=bad,
        output_path=tmp_path / "diff.json",
        offline=True,
    )
    assert exit_code == 2


def test_bridge_sync_decay_helper_treats_missing_field_as_stale() -> None:
    """The _is_stale helper directly — missing/empty `last_verified_at`
    counts as stale (forces operator to fill it in)."""
    today = datetime(2026, 5, 26, tzinfo=UTC)
    assert bs._is_stale(None, today)
    assert bs._is_stale("", today)
    assert bs._is_stale("   ", today)
    # 1 day ago — fresh.
    assert not bs._is_stale("2026-05-25T00:00:00Z", today)
    # 100 days ago — stale (>90).
    assert bs._is_stale("2026-02-15T00:00:00Z", today)
    # Malformed timestamp → stale.
    assert bs._is_stale("not-a-date", today)
