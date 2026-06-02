"""v0.35.15 (J3) — label-freshness SLA monitor.

Pins: per-source age-vs-SLA classification (fresh/stale/critical); no-timestamp
→ unknown (never assumed fresh); deterministic with an injected `now`;
worst-first ordering; the scan reads `.meta.json` last_synced_utc and falls back
to file mtime; the report's OFAC headline alarm.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from recupero.labels.freshness import (
    build_freshness_report,
    evaluate_label_freshness,
    scan_label_sources,
)

NOW = datetime(2026, 6, 2, 12, 0, tzinfo=UTC)


def _iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


def test_fresh_stale_critical_classification():
    sources = [
        {"name": "ofac.csv", "source_class": "ofac_sanctions", "sla_days": 7,
         "last_updated_utc": _iso(3)},     # within 7 → fresh
        {"name": "bridges.json", "source_class": "bridges", "sla_days": 30,
         "last_updated_utc": _iso(45)},    # 30<45<=60 → stale
        {"name": "cex.json", "source_class": "exchange_deposits", "sla_days": 30,
         "last_updated_utc": _iso(120)},   # >60 → critical
    ]
    by_name = {s.name: s for s in evaluate_label_freshness(sources, now=NOW)}
    assert by_name["ofac.csv"].status == "fresh"
    assert by_name["bridges.json"].status == "stale"
    assert by_name["cex.json"].status == "critical"
    assert by_name["cex.json"].age_days == 120


def test_missing_timestamp_is_unknown_not_fresh():
    sources = [{"name": "x.json", "source_class": "mixers", "sla_days": 90,
                "last_updated_utc": None}]
    st = evaluate_label_freshness(sources, now=NOW)[0]
    assert st.status == "unknown"
    assert st.age_days is None
    assert "overdue" in st.message.lower()


def test_worst_first_ordering():
    sources = [
        {"name": "fresh", "source_class": "a", "sla_days": 30, "last_updated_utc": _iso(1)},
        {"name": "crit", "source_class": "b", "sla_days": 7, "last_updated_utc": _iso(90)},
        {"name": "stale", "source_class": "c", "sla_days": 30, "last_updated_utc": _iso(40)},
        {"name": "unk", "source_class": "d", "sla_days": 30, "last_updated_utc": None},
    ]
    order = [s.status for s in evaluate_label_freshness(sources, now=NOW)]
    assert order == ["critical", "stale", "unknown", "fresh"]


def test_z_suffix_timestamp_parsed():
    sources = [{"name": "x", "source_class": "ofac_sanctions", "sla_days": 7,
                "last_updated_utc": "2026-06-01T00:00:00Z"}]
    st = evaluate_label_freshness(sources, now=NOW)[0]
    assert st.status == "fresh"
    assert st.age_days == 1


def test_scan_reads_meta_json_then_mtime(tmp_path: Path):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    # ofac with an explicit meta.json
    (seeds / "ofac_crypto_live.csv").write_text("address\n", encoding="utf-8")
    (seeds / "ofac_crypto_live.csv.meta.json").write_text(
        json.dumps({"last_synced_utc": _iso(2)}), encoding="utf-8",
    )
    # bridges with no meta → falls back to mtime (just written → ~0d old)
    (seeds / "bridges.json").write_text("[]", encoding="utf-8")
    scanned = {s["name"]: s for s in scan_label_sources(seeds)}
    assert scanned["ofac_crypto_live.csv"]["last_updated_utc"] == _iso(2)
    assert scanned["bridges.json"]["last_updated_utc"] is not None   # mtime
    # A source with no file at all → None (reported unknown downstream).
    assert scanned["mixers.json"]["last_updated_utc"] is None


def test_build_report_ofac_alarm(tmp_path: Path):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "ofac_crypto_live.csv").write_text("address\n", encoding="utf-8")
    (seeds / "ofac_crypto_live.csv.meta.json").write_text(
        json.dumps({"last_synced_utc": _iso(30)}), encoding="utf-8",  # 30d >> 14 (2×7) → critical
    )
    report = build_freshness_report(seeds_dir=seeds, now=NOW)
    assert report["summary"]["ofac_status"] == "critical"
    assert report["summary"]["ofac_age_days"] == 30
    assert report["summary"]["total"] == 9   # all known sources reported
