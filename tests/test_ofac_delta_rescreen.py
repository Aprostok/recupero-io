"""Roadmap-#1 v3 item #9: OFAC-delta re-screen of open cases.

When Treasury adds a crypto wallet to the SDN list and that wallet is already on
an active case's watchlist, surface a FORWARD-LOOKING alert — without rewriting
the brief's historical label (point-in-time discipline). The first run only
establishes a baseline (no flood).
"""

from __future__ import annotations

from types import SimpleNamespace

import recupero.monitoring.ofac_delta_rescreen as mod
from recupero.monitoring.ofac_delta_rescreen import (
    OFACDeltaAlert,
    build_watch_index,
    diff_ofac_additions,
    load_snapshot,
    match_additions_to_watchlist,
    screen_ofac_additions,
    write_snapshot,
)

_A = "0x" + "11" * 20
_B = "0x" + "22" * 20
_C = "0x" + "33" * 20


def _entry(address, *, sdn_entry_name="SDN ENTITY", listing_date="2026-06-09",
           chain="ethereum", removed_at_utc=""):
    return SimpleNamespace(
        address=address, sdn_entry_name=sdn_entry_name, listing_date=listing_date,
        chain=chain, removed_at_utc=removed_at_utc,
    )


# ---- pure cores ----------------------------------------------------------
def test_diff_additions_is_set_difference() -> None:
    assert diff_ofac_additions({_A, _B}, {_A, _B, _C}) == {_C}
    assert diff_ofac_additions({_A}, {_A}) == set()
    # removed addresses (present before, gone now) are NOT "additions"
    assert diff_ofac_additions({_A, _B}, {_A}) == set()


def test_build_watch_index_keys_by_canonical_address() -> None:
    from recupero._common import canonical_address_key as ck
    addr_lower = "0x" + "ab" * 20
    addr_upper = "0x" + "AB" * 20  # same address, checksum-style uppercase hex
    rows = [
        {"address": addr_upper, "chain": "ethereum", "investigation_id": "i1", "role": "hop"},
        {"address": addr_lower, "chain": "ethereum", "investigation_id": "i2", "role": "perpetrator"},
        {"address": "", "chain": "ethereum", "investigation_id": "i3", "role": "x"},  # skipped
    ]
    idx = build_watch_index(rows)
    # both rows collapse under one canonical key (EVM hex lowercased)
    assert len(idx[ck(addr_lower)]) == 2
    assert "" not in idx


def test_match_emits_alert_only_for_watched_additions() -> None:
    idx = build_watch_index([
        {"address": _B, "chain": "ethereum", "investigation_id": "inv-7", "role": "current_holder"},
    ])
    added = [
        _entry(_B, sdn_entry_name="LAZARUS GROUP", listing_date="2026-06-09"),
        _entry(_C),  # newly listed but NOT on any watchlist → no alert
    ]
    alerts = match_additions_to_watchlist(added, idx)
    assert len(alerts) == 1
    a = alerts[0]
    assert isinstance(a, OFACDeltaAlert)
    assert a.investigation_id == "inv-7"
    assert a.watch_role == "current_holder"
    assert "LAZARUS GROUP" in a.message
    # point-in-time discipline must be spelled out in the alert
    assert "do NOT rewrite" in a.message


def test_match_emits_one_alert_per_watching_case() -> None:
    idx = build_watch_index([
        {"address": _A, "chain": "ethereum", "investigation_id": "inv-1", "role": "hop"},
        {"address": _A, "chain": "ethereum", "investigation_id": "inv-2", "role": "hop"},
    ])
    alerts = match_additions_to_watchlist([_entry(_A)], idx)
    assert {a.investigation_id for a in alerts} == {"inv-1", "inv-2"}


# ---- snapshot IO ---------------------------------------------------------
def test_snapshot_roundtrip_and_absent_and_corrupt(tmp_path) -> None:
    p = tmp_path / "seen.json"
    assert load_snapshot(p) is None  # absent → None (baseline), NOT empty set
    write_snapshot(p, {_A, _B})
    assert load_snapshot(p) == {_A, _B}
    p.write_text("{ this is not valid json", encoding="utf-8")
    assert load_snapshot(p) is None  # corrupt → None (degrade to fresh baseline)


# ---- orchestrator --------------------------------------------------------
def test_first_run_is_baseline_no_alerts(tmp_path, monkeypatch) -> None:
    snap = tmp_path / "seen.json"
    monkeypatch.setattr("recupero.trace.ofac_sync.load_ofac_csv",
                        lambda *a, **k: [_entry(_A), _entry(_B)])
    # Even if the watchlist would match, the FIRST run emits nothing.
    monkeypatch.setattr(mod, "_query_active_watchlist",
                        lambda dsn: [{"address": _A, "chain": "ethereum",
                                      "investigation_id": "inv", "role": "hop"}])
    out = screen_ofac_additions(dsn="dsn", snapshot_path=snap)
    assert out == []
    assert load_snapshot(snap) is not None  # baseline persisted


def test_second_run_alerts_on_new_listing_in_open_case(tmp_path, monkeypatch) -> None:
    snap = tmp_path / "seen.json"
    # Run 1: baseline with just _A.
    monkeypatch.setattr("recupero.trace.ofac_sync.load_ofac_csv",
                        lambda *a, **k: [_entry(_A)])
    monkeypatch.setattr(mod, "_query_active_watchlist", lambda dsn: [])
    assert screen_ofac_additions(dsn="dsn", snapshot_path=snap) == []
    # Run 2: _B is newly listed AND on an active case's watchlist → alert.
    monkeypatch.setattr("recupero.trace.ofac_sync.load_ofac_csv",
                        lambda *a, **k: [_entry(_A), _entry(_B, sdn_entry_name="OFAC NEW")])
    monkeypatch.setattr(mod, "_query_active_watchlist",
                        lambda dsn: [{"address": _B, "chain": "ethereum",
                                      "investigation_id": "inv-9", "role": "hop"}])
    out = screen_ofac_additions(dsn="dsn", snapshot_path=snap)
    assert len(out) == 1
    assert out[0].investigation_id == "inv-9"
    assert "OFAC NEW" in out[0].message
    # Run 3: nothing new → no repeat alert (baseline advanced).
    out3 = screen_ofac_additions(dsn="dsn", snapshot_path=snap)
    assert out3 == []


def test_removed_listings_excluded_from_current_set(tmp_path, monkeypatch) -> None:
    snap = tmp_path / "seen.json"
    monkeypatch.setattr("recupero.trace.ofac_sync.load_ofac_csv",
                        lambda *a, **k: [_entry(_A)])
    monkeypatch.setattr(mod, "_query_active_watchlist", lambda dsn: [])
    screen_ofac_additions(dsn="dsn", snapshot_path=snap)  # baseline {_A}
    # _B appears but is DELISTED (removed_at_utc set) — must not count as added.
    monkeypatch.setattr("recupero.trace.ofac_sync.load_ofac_csv",
                        lambda *a, **k: [_entry(_A), _entry(_B, removed_at_utc="2026-06-09")])
    monkeypatch.setattr(mod, "_query_active_watchlist",
                        lambda dsn: [{"address": _B, "chain": "ethereum",
                                      "investigation_id": "inv", "role": "hop"}])
    assert screen_ofac_additions(dsn="dsn", snapshot_path=snap) == []


def test_dsn_none_still_advances_baseline_without_query(tmp_path, monkeypatch) -> None:
    snap = tmp_path / "seen.json"
    monkeypatch.setattr("recupero.trace.ofac_sync.load_ofac_csv",
                        lambda *a, **k: [_entry(_A)])
    screen_ofac_additions(dsn=None, snapshot_path=snap)  # baseline
    # New addition but dsn=None → no watchlist query, no alert, baseline advances.
    monkeypatch.setattr("recupero.trace.ofac_sync.load_ofac_csv",
                        lambda *a, **k: [_entry(_A), _entry(_B)])
    out = screen_ofac_additions(dsn=None, snapshot_path=snap)
    assert out == []
    assert load_snapshot(snap) is not None
