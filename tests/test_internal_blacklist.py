"""Internal known-bad blacklist harvested from the case corpus (v0.39).

The SAFETY-CRITICAL contract: an address is ARMED (alert-triggering) ONLY when
it was seen in a REAL investigation, in an illicit role
(perpetrator/mixer/current-holder), and is not a victim or legitimate service.
Arming a test-fixture / victim / exchange / bridge address would false-alarm on
legitimate future cases and risk a wrongful freeze — so these pins are strict.

Also pins: dedup provenance + OR-arming, the high-risk projection (category +
severity), JSON round-trip, the screener firing "high" on a hit (NEVER
"sanctioned"), and load_high_risk_db merging only the armed subset.
"""

from __future__ import annotations

from pathlib import Path

from recupero._common import canonical_address_key as ck
from recupero.labels.internal_blacklist import (
    AddressObservation,
    add_manual_arm,
    armed_high_risk_entries,
    build_blacklist,
    load_blacklist_entries,
    load_manual_arms,
    remove_manual_arm,
    save_blacklist,
)

_PERP = "0x" + "a1" * 20
_MIX = "0x" + "b2" * 20
_HOLD = "0x" + "c3" * 20
_HOP = "0x" + "d4" * 20
_EXCH = "0x" + "e5" * 20
_BRIDGE = "0x" + "f6" * 20
_FIXTURE_PERP = "0x" + "17" * 20


def _obs(address, role, *, inv, test, cat=None, name=None):
    return AddressObservation(
        address=address, chain="ethereum", role=role,
        label_category=cat, label_name=name,
        investigation_id=inv, case_is_test=test,
    )


def test_arms_only_real_illicit_roles() -> None:
    obs = [
        _obs(_PERP, "perpetrator", inv="real-1", test=False),
        _obs(_MIX, "mixer", inv="real-1", test=False, cat="mixer", name="Tornado"),
        _obs(_HOLD, "current_holder", inv="real-1", test=False),
        _obs(_HOP, "hop", inv="real-1", test=False),            # ambiguous → no arm
        _obs(_EXCH, "exchange_deposit", inv="real-1", test=False),  # service → no arm
        _obs(_BRIDGE, "bridge", inv="real-1", test=False),      # service → no arm
        _obs(_FIXTURE_PERP, "perpetrator", inv="test-9", test=True),  # fixture → no arm
    ]
    entries = {e.address: e for e in build_blacklist(obs)}
    armed = {a for a, e in entries.items() if e.alert_enabled}
    assert armed == {ck(_PERP), ck(_MIX), ck(_HOLD)}
    # Everything is still INGESTED (visible context) — just not armed.
    assert set(entries) == {
        ck(_PERP), ck(_MIX), ck(_HOLD), ck(_HOP), ck(_EXCH), ck(_BRIDGE),
        ck(_FIXTURE_PERP),
    }
    # The fixture perpetrator is present but explicitly NOT armed.
    assert entries[ck(_FIXTURE_PERP)].alert_enabled is False


def test_dedup_merges_provenance_and_or_arms() -> None:
    # 0xMIX: mixer in a real case + a benign hop in a test fixture → armed,
    # strongest role wins, provenance accumulates, real_case_count=1 → medium.
    obs = [
        _obs(_MIX, "mixer", inv="real-1", test=False, cat="mixer", name="Sinbad"),
        _obs(_MIX, "hop", inv="test-2", test=True),
        # 0xPERP: perpetrator in TWO distinct real cases → high confidence.
        _obs(_PERP, "perpetrator", inv="real-1", test=False),
        _obs(_PERP, "perpetrator", inv="real-3", test=False),
    ]
    entries = {e.address: e for e in build_blacklist(obs)}
    mix = entries[ck(_MIX)]
    assert mix.alert_enabled is True
    assert mix.role == "mixer"                     # strongest of {mixer, hop}
    assert mix.source_case_count == 2
    assert mix.real_case_count == 1
    assert mix.confidence == "medium"
    assert sorted(mix.source_investigation_ids) == ["real-1", "test-2"]

    perp = entries[ck(_PERP)]
    assert perp.alert_enabled is True
    assert perp.real_case_count == 2
    assert perp.confidence == "high"


def test_armed_high_risk_entries_projection() -> None:
    obs = [
        _obs(_MIX, "mixer", inv="real-1", test=False, name="Tornado"),
        _obs(_HOP, "hop", inv="real-1", test=False),         # not armed
        _obs(_FIXTURE_PERP, "perpetrator", inv="t-1", test=True),  # not armed
    ]
    hrd = armed_high_risk_entries(build_blacklist(obs))
    assert set(hrd) == {ck(_MIX)}                            # only the armed one
    e = hrd[ck(_MIX)]
    assert e.risk_category == "internal_blacklist"
    assert e.severity == 3
    assert "Tornado" in e.name


def test_save_load_roundtrip(tmp_path: Path) -> None:
    obs = [_obs(_PERP, "perpetrator", inv="real-1", test=False)]
    entries = build_blacklist(obs)
    p = tmp_path / "intel" / "internal_blacklist.json"
    assert save_blacklist(entries, p) == 1
    loaded = load_blacklist_entries(p)
    assert len(loaded) == 1
    assert loaded[0].address == ck(_PERP)
    assert loaded[0].alert_enabled is True
    # Missing file → empty, never raises.
    assert load_blacklist_entries(tmp_path / "nope.json") == []


def test_screener_fires_high_on_internal_blacklist_hit() -> None:
    from recupero.screen.screener import screen_address

    obs = [_obs(_MIX, "mixer", inv="real-1", test=False, name="Sinbad")]
    hrd = armed_high_risk_entries(build_blacklist(obs))
    res = screen_address(_MIX, chain="ethereum", use_correlation_db=False,
                         high_risk_db=hrd)
    # Internal attribution → HIGH, never SANCTIONED (not an OFAC designation).
    assert res.risk_verdict == "high"
    assert res.is_ofac_sanctioned is False
    cats = {label.category for label in res.labels}
    assert "internal_blacklist" in cats
    src = {label.source for label in res.labels}
    assert "internal_blacklist" in src
    assert "internal blacklist" in res.investigator_note.lower()


def test_screener_clean_when_not_listed() -> None:
    from recupero.screen.screener import screen_address

    hrd = armed_high_risk_entries(build_blacklist(
        [_obs(_MIX, "mixer", inv="real-1", test=False)]
    ))
    # A different, unlisted address screens clean against the same DB.
    res = screen_address(_HOLD, chain="ethereum", use_correlation_db=False,
                         high_risk_db=hrd)
    assert res.risk_verdict == "clean"


def test_load_high_risk_db_merges_only_armed(tmp_path: Path) -> None:
    from recupero.trace.risk_scoring import load_high_risk_db

    obs = [
        _obs(_MIX, "mixer", inv="real-1", test=False, name="Tornado"),
        _obs(_HOP, "hop", inv="real-1", test=False),              # not armed
        _obs(_FIXTURE_PERP, "perpetrator", inv="t-1", test=True),  # not armed
    ]
    p = tmp_path / "internal_blacklist.json"
    save_blacklist(build_blacklist(obs), p)

    missing = tmp_path / "does_not_exist.json"
    db = load_high_risk_db(
        high_risk_path=missing, mixers_path=missing, ransomware_path=missing,
        ofac_csv_path=missing, intl_sanctions_csv_path=missing,
        scam_drainers_path=missing, internal_blacklist_path=p,
        internal_blacklist_seed_path=missing,
    )
    assert ck(_MIX) in db
    assert db[ck(_MIX)].risk_category == "internal_blacklist"
    # Non-armed addresses are NEVER merged into the risk DB.
    assert ck(_HOP) not in db
    assert ck(_FIXTURE_PERP) not in db


def test_committed_seed_loads_ronin_armed() -> None:
    """The shipped curated seed file parses, and the Ronin/Lazarus exploiter is
    present + armed (a regression guard on the seed file itself)."""
    from recupero.trace.risk_scoring import _INTERNAL_BLACKLIST_SEED_PATH

    entries = load_blacklist_entries(_INTERNAL_BLACKLIST_SEED_PATH)
    armed = {e.address for e in entries if e.alert_enabled}
    ronin = ck("0x098b716b8aaf21512996dc57eb0615e2383e2f96")
    assert ronin in armed
    hrd = armed_high_risk_entries(entries)
    assert hrd[ronin].risk_category == "internal_blacklist"


# ----- operator-curated manual arms ----- #


def test_manual_arm_add_load_remove(tmp_path: Path) -> None:
    p = tmp_path / "intel" / "internal_blacklist_manual.json"
    assert add_manual_arm(p, _PERP, "ethereum",
                          reason="Ronin/Lazarus exploiter seed") is True
    # re-arming the same address updates (no duplicate row), returns False
    assert add_manual_arm(p, _PERP, "ethereum", reason="updated") is False
    arms = load_manual_arms(p)
    assert len(arms) == 1
    assert arms[0].address == ck(_PERP)
    assert arms[0].alert_enabled is True
    assert arms[0].role == "manual"
    assert "updated" in arms[0].reason
    # disarm
    assert remove_manual_arm(p, _PERP, "ethereum") is True
    assert load_manual_arms(p) == []
    assert remove_manual_arm(p, _PERP, "ethereum") is False  # already gone


def test_manual_arm_rejects_uncanonicalizable(tmp_path: Path) -> None:
    import pytest
    p = tmp_path / "manual.json"
    with pytest.raises(ValueError):
        add_manual_arm(p, "   ", "ethereum")


def test_load_high_risk_db_picks_up_manual_arms(tmp_path: Path) -> None:
    from recupero.trace.risk_scoring import load_high_risk_db

    auto = tmp_path / "internal_blacklist.json"
    save_blacklist([], auto)  # empty auto file
    # Manual arm lives in the sibling file the loader derives.
    manual = tmp_path / "internal_blacklist_manual.json"
    add_manual_arm(manual, _HOLD, "ethereum", reason="hand-attributed mule")

    missing = tmp_path / "missing.json"
    db = load_high_risk_db(
        high_risk_path=missing, mixers_path=missing, ransomware_path=missing,
        ofac_csv_path=missing, intl_sanctions_csv_path=missing,
        scam_drainers_path=missing, internal_blacklist_path=auto,
    )
    assert ck(_HOLD) in db
    assert db[ck(_HOLD)].risk_category == "internal_blacklist"
