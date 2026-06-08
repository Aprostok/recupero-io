"""Confirmed-win auto-arm (v0.39, Activation Sprint #2) — the compounding moat.

When stolen funds are actually frozen/returned at an address, it's confirmed
known-bad at the highest confidence and is armed into the internal blacklist so
future cases through it fire instantly. Pins:
  * ONLY win outcomes arm (full/partial freeze, returned_to_victim) — never
    acknowledged/declined/released/silence (no confirmation / affirmatively not bad);
  * malformed/empty addresses are skipped, never abort the batch;
  * idempotent (re-running rebuilds the same file — survives ephemeral data_dir);
  * armed entries are loadable + armed; the cron job is registered + DSN-skips.
"""

from __future__ import annotations

from pathlib import Path

from recupero._common import canonical_address_key as ck
from recupero.freeze_learning.confirmed_bad import (
    WIN_ARM_OUTCOMES,
    arm_rows,
    promote_confirmed_wins,
)
from recupero.labels.internal_blacklist import load_manual_arms

_HOLDER = "0x" + "ab" * 20
_HOLDER2 = "0x" + "cd" * 20
_DECLINED = "0x" + "ef" * 20


def _row(addr, outcome, *, chain="ethereum", issuer="Tether", case="case-1"):
    return {"target_address": addr, "chain": chain, "issuer": issuer,
            "case_id": case, "outcome_type": outcome}


def test_only_win_outcomes_arm(tmp_path: Path) -> None:
    mp = tmp_path / "internal_blacklist_manual.json"
    rows = [
        _row(_HOLDER, "full_freeze"),
        _row(_HOLDER2, "returned_to_victim"),
        _row(_DECLINED, "declined"),           # NOT a win → must not arm
        _row("0x" + "11" * 20, "acknowledged"),  # NOT a win
        _row("0x" + "22" * 20, "silence_14d"),    # NOT a win
    ]
    n = arm_rows(rows, manual_path=mp)
    assert n == 2
    armed = {e.address for e in load_manual_arms(mp)}
    assert armed == {ck(_HOLDER), ck(_HOLDER2)}
    assert ck(_DECLINED) not in armed


def test_partial_freeze_arms_and_is_win() -> None:
    assert "partial_freeze" in WIN_ARM_OUTCOMES
    assert "full_freeze" in WIN_ARM_OUTCOMES
    assert "returned_to_victim" in WIN_ARM_OUTCOMES
    assert "declined" not in WIN_ARM_OUTCOMES
    assert "released" not in WIN_ARM_OUTCOMES
    assert "acknowledged" not in WIN_ARM_OUTCOMES


def test_skips_malformed_addresses_without_aborting(tmp_path: Path) -> None:
    mp = tmp_path / "m.json"
    rows = [
        _row(None, "full_freeze"),        # missing addr
        _row("   ", "full_freeze"),       # blank
        _row(_HOLDER, "full_freeze"),     # good — must still arm
    ]
    assert arm_rows(rows, manual_path=mp) == 1
    assert {e.address for e in load_manual_arms(mp)} == {ck(_HOLDER)}


def test_idempotent_rebuild(tmp_path: Path) -> None:
    mp = tmp_path / "m.json"
    rows = [_row(_HOLDER, "full_freeze"), _row(_HOLDER2, "partial_freeze")]
    arm_rows(rows, manual_path=mp)
    arm_rows(rows, manual_path=mp)  # second run: rebuild, no duplicates
    arms = load_manual_arms(mp)
    assert sorted(e.address for e in arms) == sorted({ck(_HOLDER), ck(_HOLDER2)})
    assert all(e.alert_enabled for e in arms)


def test_armed_entry_reason_cites_outcome(tmp_path: Path) -> None:
    mp = tmp_path / "m.json"
    arm_rows([_row(_HOLDER, "full_freeze", issuer="Circle", case="abc")], manual_path=mp)
    e = load_manual_arms(mp)[0]
    assert "full_freeze" in e.reason and "Circle" in e.reason


def test_promote_confirmed_wins_uses_fetch(monkeypatch, tmp_path: Path) -> None:
    from recupero.freeze_learning import confirmed_bad
    monkeypatch.setattr(
        confirmed_bad, "fetch_confirmed_bad_rows",
        lambda dsn: [_row(_HOLDER, "full_freeze")],
    )
    mp = tmp_path / "m.json"
    n = promote_confirmed_wins(dsn="postgresql://x", manual_path=mp)
    assert n == 1
    assert {e.address for e in load_manual_arms(mp)} == {ck(_HOLDER)}


def test_cron_job_registered_and_dsn_skips(monkeypatch) -> None:
    from recupero.worker import cron_scheduler as cs
    assert "confirmed_win_autoarm" in {j.name for j in cs._build_default_jobs()}
    monkeypatch.setattr(cs, "_supabase_dsn", lambda: "")
    cs._job_promote_confirmed_wins()  # must not raise
