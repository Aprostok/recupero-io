"""v0.36.0 + v0.37.0 — forensic-trace wiring + deep-reach-is-default.

Recupero goes DEEP on every trace. The engine already had the full forensic
recipe — 240 bridge seeds, an 8-protocol cryptographic pairing oracle
(DLN/Across/Celer/Hop/Synapse/CCIP/Connext/Wormhole, "verified vs Zigha"),
cross-chain BFS continuation, value-directed deep-reach (peel/split follow,
dormancy window, labeled mixer/exchange/bridge terminals). It used to be
gated OFF by default; v0.37.0 makes deep-reach the DEFAULT so a standard
trace follows funds to where they rest (across bridges, through aggregators,
past peels) instead of stopping at the first hop.

This pins the two resolution contracts so they can't silently regress:

  _deep_reach_enabled():
    * nothing set                 -> ON   (the new default — go deep)
    * RECUPERO_DEEP_REACH=0        -> OFF  (opt-out: legacy/cheap pass)

  _bridge_confirm_enabled() (the cross-chain oracle):
    * inherits deep-reach when RECUPERO_BRIDGE_CONFIRM is unset
    * explicit RECUPERO_BRIDGE_CONFIRM always wins (even =0 under deep-reach)
"""

from __future__ import annotations

import pytest

from recupero.trace.tracer import (
    _bridge_confirm_enabled,
    _crosschain_max_bridge_hops,
    _deep_reach_enabled,
)

_BC = "RECUPERO_BRIDGE_CONFIRM"
_DR = "RECUPERO_DEEP_REACH"


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_BC, raising=False)
    monkeypatch.delenv(_DR, raising=False)


# ── deep-reach default ────────────────────────────────────────────────

def test_deep_reach_is_on_by_default() -> None:
    # v0.37.0: nothing set ⇒ deep. This is the headline behavior change.
    assert _deep_reach_enabled() is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off", "OFF", "False"])
def test_deep_reach_opt_out(monkeypatch: pytest.MonkeyPatch, val: str) -> None:
    monkeypatch.setenv(_DR, val)
    assert _deep_reach_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "TRUE"])
def test_deep_reach_explicit_on(monkeypatch: pytest.MonkeyPatch, val: str) -> None:
    monkeypatch.setenv(_DR, val)
    assert _deep_reach_enabled() is True


# ── cross-chain oracle inherits deep-reach ─────────────────────────────

def test_oracle_on_by_default() -> None:
    # Nothing set ⇒ deep ⇒ the cryptographic cross-chain oracle runs.
    assert _bridge_confirm_enabled() is True


def test_oracle_off_when_deep_reach_opted_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_DR, "0")
    assert _bridge_confirm_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on"])
def test_explicit_bridge_confirm_on(
    monkeypatch: pytest.MonkeyPatch, val: str,
) -> None:
    monkeypatch.setenv(_BC, val)
    assert _bridge_confirm_enabled() is True


def test_explicit_bridge_confirm_off_wins_over_deep_reach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Cheaper same-chain-only deep pass: deep on, oracle explicitly pinned off.
    monkeypatch.setenv(_DR, "1")
    monkeypatch.setenv(_BC, "0")
    assert _bridge_confirm_enabled() is False


def test_explicit_bridge_confirm_on_overrides_deep_reach_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Bridge-follow-only on an otherwise-shallow pass.
    monkeypatch.setenv(_DR, "0")
    monkeypatch.setenv(_BC, "1")
    assert _bridge_confirm_enabled() is True


# ── multi-bridge recursion hop cap (deep cross-chain #2) ───────────────

_MBH = "RECUPERO_CROSSCHAIN_MAX_BRIDGE_HOPS"


def test_bridge_hops_default_deep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_MBH, raising=False)
    # deep-reach default ON ⇒ follow up to 4 consecutive bridge crossings.
    assert _crosschain_max_bridge_hops() == 4


def test_bridge_hops_single_when_deep_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_MBH, raising=False)
    monkeypatch.setenv(_DR, "0")
    # deep-reach opted out ⇒ legacy single crossing.
    assert _crosschain_max_bridge_hops() == 1


def test_bridge_hops_explicit_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_DR, "0")
    monkeypatch.setenv(_MBH, "6")
    assert _crosschain_max_bridge_hops() == 6


def test_bridge_hops_clamped_to_at_least_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_MBH, "0")
    assert _crosschain_max_bridge_hops() == 1


def test_bridge_hops_bad_value_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_MBH, "abc")  # bad → deep-reach-derived default
    monkeypatch.delenv(_DR, raising=False)
    assert _crosschain_max_bridge_hops() == 4
