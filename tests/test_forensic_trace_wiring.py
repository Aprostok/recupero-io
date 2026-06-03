"""v0.36.0 — forensic-trace wiring: RECUPERO_DEEP_REACH enables the
cryptographic cross-chain bridge-pairing oracle.

Context (Jacob V-CFI02 follow-up, "what needs to be added to the initial
trace"): the engine already has everything a real bridge case needs —
240 bridge seeds, an 8-protocol cryptographic pairing oracle
(DLN/Across/Celer/Hop/Synapse/CCIP/Connext/Wormhole, "verified vs Zigha"),
cross-chain BFS continuation (default ON), and value-directed deep-reach.
The only reason a default run under-traces a bridge case is that the
forensic-depth gates are OFF by default for byte-identical fixture
stability.

v0.36.0 folds the bridge-pairing oracle into the deep-reach master switch
so a single knob (`RECUPERO_DEEP_REACH=1`, the recommended production
setting) turns on the FULL forensic recipe, while keeping the default OFF
(byte-identical). This pins the resolution contract so it can't silently
regress.

Contract (`_bridge_confirm_enabled`):
  * neither env var set                         -> OFF  (byte-identical)
  * RECUPERO_DEEP_REACH=1 (BRIDGE_CONFIRM unset)-> ON   (inherits deep-reach)
  * explicit RECUPERO_BRIDGE_CONFIRM always wins (even =0 under deep-reach)
"""

from __future__ import annotations

import pytest

from recupero.trace.tracer import _bridge_confirm_enabled

_BC = "RECUPERO_BRIDGE_CONFIRM"
_DR = "RECUPERO_DEEP_REACH"


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_BC, raising=False)
    monkeypatch.delenv(_DR, raising=False)


def test_default_off_byte_identical() -> None:
    # Neither set — the standard trace must NOT run the oracle (preserves
    # every existing fixture, incl. Zigha 4/4, byte-identically).
    assert _bridge_confirm_enabled() is False


def test_deep_reach_enables_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    # The recommended production setting: one knob turns on the oracle.
    monkeypatch.setenv(_DR, "1")
    assert _bridge_confirm_enabled() is True


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "TRUE", "On"])
def test_explicit_bridge_confirm_on(
    monkeypatch: pytest.MonkeyPatch, val: str,
) -> None:
    monkeypatch.setenv(_BC, val)
    assert _bridge_confirm_enabled() is True


def test_explicit_bridge_confirm_off_wins_over_deep_reach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Operator wants a cheaper same-chain-only deep pass: deep-reach on,
    # oracle explicitly pinned off. The explicit value must win.
    monkeypatch.setenv(_DR, "1")
    monkeypatch.setenv(_BC, "0")
    assert _bridge_confirm_enabled() is False


def test_deep_reach_off_keeps_oracle_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_DR, "0")
    assert _bridge_confirm_enabled() is False


def test_explicit_bridge_confirm_on_without_deep_reach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Bridge-follow-only profile: oracle on, deep-reach untouched.
    monkeypatch.setenv(_BC, "1")
    assert _bridge_confirm_enabled() is True
