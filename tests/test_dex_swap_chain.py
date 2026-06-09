"""Roadmap-#1 v3 item #8: iterative multi-swap-chain continuation.

The same-chain DEX continuation used to collect swap-output recipients ONCE, so a
chain of 3+ swaps (USDT->WBTC->ETH->...) dead-ended after the first.
_continue_dex_swap_chain re-collects swap-output seeds from each round's new
transfers, bounded by RECUPERO_DEX_SWAP_MAX_ROUNDS (default 1 = byte-identical
single pass — that default path is locked by the full tracer regression).
"""

from __future__ import annotations

from types import SimpleNamespace

import recupero.trace.tracer as tracer_mod
from recupero.models import Chain
from recupero.trace.tracer import _continue_dex_swap_chain, _dex_swap_max_rounds


def test_dex_swap_max_rounds_default_clamp_and_garbage(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_DEX_SWAP_MAX_ROUNDS", raising=False)
    assert _dex_swap_max_rounds() == 1            # default = byte-identical
    monkeypatch.setenv("RECUPERO_DEX_SWAP_MAX_ROUNDS", "3")
    assert _dex_swap_max_rounds() == 3
    monkeypatch.setenv("RECUPERO_DEX_SWAP_MAX_ROUNDS", "99")
    assert _dex_swap_max_rounds() == 8            # clamp high
    monkeypatch.setenv("RECUPERO_DEX_SWAP_MAX_ROUNDS", "0")
    assert _dex_swap_max_rounds() == 1            # clamp low
    monkeypatch.setenv("RECUPERO_DEX_SWAP_MAX_ROUNDS", "garbage")
    assert _dex_swap_max_rounds() == 1            # fallback


def _xfer(h):
    return SimpleNamespace(tx_hash=h)


def _run_chain(monkeypatch, *, max_rounds, collect_fn, wave_fn):
    monkeypatch.setattr(tracer_mod, "_collect_swap_output_seeds", collect_fn)
    monkeypatch.setattr(tracer_mod, "_process_wave", wave_fn)
    return _continue_dex_swap_chain(
        [_xfer("init")], chain=Chain.ethereum, adapter=None,
        label_store=None, price_client=None, policy=SimpleNamespace(),
        incident_time=None, config=None, evidence_dir=None, visited=set(),
        trace_concurrency=1, max_rounds=max_rounds,
    )


def test_follows_until_dry(monkeypatch) -> None:
    calls = {"collect": 0, "wave": 0}

    def collect(transfers, *, chain, adapter, visited):
        calls["collect"] += 1
        return ["0xseed"] if calls["collect"] == 1 else []  # one round, then dry

    def wave(wv, **kw):
        calls["wave"] += 1
        return [(wv[0][0], 1, [_xfer(f"r{calls['wave']}")], False)]

    extra = _run_chain(monkeypatch, max_rounds=3, collect_fn=collect, wave_fn=wave)
    assert len(extra) == 1          # one productive round, then dry → stop
    assert calls["wave"] == 1
    assert calls["collect"] == 2    # round-1 (seed) + round-2 (dry → break)


def test_noop_when_max_rounds_is_one(monkeypatch) -> None:
    def collect(*a, **k):
        raise AssertionError("must not collect when max_rounds == 1")

    extra = _run_chain(monkeypatch, max_rounds=1, collect_fn=collect,
                       wave_fn=lambda *a, **k: [])
    assert extra == []              # rounds_left == 0 → loop body never runs


def test_respects_round_cap(monkeypatch) -> None:
    # Every round finds a fresh seed → bounded strictly by max_rounds-1 waves.
    calls = {"wave": 0}

    def collect(transfers, *, chain, adapter, visited):
        return ["0xseed"]           # never goes dry

    def wave(wv, **kw):
        calls["wave"] += 1
        return [(wv[0][0], 1, [_xfer(f"r{calls['wave']}")], False)]

    extra = _run_chain(monkeypatch, max_rounds=4, collect_fn=collect, wave_fn=wave)
    assert calls["wave"] == 3       # max_rounds(4) - 1 round already done by caller
    assert len(extra) == 3
