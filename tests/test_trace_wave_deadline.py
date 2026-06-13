"""#253 regression: a single BFS wave must honor the trace wall-clock deadline.

The runaway found by the no-answer-key Lazarus/Ronin trace: ``run_trace`` only
checked the deadline BETWEEN waves, so one wave over a large, expensive frontier
(dozens of high-fan-out $-consolidation nodes against a rate-limited API) ran for
80+ minutes — the trace never returned. ``_process_wave`` now stops collecting
once the deadline elapses and returns the partial wave, so the caller degrades to
a partial-trace case instead of hanging.

These tests block each node's work (a stand-in for slow network hops) and assert
the wave returns in far less than ``wave_size * per_node`` once the deadline is
hit — i.e. it does NOT wait for every node.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import recupero.trace.tracer as tracer

_WAVE = [(f"0x{i:040x}", 1) for i in range(8)]


def _slow_hop(seconds: float):
    def _hop(**_kwargs: Any) -> tuple[list, bool]:
        time.sleep(seconds)
        return ([], False)
    return _hop


def _run_wave(monkeypatch, *, deadline, concurrency, per_node=1.0):
    monkeypatch.setattr(tracer, "_trace_one_hop", _slow_hop(per_node))
    t0 = time.monotonic()
    results = tracer._process_wave(
        list(_WAVE),
        adapter=None, label_store=None, price_client=None, policy=None,
        incident_time=None, config=None, evidence_dir=Path("."),
        concurrency=concurrency, value_trace=False, deadline=deadline,
    )
    return results, time.monotonic() - t0


def test_threaded_wave_returns_promptly_when_deadline_passed(monkeypatch) -> None:
    # Deadline already elapsed: each node "hop" sleeps 1s, but the wave must NOT
    # block ~ (8 nodes / 4 workers) * 1s — it returns near-instantly with partial.
    past = datetime.now(UTC) - timedelta(seconds=1)
    results, elapsed = _run_wave(monkeypatch, deadline=past, concurrency=4, per_node=1.0)
    assert elapsed < 0.9, f"wave blocked for {elapsed:.2f}s past an elapsed deadline"
    assert len(results) < len(_WAVE)  # partial — did not wait for the frontier


def test_serial_wave_stops_at_deadline(monkeypatch) -> None:
    # concurrency=1 serial path is bounded too.
    past = datetime.now(UTC) - timedelta(seconds=1)
    results, elapsed = _run_wave(monkeypatch, deadline=past, concurrency=1, per_node=1.0)
    assert elapsed < 0.9
    assert results == []


def test_no_deadline_processes_whole_wave(monkeypatch) -> None:
    # deadline=None preserves the original behavior: every node is processed.
    results, _elapsed = _run_wave(
        monkeypatch, deadline=None, concurrency=4, per_node=0.02,
    )
    assert len(results) == len(_WAVE)


def test_far_deadline_processes_whole_wave(monkeypatch) -> None:
    # A deadline comfortably in the future also lets the full wave finish.
    future = datetime.now(UTC) + timedelta(seconds=30)
    results, _elapsed = _run_wave(
        monkeypatch, deadline=future, concurrency=4, per_node=0.02,
    )
    assert len(results) == len(_WAVE)
