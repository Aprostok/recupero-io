"""Unit tests for the opt-in MistTrack auto-enrichment pipeline hook
(worker.pipeline._maybe_misttrack_enrich).

MistTrack is pay-per-lookup, so the hook is doubly gated (RECUPERO_MISTTRACK_AUTO
AND a key) and cost-capped (RECUPERO_MISTTRACK_MAX_ADDRS). These tests pin that
contract with the provider + enrichment functions monkeypatched — no key, no
network, no DB.
"""

from __future__ import annotations

import recupero.labels.misttrack_enrich as mte
import recupero.labels.providers.misttrack as mtp
from recupero.worker import pipeline


def _wire(monkeypatch, *, enabled=True, targets=(["0xabc", "0xdef"], "ethereum")):
    """Monkeypatch the lazily-imported deps; return a dict recording calls."""
    calls: dict = {"run": [], "targets": 0}
    monkeypatch.setattr(mtp, "misttrack_enabled", lambda: enabled)

    def _targets(case_id, **kw):
        calls["targets"] += 1
        return targets

    def _run(addrs, **kw):
        calls["run"].append({"addrs": addrs, **kw})
        return {"enabled": True, "targets": len(addrs), "queried": len(addrs)}

    monkeypatch.setattr(mte, "targets_from_case", _targets)
    monkeypatch.setattr(mte, "run_misttrack_enrichment", _run)
    return calls


def test_noop_when_flag_unset(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_MISTTRACK_AUTO", raising=False)
    calls = _wire(monkeypatch)
    pipeline._maybe_misttrack_enrich("inv-1")
    assert calls["run"] == [] and calls["targets"] == 0  # never even checked


def test_noop_when_key_absent(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_MISTTRACK_AUTO", "1")
    calls = _wire(monkeypatch, enabled=False)  # no MISTTRACK_API_KEY
    pipeline._maybe_misttrack_enrich("inv-1")
    assert calls["run"] == []


def test_runs_when_flag_and_key_set_with_cap(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_MISTTRACK_AUTO", "true")
    monkeypatch.setenv("RECUPERO_MISTTRACK_MAX_ADDRS", "10")
    calls = _wire(monkeypatch)
    pipeline._maybe_misttrack_enrich("inv-1")
    assert len(calls["run"]) == 1
    assert calls["run"][0]["addrs"] == ["0xabc", "0xdef"]
    assert calls["run"][0]["chain"] == "ethereum"
    assert calls["run"][0]["limit"] == 10  # cost cap threaded through


def test_default_cap_is_25(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_MISTTRACK_AUTO", "1")
    monkeypatch.delenv("RECUPERO_MISTTRACK_MAX_ADDRS", raising=False)
    calls = _wire(monkeypatch)
    pipeline._maybe_misttrack_enrich("inv-1")
    assert calls["run"][0]["limit"] == 25


def test_cap_zero_disables(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_MISTTRACK_AUTO", "1")
    monkeypatch.setenv("RECUPERO_MISTTRACK_MAX_ADDRS", "0")
    calls = _wire(monkeypatch)
    pipeline._maybe_misttrack_enrich("inv-1")
    assert calls["run"] == []


def test_noop_when_no_targets(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_MISTTRACK_AUTO", "1")
    calls = _wire(monkeypatch, targets=([], None))
    pipeline._maybe_misttrack_enrich("inv-1")
    assert calls["run"] == []


def test_never_raises_on_failure(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_MISTTRACK_AUTO", "1")
    monkeypatch.setattr(mtp, "misttrack_enabled", lambda: True)

    def _boom(case_id, **kw):
        raise RuntimeError("supabase down")

    monkeypatch.setattr(mte, "targets_from_case", _boom)
    # Must not raise — enrichment can never break case completion.
    pipeline._maybe_misttrack_enrich("inv-1")


def test_bad_cap_keeps_default(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_MISTTRACK_AUTO", "1")
    monkeypatch.setenv("RECUPERO_MISTTRACK_MAX_ADDRS", "not-an-int")
    calls = _wire(monkeypatch)
    pipeline._maybe_misttrack_enrich("inv-1")
    assert calls["run"][0]["limit"] == 25
