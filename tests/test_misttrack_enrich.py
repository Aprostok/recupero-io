"""Tests for the MistTrack enrichment wiring (labels/misttrack_enrich.py).

No network and no DB: a fake httpx-shaped client feeds canned MistTrack
``/address_labels`` bodies, and ``persist_candidates`` is monkeypatched to a
recorder. The no-key path is proven inert with a client that raises on any use.
"""
from __future__ import annotations

import pytest

from recupero.labels.internal_blacklist import AddressObservation
from recupero.labels.misttrack_enrich import (
    EnrichmentResult,
    _dedup_clean,
    resolve_targets,
    run_misttrack_enrichment,
    select_attribution_targets,
    targets_from_case,
)

_KEY = "test-misttrack-key"


# --------------------------------------------------------------------------- #
# Fakes matching what providers.misttrack._get calls: client.get(url, params=,
# follow_redirects=) -> resp with .status_code + .json().
# --------------------------------------------------------------------------- #
class _FakeResp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class _FakeClient:
    def __init__(self, by_address):
        self.by_address = by_address
        self.calls = []

    def get(self, url, params=None, follow_redirects=False):
        params = params or {}
        addr = params.get("address")
        self.calls.append(addr)
        body = self.by_address.get(addr)
        if body is None:
            return _FakeResp(200, {"success": False})
        return _FakeResp(200, body)


class _ExplodingClient:
    def get(self, *a, **k):
        raise AssertionError("network call made when no key is set")


def _exchange_body(name):
    return {"success": True, "data": {"label_type": "exchange",
                                      "label_list": [name]}}


def _scam_body(tag):
    return {"success": True, "data": {"label_type": "malicious",
                                      "label_list": [tag]}}


def _unmapped_body():
    return {"success": True, "data": {"label_type": "defi",
                                      "label_list": ["Some Generic Pool"]}}


@pytest.fixture(autouse=True)
def _no_env_key(monkeypatch):
    """Never let a real ambient key leak into these tests."""
    monkeypatch.delenv("MISTTRACK_API_KEY", raising=False)


# --------------------------------------------------------------------------- #
# _dedup_clean
# --------------------------------------------------------------------------- #
def test_dedup_clean_strips_dedups_and_drops_non_str():
    out = _dedup_clean(["  0xabc ", "0xabc", "", "  ", None, 123, "0xdef"])
    assert out == ["0xabc", "0xdef"]


# --------------------------------------------------------------------------- #
# resolve_targets
# --------------------------------------------------------------------------- #
def test_resolve_targets_exchange_hit_low_confidence_candidate():
    addr = "0x1111111111111111111111111111111111111111"
    fake = _FakeClient({addr: _exchange_body("Binance 14")})
    cands = resolve_targets([addr], chain="ethereum", api_key=_KEY,
                            http_client=fake)
    assert len(cands) == 1
    c = cands[0]
    assert c.proposed_category == "exchange_hot_wallet"
    assert c.proposed_confidence == "low"      # doctrine: MistTrack is never high
    assert c.source == "misttrack"
    assert c.proposed_name.startswith("MistTrack:")
    assert c.address == addr.lower()


def test_resolve_targets_scam_categorized():
    addr = "0x2222222222222222222222222222222222222222"
    fake = _FakeClient({addr: _scam_body("Fake_Phishing 7")})
    cands = resolve_targets([addr], chain="ethereum", api_key=_KEY,
                            http_client=fake)
    assert len(cands) == 1
    assert cands[0].proposed_category == "scam_drainer"
    assert cands[0].proposed_confidence == "low"


def test_resolve_targets_unmapped_label_yields_nothing():
    addr = "0x3333333333333333333333333333333333333333"
    fake = _FakeClient({addr: _unmapped_body()})
    cands = resolve_targets([addr], chain="ethereum", api_key=_KEY,
                            http_client=fake)
    assert cands == []
    assert fake.calls == [addr]  # it WAS queried, just not categorizable


def test_resolve_targets_dedups_before_querying():
    addr = "0x4444444444444444444444444444444444444444"
    fake = _FakeClient({addr: _exchange_body("Kraken 2")})
    cands = resolve_targets([addr, addr, "  " + addr + " "], chain="ethereum",
                            api_key=_KEY, http_client=fake)
    assert len(cands) == 1
    assert fake.calls == [addr]  # queried exactly once despite 3 inputs


def test_resolve_targets_limit_caps_paid_queries():
    a = [f"0x{i:040d}" for i in range(5)]
    fake = _FakeClient({x: _exchange_body("OKX") for x in a})
    cands = resolve_targets(a, chain="ethereum", api_key=_KEY,
                            http_client=fake, limit=2)
    assert len(fake.calls) == 2      # only 2 paid queries
    assert len(cands) == 2


def test_resolve_targets_no_key_is_inert_and_makes_no_call():
    cands = resolve_targets(["0xabc"], chain="ethereum",
                            http_client=_ExplodingClient())
    assert cands == []


# --------------------------------------------------------------------------- #
# run_misttrack_enrichment
# --------------------------------------------------------------------------- #
def test_run_no_key_returns_disabled_result_no_db(monkeypatch):
    # persist must NEVER be reached on the no-key path
    import recupero.labels.auto_ingest as ai

    def _boom(*a, **k):
        raise AssertionError("persist hit with no key")

    monkeypatch.setattr(ai, "persist_candidates", _boom)
    res = run_misttrack_enrichment(["0xabc", "0xabc", "0xdef"],
                                   http_client=_ExplodingClient())
    assert res == EnrichmentResult(enabled=False, targets=2, queried=0,
                                   resolved=0, persisted=0)


def test_run_persists_resolved_candidates(monkeypatch):
    import recupero.labels.auto_ingest as ai
    captured = {}

    def _fake_persist(cands, *, dsn=None, daily_cap=None):
        captured["cands"] = cands
        captured["dsn"] = dsn
        return len(cands)

    monkeypatch.setattr(ai, "persist_candidates", _fake_persist)

    a1 = "0x5555555555555555555555555555555555555555"
    a2 = "0x6666666666666666666666666666666666666666"
    a3 = "0x7777777777777777777777777777777777777777"  # unmapped
    fake = _FakeClient({
        a1: _exchange_body("Coinbase 3"),
        a2: _scam_body("drainer cluster"),
        a3: _unmapped_body(),
    })
    res = run_misttrack_enrichment([a1, a2, a3], chain="ethereum",
                                   api_key=_KEY, http_client=fake)
    assert res.enabled is True
    assert res.targets == 3
    assert res.queried == 3
    assert res.resolved == 2          # a3 not categorizable
    assert res.persisted == 2
    cats = sorted(c.proposed_category for c in captured["cands"])
    assert cats == ["exchange_hot_wallet", "scam_drainer"]


def test_run_resolved_zero_skips_persist(monkeypatch):
    import recupero.labels.auto_ingest as ai

    def _boom(*a, **k):
        raise AssertionError("persist called with zero candidates")

    monkeypatch.setattr(ai, "persist_candidates", _boom)
    addr = "0x8888888888888888888888888888888888888888"
    fake = _FakeClient({addr: _unmapped_body()})
    res = run_misttrack_enrichment([addr], chain="ethereum", api_key=_KEY,
                                   http_client=fake)
    assert res.enabled is True
    assert res.resolved == 0
    assert res.persisted == 0


# --------------------------------------------------------------------------- #
# select_attribution_targets (pure) + targets_from_case (guarded I/O)
# --------------------------------------------------------------------------- #
def _obs(address, *, chain="ethereum", role="hop", label_category=None,
         label_name=None, case_is_test=False):
    return AddressObservation(
        address=address, chain=chain, role=role,
        label_category=label_category, label_name=label_name,
        investigation_id="inv-test", case_is_test=case_is_test,
    )


def test_select_targets_keeps_only_unlabeled():
    obs = [
        _obs("0xUNKNOWN1"),                                   # keep (unlabeled hop)
        _obs("0xKNOWN", label_category="exchange_deposit",
             label_name="Binance"),                           # drop (attributed)
        _obs("0xNAMED", label_name="Some Service"),           # drop (named)
        _obs("0xUNKNOWN2", role="unlabeled"),                 # keep
    ]
    addrs, chain = select_attribution_targets(obs)
    assert addrs == ["0xUNKNOWN1", "0xUNKNOWN2"]
    assert chain == "ethereum"


def test_select_targets_dedups_canonically():
    # canonical_address_key lower-cases valid 0x+40hex addrs; mixed-case
    # variants of the SAME address must collapse to one target.
    mixed = "0x" + "aB" * 20          # 40 hex chars, mixed case
    obs = [_obs(mixed), _obs(mixed.lower()),
           _obs("0x" + "Ab" * 20)]
    addrs, chain = select_attribution_targets(obs)
    assert len(addrs) == 1            # canonical-key dedup (EVM case-insensitive)
    assert chain == "ethereum"


def test_select_targets_excludes_test_fixtures_by_default():
    obs = [_obs("0xFIXTURE", case_is_test=True), _obs("0xREAL")]
    addrs, _ = select_attribution_targets(obs)
    assert addrs == ["0xREAL"]
    addrs_all, _ = select_attribution_targets(obs, include_test=True)
    assert set(addrs_all) == {"0xFIXTURE", "0xREAL"}


def test_select_targets_empty_returns_none_chain():
    assert select_attribution_targets([]) == ([], None)
    # a case of only-labeled addresses yields no targets
    only_labeled = [_obs("0xX", label_category="exchange_deposit")]
    assert select_attribution_targets(only_labeled) == ([], None)


def test_select_targets_carries_non_evm_chain():
    obs = [_obs("Txxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", chain="tron")]
    addrs, chain = select_attribution_targets(obs)
    assert chain == "tron"
    assert len(addrs) == 1


def test_targets_from_case_guarded_when_supabase_disabled(monkeypatch):
    import recupero.api._supabase_case_source as sb
    monkeypatch.setattr(sb, "enabled", lambda: False)
    assert targets_from_case("some-case-id") == ([], None)
