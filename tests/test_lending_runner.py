"""Roadmap-v4 Tier-2 #11 (slice 1): Aave V3 park-and-withdraw leads.

The fixture Withdraw log is a REAL mainnet log captured live (2026-06) from
the verified Aave V3 Pool: reserve=WETH topic 1, user topic 2, to topic 3,
amount = one data word.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from recupero.trace.lending_runner import (
    AAVE_V3_POOL_BY_CHAIN,
    AAVE_V3_WITHDRAW_TOPIC0,
    COMPOUND_V3_COMETS_BY_CHAIN,
    COMPOUND_V3_WITHDRAW_TOPIC0,
    comet_withdraws_from_logs,
    leads_to_json,
    lending_leads_enabled,
    run_lending_leads,
    withdraws_from_logs,
)

_POOL = AAVE_V3_POOL_BY_CHAIN["ethereum"]
_WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
_USER = "0x872fbcb1b582e8cd0d0dd4327fbfa0b4c2730995"
_FRESH = "0x" + "fe" * 20


def _topic_addr(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:].lower()


# REAL Withdraw log (live-captured 2026-06): user == to (back-to-self).
_REAL_WITHDRAW_LOG = {
    "address": _POOL,
    "topics": [
        AAVE_V3_WITHDRAW_TOPIC0,
        _topic_addr(_WETH),
        _topic_addr(_USER),
        _topic_addr(_USER),
    ],
    "data": "0x00000000000000000000000000000000000000000000000000038d7ea4c68000",
    "transactionHash":
        "0x4a88a8c6a43b5df2ee59ebcf266225fbc5b876f202009422f0f9d05cc4915f35",
}


def _cross_address_log(user: str, to: str) -> dict[str, Any]:
    return {
        **_REAL_WITHDRAW_LOG,
        "topics": [
            AAVE_V3_WITHDRAW_TOPIC0,
            _topic_addr(_WETH),
            _topic_addr(user),
            _topic_addr(to),
        ],
        "transactionHash": "0xexit",
    }


def _transfer(frm):
    return SimpleNamespace(from_address=frm, to_address="0x" + "11" * 20)


class _StubAdapter:
    def __init__(self, logs, comet_logs=None):
        self.logs = logs                       # Aave Withdraw logs
        self.comet_logs = comet_logs or []     # Comet Withdraw logs
        self.calls: list[dict[str, Any]] = []

    def fetch_logs(self, address, topic0, *, from_block, to_block, topics=None):
        self.calls.append({"address": address, "topic0": topic0, "topics": topics})
        if topic0 == COMPOUND_V3_WITHDRAW_TOPIC0:
            return self.comet_logs
        return self.logs


def test_gate_default_off(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_LENDING_LEADS", raising=False)
    assert lending_leads_enabled() is False
    assert run_lending_leads(transfers=[_transfer(_USER)], adapter=None) == []
    monkeypatch.setenv("RECUPERO_LENDING_LEADS", "true")
    assert lending_leads_enabled() is True


def test_withdraws_parse_real_log() -> None:
    rows = withdraws_from_logs([_REAL_WITHDRAW_LOG])
    assert len(rows) == 1
    r = rows[0]
    assert r["reserve"] == _WETH
    assert r["user"] == _USER
    assert r["to"] == _USER
    assert r["amount_raw"] == str(0x38D7EA4C68000)  # 0.001 WETH raw


def test_withdraws_reject_malformed_topics() -> None:
    bad = dict(_REAL_WITHDRAW_LOG)
    bad["topics"] = [AAVE_V3_WITHDRAW_TOPIC0, "0x" + "ff" * 32,
                     _topic_addr(_USER), _topic_addr(_USER)]
    assert withdraws_from_logs([bad]) == []   # non-address-shaped reserve topic


def test_back_to_self_withdrawal_is_not_a_lead() -> None:
    adapter = _StubAdapter([_REAL_WITHDRAW_LOG])
    leads = run_lending_leads(
        transfers=[_transfer(_USER)], adapter=adapter, force=True,
    )
    assert leads == []  # funds returned to the traced wallet — BFS covers them
    # the getLogs call filtered on topic2 = the traced wallet (topic1 = None)
    assert adapter.calls[0]["topics"] == [None, _topic_addr(_USER)]


def test_cross_address_withdrawal_is_a_high_lead() -> None:
    adapter = _StubAdapter([
        _REAL_WITHDRAW_LOG,                        # back-to-self: context only
        _cross_address_log(_USER, _FRESH),          # the invisible exit
    ])
    leads = run_lending_leads(
        transfers=[_transfer(_USER)], adapter=adapter, force=True,
    )
    assert len(leads) == 1
    ld = leads[0]
    assert ld["user"] == _USER
    assert ld["exit_recipient"] == _FRESH
    assert ld["reserve"] == _WETH
    assert ld["confidence"] == "high"            # both topics protocol-stamped
    assert ld["protocol"] == "aave_v3"


def test_foreign_user_rows_are_dropped() -> None:
    # Defense-in-depth: a server ignoring the topic filter must not let
    # another user's withdrawal become this wallet's lead.
    other = "0x" + "77" * 20
    adapter = _StubAdapter([_cross_address_log(other, _FRESH)])
    leads = run_lending_leads(
        transfers=[_transfer(_USER)], adapter=adapter, force=True,
    )
    assert leads == []


def test_unsupported_chain_yields_empty() -> None:
    adapter = _StubAdapter([_cross_address_log(_USER, _FRESH)])
    leads = run_lending_leads(
        transfers=[_transfer(_USER)], adapter=adapter,
        default_chain="solana", force=True,
    )
    assert leads == []
    assert adapter.calls == []  # no pool → no fetch


# ---- Compound III (Comet) ---- #

_COMET = COMPOUND_V3_COMETS_BY_CHAIN["ethereum"][0]  # cUSDCv3


def _comet_log(*, market, src, to, amount="0x1dcd6500", tx="0xcomet"):
    # Comet Withdraw(src indexed, to indexed, amount): topics=[t0, src, to];
    # data = one word (raw base-asset amount).
    return {
        "address": market,
        "topics": [COMPOUND_V3_WITHDRAW_TOPIC0, _topic_addr(src), _topic_addr(to)],
        "data": "0x" + amount[2:].rjust(64, "0"),
        "transactionHash": tx,
    }


def test_comet_withdraws_parse() -> None:
    rows = comet_withdraws_from_logs(
        [_comet_log(market=_COMET, src=_USER, to=_FRESH)])
    assert len(rows) == 1
    r = rows[0]
    assert r["src"] == _USER
    assert r["to"] == _FRESH
    assert r["comet"] == _COMET
    assert r["amount_raw"] == str(0x1DCD6500)   # 500 USDC (6dp) raw


def test_comet_cross_address_is_a_high_lead() -> None:
    adapter = _StubAdapter(
        [],   # no Aave logs
        comet_logs=[
            _comet_log(market=_COMET, src=_USER, to=_USER, tx="0xself"),   # context
            _comet_log(market=_COMET, src=_USER, to=_FRESH, tx="0xexit"),  # exit
        ],
    )
    leads = run_lending_leads(
        transfers=[_transfer(_USER)], adapter=adapter, force=True,
    )
    # one cross-address comet lead (back-to-self excluded). Comet markets are
    # queried per-market with src on topic1.
    comet_leads = [x for x in leads if x["protocol"] == "compound_v3"]
    assert len(comet_leads) == 1
    ld = comet_leads[0]
    assert ld["user"] == _USER
    assert ld["exit_recipient"] == _FRESH
    assert ld["reserve"] == _COMET
    assert ld["confidence"] == "high"
    # the Comet getLogs filtered src on topic1
    comet_call = next(c for c in adapter.calls
                      if c["topic0"] == COMPOUND_V3_WITHDRAW_TOPIC0)
    assert comet_call["topics"] == [_topic_addr(_USER)]
    assert comet_call["address"] == _COMET


def test_comet_foreign_market_emitter_dropped() -> None:
    # Defense-in-depth: a row whose emitter isn't the pinned market (a server
    # ignoring the address filter) must not become a lead.
    rogue = "0x" + "ab" * 20
    adapter = _StubAdapter(
        [], comet_logs=[_comet_log(market=rogue, src=_USER, to=_FRESH)],
    )
    leads = run_lending_leads(
        transfers=[_transfer(_USER)], adapter=adapter, force=True,
    )
    assert [x for x in leads if x["protocol"] == "compound_v3"] == []


def test_leads_to_json_artifact_shape() -> None:
    doc = leads_to_json([{"x": 1}])
    assert doc["kind"] == "recupero_lending_leads"
    assert doc["lead_count"] == 1
    assert "never a followed destination" in doc["disclaimer"]
    assert "protocol identity" in doc["disclaimer"]
    assert "Compound III" in doc["disclaimer"]
