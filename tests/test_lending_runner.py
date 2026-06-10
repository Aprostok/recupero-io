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
    def __init__(self, logs):
        self.logs = logs
        self.calls: list[dict[str, Any]] = []

    def fetch_logs(self, address, topic0, *, from_block, to_block, topics=None):
        self.calls.append({"address": address, "topics": topics})
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


def test_leads_to_json_artifact_shape() -> None:
    doc = leads_to_json([{"x": 1}])
    assert doc["kind"] == "recupero_lending_leads"
    assert doc["lead_count"] == 1
    assert "never a followed destination" in doc["disclaimer"]
    assert "protocol identity" in doc["disclaimer"]
