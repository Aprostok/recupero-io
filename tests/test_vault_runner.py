"""Roadmap-v4 Tier-2 #11 (slice 2): ERC-4626 vault park-and-withdraw leads.

Fixtures are REAL mainnet log shapes captured live (2026-06) from MetaMorpho /
Spark sUSDS — e.g. a real receiver!=owner Withdraw, owner=indexed topic 3.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from recupero.trace.vault_runner import (
    ERC4626_DEPOSIT_TOPIC0,
    ERC4626_WITHDRAW_TOPIC0,
    deposit_vaults_by_owner,
    leads_to_json,
    run_vault_leads,
    vault_leads_enabled,
    withdraws_by_owner,
)

_VAULT = "0xbeef01735c132ada46aa9aa4c54623caa92a64cb"   # MetaMorpho SteakUSDC
_OWNER = "0x255c7705e8bb334dfcae438197f7c4297988085a"   # real owner from live probe
_RECV = "0xaad4a20e53ffd77787941b8e210c16f460509e72"    # real cross receiver
_OTHER_VAULT = "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd"  # Spark sUSDS


def _topic(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:].lower()


def _withdraw_log(*, vault, receiver, owner, assets="0x05f5e100", shares="0x0569de0d",
                  tx="0xwd"):
    return {
        "address": vault,
        "topics": [ERC4626_WITHDRAW_TOPIC0, _topic("0x" + "99" * 20),
                   _topic(receiver), _topic(owner)],
        "data": "0x" + assets[2:].rjust(64, "0") + shares[2:].rjust(64, "0"),
        "transactionHash": tx,
    }


def _deposit_log(*, vault, owner):
    return {
        "address": vault,
        "topics": [ERC4626_DEPOSIT_TOPIC0, _topic("0x" + "99" * 20), _topic(owner)],
        "data": "0x" + "00" * 64,
    }


def _transfer(frm):
    return SimpleNamespace(from_address=frm, to_address="0x" + "11" * 20)


class _StubAdapter:
    def __init__(self, *, withdraw_logs, deposit_logs):
        self.withdraw_logs = withdraw_logs
        self.deposit_logs = deposit_logs
        self.calls: list[dict[str, Any]] = []

    def fetch_logs(self, address, topic0, *, from_block, to_block, topics=None):
        self.calls.append({"address": address, "topic0": topic0, "topics": topics})
        if topic0 == ERC4626_WITHDRAW_TOPIC0:
            return self.withdraw_logs
        if topic0 == ERC4626_DEPOSIT_TOPIC0:
            return self.deposit_logs
        return []


def test_gate_default_off(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_VAULT_LEADS", raising=False)
    assert vault_leads_enabled() is False
    assert run_vault_leads(transfers=[_transfer(_OWNER)], adapter=None) == []
    monkeypatch.setenv("RECUPERO_VAULT_LEADS", "yes")
    assert vault_leads_enabled() is True


def test_withdraws_parse_real_shape() -> None:
    rows = withdraws_by_owner(
        [_withdraw_log(vault=_VAULT, receiver=_RECV, owner=_OWNER)], owner=_OWNER)
    assert len(rows) == 1
    r = rows[0]
    assert r["vault"] == _VAULT
    assert r["receiver"] == _RECV
    assert r["owner"] == _OWNER
    assert r["assets_raw"] == str(0x05F5E100)
    assert r["shares_raw"] == str(0x0569DE0D)


def test_withdraws_filter_foreign_owner() -> None:
    # A Withdraw owned by someone else must not surface for this wallet.
    other = "0x" + "77" * 20
    rows = withdraws_by_owner(
        [_withdraw_log(vault=_VAULT, receiver=_RECV, owner=other)], owner=_OWNER)
    assert rows == []


def test_deposit_vaults_by_owner() -> None:
    logs = [
        _deposit_log(vault=_VAULT, owner=_OWNER),
        _deposit_log(vault=_OTHER_VAULT, owner="0x" + "77" * 20),  # foreign
    ]
    assert deposit_vaults_by_owner(logs, owner=_OWNER) == {_VAULT}


def test_cross_address_withdraw_with_round_trip_is_high() -> None:
    adapter = _StubAdapter(
        withdraw_logs=[_withdraw_log(vault=_VAULT, receiver=_RECV, owner=_OWNER)],
        deposit_logs=[_deposit_log(vault=_VAULT, owner=_OWNER)],
    )
    leads = run_vault_leads(transfers=[_transfer(_OWNER)], adapter=adapter, force=True)
    assert len(leads) == 1
    ld = leads[0]
    assert ld["exit_recipient"] == _RECV
    assert ld["round_trip_confirmed"] is True
    assert ld["confidence"] == "high"
    # Withdraw query filtered owner on topic 3 (topic1/2 unfiltered)
    wd_call = next(c for c in adapter.calls if c["topic0"] == ERC4626_WITHDRAW_TOPIC0)
    assert wd_call["address"] == ""              # address-less (all vaults)
    assert wd_call["topics"] == [None, None, _topic(_OWNER)]


def test_cross_address_without_deposit_is_medium() -> None:
    adapter = _StubAdapter(
        withdraw_logs=[_withdraw_log(vault=_VAULT, receiver=_RECV, owner=_OWNER)],
        deposit_logs=[],   # no observed deposit by this wallet
    )
    leads = run_vault_leads(transfers=[_transfer(_OWNER)], adapter=adapter, force=True)
    assert len(leads) == 1
    assert leads[0]["round_trip_confirmed"] is False
    assert leads[0]["confidence"] == "medium"


def test_back_to_self_withdraw_is_not_a_lead() -> None:
    adapter = _StubAdapter(
        withdraw_logs=[_withdraw_log(vault=_VAULT, receiver=_OWNER, owner=_OWNER)],
        deposit_logs=[_deposit_log(vault=_VAULT, owner=_OWNER)],
    )
    leads = run_vault_leads(transfers=[_transfer(_OWNER)], adapter=adapter, force=True)
    assert leads == []   # funds back to the traced wallet — BFS covers them


def test_leads_to_json_artifact_shape() -> None:
    doc = leads_to_json([{"x": 1}])
    assert doc["kind"] == "recupero_vault_leads"
    assert doc["lead_count"] == 1
    assert "never a followed destination" in doc["disclaimer"]
    assert "round-trip" in doc["disclaimer"]
