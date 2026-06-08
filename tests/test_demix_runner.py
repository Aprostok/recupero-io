"""Mixer demixing runner (v0.39 Activation Sprint #4) — wires the previously
DEAD ``demix_candidates`` scorer into a live, opt-in, tested pipeline.

Pins: mixer-deposit detection off real Tornado pool addresses, Tornado Withdrawal
log parsing (recipient = data word 0, relayer = topic 1 — verified vs real logs),
the opt-in gate, and the end-to-end scorer call producing an address-reuse lead
(the proof the dead code is now exercised). Leads stay confidence 'low'.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from recupero.trace.demix_runner import (
    TORNADO_WITHDRAWAL_TOPIC0,
    find_mixer_deposits,
    leads_to_json,
    run_demix_leads,
    withdrawals_from_logs,
)

_POOL_100ETH = "0xa160cdab225685da1d56aa342ad8841c3b53f291"  # Tornado 100 ETH (eth)
_DEPOSITOR = "0x" + "ab" * 20
_OTHER = "0x" + "cd" * 20
_RELAYER = "0x" + "11" * 20


def _tx(to, frm, *, chain="ethereum", txh="0xdep", when=datetime(2022, 1, 1, tzinfo=UTC)):
    return SimpleNamespace(
        to_address=to, from_address=frm,
        chain=SimpleNamespace(value=chain), block_time=when, tx_hash=txh,
    )


def _withdrawal_log(recipient: str, *, relayer: str = _RELAYER,
                    when=datetime(2022, 2, 1, tzinfo=UTC), txh="0xwtx") -> dict:
    word0 = recipient.removeprefix("0x").rjust(64, "0")        # to
    word1 = "ff" * 32                                          # nullifierHash
    word2 = format(10**17, "064x")                             # fee
    return {
        "data": "0x" + word0 + word1 + word2,
        "topics": [TORNADO_WITHDRAWAL_TOPIC0, "0x" + relayer.removeprefix("0x").rjust(64, "0")],
        "transactionHash": txh,
        "timeStamp": str(int(when.timestamp())),
    }


def test_find_mixer_deposits_detects_tornado() -> None:
    transfers = [
        _tx(_POOL_100ETH, _DEPOSITOR, txh="0xa"),
        _tx(_OTHER, _DEPOSITOR, txh="0xb"),               # not a mixer
        _tx(_POOL_100ETH, _DEPOSITOR, txh="0xa"),          # dup → deduped
    ]
    deps = find_mixer_deposits(transfers, default_chain="ethereum")
    assert len(deps) == 1
    assert deps[0].pool_address == _POOL_100ETH
    assert "Tornado" in deps[0].pool_name
    assert deps[0].deposit.address == _DEPOSITOR


def test_withdrawals_from_logs_parses_recipient_and_relayer() -> None:
    ws = withdrawals_from_logs([_withdrawal_log(_OTHER)], pool_name="Tornado Cash 100 ETH")
    assert len(ws) == 1
    assert ws[0].address == _OTHER
    assert ws[0].relayer == _RELAYER
    assert ws[0].pool == "Tornado Cash 100 ETH"
    # malformed log skipped, never fabricated
    assert withdrawals_from_logs([{"data": "0x", "topics": []}], pool_name="p") == []


class _MockAdapter:
    def __init__(self, logs):
        self._logs = logs

    def block_at_or_before(self, _ts):
        return 1000

    def fetch_logs(self, _addr, _topic0, *, from_block, to_block, topics=None):
        return self._logs


def test_run_demix_leads_address_reuse_end_to_end() -> None:
    # A withdrawal back to the SAME address that deposited → the strongest signal.
    adapter = _MockAdapter([_withdrawal_log(_DEPOSITOR)])
    out = run_demix_leads(
        transfers=[_tx(_POOL_100ETH, _DEPOSITOR)], adapter=adapter,
        default_chain="ethereum", force=True,
    )
    assert out  # the dead scorer is now CALLED and producing leads
    leads = next(iter(out.values()))
    assert any("address_reuse" in ld.signals for ld in leads)
    assert all(ld.confidence == "low" for ld in leads)  # never escalated


def test_opt_in_gate_off_returns_empty(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_DEMIX_LEADS", raising=False)
    adapter = _MockAdapter([_withdrawal_log(_DEPOSITOR)])
    assert run_demix_leads(transfers=[_tx(_POOL_100ETH, _DEPOSITOR)],
                           adapter=adapter, force=False) == {}


def test_leads_to_json_shape() -> None:
    adapter = _MockAdapter([_withdrawal_log(_DEPOSITOR)])
    out = run_demix_leads(transfers=[_tx(_POOL_100ETH, _DEPOSITOR)], adapter=adapter, force=True)
    doc = leads_to_json(out)
    assert doc["kind"] == "recupero_demix_leads"
    assert "never proof" in doc["disclaimer"].lower()
    assert doc["deposits"] and doc["deposits"][0]["leads"][0]["confidence"] == "low"


def test_fetch_failure_skips_pool_never_raises() -> None:
    class _Boom:
        def block_at_or_before(self, _ts):
            return 1
        def fetch_logs(self, *a, **k):
            raise RuntimeError("rpc down")
    out = run_demix_leads(transfers=[_tx(_POOL_100ETH, _DEPOSITOR)], adapter=_Boom(), force=True)
    assert out == {}  # degraded cleanly
