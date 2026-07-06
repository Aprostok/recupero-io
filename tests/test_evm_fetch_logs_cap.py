"""EVM fetch_logs surfaces Etherscan's silent getLogs cap.

Etherscan's logs/getLogs returns at most 1000 records per call and gives NO
signal when a range holds more — the extras are silently dropped. fetch_logs is
the shared primitive behind bridge-pairing confirmation and demix-lead discovery;
a truncated range masquerading as complete = a missed destination fill (bridge
false-negative) or missed Tornado withdrawals (incomplete demix). These tests
lock in that a cap-hit is WARNED (observability), not silent.
"""
from __future__ import annotations

import logging

from recupero.chains.evm.adapter import _ETHERSCAN_GETLOGS_MAX, EvmAdapter
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain


def _adapter() -> EvmAdapter:
    # Dummy key satisfies EtherscanClient; _call is stubbed so no network.
    return EvmAdapter(
        (RecuperoConfig(), RecuperoEnv(ETHERSCAN_API_KEY="k")), Chain.ethereum,
    )


def test_fetch_logs_warns_at_getlogs_cap(caplog):
    ad = _adapter()
    ad.client._call = lambda **kw: {"status": "1", "result": [
        {"address": "0xabc", "transactionHash": f"0x{i:064x}"}
        for i in range(_ETHERSCAN_GETLOGS_MAX)
    ]}
    with caplog.at_level(logging.WARNING):
        out = ad.fetch_logs("0xpool", "0xtopic", from_block=1, to_block=999)
    assert len(out) == _ETHERSCAN_GETLOGS_MAX
    assert "TRUNCATED" in caplog.text


def test_fetch_logs_no_warn_below_cap(caplog):
    ad = _adapter()
    ad.client._call = lambda **kw: {"status": "1", "result": [
        {"address": "0xabc"} for _ in range(5)
    ]}
    with caplog.at_level(logging.WARNING):
        out = ad.fetch_logs("0xpool", "0xt", from_block=1, to_block=2)
    assert len(out) == 5
    assert "TRUNCATED" not in caplog.text
