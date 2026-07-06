"""EVM fetch_logs recovers logs past Etherscan's silent getLogs cap.

Etherscan's logs/getLogs returns at most 1000 records per call and gives NO
signal when a range holds more — the extras are silently dropped. fetch_logs is
the shared primitive behind bridge-pairing confirmation and demix-lead discovery;
a truncated range masquerading as complete = a missed destination fill (bridge
false-negative) or missed Tornado withdrawals (incomplete demix). fetch_logs now
BISECTS a cap-hit block range and re-fetches each half until every sub-range
returns under the cap, so the full set is recovered rather than truncated. These
tests lock in: (1) the common under-cap fetch stays a single call; (2) a
truncated-but-splittable range is paginated to completeness with no false
"incomplete" warning; (3) genuine incompleteness (call budget, unsplittable
single block, failed sub-range) is WARNED — never a silent cap.
"""
from __future__ import annotations

import logging

from recupero.chains.evm.adapter import (
    _ETHERSCAN_GETLOGS_MAX,
    _ETHERSCAN_GETLOGS_PAGE_BUDGET,
    EvmAdapter,
)
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain


def _adapter() -> EvmAdapter:
    # Dummy key satisfies EtherscanClient; _call is stubbed so no network.
    return EvmAdapter(
        (RecuperoConfig(), RecuperoEnv(ETHERSCAN_API_KEY="k")), Chain.ethereum,
    )


def _block_range_backend(logs: list[dict], calls: list):
    """A fake ``client._call`` that serves ``logs`` (each with a numeric
    ``blockNumber``) filtered to the requested [fromBlock, toBlock] and CAPPED at
    the getLogs limit — exactly Etherscan's silent-truncation behaviour. Records
    each call's (from, to) in ``calls`` so tests can assert the call pattern."""
    def _call(**kw):
        a = int(kw["fromBlock"])
        b = 10**9 if kw["toBlock"] == "latest" else int(kw["toBlock"])
        calls.append((a, b))
        sel = [lg for lg in logs if a <= int(lg["blockNumber"], 16) <= b]
        return {"status": "1", "result": sel[:_ETHERSCAN_GETLOGS_MAX]}
    return _call


def test_fetch_logs_single_call_below_cap(caplog):
    ad = _adapter()
    calls: list = []
    ad.client._call = lambda **kw: (calls.append(1), {
        "status": "1", "result": [{"address": "0xabc"} for _ in range(5)],
    })[1]
    with caplog.at_level(logging.WARNING):
        out = ad.fetch_logs("0xpool", "0xt", from_block=1, to_block=2)
    assert len(out) == 5
    assert len(calls) == 1  # under the cap → exactly one call, no pagination
    assert "TRUNCATED" not in caplog.text
    assert "INCOMPLETE" not in caplog.text


def test_fetch_logs_paginates_truncated_range_to_completeness(caplog):
    ad = _adapter()
    # 1500 logs, one per block 1..1500. A call over the whole range caps at 1000
    # (looks truncated); each half holds 750 (< cap, complete).
    logs = [
        {"transactionHash": f"0x{i:064x}", "logIndex": "0x0", "blockNumber": hex(i)}
        for i in range(1, 1501)
    ]
    calls: list = []
    ad.client._call = _block_range_backend(logs, calls)
    with caplog.at_level(logging.WARNING):
        out = ad.fetch_logs("0xpool", "0xt", from_block=1, to_block=1500)
    # Every log recovered despite the per-call cap.
    assert len(out) == 1500
    hashes = {lg["transactionHash"] for lg in out}
    assert len(hashes) == 1500  # deduped, disjoint halves → all unique
    # First call over the full range (cap hit), then the two halves.
    assert calls[0] == (1, 1500)
    assert (1, 750) in calls and (751, 1500) in calls
    assert len(calls) == 3
    # A truncation that was fully recovered is NOT an incompleteness warning.
    assert "INCOMPLETE" not in caplog.text
    assert "budget" not in caplog.text


def test_fetch_logs_resolves_latest_tip_then_paginates():
    ad = _adapter()
    logs = [
        {"transactionHash": f"0x{i:064x}", "logIndex": "0x0", "blockNumber": hex(i)}
        for i in range(1, 1501)
    ]
    calls: list = []
    ad.client._call = _block_range_backend(logs, calls)
    tip_calls: list = []
    ad.client.get_block_number_by_time = lambda ts, closest="before": (
        tip_calls.append((ts, closest)), 1500,
    )[1]
    out = ad.fetch_logs("0xpool", "0xt", from_block=1, to_block="latest")
    assert len(out) == 1500
    assert tip_calls  # "latest" was resolved to a concrete tip before bisecting
    assert calls[0] == (1, 10**9)  # first probe used the "latest" sentinel


def test_fetch_logs_warns_when_call_budget_exhausted(caplog):
    ad = _adapter()
    # Every range comes back at the cap → the bisection never bottoms out, so the
    # call budget is hit and the remaining sub-ranges are left unfetched.
    ad.client._call = lambda **kw: {
        "status": "1",
        "result": [
            {"transactionHash": f"0x{int(kw['fromBlock']):x}{i:04x}",
             "logIndex": hex(i), "blockNumber": kw["fromBlock"]}
            for i in range(_ETHERSCAN_GETLOGS_MAX)
        ],
    }
    with caplog.at_level(logging.WARNING):
        out = ad.fetch_logs("0xpool", "0xt", from_block=1, to_block=10_000_000)
    assert out  # best-effort: leaves that were processed still contribute
    assert "budget" in caplog.text
    assert "INCOMPLETE" in caplog.text
    assert str(_ETHERSCAN_GETLOGS_PAGE_BUDGET) in caplog.text


def test_fetch_logs_warns_unsplittable_single_block(caplog):
    ad = _adapter()
    # A single block that itself holds >= cap logs can't be split further.
    ad.client._call = lambda **kw: {
        "status": "1",
        "result": [
            {"transactionHash": f"0x{i:064x}", "logIndex": hex(i),
             "blockNumber": "0x5"}
            for i in range(_ETHERSCAN_GETLOGS_MAX)
        ],
    }
    # from==to so the first call is already a single, unsplittable block.
    with caplog.at_level(logging.WARNING):
        out = ad.fetch_logs("0xpool", "0xt", from_block=5, to_block=5)
    assert len(out) == _ETHERSCAN_GETLOGS_MAX
    assert "NOT splittable" in caplog.text or "unsplittable" in caplog.text


def test_fetch_logs_notes_failed_subrange_but_returns_rest(caplog):
    ad = _adapter()
    logs = [
        {"transactionHash": f"0x{i:064x}", "logIndex": "0x0", "blockNumber": hex(i)}
        for i in range(1, 1501)
    ]
    real_backend = _block_range_backend(logs, [])

    def flaky(**kw):
        # Fail the lower half exactly once so pagination sees a None sub-range.
        if kw["fromBlock"] == "1" and kw["toBlock"] == "750":
            raise RuntimeError("boom")
        return real_backend(**kw)

    ad.client._call = flaky
    with caplog.at_level(logging.WARNING):
        out = ad.fetch_logs("0xpool", "0xt", from_block=1, to_block=1500)
    # Upper half (751..1500) still recovered; lower half dropped but WARNED.
    assert 0 < len(out) <= 750
    assert "incomplete" in caplog.text.lower()


def test_fetch_logs_call_error_yields_empty():
    ad = _adapter()
    def boom(**kw):
        raise RuntimeError("network")
    ad.client._call = boom
    assert ad.fetch_logs("0xpool", "0xt", from_block=1, to_block=2) == []
