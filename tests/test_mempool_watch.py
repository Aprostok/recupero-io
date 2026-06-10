"""Roadmap-#1 v3 item #5: mempool pre-confirmation freeze watch.

The protocol layer (URL + subscribe-request builders + notification classifier)
is pure; the async read/dispatch loop is exercised with an injected fake
websocket. Every alert is UNCONFIRMED (settled=False) — a pending tx may be
dropped/replaced and never land.
"""

from __future__ import annotations

import json

import pytest

from recupero.monitoring.mempool_watch import (
    PendingFreezeAlert,
    alchemy_pending_ws_url,
    build_pending_subscribe_request,
    classify_pending_notification,
    iter_pending_alerts,
    load_freezable_watchlist_addresses,
    run_mempool_watch,
)

_WATCHED = "0x" + "ab" * 20
_OTHER = "0x" + "11" * 20


def test_ws_url_valid_and_invalid() -> None:
    assert alchemy_pending_ws_url("ethereum", "KEY") == "wss://eth-mainnet.g.alchemy.com/v2/KEY"
    assert alchemy_pending_ws_url("polygon", "KEY").startswith("wss://polygon-mainnet.g.alchemy.com")
    with pytest.raises(ValueError):
        alchemy_pending_ws_url("solana", "KEY")        # no mempool sub
    with pytest.raises(ValueError):
        alchemy_pending_ws_url("ethereum", "")          # missing key


def test_subscribe_request_shape_and_cap() -> None:
    req = build_pending_subscribe_request([_WATCHED.upper(), _WATCHED, _OTHER])
    assert req["method"] == "eth_subscribe"
    assert req["params"][0] == "alchemy_pendingTransactions"
    opts = req["params"][1]
    # deduped + lowercased; filters on both from+to
    assert opts["fromAddress"] == opts["toAddress"] == [_WATCHED.lower(), _OTHER.lower()]
    assert opts["hashesOnly"] is False
    # cap at 1000
    big = [f"0x{i:040x}" for i in range(1100)]
    capped = build_pending_subscribe_request(big)
    assert len(capped["params"][1]["fromAddress"]) == 1000


def test_classify_inbound_outbound_and_nonmatch() -> None:
    watched = {__import__("recupero._common", fromlist=["canonical_address_key"]).canonical_address_key(_WATCHED)}
    inbound = {"params": {"result": {"hash": "0xdead", "from": _OTHER, "to": _WATCHED,
                                     "value": "0xde0b6b3a7640000"}}}  # 1 ETH
    a = classify_pending_notification(inbound, watched=watched, chain="ethereum")
    assert isinstance(a, PendingFreezeAlert)
    assert a.direction == "inbound" and a.address == _WATCHED
    assert a.value_wei == 10**18
    assert a.settled is False and "UNCONFIRMED" in a.caveat

    outbound = {"params": {"result": {"hash": "0xbeef", "from": _WATCHED, "to": _OTHER}}}
    b = classify_pending_notification(outbound, watched=watched, chain="ethereum")
    assert b is not None and b.direction == "outbound"

    nomatch = {"params": {"result": {"hash": "0x0", "from": _OTHER, "to": "0x" + "22" * 20}}}
    assert classify_pending_notification(nomatch, watched=watched, chain="ethereum") is None


def test_classify_hashes_only_is_a_match() -> None:
    # hashesOnly result is a bare hash (server already filtered to the watched set).
    msg = {"params": {"result": "0xfeed"}}
    a = classify_pending_notification(msg, watched={"x"}, chain="ethereum")
    assert a is not None and a.tx_hash == "0xfeed" and a.settled is False


def test_iter_skips_ack_and_malformed() -> None:
    frames = [
        '{"id":2,"result":"0xsubid"}',                       # subscribe ack — skipped
        "not json",                                          # malformed — skipped
        json.dumps({"params": {"result": {"hash": "0xh", "from": _OTHER, "to": _WATCHED}}}),
    ]
    alerts = list(iter_pending_alerts(frames, watched={_WATCHED}, chain="ethereum"))
    assert len(alerts) == 1 and alerts[0].direction == "inbound"


class _FakeWS:
    def __init__(self, frames):
        self.frames = frames
        self.sent: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def send(self, data):
        self.sent.append(data)

    def __aiter__(self):
        self._it = iter(self.frames)
        return self

    async def __anext__(self):
        try:
            return next(self._it)
        except StopIteration:
            raise StopAsyncIteration from None


@pytest.mark.asyncio
async def test_run_mempool_watch_dispatches_only_matches() -> None:
    frames = [
        '{"id":2,"result":"0xsubid"}',
        json.dumps({"method": "eth_subscription", "params": {"subscription": "0xsubid",
            "result": {"hash": "0xA", "from": _OTHER, "to": _WATCHED, "value": "0x1"}}}),
        json.dumps({"method": "eth_subscription", "params": {"subscription": "0xsubid",
            "result": {"hash": "0xB", "from": _OTHER, "to": "0x" + "22" * 20}}}),
    ]
    fake = _FakeWS(frames)
    got: list[PendingFreezeAlert] = []
    n = await run_mempool_watch(
        api_key="KEY", network="ethereum", addresses=[_WATCHED],
        on_alert=got.append, connect=lambda url: fake,
    )
    assert n == 1
    assert len(got) == 1 and got[0].address == _WATCHED
    # the subscribe request was actually sent on the socket
    assert any("alchemy_pendingTransactions" in s for s in fake.sent)


@pytest.mark.asyncio
async def test_run_mempool_watch_reconnects_on_transport_error() -> None:
    # A dropped socket (transport error) must reconnect + re-subscribe — a
    # missed pending tx is a missed freeze. First connect raises; second works.
    frames = [json.dumps({"method": "eth_subscription", "params": {
        "subscription": "0xs",
        "result": {"hash": "0xA", "from": _OTHER, "to": _WATCHED, "value": "0x1"}}})]
    calls = {"connect": 0}
    fake = _FakeWS(frames)

    def _connect(url):
        calls["connect"] += 1
        if calls["connect"] == 1:
            raise ConnectionError("simulated drop")
        return fake

    sleeps: list[float] = []

    async def _no_sleep(s):
        sleeps.append(s)

    got: list[PendingFreezeAlert] = []
    n = await run_mempool_watch(
        api_key="KEY", network="ethereum", addresses=[_WATCHED],
        on_alert=got.append, connect=_connect, reconnect_attempts=3,
        backoff_sleep=_no_sleep,
    )
    assert n == 1                       # alert dispatched after the reconnect
    assert calls["connect"] == 2        # reconnected exactly once
    assert sleeps == [2.0]              # one exponential-backoff wait


@pytest.mark.asyncio
async def test_run_mempool_watch_raises_when_reconnects_exhausted() -> None:
    def _always_fail(url):
        raise ConnectionError("down")

    async def _no_sleep(s):
        pass

    with pytest.raises(ConnectionError):
        await run_mempool_watch(
            api_key="KEY", network="ethereum", addresses=[_WATCHED],
            on_alert=lambda a: None, connect=_always_fail,
            reconnect_attempts=2, backoff_sleep=_no_sleep,
        )


def test_load_freezable_watchlist_addresses_guards() -> None:
    # No DSN → [] (never raises). Unsupported network (Solana — no mempool sub,
    # no watchlist chain mapping) → [] even with a DSN present.
    assert load_freezable_watchlist_addresses(None, network="ethereum") == []
    assert load_freezable_watchlist_addresses("", network="ethereum") == []
    assert load_freezable_watchlist_addresses("postgresql://x", network="solana") == []
    assert load_freezable_watchlist_addresses("postgresql://x", network="bogus") == []
