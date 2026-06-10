"""Mempool / pending-transaction pre-confirmation freeze watch (roadmap #5).

Detect a stolen-funds movement touching a watched address BEFORE it confirms, so
an operator can race a freeze. Built on Alchemy's address-filtered
``alchemy_pendingTransactions`` websocket subscription (the only widely-available
filtered pending-tx feed).

FORENSIC CONSTRAINT — pending != settled. A pending tx can be dropped or replaced
(same-nonce fee-bump) and NEVER land. Every alert this emits is explicitly
labelled "UNCONFIRMED — may not land" and ``settled=False``; it is a race signal
for a human, never recorded as a settled fact.

Scope / verified facts (see ROADMAP research): the filtered sub is ETH-mainnet,
ETH-sepolia and Polygon-mainnet ONLY; capped at 1000 addresses; the ws URL is
``wss://<network>.g.alchemy.com/v2/<API_KEY>``. Solana has no mempool, so there
is no pre-confirmation hook there (logsSubscribe @processed is the earliest
signal — out of scope here).

Design: the protocol layer (URL builder, subscribe-request builder, notification
classifier) is PURE and unit-tested; ``run_mempool_watch`` is a thin async
``websockets`` transport with an injectable ``connect`` so the read/dispatch loop
is testable without a live socket. Opt-in: the operator explicitly starts it via
``recupero-ops mempool-watch`` (needs ``ALCHEMY_API_KEY``); nothing runs otherwise.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# Networks where alchemy_pendingTransactions (address-filtered) is available.
# chain display name -> Alchemy network slug.
_SUPPORTED_NETWORKS: dict[str, str] = {
    "ethereum": "eth-mainnet",
    "eth-mainnet": "eth-mainnet",
    "sepolia": "eth-sepolia",
    "eth-sepolia": "eth-sepolia",
    "polygon": "polygon-mainnet",
    "polygon-mainnet": "polygon-mainnet",
}

_MAX_FILTER_ADDRESSES = 1000  # Alchemy's documented cap across from+to.

_UNCONFIRMED_CAVEAT = (
    "UNCONFIRMED — pending mempool transaction. It may be dropped or replaced "
    "(same-nonce fee-bump) and never land. NOT a settled fact; treat as a "
    "time-critical race signal only."
)


def _ck(addr: str) -> str:
    from recupero._common import canonical_address_key
    return canonical_address_key(addr)


@dataclass(frozen=True)
class PendingFreezeAlert:
    """A watched address appeared in a PENDING transaction. Pre-confirmation —
    always ``settled=False``."""
    address: str               # the watched address that matched
    counterparty: str | None   # the other side, when the notification carries it
    chain: str
    tx_hash: str
    value_wei: int | None
    direction: str             # "inbound" | "outbound" | "unknown"
    settled: bool              # ALWAYS False — pre-confirmation
    caveat: str
    recommended_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address, "counterparty": self.counterparty,
            "chain": self.chain, "tx_hash": self.tx_hash,
            "value_wei": self.value_wei, "direction": self.direction,
            "settled": self.settled, "caveat": self.caveat,
            "recommended_action": self.recommended_action,
        }


def alchemy_pending_ws_url(network: str, api_key: str) -> str:
    """Build the Alchemy websocket URL for ``network``. Raises ValueError for an
    unsupported network (the filtered pending sub only exists on a few)."""
    slug = _SUPPORTED_NETWORKS.get((network or "").strip().lower())
    if not slug:
        raise ValueError(
            f"network {network!r} does not support alchemy_pendingTransactions "
            f"(supported: {sorted(set(_SUPPORTED_NETWORKS.values()))})"
        )
    if not api_key or not api_key.strip():
        raise ValueError("api_key is required")
    return f"wss://{slug}.g.alchemy.com/v2/{api_key.strip()}"


def build_pending_subscribe_request(
    addresses: Iterable[str],
    *,
    hashes_only: bool = False,
    request_id: int = 2,
) -> dict[str, Any]:
    """Build the exact ``eth_subscribe(alchemy_pendingTransactions, ...)`` JSON-RPC
    payload, filtering on BOTH from+to for the watched addresses (union/OR match
    server-side). Addresses are lowercased + de-duped + capped at 1000 (a warning
    logs what was dropped — no silent truncation)."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for a in addresses or []:
        if not isinstance(a, str) or not a.strip():
            continue
        lo = a.strip().lower()
        if lo not in seen_set:
            seen_set.add(lo)
            seen.append(lo)
    if len(seen) > _MAX_FILTER_ADDRESSES:
        log.warning(
            "mempool-watch: %d watched addresses exceeds Alchemy's %d cap — "
            "watching only the first %d (raise coverage by sharding the rest "
            "into a second subscription).",
            len(seen), _MAX_FILTER_ADDRESSES, _MAX_FILTER_ADDRESSES,
        )
        seen = seen[:_MAX_FILTER_ADDRESSES]
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "eth_subscribe",
        "params": [
            "alchemy_pendingTransactions",
            {"fromAddress": seen, "toAddress": seen, "hashesOnly": bool(hashes_only)},
        ],
    }


def classify_pending_notification(
    msg: Any,
    *,
    watched: set[str],
    chain: str,
) -> PendingFreezeAlert | None:
    """Turn one parsed ``eth_subscription`` notification into a
    :class:`PendingFreezeAlert`, or ``None`` if it isn't a watched-address hit.

    Handles BOTH result shapes: a full tx object ({from,to,value,hash}) and the
    ``hashesOnly`` form (result is just a hash string — already server-filtered to
    the watched set, so it's a match by construction). Pure.
    """
    if not isinstance(msg, dict):
        return None
    params = msg.get("params")
    if not isinstance(params, dict):
        return None
    result = params.get("result")

    def _alert(addr, counterparty, txh, value_wei, direction):
        return PendingFreezeAlert(
            address=addr, counterparty=counterparty, chain=chain,
            tx_hash=str(txh or ""), value_wei=value_wei, direction=direction,
            settled=False, caveat=_UNCONFIRMED_CAVEAT,
            recommended_action=(
                "Confirm the pending tx is real (it may be dropped/replaced), "
                "then race a freeze request to the issuer/exchange holding the "
                "destination before it confirms."
            ),
        )

    # hashesOnly form: result is a bare hash string → server already filtered to
    # the watched set, so this IS a hit (we just don't know which side).
    if isinstance(result, str):
        return _alert("(server-filtered watched address)", None, result, None, "unknown")

    if not isinstance(result, dict):
        return None
    frm = (result.get("from") or "") if isinstance(result.get("from"), str) else ""
    to = (result.get("to") or "") if isinstance(result.get("to"), str) else ""
    txh = result.get("hash")
    value_wei: int | None = None
    raw_val = result.get("value")
    if isinstance(raw_val, str):
        try:
            value_wei = int(raw_val, 16) if raw_val.startswith("0x") else int(raw_val)
        except (ValueError, TypeError):
            value_wei = None

    frm_w = bool(frm) and _ck(frm) in watched
    to_w = bool(to) and _ck(to) in watched
    if to_w:
        # Funds arriving AT a watched address (inbound) — a freeze opportunity.
        return _alert(to, frm or None, txh, value_wei, "inbound")
    if frm_w:
        # Funds LEAVING a watched address (outbound) — freeze before it moves on.
        return _alert(frm, to or None, txh, value_wei, "outbound")
    return None


def iter_pending_alerts(
    raw_messages: Iterable[str | bytes],
    *,
    watched: set[str],
    chain: str,
) -> Iterator[PendingFreezeAlert]:
    """Parse + classify a stream of raw websocket text frames into alerts.
    Malformed frames and the initial subscribe-ack are skipped, never raised.
    Pure (no socket) — this is what makes the dispatch loop unit-testable."""
    wk = {_ck(a) for a in watched}
    for frame in raw_messages or []:
        try:
            text = frame.decode("utf-8") if isinstance(frame, bytes) else frame
            msg = json.loads(text)
        except (ValueError, AttributeError, UnicodeDecodeError):
            continue
        # The subscribe ack is {"id":..,"result":"0xSubId"} — no params; skipped.
        alert = classify_pending_notification(msg, watched=wk, chain=chain)
        if alert is not None:
            yield alert


async def _drain_once(
    *,
    url: str,
    sub_req: dict[str, Any],
    watched: set[str],
    chain: str,
    on_alert: Any,
    connect: Any,
    max_messages: int | None,
) -> int:
    """One connect → subscribe → read-until-close cycle. Returns the number of
    alerts dispatched. Propagates any transport error so the caller can decide
    whether to reconnect."""
    dispatched = 0
    seen = 0
    async with connect(url) as ws:
        await ws.send(json.dumps(sub_req))
        async for frame in ws:
            seen += 1
            try:
                text = frame.decode("utf-8") if isinstance(frame, bytes) else frame
                msg = json.loads(text)
            except (ValueError, AttributeError, UnicodeDecodeError):
                if max_messages is not None and seen >= max_messages:
                    break
                continue
            alert = classify_pending_notification(msg, watched=watched, chain=chain)
            if alert is not None:
                log.warning("mempool-watch ALERT (%s): %s", alert.direction, alert.caveat)
                on_alert(alert)
                dispatched += 1
            if max_messages is not None and seen >= max_messages:
                break
    return dispatched


async def run_mempool_watch(
    *,
    api_key: str,
    network: str,
    addresses: Iterable[str],
    on_alert: Any,
    hashes_only: bool = False,
    connect: Any = None,
    max_messages: int | None = None,
    reconnect_attempts: int = 0,
    backoff_sleep: Any = None,
) -> int:
    """Open the Alchemy pending-tx websocket, subscribe to the watched
    addresses, and invoke ``on_alert(PendingFreezeAlert)`` for each hit.

    ``connect`` is an async-context-manager factory (defaults to
    ``websockets.connect``); inject a fake for testing. ``max_messages`` bounds
    the read loop (tests / one-shot drains). Returns the number of alerts
    dispatched.

    Reconnect: a long-lived race watch must survive a dropped socket (a missed
    pending tx is a missed freeze). On a TRANSPORT ERROR (not a clean close) the
    loop reconnects + re-subscribes up to ``reconnect_attempts`` times with
    exponential backoff (capped 30s; ``backoff_sleep`` is injectable for tests).
    Default 0 ⇒ no reconnect (a clean close always returns — only errors retry),
    so a one-shot / bounded drain is unchanged. A clean close (server ended the
    stream / ``max_messages`` reached) always returns without reconnecting.
    """
    url = alchemy_pending_ws_url(network, api_key)
    sub_req = build_pending_subscribe_request(addresses, hashes_only=hashes_only)
    watched = {_ck(a) for a in addresses}
    chain = (network or "").strip().lower()

    if connect is None:  # pragma: no cover - live transport
        import websockets
        connect = websockets.connect
    if backoff_sleep is None:  # pragma: no cover - real timer
        import asyncio
        backoff_sleep = asyncio.sleep

    dispatched = 0
    attempt = 0
    while True:
        try:
            dispatched += await _drain_once(
                url=url, sub_req=sub_req, watched=watched, chain=chain,
                on_alert=on_alert, connect=connect, max_messages=max_messages,
            )
            return dispatched  # clean close — never reconnect on a graceful end
        except Exception as exc:  # noqa: BLE001 — any transport error is retryable
            if attempt >= reconnect_attempts:
                raise
            attempt += 1
            wait = min(30.0, 2.0 ** attempt)
            log.warning(
                "mempool-watch: connection error (%s); reconnecting %d/%d in "
                "%.0fs", exc, attempt, reconnect_attempts, wait,
            )
            await backoff_sleep(wait)


__all__ = (
    "PendingFreezeAlert",
    "alchemy_pending_ws_url",
    "build_pending_subscribe_request",
    "classify_pending_notification",
    "iter_pending_alerts",
    "run_mempool_watch",
)
