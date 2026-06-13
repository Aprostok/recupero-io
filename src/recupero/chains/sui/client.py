"""Sui JSON-RPC client (https://fullnode.mainnet.sui.io).

Public, no-auth Sui full-node JSON-RPC. Two methods are used:

  * ``suix_queryTransactionBlocks`` — transaction blocks filtered by
    ``FromAddress`` / ``ToAddress``, requested with ``showBalanceChanges`` (the
    net per-owner per-coin deltas) + ``showInput`` (for the sender + timestamp).
    Cursor-paginated, newest-first.
  * ``suix_getCoinMetadata`` — ``decimals`` + ``symbol`` for a coinType. Cached
    per coinType (a coin's metadata is immutable) so a trace doesn't re-fetch.

Shapes captured LIVE (2026-06) before implementation. A balanceChange is
``{owner: {AddressOwner|ObjectOwner|Shared|Immutable}, coinType, amount}`` where
``amount`` is a SIGNED decimal string (negative = the owner's balance of that
coin went down in this tx); the sender is ``transaction.data.sender``;
``timestampMs`` is top-level. Best-effort transport: a non-2xx, a JSON-RPC
``error``, or a malformed body raises ``SuiRPCError`` — the adapter degrades
gracefully (yields no transfers rather than crashing a trace).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

_SUI_HOST = "fullnode.mainnet.sui.io"
SUI_RPC_URL = f"https://{_SUI_HOST}"


class SuiRPCError(RuntimeError):
    """Raised on a non-2xx, JSON-RPC error, or malformed Sui RPC response."""


class _RateLimiter:
    def __init__(self, rps: float) -> None:
        self._min_interval = 1.0 / rps if rps > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        now = time.monotonic()
        delta = now - self._last
        if delta < self._min_interval:
            time.sleep(self._min_interval - delta)
        self._last = time.monotonic()


class SuiRPCClient:
    """Thin Sui full-node JSON-RPC client (tx-blocks + coin metadata)."""

    def __init__(
        self,
        base_url: str = SUI_RPC_URL,
        *,
        requests_per_second: float = 8.0,
        timeout_seconds: float = 25.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._host = httpx.URL(self.base_url).host
        self.limiter = _RateLimiter(requests_per_second)
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(connect=10.0, read=timeout_seconds,
                                  write=timeout_seconds, pool=timeout_seconds),
            headers={"User-Agent": "recupero-sui/1.0"},
        )
        self._owns_client = http_client is None
        # coinType -> metadata dict (immutable on-chain; safe to cache).
        self._meta_cache: dict[str, dict[str, Any] | None] = {}

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> SuiRPCClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ----- raw JSON-RPC -----

    def _rpc(self, method: str, params: list[Any]) -> Any:
        self.limiter.wait()
        if httpx.URL(self.base_url).host != _SUI_HOST:
            raise SuiRPCError(f"refusing non-Sui host in {self.base_url!r}")
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        try:
            resp = self._client.post(self.base_url, json=payload, follow_redirects=False)
        except httpx.RequestError as exc:
            raise SuiRPCError(f"Sui {method} request failed: {exc}") from exc
        if resp.status_code != 200:
            raise SuiRPCError(
                f"Sui {method} returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            body = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise SuiRPCError(f"Sui {method} returned non-JSON") from exc
        if not isinstance(body, dict):
            raise SuiRPCError(f"Sui {method} returned non-object body")
        if body.get("error") is not None:
            raise SuiRPCError(f"Sui {method} error: {body['error']}")
        return body.get("result")

    # ----- transaction blocks -----

    def query_transaction_blocks(
        self,
        tx_filter: dict[str, Any],
        *,
        cursor: str | None = None,
        limit: int = 50,
        descending: bool = True,
    ) -> dict[str, Any]:
        """Query transaction blocks matching ``tx_filter`` (e.g.
        ``{"FromAddress": addr}`` / ``{"ToAddress": addr}``), newest-first,
        with balance-changes + input shown. Returns the raw page
        ``{"data": [...], "nextCursor": ..., "hasNextPage": bool}``."""
        query = {
            "filter": tx_filter,
            "options": {
                "showBalanceChanges": True,
                "showInput": True,
                "showEffects": False,
                "showEvents": False,
                "showObjectChanges": False,
            },
        }
        result = self._rpc(
            "suix_queryTransactionBlocks", [query, cursor, limit, descending],
        )
        if not isinstance(result, dict):
            return {"data": [], "nextCursor": None, "hasNextPage": False}
        data = result.get("data")
        if not isinstance(data, list):
            result["data"] = []
        return result

    # ----- coin metadata (decimals/symbol) -----

    def get_coin_metadata(self, coin_type: str) -> dict[str, Any] | None:
        """Return ``{decimals, symbol, name, ...}`` for ``coin_type`` (cached).
        ``None`` if the type has no metadata or the call fails — the adapter
        then SKIPS that coin rather than guessing its decimals (fabrication)."""
        if coin_type in self._meta_cache:
            return self._meta_cache[coin_type]
        try:
            result = self._rpc("suix_getCoinMetadata", [coin_type])
        except SuiRPCError as exc:
            log.warning("sui: getCoinMetadata failed for %s: %s", coin_type, exc)
            self._meta_cache[coin_type] = None
            return None
        meta = result if isinstance(result, dict) else None
        self._meta_cache[coin_type] = meta
        return meta

    # ----- single tx (for evidence anchoring) -----

    def get_transaction_block(self, digest: str) -> dict[str, Any] | None:
        """Return the full tx block for ``digest`` — ``showInput`` + ``showEffects``
        so it carries the REAL ``timestampMs`` + ``checkpoint`` + ``transaction`` +
        ``effects`` (all verified present live). ``None`` if the result isn't an
        object. Raises ``SuiRPCError`` on a transport / RPC-error response (the
        caller degrades to the unknown-time sentinel rather than fabricating)."""
        result = self._rpc(
            "sui_getTransactionBlock",
            [digest, {
                "showInput": True, "showEffects": True,
                "showBalanceChanges": False, "showEvents": False,
                "showObjectChanges": False,
            }],
        )
        return result if isinstance(result, dict) else None


__all__ = ("SuiRPCClient", "SuiRPCError", "SUI_RPC_URL")
