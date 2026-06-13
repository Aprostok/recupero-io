"""Aptos Indexer GraphQL client (https://api.mainnet.aptoslabs.com/v1/graphql).

Public, no-auth Aptos Indexer. The adapter uses ONE feed —
``fungible_asset_activities`` — because the indexer has already done the hard
part: it resolves each fungible-store OBJECT back to its OWNER address (the
correctness trap of raw Aptos FA events) AND unifies the legacy Coin standard
(``token_standard: "v1"``) with the Fungible Asset standard (``"v2"``) into one
owner-keyed activity row:

    {owner_address, amount, asset_type, type, is_gas_fee, token_standard,
     transaction_version, transaction_timestamp, is_transaction_success}

``fungible_asset_metadata`` supplies ``decimals``/``symbol`` per ``asset_type``
(cached — metadata is immutable). Shapes captured LIVE (2026-06) before
implementation. Best-effort transport: a non-2xx, a GraphQL ``errors`` payload,
or a malformed body raises ``AptosIndexerError`` and the adapter degrades to
no-transfers rather than crashing a trace.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

_APTOS_HOST = "api.mainnet.aptoslabs.com"
APTOS_INDEXER_URL = f"https://{_APTOS_HOST}/v1/graphql"

# Activities a focus address SENT (its own withdrawals; gas excluded).
_Q_WITHDRAWS = """
query($owner:String!,$limit:Int!){
  fungible_asset_activities(
    where:{owner_address:{_eq:$owner}, type:{_ilike:"%Withdraw%"},
           is_gas_fee:{_eq:false}, is_transaction_success:{_eq:true}},
    order_by:{transaction_version:desc}, limit:$limit
  ){ owner_address amount asset_type type transaction_version transaction_timestamp }
}
"""

# Activities a focus address RECEIVED (its own deposits).
_Q_DEPOSITS = """
query($owner:String!,$limit:Int!){
  fungible_asset_activities(
    where:{owner_address:{_eq:$owner}, type:{_ilike:"%Deposit%"},
           is_gas_fee:{_eq:false}, is_transaction_success:{_eq:true}},
    order_by:{transaction_version:desc}, limit:$limit
  ){ owner_address amount asset_type type transaction_version transaction_timestamp }
}
"""

# ALL non-gas activities at a set of transaction versions (to find counterparties).
_Q_AT_VERSIONS = """
query($versions:[bigint!],$limit:Int!){
  fungible_asset_activities(
    where:{transaction_version:{_in:$versions}, is_gas_fee:{_eq:false},
           is_transaction_success:{_eq:true}},
    order_by:{transaction_version:desc}, limit:$limit
  ){ owner_address amount asset_type type transaction_version }
}
"""

_Q_METADATA = """
query($assets:[String!]){
  fungible_asset_metadata(where:{asset_type:{_in:$assets}}){ asset_type symbol decimals }
}
"""


class AptosIndexerError(RuntimeError):
    """Raised on a non-2xx, GraphQL errors payload, or malformed Indexer response."""


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


class AptosIndexerClient:
    """Thin Aptos Indexer GraphQL client (activities + asset metadata)."""

    def __init__(
        self,
        base_url: str = APTOS_INDEXER_URL,
        *,
        requests_per_second: float = 6.0,
        timeout_seconds: float = 25.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url
        self.limiter = _RateLimiter(requests_per_second)
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(connect=10.0, read=timeout_seconds,
                                  write=timeout_seconds, pool=timeout_seconds),
            headers={"User-Agent": "recupero-aptos/1.0"},
        )
        self._owns_client = http_client is None
        self._meta_cache: dict[str, dict[str, Any] | None] = {}

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> AptosIndexerClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ----- raw GraphQL -----

    def _gql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        self.limiter.wait()
        if httpx.URL(self.base_url).host != _APTOS_HOST:
            raise AptosIndexerError(f"refusing non-Aptos host in {self.base_url!r}")
        try:
            resp = self._client.post(
                self.base_url, json={"query": query, "variables": variables},
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise AptosIndexerError(f"Aptos indexer request failed: {exc}") from exc
        if resp.status_code != 200:
            raise AptosIndexerError(
                f"Aptos indexer returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            body = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise AptosIndexerError("Aptos indexer returned non-JSON") from exc
        if not isinstance(body, dict):
            raise AptosIndexerError("Aptos indexer returned non-object body")
        if body.get("errors"):
            raise AptosIndexerError(f"Aptos indexer GraphQL errors: {body['errors']}")
        data = body.get("data")
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _rows(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
        rows = data.get(key)
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []

    # ----- activity queries -----

    def withdraw_activities(self, owner: str, *, limit: int = 100) -> list[dict[str, Any]]:
        data = self._gql(_Q_WITHDRAWS, {"owner": owner, "limit": limit})
        return self._rows(data, "fungible_asset_activities")

    def deposit_activities(self, owner: str, *, limit: int = 100) -> list[dict[str, Any]]:
        data = self._gql(_Q_DEPOSITS, {"owner": owner, "limit": limit})
        return self._rows(data, "fungible_asset_activities")

    def activities_at_versions(
        self, versions: list[int], *, limit: int = 1000,
    ) -> list[dict[str, Any]]:
        if not versions:
            return []
        data = self._gql(_Q_AT_VERSIONS, {"versions": versions, "limit": limit})
        return self._rows(data, "fungible_asset_activities")

    # ----- asset metadata (decimals/symbol) -----

    def asset_metadata(self, asset_types: list[str]) -> dict[str, dict[str, Any]]:
        """Return ``{asset_type: {symbol, decimals}}`` for the unseen members of
        ``asset_types`` (cached). Missing types map to ``None`` in the cache so
        the adapter skips them (no guessed decimals)."""
        need = [a for a in asset_types if a and a not in self._meta_cache]
        if need:
            try:
                data = self._gql(_Q_METADATA, {"assets": need})
                got = {
                    r["asset_type"]: r
                    for r in self._rows(data, "fungible_asset_metadata")
                    if isinstance(r.get("asset_type"), str)
                }
            except AptosIndexerError as exc:
                log.warning("aptos: asset_metadata fetch failed: %s", exc)
                got = {}
            for a in need:
                self._meta_cache[a] = got.get(a)
        return {a: m for a in asset_types if (m := self._meta_cache.get(a)) is not None}


__all__ = ("AptosIndexerClient", "AptosIndexerError", "APTOS_INDEXER_URL")
