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

# The Aptos Indexer hard-caps a single query at 100 rows regardless of the
# requested limit (verified live: limit 1000/5000/20000 all return 100). To fetch
# a complete history we paginate with a COMPOUND cursor
# (transaction_version desc, event_index desc): one tx emits many activities that
# share a single transaction_version, so a version-only cursor would skip/dup rows
# at a page boundary — the (version, event_index) cursor is stable (verified live).
_PAGE_SIZE = 100
_MAX_BIGINT = 9223372036854775807  # initial cursor: `_lt MAX` matches everything.

# Activities a focus address SENT (its own withdrawals; gas excluded). Paginated
# via the compound cursor ($v,$e); $page is the per-request page size.
_Q_WITHDRAWS = """
query($owner:String!,$page:Int!,$v:bigint!,$e:bigint!){
  fungible_asset_activities(
    where:{owner_address:{_eq:$owner}, type:{_ilike:"%Withdraw%"},
           is_gas_fee:{_eq:false}, is_transaction_success:{_eq:true},
           _or:[{transaction_version:{_lt:$v}},
                {transaction_version:{_eq:$v}, event_index:{_lt:$e}}]},
    order_by:[{transaction_version:desc},{event_index:desc}], limit:$page
  ){ owner_address amount asset_type type transaction_version transaction_timestamp event_index }
}
"""

# Activities a focus address RECEIVED (its own deposits).
_Q_DEPOSITS = """
query($owner:String!,$page:Int!,$v:bigint!,$e:bigint!){
  fungible_asset_activities(
    where:{owner_address:{_eq:$owner}, type:{_ilike:"%Deposit%"},
           is_gas_fee:{_eq:false}, is_transaction_success:{_eq:true},
           _or:[{transaction_version:{_lt:$v}},
                {transaction_version:{_eq:$v}, event_index:{_lt:$e}}]},
    order_by:[{transaction_version:desc},{event_index:desc}], limit:$page
  ){ owner_address amount asset_type type transaction_version transaction_timestamp event_index }
}
"""

# ALL non-gas activities at a set of transaction versions (to find counterparties).
_Q_AT_VERSIONS = """
query($versions:[bigint!],$page:Int!,$v:bigint!,$e:bigint!){
  fungible_asset_activities(
    where:{transaction_version:{_in:$versions}, is_gas_fee:{_eq:false},
           is_transaction_success:{_eq:true},
           _or:[{transaction_version:{_lt:$v}},
                {transaction_version:{_eq:$v}, event_index:{_lt:$e}}]},
    order_by:[{transaction_version:desc},{event_index:desc}], limit:$page
  ){ owner_address amount asset_type type transaction_version event_index }
}
"""

_Q_METADATA = """
query($assets:[String!]){
  fungible_asset_metadata(where:{asset_type:{_in:$assets}}){ asset_type symbol decimals }
}
"""

# The REAL block time for a ledger version (one activity row) — anchors the
# evidence receipt instead of a placeholder epoch-0 time.
_Q_TX_AT_VERSION = """
query($v:bigint!){
  fungible_asset_activities(where:{transaction_version:{_eq:$v}}, limit:1){
    transaction_version transaction_timestamp }
}
"""


def _as_int(value: Any) -> int | None:
    """Parse a Hasura bigint (int or string) to int, or None when unparseable."""
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


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

    # ----- pagination -----

    def _paginate(
        self, query: str, base_vars: dict[str, Any], *, limit: int,
    ) -> list[dict[str, Any]]:
        """Compound-cursor pagination (transaction_version desc, event_index desc)
        over ``query``, accumulating up to ``limit`` rows total. The Indexer caps a
        single query at 100 rows; this walks pages until a short page, the budget,
        or a stuck cursor (a buggy/echoing mirror can't loop forever). The
        (version, event_index) cursor is stable across the many activities a single
        tx emits at one version — no boundary skip/dup."""
        out: list[dict[str, Any]] = []
        v, e = _MAX_BIGINT, _MAX_BIGINT
        last_cursor: tuple[int, int] | None = None
        while len(out) < limit:
            page = min(_PAGE_SIZE, limit - len(out))
            try:
                data = self._gql(query, {**base_vars, "page": page, "v": v, "e": e})
            except AptosIndexerError:
                # Mid-pagination failure (e.g. the public indexer's 10s timeout on
                # a very-high-volume address): keep the pages already collected
                # rather than losing them. A page-1 failure (no rows yet) still
                # propagates so the caller logs + degrades to no-transfers.
                if out:
                    log.warning(
                        "aptos: pagination stopped early after %d row(s) — "
                        "returning partial results.", len(out),
                    )
                    break
                raise
            rows = self._rows(data, "fungible_asset_activities")
            if not rows:
                break
            tail = rows[-1]
            nv = _as_int(tail.get("transaction_version"))
            ne = _as_int(tail.get("event_index"))
            cursor = (nv, ne) if nv is not None and ne is not None else None
            # Stuck-cursor guard: a buggy/echoing mirror returns the same tail →
            # break BEFORE re-adding the duplicate page (no dup rows, no loop).
            if cursor is not None and cursor == last_cursor:
                break
            out.extend(rows)
            if cursor is None:
                break  # can't advance the cursor safely → stop (no fabrication)
            last_cursor = cursor
            v, e = cursor
            if len(rows) < page:  # short page → exhausted
                break
        return out[:limit]

    # ----- activity queries -----

    def withdraw_activities(self, owner: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """All of ``owner``'s withdrawal activities (gas excluded), newest-first,
        paginated up to ``limit`` total rows (no longer the 100-row indexer cap)."""
        return self._paginate(_Q_WITHDRAWS, {"owner": owner}, limit=limit)

    def deposit_activities(self, owner: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """All of ``owner``'s deposit activities, paginated up to ``limit``."""
        return self._paginate(_Q_DEPOSITS, {"owner": owner}, limit=limit)

    def activities_at_versions(
        self, versions: list[int], *, limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """All non-gas activities at ``versions`` (counterparty discovery). Versions
        are chunked so each ``_in`` query stays small, and each chunk is paginated
        with the compound cursor — so a version with many parties isn't truncated at
        the 100-row indexer cap."""
        if not versions:
            return []
        out: list[dict[str, Any]] = []
        chunk = 50
        for i in range(0, len(versions), chunk):
            if len(out) >= limit:
                break
            batch = versions[i:i + chunk]
            out.extend(self._paginate(
                _Q_AT_VERSIONS, {"versions": batch}, limit=limit - len(out),
            ))
        return out[:limit]

    def transaction_meta(self, version: int) -> dict[str, Any] | None:
        """Return ``{transaction_version, transaction_timestamp}`` for ``version``
        (one activity row), or ``None`` if the version has no indexed activity.
        Used to anchor the evidence receipt to the REAL block time. Raises
        ``AptosIndexerError`` on a transport / GraphQL-error response (the caller
        degrades to the unknown-time sentinel rather than fabricating)."""
        data = self._gql(_Q_TX_AT_VERSION, {"v": int(version)})
        rows = self._rows(data, "fungible_asset_activities")
        return rows[0] if rows else None

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
