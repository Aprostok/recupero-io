"""Alchemy backend client for EVM chains.

This is an alternative to ``EtherscanClient`` that uses Alchemy's
``alchemy_getAssetTransfers`` JSON-RPC method. It returns rows in the
SAME shape EtherscanClient does so the downstream EvmAdapter
normalization code is unchanged — only the network backend differs.

Why this exists (RIGOR-Jacob B):

  * Etherscan's free tier is 5 req/sec, 100k/day. Heavy operator
    workflows (multi-hop V-CFI01-shape investigations) burn through
    the daily budget fast, so the operator's --prefer-alchemy escape
    hatch lets us route through Alchemy's much higher quota
    (compute-units based, ~300M CU/day on the free tier).
  * Alchemy's address-transfer endpoint paginates differently than
    Etherscan's. Where Etherscan caps each account-action query at
    `page*offset <= 10_000`, Alchemy uses a pageKey cursor and has
    no equivalent hard cap. For very-chatty wallets that hit
    Etherscan's pagination ceiling, Alchemy reliably returns the
    complete history.
  * Etherscan V2 occasionally returns empty for high-block-rate
    chains (Arbitrum, Polygon, Base) when called with a non-zero
    startblock. The client-side filter in
    EvmAdapter._needs_client_side_start_block_filter is one
    mitigation; Alchemy is another — it has consistent semantics
    across all chains.

What it does NOT do:

  * Block-by-timestamp (Alchemy doesn't have a 1-call equivalent of
    Etherscan's ``getblocknobytime``). The adapter falls back to
    Etherscan for that one call; if both are unavailable it walks
    via binary search over eth_getBlockByNumber.
  * Contract metadata (``get_contract_source``). Alchemy doesn't
    surface verified-source listings the way Etherscan does.
    EvmAdapter.is_contract() handles its own fallback —
    eth_getCode returns non-empty bytecode for any contract address,
    so we don't actually need the source lookup; the existing code
    just uses it as a convenience signal. The Alchemy backend
    answers is_contract via eth_getCode.

The compatibility contract: callers of EtherscanClient see the same
public method signatures and return shapes from this class. Any
divergence breaks the adapter — locked by
tests/test_alchemy_client_compat.py.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)


class AlchemyError(RuntimeError):
    """Non-recoverable Alchemy response (bad input, banned key, etc.)."""


class AlchemyRateLimitError(RuntimeError):
    """HTTP 429 or 'compute units exhausted'. Retryable / fallback."""


# Map from recupero Chain enum / Etherscan chain_id → Alchemy network URL
# prefix. The full URL is f"https://{prefix}.g.alchemy.com/v2/{api_key}".
# Maintainability: every EVM chain we support via Etherscan V2 should be
# representable here (or explicitly fall through to Etherscan when not).
_CHAIN_ID_TO_ALCHEMY_PREFIX: dict[int, str] = {
    1: "eth-mainnet",
    137: "polygon-mainnet",
    42161: "arb-mainnet",
    10: "opt-mainnet",
    8453: "base-mainnet",
    56: "bnb-mainnet",        # Alchemy added BNB chain late-2024
    43114: "avax-mainnet",    # Alchemy Avalanche C-Chain
    81457: "blast-mainnet",
    324: "zksync-mainnet",
    534352: "scroll-mainnet",
    5000: "mantle-mainnet",
    59144: "linea-mainnet",
}


class _RateLimiter:
    """Same shape as EtherscanClient._RateLimiter — duplicated rather
    than imported to avoid coupling. ~300 CU/sec on Alchemy's free
    tier; alchemy_getAssetTransfers costs 150 CU per call, so 2 calls/sec
    is the safe upper bound."""

    def __init__(self, rps: float) -> None:
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            target = max(self._next_allowed, now)
            self._next_allowed = target + self.min_interval
        delay = target - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class AlchemyClient:
    """Etherscan-shape client backed by Alchemy's RPC.

    Returns the SAME dict keys as EtherscanClient on:
      * get_normal_transactions    (Etherscan: txlist)
      * get_internal_transactions  (Etherscan: txlistinternal)
      * get_erc20_transfers        (Etherscan: tokentx)

    Other methods (get_block_number_by_time, get_contract_source,
    get_transaction_by_hash, get_transaction_receipt, etc.) raise
    NotImplementedError — the adapter must fall back to Etherscan for
    these. The fallback is handled at the adapter level so the client
    stays clean and single-purpose.
    """

    # Alchemy's alchemy_getAssetTransfers has a hard cap of 1000 rows
    # per call (maxCount). We loop on pageKey until either:
    #   - empty pageKey (end of data), or
    #   - we've accumulated max_results rows, or
    #   - the safety cap is hit.
    _ALCHEMY_MAX_PAGE_SIZE = 1000
    _ALCHEMY_MAX_PAGES = 20  # 20k row safety ceiling per call

    def __init__(
        self,
        api_key: str,
        chain_id: int = 1,
        requests_per_second: float = 2.0,
        timeout_seconds: float = 60.0,
    ) -> None:
        if not api_key:
            raise ValueError("ALCHEMY_API_KEY is required")
        if chain_id not in _CHAIN_ID_TO_ALCHEMY_PREFIX:
            raise ValueError(
                f"Alchemy backend doesn't support chain_id={chain_id} "
                f"(supported: {sorted(_CHAIN_ID_TO_ALCHEMY_PREFIX)})"
            )
        self.api_key = api_key
        self.chain_id = chain_id
        prefix = _CHAIN_ID_TO_ALCHEMY_PREFIX[chain_id]
        self.api_url = f"https://{prefix}.g.alchemy.com/v2/{api_key}"
        self.limiter = _RateLimiter(requests_per_second)
        # Split connect vs read timeout: a slow-DNS / hung-TCP-handshake
        # against *.g.alchemy.com must not block the worker for the full
        # 60s read window. Connect cap = 10s — any Alchemy edge resolves
        # well under that on a healthy network.
        self._client = httpx.Client(
            timeout=httpx.Timeout(
                connect=10.0,
                read=timeout_seconds,
                write=timeout_seconds,
                pool=timeout_seconds,
            )
        )

    def close(self) -> None:
        self._client.close()

    def _redact(self, text: str) -> str:
        """Strip the api_key out of an error message.

        Alchemy embeds the api_key directly in the URL path segment, so
        any httpx exception that includes the URL (most do — DNS,
        connect, read-timeout all stringify with the request URL) will
        leak the secret. Replace both the raw key and the full URL
        prefix with a sentinel before propagation.
        """
        # `getattr` so test fixtures that build via __new__ (bypassing
        # __init__) don't AttributeError on the redaction path itself.
        api_key = getattr(self, "api_key", None)
        if not text or not api_key:
            return text
        # Replace the full URL first so partial-key matches don't shadow
        # the surrounding path.
        api_url = getattr(self, "api_url", None)
        if api_url:
            text = text.replace(api_url, "https://[REDACTED]/v2/[REDACTED]")
        return text.replace(api_key, "[REDACTED]")

    # ---------- Low-level JSON-RPC ----------

    def _rpc(self, method: str, params: list[Any]) -> Any:
        """Call the Alchemy JSON-RPC. Raises AlchemyError on non-2xx /
        RPC error bodies, AlchemyRateLimitError on 429 / quota."""
        self.limiter.wait()
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
        try:
            resp = self._client.post(self.api_url, json=body)
        except httpx.HTTPError as e:
            # Adversarial-input wave: httpx exception messages embed the
            # request URL, and our Alchemy URL has the api_key in the
            # PATH segment (https://eth-mainnet.g.alchemy.com/v2/<KEY>).
            # The logging-setup redaction layer catches `?api-key=` and
            # `Bearer ...` shapes but does NOT catch path-segment keys
            # with no fixed prefix, so the raw key would land in any log
            # that prints this exception. Scrub the api_key out of the
            # message before re-raising.
            raise AlchemyError(
                f"alchemy rpc transport: {self._redact(str(e))}"
            ) from e
        if resp.status_code == 429:
            raise AlchemyRateLimitError(
                f"alchemy 429 (rate-limit / quota): {self._redact(resp.text[:200])}"
            )
        if resp.status_code >= 500:
            # Treat 5xx as rate-limit-shape (retryable / fallback).
            raise AlchemyRateLimitError(
                f"alchemy {resp.status_code}: {self._redact(resp.text[:200])}"
            )
        if resp.status_code != 200:
            raise AlchemyError(
                f"alchemy http {resp.status_code}: {self._redact(resp.text[:200])}"
            )
        # RIGOR-Jacob D adversarial: a 200 OK from Alchemy's edge proxy
        # during a regional incident has been observed to carry an HTML
        # body (e.g. a 503 page served by Cloudflare while the JSON
        # backend is sick). ``resp.json()`` then raises ValueError /
        # ``json.JSONDecodeError`` — which is NOT a subclass of
        # ``httpx.HTTPError`` and would bypass the dual-backend
        # fallback (``_alchemy_or_fallback`` only catches
        # ``AlchemyError`` / ``AlchemyRateLimitError``). Wrap as
        # AlchemyError so the fallback triggers cleanly.
        try:
            data = resp.json()
        except ValueError as e:
            raise AlchemyError(
                f"alchemy returned non-JSON body: {self._redact(resp.text[:200])!r}"
            ) from e
        if "error" in data:
            err = data["error"]
            code = err.get("code", 0) if isinstance(err, dict) else 0
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            msg = self._redact(msg)
            # Alchemy error code -32005 is "Your app has exceeded its
            # compute units per second capacity" — treat as
            # retryable / fallback signal.
            if code == -32005 or "rate limit" in msg.lower() or "quota" in msg.lower():
                raise AlchemyRateLimitError(f"alchemy rate-limit: {msg}")
            raise AlchemyError(f"alchemy rpc error {code}: {msg}")
        return data.get("result")

    # ---------- alchemy_getAssetTransfers wrapper ----------

    def _get_asset_transfers(
        self,
        *,
        from_address: str | None,
        to_address: str | None,
        category: list[str],
        from_block_hex: str,
        max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Drive paginated alchemy_getAssetTransfers.

        category options:
          - "external" — top-level ETH transfers (≈ Etherscan txlist)
          - "internal" — internal ETH transfers (≈ txlistinternal)
          - "erc20"    — ERC-20 token transfers (≈ tokentx)
          - "erc721", "erc1155" — NFTs (not used here)
        """
        all_rows: list[dict[str, Any]] = []
        page_key: str | None = None
        params_base: dict[str, Any] = {
            "fromBlock": from_block_hex,
            "toBlock": "latest",
            "category": category,
            "excludeZeroValue": True,
            "withMetadata": True,
            "maxCount": hex(self._ALCHEMY_MAX_PAGE_SIZE),
            "order": "asc",
        }
        if from_address:
            params_base["fromAddress"] = from_address
        if to_address:
            params_base["toAddress"] = to_address

        last_page_key: str | None = None
        for _ in range(self._ALCHEMY_MAX_PAGES):
            params = dict(params_base)
            if page_key:
                params["pageKey"] = page_key
            # RIGOR-Jacob D adversarial: stuck-cursor early bail. If
            # the upstream just handed us back the SAME pageKey we used
            # last iteration, calling again will return the same page —
            # don't make the round trip, don't append the duplicate
            # rows. (Detect BEFORE extend so we never emit a duplicate
            # page even once.)
            if page_key is not None and page_key == last_page_key:
                log.warning(
                    "alchemy_getAssetTransfers stuck cursor detected "
                    "(pageKey=%r repeated) — stopping pagination",
                    page_key,
                )
                break
            last_page_key = page_key
            result = self._rpc("alchemy_getAssetTransfers", [params])
            if not isinstance(result, dict):
                break
            # RIGOR-Jacob D: ``transfers`` MUST be a list. Defensive
            # type check — without it, a malformed response like
            # ``{"transfers": "garbage-string"}`` would iterate over
            # the string's characters via ``.extend()``, producing
            # nonsense "rows" that would crash the normalizer
            # downstream. Locked by tests
            # ``test_pagination_handles_non_list_transfers_field`` /
            # ``test_pagination_handles_null_transfers_field``.
            transfers = result.get("transfers")
            if not isinstance(transfers, list):
                break
            all_rows.extend(transfers)
            page_key = result.get("pageKey")
            # RIGOR-Jacob A: honor the fetch-layer cap.
            if max_results is not None and len(all_rows) >= max_results:
                break
            if not page_key:
                break
        return all_rows

    # ---------- Public API (Etherscan-compatible shape) ----------

    def get_normal_transactions(
        self,
        address: str,
        start_block: int,
        end_block: int = 99_999_999,  # noqa: ARG002 (unused — Alchemy uses "latest")
        page: int = 1,  # noqa: ARG002 (single-shot path not supported)
        offset: int = 1000,  # noqa: ARG002
        max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        rows = self._get_asset_transfers(
            from_address=address.lower(),
            to_address=None,
            category=["external"],
            from_block_hex=hex(start_block),
            max_results=max_results,
        )
        return [self._normalize_external_to_etherscan(r) for r in rows]

    def get_internal_transactions(
        self,
        address: str,
        start_block: int,
        end_block: int = 99_999_999,  # noqa: ARG002
        page: int = 1,  # noqa: ARG002
        offset: int = 1000,  # noqa: ARG002
        max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        rows = self._get_asset_transfers(
            from_address=address.lower(),
            to_address=None,
            category=["internal"],
            from_block_hex=hex(start_block),
            max_results=max_results,
        )
        return [self._normalize_external_to_etherscan(r) for r in rows]

    def get_erc20_transfers(
        self,
        address: str,
        start_block: int,
        end_block: int = 99_999_999,  # noqa: ARG002
        page: int = 1,  # noqa: ARG002
        offset: int = 1000,  # noqa: ARG002
        max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        rows = self._get_asset_transfers(
            from_address=address.lower(),
            to_address=None,
            category=["erc20"],
            from_block_hex=hex(start_block),
            max_results=max_results,
        )
        return [self._normalize_erc20_to_etherscan(r) for r in rows]

    # ---------- Normalization helpers ----------
    #
    # Alchemy's row shape:
    #   {
    #     "blockNum": "0x12abcd",
    #     "hash": "0x...",
    #     "from": "0x...",
    #     "to": "0x...",
    #     "value": 0.5,         # already in token units (NOT raw)
    #     "asset": "ETH",
    #     "category": "external",
    #     "rawContract": {
    #       "address": null (for native) | "0xCONTRACT",
    #       "value":   "0x6f05b59d3b20000",   # raw hex amount
    #       "decimal": "0x12",
    #     },
    #     "metadata": {"blockTimestamp": "2025-01-01T00:00:00Z"},
    #   }
    #
    # Etherscan native-tx row:
    #   {
    #     "hash": "0x...", "blockNumber": "<int-as-str>",
    #     "timeStamp": "<unix-as-str>", "from": "0x...", "to": "0x...",
    #     "value": "<wei-as-str>", "isError": "0", "txreceipt_status": "1",
    #     "contractAddress": "",
    #   }
    #
    # Etherscan token-tx row:
    #   {
    #     "hash": "0x...", "blockNumber": "<int-as-str>",
    #     "timeStamp": "<unix-as-str>", "from": "0x...", "to": "0x...",
    #     "value": "<raw-as-str>", "tokenName": "...", "tokenSymbol": "...",
    #     "tokenDecimal": "<int-as-str>", "contractAddress": "0x...",
    #     "isError": "0",
    #   }

    @staticmethod
    def _normalize_external_to_etherscan(row: dict[str, Any]) -> dict[str, Any]:
        """Reshape an Alchemy external/internal transfer into the dict
        keys EthereumAdapter expects from Etherscan."""
        raw = row.get("rawContract") or {}
        block_num_hex = row.get("blockNum") or "0x0"
        try:
            block_num = int(block_num_hex, 16)
        except (ValueError, TypeError):
            block_num = 0
        ts_iso = (row.get("metadata") or {}).get("blockTimestamp", "")
        ts_str = _iso_to_unix_or_sentinel(ts_iso)
        # raw.value is hex-encoded native units (wei for ETH chains).
        raw_value_hex = raw.get("value") or "0x0"
        try:
            wei = int(raw_value_hex, 16)
        except (ValueError, TypeError):
            wei = 0
        return {
            "hash": row.get("hash", ""),
            "blockNumber": str(block_num),
            "timeStamp": ts_str,
            "from": (row.get("from") or "").lower(),
            "to": (row.get("to") or "").lower(),
            "value": str(wei),
            # Alchemy doesn't surface revert state on the transfers
            # endpoint — Alchemy filters reverted txs out at the source.
            # So set the Etherscan revert fields to "success" to keep
            # the EvmAdapter._is_failed_tx filter happy.
            "isError": "0",
            "txreceipt_status": "1",
            "contractAddress": "",
        }

    @staticmethod
    def _normalize_erc20_to_etherscan(row: dict[str, Any]) -> dict[str, Any]:
        """Reshape an Alchemy erc20 transfer into the Etherscan tokentx
        dict shape.

        RIGOR-Jacob D (adversarial-input audit): the sentinel values
        below match Etherscan's "missing field" shape so the EVM
        adapter's existing skip logic catches bad rows uniformly,
        regardless of backend:
          * missing/unparseable ``tokenDecimal`` → emit ``""``
            (Etherscan does the same; EvmAdapter._normalize_erc20
            raises ValueError → row is logged + skipped).
          * missing/unparseable ``blockTimestamp`` → emit ``""``
            (Etherscan's _decode_block_time raises ValueError on
            non-integer; same skip path).
        Pre-fix the Alchemy backend silently emitted decimals=0 (a
        USDT row would 10^6× inflate) and timeStamp=0 (1970-01-01
        block_time landing in case.json).
        """
        raw = row.get("rawContract") or {}
        block_num_hex = row.get("blockNum") or "0x0"
        try:
            block_num = int(block_num_hex, 16)
        except (ValueError, TypeError):
            block_num = 0
        ts_iso = (row.get("metadata") or {}).get("blockTimestamp", "")
        ts_str = _iso_to_unix_or_sentinel(ts_iso)
        # rawContract.value: raw hex token units (factor in decimals).
        raw_value_hex = raw.get("value") or "0x0"
        try:
            raw_value = int(raw_value_hex, 16)
        except (ValueError, TypeError):
            raw_value = 0
        # rawContract.decimal: hex string ("0x12" = 18) OR integer
        # (older API). Anything else → "" sentinel matching Etherscan's
        # unenriched-token shape.
        decimal_str = _parse_alchemy_decimal_or_sentinel(raw.get("decimal"))
        return {
            "hash": row.get("hash", ""),
            "blockNumber": str(block_num),
            "timeStamp": ts_str,
            "from": (row.get("from") or "").lower(),
            "to": (row.get("to") or "").lower(),
            "value": str(raw_value),
            "tokenName": row.get("asset", "") or "",
            "tokenSymbol": row.get("asset", "") or "",
            "tokenDecimal": decimal_str,
            "contractAddress": (raw.get("address") or "").lower(),
            "isError": "0",
            "txreceipt_status": "1",
        }


def _iso_to_unix_or_sentinel(iso: str) -> str:
    """ISO-8601 → ``"<unix_seconds>"``, or ``""`` (sentinel) when the
    input is missing/unparseable.

    The "" sentinel matters: ``EvmAdapter._decode_block_time`` raises
    ValueError on a non-integer timeStamp, which causes the row to be
    logged + skipped. Returning ``"0"`` instead would silently emit a
    1970-01-01 block_time into case.json. See test
    ``test_normalize_native_missing_timestamp_does_not_silently_emit_1970``.
    """
    if not iso:
        return ""
    try:
        from datetime import datetime
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        unix = int(datetime.fromisoformat(iso).timestamp())
        if unix <= 0:
            return ""  # epoch or before → sentinel
        return str(unix)
    except (ValueError, TypeError):
        return ""


def _parse_alchemy_decimal_or_sentinel(dec_field: Any) -> str:
    """rawContract.decimal → decimal string, or ``""`` sentinel.

    Alchemy emits decimal as either a hex-prefixed string (``"0x12"``)
    or an integer (older API). Anything else → ``""`` which causes
    the downstream EVM adapter to raise+log+skip the row — same
    behavior as Etherscan's unenriched-token shape. Pre-fix the
    fallback was ``"0"`` which would silently 10^N-inflate USDT/USDC.
    """
    if dec_field is None:
        return ""
    try:
        if isinstance(dec_field, bool):
            # bool is an int subclass in Python; reject explicitly.
            return ""
        if isinstance(dec_field, int):
            if dec_field < 0 or dec_field > 38:
                # Token decimals beyond 38 are not real; reject.
                return ""
            return str(dec_field)
        if isinstance(dec_field, str):
            if dec_field.startswith("0x"):
                val = int(dec_field, 16)
            else:
                val = int(dec_field)
            if val < 0 or val > 38:
                return ""
            return str(val)
    except (ValueError, TypeError):
        pass
    return ""
