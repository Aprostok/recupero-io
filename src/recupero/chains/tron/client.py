"""Thin TronGrid REST client (v0.12.0).

TronGrid (https://www.trongrid.io) is the canonical public API
gateway for Tron mainnet, maintained by the Tron Foundation —
roughly equivalent role to Etherscan for EVM. We use its
**REST v1** endpoints (not the JSON-RPC endpoints) because:

  * They return parsed TRC-20 transfer arrays directly. JSON-RPC
    returns raw VM data that would require us to implement the
    Tron-specific event-log decoding ourselves.

  * Pagination is cursor-based via the ``fingerprint`` field,
    which is far more reliable than block-number windowing for
    high-traffic addresses.

Free tier: 100k requests per day, ~10 req/sec. API key (optional but
recommended) goes in the ``TRON_PRO_API_KEY`` header.

Endpoints we wrap
-----------------

  GET /v1/accounts/{address}
    Account metadata: balance, frozen amount, contract flag.

  GET /v1/accounts/{address}/transactions/trc20
    Paginated TRC-20 transfer history. Returns parsed events
    with ``token_info`` (symbol, decimals, contract address),
    ``from`` / ``to`` in base58check, ``value`` in raw integer.

  GET /v1/blocks/latest
    Used by adapters to anchor a "trace up through now" window.

  GET /walletsolidity/getblockbylimit (Tron JSON-RPC-ish)
    For mapping a timestamp → block. The REST API has no direct
    timestamp-to-block endpoint, but the wallet-solidity path
    accepts a ``num`` range and returns block headers from which
    we can binary-search.

Reference docs:
  https://developers.tron.network/reference/trc20-transactions
  https://developers.tron.network/reference/api-key
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

log = logging.getLogger(__name__)


def _strip_0x(s: str) -> str:
    """Strip an optional 0x prefix from a hex string.

    Tron txID's are 64-char lowercase hex WITHOUT a 0x prefix. Some
    callers (and explorer URLs) pass the EVM-style 0x prefix anyway;
    the wallet endpoints reject those. Normalize defensively.
    """
    s = (s or "").strip()
    if s.startswith(("0x", "0X")):
        return s[2:]
    return s


# Public TronGrid endpoints. Mainnet only — we don't expose Shasta /
# Nile testnets because forensic cases always run against mainnet.
TRONGRID_BASE_MAINNET = "https://api.trongrid.io"


class TronGridError(RuntimeError):
    """Non-recoverable TronGrid error (bad address, auth failure)."""


class TronGridRateLimitError(RuntimeError):
    """HTTP 429 or rate-limit-style response. Retryable."""


class _RateLimiter:
    """Simple monotonic-clock rate limiter (thread-safe)."""

    def __init__(self, rps: float) -> None:
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        # v0.18.5 (round-11 chains-CRIT-003): reserve under lock,
        # sleep WITHOUT it. Pre-v0.18.5 the entire `time.sleep` ran
        # while holding the lock — every concurrent thread queued
        # behind it serialized to ~1/rps regardless of parallelism.
        # Etherscan client has this exact fix documented; ported here.
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            target = max(self._next_allowed, now)
            self._next_allowed = target + self.min_interval
        delay = target - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class TronGridClient:
    """Synchronous TronGrid REST client.

    API key is optional but strongly recommended for production —
    unkeyed access has tighter rate limits (~5 rps) and is the
    first thing throttled when TronGrid is under load.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = TRONGRID_BASE_MAINNET,
        requests_per_second: float = 8.0,
        timeout_seconds: float = 30.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.api_key = api_key or ""
        self.base_url = base_url.rstrip("/")
        self.limiter = _RateLimiter(requests_per_second)
        # http_client injection point — lets tests pass a respx-
        # mocked Client without monkey-patching httpx globally.
        self._client = http_client or httpx.Client(timeout=timeout_seconds)
        self._owns_client = http_client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> TronGridClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ---------- High-level wrappers ---------- #

    def get_account(self, address: str) -> dict[str, Any]:
        """Fetch the account metadata for ``address`` (base58check).

        Returns the raw TronGrid response object (parsed JSON). The
        adapter is responsible for extracting balance / contract
        flag / etc.

        Empty addresses (never observed on-chain) return ``{"data": []}``
        from TronGrid — we pass that through; the caller should
        treat empty ``data`` as "address never existed".
        """
        return self._get(
            f"/v1/accounts/{address}",
            params={"only_confirmed": "true"},
        )

    def get_trc20_transfers(
        self,
        address: str,
        *,
        limit: int = 200,
        min_timestamp: int | None = None,
        max_timestamp: int | None = None,
        contract_address: str | None = None,
        max_pages: int = 50,
        only_to: bool | None = None,
        only_from: bool | None = None,
    ) -> list[dict[str, Any]]:
        """Paginated TRC-20 transfer history for ``address``.

        Returns the flat list of parsed transfer events (each one
        a dict with ``from``, ``to``, ``value``, ``token_info``,
        ``block_timestamp``, ``transaction_id`` and friends).

        Pagination is cursor-based: TronGrid returns a
        ``meta.fingerprint`` field if more pages exist. We thread
        that through up to ``max_pages`` (default 50 → 10k events
        per call, generous for any realistic case).

        ``only_to`` / ``only_from`` restrict to one direction at the
        TronGrid level (server-side filter), avoiding wasted
        bandwidth.

        ``min_timestamp`` / ``max_timestamp`` are unix-MS timestamps.
        TronGrid filters on ``block_timestamp`` (millisecond
        precision) — we pass straight through.

        Tron's contract address for filtering is in **base58check**
        form (matching TronGrid's accepted input shape), e.g.
        ``TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`` for USDT.
        """
        out: list[dict[str, Any]] = []
        params: dict[str, Any] = {"limit": str(min(limit, 200))}
        if min_timestamp is not None:
            params["min_timestamp"] = str(min_timestamp)
        if max_timestamp is not None:
            params["max_timestamp"] = str(max_timestamp)
        if contract_address is not None:
            params["contract_address"] = contract_address
        if only_to:
            params["only_to"] = "true"
        if only_from:
            params["only_from"] = "true"

        url = f"/v1/accounts/{address}/transactions/trc20"
        for page in range(max_pages):
            body = self._get(url, params=params)
            data = body.get("data") or []
            if not isinstance(data, list):
                log.warning(
                    "trongrid trc20 transfers: unexpected non-list 'data' field "
                    "(got %r); stopping pagination",
                    type(data).__name__,
                )
                break
            out.extend(data)
            meta = body.get("meta") or {}
            fingerprint = meta.get("fingerprint") if isinstance(meta, dict) else None
            if not fingerprint or not data:
                break
            params["fingerprint"] = fingerprint
        else:
            log.warning(
                "trongrid trc20 transfers: hit max_pages=%d for %s; "
                "results may be truncated",
                max_pages, address,
            )
        return out

    def get_latest_block(self) -> dict[str, Any]:
        """Latest block header. Used by adapters to anchor an
        "up through now" timestamp window."""
        return self._get("/v1/blocks/latest")

    def get_transaction_by_id(self, tx_hash: str) -> dict[str, Any]:
        """Fetch the signed transaction by hash (v0.17.5).

        Used by the adapter's fetch_evidence_receipt to assemble
        the chain-of-custody bundle. Returns the raw signed-tx
        envelope including ``raw_data`` (contract list, ref_block,
        expiration, fee_limit), ``signature``, and ``txID``.

        Tron tx hashes are 64-char lowercase hex (no 0x prefix).
        The /wallet/gettransactionbyid endpoint expects POST with
        ``{"value": hex_hash}``.
        """
        return self._post(
            "/wallet/gettransactionbyid",
            body={"value": _strip_0x(tx_hash)},
        )

    def get_transaction_info_by_id(self, tx_hash: str) -> dict[str, Any]:
        """Fetch the transaction receipt (post-execution info) by hash.

        Returns block number, contract results, log events, energy
        usage, and fee — the receipt half of the evidence bundle.

        Same POST shape as get_transaction_by_id.
        """
        return self._post(
            "/wallet/gettransactioninfobyid",
            body={"value": _strip_0x(tx_hash)},
        )

    def get_block_by_num(self, block_num: int) -> dict[str, Any]:
        """Fetch a block header by block number (v0.17.5).

        Tron's wallet endpoint returns the block header + parent
        hash + transactions array. We use it for the
        EvidenceReceipt.raw_block_header field.
        """
        return self._post(
            "/wallet/getblockbynum",
            body={"num": int(block_num)},
        )

    # ---------- Low-level GET / POST ---------- #

    @retry(
        retry=retry_if_exception_type(TronGridRateLimitError),
        wait=wait_exponential(multiplier=1.0, min=1, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Internal GET with rate limiting + 429 retry."""
        self.limiter.wait()
        url = f"{self.base_url}{path}"
        headers: dict[str, str] = {}
        if self.api_key:
            headers["TRON-PRO-API-KEY"] = self.api_key
        try:
            resp = self._client.get(url, params=params, headers=headers)
        except httpx.RequestError as e:
            # v0.18.5 (round-11 chains-CRIT-005): treat transient
            # network errors (DNS, connect, read timeout, RST) as
            # retryable. Pre-v0.18.5 a single TCP RST killed
            # mid-pagination — TronGrid pagination at page 12 of 50
            # would silently drop pages 12+ on one bad request.
            raise TronGridRateLimitError(f"network error: {e}") from e
        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After", "(none)")
            log.info("trongrid 429 rate limit; retry-after=%s", ra)
            raise TronGridRateLimitError(
                f"HTTP 429 for {url} (retry-after={ra})"
            )
        if resp.status_code >= 500:
            # Server error — also retry. We funnel through the
            # rate-limit exception so tenacity catches it.
            raise TronGridRateLimitError(
                f"HTTP {resp.status_code} for {url}: {resp.text[:200]!r}"
            )
        if resp.status_code != 200:
            raise TronGridError(
                f"HTTP {resp.status_code} for {url}: {resp.text[:500]!r}"
            )
        try:
            body = resp.json()
        except ValueError as e:
            raise TronGridError(f"non-JSON response from {url}: {e}") from e
        # TronGrid sometimes returns ``{"Error": "..."}`` with a 200
        # status (e.g. for an unknown address). Surface as a real
        # error so callers don't silently accept empty results.
        if isinstance(body, dict) and body.get("Error"):
            raise TronGridError(f"TronGrid error for {url}: {body.get('Error')}")
        return body

    @retry(
        retry=retry_if_exception_type(TronGridRateLimitError),
        wait=wait_exponential(multiplier=1.0, min=1, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _post(
        self,
        path: str,
        *,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        """Internal JSON POST with rate limiting + 429 / 5xx retry.

        Used for Tron's wallet endpoints (gettransactionbyid,
        gettransactioninfobyid, getblockbynum), which require POST
        even when semantically read-only. The retry / error shape
        mirrors _get exactly.
        """
        self.limiter.wait()
        url = f"{self.base_url}{path}"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["TRON-PRO-API-KEY"] = self.api_key
        try:
            resp = self._client.post(url, json=body, headers=headers)
        except httpx.RequestError as e:
            # v0.18.5 (round-11 chains-CRIT-005): network errors → retryable.
            raise TronGridRateLimitError(f"network error: {e}") from e
        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After", "(none)")
            log.info("trongrid 429 rate limit; retry-after=%s", ra)
            raise TronGridRateLimitError(
                f"HTTP 429 for {url} (retry-after={ra})"
            )
        if resp.status_code >= 500:
            raise TronGridRateLimitError(
                f"HTTP {resp.status_code} for {url}: {resp.text[:200]!r}"
            )
        if resp.status_code != 200:
            raise TronGridError(
                f"HTTP {resp.status_code} for {url}: {resp.text[:500]!r}"
            )
        try:
            out = resp.json()
        except ValueError as e:
            raise TronGridError(f"non-JSON response from {url}: {e}") from e
        if isinstance(out, dict) and out.get("Error"):
            raise TronGridError(f"TronGrid error for {url}: {out.get('Error')}")
        return out if isinstance(out, dict) else {"data": out}


__all__ = (
    "TronGridError",
    "TronGridRateLimitError",
    "TronGridClient",
    "TRONGRID_BASE_MAINNET",
)
