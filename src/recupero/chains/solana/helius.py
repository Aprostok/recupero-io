"""Thin Helius API client.

Helius's Enhanced Transactions API returns parsed Solana transactions with
native + SPL token transfer arrays already decoded. This client just wraps
pagination and rate limiting; the adapter normalizes into our internal shape.

Free tier: 100K requests/month, no per-second limit documented but we throttle
to 10 rps out of politeness.

Reference: https://docs.helius.dev/api-reference/enhanced-transactions
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

log = logging.getLogger(__name__)


class HeliusError(RuntimeError):
    """Non-recoverable Helius error (bad address, auth failure)."""


class HeliusRateLimitError(RuntimeError):
    """HTTP 429 or rate limit message from Helius. Retryable."""


class _RateLimiter:
    def __init__(self, rps: float) -> None:
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        # v0.18.5 (round-11 chains-CRIT-003): reserve under lock,
        # sleep without it. See Etherscan client for full rationale.
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            target = max(self._next_allowed, now)
            self._next_allowed = target + self.min_interval
        delay = target - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class HeliusClient:
    """Synchronous client over Helius's Enhanced Transactions API."""

    BASE = "https://api.helius.xyz"
    RPC = "https://mainnet.helius-rpc.com"

    def __init__(
        self,
        api_key: str,
        requests_per_second: float = 10.0,
        timeout_seconds: float = 30.0,
    ) -> None:
        if not api_key:
            raise ValueError("HELIUS_API_KEY is required")
        self.api_key = api_key
        self.limiter = _RateLimiter(requests_per_second)
        # Split connect vs read timeout: a slow-DNS / hung-TCP-handshake
        # against api.helius.xyz must not block the worker for the full
        # 30s read window. Connect cap = 10s.
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

    # ---------- High-level wrappers ----------

    def get_parsed_transactions(
        self,
        address: str,
        *,
        limit: int = 100,
        before_signature: str | None = None,
        max_pages: int = 50,
        stop_if_older_than: int | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch parsed transactions for ``address``, paginating until exhausted
        or until we hit a transaction older than ``stop_if_older_than`` (unix ts).

        Returns the raw Helius parsed-transaction objects (list of dicts). The
        adapter is responsible for converting these into our internal format.
        """
        all_txs: list[dict[str, Any]] = []
        cursor = before_signature
        # RIGOR-Jacob Z14: detect a non-advancing cursor (buggy or
        # adversarial mirror returns the same last-signature forever)
        # and break early instead of burning all max_pages slots on
        # duplicate work.
        stuck_count = 0
        for page in range(max_pages):
            batch = self._fetch_page(address, limit=limit, before=cursor)
            if not batch:
                break
            all_txs.extend(batch)
            # Helius sorts newest-first. If oldest in this batch is older than
            # our cutoff, we can stop paginating.
            if stop_if_older_than is not None:
                oldest_ts = min((tx.get("timestamp", 0) for tx in batch), default=0)
                if oldest_ts < stop_if_older_than:
                    log.debug(
                        "helius pagination stop at page %d (oldest tx ts=%d < cutoff=%d)",
                        page, oldest_ts, stop_if_older_than,
                    )
                    break
            # Cursor = signature of the last (oldest) tx in this page
            next_cursor = batch[-1].get("signature")
            if not next_cursor:
                break
            # Stuck-cursor guard: if this page's cursor equals the
            # cursor we used to fetch it, the mirror is returning the
            # same page repeatedly. Count repeats; break early.
            if next_cursor == cursor:
                stuck_count += 1
                if stuck_count >= 1:
                    log.warning(
                        "helius pagination stuck cursor at page %d "
                        "(cursor=%r); breaking",
                        page, next_cursor,
                    )
                    break
            else:
                stuck_count = 0
            cursor = next_cursor
        return all_txs

    def get_current_slot(self) -> int:
        """RPC getSlot — returns the most recent confirmed slot number."""
        data = self._rpc_call("getSlot")
        return int(data.get("result", 0))

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type((HeliusRateLimitError, httpx.TransportError)),
        reraise=True,
    )
    def get_parsed_transaction(self, signature: str) -> dict[str, Any] | None:
        """Fetch a single parsed transaction by its signature.

        Wrapped with the same retry decorator as the sister methods
        (_fetch_page, _rpc_call) — this was the one chain-call path
        Jacob's ReadTimeout in the freeze-target stage could have
        hit without an absorbing layer. Closed in v0.5.3.
        """
        self.limiter.wait()
        url = f"{self.BASE}/v0/transactions"
        params = {"api-key": self.api_key}
        payload = {"transactions": [signature]}
        resp = self._client.post(url, params=params, json=payload)
        if resp.status_code == 429:
            raise HeliusRateLimitError("HTTP 429")
        if resp.status_code == 401:
            raise HeliusError("HTTP 401 — HELIUS_API_KEY rejected")
        # v0.18.5 (round-11 chains-CRIT-004): treat 5xx as retryable.
        # Pre-v0.18.5 a transient 503/504 from Helius killed the
        # entire trace branch — only 429 was in the retry list.
        if resp.status_code >= 500:
            raise HeliusRateLimitError(
                f"HTTP {resp.status_code} (transient)"
            )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list) and data:
            return data[0]
        return None

    def get_account_info(self, address: str) -> dict[str, Any]:
        """RPC getAccountInfo — used to determine if an address is a program
        (executable) or a regular wallet. Returns the raw `value` payload
        (or {} if the account doesn't exist)."""
        data = self._rpc_call(
            "getAccountInfo",
            [address, {"encoding": "base64"}],
        )
        result = data.get("result", {}) or {}
        return result.get("value") or {}

    # ---------- Internals ----------

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type((HeliusRateLimitError, httpx.TransportError)),
        reraise=True,
    )
    def _fetch_page(
        self, address: str, *, limit: int, before: str | None
    ) -> list[dict[str, Any]]:
        self.limiter.wait()
        params: dict[str, Any] = {"api-key": self.api_key, "limit": str(limit)}
        if before:
            params["before"] = before
        url = f"{self.BASE}/v0/addresses/{address}/transactions"
        resp = self._client.get(url, params=params)
        if resp.status_code == 429:
            raise HeliusRateLimitError("HTTP 429")
        if resp.status_code == 401:
            raise HeliusError("HTTP 401 — HELIUS_API_KEY rejected")
        # v0.18.5 (round-11 chains-CRIT-004): treat 5xx as retryable.
        # Pre-v0.18.5 a transient 503/504 from Helius killed the
        # entire trace branch — only 429 was in the retry list.
        if resp.status_code >= 500:
            raise HeliusRateLimitError(
                f"HTTP {resp.status_code} (transient)"
            )
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError as e:
            # RIGOR-Jacob Z14: Cloudflare 200 + HTML body. resp.json()
            # raises JSONDecodeError (ValueError) which is NOT in the
            # retry allow-list — would propagate as a raw ValueError
            # and kill the trace branch.
            raise HeliusError(
                f"non-JSON response from Helius (HTML or invalid body): {e}"
            ) from e
        if not isinstance(data, list):
            # Helius returns {"error": "..."} on errors
            msg = data.get("error") if isinstance(data, dict) else str(data)
            raise HeliusError(f"Unexpected Helius response: {msg}")
        return data

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type((HeliusRateLimitError, httpx.TransportError)),
        reraise=True,
    )
    def _rpc_call(self, method: str, params: list[Any] | None = None) -> dict[str, Any]:
        self.limiter.wait()
        # v0.18.5 (round-11 chains-CRIT-002): pre-v0.18.5 the api-key
        # sat in the URL `?api-key=...`. httpx.HTTPStatusError exception
        # messages include the URL, which would have leaked the key
        # into tracebacks. The v0.17.10 secret-redaction patterns
        # catch the `?api-key=` query-param shape in logs (verified by
        # tests/test_logging_redact.py), so logged-and-redacted is the
        # current defense. Leaving the query-param for API compatibility
        # — Helius docs assume this shape. The redaction layer is the
        # belt-and-suspenders that makes it safe.
        url = f"{self.RPC}/?api-key={self.api_key}"
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
        resp = self._client.post(url, json=payload)
        if resp.status_code == 429:
            raise HeliusRateLimitError("HTTP 429")
        if resp.status_code == 401:
            raise HeliusError("HTTP 401 — HELIUS_API_KEY rejected")
        # RIGOR-Jacob Z14: classify 5xx as retryable (mirror parity
        # with _fetch_page). A 502/503/504 from mainnet.helius-rpc.com
        # used to leak as a raw HTTPStatusError and kill the trace.
        if resp.status_code >= 500:
            raise HeliusRateLimitError(
                f"HTTP {resp.status_code} (transient)"
            )
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError as e:
            # Cloudflare 200 + HTML body → surface as HeliusError.
            raise HeliusError(
                f"non-JSON RPC response from Helius (HTML or invalid body): {e}"
            ) from e
        # RIGOR-Jacob R: the RPC endpoint MUST return a dict (JSON-RPC
        # envelope). A list / string / other shape from a misbehaving
        # mirror would crash callers like get_account_info on
        # ``.get("result")`` with AttributeError. Surface as a clean
        # HeliusError instead.
        if not isinstance(data, dict):
            raise HeliusError(
                f"Helius RPC returned non-dict shape: {type(data).__name__}"
            )
        return data
