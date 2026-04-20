"""Thin client over Etherscan API v2 (multichain).

Etherscan v2 uses a single endpoint with a `chainid` parameter. Free tier:
5 req/sec, 100k req/day. We rate-limit ourselves to 4 req/sec to leave headroom.

This client is intentionally thin — it returns parsed JSON (dicts) and lets
the EthereumAdapter normalize into our internal shape. That separation makes
it trivial to swap in Alchemy or a self-hosted node later.

Reference: https://docs.etherscan.io/etherscan-v2/getting-started/v2-quickstart
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


class EtherscanError(RuntimeError):
    """Raised for non-recoverable Etherscan responses (bad input, banned key, etc.)."""


class EtherscanRateLimitError(RuntimeError):
    """Raised on HTTP 429 or 'Max rate limit reached'. Retryable."""


class _RateLimiter:
    """Token-bucket-ish; simple and good enough for single-process Phase 1."""

    def __init__(self, rps: float) -> None:
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next_allowed - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.monotonic()
            self._next_allowed = now + self.min_interval


class EtherscanClient:
    """Synchronous Etherscan v2 client."""

    def __init__(
        self,
        api_key: str,
        api_base: str = "https://api.etherscan.io/v2/api",
        chain_id: int = 1,
        requests_per_second: float = 4.0,
        timeout_seconds: float = 30.0,
    ) -> None:
        if not api_key:
            raise ValueError("ETHERSCAN_API_KEY is required")
        self.api_key = api_key
        self.api_base = api_base
        self.chain_id = chain_id
        self.limiter = _RateLimiter(requests_per_second)
        self._client = httpx.Client(timeout=timeout_seconds)

    def close(self) -> None:
        self._client.close()

    # ---------- High-level wrappers ----------

    def get_block_number_by_time(self, ts_unix: int, closest: str = "before") -> int:
        """Module=block, action=getblocknobytime."""
        data = self._call(
            module="block",
            action="getblocknobytime",
            timestamp=str(ts_unix),
            closest=closest,
        )
        return int(data["result"])

    def get_eth_balance(self, address: str, tag: str = "latest") -> int:
        data = self._call(module="account", action="balance", address=address, tag=tag)
        return int(data["result"])

    def get_normal_transactions(
        self, address: str, start_block: int, end_block: int = 99_999_999, page: int = 1, offset: int = 1000
    ) -> list[dict[str, Any]]:
        """Module=account, action=txlist. Returns native-ETH transactions involving address."""
        data = self._call(
            module="account",
            action="txlist",
            address=address,
            startblock=str(start_block),
            endblock=str(end_block),
            page=str(page),
            offset=str(offset),
            sort="asc",
        )
        return self._coerce_list(data)

    def get_internal_transactions(
        self, address: str, start_block: int, end_block: int = 99_999_999, page: int = 1, offset: int = 1000
    ) -> list[dict[str, Any]]:
        """Module=account, action=txlistinternal. Catches contract-mediated value moves."""
        data = self._call(
            module="account",
            action="txlistinternal",
            address=address,
            startblock=str(start_block),
            endblock=str(end_block),
            page=str(page),
            offset=str(offset),
            sort="asc",
        )
        return self._coerce_list(data)

    def get_erc20_transfers(
        self, address: str, start_block: int, end_block: int = 99_999_999, page: int = 1, offset: int = 1000
    ) -> list[dict[str, Any]]:
        """Module=account, action=tokentx."""
        data = self._call(
            module="account",
            action="tokentx",
            address=address,
            startblock=str(start_block),
            endblock=str(end_block),
            page=str(page),
            offset=str(offset),
            sort="asc",
        )
        return self._coerce_list(data)

    def get_transaction_by_hash(self, tx_hash: str) -> dict[str, Any]:
        data = self._call(module="proxy", action="eth_getTransactionByHash", txhash=tx_hash)
        return data.get("result") or {}

    def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any]:
        data = self._call(module="proxy", action="eth_getTransactionReceipt", txhash=tx_hash)
        return data.get("result") or {}

    def get_block_by_number(self, block_number: int, full_tx: bool = False) -> dict[str, Any]:
        data = self._call(
            module="proxy",
            action="eth_getBlockByNumber",
            tag=hex(block_number),
            boolean="true" if full_tx else "false",
        )
        return data.get("result") or {}

    def get_contract_source(self, address: str) -> dict[str, Any]:
        """Returns contract metadata. Empty result for EOAs.
        Use to determine is_contract: if 'ContractName' is empty, treat as EOA.
        """
        data = self._call(module="contract", action="getsourcecode", address=address)
        result = data.get("result")
        if isinstance(result, list) and result:
            return result[0]
        return {}

    # ---------- Internal HTTP plumbing ----------

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=1, max=32),
        retry=retry_if_exception_type((EtherscanRateLimitError, httpx.TransportError)),
        reraise=True,
    )
    def _call(self, **params: str) -> dict[str, Any]:
        params = {**params, "apikey": self.api_key, "chainid": str(self.chain_id)}
        self.limiter.wait()
        log.debug("etherscan call", extra={"params": {k: v for k, v in params.items() if k != "apikey"}})
        resp = self._client.get(self.api_base, params=params)
        if resp.status_code == 429:
            raise EtherscanRateLimitError("HTTP 429")
        resp.raise_for_status()
        data = resp.json()

        # Etherscan returns 200 with a JSON-encoded error sometimes.
        # Status "1" = OK, "0" = error. But "no records found" is also "0" — handle that.
        if isinstance(data, dict) and data.get("status") == "0":
            msg = str(data.get("message", "")).lower()
            result = data.get("result", "")
            if "no transactions found" in msg or "no records found" in msg:
                return {"status": "1", "message": "OK", "result": []}
            if "rate limit" in str(result).lower() or "rate limit" in msg:
                raise EtherscanRateLimitError(str(result) or msg)
            raise EtherscanError(f"Etherscan error: {data.get('message')} / {data.get('result')}")
        return data

    @staticmethod
    def _coerce_list(data: dict[str, Any]) -> list[dict[str, Any]]:
        result = data.get("result", [])
        if isinstance(result, list):
            return result
        return []
