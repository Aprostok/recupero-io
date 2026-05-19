"""Thin Esplora REST client for Bitcoin (v0.13.0).

Esplora (https://github.com/Blockstream/esplora) is Blockstream's
open-source block explorer backend. Two hosted instances expose
the same API:

  * https://blockstream.info/api (Blockstream-run, free, no key)
  * https://mempool.space/api    (mempool.space, free, no key)

We default to mempool.space — comparable uptime, faster mainnet
node, more aggressive caching. The client supports swapping the
base URL so cases that need redundancy can fail over.

Endpoints we wrap
-----------------

  GET /address/{address}/txs
    Confirmed transaction history for an address. Returns up to
    50 txs at a time, sorted newest-first. Pagination is "last
    seen txid" cursor-style.

  GET /address/{address}/txs/chain/{last_seen_txid}
    Next page after ``last_seen_txid``. Used for pagination.

  GET /tx/{txid}
    Full transaction with all inputs (``vin``) and outputs
    (``vout``), each input including the prev-tx value + script
    (so we know what address signed it).

  GET /block-height/{height}
    Block hash at a given height; used for timestamp anchoring.

  GET /blocks/tip/height
    Current chain tip height (for "trace up to now" windows).

Rate limiting: blockstream.info / mempool.space are tolerant of
~10 req/s but ramp up quickly to 429 above that. We default to
8 rps and use tenacity exponential backoff on 429/5xx.

Reference docs:
  https://github.com/Blockstream/esplora/blob/master/API.md
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


# Public Esplora endpoints. mempool.space is the primary; Blockstream
# is the fallback that callers can swap to if mempool.space throttles.
ESPLORA_MEMPOOL_SPACE = "https://mempool.space/api"
ESPLORA_BLOCKSTREAM = "https://blockstream.info/api"


class EsploraError(RuntimeError):
    """Non-recoverable Esplora error (bad address, auth failure)."""


class EsploraRateLimitError(RuntimeError):
    """HTTP 429 or rate-limit-style response. Retryable."""


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


class EsploraClient:
    """Synchronous Esplora REST client."""

    def __init__(
        self,
        base_url: str = ESPLORA_MEMPOOL_SPACE,
        requests_per_second: float = 8.0,
        timeout_seconds: float = 30.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.limiter = _RateLimiter(requests_per_second)
        self._client = http_client or httpx.Client(timeout=timeout_seconds)
        self._owns_client = http_client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> EsploraClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ---------- High-level wrappers ---------- #

    def get_address_txs(
        self,
        address: str,
        *,
        max_pages: int = 50,
    ) -> list[dict[str, Any]]:
        """Paginated confirmed transaction history for ``address``.

        Esplora returns up to 50 txs per page; we paginate via the
        ``last_seen_txid`` cursor up to ``max_pages`` (default 50 →
        2500 txs, generous for any forensic case).

        Returns the flat list of parsed transaction objects (each
        a dict with ``txid``, ``vin``, ``vout``, ``status``,
        ``fee``, etc.).
        """
        out: list[dict[str, Any]] = []
        last_seen: str | None = None
        for page in range(max_pages):
            path = f"/address/{address}/txs"
            if last_seen:
                path = f"/address/{address}/txs/chain/{last_seen}"
            batch = self._get(path)
            if not isinstance(batch, list):
                log.warning(
                    "esplora address/txs: unexpected non-list response "
                    "(got %r); stopping pagination",
                    type(batch).__name__,
                )
                break
            if not batch:
                break
            out.extend(batch)
            last_seen = batch[-1].get("txid") if batch else None
            if not last_seen:
                break
            # Esplora pagination stops naturally when a page has <25
            # results, but we don't have a documented hard rule —
            # check by length to avoid infinite loop on a misbehaving
            # mirror.
            if len(batch) < 25:
                break
        else:
            log.warning(
                "esplora address/txs: hit max_pages=%d for %s; results "
                "may be truncated",
                max_pages, address,
            )
        return out

    def get_transaction(self, txid: str) -> dict[str, Any]:
        """Fetch one transaction by id. Returns the full dict with
        ``vin`` (inputs, each with ``prevout`` showing the spent
        UTXO's value + script + address) and ``vout`` (outputs).
        """
        return self._get(f"/tx/{txid}")

    def get_tip_height(self) -> int:
        """Current chain tip block height."""
        body = self._get("/blocks/tip/height")
        if isinstance(body, int):
            return body
        if isinstance(body, str):
            try:
                return int(body)
            except ValueError as e:
                raise EsploraError(
                    f"tip height response not parseable as int: {body!r}"
                ) from e
        raise EsploraError(f"tip height response wrong type: {type(body).__name__}")

    def get_block_at_height(self, height: int) -> dict[str, Any]:
        """Block hash at a given height. Used for timestamp anchoring."""
        return self._get(f"/block-height/{height}")

    # ---------- Low-level GET ---------- #

    @retry(
        retry=retry_if_exception_type(EsploraRateLimitError),
        wait=wait_exponential(multiplier=1.0, min=1, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _get(self, path: str) -> Any:
        """Internal GET with rate limiting + retry on 429/5xx."""
        self.limiter.wait()
        url = f"{self.base_url}{path}"
        try:
            resp = self._client.get(url)
        except httpx.RequestError as e:
            # v0.18.5 (round-11 chains-CRIT-005): network errors → retryable.
            raise EsploraRateLimitError(f"network error: {e}") from e
        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After", "(none)")
            log.info("esplora 429 rate limit; retry-after=%s", ra)
            raise EsploraRateLimitError(
                f"HTTP 429 for {url} (retry-after={ra})"
            )
        if resp.status_code >= 500:
            raise EsploraRateLimitError(
                f"HTTP {resp.status_code} for {url}: {resp.text[:200]!r}"
            )
        if resp.status_code == 404:
            raise EsploraError(f"HTTP 404 for {url} (not found)")
        if resp.status_code != 200:
            raise EsploraError(
                f"HTTP {resp.status_code} for {url}: {resp.text[:500]!r}"
            )
        # Esplora returns JSON for most endpoints but plain text /
        # integers for a few (e.g. /blocks/tip/height returns a bare
        # int as text). Try JSON first, fall back to text.
        try:
            return resp.json()
        except ValueError:
            return resp.text.strip()


__all__ = (
    "EsploraError",
    "EsploraRateLimitError",
    "EsploraClient",
    "ESPLORA_MEMPOOL_SPACE",
    "ESPLORA_BLOCKSTREAM",
)
