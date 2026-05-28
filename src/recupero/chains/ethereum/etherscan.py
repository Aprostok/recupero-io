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
        # Reserve a slot under the lock, sleep without it. The previous
        # version held `self._lock` across `time.sleep()`, which serialized
        # every concurrent caller end-to-end instead of letting them queue
        # reservations in parallel — under contention the effective rps
        # collapsed to 1/(sum of all callers' waits) instead of the
        # configured rate.
        with self._lock:
            now = time.monotonic()
            target = max(self._next_allowed, now)
            self._next_allowed = target + self.min_interval
        delay = target - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class EtherscanClient:
    """Synchronous Etherscan v2 client."""

    def __init__(
        self,
        api_key: str,
        api_base: str = "https://api.etherscan.io/v2/api",
        chain_id: int = 1,
        requests_per_second: float = 4.0,
        # Default 60s (was 30s). Etherscan v2 occasionally takes 30-45s to
        # respond on whale wallets / busy endpoints. A single slow response
        # shouldn't kill an in-progress depth-3 trace; the BFS catch-and-
        # continue handles retries, but raising the per-call ceiling here
        # means most slow calls succeed instead of needing retry.
        timeout_seconds: float = 60.0,
        # v0.32 — per-case API budget tracker. When provided, the
        # client calls ``budget.record("etherscan")`` after every
        # successful HTTP response. A budget=None or budget.enabled
        # == False makes this a no-op; the tracer constructs one
        # CaseBudget per case and passes it through to every adapter.
        budget: object | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("ETHERSCAN_API_KEY is required")
        self.api_key = api_key
        self.api_base = api_base
        self.chain_id = chain_id
        self.limiter = _RateLimiter(requests_per_second)
        self.budget = budget
        # Split connect/read timeouts: a slow-DNS host must not block the
        # worker for the full read window (60s). Connect cap = 10s — any
        # public Etherscan endpoint resolves + handshakes well under that.
        # Read uses `timeout_seconds` so whale-wallet queries still get
        # their full per-call window.
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

    def get_block_number_by_time(self, ts_unix: int, closest: str = "before") -> int:
        """Module=block, action=getblocknobytime.

        Etherscan returns ``"Error! No closest block found"`` (as the
        ``result`` string) for timestamps before the chain's first
        block — closest=before has no answer in that case. We clamp
        to block 1 instead of raising, which matches the
        semantically-correct interpretation: "give me the earliest
        block you have" should return the earliest block, not crash.

        This was the empirical failure mode on wallet-trace runs
        when ``incident_time`` defaults to the chain-genesis
        timestamp. The trace was emitting "trace hop failed:
        invalid literal for int()" and returning 0 transfers — a
        misleading "found nothing" result on wallets that actually
        had activity. Clamping to block 1 lets the txlist call below
        actually return the wallet's history.
        """
        data = self._call(
            module="block",
            action="getblocknobytime",
            timestamp=str(ts_unix),
            closest=closest,
        )
        result = data.get("result")
        if isinstance(result, str) and "no closest block" in result.lower():
            # Pre-genesis timestamp. Clamp to block 1 (block 0 has a
            # null timestamp on Ethereum mainnet — not a real block).
            #
            # v0.16.10 (round-9 output LOW): log a WARNING so operators
            # who pass an obviously-misconfigured incident time (e.g.,
            # a 2009 timestamp on a 2023 chain — usually a bad CSV
            # import) see a smoking gun rather than "trace returned 0
            # transfers" with no diagnostic.
            log.warning(
                "etherscan getblocknobytime: ts=%d predates chain genesis on "
                "chain_id=%d — clamping to block 1. If unexpected, check the "
                "incident_time on the investigation row.",
                ts_unix, self.chain_id,
            )
            return 1
        # v0.16.10: future-timestamp guard. A malformed Etherscan response
        # (or a forged-upstream RPC) returning a wildly future block
        # number would silently land in the case file. Cap to a sane
        # bound — anything above 1B is a tampered response (Ethereum is
        # at ~22M, BSC ~50M as of 2026).
        try:
            block_num = int(result)
        except (TypeError, ValueError) as e:
            raise EtherscanError(
                f"getblocknobytime returned non-integer result: {result!r}"
            ) from e
        if block_num < 0 or block_num > 1_000_000_000:
            raise EtherscanError(
                f"getblocknobytime returned implausible block_num={block_num} "
                f"for ts={ts_unix} chain_id={self.chain_id}"
            )
        return block_num

    def get_eth_balance(self, address: str, tag: str = "latest") -> int:
        data = self._call(module="account", action="balance", address=address, tag=tag)
        return int(data["result"])

    def get_token_balance(self, contract: str, address: str, tag: str = "latest") -> int:
        """Current ERC-20 balance of `address` for token at `contract`. Returns
        the raw integer amount (decimal-aware conversion is the caller's job)."""
        data = self._call(
            module="account",
            action="tokenbalance",
            contractaddress=contract,
            address=address,
            tag=tag,
        )
        try:
            return int(data["result"])
        except (KeyError, ValueError, TypeError):
            return 0

    # Etherscan v2 caps every account-action query at page*offset <= 10_000.
    # With offset=1000 that gives us up to 10 pages before the API itself
    # rejects further paging. Anything beyond that requires re-querying with
    # a narrower block window (which the caller can do by walking start_block
    # forward to the last seen block + 1).
    _ETHERSCAN_MAX_PAGES = 10
    _ETHERSCAN_PAGE_SIZE_CAP = 10_000  # max page*offset Etherscan accepts

    def _paginate_account_action(
        self,
        *,
        action: str,
        address: str,
        start_block: int,
        end_block: int,
        page: int,
        offset: int,
        max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Drives page=1..N pagination for account txlist-style actions.

        Pre-v0.16.6 this client called Etherscan with `page=1, offset=1000`
        and stopped — silently truncating any wallet with >1000 hits of a
        given transfer type. Consolidation hubs in V-CFI01-shape cases
        routinely have thousands of historical inflows; truncation meant
        the historical-inflow synthesizer would generate freeze asks
        against only the most recent slice of victims, missing the bulk
        of the recoverable amount.

        Single-page mode is preserved when callers explicitly pass page>1
        (they're driving pagination themselves) — that path is used by
        the inspector's incremental scan and a few tests with mocks.

        Returns all rows aggregated across pages. Logs a warning if the
        last page filled completely AND we've hit `_ETHERSCAN_MAX_PAGES`,
        which means the wallet has more rows than Etherscan will return
        for this block window — caller should narrow the window.
        """
        # If caller wants a specific single page, honor it (back-compat).
        if page != 1:
            data = self._call(
                module="account",
                action=action,
                address=address,
                startblock=str(start_block),
                endblock=str(end_block),
                page=str(page),
                offset=str(offset),
                sort="asc",
            )
            return self._coerce_list(data)

        all_rows: list[dict[str, Any]] = []
        cur_page = 1
        while cur_page <= self._ETHERSCAN_MAX_PAGES:
            # Stay under Etherscan's hard cap on page*offset.
            if cur_page * offset > self._ETHERSCAN_PAGE_SIZE_CAP:
                break
            data = self._call(
                module="account",
                action=action,
                address=address,
                startblock=str(start_block),
                endblock=str(end_block),
                page=str(cur_page),
                offset=str(offset),
                sort="asc",
            )
            rows = self._coerce_list(data)
            if not rows:
                break
            all_rows.extend(rows)
            # RIGOR-Jacob A: short-circuit pagination once max_results
            # is satisfied. Pre-fix the loop walked the full address
            # history; for exchange hot wallets (1M+ tx) this meant
            # ~1k API calls per BFS node before the post-fetch slice
            # threw the data away. Cap is opt-in (default None = walk
            # to natural end-of-data).
            if max_results is not None and len(all_rows) >= max_results:
                break
            # If the page wasn't full, we've reached the end.
            if len(rows) < offset:
                break
            cur_page += 1
        else:
            # `while...else` runs when the loop exited via the condition
            # (not via break). That means we made MAX_PAGES requests and
            # the last one was full — meaning more data exists.
            log.warning(
                "etherscan pagination capped at %d pages for %s action=%s "
                "addr=%s start_block=%d — wallet has >%d rows in window; "
                "caller should re-query with narrower block range",
                self._ETHERSCAN_MAX_PAGES, "txlist", action, address,
                start_block, self._ETHERSCAN_MAX_PAGES * offset,
            )
        return all_rows

    def get_normal_transactions(
        self, address: str, start_block: int, end_block: int = 99_999_999,
        page: int = 1, offset: int = 1000,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Module=account, action=txlist. Returns native-ETH transactions involving address.

        Auto-paginates to up to 10 pages (the Etherscan cap) when called with
        the default page=1. Pass page>1 for manual single-page paging.

        ``max_results`` (RIGOR-Jacob A): short-circuit pagination
        once that many rows are collected. Default None = walk to
        natural end-of-data.
        """
        return self._paginate_account_action(
            action="txlist",
            address=address,
            start_block=start_block,
            end_block=end_block,
            page=page,
            offset=offset,
            max_results=max_results,
        )

    def get_internal_transactions(
        self, address: str, start_block: int, end_block: int = 99_999_999,
        page: int = 1, offset: int = 1000,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Module=account, action=txlistinternal. Catches contract-mediated value moves."""
        return self._paginate_account_action(
            action="txlistinternal",
            address=address,
            start_block=start_block,
            end_block=end_block,
            page=page,
            offset=offset,
            max_results=max_results,
        )

    def get_erc20_transfers(
        self, address: str, start_block: int, end_block: int = 99_999_999,
        page: int = 1, offset: int = 1000,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Module=account, action=tokentx."""
        return self._paginate_account_action(
            action="tokentx",
            address=address,
            start_block=start_block,
            end_block=end_block,
            page=page,
            offset=offset,
            max_results=max_results,
        )

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
        # v0.32 — per-case API budget. Record BEFORE shape / status
        # checks so rate-limited retries also count. getattr-with-default
        # defends against tests that construct the client via __new__()
        # (see ``test_etherscan_response_shape``).
        _b = getattr(self, "budget", None)
        if _b is not None:
            _b.record("etherscan")
        if resp.status_code == 429:
            raise EtherscanRateLimitError("HTTP 429")
        # v0.18.5 (round-11 chains-CRIT-004): 5xx → retryable. A
        # transient 503 from Etherscan (deploy, edge restart) would
        # otherwise kill the trace branch.
        if resp.status_code >= 500:
            raise EtherscanRateLimitError(
                f"HTTP {resp.status_code} (transient)"
            )
        resp.raise_for_status()
        data = resp.json()

        # Etherscan returns 200 with a JSON-encoded error sometimes.
        # Status "1" = OK, "0" = error. But "no records found" is also "0" — handle that.
        if isinstance(data, dict) and data.get("status") == "0":
            msg = str(data.get("message", "")).lower()
            result = data.get("result", "")
            result_lower = str(result).lower()
            if "no transactions found" in msg or "no records found" in msg:
                return {"status": "1", "message": "OK", "result": []}
            # Etherscan returns rate-limit notices in different shapes depending
            # on which endpoint and tier. Patterns observed in production:
            #   "Max rate limit reached"
            #   "Max calls per sec rate limit reached (3/sec)"
            #   "rate limit"  (BSC/Arbitrum variants)
            # Match permissively on the substring "rate limit" in either field.
            if "rate limit" in msg or "rate limit" in result_lower:
                raise EtherscanRateLimitError(str(result) or msg)
            raise EtherscanError(f"Etherscan error: {data.get('message')} / {data.get('result')}")
        return data

    @staticmethod
    def _coerce_list(data: Any) -> list[dict[str, Any]]:
        """Extract a row list from a (possibly malformed) Etherscan body.

        RIGOR-Jacob U: pre-fix this signature took ``dict`` and called
        ``data.get("result", [])`` unconditionally — a non-dict input
        (Cloudflare HTML string, JSON array, None) raised
        AttributeError into the adapter and killed the BFS hop. Now
        we accept Any and fall back to [] on anything not dict-shaped.
        """
        if not isinstance(data, dict):
            return []
        result = data.get("result", [])
        if isinstance(result, list):
            return result
        return []
