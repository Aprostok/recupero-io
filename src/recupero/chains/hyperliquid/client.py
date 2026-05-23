"""Hyperliquid public API client — non-funding ledger updates.

Hyperliquid is a perpetuals DEX, not an EVM chain. There's no "block",
"transaction hash", or "transfer" in the Ethereum sense. What matters for
forensic purposes is the ``userNonFundingLedgerUpdates`` endpoint, which
returns deposits, withdrawals, and other balance-changing events (spot
transfers, cross-margin movements, etc.) per user address.

For the Zigha case specifically: the perpetrator drained positions and
withdrew USDC via Hyperliquid's native bridge to Arbitrum. Those withdrawals
show up here as ``withdraw`` type entries with the destination (always the
Arbitrum address of the same wallet for Hyperliquid's native bridge).

API is POST-only. No auth required for read-only queries. Rate limits are
generous (1200 req/minute). Docs:
https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint

This module is NOT a ChainAdapter because the data model is too different
from the Transfer abstraction. Callers use it to produce case files directly.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

log = logging.getLogger(__name__)


class HyperliquidError(RuntimeError):
    """Non-recoverable Hyperliquid API error."""


class HyperliquidRateLimitError(RuntimeError):
    """HTTP 429. Retryable."""


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


@dataclass(frozen=True)
class HyperliquidLedgerEvent:
    """A single balance-changing event for a user wallet."""
    time_ms: int                  # ms since epoch
    hash: str                     # Hyperliquid-internal event hash
    delta_type: str               # "withdraw", "deposit", "spotTransfer", "accountClassTransfer", etc.
    usdc_delta: Decimal           # signed USDC change (negative for withdrawals)
    destination: str | None       # for withdrawals: the Arbitrum address funds went to
    raw: dict[str, Any]           # original event payload for full fidelity

    @property
    def when(self) -> datetime:
        # Adversarial-hardening: Hyperliquid's API returns the timestamp
        # verbatim — a poisoned / MITM'd response can carry an extreme
        # value (positive or negative) that overflows datetime.fromtimestamp
        # on Windows (OSError) or Linux (OverflowError / ValueError).
        # The scraper uses this property as Transfer.block_time inside
        # a for-loop; one bad event must not poison the whole case build.
        # Fallback to epoch (1970-01-01 UTC) — same convention the rest
        # of the codebase uses for unrecoverable timestamps.
        try:
            return datetime.fromtimestamp(self.time_ms / 1000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return datetime.fromtimestamp(0, tz=UTC)


class HyperliquidClient:
    BASE = "https://api.hyperliquid.xyz"

    def __init__(
        self,
        requests_per_second: float = 10.0,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.limiter = _RateLimiter(requests_per_second)
        self._client = httpx.Client(timeout=timeout_seconds)

    def close(self) -> None:
        self._client.close()

    # ---------- High-level wrappers ----------

    def get_clearinghouse_state(self, user: str) -> dict[str, Any]:
        """Return the perpetual clearinghouse state for ``user``.

        Shape: ``{ "marginSummary": { "accountValue": "...", ... },
                   "withdrawable": "...",
                   "assetPositions": [...], ... }``
        — empty dict on miss / error so callers can default to 0.

        Used by the watch-tick snapshot path to total a Hyperliquid
        account's USD value (perp account equity + cross-margin
        balance). Spot is a separate clearinghouse — call
        ``get_spot_clearinghouse_state`` for that.
        """
        return self._call_info({"type": "clearinghouseState", "user": user})

    def get_spot_clearinghouse_state(self, user: str) -> dict[str, Any]:
        """Return spot balances for ``user``: { "balances": [
        { "coin": "USDC", "total": "...", "hold": "..." }, ...] }."""
        return self._call_info({"type": "spotClearinghouseState", "user": user})

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type((HyperliquidRateLimitError, httpx.TransportError)),
        reraise=True,
    )
    def _call_info(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Generic POST /info wrapper for simple { type, user } queries."""
        self.limiter.wait()
        resp = self._client.post(f"{self.BASE}/info", json=payload)
        if resp.status_code == 429:
            raise HyperliquidRateLimitError("HTTP 429")
        # v0.18.5 (round-11 chains-CRIT-004): 5xx → retryable.
        if resp.status_code >= 500:
            raise HyperliquidRateLimitError(
                f"HTTP {resp.status_code} (transient)"
            )
        resp.raise_for_status()
        try:
            return resp.json() or {}
        except Exception:  # noqa: BLE001
            return {}

    def get_non_funding_ledger_updates(
        self,
        user: str,
        *,
        start_time_ms: int,
        end_time_ms: int | None = None,
    ) -> list[HyperliquidLedgerEvent]:
        """Fetch all non-funding ledger updates for ``user`` since start_time.

        Paginates internally — Hyperliquid returns up to ~500 events per call
        and uses time ranges, so we step forward by extending start_time.
        """
        events: list[HyperliquidLedgerEvent] = []
        seen_hashes: set[str] = set()
        cursor_start = start_time_ms
        page = 0
        while page < 20:  # hard cap to prevent runaway
            page += 1
            batch = self._call_ledger(user, cursor_start, end_time_ms)
            if not batch:
                break
            new_this_page = 0
            for raw in batch:
                evt = _parse_ledger_event(raw)
                if evt is None:
                    continue
                if evt.hash in seen_hashes:
                    continue
                seen_hashes.add(evt.hash)
                events.append(evt)
                new_this_page += 1
            if new_this_page == 0:
                break
            # Advance cursor to the newest timestamp seen, +1 ms to avoid duplicates
            newest_ms = max(evt.time_ms for evt in events)
            next_cursor = newest_ms + 1
            if next_cursor <= cursor_start:
                break
            cursor_start = next_cursor
        # Sort oldest-first for caller convenience
        events.sort(key=lambda e: e.time_ms)
        return events

    # ---------- Internals ----------

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type((HyperliquidRateLimitError, httpx.TransportError)),
        reraise=True,
    )
    def _call_ledger(
        self, user: str, start_time_ms: int, end_time_ms: int | None
    ) -> list[dict[str, Any]]:
        self.limiter.wait()
        payload: dict[str, Any] = {
            "type": "userNonFundingLedgerUpdates",
            "user": user,
            "startTime": start_time_ms,
        }
        if end_time_ms is not None:
            payload["endTime"] = end_time_ms
        resp = self._client.post(f"{self.BASE}/info", json=payload)
        if resp.status_code == 429:
            raise HyperliquidRateLimitError("HTTP 429")
        # v0.18.5 (round-11 chains-CRIT-004): 5xx → retryable.
        if resp.status_code >= 500:
            raise HyperliquidRateLimitError(
                f"HTTP {resp.status_code} (transient)"
            )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            raise HyperliquidError(f"Unexpected Hyperliquid response: {data}")
        return data


def _parse_ledger_event(raw: dict[str, Any]) -> HyperliquidLedgerEvent | None:
    """Parse one Hyperliquid ledger item. Returns None for malformed entries."""
    try:
        time_ms = int(raw["time"])
        event_hash = str(raw.get("hash") or raw.get("Id") or f"synthetic-{time_ms}")
        delta = raw.get("delta") or {}
        delta_type = str(delta.get("type", "unknown"))
        usdc_value = delta.get("usdc") or "0"
        try:
            usdc_delta = Decimal(str(usdc_value))
        except Exception:  # noqa: BLE001
            usdc_delta = Decimal("0")
        # Adversarial-hardening: Decimal("NaN") and Decimal("Infinity")
        # are LEGAL Decimal values that don't raise on construction but
        # blow up downstream (int(NaN * 10**6) → ValueError,
        # int(Infinity * 10**6) → OverflowError, NaN < 0 →
        # InvalidOperation under default contexts). Coerce non-finite
        # values to 0 so the event is treated as a no-op rather than
        # crashing the case build.
        if not usdc_delta.is_finite():
            usdc_delta = Decimal("0")
        destination = delta.get("destination") or delta.get("to") or None
        return HyperliquidLedgerEvent(
            time_ms=time_ms,
            hash=event_hash,
            delta_type=delta_type,
            usdc_delta=usdc_delta,
            destination=destination,
            raw=raw,
        )
    except (KeyError, ValueError, TypeError) as e:
        log.debug("skipping malformed Hyperliquid event: %s (%s)", raw, e)
        return None
