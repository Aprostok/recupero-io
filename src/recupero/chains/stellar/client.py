"""Horizon API client (https://horizon.stellar.org).

Public, no-auth Stellar API. Used:
  * GET /accounts/{id}/payments — payment operations (native + issued-asset),
    each with type / from / to / amount / asset_type / asset_code / asset_issuer
    / created_at / transaction_hash. Cursor-paginated (``order=desc``).
  * GET /accounts/{id} — account state (balances, existence).

Shapes captured live before implementation. Best-effort transport: a non-2xx or
malformed body raises HorizonError; the adapter degrades gracefully.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

_HORIZON_HOST = "horizon.stellar.org"
HORIZON_BASE = f"https://{_HORIZON_HOST}"


class HorizonError(RuntimeError):
    """Raised on a non-2xx / malformed Horizon response."""


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


class HorizonClient:
    """Thin Stellar Horizon client (payments + account state)."""

    def __init__(
        self,
        base_url: str = HORIZON_BASE,
        *,
        requests_per_second: float = 5.0,
        timeout_seconds: float = 20.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.limiter = _RateLimiter(requests_per_second)
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(connect=10.0, read=timeout_seconds,
                                  write=timeout_seconds, pool=timeout_seconds)
        )
        self._owns_client = http_client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HorizonClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def get_account(self, account: str) -> dict[str, Any]:
        """Account state ({balances, ...}). Returns {} on a 404 (never funded)."""
        body = self._get(f"/accounts/{account}", {})
        return body if isinstance(body, dict) else {}

    def get_payments(
        self, account: str, *, limit: int = 100, cursor: str | None = None,
    ) -> list[dict[str, Any]]:
        """Payment operations for ``account``, newest first. Returns the
        ``_embedded.records`` list."""
        params: dict[str, Any] = {"limit": limit, "order": "desc"}
        if cursor:
            params["cursor"] = cursor
        body = self._get(f"/accounts/{account}/payments", params)
        if not isinstance(body, dict):
            return []
        recs = body.get("_embedded", {}).get("records")
        return recs if isinstance(recs, list) else []

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        self.limiter.wait()
        url = f"{self.base_url}{path}"
        if httpx.URL(url).host != _HORIZON_HOST:
            raise HorizonError(f"refusing non-Horizon host in {url!r}")
        try:
            resp = self._client.get(url, params=params, follow_redirects=False)
        except httpx.RequestError as exc:
            raise HorizonError(f"Horizon request failed: {exc}") from exc
        if resp.status_code == 404:
            return {}
        if resp.status_code != 200:
            raise HorizonError(
                f"Horizon {path} returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            body = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise HorizonError(f"Horizon {path} returned non-JSON") from exc
        return body if isinstance(body, dict) else {}
