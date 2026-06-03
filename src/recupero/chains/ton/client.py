"""TON Center API client (https://toncenter.com).

Two API surfaces are used:
  * v2 ``/api/v2/getAddressInformation`` — account balance + state (is_contract).
  * v2 ``/api/v2/getTransactions``       — native-TON transaction history. Each
    tx carries ``utime`` (unix s), ``transaction_id.{lt,hash}``, ``in_msg`` and
    ``out_msgs[]`` (each msg: ``source`` / ``destination`` / ``value`` in
    nanoton, 9 decimals).
  * v3 ``/api/v3/jetton/transfers``      — DECODED Jetton transfers (USDT-TON
    etc.): ``source`` / ``destination`` / ``amount`` (raw, jetton decimals) /
    ``jetton_master`` / ``transaction_hash`` / ``transaction_now`` (unix s),
    all as raw ``0:hex`` addresses. Avoids hand-parsing TON cells.

No auth required on the free tier; ``TONCENTER_API_KEY`` (env) raises the rate
limit when set. Shapes captured live before implementation.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

TONCENTER_BASE = "https://toncenter.com"


class TonCenterError(RuntimeError):
    """Raised on a non-2xx / malformed TON Center response."""


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


class TonCenterClient:
    """Thin TON Center v2 + v3 client."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = TONCENTER_BASE,
        *,
        requests_per_second: float = 1.0,
        timeout_seconds: float = 20.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        # TON Center's free tier is ~1 rps; an API key lifts it. Default
        # conservative so an un-keyed deploy doesn't get hard-throttled.
        self.api_key = api_key or os.environ.get("TONCENTER_API_KEY", "") or ""
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

    def __enter__(self) -> TonCenterClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ----- v2 ----- #

    def get_address_information(self, address: str) -> dict[str, Any]:
        """Account state: balance (nanoton), code/state, last tx. Used for
        balance + is_contract."""
        body = self._get("/api/v2/getAddressInformation", {"address": address})
        result = body.get("result")
        return result if isinstance(result, dict) else {}

    def get_transactions(
        self, address: str, *, limit: int = 100, to_lt: int | None = None,
    ) -> list[dict[str, Any]]:
        """Native-TON transaction history (most-recent first). ``to_lt`` bounds
        pagination by logical time."""
        params: dict[str, Any] = {"address": address, "limit": limit}
        if to_lt is not None:
            params["to_lt"] = to_lt
        body = self._get("/api/v2/getTransactions", params)
        result = body.get("result")
        return result if isinstance(result, list) else []

    # ----- v3 ----- #

    def get_jetton_transfers(
        self, *, owner_address: str, limit: int = 100, offset: int = 0,
    ) -> dict[str, Any]:
        """Decoded Jetton transfers where ``owner_address`` is a party. Returns
        the raw v3 body (``jetton_transfers`` list + ``address_book``)."""
        params = {"owner_address": owner_address, "limit": limit, "offset": offset}
        return self._get("/api/v3/jetton/transfers", params)

    # ----- transport ----- #

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        self.limiter.wait()
        headers = {"X-API-Key": self.api_key} if self.api_key else {}
        url = f"{self.base_url}{path}"
        try:
            resp = self._client.get(url, params=params, headers=headers)
        except httpx.RequestError as exc:
            raise TonCenterError(f"TON Center request failed: {exc}") from exc
        if resp.status_code != 200:
            raise TonCenterError(
                f"TON Center {path} returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            body = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise TonCenterError(f"TON Center {path} returned non-JSON") from exc
        # v2 wraps payloads in {ok, result}; v3 returns the object directly.
        if isinstance(body, dict) and body.get("ok") is False:
            raise TonCenterError(f"TON Center {path} ok=false: {body.get('error')}")
        return body if isinstance(body, dict) else {}
