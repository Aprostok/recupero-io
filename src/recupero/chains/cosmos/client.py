"""Cosmos LCD HTTP client wrapper (v0.32.1+ Cap-C).

Targets the Cosmos LCD (light-client daemon) REST API exposed by
public endpoints (Cosmos Hub: rest.cosmos.network, Osmosis:
lcd.osmosis.zone, Injective: sentry.lcd.injective.network) AND
Mintscan's V1 API as a labeled-frontend alternative.

Why LCD + Mintscan
------------------

LCD endpoints are open, free, and stable — they expose
``/cosmos/tx/v1beta1/txs?events=...`` for tx-by-event queries
(needed for "all transfers TO/FROM address X"). They are slower
and rate-limited but reliable.

Mintscan layers a labeled view on top of LCD data — exchange
deposit addresses are tagged, validators are named — which is
useful for the brief renderer. Where Mintscan is unavailable
(rate-limited, region-blocked), we fall back to raw LCD.

Per-zone endpoint resolution
----------------------------

The zone is inferred from the bech32 prefix of the queried
address — we don't require the caller to thread chain config
explicitly:

  cosmos1... -> Cosmos Hub
  osmo1...   -> Osmosis
  inj1...    -> Injective
  juno1...   -> Juno
  stars1...  -> Stargaze
  axelar1... -> Axelar

Unknown prefixes fall back to a configurable default endpoint
(useful for testing against archive nodes).

Retries
-------

We use a small exponential backoff (3 attempts, 1s -> 2s -> 4s)
on 429 / 5xx responses. Anything else (404, 400) is surfaced
immediately to the caller — those are usually programming bugs,
not transient failures.
"""

from __future__ import annotations

import contextlib
import logging
import time
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Per-zone endpoint registry
# -----------------------------------------------------------------------------
#
# Format: bech32_prefix -> (zone_name, lcd_base_url, mintscan_chain_id)

ZONE_ENDPOINTS: dict[str, tuple[str, str, str]] = {
    "cosmos": (
        "cosmos-hub",
        "https://rest.cosmos.network",
        "cosmos",
    ),
    "osmo": (
        "osmosis",
        "https://lcd.osmosis.zone",
        "osmosis",
    ),
    "inj": (
        "injective",
        "https://sentry.lcd.injective.network",
        "injective",
    ),
    "juno": (
        "juno",
        "https://juno-lcd.publicnode.com",
        "juno",
    ),
    "stars": (
        "stargaze",
        "https://rest.stargaze-apis.com",
        "stargaze",
    ),
    "axelar": (
        "axelar",
        "https://lcd-axelar.imperator.co",
        "axelar",
    ),
    "secret": (
        "secret",
        "https://lcd.secret.express",
        "secret",
    ),
    "kava": (
        "kava-cosmos",
        "https://api.data.kava.io",
        "kava",
    ),
    "celestia": (
        "celestia",
        "https://api.celestia.pops.one",
        "celestia",
    ),
}


# Per-zone base (staking / fee) denom. Used to decide whether a transfer's
# denom is the chain's NATIVE asset. Keyed by bech32 prefix so it resolves
# off the same address-prefix lookup as ZONE_ENDPOINTS.
#
# This is the *only* reliable native-denom signal — length/prefix heuristics
# misclassify legit short micro-denoms (uusdc) and TokenFactory denoms. A
# denom is native iff it EXACTLY equals the zone's base denom here.
ZONE_BASE_DENOM: dict[str, str] = {
    "cosmos": "uatom",
    "osmo": "uosmo",
    "inj": "inj",
    "juno": "ujuno",
    "stars": "ustars",
    "axelar": "uaxl",
    "secret": "uscrt",
    "kava": "ukava",
    "celestia": "utia",
}


def base_denom_for(address: str) -> str | None:
    """Return the native base denom for ``address``'s zone, or None.

    Resolves via the bech32 prefix; returns None for unknown zones so
    the caller can degrade (treat native-detection as best-effort).
    """
    if not isinstance(address, str) or "1" not in address:
        return None
    idx = address.find("1")
    if idx <= 0:
        return None
    return ZONE_BASE_DENOM.get(address[:idx])


@dataclass(frozen=True)
class ZoneInfo:
    """Resolution result for a bech32-prefixed address."""

    prefix: str
    zone: str
    lcd_base_url: str
    mintscan_chain_id: str


def resolve_zone(address: str) -> ZoneInfo | None:
    """Look up the Cosmos zone for an address by bech32 prefix.

    Returns None if the prefix is not in ``ZONE_ENDPOINTS``. The caller
    can fall back to a configured default endpoint in that case.
    """
    if not isinstance(address, str) or "1" not in address:
        return None
    # bech32 separator is '1' — first '1' after prefix.
    idx = address.find("1")
    if idx <= 0:
        return None
    prefix = address[:idx]
    entry = ZONE_ENDPOINTS.get(prefix)
    if entry is None:
        return None
    zone, lcd, mintscan = entry
    return ZoneInfo(prefix=prefix, zone=zone, lcd_base_url=lcd, mintscan_chain_id=mintscan)


# -----------------------------------------------------------------------------
# HTTP client
# -----------------------------------------------------------------------------


def _build_httpx_http_get(client: Any) -> Any:
    """Adapt an ``httpx.Client`` to the ``http_get(url, params, headers) ->
    {"status_code", "json"}`` shape :meth:`CosmosLCDClient.get_json` expects.

    Used by the production ``ChainAdapter.for_chain`` path (a bare
    ``CosmosLCDClient()`` keeps the no-network fallback so unit tests never
    touch the wire). A transport-level failure is mapped to a synthetic ``503``
    so ``get_json``'s existing 5xx backoff retries transient network blips
    rather than letting the exception escape into the tracer; a persistent
    failure surfaces as an ``_error`` dict after the retries, so the adapter
    degrades to "no transfers" instead of crashing the trace.
    """

    def _get(
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            resp = client.get(url, params=params or {}, headers=headers or {})
        except Exception as exc:  # noqa: BLE001 — transport flakiness → retryable
            log.warning("cosmos_lcd_transport_error url=%s: %s", url, exc)
            return {"status_code": 503, "json": {}}
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001 — non-JSON / truncated body
            body = {}
        return {
            "status_code": int(getattr(resp, "status_code", 0)),
            "json": body if isinstance(body, dict) else {},
        }

    return _get


class CosmosLCDClient:
    """Thin HTTP wrapper over Cosmos LCD endpoints.

    Why a class (not a function): we hold the http client (httpx /
    requests) so the adapter doesn't open a new socket per request.
    Matches the EVM / TronGrid / Helius client pattern.

    The client is intentionally **transport-agnostic** — the actual
    HTTP call goes through a swappable callable so tests don't need
    network. By default, the callable is None and a sync ``urllib``
    fallback is used (no external dep). Production wave-7 should
    inject the project-standard ``httpx`` client.
    """

    def __init__(
        self,
        *,
        default_lcd_base_url: str | None = None,
        http_get: Any = None,
        http_client: Any = None,
        max_retries: int = 3,
        initial_backoff_sec: float = 1.0,
    ) -> None:
        self._default_lcd = default_lcd_base_url or "https://rest.cosmos.network"
        # v0.39 (Activation Sprint #5 — for_chain wiring): when a real
        # ``httpx.Client`` is supplied (the production path from
        # ``ChainAdapter.for_chain``) and no explicit ``http_get`` override is
        # given, build the transport callable from it and own it for ``close()``.
        # Tests keep injecting ``http_get`` directly (network-free); a bare
        # ``CosmosLCDClient()`` still uses the no-network fallback so unit tests
        # never touch the wire.
        self._httpx_client = http_client
        if http_get is None and http_client is not None:
            http_get = _build_httpx_http_get(http_client)
        self._http_get = http_get  # callable(url, params, headers) -> {"status_code": int, "json": dict}
        self._max_retries = max_retries
        self._initial_backoff_sec = initial_backoff_sec

    # ----- low-level GET with retry -----

    def get_json(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """GET ``url``, return parsed JSON. Retries on 429/5xx.

        The http_get injected into the constructor is responsible for
        the actual transport. Returning a dict with ``status_code`` and
        ``json`` keeps the wrapper unit-testable without mocking httpx.
        """
        if self._http_get is None:
            return self._urllib_fallback(url, params=params, headers=headers)

        backoff = self._initial_backoff_sec
        for attempt in range(self._max_retries):
            resp = self._http_get(url, params=params or {}, headers=headers or {})
            status = int(resp.get("status_code", 0))
            if 200 <= status < 300:
                body = resp.get("json")
                return body if isinstance(body, dict) else {}
            if status in (429,) or 500 <= status < 600:
                # Transient — backoff + retry.
                if attempt < self._max_retries - 1:
                    log.warning(
                        "cosmos_lcd_retry url=%s status=%s attempt=%s",
                        url, status, attempt + 1,
                    )
                    time.sleep(backoff)
                    backoff *= 2
                    continue
            # Non-retryable; surface as error dict.
            return {
                "_error": f"HTTP {status}",
                "_status_code": status,
            }
        return {"_error": "exhausted retries"}

    def _urllib_fallback(
        self,
        url: str,
        params: dict[str, Any] | None,
        headers: dict[str, str] | None,
    ) -> dict[str, Any]:
        """No-network fallback used by tests; production should inject http_get."""
        log.debug("cosmos_lcd_urllib_fallback url=%s (no real network call)", url)
        return {"_error": "no http_get callable injected", "_test_mode": True}

    # ----- high-level endpoints -----

    def fetch_txs_by_sender(
        self,
        sender_address: str,
        *,
        limit: int = 100,
        offset: int = 0,
        lcd_base_url: str | None = None,
    ) -> dict[str, Any]:
        """List txs where ``sender_address`` is the message.sender.

        Returns the raw LCD response — caller is responsible for
        decoding ``tx_responses`` (a list of TxResponse objects).

        NOTE: this fetches a SINGLE page only. For full-history
        ingestion use :meth:`fetch_all_txs_by_sender`, which paginates
        on ``pagination.next_key`` until exhausted.
        """
        base = lcd_base_url or self._resolve_lcd_for(sender_address)
        url = f"{base.rstrip('/')}/cosmos/tx/v1beta1/txs"
        params = {
            "events": f"message.sender='{sender_address}'",
            "pagination.limit": str(limit),
            "pagination.offset": str(offset),
            "order_by": "ORDER_BY_DESC",
        }
        return self.get_json(url, params=params)

    def fetch_txs_by_recipient(
        self,
        recipient_address: str,
        *,
        limit: int = 100,
        offset: int = 0,
        lcd_base_url: str | None = None,
    ) -> dict[str, Any]:
        """List txs where ``recipient_address`` is a transfer.recipient.

        Single page only. See :meth:`fetch_all_txs_by_recipient` for the
        paginating variant.
        """
        base = lcd_base_url or self._resolve_lcd_for(recipient_address)
        url = f"{base.rstrip('/')}/cosmos/tx/v1beta1/txs"
        params = {
            "events": f"transfer.recipient='{recipient_address}'",
            "pagination.limit": str(limit),
            "pagination.offset": str(offset),
            "order_by": "ORDER_BY_DESC",
        }
        return self.get_json(url, params=params)

    # ----- paginating variants -----

    def fetch_all_txs_by_sender(
        self,
        sender_address: str,
        *,
        limit: int = 100,
        max_pages: int = 50,
        lcd_base_url: str | None = None,
    ) -> dict[str, Any]:
        """Paginate ``fetch_txs_by_sender`` across all LCD pages.

        Loops on ``pagination.next_key`` until exhausted or until a
        safety cap (``max_pages``). Mirrors the Tron/Helius cursor
        paginators' stuck-cursor guard so a buggy or adversarial mirror
        that returns the same ``next_key`` forever cannot burn every
        page slot on duplicate work.

        Returns a synthetic LCD response dict with a merged
        ``tx_responses`` list (and ``txs`` if present), so existing
        callers that read ``tx_responses`` work unchanged.
        """
        return self._fetch_all_txs(
            address=sender_address,
            events=f"message.sender='{sender_address}'",
            limit=limit,
            max_pages=max_pages,
            lcd_base_url=lcd_base_url,
        )

    def fetch_all_txs_by_recipient(
        self,
        recipient_address: str,
        *,
        limit: int = 100,
        max_pages: int = 50,
        lcd_base_url: str | None = None,
    ) -> dict[str, Any]:
        """Paginate ``fetch_txs_by_recipient`` across all LCD pages."""
        return self._fetch_all_txs(
            address=recipient_address,
            events=f"transfer.recipient='{recipient_address}'",
            limit=limit,
            max_pages=max_pages,
            lcd_base_url=lcd_base_url,
        )

    def _fetch_all_txs(
        self,
        *,
        address: str,
        events: str,
        limit: int,
        max_pages: int,
        lcd_base_url: str | None,
    ) -> dict[str, Any]:
        """Shared cursor-paginator for the ``/cosmos/tx/v1beta1/txs`` query.

        Cosmos LCD pagination is key-based: each response carries a
        ``pagination.next_key`` (base64 string) which, when non-null, is
        echoed back as ``pagination.key`` to fetch the next page. We
        thread that through up to ``max_pages`` with a stuck-cursor
        guard. On a mid-pagination error we keep whatever we accumulated
        rather than discarding it (unless page 0 fails, where we surface
        the error so the caller can degrade).
        """
        base = lcd_base_url or self._resolve_lcd_for(address)
        url = f"{base.rstrip('/')}/cosmos/tx/v1beta1/txs"

        merged_tx_responses: list[Any] = []
        merged_txs: list[Any] = []
        next_key: str | None = None
        last_pagination: Any = None
        stuck_count = 0

        for page in range(max_pages):
            params: dict[str, Any] = {
                "events": events,
                "pagination.limit": str(limit),
                "order_by": "ORDER_BY_DESC",
            }
            if next_key:
                # Key-based paging: don't send offset alongside key.
                params["pagination.key"] = next_key
            else:
                params["pagination.offset"] = "0"

            body = self.get_json(url, params=params)
            if not isinstance(body, dict):
                break
            if body.get("_error"):
                # Page 0 failure → surface the error so the caller
                # degrades gracefully. Later pages → keep partial.
                if page == 0:
                    return body
                log.warning(
                    "cosmos_lcd_pagination_stop page=%s error=%s",
                    page, body.get("_error"),
                )
                break

            tx_responses = body.get("tx_responses")
            if isinstance(tx_responses, list):
                merged_tx_responses.extend(tx_responses)
            txs = body.get("txs")
            if isinstance(txs, list):
                merged_txs.extend(txs)

            pagination = body.get("pagination")
            last_pagination = pagination if isinstance(pagination, dict) else None
            new_key = (
                last_pagination.get("next_key") if last_pagination else None
            )
            # next_key is null/empty when there are no more pages.
            if not new_key or not isinstance(new_key, str):
                break
            # Stuck-cursor guard: same key echoed back → not advancing.
            if new_key == next_key:
                stuck_count += 1
                if stuck_count >= 1:
                    log.warning(
                        "cosmos_lcd_pagination_stuck page=%s key=%r; breaking",
                        page, new_key,
                    )
                    break
            else:
                stuck_count = 0
            next_key = new_key
        else:
            log.warning(
                "cosmos_lcd_pagination_max_pages hit max_pages=%s for %s; "
                "results may be truncated",
                max_pages, address,
            )

        return {
            "tx_responses": merged_tx_responses,
            "txs": merged_txs,
            "pagination": last_pagination or {},
        }

    def fetch_balance(
        self,
        address: str,
        *,
        denom: str | None = None,
        lcd_base_url: str | None = None,
    ) -> dict[str, Any]:
        """Get the on-chain balance for ``address``.

        If ``denom`` is provided, returns single-denom; otherwise
        the LCD returns all balances for the address.
        """
        base = lcd_base_url or self._resolve_lcd_for(address)
        if denom:
            url = f"{base.rstrip('/')}/cosmos/bank/v1beta1/balances/{address}/by_denom"
            return self.get_json(url, params={"denom": denom})
        url = f"{base.rstrip('/')}/cosmos/bank/v1beta1/balances/{address}"
        return self.get_json(url)

    def fetch_latest_block(self, *, lcd_base_url: str | None = None) -> dict[str, Any]:
        """Return the chain's tip block info — used by ``block_at_or_before``."""
        base = lcd_base_url or self._default_lcd
        url = f"{base.rstrip('/')}/cosmos/base/tendermint/v1beta1/blocks/latest"
        return self.get_json(url)

    def fetch_block_at_height(
        self,
        height: int,
        *,
        lcd_base_url: str | None = None,
    ) -> dict[str, Any]:
        base = lcd_base_url or self._default_lcd
        url = f"{base.rstrip('/')}/cosmos/base/tendermint/v1beta1/blocks/{int(height)}"
        return self.get_json(url)

    # ----- internal -----

    def _resolve_lcd_for(self, address: str) -> str:
        zi = resolve_zone(address)
        if zi is None:
            return self._default_lcd
        return zi.lcd_base_url

    def close(self) -> None:
        """Close the owned ``httpx.Client`` if one was supplied (the
        ``ChainAdapter.for_chain`` production path). For an injected
        ``http_get`` (tests) or the no-network fallback there is nothing to
        close."""
        client = self._httpx_client
        if client is not None and hasattr(client, "close"):
            with contextlib.suppress(Exception):
                client.close()
        self._httpx_client = None
