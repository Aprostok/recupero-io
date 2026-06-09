"""Dual-backend client: prefer Alchemy, fall back to Etherscan.

RIGOR-Jacob B: When the operator passes the ``--prefer-alchemy`` CLI flag
(there is NO env-var equivalent; the control is the ``prefer_alchemy``
constructor arg), the adapter uses this wrapper instead
of the raw EtherscanClient. The wrapper routes account-transfer
queries through Alchemy (higher quota, better pagination semantics
on chatty wallets, consistent behavior across high-block-rate chains
like Arbitrum/Polygon/Base).

Methods that Alchemy doesn't cover (block-by-timestamp,
contract source lookup, raw tx receipts) transparently fall back to
the Etherscan client.

Automatic fallback on failure: if Alchemy raises
AlchemyRateLimitError mid-pagination, the wrapper retries the SAME
call against Etherscan. We log the fallback so an operator can see
when their preferred backend is unhealthy.

Why "wrapper" instead of "EVM adapter takes both clients": the
EvmAdapter is already complex; this isolates the dual-backend
decision in one place and the rest of the adapter is unchanged.
"""

from __future__ import annotations

import logging
from typing import Any

from recupero.chains.ethereum.etherscan import EtherscanClient
from recupero.chains.evm.alchemy_client import (
    _CHAIN_ID_TO_ALCHEMY_PREFIX,
    AlchemyClient,
    AlchemyError,
    AlchemyRateLimitError,
)

log = logging.getLogger(__name__)


class DualBackendClient:
    """Etherscan-shape client that prefers Alchemy.

    Behavior:
      * Address transfer queries (``get_normal_transactions``,
        ``get_internal_transactions``, ``get_erc20_transfers``)
        → tried against Alchemy first, fall back to Etherscan on
          failure.
      * Everything else → Etherscan directly.

    Holds both backend clients so close() releases both.
    """

    def __init__(
        self,
        etherscan: EtherscanClient,
        alchemy: AlchemyClient | None,
    ) -> None:
        # ``alchemy`` may be None: when the operator's chain isn't
        # supported by Alchemy or the key is missing, we silently fall
        # through to Etherscan-only semantics.
        self.etherscan = etherscan
        self.alchemy = alchemy

    @classmethod
    def build(
        cls,
        *,
        etherscan_api_key: str,
        etherscan_api_base: str,
        chain_id: int,
        alchemy_api_key: str,
        requests_per_second: float = 4.0,
        timeout_seconds: float = 60.0,
        prefer_alchemy: bool = False,
    ) -> DualBackendClient | EtherscanClient:
        """Factory: returns a DualBackendClient if Alchemy is usable,
        else a plain EtherscanClient. This keeps the call site simple
        — the EvmAdapter doesn't need to branch on whether Alchemy is
        available."""
        etherscan = EtherscanClient(
            api_key=etherscan_api_key,
            api_base=etherscan_api_base,
            chain_id=chain_id,
            requests_per_second=requests_per_second,
            timeout_seconds=timeout_seconds,
        )
        if not prefer_alchemy:
            return etherscan
        if not alchemy_api_key:
            log.warning(
                "--prefer-alchemy requested but ALCHEMY_API_KEY is "
                "unset; using Etherscan only"
            )
            return etherscan
        if chain_id not in _CHAIN_ID_TO_ALCHEMY_PREFIX:
            log.warning(
                "--prefer-alchemy requested but chain_id=%d is not "
                "supported by Alchemy; using Etherscan only",
                chain_id,
            )
            return etherscan
        try:
            alchemy = AlchemyClient(
                api_key=alchemy_api_key,
                chain_id=chain_id,
                timeout_seconds=timeout_seconds,
            )
        except ValueError as e:
            log.warning("could not build Alchemy client: %s — using Etherscan only", e)
            return etherscan
        return cls(etherscan=etherscan, alchemy=alchemy)

    def close(self) -> None:
        # Close both — defensive. close() may be called multiple times
        # (adapter.close() loops) so each underlying client must be
        # idempotent (httpx.Client.close() is).
        try:
            self.etherscan.close()
        except Exception:  # noqa: BLE001
            pass
        if self.alchemy is not None:
            try:
                self.alchemy.close()
            except Exception:  # noqa: BLE001
                pass

    # --- Account-transfer methods: route via Alchemy, fall back. ---

    def _alchemy_or_fallback(
        self,
        method_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Try the named method on Alchemy first; fall back to
        Etherscan on AlchemyRateLimitError / AlchemyError. Logs the
        fallback at WARN so an operator can see backend health
        issues."""
        if self.alchemy is None:
            return getattr(self.etherscan, method_name)(*args, **kwargs)
        try:
            return getattr(self.alchemy, method_name)(*args, **kwargs)
        except AlchemyRateLimitError as e:
            log.warning(
                "alchemy rate-limited on %s: %s — falling back to Etherscan",
                method_name, e,
            )
        except AlchemyError as e:
            log.warning(
                "alchemy error on %s: %s — falling back to Etherscan",
                method_name, e,
            )
        return getattr(self.etherscan, method_name)(*args, **kwargs)

    def get_normal_transactions(
        self,
        address: str,
        start_block: int,
        end_block: int = 99_999_999,
        page: int = 1,
        offset: int = 1000,
        max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        return self._alchemy_or_fallback(
            "get_normal_transactions",
            address, start_block, end_block, page, offset,
            max_results=max_results,
        )

    def get_internal_transactions(
        self,
        address: str,
        start_block: int,
        end_block: int = 99_999_999,
        page: int = 1,
        offset: int = 1000,
        max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        return self._alchemy_or_fallback(
            "get_internal_transactions",
            address, start_block, end_block, page, offset,
            max_results=max_results,
        )

    def get_erc20_transfers(
        self,
        address: str,
        start_block: int,
        end_block: int = 99_999_999,
        page: int = 1,
        offset: int = 1000,
        max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        return self._alchemy_or_fallback(
            "get_erc20_transfers",
            address, start_block, end_block, page, offset,
            max_results=max_results,
        )

    # --- Other methods: pass through to Etherscan unchanged. ---

    def __getattr__(self, name: str) -> Any:
        # Anything not explicitly handled here falls through to
        # Etherscan. block_by_time, contract_source, tx receipts,
        # etc. all live on the Etherscan client.
        return getattr(self.etherscan, name)
