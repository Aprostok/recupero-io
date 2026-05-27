"""Abstract chain adapter.

Phase 1 ships only the Ethereum implementation. The abstraction exists from day
one so that Phase 3 (Solana) plugs in without touching the tracer. If the Solana
implementation forces changes to this interface, that's a sign Phase 1 over-fit
to Ethereum semantics — fix it then, but try hard to keep the surface small.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from recupero.models import Address, Chain, EvidenceReceipt


class ChainAdapter(ABC):
    """One implementation per chain. Stateless from the tracer's POV."""

    chain: Chain

    @classmethod
    def for_chain(cls, chain: Chain, config: Any) -> ChainAdapter:
        """Factory. Imports done locally to avoid cycles."""
        if chain == Chain.ethereum:
            from recupero.chains.ethereum.adapter import EthereumAdapter
            return EthereumAdapter(config)
        # v0.20.0 (round-13 chain-coverage research): seven additional
        # EVM chains route through the same shared EvmAdapter — Etherscan
        # V2 multichain covers all of them via the chainid query parameter.
        #
        # v0.31.2: added the 6 v0.29.0/v0.31.0-promoted destinations —
        # fantom (250), celo (42220), gnosis (100), moonbeam (1284),
        # metis (1088), kava (2222). Pre-v0.31.2 these were ENUM
        # members + had chainIDs wired in worker/watch_tick.py + had
        # explorer URLs in _common.py, but the ADAPTER FACTORY didn't
        # know about them — so when the BFS tried to follow a bridge
        # handoff into one of these chains, ChainAdapter.for_chain
        # raised NotImplementedError, which the cross-chain
        # continuation block in tracer.py swallowed via its broad
        # try/except. Net: the chain showed up as a candidate in the
        # brief but the BFS silently did NOT continue. The handoff
        # claim was real, the continuation was a lie.
        if chain in (
            Chain.arbitrum, Chain.bsc, Chain.polygon, Chain.base,
            Chain.optimism, Chain.avalanche, Chain.linea, Chain.blast,
            Chain.zksync, Chain.scroll, Chain.mantle,
            Chain.fantom, Chain.celo, Chain.gnosis, Chain.moonbeam,
            Chain.metis, Chain.kava,
        ):
            # Etherscan V2 unified API covers every EVM-compatible chain
            # via the chainid parameter — same client class, different
            # chain_id + native-symbol per profile.
            from recupero.chains.evm.adapter import EvmAdapter
            return EvmAdapter(config, chain=chain)
        if chain == Chain.solana:
            from recupero.chains.solana.adapter import SolanaAdapter
            return SolanaAdapter(config)
        if chain == Chain.tron:
            # Tron uses a separate REST gateway (TronGrid). Its config
            # surface is small — just an optional API key from env —
            # so the adapter resolves that itself rather than threading
            # through RecuperoConfig.
            from recupero.chains.tron.adapter import TronAdapter
            return TronAdapter()
        if chain == Chain.bitcoin:
            # Bitcoin uses Esplora (mempool.space / blockstream.info)
            # which requires no auth on the free tier. Like Tron, the
            # adapter resolves its own config — no RecuperoConfig
            # threading needed yet.
            from recupero.chains.bitcoin.adapter import BitcoinAdapter
            return BitcoinAdapter()
        raise NotImplementedError(f"No adapter for chain {chain}")

    # --- block / time ---

    @abstractmethod
    def block_at_or_before(self, ts: datetime) -> int:
        """Return the highest block number whose timestamp is <= ts."""

    @abstractmethod
    def is_contract(self, address: Address) -> bool:
        """Return True if address is a contract account."""

    # --- transfer fetching ---

    @abstractmethod
    def fetch_native_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        """Fetch native-asset outbound transfers from `from_address` since `start_block`.

        Returns a list of normalized dicts with keys:
            chain, tx_hash, block_number, block_time, log_index (None for native),
            from, to, token (TokenRef), amount_raw (int), explorer_url
        """

    @abstractmethod
    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        """Same as fetch_native_outflows but for token transfers (ERC-20 / SPL / etc.)."""

    # --- evidence ---

    @abstractmethod
    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        """Fetch the full chain-of-custody receipt for a transaction."""

    # --- explorer URLs (used for human-clickable verification) ---

    @abstractmethod
    def explorer_tx_url(self, tx_hash: str) -> str:
        ...

    @abstractmethod
    def explorer_address_url(self, address: Address) -> str:
        ...

    # --- lifecycle ---

    def close(self) -> None:
        """Release any HTTP clients / file handles held by the adapter.

        Default implementation closes ``self.client`` if it has a
        ``close`` method (matches the EVM/Helius/TronGrid client
        pattern). Adapters with multiple clients should override.

        v0.17.4 (round-10 audit CRIT): the tracer's cross-chain
        continuation pass instantiated destination-chain adapters
        per investigation but never closed them — over hours of
        operation the worker leaked httpx clients until the OS
        file-descriptor limit was hit and the process hung.
        """
        client = getattr(self, "client", None)
        if client is not None and hasattr(client, "close"):
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
