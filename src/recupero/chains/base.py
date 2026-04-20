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
    def for_chain(cls, chain: Chain, config: Any) -> "ChainAdapter":
        """Factory. Imports done locally to avoid cycles."""
        if chain == Chain.ethereum:
            from recupero.chains.ethereum.adapter import EthereumAdapter
            return EthereumAdapter(config)
        if chain in (Chain.arbitrum, Chain.bsc):
            from recupero.chains.evm.adapter import EvmAdapter
            return EvmAdapter(config, chain=chain)
        if chain == Chain.solana:
            from recupero.chains.solana.adapter import SolanaAdapter
            return SolanaAdapter(config)
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
