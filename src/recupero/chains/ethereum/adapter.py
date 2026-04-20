"""Ethereum implementation of the ChainAdapter protocol.

Since Etherscan V2 is a unified API, this is now a thin wrapper over the
shared EvmAdapter — Ethereum is just one EVM chain among many.
"""

from __future__ import annotations

from recupero.chains.evm.adapter import EvmAdapter
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain


class EthereumAdapter(EvmAdapter):
    """Ethereum mainnet adapter. Backward-compatible import path."""

    def __init__(self, bundle: tuple[RecuperoConfig, RecuperoEnv]) -> None:
        super().__init__(bundle, chain=Chain.ethereum)

