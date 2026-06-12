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
            # v0.35.3 — opBNB (chain_id 204), verified on the live Etherscan
            # V2 chainlist. Was label-only → BFS dead-ended on a bridge
            # handoff into it; now routes through the shared EvmAdapter.
            Chain.opbnb,
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
        if chain == Chain.ton:
            # TON uses the public TON Center API (v2 native + v3 Jetton). Like
            # Tron/Bitcoin the adapter resolves its own config — an optional
            # TONCENTER_API_KEY from env lifts the rate limit.
            from recupero.chains.ton.adapter import TonAdapter
            return TonAdapter()
        if chain == Chain.stellar:
            # Stellar uses the public Horizon API (no auth). Like Tron/TON the
            # adapter resolves its own config.
            from recupero.chains.stellar.adapter import StellarAdapter
            return StellarAdapter()
        if chain == Chain.sui:
            # roadmap-v4: Sui mainnet via the public keyless fullnode JSON-RPC.
            # Like Tron/TON/Stellar the adapter resolves its own client. Before
            # this branch a trace that bridged INTO Sui dead-ended here
            # (NotImplementedError, swallowed by the continuation block); now the
            # BFS follows the Sui wallet's coin movements (native SUI + USDC/USDT)
            # to their next address via the tx balanceChanges.
            from recupero.chains.sui.adapter import SuiAdapter
            return SuiAdapter()
        if chain == Chain.cosmos:
            # v0.39 (Activation Sprint #5): Cosmos / IBC zones (Cosmos Hub,
            # Osmosis, Injective, Juno, Stargaze, Axelar, Secret, Kava,
            # Celestia). The adapter resolves the per-zone LCD endpoint from the
            # queried address's bech32 prefix, so — like Tron/TON/Stellar — it
            # owns its own config rather than threading RecuperoConfig.
            #
            # We MUST inject a real httpx transport here: the CosmosLCDClient
            # default is a no-network stub used by unit tests, so a bare
            # CosmosAdapter() would silently fetch ZERO transfers and dead-end
            # at a Cosmos hop. IBC cross-chain *continuation* (following funds
            # OUT of Cosmos) is the next layer and not yet wired — the BFS now
            # reaches + follows funds ON Cosmos and surfaces the hop.
            import httpx

            from recupero.chains.cosmos.adapter import CosmosAdapter
            from recupero.chains.cosmos.client import CosmosLCDClient
            httpx_client = httpx.Client(
                timeout=httpx.Timeout(connect=10.0, read=20.0, write=20.0, pool=20.0),
                headers={"User-Agent": "recupero-cosmos/1.0"},
                follow_redirects=True,
            )
            return CosmosAdapter(client=CosmosLCDClient(http_client=httpx_client))
        if chain == Chain.hyperliquid:
            # roadmap-v4 #12: Hyperliquid is a perps/spot venue (not a block
            # chain) with an Ethereum-format address space and its own USDC
            # ledger over the public info API (no auth). Like Tron/TON the
            # adapter resolves its own client. Before this branch a trace that
            # bridged INTO Hyperliquid dead-ended here (NotImplementedError,
            # swallowed by the continuation block); now the BFS follows the
            # HL wallet's USDC withdrawals to their Arbitrum destination.
            from recupero.chains.hyperliquid.adapter import HyperliquidAdapter
            return HyperliquidAdapter()
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

    # --- inbound transfer fetching (optional capability) ---
    #
    # v0.32.1 (trace-depth #1 wiring): cross-chain lock-and-mint matching
    # needs to query an address's INBOUND transfers on a candidate
    # destination chain (the mint/withdrawal side) to correlate against a
    # source-chain bridge deposit. These are CONCRETE defaults (not
    # abstract) returning [] — an adapter that hasn't implemented inbound
    # fetch degrades gracefully (the lock-mint matcher simply finds no
    # candidates on that chain) rather than the interface forcing every
    # adapter to implement it. The EVM adapter overrides both.
    def fetch_native_inflows(
        self, to_address: Address, start_block: int,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Native-asset INBOUND transfers TO `to_address` since
        `start_block`. Same normalized dict shape as
        `fetch_native_outflows`. Default: [] (adapter has no inbound
        support yet)."""
        return []

    def fetch_erc20_inflows(
        self, to_address: Address, start_block: int,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Token INBOUND transfers TO `to_address`. Default: [] (adapter
        has no inbound support yet)."""
        return []

    # --- event logs (v0.34 — bridge source↔destination pairing) ---

    def fetch_logs(
        self,
        address: Address,
        topic0: str,
        *,
        from_block: int,
        to_block: int | str = "latest",
        topics: list[str | None] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch event logs emitted by ``address`` with ``topic0`` (the event
        signature) in ``[from_block, to_block]``, optionally further filtered by
        indexed ``topics`` (topic1..topic3; ``None`` = wildcard).

        Returns the raw log dicts (each with at least ``address``, ``topics``,
        ``data``, ``transactionHash``, ``blockNumber``). Default: ``[]`` —
        adapters that can't query logs (or non-EVM chains) simply yield nothing,
        so the bridge-pairing confirmation degrades to "unconfirmed" rather than
        raising. The EVM adapter overrides this via Etherscan ``eth_getLogs``.
        """
        return []

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
