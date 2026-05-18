"""Tests for the chain adapter dispatch + per-chain profile build.

The dispatch path (``ChainAdapter.for_chain``) + profile builder
(``_profile_for`` in chains/evm/adapter.py) is the entry point for
every multi-chain trace. Before this commit:

  * Ethereum had a dedicated adapter (EthereumAdapter).
  * Arbitrum + BSC routed to EvmAdapter via the Etherscan V2 chainid
    parameter. ``_profile_for`` had explicit branches for both.
  * **Polygon and Base were NOT registered** — even though their
    explorer URLs existed in ``_EXPLORER_BY_CHAIN`` (used by the
    flow-diagram renderer), the trace dispatch would raise
    NotImplementedError for them, crashing the pipeline on the
    first Polygon or Base wallet-trace.

This test suite locks the fix in:

  * ``ChainAdapter.for_chain`` routes Polygon + Base to EvmAdapter.
  * ``_profile_for`` returns a populated profile for each chain.
  * Each chain's profile has the right chain_id, native symbol, and
    CoinGecko platform id (these drive the explorer URLs the
    letter templates and trace_report link to, and the pricing
    lookups the tracer uses).

Tests use stub config + env objects so we don't have to wire a
real Etherscan API key. The EvmAdapter constructor will accept
an empty api_key (it raises only when actually called against
Etherscan).
"""

from __future__ import annotations

import pytest

from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.chains.base import ChainAdapter
from recupero.chains.evm.adapter import EvmAdapter, _profile_for
from recupero.models import Chain


def _bundle() -> tuple[RecuperoConfig, RecuperoEnv]:
    """Stub config + env with a dummy Etherscan key so the EvmAdapter
    constructor doesn't raise. Real network calls aren't made by
    these tests — we only exercise the dispatch + profile-build
    logic."""
    cfg = RecuperoConfig()
    env = RecuperoEnv(ETHERSCAN_API_KEY="dummy-test-key")
    return cfg, env


# ---- _profile_for ---- #


def test_profile_for_ethereum() -> None:
    cfg, _env = _bundle()
    p = _profile_for(Chain.ethereum, cfg)
    assert p.chain == Chain.ethereum
    assert p.chain_id == 1
    assert p.native_symbol == "ETH"
    assert "etherscan.io" in p.explorer_base


def test_profile_for_arbitrum() -> None:
    cfg, _env = _bundle()
    p = _profile_for(Chain.arbitrum, cfg)
    assert p.chain_id == 42161
    assert p.native_symbol == "ETH"
    assert "arbiscan.io" in p.explorer_base
    assert p.coingecko_platform == "arbitrum-one"


def test_profile_for_bsc() -> None:
    cfg, _env = _bundle()
    p = _profile_for(Chain.bsc, cfg)
    assert p.chain_id == 56
    assert p.native_symbol == "BNB"
    assert "bscscan.com" in p.explorer_base
    assert p.coingecko_native_id == "binancecoin"


def test_profile_for_polygon() -> None:
    """Regression: Polygon was missing from _profile_for prior to the
    multi-chain validation pass. Locks chain_id (137) + CoinGecko
    platform id.

    v0.16.8 (round-9 forensic HIGH): MATIC → POL rebrand 2024-09-04.
    Default `coingecko_native_id` is now ``polygon-ecosystem-token``
    (current). Historical-incident callers should override via config
    to ``matic-network`` for pre-2024-09-04 dates.
    """
    cfg, _env = _bundle()
    p = _profile_for(Chain.polygon, cfg)
    assert p.chain_id == 137
    assert p.native_symbol == "POL"
    assert "polygonscan.com" in p.explorer_base
    assert p.coingecko_platform == "polygon-pos"
    assert p.coingecko_native_id == "polygon-ecosystem-token"


def test_profile_for_base() -> None:
    """Regression: Base was missing from _profile_for. Locks
    chain_id (8453) and the Base-specific CoinGecko platform id
    (``base``). Native gas is ETH (Base is an L2)."""
    cfg, _env = _bundle()
    p = _profile_for(Chain.base, cfg)
    assert p.chain_id == 8453
    assert p.native_symbol == "ETH"
    assert "basescan.org" in p.explorer_base
    assert p.coingecko_platform == "base"
    assert p.coingecko_native_id == "ethereum"


# ---- ChainAdapter.for_chain dispatch ---- #


def test_for_chain_routes_evm_chains_to_evm_adapter() -> None:
    """All four EVM-via-Etherscan-V2 chains route to the same
    EvmAdapter class. Regression guard against the dispatch table
    accidentally creating a separate adapter class per chain
    (which would be a maintenance nightmare and what we explicitly
    avoid via the unified V2 API)."""
    bundle = _bundle()
    for chain in (Chain.arbitrum, Chain.bsc, Chain.polygon, Chain.base):
        adapter = ChainAdapter.for_chain(chain, bundle)
        assert isinstance(adapter, EvmAdapter), (
            f"chain={chain.value} should route to EvmAdapter, got {type(adapter).__name__}"
        )
        assert adapter.chain == chain
        # And the adapter's profile has the right chain_id
        assert adapter.profile.chain_id == {
            Chain.arbitrum: 42161,
            Chain.bsc: 56,
            Chain.polygon: 137,
            Chain.base: 8453,
        }[chain]


def test_for_chain_ethereum_uses_dedicated_adapter() -> None:
    """Ethereum has its own adapter class (EthereumAdapter) — kept
    separate from the unified EvmAdapter for historical reasons + so
    Ethereum-specific behavior (e.g., the block-clamp fix) lives in
    one place. Lock this so it doesn't drift."""
    from recupero.chains.ethereum.adapter import EthereumAdapter
    bundle = _bundle()
    adapter = ChainAdapter.for_chain(Chain.ethereum, bundle)
    assert isinstance(adapter, EthereumAdapter)


def test_for_chain_bitcoin_returns_adapter() -> None:
    """Bitcoin is now wired up (v0.13.0). The factory returns a
    real BitcoinAdapter rather than raising NotImplementedError.

    This test replaces the prior canary that used Bitcoin as the
    "valid enum, no adapter" case — that canary is now obsolete.
    There is no longer a Chain enum member without an adapter.
    Adding a NEW chain enum value without an adapter would
    legitimately fail this regression test if someone copies the
    canary pattern in the future.
    """
    from recupero.chains.bitcoin.adapter import BitcoinAdapter
    bundle = _bundle()
    adapter = ChainAdapter.for_chain(Chain.bitcoin, bundle)
    assert isinstance(adapter, BitcoinAdapter)


def test_polygon_profile_loaded_from_config() -> None:
    """Verify the config.polygon field is wired through the
    profile builder. Pre-fix, RecuperoConfig didn't have a
    ``polygon`` attribute at all — accessing cfg.polygon raised."""
    cfg, _env = _bundle()
    assert hasattr(cfg, "polygon")
    assert cfg.polygon.chain_id == 137


def test_base_profile_loaded_from_config() -> None:
    """Same for Base."""
    cfg, _env = _bundle()
    assert hasattr(cfg, "base")
    assert cfg.base.chain_id == 8453
