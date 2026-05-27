"""Configuration loading.

Loads YAML config (default + optional override) and merges environment variables
from .env. Returns a typed Pydantic settings object the rest of the code uses.

The default YAML is bundled inside the package at
``recupero._defaults/default.yaml`` and read via ``importlib.resources``,
so a regular ``pip install`` Just Works — no editable install or repo-root
file required.
"""

from __future__ import annotations

from importlib.resources import files as resource_files
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------- Sub-configs ---------- #


class TraceParams(BaseModel):
    # max_depth=2 (bumped from 1 in v0.7.4): walk one hop past the
    # immediate destination. The Zigha-shape pattern is
    # victim → consolidation hub → final destinations; depth=1
    # stops at the hub and never enumerates the addresses where
    # perpetrator funds actually rest. The cost increase is ~2x
    # explorer API calls per trace, still well under $0.50/case.
    #
    # Operators can override per-case via the investigation row's
    # max_depth column when a complex multi-hop case warrants
    # depth=3 or 4. Pass-2 perpetrator-forward tracing (v0.8.0+)
    # is the architectural fix for arbitrarily-deep cases; this
    # default change is the immediate-relief patch.
    max_depth: int = 2
    # dust_threshold_usd=10 (lowered from 50 in v0.7.4): with
    # depth=2 traversal, downstream destinations receive
    # proportional shares of the hub's outflows. A $50 floor
    # dust-filtered legitimately material destinations in the
    # V-CFI01 Zigha-pattern test (CFI report's $3.27M Maple
    # destination, three DAI dormant addresses). $10 is the new
    # conservative balance — still filters the random
    # service-wallet noise without losing seven-figure
    # destinations that proportionally split below $50.
    dust_threshold_usd: float = 10.0
    stop_at_exchange: bool = True
    stop_at_contract: bool = True  # stop traversal at contract destinations (DeFi pools/routers)
    stop_at_bridge: bool = True    # stop traversal at labeled bridges (can't follow cross-chain)
    incident_buffer_minutes: int = 60
    max_transfers_per_address: int = 500
    # If a wallet has more raw outflows than this, treat it as service-like
    # (OTC desk, unlabeled exchange, mixer-adjacent, etc.) and don't traverse
    # its children. We still keep the transfers we observed in the case
    # output, but BFS terminates here. Without this cap a single 500-outflow
    # service wallet at depth 2 explodes into 500 useless wallets at depth 3.
    service_wallet_outflow_threshold: int = 200


class EthereumParams(BaseModel):
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 1
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "ETH"
    native_decimals: int = 18


class ArbitrumParams(BaseModel):
    """Arbitrum One — Etherscan V2 unified API, chain_id=42161."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 42161
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "ETH"  # Arbitrum native gas token is ETH
    native_decimals: int = 18
    explorer_base: str = "https://arbiscan.io"
    coingecko_platform: str = "arbitrum-one"
    coingecko_native_id: str = "ethereum"


class BscParams(BaseModel):
    """BNB Smart Chain — Etherscan V2 unified API, chain_id=56."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 56
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "BNB"
    native_decimals: int = 18
    explorer_base: str = "https://bscscan.com"
    coingecko_platform: str = "binance-smart-chain"
    coingecko_native_id: str = "binancecoin"


class PolygonParams(BaseModel):
    """Polygon PoS — Etherscan V2 unified API, chain_id=137.

    Native-token rebrand (2024-09-04): MATIC was redenominated to POL
    1:1 via a contract migration. The on-chain contract address for
    the staking token is now POL; the legacy MATIC contract is still
    valid but is being phased out. CoinGecko mirrored the rebrand:
    historical prices before 2024-09-04 live under ``matic-network``,
    prices on or after that date live under ``polygon-ecosystem-token``.

    v0.16.8 default (round-9 forensic HIGH): point at POL going forward.
    For incidents BEFORE 2024-09-04 callers should pin
    ``coingecko_native_id="matic-network"`` via the trace config so
    historical pricing resolves correctly.
    """
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 137
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "POL"
    native_decimals: int = 18
    explorer_base: str = "https://polygonscan.com"
    coingecko_platform: str = "polygon-pos"
    coingecko_native_id: str = "polygon-ecosystem-token"


class BaseParams(BaseModel):
    """Base mainnet — Etherscan V2 unified API, chain_id=8453.
    Native gas token is ETH (Base is an L2 settling to Ethereum)."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 8453
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "ETH"
    native_decimals: int = 18
    explorer_base: str = "https://basescan.org"
    coingecko_platform: str = "base"
    coingecko_native_id: str = "ethereum"


# v0.20.0 (round-13 chain-coverage research): seven EVM chains added.
# Each is a free Etherscan-V2-multichain wire-up — same `api_base`,
# different chainid. Defaults sourced from the chain's documentation
# + CoinGecko platform / native-id mapping.


class OptimismParams(BaseModel):
    """Optimism mainnet — Etherscan V2 unified API, chain_id=10.
    Native gas token is ETH (OP is an L2 settling to Ethereum)."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 10
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "ETH"
    native_decimals: int = 18
    explorer_base: str = "https://optimistic.etherscan.io"
    coingecko_platform: str = "optimistic-ethereum"
    coingecko_native_id: str = "ethereum"


class AvalancheParams(BaseModel):
    """Avalanche C-Chain — Etherscan V2 unified API, chain_id=43114.
    Native gas token is AVAX."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 43114
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "AVAX"
    native_decimals: int = 18
    explorer_base: str = "https://snowtrace.io"
    coingecko_platform: str = "avalanche"
    coingecko_native_id: str = "avalanche-2"


class LineaParams(BaseModel):
    """Linea — Consensys zk-rollup, Etherscan V2 unified API,
    chain_id=59144. Native gas token is ETH."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 59144
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "ETH"
    native_decimals: int = 18
    explorer_base: str = "https://lineascan.build"
    coingecko_platform: str = "linea"
    coingecko_native_id: str = "ethereum"


class BlastParams(BaseModel):
    """Blast — Etherscan V2 unified API, chain_id=81457.
    Native gas token is ETH."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 81457
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "ETH"
    native_decimals: int = 18
    explorer_base: str = "https://blastscan.io"
    coingecko_platform: str = "blast"
    coingecko_native_id: str = "ethereum"


class ZksyncParams(BaseModel):
    """zkSync Era — Etherscan V2 unified API, chain_id=324.
    Native gas token is ETH. Note: zkSync's account-abstraction model
    can produce wallet shapes that aren't EOA — most tools assume EOA,
    so traces may surface contract-wallet creations as 'unlabeled
    contract'."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 324
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "ETH"
    native_decimals: int = 18
    explorer_base: str = "https://explorer.zksync.io"
    coingecko_platform: str = "zksync"
    coingecko_native_id: str = "ethereum"


class ScrollParams(BaseModel):
    """Scroll — Etherscan V2 unified API, chain_id=534352.
    Native gas token is ETH."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 534352
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "ETH"
    native_decimals: int = 18
    explorer_base: str = "https://scrollscan.com"
    coingecko_platform: str = "scroll"
    coingecko_native_id: str = "ethereum"


class MantleParams(BaseModel):
    """Mantle — Etherscan V2 unified API, chain_id=5000.
    Native gas token is MNT."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 5000
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "MNT"
    native_decimals: int = 18
    explorer_base: str = "https://mantlescan.xyz"
    coingecko_platform: str = "mantle"
    coingecko_native_id: str = "mantle"


# v0.31.2 — six v0.29.0-promoted destination chains. All route through
# Etherscan V2 multichain via chain_id. Profiles verified against
# Etherscan V2 multichain docs + Chainalysis 2024-2025 stolen-fund
# destination reports. Each was previously LABEL-ONLY (the BFS
# raised NotImplementedError when trying to follow a bridge handoff
# into them); v0.31.2 wires the adapter routing.


class FantomParams(BaseModel):
    """Fantom Opera — Etherscan V2 unified API, chain_id=250.
    Native gas token is FTM (CoinGecko id `fantom`)."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 250
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "FTM"
    native_decimals: int = 18
    explorer_base: str = "https://ftmscan.com"
    coingecko_platform: str = "fantom"
    coingecko_native_id: str = "fantom"


class CeloParams(BaseModel):
    """Celo — Etherscan V2 unified API, chain_id=42220.
    Native gas token is CELO. After 2025 L2 migration, the chain
    remained EVM-compatible with the same chain_id."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 42220
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "CELO"
    native_decimals: int = 18
    explorer_base: str = "https://celoscan.io"
    coingecko_platform: str = "celo"
    coingecko_native_id: str = "celo"


class GnosisParams(BaseModel):
    """Gnosis Chain (formerly xDai) — Etherscan V2 unified API,
    chain_id=100. Native gas token is xDAI (stable, pegged to USD)."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 100
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "xDAI"
    native_decimals: int = 18
    explorer_base: str = "https://gnosisscan.io"
    coingecko_platform: str = "xdai"
    coingecko_native_id: str = "xdai"


class MoonbeamParams(BaseModel):
    """Moonbeam (Polkadot parachain, EVM-compatible) — Etherscan V2
    unified API, chain_id=1284. Native gas token is GLMR."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 1284
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "GLMR"
    native_decimals: int = 18
    explorer_base: str = "https://moonscan.io"
    coingecko_platform: str = "moonbeam"
    coingecko_native_id: str = "moonbeam"


class MetisParams(BaseModel):
    """Metis Andromeda — Etherscan V2 unified API, chain_id=1088.
    Native gas token is METIS."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 1088
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "METIS"
    native_decimals: int = 18
    explorer_base: str = "https://andromeda-explorer.metis.io"
    coingecko_platform: str = "metis-andromeda"
    coingecko_native_id: str = "metis-token"


class KavaParams(BaseModel):
    """Kava EVM — Etherscan V2 unified API, chain_id=2222.
    Native gas token is KAVA. Tendermint consensus + EVM rollup."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 2222
    requests_per_second: float = 2.5
    block_range_chunk: int = 10_000
    native_symbol: str = "KAVA"
    native_decimals: int = 18
    explorer_base: str = "https://kavascan.com"
    coingecko_platform: str = "kava"
    coingecko_native_id: str = "kava"


class PricingParams(BaseModel):
    provider: str = "coingecko"
    requests_per_second: float = 0.5
    fail_open: bool = True


class StorageParams(BaseModel):
    data_dir: str = "./data"
    pretty_json: bool = True


class LoggingParams(BaseModel):
    level: str = "INFO"
    format: str = "rich"


# ---------- Top-level YAML config ---------- #


class RecuperoConfig(BaseModel):
    trace: TraceParams = Field(default_factory=TraceParams)
    ethereum: EthereumParams = Field(default_factory=EthereumParams)
    arbitrum: ArbitrumParams = Field(default_factory=ArbitrumParams)
    bsc: BscParams = Field(default_factory=BscParams)
    polygon: PolygonParams = Field(default_factory=PolygonParams)
    base: BaseParams = Field(default_factory=BaseParams)
    # v0.20.0 (round-13 chain-coverage research): seven EVM chains
    # added via Etherscan V2 multichain.
    optimism: OptimismParams = Field(default_factory=OptimismParams)
    avalanche: AvalancheParams = Field(default_factory=AvalancheParams)
    linea: LineaParams = Field(default_factory=LineaParams)
    blast: BlastParams = Field(default_factory=BlastParams)
    zksync: ZksyncParams = Field(default_factory=ZksyncParams)
    scroll: ScrollParams = Field(default_factory=ScrollParams)
    mantle: MantleParams = Field(default_factory=MantleParams)
    # v0.31.2 — 6 v0.29.0-promoted destination chains.
    fantom: FantomParams = Field(default_factory=FantomParams)
    celo: CeloParams = Field(default_factory=CeloParams)
    gnosis: GnosisParams = Field(default_factory=GnosisParams)
    moonbeam: MoonbeamParams = Field(default_factory=MoonbeamParams)
    metis: MetisParams = Field(default_factory=MetisParams)
    kava: KavaParams = Field(default_factory=KavaParams)
    pricing: PricingParams = Field(default_factory=PricingParams)
    storage: StorageParams = Field(default_factory=StorageParams)
    logging: LoggingParams = Field(default_factory=LoggingParams)


# ---------- Environment / secrets ---------- #


class RecuperoEnv(BaseSettings):
    """Loaded from .env or process environment. Secrets only — no behavior tunables here."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=True)

    ETHERSCAN_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    COINGECKO_API_KEY: str = ""
    COINGECKO_TIER: str = "demo"   # "demo" (free tier, public API) or "pro"
    HELIUS_API_KEY: str = ""
    ALCHEMY_API_KEY: str = ""
    RECUPERO_DATA_DIR: str = ""
    RECUPERO_LOG_LEVEL: str = ""


# ---------- Loader ---------- #


def load_config(config_path: Path | None = None) -> tuple[RecuperoConfig, RecuperoEnv]:
    """Load default config, optionally overlay with `config_path`, and load env."""
    cfg_dict = _read_default_yaml()

    if config_path is not None:
        override = _read_yaml(config_path)
        cfg_dict = _deep_merge(cfg_dict, override)

    cfg = RecuperoConfig(**cfg_dict)
    env = RecuperoEnv()

    # Env overrides where present
    if env.RECUPERO_DATA_DIR:
        cfg.storage.data_dir = env.RECUPERO_DATA_DIR
    if env.RECUPERO_LOG_LEVEL:
        cfg.logging.level = env.RECUPERO_LOG_LEVEL

    return cfg, env


def _read_default_yaml() -> dict[str, Any]:
    """Load the bundled default.yaml via importlib.resources.

    Falls back to the repo-root ``config/default.yaml`` if the package
    resource isn't found — this happens during a development checkout
    before the package has been re-installed."""
    try:
        text = resource_files("recupero._defaults").joinpath("default.yaml").read_text(
            encoding="utf-8"
        )
        return yaml.safe_load(text) or {}
    except (FileNotFoundError, ModuleNotFoundError):
        # Dev fallback for an unreinstalled checkout.
        repo_default = Path(__file__).resolve().parents[2] / "config" / "default.yaml"
        return _read_yaml(repo_default)


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out
