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
    max_depth: int = 1
    dust_threshold_usd: float = 50.0
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
