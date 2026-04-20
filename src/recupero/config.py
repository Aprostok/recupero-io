"""Configuration loading.

Loads YAML config (default + optional override) and merges environment variables
from .env. Returns a typed Pydantic settings object the rest of the code uses.
"""

from __future__ import annotations

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
    incident_buffer_minutes: int = 60
    max_transfers_per_address: int = 500


class EthereumParams(BaseModel):
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 1
    requests_per_second: float = 4.0
    block_range_chunk: int = 10_000
    native_symbol: str = "ETH"
    native_decimals: int = 18


class ArbitrumParams(BaseModel):
    """Arbitrum One — Etherscan V2 unified API, chain_id=42161."""
    api_base: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 42161
    requests_per_second: float = 4.0
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
    requests_per_second: float = 4.0
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
    COINGECKO_API_KEY: str = ""
    COINGECKO_TIER: str = "demo"   # "demo" (free tier, public API) or "pro"
    HELIUS_API_KEY: str = ""
    ALCHEMY_API_KEY: str = ""
    RECUPERO_DATA_DIR: str = ""
    RECUPERO_LOG_LEVEL: str = ""


# ---------- Loader ---------- #


def load_config(config_path: Path | None = None) -> tuple[RecuperoConfig, RecuperoEnv]:
    """Load default config, optionally overlay with `config_path`, and load env."""
    default_path = Path(__file__).parents[2] / "config" / "default.yaml"
    cfg_dict = _read_yaml(default_path)

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


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return yaml.safe_load(f) or {}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out
