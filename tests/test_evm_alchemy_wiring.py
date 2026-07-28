"""Env-var activation of the Alchemy-preferred EVM backend.

RIGOR-Jacob B built the AlchemyClient + DualBackendClient factory but never wired
it into EvmAdapter, and there is NO CLI `--prefer-alchemy` on the async /v2 worker
path — so an ALCHEMY_API_KEY alone was inert. These tests pin the env activation:
`RECUPERO_PREFER_ALCHEMY` routes the EVM client through the dual backend, default
off is byte-identical Etherscan-only, and a missing key / unsupported chain falls
back to Etherscan (never crashes).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from recupero.chains.ethereum.etherscan import EtherscanClient
from recupero.chains.evm.adapter import _build_evm_client, _prefer_alchemy
from recupero.chains.evm.dual_backend_client import DualBackendClient


def _env(alchemy: str = "alk") -> Any:
    return SimpleNamespace(ETHERSCAN_API_KEY="esk", ALCHEMY_API_KEY=alchemy)


def _profile(chain_id: int = 1) -> Any:
    # _build_evm_client only reads api_base + chain_id off the profile.
    return SimpleNamespace(api_base="https://api.etherscan.io/api", chain_id=chain_id)


def test_prefer_alchemy_env_parsing(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_PREFER_ALCHEMY", raising=False)
    assert _prefer_alchemy() is False
    for truthy in ("1", "true", "YES", "on"):
        monkeypatch.setenv("RECUPERO_PREFER_ALCHEMY", truthy)
        assert _prefer_alchemy() is True
    monkeypatch.setenv("RECUPERO_PREFER_ALCHEMY", "0")
    assert _prefer_alchemy() is False


def test_default_is_plain_etherscan(monkeypatch) -> None:
    """Flag off → a plain EtherscanClient (unchanged historical behavior)."""
    monkeypatch.delenv("RECUPERO_PREFER_ALCHEMY", raising=False)
    client = _build_evm_client(_env(), _profile())
    try:
        assert isinstance(client, EtherscanClient)
        assert not isinstance(client, DualBackendClient)
    finally:
        client.close()


def test_prefer_alchemy_builds_dual_backend(monkeypatch) -> None:
    """Flag on + key present + supported chain → DualBackendClient (Alchemy-preferred)."""
    monkeypatch.setenv("RECUPERO_PREFER_ALCHEMY", "1")
    client = _build_evm_client(_env(), _profile(chain_id=1))  # ethereum, Alchemy-supported
    try:
        assert isinstance(client, DualBackendClient)
        assert client.alchemy is not None
    finally:
        client.close()


def test_prefer_alchemy_without_key_falls_back(monkeypatch) -> None:
    """Flag on but ALCHEMY_API_KEY empty → Etherscan-only (never crashes)."""
    monkeypatch.setenv("RECUPERO_PREFER_ALCHEMY", "1")
    client = _build_evm_client(_env(alchemy=""), _profile(chain_id=1))
    try:
        assert isinstance(client, EtherscanClient)
    finally:
        client.close()


def test_prefer_alchemy_unsupported_chain_falls_back(monkeypatch) -> None:
    """Flag on + key present but chain not in Alchemy's map → Etherscan-only."""
    monkeypatch.setenv("RECUPERO_PREFER_ALCHEMY", "1")
    client = _build_evm_client(_env(), _profile(chain_id=999_999))
    try:
        assert isinstance(client, EtherscanClient)
    finally:
        client.close()
