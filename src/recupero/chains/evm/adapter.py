"""Generic EVM chain adapter (Ethereum, Arbitrum, BSC, etc.).

Etherscan V2 is a unified API: one host, different chain_id parameters.
That means every EVM chain Etherscan supports — Ethereum, Arbitrum One, BSC,
Base, Polygon, Optimism — can share the exact same adapter code with only
three things different per chain:

  - chain_id (the integer Etherscan uses)
  - explorer URL prefix (etherscan.io vs arbiscan.io vs bscscan.com)
  - native token symbol/id (ETH vs BNB vs MATIC, for pricing)

All chain-specific differences are isolated to the EvmChainProfile dataclass
at the top of this file. To add a new EVM chain, add one entry to
CHAIN_PROFILES — no code changes needed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from eth_utils import to_checksum_address

from recupero.chains.base import ChainAdapter
from recupero.chains.ethereum.etherscan import EtherscanClient
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class EvmChainProfile:
    """Chain-specific knobs for the shared EVM adapter."""
    chain: Chain
    chain_id: int
    api_base: str
    native_symbol: str
    native_decimals: int
    explorer_base: str
    coingecko_native_id: str   # for pricing native token ("ethereum", "binancecoin")
    coingecko_platform: str    # for contract→id lookup ("ethereum", "arbitrum-one", "binance-smart-chain")


def _profile_for(chain: Chain, cfg: RecuperoConfig) -> EvmChainProfile:
    """Build an EvmChainProfile from the global config for the given chain."""
    if chain == Chain.ethereum:
        p = cfg.ethereum
        return EvmChainProfile(
            chain=chain, chain_id=p.chain_id, api_base=p.api_base,
            native_symbol=p.native_symbol, native_decimals=p.native_decimals,
            explorer_base="https://etherscan.io",
            coingecko_native_id="ethereum",
            coingecko_platform="ethereum",
        )
    if chain == Chain.arbitrum:
        p = cfg.arbitrum
        return EvmChainProfile(
            chain=chain, chain_id=p.chain_id, api_base=p.api_base,
            native_symbol=p.native_symbol, native_decimals=p.native_decimals,
            explorer_base=p.explorer_base,
            coingecko_native_id=p.coingecko_native_id,
            coingecko_platform=p.coingecko_platform,
        )
    if chain == Chain.bsc:
        p = cfg.bsc
        return EvmChainProfile(
            chain=chain, chain_id=p.chain_id, api_base=p.api_base,
            native_symbol=p.native_symbol, native_decimals=p.native_decimals,
            explorer_base=p.explorer_base,
            coingecko_native_id=p.coingecko_native_id,
            coingecko_platform=p.coingecko_platform,
        )
    raise NotImplementedError(f"No EVM profile for chain {chain}")


class EvmAdapter(ChainAdapter):
    """Adapter for any EVM chain reachable via Etherscan V2."""

    def __init__(self, bundle: tuple[RecuperoConfig, RecuperoEnv], chain: Chain) -> None:
        cfg, env = bundle
        self.cfg = cfg
        self.profile = _profile_for(chain, cfg)
        self.chain = chain
        self.client = EtherscanClient(
            api_key=env.ETHERSCAN_API_KEY,
            api_base=self.profile.api_base,
            chain_id=self.profile.chain_id,
            requests_per_second=4.0,
        )
        self._is_contract_cache: dict[str, bool] = {}

    # ---------- Required interface ----------

    def block_at_or_before(self, ts: datetime) -> int:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        unix_ts = int(ts.timestamp())
        return self.client.get_block_number_by_time(unix_ts, closest="before")

    def is_contract(self, address: Address) -> bool:
        addr = to_checksum_address(address)
        if addr in self._is_contract_cache:
            return self._is_contract_cache[addr]
        meta = self.client.get_contract_source(addr)
        is_contract = bool(meta and (meta.get("ContractName") or meta.get("Proxy") == "1"))
        self._is_contract_cache[addr] = is_contract
        return is_contract

    # Etherscan V2's free tier returns "No transactions found" on some chains
    # (notably Arbitrum One, chain_id=42161) whenever `startblock` is a large
    # value (typical post-genesis blocks for a 4-blocks-per-second chain are
    # already in the hundreds of millions). The transactions ARE there — the
    # API just returns empty. Workaround: for these chains, query from
    # startblock=0 and apply the block filter client-side.
    _CLIENT_SIDE_STARTBLOCK_FILTER_CHAIN_IDS: frozenset[int] = frozenset({42161})

    def _needs_client_side_start_block_filter(self) -> bool:
        return self.profile.chain_id in self._CLIENT_SIDE_STARTBLOCK_FILTER_CHAIN_IDS

    def fetch_native_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        addr = to_checksum_address(from_address)
        client_side_filter = self._needs_client_side_start_block_filter()
        api_start = 0 if client_side_filter else start_block
        normal = self.client.get_normal_transactions(addr, start_block=api_start)
        internal = self.client.get_internal_transactions(addr, start_block=api_start)

        def _keep(tx: dict[str, Any]) -> bool:
            if tx.get("from", "").lower() != addr.lower():
                return False
            if int(tx.get("value", "0")) == 0 or tx.get("isError") == "1":
                return False
            if client_side_filter and int(tx.get("blockNumber", "0")) < start_block:
                return False
            return True

        out: list[dict[str, Any]] = []
        for tx in normal:
            if _keep(tx):
                out.append(self._normalize_native(tx, source="normal"))
        for tx in internal:
            if _keep(tx):
                out.append(self._normalize_native(tx, source="internal"))
        return out

    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        addr = to_checksum_address(from_address)
        client_side_filter = self._needs_client_side_start_block_filter()
        api_start = 0 if client_side_filter else start_block
        rows = self.client.get_erc20_transfers(addr, start_block=api_start)
        out: list[dict[str, Any]] = []
        for tx in rows:
            if tx.get("from", "").lower() != addr.lower():
                continue
            if client_side_filter and int(tx.get("blockNumber", "0")) < start_block:
                continue
            out.append(self._normalize_erc20(tx))
        return out

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        raw_tx = self.client.get_transaction_by_hash(tx_hash)
        raw_receipt = self.client.get_transaction_receipt(tx_hash)
        block_hex = raw_tx.get("blockNumber") or raw_receipt.get("blockNumber") or "0x0"
        block_number = int(block_hex, 16)
        raw_block = self.client.get_block_by_number(block_number, full_tx=False)
        block_time = datetime.fromtimestamp(int(raw_block.get("timestamp", "0x0"), 16), tz=timezone.utc)
        return EvidenceReceipt(
            chain=self.chain, tx_hash=tx_hash, block_number=block_number, block_time=block_time,
            raw_transaction=raw_tx, raw_receipt=raw_receipt, raw_block_header=raw_block,
            fetched_at=datetime.now(timezone.utc),
            fetched_from=self.profile.api_base,
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"{self.profile.explorer_base}/tx/{tx_hash}"

    def explorer_address_url(self, address: Address) -> str:
        return f"{self.profile.explorer_base}/address/{to_checksum_address(address)}"

    # ---------- Normalizers ----------

    def _normalize_native(self, tx: dict[str, Any], source: str) -> dict[str, Any]:
        block_number = int(tx["blockNumber"])
        block_time = datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc)
        token = TokenRef(
            chain=self.chain, contract=None,
            symbol=self.profile.native_symbol,
            decimals=self.profile.native_decimals,
            coingecko_id=self.profile.coingecko_native_id,
        )
        return {
            "chain": self.chain,
            "tx_hash": tx["hash"],
            "block_number": block_number,
            "block_time": block_time,
            "log_index": None,
            "from": to_checksum_address(tx["from"]),
            "to": to_checksum_address(tx["to"]),
            "token": token,
            "amount_raw": int(tx["value"]),
            "explorer_url": self.explorer_tx_url(tx["hash"]),
            "_native_source": source,
        }

    def _normalize_erc20(self, tx: dict[str, Any]) -> dict[str, Any]:
        block_number = int(tx["blockNumber"])
        block_time = datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc)
        token = TokenRef(
            chain=self.chain,
            contract=to_checksum_address(tx["contractAddress"]),
            symbol=tx.get("tokenSymbol", "?") or "?",
            decimals=int(tx.get("tokenDecimal", "18") or 18),
            coingecko_id=None,
        )
        log_index = None
        try:
            log_index = int(tx["logIndex"])
        except (KeyError, ValueError, TypeError):
            pass
        return {
            "chain": self.chain,
            "tx_hash": tx["hash"],
            "block_number": block_number,
            "block_time": block_time,
            "log_index": log_index,
            "from": to_checksum_address(tx["from"]),
            "to": to_checksum_address(tx["to"]),
            "token": token,
            "amount_raw": int(tx["value"]),
            "explorer_url": self.explorer_tx_url(tx["hash"]),
        }
