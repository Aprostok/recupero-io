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
from datetime import UTC, datetime, timedelta
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
    if chain == Chain.polygon:
        p = cfg.polygon
        return EvmChainProfile(
            chain=chain, chain_id=p.chain_id, api_base=p.api_base,
            native_symbol=p.native_symbol, native_decimals=p.native_decimals,
            explorer_base=p.explorer_base,
            coingecko_native_id=p.coingecko_native_id,
            coingecko_platform=p.coingecko_platform,
        )
    if chain == Chain.base:
        p = cfg.base
        return EvmChainProfile(
            chain=chain, chain_id=p.chain_id, api_base=p.api_base,
            native_symbol=p.native_symbol, native_decimals=p.native_decimals,
            explorer_base=p.explorer_base,
            coingecko_native_id=p.coingecko_native_id,
            coingecko_platform=p.coingecko_platform,
        )
    # v0.20.0 (round-13 chain-coverage research): seven additional
    # EVM chains via Etherscan V2 multichain. Each uses an identical
    # profile shape (chain_id + native_symbol + explorer_base +
    # coingecko_*); the adapter logic doesn't branch further past this
    # _profile_for resolver.
    _EXTENDED_EVM_CHAINS = {
        Chain.optimism:  "optimism",
        Chain.avalanche: "avalanche",
        Chain.linea:     "linea",
        Chain.blast:     "blast",
        Chain.zksync:    "zksync",
        Chain.scroll:    "scroll",
        Chain.mantle:    "mantle",
    }
    if chain in _EXTENDED_EVM_CHAINS:
        attr = _EXTENDED_EVM_CHAINS[chain]
        p = getattr(cfg, attr)
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
            ts = ts.replace(tzinfo=UTC)
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
    # v0.18.5 (round-11 chains-MED-001): high-block-rate chains
    # where Etherscan V2's startblock filter sometimes returns
    # empty for large start_block values ("No transactions found").
    # 42161 Arbitrum was the original case; reports of same behavior
    # on Polygon (137) and Base (8453) — both have fast blocks. Use
    # client-side filter on these chains: fetch all then drop pre-
    # start_block locally.
    _CLIENT_SIDE_STARTBLOCK_FILTER_CHAIN_IDS: frozenset[int] = frozenset({42161, 137, 8453})

    def _needs_client_side_start_block_filter(self) -> bool:
        return self.profile.chain_id in self._CLIENT_SIDE_STARTBLOCK_FILTER_CHAIN_IDS

    # v0.16.11 (round-9 forensic ARCH): wrapped-native passthrough.
    #
    # Wrapping native ETH/BNB/MATIC/etc. via the canonical wrapper
    # contract's `deposit()` method is economically a NO-OP from a
    # laundering perspective: funds stay under the depositor's control,
    # just now as the wrapped-token IOU instead of native. The
    # subsequent token transfer (WETH → router, WETH → another wallet)
    # already shows up in the case via `tokentx`, so the wrap event
    # contributes nothing useful to a forensic trace.
    #
    # Pre-v0.16.11 the wrap-deposit transfer:
    #   * inflated `total_usd_out` (counted the same dollars twice
    #     once as native, again as the WETH transfer that followed)
    #   * showed up in the brief as "perp moved X ETH to WETH
    #     contract", reading like an outflow when nothing left their
    #     control
    #   * dead-ended BFS at the wrap contract (`stop_at_contract`)
    #
    # The fix: drop transfers to canonical wrapper contracts at the
    # adapter level. The subsequent WETH-token activity (which IS a
    # real laundering move when forwarded to another wallet/router)
    # captures the trace cleanly.
    #
    # Lowercased EVM hex for case-insensitive lookup.
    _WRAPPED_NATIVE_CONTRACTS: frozenset[str] = frozenset({
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH (Ethereum)
        "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",  # WETH (Arbitrum)
        "0x4200000000000000000000000000000000000006",  # WETH (Base / Optimism)
        "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",  # WMATIC (Polygon, legacy)
        "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",  # WBNB (BSC)
        "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7",  # WAVAX (Avalanche)
        "0xfa9343c3897324496a05fc75abed6bac29f8a40f",  # WMATIC (older BSC)
    })

    @classmethod
    def _is_wrap_deposit(cls, tx: dict[str, Any]) -> bool:
        """True if `tx` looks like a native-token wrap-deposit (e.g.,
        ETH → WETH.deposit()). Filtered as a no-op outflow for
        laundering-analysis purposes. See _WRAPPED_NATIVE_CONTRACTS
        docstring for the rationale.
        """
        to_addr = (tx.get("to") or "").lower()
        return to_addr in cls._WRAPPED_NATIVE_CONTRACTS

    @staticmethod
    def _is_failed_tx(tx: dict[str, Any]) -> bool:
        """True if Etherscan signals this row was a reverted transaction.

        Etherscan reports two independent fields, both must be honored:
          * `isError == "1"`   — txlist/internal/tokentx surface this
          * `txreceipt_status == "0"` — canonical receipt revert flag,
            set independently when the parent tx ran out of gas mid-call

        Pre-v0.16.7 we checked `isError` ONLY on the native-outflow path
        (and not on the ERC-20 / tokentx path at all). Etherscan's
        `tokentx` does emit rows from reverted parent txs in rare cases
        when the trace recorded a Transfer event before the revert —
        those polluted USD totals as fake outflows. Surfaced in the
        round-9 forensic audit.
        """
        if str(tx.get("isError", "")).strip() == "1":
            return True
        if str(tx.get("txreceipt_status", "")).strip() == "0":
            return True
        return False

    def fetch_native_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        addr = to_checksum_address(from_address)
        addr_l = addr.lower()
        client_side_filter = self._needs_client_side_start_block_filter()
        api_start = 0 if client_side_filter else start_block
        normal = self.client.get_normal_transactions(addr, start_block=api_start)
        internal = self.client.get_internal_transactions(addr, start_block=api_start)

        def _keep(tx: dict[str, Any]) -> bool:
            from_l = tx.get("from", "").lower()
            to_l = tx.get("to", "").lower()
            if from_l != addr_l:
                return False
            # v0.18.0 (round-11 chains-CRIT-001): contract-creation tx
            # has empty `to` and populates `contractAddress` instead.
            # Pre-v0.18.0 `_normalize_native` would call
            # `to_checksum_address("")` → eth_utils.InvalidAddress
            # → the entire fetch_native_outflows loop aborted with an
            # uncaught exception → trace silently returned 0 outflows
            # for the seed. Any seed wallet that ever deployed a
            # contract was effectively un-traceable.
            #
            # Skip contract-creation txs from the outflow list. The
            # forensic significance is "victim deployed a contract"
            # — not a money-flow event. Future enhancement could
            # surface these as a separate signal.
            if not to_l or to_l == "0x":
                return False
            # v0.16.11: drop wrap-deposit transfers. ETH → WETH contract
            # is the depositor wrapping into IOU form; the subsequent
            # WETH-token outflow already captures the real movement.
            if self._is_wrap_deposit(tx):
                return False
            # Drop self-transfers: from == to is a no-op for laundering analysis
            # (wallet reshuffles, gas top-ups inside a smart-account). Including
            # them inflates USD totals with zero-economic-value transfers.
            if from_l and to_l and from_l == to_l:
                return False
            if int(tx.get("value", "0")) == 0:
                return False
            if self._is_failed_tx(tx):
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
        addr_l = addr.lower()
        client_side_filter = self._needs_client_side_start_block_filter()
        api_start = 0 if client_side_filter else start_block
        rows = self.client.get_erc20_transfers(addr, start_block=api_start)
        out: list[dict[str, Any]] = []
        for tx in rows:
            from_l = tx.get("from", "").lower()
            to_l = tx.get("to", "").lower()
            if from_l != addr_l:
                continue
            # Self-transfer filter (same rationale as native path).
            if from_l and to_l and from_l == to_l:
                continue
            # v0.16.11: drop UNWRAP transfers. WETH → WETH.contract is
            # withdrawing native ETH from the wrap — same depositor
            # still controls the funds, just in native form now. Same
            # semantic as wrap-deposit on the native path.
            if to_l in self._WRAPPED_NATIVE_CONTRACTS:
                continue
            # Reverted-tx filter — see _is_failed_tx docstring for why this
            # check was missing from the ERC-20 path pre-v0.16.7.
            if self._is_failed_tx(tx):
                continue
            # v0.16.8 (round-9 forensic HIGH): reject NFT-shaped rows on the
            # fungible-token path. Etherscan's tokentx endpoint returns
            # ERC-20 Transfer events, BUT some hybrid tokens (ERC-404,
            # certain NFT-fractional contracts) emit ERC-20-shaped events
            # alongside their NFT semantics. A `tokenID` field on the row
            # is a smoking gun — non-fungible tokens carry an ID, fungible
            # ones never do. Without this filter the fungible-amount math
            # would treat a single NFT as N*10^decimals tokens. ERC-721/
            # ERC-1155 forensic coverage requires the tokennfttx / token1155tx
            # endpoints (separate work item).
            if tx.get("tokenID") or tx.get("tokenId"):
                continue
            # Also reject rows that look like fee-on-transfer split-events
            # to the same destination — those carry value=0 most of the
            # time. value==0 is a no-op transfer either way.
            try:
                if int(tx.get("value", "0")) == 0:
                    continue
            except (TypeError, ValueError):
                continue
            if client_side_filter and int(tx.get("blockNumber", "0")) < start_block:
                continue
            try:
                out.append(self._normalize_erc20(tx))
            except ValueError as e:
                # Token row that we can't normalize (missing/invalid decimals,
                # malformed contract). Log + skip rather than killing the
                # whole outflow fetch for this address.
                log.warning(
                    "skipping ERC-20 row from %s tx=%s: %s",
                    from_l, tx.get("hash"), e,
                )
                continue
        return out

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        raw_tx = self.client.get_transaction_by_hash(tx_hash)
        raw_receipt = self.client.get_transaction_receipt(tx_hash)
        block_hex = raw_tx.get("blockNumber") or raw_receipt.get("blockNumber") or "0x0"
        block_number = int(block_hex, 16)
        raw_block = self.client.get_block_by_number(block_number, full_tx=False)
        block_time = datetime.fromtimestamp(int(raw_block.get("timestamp", "0x0"), 16), tz=UTC)
        return EvidenceReceipt(
            chain=self.chain, tx_hash=tx_hash, block_number=block_number, block_time=block_time,
            raw_transaction=raw_tx, raw_receipt=raw_receipt, raw_block_header=raw_block,
            fetched_at=datetime.now(UTC),
            fetched_from=self.profile.api_base,
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"{self.profile.explorer_base}/tx/{tx_hash}"

    def explorer_address_url(self, address: Address) -> str:
        return f"{self.profile.explorer_base}/address/{to_checksum_address(address)}"

    # ---------- Normalizers ----------

    @staticmethod
    def _decode_block_time(ts_raw: Any) -> datetime:
        """Decode an Etherscan-supplied timestamp safely.

        v0.16.10 (round-9 forensic LOW): reject implausible values
        before they land in case.json. A malformed/forged upstream
        response with `timeStamp=9999999999` (year 2286) was previously
        accepted blind, and the bad block_time would silently propagate
        into evidence and into the brief. Cap at "now + 1 day" to
        tolerate small clock skew while rejecting obvious garbage.
        """
        try:
            ts_int = int(ts_raw)
        except (TypeError, ValueError) as e:
            raise ValueError(f"non-integer timeStamp: {ts_raw!r}") from e
        if ts_int < 0:
            raise ValueError(f"negative timeStamp: {ts_int}")
        block_time = datetime.fromtimestamp(ts_int, tz=UTC)
        # Allow a 24h forward window for clock-skew tolerance.
        if block_time > datetime.now(UTC) + timedelta(days=1):
            raise ValueError(
                f"future timeStamp {block_time.isoformat()} (>{ts_int}) — "
                "upstream response likely tampered"
            )
        return block_time

    def _normalize_native(self, tx: dict[str, Any], source: str) -> dict[str, Any]:
        block_number = int(tx["blockNumber"])
        block_time = self._decode_block_time(tx["timeStamp"])
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
        block_time = self._decode_block_time(tx["timeStamp"])
        # tokenDecimal: refuse to guess. Etherscan returns "" on rare tokens it
        # hasn't enriched; pre-v0.16.7 we defaulted to 18 which silently
        # divides a 6-decimal token (USDC/USDT) by 10^12 — the amount_decimal
        # column would be wrong by 12 orders of magnitude. The downstream USD
        # sanity ceiling occasionally catches this, but the underlying case
        # data still ships the wrong amount.
        decimals_raw = tx.get("tokenDecimal")
        if decimals_raw in (None, "", b""):
            # Mark the transfer with a sentinel so the tracer can either skip
            # or surface as a pricing/decimal error rather than guess. Using
            # 18 as a placeholder here would propagate silently downstream.
            raise ValueError(
                f"etherscan_erc20: missing tokenDecimal for contract "
                f"{tx.get('contractAddress')!r} (tx {tx.get('hash')!r}); "
                "refusing to assume 18-decimal default"
            )
        try:
            decimals = int(decimals_raw)
        except (TypeError, ValueError) as e:
            raise ValueError(
                f"etherscan_erc20: invalid tokenDecimal {decimals_raw!r} for "
                f"contract {tx.get('contractAddress')!r}"
            ) from e
        token = TokenRef(
            chain=self.chain,
            contract=to_checksum_address(tx["contractAddress"]),
            symbol=tx.get("tokenSymbol", "?") or "?",
            decimals=decimals,
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
