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
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from eth_utils import to_checksum_address

from recupero.chains.base import ChainAdapter
from recupero.chains.ethereum.etherscan import EtherscanClient
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)

# v0.34: Etherscan V2 client requests/second, configurable so a paid API tier
# can be driven at its full throughput. The default (4.0) is the free-tier-safe
# value the tracer has always used — DELIBERATELY not raised, because live runs
# show 4.0 already brushes the free tier's limit (it triggers backoff/retry);
# raising the default would cause MORE 429s -> more backoff -> a SLOWER trace
# for free-tier users. Paid users set ``RECUPERO_ETHERSCAN_RPS`` (e.g. 15-20 on
# a ~20 rps plan) to actually use the headroom they pay for. The limiter is
# shared across all wave threads of one chain adapter, so this is the COMBINED
# per-chain rps, not per-thread.
_DEFAULT_ETHERSCAN_RPS = 4.0
_MAX_ETHERSCAN_RPS = 50.0


def _resolve_etherscan_rps() -> float:
    """Resolve the Etherscan rps from ``RECUPERO_ETHERSCAN_RPS`` (float),
    falling back to the free-tier-safe default. Clamped to (0, 50]; a missing
    / empty / non-numeric / non-positive value yields the default."""
    raw = os.environ.get("RECUPERO_ETHERSCAN_RPS")
    if raw is None or not raw.strip():
        return _DEFAULT_ETHERSCAN_RPS
    try:
        rps = float(raw)
    except (TypeError, ValueError):
        log.warning(
            "RECUPERO_ETHERSCAN_RPS=%r is not a number; using default %.1f",
            raw, _DEFAULT_ETHERSCAN_RPS,
        )
        return _DEFAULT_ETHERSCAN_RPS
    if not (rps > 0):
        log.warning(
            "RECUPERO_ETHERSCAN_RPS=%r must be > 0; using default %.1f",
            raw, _DEFAULT_ETHERSCAN_RPS,
        )
        return _DEFAULT_ETHERSCAN_RPS
    return min(rps, _MAX_ETHERSCAN_RPS)


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
        # v0.31.2 — 6 v0.29.0-promoted destination chains. Identical
        # profile shape; the chain-id parameter routes through Etherscan
        # V2 multichain.
        Chain.fantom:    "fantom",
        Chain.celo:      "celo",
        Chain.gnosis:    "gnosis",
        Chain.moonbeam:  "moonbeam",
        Chain.metis:     "metis",
        Chain.kava:      "kava",
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
            requests_per_second=_resolve_etherscan_rps(),
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
        return str(tx.get("txreceipt_status", "")).strip() == "0"

    def fetch_native_outflows(
        self, from_address: Address, start_block: int,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        addr = to_checksum_address(from_address)
        addr_l = addr.lower()
        client_side_filter = self._needs_client_side_start_block_filter()
        api_start = 0 if client_side_filter else start_block
        normal = self.client.get_normal_transactions(
            addr, start_block=api_start, max_results=max_results,
        )
        internal = self.client.get_internal_transactions(
            addr, start_block=api_start, max_results=max_results,
        )

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
            # RIGOR-Jacob X: defensive ``int()`` on untrusted fields.
            # Etherscan/Alchemy are external; a single row with
            # ``value="not-a-number"`` would otherwise raise
            # ValueError uncaught and kill the BFS hop.
            try:
                if int(tx.get("value", "0") or "0") == 0:
                    return False
            except (TypeError, ValueError):
                return False
            if self._is_failed_tx(tx):
                return False
            if client_side_filter:
                try:
                    if int(tx.get("blockNumber", "0") or "0") < start_block:
                        return False
                except (TypeError, ValueError):
                    return False
            return True

        out: list[dict[str, Any]] = []
        for tx in normal:
            if not _keep(tx):
                continue
            # RIGOR-Jacob N: per-row try/except so a single malformed
            # address (truncated, non-hex, garbage) from Etherscan
            # doesn't crash the whole loop via
            # ``to_checksum_address`` → InvalidAddress.
            try:
                out.append(self._normalize_native(tx, source="normal"))
            except Exception as e:  # noqa: BLE001
                log.warning(
                    "evm: dropping malformed native row tx=%s: %s",
                    tx.get("hash", "?"), e,
                )
                continue
        for tx in internal:
            if not _keep(tx):
                continue
            try:
                out.append(self._normalize_native(tx, source="internal"))
            except Exception as e:  # noqa: BLE001
                log.warning(
                    "evm: dropping malformed internal row tx=%s: %s",
                    tx.get("hash", "?"), e,
                )
                continue
        return out

    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        addr = to_checksum_address(from_address)
        addr_l = addr.lower()
        client_side_filter = self._needs_client_side_start_block_filter()
        api_start = 0 if client_side_filter else start_block
        rows = self.client.get_erc20_transfers(
            addr, start_block=api_start, max_results=max_results,
        )
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
                if int(tx.get("value", "0") or "0") == 0:
                    continue
            except (TypeError, ValueError):
                continue
            if client_side_filter:
                try:
                    if int(tx.get("blockNumber", "0") or "0") < start_block:
                        continue
                except (TypeError, ValueError):
                    continue
            # RIGOR-Jacob N: broad-except so a malformed
            # ``contractAddress`` (or ``to`` / ``from``) doesn't crash
            # the whole loop via eth_utils.InvalidAddress.
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
            except Exception as e:  # noqa: BLE001
                # InvalidAddress (eth_utils) and other adversarial
                # malformed-row failures land here.
                log.warning(
                    "skipping malformed ERC-20 row from %s tx=%s: %s",
                    from_l, tx.get("hash"), e,
                )
                continue
        return out

    # --- inbound transfer fetching (lock-and-mint cross-chain matching) ---
    #
    # v0.32.1 (trace-depth #1 wiring): the cross-chain lock-and-mint matcher
    # needs an address's INBOUND transfers on a candidate destination chain
    # (the mint/withdrawal side) to correlate against a source-chain bridge
    # deposit. These mirror the outflow methods exactly — same Etherscan
    # calls (which return txs in BOTH directions) — but keep rows where the
    # address is the RECIPIENT (`to == addr`) instead of the sender. They
    # reuse `_normalize_native` / `_normalize_erc20`, so the per-row
    # malformed-input hardening (RIGOR-Jacob N/X) applies identically.

    def fetch_native_inflows(
        self, to_address: Address, start_block: int,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Native-asset INBOUND transfers TO ``to_address`` since
        ``start_block``. Same normalized dict shape as
        ``fetch_native_outflows``."""
        addr = to_checksum_address(to_address)
        addr_l = addr.lower()
        client_side_filter = self._needs_client_side_start_block_filter()
        api_start = 0 if client_side_filter else start_block
        normal = self.client.get_normal_transactions(
            addr, start_block=api_start, max_results=max_results,
        )
        internal = self.client.get_internal_transactions(
            addr, start_block=api_start, max_results=max_results,
        )

        def _keep(tx: dict[str, Any]) -> bool:
            from_l = (tx.get("from", "") or "").lower()
            to_l = (tx.get("to", "") or "").lower()
            if to_l != addr_l:  # inbound: we must be the RECIPIENT
                return False
            if from_l and to_l and from_l == to_l:
                return False  # self-transfer: no economic movement
            try:
                if int(tx.get("value", "0") or "0") == 0:
                    return False
            except (TypeError, ValueError):
                return False
            if self._is_failed_tx(tx):
                return False
            if client_side_filter:
                try:
                    if int(tx.get("blockNumber", "0") or "0") < start_block:
                        return False
                except (TypeError, ValueError):
                    return False
            return True

        out: list[dict[str, Any]] = []
        for source, rows in (("normal", normal), ("internal", internal)):
            for tx in rows:
                if not _keep(tx):
                    continue
                try:
                    out.append(self._normalize_native(tx, source=source))
                except Exception as e:  # noqa: BLE001
                    log.warning(
                        "evm: dropping malformed inbound native row tx=%s: %s",
                        tx.get("hash", "?"), e,
                    )
                    continue
        return out

    def fetch_erc20_inflows(
        self, to_address: Address, start_block: int,
        *, max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Token INBOUND transfers TO ``to_address``. Same shape as
        ``fetch_erc20_outflows``."""
        addr = to_checksum_address(to_address)
        addr_l = addr.lower()
        client_side_filter = self._needs_client_side_start_block_filter()
        api_start = 0 if client_side_filter else start_block
        rows = self.client.get_erc20_transfers(
            addr, start_block=api_start, max_results=max_results,
        )
        out: list[dict[str, Any]] = []
        for tx in rows:
            from_l = (tx.get("from", "") or "").lower()
            to_l = (tx.get("to", "") or "").lower()
            if to_l != addr_l:  # inbound: we must be the RECIPIENT
                continue
            if from_l and to_l and from_l == to_l:
                continue
            if self._is_failed_tx(tx):
                continue
            if tx.get("tokenID") or tx.get("tokenId"):
                continue  # NFT-shaped row on the fungible path
            try:
                if int(tx.get("value", "0") or "0") == 0:
                    continue
            except (TypeError, ValueError):
                continue
            if client_side_filter:
                try:
                    if int(tx.get("blockNumber", "0") or "0") < start_block:
                        continue
                except (TypeError, ValueError):
                    continue
            try:
                out.append(self._normalize_erc20(tx))
            except ValueError as e:
                log.warning(
                    "skipping inbound ERC-20 row to %s tx=%s: %s",
                    to_l, tx.get("hash"), e,
                )
                continue
            except Exception as e:  # noqa: BLE001
                log.warning(
                    "skipping malformed inbound ERC-20 row to %s tx=%s: %s",
                    to_l, tx.get("hash"), e,
                )
                continue
        return out

    def fetch_logs(
        self,
        address: Address,
        topic0: str,
        *,
        from_block: int,
        to_block: int | str = "latest",
        topics: list[str | None] | None = None,
    ) -> list[dict[str, Any]]:
        """Etherscan v2 ``eth_getLogs`` for ``address`` + ``topic0`` over a block
        range, with optional additional indexed topic filters. Used by the
        bridge source↔destination pairing engine to find a destination fill
        event by its protocol order-id. Best-effort: any error / malformed body
        yields ``[]`` (the pairing then reports "unconfirmed" rather than
        raising).
        """
        def _blk(b: int | str) -> str:
            # Etherscan's logs/getLogs uses DECIMAL block numbers (not hex);
            # "latest" is accepted as a sentinel for the chain tip.
            if isinstance(b, str):
                return b
            return str(int(b))

        params: dict[str, str] = {
            "module": "logs",
            "action": "getLogs",
            "fromBlock": _blk(from_block),
            "toBlock": _blk(to_block),
            "topic0": topic0,
        }
        # address is optional: an empty address means "search all emitters"
        # (used by bridge-pairing for protocols with many per-token contracts,
        # disambiguated by a globally-unique indexed id topic).
        if address:
            params["address"] = address
        # topic1..topic3: Etherscan needs the topicX_Y_opr operator between
        # consecutive indexed topics. We only ever AND them.
        for i, t in enumerate((topics or []), start=1):
            if t is None or i > 3:
                continue
            params[f"topic{i}"] = t
            params[f"topic0_{i}_opr"] = "and"
        try:
            data = self.client._call(**params)
        except Exception as exc:  # noqa: BLE001 — pairing is best-effort
            log.warning("fetch_logs getLogs failed for %s: %s", address, exc)
            return []
        # _call normalizes "No records found" to {"result": []}; a real error
        # raised above. result is the list of log dicts.
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, list):
            return []
        return [lg for lg in result if isinstance(lg, dict)]

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        raw_tx = self.client.get_transaction_by_hash(tx_hash)
        raw_receipt = self.client.get_transaction_receipt(tx_hash)
        block_hex = raw_tx.get("blockNumber") or raw_receipt.get("blockNumber") or "0x0"
        # v0.32.1 (chain-audit): guard the hex/timestamp conversions. Unlike
        # the outflow path (which routes through _decode_block_time), this
        # was a bare int(...,16) + fromtimestamp — a tampered/garbage
        # blockNumber (non-hex) or an extreme timestamp ("0xffff...") would
        # raise ValueError/OverflowError. The tracer wraps this in a broad
        # except so it only drops one evidence receipt, but guard at source.
        try:
            block_number = int(block_hex, 16)
        except (TypeError, ValueError):
            block_number = 0
        raw_block = self.client.get_block_by_number(block_number, full_tx=False)
        try:
            block_time = datetime.fromtimestamp(
                int(raw_block.get("timestamp", "0x0"), 16), tz=UTC,
            )
        except (TypeError, ValueError, OverflowError, OSError):
            block_time = datetime.now(UTC)
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
        # RIGOR-Jacob J adversarial: ``datetime.fromtimestamp`` raises
        # OverflowError on values > datetime.MAX (~year 9999) BEFORE
        # the future-cap check below ever runs. A compromised Etherscan
        # response with timeStamp=999999999999999 would otherwise leak
        # OverflowError uncaught and kill the BFS hop. Map to the
        # documented ValueError contract.
        try:
            block_time = datetime.fromtimestamp(ts_int, tz=UTC)
        except (OverflowError, OSError, ValueError) as e:
            raise ValueError(
                f"out-of-range timeStamp: {ts_int} ({e})"
            ) from e
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
        # v0.32.1 (chain-audit cycle-2, parity with the Solana adapter):
        # clamp the attacker-influenceable `tokenDecimal` to the on-chain
        # u8 ceiling at the SOURCE so the value stored in TokenRef.decimals
        # can't blow up a downstream `10**decimals` (the tracer's
        # _build_transfer also clamps, but cex_continuity / dormant /
        # watch_tick read TokenRef.decimals directly).
        decimals = max(0, min(decimals, 255))
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
