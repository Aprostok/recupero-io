"""Address inspector implementation.

Designed to be cheap: 3-5 Etherscan calls per inspection, all cacheable.
Never raises on chain errors — returns a partial profile with the fields it
managed to populate. Investigators always get *something*.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from eth_utils import to_checksum_address

from recupero.chains.base import ChainAdapter
from recupero.chains.ethereum.adapter import EthereumAdapter
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.inspect.profile import AddressProfile, CounterpartyStat
from recupero.labels.store import LabelStore
from recupero.models import Address, Chain, LabelCategory

log = logging.getLogger(__name__)

DEFAULT_WINDOW = 1000      # tx count for normal inspection
DEEP_WINDOW = 10_000       # tx count when --deep is requested


def inspect_address(
    *,
    address: Address,
    chain: Chain,
    config: RecuperoConfig,
    env: RecuperoEnv,
    label_store: LabelStore | None = None,
    window: int = DEFAULT_WINDOW,
) -> AddressProfile:
    """Profile an address. Best-effort — partial output on partial failure."""
    if chain != Chain.ethereum:
        raise NotImplementedError(f"Inspector currently supports Ethereum only (got {chain})")

    adapter: EthereumAdapter = ChainAdapter.for_chain(chain, (config, env))  # type: ignore[assignment]
    label_store = label_store or LabelStore.load(config)

    addr = to_checksum_address(address)
    log.info("inspecting %s on %s (window=%d)", addr, chain.value, window)

    # 1. Existing label
    existing_label = label_store.lookup(addr, chain=chain)

    # 2. Contract / EOA
    is_contract = False
    contract_name: str | None = None
    contract_proxy = False
    try:
        is_contract = adapter.is_contract(addr)
    except Exception as e:  # noqa: BLE001
        log.warning("is_contract check failed: %s", e)

    if is_contract:
        try:
            meta = adapter.client.get_contract_source(addr)
            if isinstance(meta, dict):
                contract_name = (meta.get("ContractName") or "").strip() or None
                contract_proxy = meta.get("Proxy") == "1"
        except Exception as e:  # noqa: BLE001
            log.debug("get_contract_source failed: %s", e)

    # 3. ETH balance
    eth_balance_wei: int | None = None
    eth_balance: Decimal | None = None
    try:
        eth_balance_wei = adapter.client.get_eth_balance(addr)
        eth_balance = Decimal(eth_balance_wei) / Decimal(10**18)
    except Exception as e:  # noqa: BLE001
        log.debug("get_eth_balance failed: %s", e)

    # 4. Activity window — pull recent txs (sort desc) for last_seen + counterparty analysis
    recent_txs: list[dict[str, Any]] = []
    try:
        recent_txs = adapter.client.get_normal_transactions(
            addr, start_block=0, page=1, offset=min(window, 10_000)
        )
        # Etherscan returns asc=oldest-first; for "recent" we want desc, but the
        # client's wrapper hard-codes asc. Workaround: take all and rely on the
        # last entries for "recent". For window=1000 this is plenty.
    except Exception as e:  # noqa: BLE001
        log.warning("get_normal_transactions failed: %s", e)

    observed_tx_count = len(recent_txs)
    observed_tx_count_capped = observed_tx_count >= min(window, 10_000)

    # 5. First / last seen — derived from the recent_txs list (sorted asc)
    first_seen_block: int | None = None
    first_seen_at: datetime | None = None
    last_seen_block: int | None = None
    last_seen_at: datetime | None = None
    if recent_txs:
        try:
            first_seen_block = int(recent_txs[0]["blockNumber"])
            first_seen_at = datetime.fromtimestamp(int(recent_txs[0]["timeStamp"]), tz=timezone.utc)
            last_seen_block = int(recent_txs[-1]["blockNumber"])
            last_seen_at = datetime.fromtimestamp(int(recent_txs[-1]["timeStamp"]), tz=timezone.utc)
        except (KeyError, ValueError, TypeError) as e:
            log.debug("could not parse tx timestamps: %s", e)

    # 6. Top counterparties — count occurrences of "the other side" of each tx
    cp_counter: Counter[str] = Counter()
    for tx in recent_txs:
        try:
            from_addr = to_checksum_address(tx["from"])
            to_addr = to_checksum_address(tx["to"]) if tx.get("to") else None
        except (KeyError, ValueError):
            continue
        if to_addr is None:  # contract creation
            continue
        other = to_addr if from_addr.lower() == addr.lower() else from_addr
        if other.lower() == addr.lower():
            continue  # self-tx, ignore
        cp_counter[other] += 1

    top_counterparties: list[CounterpartyStat] = []
    for cp_addr, count in cp_counter.most_common(5):
        cp_label = label_store.lookup(cp_addr, chain=chain)
        top_counterparties.append(CounterpartyStat(
            address=cp_addr,
            tx_count=count,
            label=cp_label,
            is_contract=None,  # not worth extra API calls; CLI can show on demand
        ))

    # 7. Identity heuristic
    likely_identity, likely_reason = _guess_identity(
        is_contract=is_contract,
        contract_name=contract_name,
        existing_label=existing_label,
        top_counterparties=top_counterparties,
        observed_tx_count=observed_tx_count,
        capped=observed_tx_count_capped,
    )

    return AddressProfile(
        address=addr,
        chain=chain,
        is_contract=is_contract,
        contract_name=contract_name,
        contract_proxy=contract_proxy,
        existing_label=existing_label,
        first_seen_block=first_seen_block,
        first_seen_at=first_seen_at,
        last_seen_block=last_seen_block,
        last_seen_at=last_seen_at,
        observed_tx_count=observed_tx_count,
        observed_tx_count_capped=observed_tx_count_capped,
        eth_balance_wei=eth_balance_wei,
        eth_balance=eth_balance,
        top_counterparties=top_counterparties,
        likely_identity=likely_identity,
        likely_identity_reason=likely_reason,
        inspected_at=datetime.now(timezone.utc),
        explorer_url=adapter.explorer_address_url(addr),
        inspection_window_size=window,
    )


def _guess_identity(
    *,
    is_contract: bool,
    contract_name: str | None,
    existing_label,
    top_counterparties: list[CounterpartyStat],
    observed_tx_count: int,
    capped: bool,
) -> tuple[str | None, str | None]:
    """Tiny heuristic. Returns (identity, reason) or (None, None).

    Deliberately conservative — we'd rather say nothing than guess wrong.
    """
    # 1. Existing label always wins
    if existing_label is not None:
        return (existing_label.name, f"already labeled in our database ({existing_label.source})")

    # 2. Verified contract name is reliable
    if is_contract and contract_name:
        return (contract_name, "verified contract on Etherscan")

    # 3. Counterparty signal — useful for unlabeled CEX deposits especially
    if top_counterparties:
        labeled_top = [c for c in top_counterparties if c.label is not None]
        if labeled_top:
            top = labeled_top[0]
            if top.label and top.label.category in (
                LabelCategory.exchange_hot_wallet,
                LabelCategory.exchange_deposit,
            ):
                ex = top.label.exchange or "an exchange"
                share = top.tx_count / max(observed_tx_count, 1)
                if share > 0.5:
                    return (
                        f"likely {ex} deposit address",
                        f"{int(share*100)}% of recent activity is with {top.label.name}",
                    )

    # 4. Volume signal
    if capped or observed_tx_count >= 5000:
        kind = "infrastructure contract" if is_contract else "high-volume EOA"
        return (
            f"high-activity {kind}",
            f"{observed_tx_count}+ transactions observed — likely a service or trading address",
        )

    # 5. New / fresh address
    if observed_tx_count <= 5 and not is_contract:
        return (
            "newly active EOA",
            "very few transactions observed — possibly fresh wallet, mule, or recently created",
        )

    return (None, None)
