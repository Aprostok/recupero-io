"""Dormant wallet detection.

Given a case file produced by `recupero trace`, identify destination addresses
that:
  - Received money during the trace
  - Still hold meaningful USD value as of right now (current on-chain balance)
  - Haven't sent it onward (or last activity is older than a threshold)

These are the freeze targets. For Zigha-style cases this surfaces wallets like
0x3e2E66af... ($3.12M mSyrupUSDp dormant), 0x3daFC6a8... ($9.98M DAI dormant),
0x415D8D07... ($6.91M DAI dormant) — the addresses worth contacting issuers about.

Output is a ranked list (highest USD first) suitable for human review and
inclusion in a freeze brief.

Phase 1 is Ethereum-only — Etherscan provides simple balance endpoints. Solana
balance fetching via Helius is a follow-up; same for Arbitrum/BSC (Etherscan V2
supports them via the same endpoints).
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

from recupero.chains.ethereum.adapter import EthereumAdapter
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Case, Chain, LabelCategory, TokenRef
from recupero.pricing.coingecko import CoinGeckoClient

# Per-address dormant checks fan out to N threads concurrently. Each
# thread does its 7 token-balance Etherscan calls + price lookups
# serially within itself; parallelism is across addresses. Both
# EtherscanClient and CoinGeckoClient have thread-safe internal
# rate-limiters (with locks), so global throughput stays under the
# per-key rate caps regardless of thread count. 5 is a safe default —
# higher values produce diminishing returns once the rate limit caps
# the throughput.
_DORMANT_CONCURRENCY = int(os.environ.get("RECUPERO_DORMANT_CONCURRENCY", "5"))


# Categories where the address itself is custodial infrastructure for
# many users — protocol contracts, exchange hot wallets, OTC desks,
# bridges, mixers. The on-chain balance there reflects the public
# infrastructure's holdings, not the perpetrator's. Querying these
# wallets' issuer-token balances produces large false-positive freeze
# targets (Uniswap V4 with $97M USDC, Binance hot wallet with $54M
# USDT, etc.). Always exclude from the candidate set.
_SERVICE_CATEGORIES: frozenset[LabelCategory] = frozenset({
    LabelCategory.exchange_deposit,
    LabelCategory.exchange_hot_wallet,
    LabelCategory.bridge,
    LabelCategory.mixer,
    LabelCategory.defi_protocol,
    LabelCategory.staking,
})

# NOTE: ``recupero.freeze.asks.load_issuer_db`` is intentionally imported
# lazily inside ``_build_issuer_token_refs`` rather than at module top
# level. ``freeze.asks`` already imports ``DormantCandidate`` /
# ``TokenHolding`` from this module, so a top-level import here would
# form a circular import (the symptom is an ImportError that surfaces
# only on cold-start, not in dev where caches sometimes paper over it).

log = logging.getLogger(__name__)


# Stablecoins / freezable tokens we always check, even if the trace
# only saw a different token flow into the candidate. Real perpetrators
# consolidate stolen value across multiple tokens — a wallet that
# received $20 USDC dust from this victim might be holding $250k USDT
# from other sources. We want the full freezable picture per wallet.
# Decimals match the on-chain ERC-20 metadata; symbols are canonical.
_DEFAULT_FREEZABLE_TOKEN_DECIMALS: dict[Chain, list[tuple[str, int]]] = {
    Chain.ethereum: [
        # (symbol, decimals) — contract addresses come from the issuer DB.
        ("USDC", 6),
        ("USDT", 6),
        ("DAI", 18),
        ("BUSD", 18),
        ("PYUSD", 6),
        ("FDUSD", 18),
        ("TUSD", 18),
    ],
}


def _build_issuer_token_refs(chain: Chain) -> list[TokenRef]:
    """Build a TokenRef list for every issuer-controlled token on ``chain``.

    Reads contract addresses from the issuer DB so we don't hard-code
    them in two places. Returns refs with normalized symbol + decimals
    suitable for handing to ``EthereumAdapter`` for balance queries.
    """
    # Lazy import to avoid circular dependency with freeze.asks
    # (which imports DormantCandidate/TokenHolding from this module).
    try:
        from recupero.freeze.asks import load_issuer_db
        db = load_issuer_db()
    except Exception as e:  # noqa: BLE001
        log.warning("could not load issuer DB; freezable-token sweep disabled: %s", e)
        return []

    decimals_by_symbol = {
        sym: dec for sym, dec in _DEFAULT_FREEZABLE_TOKEN_DECIMALS.get(chain, [])
    }
    refs: list[TokenRef] = []
    seen: set[str] = set()
    for (entry_chain, contract_lower), entry in db.items():
        if entry_chain != chain:
            continue
        if contract_lower in seen:
            continue
        seen.add(contract_lower)
        # Match the issuer DB's symbol back to a known decimal; fall
        # back to 18 if we don't have it (almost always wrong but
        # better than failing — operator will see odd amounts).
        decimals = decimals_by_symbol.get(entry.symbol.upper(), 18)
        refs.append(TokenRef(
            chain=chain,
            contract=contract_lower,
            symbol=entry.symbol.upper(),
            decimals=decimals,
        ))
    return refs


@dataclass
class TokenHolding:
    """Single-token balance snapshot for a wallet."""
    token: TokenRef
    raw_amount: int
    decimal_amount: Decimal
    usd_value: Decimal | None
    pricing_error: str | None = None


@dataclass
class DormantCandidate:
    """A wallet that still holds meaningful value at current prices."""
    address: str
    chain: Chain
    total_usd: Decimal
    holdings: list[TokenHolding] = field(default_factory=list)
    inflow_usd_during_case: Decimal = Decimal("0")  # how much came in via the case's traces
    inflow_count: int = 0
    explorer_url: str = ""

    def top_holding_summary(self, n: int = 3) -> str:
        """Human-readable summary of the top N holdings by USD value."""
        ranked = sorted(self.holdings, key=lambda h: h.usd_value or Decimal("0"), reverse=True)
        parts = []
        for h in ranked[:n]:
            usd = f"${h.usd_value:,.2f}" if h.usd_value is not None else "?"
            parts.append(f"{h.decimal_amount:,.4f} {h.token.symbol} ({usd})")
        return ", ".join(parts) if parts else "(no holdings)"


def find_dormant_in_case(
    *,
    case: Case,
    config: RecuperoConfig,
    env: RecuperoEnv,
    min_usd: Decimal = Decimal("10000"),
) -> list[DormantCandidate]:
    """Inspect each address that received funds in the case and return a list
    of those still holding >= min_usd at current prices.

    Strategy:
      1. From the case's transfers, collect every (to_address, token) pair.
      2. For each address, query current native balance + each token balance.
      3. Price each holding at today's USD price.
      4. Filter to addresses with total_usd >= min_usd.
      5. Sort by total_usd desc.

    Only the chain of the case is queried (mixed-chain cases would need
    per-chain dispatch — out of scope for now).
    """
    if case.chain != Chain.ethereum:
        # Phase 1: only Ethereum. Solana / Arbitrum / BSC support is a follow-up.
        log.warning(
            "dormant detection currently supports Ethereum only; case is %s. "
            "Returning empty list.",
            case.chain.value,
        )
        return []

    adapter = EthereumAdapter((config, env))
    cache_dir = Path(config.storage.data_dir) / "prices_cache"
    price_client = CoinGeckoClient(config, env, cache_dir)

    # Build per-address: a dict of contract_lower → TokenRef (one per unique
    # token to query) plus per-address inflow totals from the case's transfers.
    # We use dict-keyed-by-contract because TokenRef isn't hashable (Pydantic),
    # and "all the same contract" should resolve to one balance check anyway.
    address_tokens: dict[str, dict[str, TokenRef]] = {}
    address_inflow: dict[str, Decimal] = {}
    address_inflow_count: dict[str, int] = {}
    seed_addr_lower = case.seed_address.lower()
    skipped_contracts: set[str] = set()
    skipped_service_labels: dict[str, str] = {}

    for tr in case.transfers:
        # Only consider on-chain destination addresses.
        # Skip the seed itself (we don't freeze the victim).
        # Skip addresses with placeholder labels like "hyperliquid:unknown_*"
        dest = tr.to_address
        if not dest or dest.startswith("hyperliquid:") or not dest.startswith("0x"):
            continue
        dest_lower = dest.lower()
        if dest_lower == seed_addr_lower:
            continue

        # Filter out service / public-infrastructure addresses BEFORE
        # querying their balances. Without this, the dormant detector
        # surfaces things like Uniswap V4 PoolManager ($97M USDC), Binance
        # hot wallets ($54M USDT), etc. as "freezable" — those balances
        # belong to the public infrastructure, not the perpetrator.
        cp = tr.counterparty
        if cp.is_contract:
            skipped_contracts.add(dest)
            continue
        if cp.label is not None and cp.label.category in _SERVICE_CATEGORIES:
            skipped_service_labels.setdefault(
                dest, f"{cp.label.category.value}:{cp.label.name}"
            )
            continue

        bucket = address_tokens.setdefault(dest, {})
        # Native (contract=None) → use a fixed key so we don't double-add it
        token_key = (tr.token.contract or "__native__").lower()
        bucket.setdefault(token_key, tr.token)
        if tr.usd_value_at_tx is not None:
            address_inflow[dest] = address_inflow.get(dest, Decimal("0")) + tr.usd_value_at_tx
        address_inflow_count[dest] = address_inflow_count.get(dest, 0) + 1

    if skipped_contracts:
        log.info(
            "dormant: filtered %d contract address(es) from candidate set "
            "(public-infrastructure balances are not perpetrator funds): %s",
            len(skipped_contracts),
            ", ".join(sorted(skipped_contracts)[:5])
            + ("…" if len(skipped_contracts) > 5 else ""),
        )
    if skipped_service_labels:
        log.info(
            "dormant: filtered %d service-labeled address(es): %s",
            len(skipped_service_labels),
            ", ".join(f"{a} ({label})"
                      for a, label in list(skipped_service_labels.items())[:5])
            + ("…" if len(skipped_service_labels) > 5 else ""),
        )

    # ALSO check every known freezable issuer token on every candidate,
    # not just tokens observed in the trace. Real perpetrators
    # consolidate stolen funds across multiple tokens; a wallet that
    # received $20 USDC dust from this victim may be holding $250k USDT
    # from other victims. Without this sweep we'd silently miss the
    # bigger position. ~5-7 extra balance calls per address.
    issuer_token_refs = _build_issuer_token_refs(case.chain)
    if issuer_token_refs:
        for bucket in address_tokens.values():
            for ref in issuer_token_refs:
                token_key = (ref.contract or "__native__").lower()
                bucket.setdefault(token_key, ref)
        log.info(
            "dormant: also sweeping %d issuer-controlled tokens "
            "(%s) on every candidate",
            len(issuer_token_refs),
            ", ".join(t.symbol for t in issuer_token_refs),
        )

    log.info(
        "dormant: %d unique destination addresses to inspect (%d unique tokens total)",
        len(address_tokens), sum(len(d) for d in address_tokens.values()),
    )

    # Parallel fan-out across addresses. Each worker thread runs the
    # full _check_one_address sequence (token balances + pricing +
    # filter) for one candidate. The rate limiters in EtherscanClient
    # and CoinGeckoClient enforce global per-key caps, so adding more
    # threads can't violate the API's rate limits.
    candidates: list[DormantCandidate] = []
    total_n = len(address_tokens)
    completed = 0

    def _check(address: str, tokens: list[TokenRef]) -> DormantCandidate | None:
        return _check_one_address(
            address=address,
            tokens=tokens,
            adapter=adapter,
            price_client=price_client,
            chain=case.chain,
            min_usd=min_usd,
            inflow_usd=address_inflow.get(address, Decimal("0")),
            inflow_count=address_inflow_count.get(address, 0),
        )

    if total_n == 0:
        pass  # nothing to do
    elif _DORMANT_CONCURRENCY <= 1 or total_n == 1:
        # Single-threaded path — keeps test determinism and avoids
        # threadpool overhead for tiny cases.
        for idx, (address, token_dict) in enumerate(address_tokens.items(), start=1):
            log.info("dormant #%d/%d: %s (%d tokens)", idx, total_n, address, len(token_dict))
            try:
                cand = _check(address, list(token_dict.values()))
                if cand is not None:
                    candidates.append(cand)
            except Exception as e:  # noqa: BLE001
                log.warning("dormant: balance fetch failed for %s: %s — skipping", address, e)
    else:
        with ThreadPoolExecutor(
            max_workers=_DORMANT_CONCURRENCY, thread_name_prefix="dormant"
        ) as pool:
            futures = {
                pool.submit(_check, address, list(token_dict.values())): address
                for address, token_dict in address_tokens.items()
            }
            for fut in as_completed(futures):
                address = futures[fut]
                completed += 1
                try:
                    cand = fut.result()
                except Exception as e:  # noqa: BLE001
                    log.warning("dormant: balance fetch failed for %s: %s — skipping", address, e)
                    continue
                log.info("dormant %d/%d done: %s", completed, total_n, address)
                if cand is not None:
                    candidates.append(cand)

    price_client.close()
    candidates.sort(key=lambda c: c.total_usd, reverse=True)
    log.info(
        "dormant: %d candidates with total holdings >= $%s",
        len(candidates), min_usd,
    )
    return candidates


def _check_one_address(
    *,
    address: str,
    tokens: list[TokenRef],
    adapter: EthereumAdapter,
    price_client: CoinGeckoClient,
    chain: Chain,
    min_usd: Decimal,
    inflow_usd: Decimal,
    inflow_count: int,
) -> DormantCandidate | None:
    """Per-address worker run by the thread pool: balance sweep + filter.

    Returns a DormantCandidate if total holdings ≥ min_usd, else None.
    Logs balance/inflow ratio warnings for service-like wallets so the
    AI editorial picks them up via the same signal in the prompt
    summary and downgrades to 🟧 INVESTIGATE.

    All Etherscan / CoinGecko calls inside _fetch_holdings respect the
    global rate-limiters in their respective clients; running multiple
    instances of this function in parallel can't exceed the per-key cap.
    """
    holdings = _fetch_holdings(address, tokens, adapter, price_client)
    total_usd = sum(
        (h.usd_value for h in holdings if h.usd_value is not None),
        start=Decimal("0"),
    )
    if total_usd < min_usd:
        log.debug("dormant: %s holds $%s — below threshold $%s",
                  address, total_usd, min_usd)
        return None

    if inflow_usd > 0:
        ratio = total_usd / inflow_usd
        if ratio > 100:
            log.warning(
                "dormant: %s has balance/inflow ratio %.1fx "
                "(holds $%s, inflow from this case $%s) — likely "
                "consolidates from many sources; expect AI to mark "
                "INVESTIGATE rather than FREEZABLE",
                address, ratio, total_usd, inflow_usd,
            )

    return DormantCandidate(
        address=address,
        chain=chain,
        total_usd=total_usd,
        holdings=holdings,
        inflow_usd_during_case=inflow_usd,
        inflow_count=inflow_count,
        explorer_url=adapter.explorer_address_url(address),
    )


def _fetch_holdings(
    address: str,
    tokens: list[TokenRef],
    adapter: EthereumAdapter,
    price_client: CoinGeckoClient,
) -> list[TokenHolding]:
    """Fetch current balance for each (address, token) pair and price them."""
    holdings: list[TokenHolding] = []
    for token in tokens:
        if token.contract is None:
            continue  # native handled below in unified path
        try:
            raw = adapter.client.get_token_balance(token.contract, address)
        except Exception as e:  # noqa: BLE001
            log.debug("token balance failed for %s on %s: %s", token.symbol, address, e)
            continue
        if raw == 0:
            continue
        decimal_amount = Decimal(raw) / Decimal(10 ** token.decimals)
        price = price_client.price_now(token)
        usd = (price.usd_value * decimal_amount) if price.usd_value is not None else None
        holdings.append(TokenHolding(
            token=token, raw_amount=raw, decimal_amount=decimal_amount,
            usd_value=usd, pricing_error=price.error,
        ))

    # Always check native ETH (any address might still hold gas dust or more)
    try:
        eth_raw = adapter.client.get_eth_balance(address)
    except Exception as e:  # noqa: BLE001
        log.debug("native balance failed for %s: %s", address, e)
        eth_raw = 0
    if eth_raw > 0:
        eth_token = TokenRef(
            chain=Chain.ethereum, contract=None,
            symbol="ETH", decimals=18, coingecko_id="ethereum",
        )
        eth_decimal = Decimal(eth_raw) / Decimal(10 ** 18)
        price = price_client.price_now(eth_token)
        usd = (price.usd_value * eth_decimal) if price.usd_value is not None else None
        holdings.append(TokenHolding(
            token=eth_token, raw_amount=eth_raw, decimal_amount=eth_decimal,
            usd_value=usd, pricing_error=price.error,
        ))

    return holdings


def write_dormant_report(
    case_dir: Path, candidates: list[DormantCandidate]
) -> Path:
    """Write the dormant-targets list as JSON next to the case file."""
    import json
    path = case_dir / "dormant_targets.json"
    payload = {
        "candidates": [
            {
                "address": c.address,
                "chain": c.chain.value,
                "total_usd": str(c.total_usd),
                "inflow_usd_during_case": str(c.inflow_usd_during_case),
                "inflow_count": c.inflow_count,
                "explorer_url": c.explorer_url,
                "holdings": [
                    {
                        "symbol": h.token.symbol,
                        "contract": h.token.contract,
                        "decimal_amount": str(h.decimal_amount),
                        "raw_amount": str(h.raw_amount),
                        "usd_value": str(h.usd_value) if h.usd_value is not None else None,
                        "pricing_error": h.pricing_error,
                    }
                    for h in c.holdings
                ],
            }
            for c in candidates
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
