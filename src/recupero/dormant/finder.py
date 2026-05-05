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
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

from recupero.chains.ethereum.adapter import EthereumAdapter
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Case, Chain, TokenRef
from recupero.pricing.coingecko import CoinGeckoClient

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
        bucket = address_tokens.setdefault(dest, {})
        # Native (contract=None) → use a fixed key so we don't double-add it
        token_key = (tr.token.contract or "__native__").lower()
        bucket.setdefault(token_key, tr.token)
        if tr.usd_value_at_tx is not None:
            address_inflow[dest] = address_inflow.get(dest, Decimal("0")) + tr.usd_value_at_tx
        address_inflow_count[dest] = address_inflow_count.get(dest, 0) + 1

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

    candidates: list[DormantCandidate] = []
    for idx, (address, token_dict) in enumerate(address_tokens.items(), start=1):
        log.info(
            "dormant #%d/%d: checking balances for %s (%d tokens)",
            idx, len(address_tokens), address, len(token_dict),
        )
        try:
            holdings = _fetch_holdings(address, list(token_dict.values()), adapter, price_client)
        except Exception as e:  # noqa: BLE001
            log.warning("dormant: balance fetch failed for %s: %s — skipping", address, e)
            continue

        total_usd = sum(
            (h.usd_value for h in holdings if h.usd_value is not None),
            start=Decimal("0"),
        )
        if total_usd < min_usd:
            log.debug("dormant: %s holds $%s — below threshold $%s", address, total_usd, min_usd)
            continue

        candidates.append(DormantCandidate(
            address=address,
            chain=case.chain,
            total_usd=total_usd,
            holdings=holdings,
            inflow_usd_during_case=address_inflow.get(address, Decimal("0")),
            inflow_count=address_inflow_count.get(address, 0),
            explorer_url=adapter.explorer_address_url(address),
        ))

    price_client.close()
    candidates.sort(key=lambda c: c.total_usd, reverse=True)
    log.info(
        "dormant: %d candidates with total holdings >= $%s",
        len(candidates), min_usd,
    )
    return candidates


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
