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
#
# Wave-9 audit (type-coercion): a malformed env var (``"five"``,
# ``""``, ``"-3"``) used to propagate ValueError out of the *import*
# itself — every CLI/worker entrypoint crashed at startup. Wrap in
# try/except and clamp to >= 1 so the module always imports cleanly
# regardless of operator typos / orchestrator quirks.
_DEFAULT_DORMANT_CONCURRENCY = 5


def _resolve_dormant_concurrency() -> int:
    raw = os.environ.get("RECUPERO_DORMANT_CONCURRENCY", "")
    if not raw:
        return _DEFAULT_DORMANT_CONCURRENCY
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_DORMANT_CONCURRENCY
    if n < 1:
        return _DEFAULT_DORMANT_CONCURRENCY
    return n


_DORMANT_CONCURRENCY = _resolve_dormant_concurrency()


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
# Per-symbol decimals for the issuer-token sweep. The dormant
# detector queries balances by raw-int amount; if decimals is wrong,
# the human-readable amount is off by orders of magnitude. The
# fallback at line ~122 was previously 18, which silently zeroed
# any 6-decimal (USDC-like) or 8-decimal (BTC-wrapped) token whose
# symbol wasn't listed here. Now exhaustive across every freezable
# token in issuers.json + standard L2 wrappers; also covers Arbitrum,
# Base, Polygon, BSC, Solana since real cases span chains.
_DEFAULT_FREEZABLE_TOKEN_DECIMALS: dict[Chain, list[tuple[str, int]]] = {
    Chain.ethereum: [
        # 6-decimal stablecoins
        ("USDC", 6),
        ("USDT", 6),
        ("PYUSD", 6),
        ("GUSD", 2),  # Gemini USD is actually 2 decimals
        # 18-decimal stablecoins
        ("DAI", 18),
        ("BUSD", 18),
        ("FDUSD", 18),
        ("TUSD", 18),
        ("USDS", 18),
        ("USDe", 18),
        ("crvUSD", 18),
        ("LUSD", 18),
        ("sUSD", 18),
        ("FRAX", 18),
        ("fxUSD", 18),
        # 8-decimal BTC wrappers (the silent-zero bug class)
        ("cbBTC", 8),
        ("WBTC", 8),
        ("tBTC", 18),  # tBTC is actually 18 decimals on Ethereum
        # 18-decimal LSTs
        ("stETH", 18),
        ("wstETH", 18),
        ("rETH", 18),
        ("sfrxETH", 18),
        # Midas wrappers
        ("mSyrupUSDp", 18),
        ("msyrupUSDp", 18),  # case-variation seen in seed file
    ],
    Chain.arbitrum: [
        ("USDC", 6), ("USDT", 6), ("DAI", 18),
        ("ARB", 18), ("WBTC", 8),
    ],
    Chain.base: [
        ("USDC", 6), ("USDbC", 6), ("DAI", 18), ("cbBTC", 8),
    ],
    Chain.polygon: [
        ("USDC", 6), ("USDT", 6), ("DAI", 18), ("WBTC", 8),
    ],
    Chain.bsc: [
        ("USDT", 18), ("USDC", 18), ("BUSD", 18), ("BTCB", 18),
    ],
    Chain.solana: [
        ("USDC", 6), ("USDT", 6), ("PYUSD", 6),
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

    decimals_by_symbol = dict(_DEFAULT_FREEZABLE_TOKEN_DECIMALS.get(chain, []))
    refs: list[TokenRef] = []
    seen: set[str] = set()
    for (entry_chain, contract_lower), entry in db.items():
        if entry_chain != chain:
            continue
        if contract_lower in seen:
            continue
        seen.add(contract_lower)
        # Match the issuer DB's symbol back to a known decimal. The
        # table above is now exhaustive across freezable issuers in
        # issuers.json. If a NEW issuer is added without a decimals
        # entry, we WARN loudly so the missing decimals get fixed
        # rather than silently dividing balances by 10^18 (the
        # historical pre-v0.16.6 default, which zeroed cbBTC/WBTC).
        symbol_upper = entry.symbol.upper()
        decimals = decimals_by_symbol.get(symbol_upper)
        if decimals is None:
            log.warning(
                "dormant token decimals: %s (chain=%s) missing from "
                "_DEFAULT_FREEZABLE_TOKEN_DECIMALS — falling back to 18. "
                "If this is a 6/8-decimal token, balance will be "
                "mis-divided. Add to the table.",
                symbol_upper, chain.value,
            )
            decimals = 18
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
    # v0.17.3 (round-10 audit HIGH): chain-aware adapter dispatch.
    # Pre-v0.17.3 hard-coded Ethereum-only gate at this line silently
    # returned [] for every non-Ethereum case — making the v0.16.7
    # expanded decimals table (which added Arb/Base/Polygon/BSC/Solana/
    # Tron tokens) entirely unreachable. The round-10 audit caught
    # this as a regression: the fix shipped the table without removing
    # the gate.
    from recupero.chains.base import ChainAdapter
    try:
        adapter = ChainAdapter.for_chain(case.chain, (config, env))
    except (NotImplementedError, Exception) as exc:  # noqa: BLE001
        log.warning(
            "dormant detection: no adapter for chain=%s (%s); "
            "returning empty list",
            case.chain.value, exc,
        )
        return []
    cache_dir = Path(config.storage.data_dir) / "prices_cache"
    price_client = CoinGeckoClient(config, env, cache_dir)

    # Build per-address: a dict of contract_lower → TokenRef (one per unique
    # token to query) plus per-address inflow totals from the case's transfers.
    # We use dict-keyed-by-contract because TokenRef isn't hashable (Pydantic),
    # and "all the same contract" should resolve to one balance check anyway.
    address_tokens: dict[str, dict[str, TokenRef]] = {}
    address_inflow: dict[str, Decimal] = {}
    address_inflow_count: dict[str, int] = {}
    # v0.20.2 (audit-round-2 finding #11): canonical key → display
    # address (first-seen original casing). Downstream DormantCandidate
    # rows carry the display form so EIP-55 mixed case survives into
    # freeze_asks.json and the operator-facing trace report; the
    # canonical key drives dedup so two case variants of the same
    # EVM destination collapse into one balance call.
    address_display: dict[str, str] = {}
    # v0.17.9 (round-10 forensic HIGH): canonical address keying so
    # base58 self-reference checks don't false-match on lowercase collision.
    from recupero._common import canonical_address_key as _ck
    seed_addr_lower = _ck(case.seed_address)
    skipped_service_labels: dict[str, str] = {}

    for tr in case.transfers:
        # Only consider on-chain destination addresses.
        # Skip the seed itself (we don't freeze the victim).
        # Skip addresses with placeholder labels like "hyperliquid:unknown_*"
        #
        # v0.17.3 (round-10 audit HIGH): the prior `not dest.startswith("0x")`
        # filter excluded Solana base58, Tron T-prefix, Bitcoin bc1q
        # addresses unconditionally — defeating the multi-chain adapter
        # dispatch above. Now: only skip the explicit Hyperliquid
        # sentinel placeholders, and let the per-chain adapter's
        # balance query decide whether the address is real.
        dest = tr.to_address
        if not dest or dest.startswith("hyperliquid:"):
            continue
        # Skip self-references (don't freeze the victim).
        dest_lower = _ck(dest)
        if dest_lower == seed_addr_lower:
            continue

        # Filter LABELED service / public-infrastructure addresses
        # (Uniswap V4 PoolManager, Binance hot wallets, etc.). Unlabeled
        # contracts are kept — they may be Safe / Gnosis Safe / smart-
        # account wallets controlled by the perpetrator. v0.16.6
        # widened the filter: pre-fix EVERY is_contract=True address
        # was excluded, hiding multi-sig perp wallets that hold real
        # freezable funds.
        cp = tr.counterparty
        if cp.label is not None and cp.label.category in _SERVICE_CATEGORIES:
            skipped_service_labels.setdefault(
                dest, f"{cp.label.category.value}:{cp.label.name}"
            )
            continue
        # Unlabeled contracts pass through. They get a balance check
        # like any other destination; if they hold no freezable
        # tokens, they're naturally filtered by the $10K threshold.

        # v0.20.2 (audit-round-2 finding #11): canonical-key the
        # destination dict-keys so two case variants of the same
        # EVM address don't get two separate buckets (which then
        # produced two duplicate dormant balance calls + two
        # duplicate freeze-ask candidates for one underlying
        # wallet). Base58 chains (Solana / Tron) preserve case via
        # canonical_address_key, so this is safe across the
        # multi-chain dispatch.
        dest_key = dest_lower  # already _ck(dest) from line above
        address_display.setdefault(dest_key, dest)
        bucket = address_tokens.setdefault(dest_key, {})
        # Native (contract=None) → use a fixed key so we don't double-add it.
        # v0.19.2 (round-13 type-HIGH-2): canonical_address_key — case-
        # preserves Solana / Tron base58 mints, lowercases EVM hex.
        # Pre-v0.19.2 `.lower()` mangled the mint to a non-on-chain
        # string; two on-chain mints whose lowercased forms collided
        # got merged into one bucket entry (silent forensic corruption).
        token_key = _ck(tr.token.contract) if tr.token.contract else "__native__"
        bucket.setdefault(token_key, tr.token)
        if tr.usd_value_at_tx is not None:
            address_inflow[dest_key] = (
                address_inflow.get(dest_key, Decimal("0")) + tr.usd_value_at_tx
            )
        address_inflow_count[dest_key] = (
            address_inflow_count.get(dest_key, 0) + 1
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
        # v0.19.2 (round-13 type-HIGH-2): canonical_address_key for the
        # second bucket-key compute, matching the trace-derived path.
        from recupero._common import canonical_address_key as _ck_ref
        for bucket in address_tokens.values():
            for ref in issuer_token_refs:
                token_key = _ck_ref(ref.contract) if ref.contract else "__native__"
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

    def _check(
        canon_key: str, display_addr: str, tokens: list[TokenRef]
    ) -> DormantCandidate | None:
        # v0.20.2 (audit-round-2 finding #11): pass the display
        # address (EIP-55 mixed-case for EVM, original casing for
        # base58) into _check_one_address so the DormantCandidate's
        # `address` field — which threads through to freeze_asks.json
        # and the trace report — preserves on-chain casing. Inflow
        # lookups use the canonical key, since address_inflow /
        # address_inflow_count are canonical-keyed.
        return _check_one_address(
            address=display_addr,
            tokens=tokens,
            adapter=adapter,
            price_client=price_client,
            chain=case.chain,
            min_usd=min_usd,
            inflow_usd=address_inflow.get(canon_key, Decimal("0")),
            inflow_count=address_inflow_count.get(canon_key, 0),
        )

    if total_n == 0:
        pass  # nothing to do
    elif _DORMANT_CONCURRENCY <= 1 or total_n == 1:
        # Single-threaded path — keeps test determinism and avoids
        # threadpool overhead for tiny cases.
        for idx, (canon_key, token_dict) in enumerate(address_tokens.items(), start=1):
            display_addr = address_display.get(canon_key, canon_key)
            log.info(
                "dormant #%d/%d: %s (%d tokens)",
                idx, total_n, display_addr, len(token_dict),
            )
            try:
                cand = _check(canon_key, display_addr, list(token_dict.values()))
                if cand is not None:
                    candidates.append(cand)
            except Exception as e:  # noqa: BLE001
                log.warning(
                    "dormant: balance fetch failed for %s: %s — skipping",
                    display_addr, e,
                )
    else:
        with ThreadPoolExecutor(
            max_workers=_DORMANT_CONCURRENCY, thread_name_prefix="dormant"
        ) as pool:
            futures = {
                pool.submit(
                    _check,
                    canon_key,
                    address_display.get(canon_key, canon_key),
                    list(token_dict.values()),
                ): address_display.get(canon_key, canon_key)
                for canon_key, token_dict in address_tokens.items()
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
    holdings = _fetch_holdings(address, tokens, adapter, price_client, chain=chain)
    # RIGOR-Jacob Z10: filter out holdings whose ``usd_value`` is
    # non-finite (NaN / Infinity) BEFORE aggregating. ``price_now``'s
    # cache is hardened against ``{"usd": "NaN"}`` corruption at the
    # read side, but adversarial-test fakes (and any future cache
    # backend that doesn't run the parser) could still produce a
    # poisoned Decimal here. ``NaN < min_usd`` is False so an
    # un-filtered NaN would pass the threshold, contaminate
    # ``DormantCandidate.total_usd``, and crash ``FreezeAsk.__post_init__``
    # mid-brief generation — a DoS on the freeze brief from an
    # attacker-controlled token contract.
    finite_holdings = []
    for h in holdings:
        if h.usd_value is None:
            finite_holdings.append(h)
            continue
        if not h.usd_value.is_finite():
            log.warning(
                "dormant: dropping holding %s on %s with non-finite "
                "usd_value=%r (cache poison / pricing corruption)",
                h.token.symbol, address, h.usd_value,
            )
            continue
        finite_holdings.append(h)
    holdings = finite_holdings
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
    chain: Chain = Chain.ethereum,
) -> list[TokenHolding]:
    """Fetch current balance for each (address, token) pair and price them.

    v0.18.0 (round-11 pricing-CRIT-005): `chain` parameter added so the
    native-balance check uses the chain's actual native asset (BNB on BSC,
    POL on Polygon, etc.) instead of hardcoding ETH. Defaults to ethereum
    for back-compat with callers that don't pass chain.
    """
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
        # RIGOR-Jacob Z10: guard the multiply against a non-finite
        # ``price.usd_value`` (cache poison / fake-test injection).
        # ``Decimal('NaN') * Decimal('1')`` raises ``InvalidOperation``
        # in the default Decimal context — which would propagate out
        # of ``_fetch_holdings`` and crash the per-address worker.
        # Treat poison as "no price available" so the holding still
        # surfaces in the audit list but contributes zero USD.
        if price.usd_value is None or not price.usd_value.is_finite():
            usd = None
        else:
            try:
                usd = price.usd_value * decimal_amount
                if not usd.is_finite():
                    usd = None
            except ArithmeticError:
                usd = None
        holdings.append(TokenHolding(
            token=token, raw_amount=raw, decimal_amount=decimal_amount,
            usd_value=usd, pricing_error=price.error,
        ))

    # v0.18.0 (round-11 pricing-CRIT-005): chain-aware native balance.
    # Pre-v0.18.0 this hardcoded ETH (chain=ethereum, decimals=18,
    # coingecko_id=ethereum) for every chain. Net effect on non-Ethereum:
    #   * BSC: BNB ($600-700 USD) priced as ETH ($2-3K USD) → 4-5× over
    #   * Polygon: POL ($0.30-0.50) priced as ETH → 6000-10000× over
    #   * Tron / Solana / Bitcoin: adapter.client.get_eth_balance
    #     AttributeErrors silently (`except Exception`) — bug masked,
    #     no native dormant detection on those chains
    # Now: dispatch to per-chain native-balance method + chain-appropriate
    # TokenRef. Best-effort: chains whose adapter doesn't expose a native
    # balance probe just skip the native check (consistent with old
    # masked behavior, but logged at debug).
    # `chain` was threaded through the kwarg above (default Chain.ethereum
    # for back-compat). For multi-chain dispatch the caller passes the
    # actual chain.
    _native = _fetch_native_holding(address, adapter, chain, price_client)
    if _native is not None:
        holdings.append(_native)

    return holdings


# Per-chain native-asset metadata. Used by _fetch_native_holding to
# build the correct TokenRef + decimals for the dormant detector's
# native balance check. Mirrors the per-chain fields in config.py's
# *Params classes (native_symbol / native_decimals / coingecko_native_id)
# without taking a config dependency here.
_NATIVE_BY_CHAIN: dict[Chain, dict[str, object]] = {
    Chain.ethereum: {"symbol": "ETH",  "decimals": 18, "cg": "ethereum"},
    Chain.arbitrum: {"symbol": "ETH",  "decimals": 18, "cg": "ethereum"},
    Chain.base:     {"symbol": "ETH",  "decimals": 18, "cg": "ethereum"},
    Chain.bsc:      {"symbol": "BNB",  "decimals": 18, "cg": "binancecoin"},
    Chain.polygon:  {"symbol": "POL",  "decimals": 18, "cg": "polygon-ecosystem-token"},
    Chain.solana:   {"symbol": "SOL",  "decimals": 9,  "cg": "solana"},
    Chain.tron:     {"symbol": "TRX",  "decimals": 6,  "cg": "tron"},
    Chain.bitcoin:  {"symbol": "BTC",  "decimals": 8,  "cg": "bitcoin"},
}


def _fetch_native_holding(
    address: str,
    adapter,
    chain: Chain,
    price_client: CoinGeckoClient,
) -> TokenHolding | None:
    """Best-effort native-balance probe per chain.

    Returns None when:
      * the chain isn't in `_NATIVE_BY_CHAIN` (unknown native asset)
      * the adapter doesn't expose a method we know how to call
      * the balance probe raises (transient network, rate limit)
      * the balance is zero

    Each adapter exposes the native-balance method differently:
      * EVM: `adapter.client.get_eth_balance(address)` returns wei
      * Solana / Tron / Bitcoin: not currently exposed → skip
    """
    meta = _NATIVE_BY_CHAIN.get(chain)
    if meta is None:
        return None
    raw = 0
    try:
        # EVM family — the unified Etherscan-V2 client exposes
        # get_eth_balance regardless of which chain it's pointed at
        # (the chainid is set at client construction). For BSC / Polygon
        # / etc. the same call returns the chain's native asset balance.
        client = getattr(adapter, "client", None)
        if client is not None and hasattr(client, "get_eth_balance"):
            raw = client.get_eth_balance(address)
        else:
            # Solana / Tron / Bitcoin: no native-balance method exposed
            # on the adapter today. Skip silently (consistent with the
            # pre-v0.18.0 masked behavior, but documented).
            return None
    except Exception as e:  # noqa: BLE001
        log.debug("native balance failed for %s on %s: %s", address, chain.value, e)
        return None
    raw = int(raw or 0)
    if raw <= 0:
        return None
    token = TokenRef(
        chain=chain, contract=None,
        symbol=str(meta["symbol"]),
        decimals=int(meta["decimals"]),  # type: ignore[arg-type]
        coingecko_id=str(meta["cg"]),
    )
    decimal_amount = Decimal(raw) / Decimal(10 ** int(meta["decimals"]))  # type: ignore[arg-type]
    price = price_client.price_now(token)
    # RIGOR-Jacob Z10: same non-finite guard as _fetch_holdings above.
    if price.usd_value is None or not price.usd_value.is_finite():
        usd = None
    else:
        try:
            usd = price.usd_value * decimal_amount
            if not usd.is_finite():
                usd = None
        except ArithmeticError:
            usd = None
    return TokenHolding(
        token=token, raw_amount=raw, decimal_amount=decimal_amount,
        usd_value=usd, pricing_error=price.error,
    )


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
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False, ensure_ascii=False), encoding="utf-8")
    return path
