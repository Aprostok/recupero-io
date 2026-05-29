"""Trace traversal policies.

A policy answers two questions per transfer:
  1. Should we *include* this transfer in the case? (filter — dust, spoof, etc.)
  2. Should we *follow* this transfer to its destination as a new seed? (recursion)

The recursion answer is where the tool decides when to stop chasing money. Without
aggressive stop conditions a deep trace would explode — a single theft case has
fan-out of 10-50 counterparties per hop, so depth 3 unbounded is 125K+ transfers.

The default policy stops at:
  - labeled exchanges (off-ramp reached — terminal for the trace)
  - labeled mixers (funds obfuscated — flag and stop)
  - labeled bridges (cross-chain — we can't follow without a cross-chain adapter)
  - contract addresses (DeFi pools, routers, aggregators — usually not
    interesting to the theft narrative, and would explode the trace)
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from recupero.models import Address, LabelCategory, Transfer

# Known burn / null sinks: funds reaching these are economically
# destroyed. Lowercased EVM form; non-EVM equivalents (Solana
# 11111111111111111111111111111111 system program, Tron T9yD…) get
# added as we encounter them in real cases.
_BURN_OR_ZERO_ADDRESSES: frozenset[str] = frozenset({
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
    "0xdead000000000000000042069420694206942069",
    # Solana system program (often used as a "burn" sink in NFT contexts)
    "11111111111111111111111111111111",
})


def _is_burn_or_zero_address(address: Address) -> bool:
    """True if `address` is a well-known burn / zero sink.

    Case-insensitive for the EVM hex set; exact-match for non-EVM
    entries (base58 IS case-sensitive but the system-program key is
    all-1s so case is moot).
    """
    if not address:
        return False
    if address.lower() in _BURN_OR_ZERO_ADDRESSES:
        return True
    return address in _BURN_OR_ZERO_ADDRESSES


def _is_synthetic_placeholder(address: Address) -> bool:
    """True if `address` is a synthetic Recupero-internal placeholder.

    v0.17.5 (round-10 forensic HIGH): the Hyperliquid scraper emits
    Transfer rows whose ``to_address`` is ``"hyperliquid:unknown_destination"``
    for events with no parseable on-chain destination (Recupero-side
    metadata, NOT a real address). Pre-v0.17.5 the BFS tried to
    follow these — adapter.is_contract / fetch_*_outflows obviously
    fail, but each fail still burned one Etherscan probe + one
    Helius/TronGrid round-trip per BFS wave. Now: terminal, like
    burn addresses.

    Pattern: ``<protocol>:<sentinel>`` — colon-separated. No real
    on-chain address contains a colon, so the check is unambiguous.
    """
    if not address:
        return False
    return ":" in address


@dataclass
class TracePolicy:
    """Default policy.

    v0.7.4 bumped ``max_depth`` from 1 → 2 and lowered
    ``dust_threshold_usd`` from 50 → 10 in response to the
    V-CFI01 Zigha-pattern validation. See the same defaults
    in ``config.TraceParams`` for the operational reasoning.
    """

    max_depth: int = 2
    dust_threshold_usd: Decimal = Decimal("10")
    stop_at_exchange: bool = True
    stop_at_mixer: bool = True
    stop_at_bridge: bool = True
    # Whether to stop at destinations that are contract addresses. Defaults
    # True because most unlabeled contracts are DeFi routers / aggregators /
    # pools whose internal flow is not useful for theft tracing, and following
    # them explodes the trace. Override to False for specific investigations
    # where contract-internal flow matters (e.g., tracing through a vault).
    stop_at_contract: bool = True
    # If a wallet emits more outflows than this within the trace window,
    # treat it as a service address (unlabeled exchange / OTC desk / token
    # distributor) and stop BFS at it. Transfers TO/FROM the wallet still
    # land in the case file for the audit trail; the wallet's children
    # just don't get queued for the next hop. Without this cap, hitting a
    # 500-outflow service wallet at depth 2 explodes downstream.
    # Real perp paths in published thefts cap out at ~30 per hop;
    # 200 leaves headroom for legitimate dispersal.
    service_wallet_outflow_threshold: int = 200

    def should_include(self, transfer: Transfer) -> bool:
        """Filter: should this transfer appear in the case at all?

        v0.18.0 (round-11 forensic-HIGH-003): pre-v0.18.0 transfers with
        `usd_value_at_tx is None` (pricing fetch failed, token had no
        coingecko_id, historical price unavailable, etc.) UNCONDITIONALLY
        passed the dust filter — they got included in the case with no
        USD value. Downstream `_compute_total_drained` and `_sum_usd`
        skip None-USD transfers, so they didn't inflate the headline,
        but they DID:
          * bloat the counterparty list with phantom dust hops
          * pass through to brief destinations sorted at $0
          * confuse the operator ("why is this $0 transfer in the brief?")
        Now: when USD is unavailable AND token amount is below a tiny
        absolute floor, treat as dust. Real theft transfers have
        non-trivial amounts; unpriced dust transfers (spam, airdrops,
        sentinel) get the same treatment as priced dust.

        v0.32.1 (trace-depth #2): the unpriced floor was lowered from 10
        units to 1e-3. The old "< 10 units" floor was VALUE-BLIND and could
        drop a genuinely high-value hop: a transfer of, say, 5 units of a
        token CoinGecko couldn't price (new listing, low-liquidity, or a
        pricing outage) is dropped as "dust" even if those 5 units are 5
        WBTC (~$300K). Because this same filter gates FRONTIER expansion
        (tracer drops the transfer before queueing its destination), that
        also silently lost the onward trail — a launderer could route
        through a low-liquidity / self-issued unpriced token in small unit
        counts to evade the trace. We don't get to ASSUME an unknown-value
        transfer is worthless: only literal micro-dust (≈0, e.g. a 1-wei
        sentinel) is dropped now; anything with a non-trivial on-chain
        amount is traced AND recorded (the brief skips None-USD from
        totals, so it can't inflate the headline, and the audit trail
        stays complete). Bounded by the existing service-wallet, depth, and
        per-case transfer caps so this can't explode the BFS.
        """
        if (
            transfer.usd_value_at_tx is not None
            and transfer.usd_value_at_tx < self.dust_threshold_usd
        ):
            return False
        # Unpriced transfers: drop ONLY literal micro-dust (≈0). A value-
        # blind unit threshold cannot tell 5 WBTC ($300K) from 5 SCAM
        # ($0), so we refuse to assume an unknown-value transfer is dust
        # unless its on-chain amount is negligible. `amount_decimal` is the
        # human-units amount (1.0 ETH not 10^18).
        if (
            transfer.usd_value_at_tx is None
            and transfer.amount_decimal is not None
            and transfer.amount_decimal < Decimal("0.001")
        ):
            return False
        return True

    def should_traverse(self, transfer: Transfer) -> bool:
        """Recursion: should we follow this transfer's destination as a new seed?

        Does NOT check is_contract — that requires an adapter call. The caller
        (tracer) does that check separately and passes its result via the
        destination_is_contract keyword if applicable.
        """
        if transfer.hop_depth + 1 >= self.max_depth:
            return False
        # v0.16.8 (round-9 forensic HIGH): zero / burn addresses are TERMINAL.
        # Funds moved to 0x000…000 or 0x000…dEaD are economically destroyed;
        # tracing further is wasted budget and the analyst-facing brief
        # showing "trace continues at 0x0…" reads as a forensic error.
        if _is_burn_or_zero_address(transfer.to_address):
            return False
        # v0.17.5 (round-10 forensic HIGH): synthetic placeholders (e.g.
        # "hyperliquid:unknown_destination") are TERMINAL — no adapter
        # can resolve them and each fail burns API budget.
        if _is_synthetic_placeholder(transfer.to_address):
            return False
        if transfer.counterparty.label is None:
            return True  # unlabeled — still investigate
        cat = transfer.counterparty.label.category
        if self.stop_at_exchange and cat in (
            LabelCategory.exchange_deposit,
            LabelCategory.exchange_hot_wallet,
        ):
            return False
        if self.stop_at_mixer and cat == LabelCategory.mixer:
            return False
        if self.stop_at_bridge and cat == LabelCategory.bridge:
            return False
        return True

    def should_traverse_address(self, *, is_contract: bool) -> bool:
        """Secondary check — applied per destination, independent of the
        transfer label. Returns True if the address is OK to traverse;
        False if it should be treated as terminal.
        """
        if self.stop_at_contract and is_contract:
            return False
        return True
