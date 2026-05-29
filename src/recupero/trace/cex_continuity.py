"""CEX trace continuity heuristic (v0.31.2).

When stolen funds land in a labeled CEX hot wallet, the trace
traditionally stops there (it's KYC-opaque). But the same hot
wallet's OUTBOUND transfers within a short time window of our
inbound deposit are a forensically-useful signal that the same
funds may have re-emerged at a new address.

Critical: this is a CORRELATION, not a causation. CEX hot wallets
commingle billions in deposits; matching a $50K theft to a $50K
withdrawal seconds later is noise. The signal is meaningful only
when:
  * the amount is large enough ($100K+ default)
  * the token is uncommon enough (not USDT/USDC — too noisy)
  * the time window is tight (default <= 6 hours)
  * the withdrawal amount is within tolerance of the deposit
    (default +-5%)

Operators see these as LEADS, not conclusions. The brief surfaces
them under a CEX_CONTINUITY_LEADS section explicitly framed as
"LEAD ONLY — same-hot-wallet correlation, not proven re-emergence."

Closes gap #15 from the trace-completeness assessment: the trace
ends at the CEX deposit address (KYC opaque), but we can still
provide investigative leads on the OUTBOUND side without claiming
proof of re-emergence.

Wired into the brief at render time (not trace time) — adapter
calls cost API budget, so this module is opt-in via the
``RECUPERO_CEX_CONTINUITY=1`` env var. Bounded at TOP 5 leads per
case so a chatty CEX hot wallet doesn't burn the budget.
"""

from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from recupero._common import canonical_address_key as _ck
from recupero.models import Case, Chain

if TYPE_CHECKING:
    from recupero.chains.base import ChainAdapter
    from recupero.labels.store import LabelStore
from recupero.labels.store import lookup_pit_safe  # v0.31.4

log = logging.getLogger(__name__)


# Default heuristic knobs. All overridable via env vars + kwargs.
_DEFAULT_WINDOW_HOURS = 6.0
_DEFAULT_MIN_USD = Decimal("100000")
_DEFAULT_AMOUNT_TOLERANCE_PCT = 0.05
# v0.32.1 HIGH-10: per-parity tolerance — stable parity is tighter
# (USDT↔USDC trades at <0.2% slippage routinely; 1.5% is the
# conservative bound that lets in real laundering routes but not
# noise). ETH/BTC parity derivatives slip a bit more (staking
# yields drift the underlying); 1% is empirically right.
_STABLE_PARITY_TOLERANCE_PCT = 0.015
_ETH_PARITY_TOLERANCE_PCT = 0.010
_BTC_PARITY_TOLERANCE_PCT = 0.010
# Tier 3 cross-chain window is tighter than the default — cross-chain
# CEX rails are sub-hour by design, so anything beyond 4h is noise.
_TIER3_CROSS_CHAIN_WINDOW_HOURS = 4.0
# Tokens noisy enough that an amount-match in a short window is
# almost certainly coincidence. CEX hot wallets process millions
# of dollars of USDT / USDC per minute; a $250K match in 2h is
# statistical noise, not a re-emergence signal.
_DEFAULT_NOISY_TOKENS: frozenset[str] = frozenset(
    {"USDT", "USDC", "DAI", "ETH", "WETH"}
)
# Hard cap on leads per case. Each lead costs at least one
# adapter call (and possibly several pages of outflow fetches);
# we cap so a chatty hot wallet doesn't run away with the budget.
_MAX_LEADS_PER_CASE = 5


# v0.32.1 JACOB_TRACE_AUDIT_v032 HIGH-10 close-out: cross-token parity
# match. Pre-v0.32.1 the matcher required EXACT token-symbol equality —
# an adversary depositing USDT and withdrawing USDC at the same
# exchange within minutes returned zero leads. Real-world routes use
# this pattern routinely. The parity groups below are the asset
# families that trade at ≈1:1 with each other (fees + slippage absorb
# the residual). USD value comparison still applies (existing 5%
# tolerance) — we just remove the strict-symbol gate when both tokens
# belong to the same parity group.
#
# IMPORTANT: only "stable-to-stable", "ETH-to-ETH-derivative", and
# "BTC-to-BTC-derivative" pairs go in here. Adding non-parity assets
# (e.g. USDT ↔ BNB) would inject false positives — that's a DEX-trace
# concern, not CEX continuity.
_STABLE_PARITY = frozenset({
    "USDT", "USDC", "USDC.E", "DAI", "BUSD", "TUSD", "FRAX", "USDP", "GUSD",
    "USDD", "LUSD", "SUSD", "MIM", "USDE", "USDS", "USDJ", "PYUSD", "USDH",
    "USDBC", "AXLUSDC", "USD1",
})
_ETH_PARITY = frozenset({
    "ETH", "WETH", "STETH", "WSTETH", "RETH", "CBETH", "FRXETH", "SFRXETH",
})
_BTC_PARITY = frozenset({
    "WBTC", "BTCB", "TBTC", "CBBTC", "RENBTC", "HBTC", "WBTC.E",
})

# v0.32.1 test-public aliases for the test scaffolding. The audit's
# canonical shape is ``dict[Chain, frozenset[str]]`` (per-chain parity
# entries) so cross-chain Tier-3 logic can ask "is USDC valid on
# polygon?" — the parity-tables-per-chain shape lets the cross-chain
# match enforce that the candidate token actually exists on the
# candidate chain. Until per-chain divergence ships, every chain has
# the same parity set.
def _per_chain_table(symbols: frozenset[str]) -> dict[Chain, frozenset[str]]:
    chains = (
        Chain.ethereum, Chain.tron, Chain.bsc, Chain.polygon,
        Chain.arbitrum, Chain.optimism, Chain.base, Chain.avalanche,
        Chain.solana,
    )
    return dict.fromkeys(chains, symbols)


STABLECOIN_PARITY_GROUPS: dict[Chain, frozenset[str]] = (
    _per_chain_table(_STABLE_PARITY)
)
ETH_PARITY_GROUPS: dict[Chain, frozenset[str]] = (
    _per_chain_table(_ETH_PARITY)
)
BTC_PARITY_GROUPS: dict[Chain, frozenset[str]] = {
    # WBTC-family lives mostly on EVM mainnets.
    Chain.ethereum: _BTC_PARITY,
    Chain.bsc: _BTC_PARITY,
    Chain.polygon: _BTC_PARITY,
    Chain.arbitrum: _BTC_PARITY,
    Chain.optimism: _BTC_PARITY,
    Chain.base: _BTC_PARITY,
    Chain.avalanche: _BTC_PARITY,
}


def _parity_group(symbol: str) -> str | None:
    """Return ``"stable" | "eth" | "btc"`` if symbol is in a parity
    group, else ``None``."""
    s = (symbol or "").upper()
    if s in _STABLE_PARITY:
        return "stable"
    if s in _ETH_PARITY:
        return "eth"
    if s in _BTC_PARITY:
        return "btc"
    return None


def _are_at_parity(token_a: str, token_b: str) -> bool:
    """True iff both tokens belong to the same parity group."""
    if not token_a or not token_b:
        return False
    if token_a.upper() == token_b.upper():
        return True
    ga, gb = _parity_group(token_a), _parity_group(token_b)
    return ga is not None and ga == gb


@dataclass(frozen=True)
class CexContinuityLead:
    """One investigative lead.

    DELIBERATELY confidence='low'. The brief section that consumes
    these is framed as 'LEAD ONLY — same-hot-wallet correlation, not
    proven re-emergence.' Operators decide whether to follow up.

    The v0.32.1 HIGH-10 cross-token / cross-chain matcher still runs
    (it widens WHICH outflows count as a candidate via parity groups
    and per-tier windows/tolerances), but the confidence label is
    ALWAYS 'low' — a forensic-integrity invariant. This is a
    CORRELATION across a tight time window, never a causation, so it
    can never carry 'high'/'medium' confidence regardless of tier.
    """
    deposit_tx_hash: str
    deposit_address: str          # CEX hot wallet (the to_address of the deposit)
    deposit_amount_usd: Decimal
    deposit_token_symbol: str
    deposit_block_time: datetime
    cex_name: str
    candidate_withdrawal_tx_hash: str
    candidate_withdrawal_to: str   # new address that received CEX outbound
    candidate_amount_usd: Decimal
    candidate_block_time: datetime
    delta_hours: float
    amount_match_pct: float        # |dep - wth| / dep, expressed as a fraction
    confidence: str                # always "low" — by design (invariant)
    # v0.32.1 HIGH-10: cross-token + cross-chain parity metadata.
    candidate_token_symbol: str = ""
    candidate_chain: Chain | None = None
    parity_group: str | None = None        # "stable" | "eth" | "btc" | None
    parity_match: dict[str, str] | None = None  # {"deposit_asset","withdrawal_asset","parity_group"}
    cross_chain_parity: bool = False


def _is_finite_decimal(value: Decimal | None) -> bool:
    """True if value is a real, finite Decimal (not None / NaN / Inf).

    Mirrors the dust_attack._is_finite_decimal pattern — Decimal can
    carry NaN/Infinity sentinels just like float, and we never want
    those participating in arithmetic or comparisons (NaN comparisons
    silently return False and break filtering).
    """
    if value is None:
        return False
    try:
        if value.is_nan() or value.is_infinite():
            return False
        return math.isfinite(float(value))
    except (ValueError, ArithmeticError, OverflowError, TypeError):
        return False


def _resolve_cex_label(
    address: str,
    chain: Chain,
    label_store: LabelStore | None,
    *,
    point_in_time: datetime | None = None,
) -> tuple[str, str] | None:
    """Return ``(cex_name, category)`` if ``address`` is a labeled CEX
    hot wallet / deposit address; ``None`` otherwise.

    Looks up via the LabelStore (which loads cex_deposits.json + any
    user-supplied overrides). The category must be one of
    ``exchange_hot_wallet`` / ``exchange_deposit`` for the address to
    be considered a CEX endpoint.

    v0.31.4 (Gap 1a): pass ``point_in_time`` so the label state AT THE
    TIME OF THEFT is used. A CEX hot wallet labeled today wasn't
    necessarily a CEX wallet 6 months ago.
    """
    if label_store is None or not address:
        return None
    try:
        label = lookup_pit_safe(label_store, address, chain=chain, point_in_time=point_in_time,)
    except Exception as exc:  # noqa: BLE001
        log.debug(
            "cex_continuity: label lookup raised for %s on %s: %s",
            address, chain, exc,
        )
        return None
    if label is None:
        return None
    cat = getattr(label.category, "value", None) or str(label.category)
    if cat not in ("exchange_hot_wallet", "exchange_deposit"):
        return None
    name = label.exchange or label.name or "(unknown CEX)"
    return (name, cat)


def _within_tolerance(
    deposit_usd: Decimal,
    candidate_usd: Decimal,
    tolerance_pct: float,
) -> tuple[bool, float]:
    """True iff ``|deposit - candidate| / deposit <= tolerance_pct``.

    Returns ``(matched, match_pct)`` so the caller can populate the
    lead's ``amount_match_pct`` field without recomputing.

    Both inputs MUST be finite-checked by the caller; this function
    asserts pre-condition via early return on degenerate input.
    """
    if deposit_usd <= 0:
        return (False, 0.0)
    try:
        diff = abs(deposit_usd - candidate_usd)
        pct = float(diff / deposit_usd)
    except (ArithmeticError, ValueError, OverflowError):
        return (False, 0.0)
    if not math.isfinite(pct):
        return (False, 0.0)
    return (pct <= tolerance_pct, pct)


def identify_cex_continuity_leads(
    case: Case,
    *,
    adapter: ChainAdapter | None,
    label_store: LabelStore | None,
    window_hours: float = _DEFAULT_WINDOW_HOURS,
    min_usd: Decimal = _DEFAULT_MIN_USD,
    amount_tolerance_pct: float = _DEFAULT_AMOUNT_TOLERANCE_PCT,
    noisy_tokens: frozenset[str] = _DEFAULT_NOISY_TOKENS,
) -> list[CexContinuityLead]:
    """Walk ``case.transfers`` looking for CEX-continuity correlations.

    For each transfer whose ``to_address`` is a labeled CEX hot wallet
    AND amount >= ``min_usd`` AND token NOT IN ``noisy_tokens``, fetch
    the CEX hot wallet's outbound transfers in
    ``[block_time, block_time + window_hours]`` and produce a lead for
    each matching amount within ``amount_tolerance_pct``.

    Bounded at TOP ``_MAX_LEADS_PER_CASE`` (5) leads per case so a
    chatty CEX hot wallet doesn't run away with the API budget.

    Defensive contract:
      * ``case`` empty or ``transfers`` empty -> ``[]``, no adapter call.
      * ``adapter`` None -> ``[]``, no adapter call (env-var gate
        will normally short-circuit this path before we get here, but
        defense-in-depth keeps the public API safe).
      * Any adapter call raising -> log + skip that candidate; never
        propagate.
      * Any individual transfer with NaN/Inf USD value -> skipped.

    All leads carry ``confidence="low"`` by design. This is a
    CORRELATION, never a causation.
    """
    if not case or not getattr(case, "transfers", None):
        return []
    if adapter is None:
        log.debug("cex_continuity: no adapter provided; skipping")
        return []

    # Defensive: coerce + clamp knobs to sane bounds even when called
    # with weird kwargs (mirror the env-var path's hardening so the
    # public API can't be coaxed into NaN math by a misbehaving caller).
    try:
        window_h = float(window_hours)
        if not math.isfinite(window_h) or window_h <= 0:
            window_h = _DEFAULT_WINDOW_HOURS
    except (TypeError, ValueError):
        window_h = _DEFAULT_WINDOW_HOURS

    try:
        min_usd_d = Decimal(str(min_usd))
        if not _is_finite_decimal(min_usd_d) or min_usd_d <= 0:
            min_usd_d = _DEFAULT_MIN_USD
    except (TypeError, ValueError, ArithmeticError):
        min_usd_d = _DEFAULT_MIN_USD

    try:
        tol_pct = float(amount_tolerance_pct)
        if not math.isfinite(tol_pct) or tol_pct < 0:
            tol_pct = _DEFAULT_AMOUNT_TOLERANCE_PCT
    except (TypeError, ValueError):
        tol_pct = _DEFAULT_AMOUNT_TOLERANCE_PCT

    # Step 1: walk case.transfers + identify candidate deposits (transfers
    # that landed at a labeled CEX hot wallet, are above min_usd, and
    # involve a non-noisy token). Sort by USD value descending so the
    # TOP-5 cap surfaces the most consequential leads first.
    candidate_deposits: list[tuple[Any, str, str]] = []
    # tuples: (transfer, cex_name, category)
    for t in case.transfers:
        usd_val = t.usd_value_at_tx
        if not _is_finite_decimal(usd_val):
            continue
        # mypy narrow + redundant guard
        assert usd_val is not None
        if usd_val < min_usd_d:
            continue
        token_sym = (t.token.symbol or "").upper() if t.token else ""
        # Forensic-integrity invariant: noisy tokens (USDT/USDC/DAI/
        # ETH/WETH) are filtered out at the deposit gate. CEX hot
        # wallets process millions of dollars of these per minute, so
        # a $250K amount-match in a short window is statistical noise,
        # not a re-emergence signal. A correlation on a noisy token is
        # never strong enough to surface as a lead — so we drop the
        # deposit before any (cost-incurring) adapter call.
        #
        # NOTE: an earlier v0.32.1 change tried to let noisy-symbol
        # deposits through when they belonged to a parity group (to
        # catch cross-token routes). That re-introduced exactly the
        # coincidental-match noise this gate exists to suppress, so the
        # strict gate is restored.
        if token_sym in noisy_tokens:
            continue
        # v0.31.4 (Gap 1a): use case.incident_time so the CEX label at
        # the time of theft is applied, not today's.
        resolved = _resolve_cex_label(
            t.to_address, t.chain, label_store,
            point_in_time=case.incident_time,
        )
        if resolved is None:
            continue
        cex_name, category = resolved
        candidate_deposits.append((t, cex_name, category))

    if not candidate_deposits:
        return []

    # Sort by USD value descending: the largest deposits are the most
    # forensically consequential. Stable sort by tx_hash + log_index for
    # determinism when two deposits tie on USD.
    candidate_deposits.sort(
        key=lambda triple: (
            -float(triple[0].usd_value_at_tx or 0),
            triple[0].tx_hash,
            triple[0].log_index or 0,
        )
    )

    leads: list[CexContinuityLead] = []

    for deposit, cex_name, _category in candidate_deposits:
        if len(leads) >= _MAX_LEADS_PER_CASE:
            break

        deposit_usd: Decimal = deposit.usd_value_at_tx  # validated above
        deposit_time: datetime = deposit.block_time
        deposit_addr: str = deposit.to_address
        deposit_chain: Chain = deposit.chain
        # Same-chain window: default (6h). Cross-chain (Tier 3) is
        # checked tightly later — fetch outflows out to the larger of
        # the two so we don't drop cross-chain rows here.
        window_end = deposit_time + timedelta(
            hours=max(window_h, _TIER3_CROSS_CHAIN_WINDOW_HOURS),
        )

        # Resolve the start block from the deposit's block_number — we
        # only need outflows AT OR AFTER the deposit block. Adapters may
        # over-fetch (Etherscan returns by block-range, not by
        # timestamp), so we filter again client-side by block_time.
        start_block = max(0, int(deposit.block_number))

        # Fetch outflows from the CEX hot wallet. Both native + ERC-20.
        # Catch ANY exception — adapter errors must not crash the brief.
        try:
            native_rows = adapter.fetch_native_outflows(
                deposit_addr, start_block,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "cex_continuity: native outflow fetch failed for %s "
                "(start_block=%s): %s",
                deposit_addr, start_block, exc,
            )
            native_rows = []
        try:
            erc20_rows = adapter.fetch_erc20_outflows(
                deposit_addr, start_block,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "cex_continuity: ERC-20 outflow fetch failed for %s "
                "(start_block=%s): %s",
                deposit_addr, start_block, exc,
            )
            erc20_rows = []

        # Step 2: scan outflows for amount-matched candidates inside
        # the window. Adapter rows are dicts with normalized shape
        # (see chains/base.py docstring). We need block_time, to,
        # amount_raw, token, tx_hash. USD value is NOT carried at this
        # layer (priced later in the trace pipeline) — we approximate
        # by converting amount_raw via the token's decimals and pricing
        # 1:1 with the deposit's token if symbols match. For
        # cross-token re-emergence (deposit USDT, withdraw ETH) we
        # cannot match without a pricer; that's an acceptable gap for
        # this LEAD-ONLY heuristic.
        deposit_token = (deposit.token.symbol or "").upper() if deposit.token else ""

        for row in list(native_rows) + list(erc20_rows):
            if len(leads) >= _MAX_LEADS_PER_CASE:
                break
            try:
                row_block_time = row.get("block_time")
                if not isinstance(row_block_time, datetime):
                    continue
                # Window check — must be after deposit (exclusive) and
                # within window_end (inclusive).
                if row_block_time < deposit_time:
                    continue
                if row_block_time > window_end:
                    continue
                row_to = row.get("to")
                if not isinstance(row_to, str) or not row_to:
                    continue
                # Skip outflows back to the deposit address itself (self-
                # transfers / internal sweeps). Compare canonically.
                if _ck(row_to) == _ck(deposit_addr):
                    continue
                row_token = row.get("token")
                row_token_symbol = (
                    getattr(row_token, "symbol", "") or ""
                ).upper()
                # Candidate chain (may differ from deposit_chain for Tier 3
                # cross-chain rails).
                row_chain_raw = row.get("chain")
                row_chain: Chain | None
                if isinstance(row_chain_raw, Chain):
                    row_chain = row_chain_raw
                elif isinstance(row_chain_raw, str):
                    try:
                        row_chain = Chain(row_chain_raw.lower())
                    except ValueError:
                        row_chain = None
                else:
                    row_chain = None
                same_chain = (row_chain is not None and row_chain == deposit_chain)

                # v0.32.1 HIGH-10 close-out: tiered matching.
                #   Tier 1 — same symbol, same chain → 'high' / 5% tol.
                #   Tier 2 — same parity group, same chain → 'medium' /
                #            per-parity tol (1.5% stable, 1.0% ETH/BTC).
                #   Tier 3 — same parity group, DIFFERENT chain → 'low' /
                #            per-parity tol, 4h window only.
                # Any non-parity pair (e.g. USDT → BNB) remains filtered.
                exact_match = (row_token_symbol == deposit_token)
                parity = (
                    not exact_match and _are_at_parity(
                        deposit_token, row_token_symbol,
                    )
                )
                if not (exact_match or parity):
                    continue

                # Determine tier + per-tier window/tolerance/confidence.
                tier_window_h: float
                tier_tol_pct: float
                tier_confidence: str
                tier_parity_group: str | None = None
                tier_parity_match: dict[str, str] | None = None
                tier_cross_chain = False

                if exact_match and same_chain:
                    # Tier 1
                    tier_window_h = window_h
                    tier_tol_pct = tol_pct
                    # Forensic-integrity invariant: this is a CORRELATION,
                    # never a causation. CEX hot wallets commingle funds,
                    # so even a same-symbol same-chain amount-match is only
                    # a LEAD — confidence is ALWAYS "low" by design.
                    tier_confidence = "low"
                elif parity and same_chain:
                    # Tier 2
                    pg = _parity_group(deposit_token)
                    if pg is None:
                        continue
                    tier_window_h = window_h
                    tier_tol_pct = {
                        "stable": _STABLE_PARITY_TOLERANCE_PCT,
                        "eth": _ETH_PARITY_TOLERANCE_PCT,
                        "btc": _BTC_PARITY_TOLERANCE_PCT,
                    }[pg]
                    # Invariant: correlation, not causation → always "low".
                    tier_confidence = "low"
                    tier_parity_group = pg
                    tier_parity_match = {
                        "deposit_asset": deposit_token,
                        "withdrawal_asset": row_token_symbol,
                        "parity_group": pg,
                    }
                elif parity and not same_chain:
                    # Tier 3 — cross-chain. Require row_chain to be in the
                    # parity table for the matched group; if the candidate
                    # token doesn't exist on the candidate chain, skip.
                    pg = _parity_group(deposit_token)
                    if pg is None or row_chain is None:
                        continue
                    table = {
                        "stable": STABLECOIN_PARITY_GROUPS,
                        "eth": ETH_PARITY_GROUPS,
                        "btc": BTC_PARITY_GROUPS,
                    }[pg]
                    if row_chain not in table or row_token_symbol not in table[row_chain]:
                        continue
                    tier_window_h = _TIER3_CROSS_CHAIN_WINDOW_HOURS
                    tier_tol_pct = {
                        "stable": _STABLE_PARITY_TOLERANCE_PCT,
                        "eth": _ETH_PARITY_TOLERANCE_PCT,
                        "btc": _BTC_PARITY_TOLERANCE_PCT,
                    }[pg]
                    tier_confidence = "low"
                    tier_parity_group = pg
                    tier_parity_match = {
                        "deposit_asset": deposit_token,
                        "withdrawal_asset": row_token_symbol,
                        "parity_group": pg,
                    }
                    tier_cross_chain = True
                else:
                    # exact_match + different chain — legacy single-tier
                    # path, treat as low-confidence cross-chain Tier 1
                    # equivalent.
                    tier_window_h = _TIER3_CROSS_CHAIN_WINDOW_HOURS
                    tier_tol_pct = tol_pct
                    tier_confidence = "low"
                    tier_cross_chain = True

                # Per-tier window enforcement (re-check after the broader
                # outer fetch window).
                tier_window_end = deposit_time + timedelta(hours=tier_window_h)
                if row_block_time > tier_window_end:
                    continue
                row_amount_raw = row.get("amount_raw", 0)
                row_decimals = getattr(row_token, "decimals", None)
                if row_decimals is None:
                    continue
                try:
                    raw_int = int(row_amount_raw)
                    decimals_int = int(row_decimals)
                    if decimals_int < 0 or decimals_int > 36:
                        continue
                except (TypeError, ValueError):
                    continue
                try:
                    row_amount_decimal = (
                        Decimal(raw_int) / (Decimal(10) ** decimals_int)
                    )
                except (ArithmeticError, ValueError):
                    continue
                if not _is_finite_decimal(row_amount_decimal):
                    continue
                # Same-token match: USD value of the candidate is
                # approximated as (row_amount_decimal / deposit_amount_decimal)
                # * deposit_usd. This implicitly assumes price was
                # stable across the window (default 6h max). For the
                # tight time window the heuristic targets, that's a
                # reasonable approximation; cross-day windows would
                # need real pricing.
                deposit_amount_decimal = deposit.amount_decimal
                if (
                    not _is_finite_decimal(deposit_amount_decimal)
                    or deposit_amount_decimal <= 0
                ):
                    continue
                try:
                    candidate_usd = (
                        row_amount_decimal / deposit_amount_decimal
                    ) * deposit_usd
                except (ArithmeticError, ValueError):
                    continue
                if not _is_finite_decimal(candidate_usd):
                    continue

                matched, match_pct = _within_tolerance(
                    deposit_usd, candidate_usd, tier_tol_pct,
                )
                if not matched:
                    continue

                delta_seconds = (row_block_time - deposit_time).total_seconds()
                delta_hours = delta_seconds / 3600.0
                if not math.isfinite(delta_hours) or delta_hours < 0:
                    continue

                lead = CexContinuityLead(
                    deposit_tx_hash=deposit.tx_hash,
                    deposit_address=deposit_addr,
                    deposit_amount_usd=deposit_usd,
                    deposit_token_symbol=deposit_token,
                    deposit_block_time=deposit_time,
                    cex_name=cex_name,
                    candidate_withdrawal_tx_hash=str(row.get("tx_hash", "")),
                    candidate_withdrawal_to=row_to,
                    candidate_amount_usd=candidate_usd,
                    candidate_block_time=row_block_time,
                    delta_hours=delta_hours,
                    amount_match_pct=match_pct,
                    confidence=tier_confidence,
                    candidate_token_symbol=row_token_symbol,
                    candidate_chain=row_chain,
                    parity_group=tier_parity_group,
                    parity_match=tier_parity_match,
                    cross_chain_parity=tier_cross_chain,
                )
                leads.append(lead)
            except Exception as exc:  # noqa: BLE001 — defensive
                log.debug(
                    "cex_continuity: row processing failed: %s", exc,
                )
                continue

    # Final cap (belt-and-braces — the inner loops also cap, but a
    # paranoid final slice keeps the public contract clean).
    return leads[:_MAX_LEADS_PER_CASE]


def leads_to_brief_section(
    leads: list[CexContinuityLead],
) -> list[dict[str, Any]]:
    """Serialize leads for the brief.

    Each lead becomes a JSON dict with explicit 'lead_only' framing
    — never 'destination_chain' or 'destination_address' (which
    would imply we proved it). Field names mirror the dataclass
    but are prefixed with 'candidate_' on the withdrawal side to
    signal these are LEADS, not proven destinations.

    Returns an empty list for an empty input — caller (emit_brief)
    omits the section key entirely when this returns ``[]`` so
    existing brief-key-set tests stay green.
    """
    out: list[dict[str, Any]] = []
    for lead in leads:
        # Defensive: serialize Decimal/datetime in stable ISO + str
        # form, never let a NaN slip through to JSON.
        dep_usd = (
            f"${lead.deposit_amount_usd:,.2f}"
            if _is_finite_decimal(lead.deposit_amount_usd)
            else None
        )
        cand_usd = (
            f"${lead.candidate_amount_usd:,.2f}"
            if _is_finite_decimal(lead.candidate_amount_usd)
            else None
        )
        # v0.32.1 HIGH-10: surface parity + cross-chain metadata so
        # operators / downstream serializers see WHY this is a lead.
        candidate_chain_str = (
            lead.candidate_chain.value
            if lead.candidate_chain is not None
            else None
        )
        candidate_token_symbol = (
            lead.candidate_token_symbol or lead.deposit_token_symbol
        )
        if lead.parity_match and lead.cross_chain_parity:
            inv_note = (
                f"Cross-chain re-emergence lead: {lead.deposit_token_symbol} "
                f"deposit ({dep_usd or '(unknown USD)'}) at {lead.cex_name} "
                f"hot wallet {lead.deposit_address[:10]}... at "
                f"{lead.deposit_block_time.isoformat().replace('+00:00', 'Z')}. "
                f"The SAME exchange emitted {cand_usd or '(unknown USD)'} "
                f"{candidate_token_symbol} on "
                f"{candidate_chain_str or 'unknown chain'} to "
                f"{lead.candidate_withdrawal_to[:10]}... "
                f"{lead.delta_hours:.1f}h later "
                f"(parity group: {lead.parity_group}; "
                f"amount match: {lead.amount_match_pct * 100:.2f}%). "
                "LEAD ONLY — investigator should subpoena the CEX for "
                "the deposit's KYC + cross-reference; do NOT publish "
                "this candidate as a confirmed destination."
            )
        elif lead.parity_match:
            inv_note = (
                f"Cross-token re-emergence lead: {lead.deposit_token_symbol} "
                f"→ {candidate_token_symbol} at {lead.cex_name} "
                f"hot wallet {lead.deposit_address[:10]}... "
                f"(parity group: {lead.parity_group}; "
                f"amount match: {lead.amount_match_pct * 100:.2f}%; "
                f"{lead.delta_hours:.1f}h later). "
                "LEAD ONLY — investigator should subpoena the CEX for "
                "the deposit's KYC + cross-reference; do NOT publish "
                "this candidate as a confirmed destination."
            )
        else:
            inv_note = (
                f"Funds landed at {lead.cex_name} hot wallet "
                f"{lead.deposit_address[:10]}... at "
                f"{lead.deposit_block_time.isoformat().replace('+00:00', 'Z')}. "
                f"The SAME hot wallet later emitted "
                f"{cand_usd or '(unknown USD)'} {lead.deposit_token_symbol} "
                f"to {lead.candidate_withdrawal_to[:10]}... "
                f"{lead.delta_hours:.1f}h later "
                f"(amount match: {lead.amount_match_pct * 100:.2f}%). "
                "LEAD ONLY — investigator should subpoena the CEX for "
                "the deposit's KYC + cross-reference; do NOT publish "
                "this candidate as a confirmed destination."
            )

        entry: dict[str, Any] = {
            "lead_only": True,
            "framing": (
                "LEAD ONLY — same-hot-wallet correlation, not proven "
                "re-emergence. CEX hot wallets commingle funds; this "
                "is a correlation across a tight time window with an "
                "amount match, NOT a proof that the same funds re-"
                "emerged at the candidate address."
            ),
            "confidence": lead.confidence,
            "deposit_tx_hash": lead.deposit_tx_hash,
            "deposit_address": lead.deposit_address,
            "deposit_amount_usd": dep_usd,
            "deposit_token_symbol": lead.deposit_token_symbol,
            "deposit_block_time": lead.deposit_block_time.isoformat().replace(
                "+00:00", "Z",
            ),
            "cex_name": lead.cex_name,
            "candidate_withdrawal_tx_hash": lead.candidate_withdrawal_tx_hash,
            "candidate_withdrawal_to": lead.candidate_withdrawal_to,
            "candidate_amount_usd": cand_usd,
            "candidate_block_time": lead.candidate_block_time.isoformat().replace(
                "+00:00", "Z",
            ),
            "delta_hours": round(lead.delta_hours, 3),
            "amount_match_pct": round(lead.amount_match_pct, 4),
            "candidate_token_symbol": candidate_token_symbol,
            "candidate_chain": candidate_chain_str,
            "parity_group": lead.parity_group,
            "parity_match": lead.parity_match,
            "cross_chain_parity": lead.cross_chain_parity,
            "investigator_note": inv_note,
        }
        out.append(entry)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Env-var parsers (v0.31.2 NaN-rejecting pattern from v0.31.1).
# Surfaced as module-level functions so the emit_brief integration AND
# the tests can share the exact same parsing logic.
# ─────────────────────────────────────────────────────────────────────────────


def env_continuity_enabled() -> bool:
    """RECUPERO_CEX_CONTINUITY: default ON since v0.31.4 (Gap 6).

    Adapter calls cost money, but the leads are bounded at TOP-5
    per case + min $100K USD + uncommon-token filter, so the
    worst-case extra spend per case is small. To OPT OUT set the
    env var to one of {"0", "false", "no", "off"}.

    Pre-v0.31.4 this was default-OFF; in practice that meant the
    feature was invisible (operators didn't know to enable it).
    Honest-gaps audit flagged it as integration gap #2b.
    """
    raw = os.environ.get("RECUPERO_CEX_CONTINUITY", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    # Anything else — including unset / "" / "1" / "true" — enables.
    return True


def env_window_hours() -> float:
    """RECUPERO_CEX_CONTINUITY_WINDOW_HOURS — default 6, clamped [0.5, 168].

    Lower bound 0.5h (30 minutes) because anything tighter is below
    typical CEX hot-wallet sweep cadence — sub-30-minute matches are
    pure noise. Upper bound 168h (one week) because beyond that price
    drift makes the amount-tolerance check meaningless.

    Rejects NaN / Inf via math.isfinite (v0.31.1 pattern).
    """
    raw = os.environ.get("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS")
    if raw is None:
        return _DEFAULT_WINDOW_HOURS
    try:
        val = float(raw)
        if not math.isfinite(val):
            raise ValueError("non-finite")
        return max(0.5, min(168.0, val))
    except (TypeError, ValueError):
        log.warning(
            "RECUPERO_CEX_CONTINUITY_WINDOW_HOURS=%r rejected; using default %s",
            raw, _DEFAULT_WINDOW_HOURS,
        )
        return _DEFAULT_WINDOW_HOURS


def env_min_usd() -> Decimal:
    """RECUPERO_CEX_CONTINUITY_MIN_USD — default $100K, must be >= $1K.

    Reject NaN/Inf via math.isfinite. Reject below $1K because the
    whole point of the heuristic is to surface large, low-noise
    matches — a $500 lead is just statistical noise.
    """
    raw = os.environ.get("RECUPERO_CEX_CONTINUITY_MIN_USD")
    if raw is None:
        return _DEFAULT_MIN_USD
    try:
        # Parse via float first so we can math.isfinite check it.
        f_val = float(raw)
        if not math.isfinite(f_val):
            raise ValueError("non-finite")
        if f_val < 1000.0:
            raise ValueError("below $1K minimum")
        return Decimal(str(f_val))
    except (TypeError, ValueError, ArithmeticError):
        log.warning(
            "RECUPERO_CEX_CONTINUITY_MIN_USD=%r rejected; using default %s",
            raw, _DEFAULT_MIN_USD,
        )
        return _DEFAULT_MIN_USD


__all__ = (
    "CexContinuityLead",
    "identify_cex_continuity_leads",
    "leads_to_brief_section",
    "env_continuity_enabled",
    "env_window_hours",
    "env_min_usd",
)
