"""Cross-chain lock-and-mint bridge matching (trace-depth #1).

Some bridges DO NOT carry the destination recipient in the source-chain
calldata: the user locks/burns tokens on chain A, an off-chain relayer
watches for the event, and then MINTS/releases an equivalent amount to the
recipient on chain B in a SEPARATE transaction. Examples: Celer cBridge
(pool-based), Orbiter (order-book), legacy Multichain/Anyswap. For these,
``bridge_calldata.decode_bridge_calldata`` returns no destination address,
so the tracer's calldata-driven cross-chain continuation
(``tracer._continue_past_dex_and_bridges``) has nothing to follow and the
trail DEAD-ENDS at the bridge.

This module supplies the missing link: given the source-chain bridge
deposit (amount + time) and a set of candidate destination-chain transfers,
find the withdrawal/mint that most plausibly corresponds to it by matching
on AMOUNT (within a fee/slippage tolerance) and TIME (a settlement window
after the deposit).

FORENSIC INVARIANT — this is a CORRELATION, never proof. An amount+time
match across chains is circumstantial: two unrelated transfers can share an
amount and a window. So a match is surfaced at confidence "medium" at best
(a clean, unique, tight match) and "low" otherwise — NEVER "high". When the
evidence cannot single out one withdrawal (several equally-plausible
candidates), we refuse to guess: the result is flagged ``ambiguous`` so the
caller surfaces "N candidate matches" for manual review rather than
fabricating a single destination.

The matching function is PURE (no network / no clock) so it is fully unit
testable. The caller is responsible for sourcing candidate destination
transfers (e.g. the perpetrator address's inbound transfers on each
candidate chain, or a bridge's destination-side disbursement outflows) and
for any live fetching — that I/O is intentionally NOT in this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Literal

__all__ = [
    "BridgeMatchCandidate",
    "BridgeMatchResult",
    "match_bridge_withdrawal",
    "candidates_from_transfers",
]


# Defaults. Bridges take a fee and/or incur slippage, so the destination
# amount is typically slightly BELOW the source amount; a small tolerance
# absorbs that. Settlement is usually seconds-to-minutes but can lag hours
# under congestion, so the default window is generous but bounded.
_DEFAULT_SLIPPAGE_PCT = Decimal("2.0")        # loose outer bound for a match
_DEFAULT_WINDOW_HOURS = 24.0
_TIGHT_SLIPPAGE_PCT = Decimal("0.5")          # "clean" match → medium
_TIGHT_WINDOW_HOURS = 2.0
# Two candidates whose amount-distance from the source differ by less than
# this are treated as indistinguishable → ambiguous (refuse to single one
# out). Expressed in percentage points of the source amount.
_AMBIGUITY_MARGIN_PCT = Decimal("0.1")
# In amount+time-ONLY mode (a DIFFERENT-address match — no same-address link
# to corroborate), the source amount must carry at least this many significant
# digits. A round amount (1, 100, 0.5) is too coincidence-prone to match across
# chains on amount alone, so it is rejected outright in that mode.
_DEFAULT_MIN_SIGNIFICANT_DIGITS = 5


@dataclass(frozen=True)
class BridgeMatchCandidate:
    """A possible destination-chain withdrawal/mint to match against a
    source-chain bridge deposit. Pure value object — no chain I/O."""

    chain: str
    address: str                       # recipient on the destination chain
    tx_hash: str
    amount_decimal: Decimal
    block_time: datetime
    token_symbol: str | None = None
    usd_value: Decimal | None = None
    explorer_url: str | None = None


@dataclass(frozen=True)
class BridgeMatchResult:
    """Outcome of matching a source deposit to destination candidates."""

    candidate: BridgeMatchCandidate
    confidence: Literal["medium", "low"]   # NEVER "high" — correlation, not proof
    amount_diff_pct: Decimal
    delay_seconds: float
    ambiguous: bool                        # True → competing candidate(s); manual review
    reason: str


def _abs(d: Decimal) -> Decimal:
    return -d if d < 0 else d


def _significant_digits(amount: Decimal) -> int:
    """Count significant digits — a distinctiveness proxy. 100 → 1, 0.5 → 1,
    1.2345 → 5, 13.37428 → 7. Round amounts score low (coincidence-prone)."""
    try:
        return len(amount.normalize().as_tuple().digits)
    except (InvalidOperation, ValueError):
        return 0


def match_bridge_withdrawal(
    *,
    source_amount: Decimal,
    source_time: datetime,
    candidates: list[BridgeMatchCandidate],
    source_token_symbol: str | None = None,
    slippage_pct: Decimal = _DEFAULT_SLIPPAGE_PCT,
    window_hours: float = _DEFAULT_WINDOW_HOURS,
    amount_time_only: bool = False,
    min_significant_digits: int = _DEFAULT_MIN_SIGNIFICANT_DIGITS,
) -> BridgeMatchResult | None:
    """Find the destination withdrawal that best matches a bridge deposit.

    A candidate qualifies only if ALL hold:
      * it occurs AFTER ``source_time`` and within ``window_hours`` (a mint
        cannot precede the lock; and a match many days later is not
        credibly the same transfer);
      * its amount is within ``slippage_pct`` BELOW or at the source amount
        (bridges deduct a fee — a destination amount ABOVE the source by
        more than rounding is suspicious and not matched on the
        fee-deduction model). A small positive tolerance is allowed for
        rounding;
      * if ``source_token_symbol`` is given, the candidate carries the same
        symbol (lock-and-mint preserves the asset). Candidates with an
        unknown symbol are NOT excluded (we may not have priced/identified
        the token), they just can't be confirmed on asset.

    Returns the best qualifying candidate, or ``None`` if none qualify.
    Confidence is:
      * ``"medium"`` — a UNIQUE clean match: within the tight slippage +
        tight window, and no other candidate is comparably close;
      * ``"low"`` — a looser match, or a tight match that has a
        comparably-close competitor (``ambiguous=True``).
    Never ``"high"``: a cross-chain amount/time correlation is
    circumstantial. On genuine ambiguity the result is still returned (so
    the lead is not lost) but flagged ``ambiguous`` for manual review.

    DIFFERENT-ADDRESS mode (``amount_time_only=True``): for bridges that mint
    to a DIFFERENT recipient than the source sender (so there is NO
    same-address link to corroborate — e.g. matching a pool bridge's
    destination-side disbursements). With no address link, amount+time alone is
    the weakest signal, so this mode is deliberately strict and refuses to
    guess: it returns ``None`` unless (a) the source amount is DISTINCTIVE
    (≥ ``min_significant_digits`` significant digits — round amounts are too
    coincidence-prone) AND (b) exactly ONE candidate qualifies (any second
    qualifier → unresolvable → ``None``). A surviving match is ALWAYS "low".
    """
    if source_amount is None or source_amount <= 0:
        return None
    if not candidates:
        return None
    if not (slippage_pct >= 0):  # NaN-safe
        slippage_pct = _DEFAULT_SLIPPAGE_PCT
    if not (window_hours > 0):
        window_hours = _DEFAULT_WINDOW_HOURS
    # DIFFERENT-address (amount+time-only) mode: with no same-address link to
    # corroborate, a round source amount is too coincidence-prone to match
    # across chains. Refuse it outright rather than surface noise.
    if amount_time_only and _significant_digits(source_amount) < min_significant_digits:
        return None

    window = timedelta(hours=window_hours)
    src_sym = source_token_symbol.strip().lower() if source_token_symbol else None

    scored: list[tuple[Decimal, float, BridgeMatchCandidate]] = []
    for c in candidates:
        if c.amount_decimal is None or c.amount_decimal <= 0:
            continue
        # Asset gate (only when both symbols are known).
        if src_sym and c.token_symbol and c.token_symbol.strip().lower() != src_sym:
            continue
        # Time gate: strictly after the deposit, within the window. Equal
        # timestamps are allowed (same-block settlement on fast bridges).
        delay = (c.block_time - source_time).total_seconds()
        if delay < 0 or c.block_time > source_time + window:
            continue
        # Amount gate: destination = source minus fee, so we accept amounts
        # at or below source within slippage, plus a tiny rounding cushion
        # above. diff_pct is the absolute distance from the source amount.
        diff_pct = (_abs(c.amount_decimal - source_amount) / source_amount) * Decimal(100)
        # Reject destination amounts MORE than slippage above source (a
        # larger payout is not explained by a fee deduction).
        if c.amount_decimal > source_amount and diff_pct > slippage_pct:
            continue
        if diff_pct > slippage_pct:
            continue
        scored.append((diff_pct, delay, c))

    if not scored:
        return None

    # Best = closest amount, then soonest.
    scored.sort(key=lambda s: (s[0], s[1]))
    best_diff, best_delay, best = scored[0]

    if amount_time_only:
        # No same-address link → require a UNIQUE qualifying candidate. Any
        # second qualifier (a different tx/address) makes the correlation
        # unresolvable; refuse rather than guess a different-address dest.
        distinct = {(c.tx_hash, c.address) for _d, _dl, c in scored}
        if len(distinct) > 1:
            return None

    # Ambiguity: is there another candidate whose amount-distance is within
    # the margin of the best's? If so we cannot single one out on amount.
    ambiguous = False
    for diff_pct, _delay, cand in scored[1:]:
        if cand.tx_hash == best.tx_hash and cand.address == best.address:
            continue
        if _abs(diff_pct - best_diff) <= _AMBIGUITY_MARGIN_PCT:
            ambiguous = True
            break

    is_tight = (
        best_diff <= _TIGHT_SLIPPAGE_PCT
        and best_delay <= _TIGHT_WINDOW_HOURS * 3600
    )
    confidence: Literal["medium", "low"] = (
        # No same-address link → cap at "low" no matter how tight: amount+time
        # alone is the weakest cross-chain signal.
        "low" if amount_time_only
        else ("medium" if (is_tight and not ambiguous) else "low")
    )

    if amount_time_only:
        reason = (
            f"amount~{source_amount} matched a UNIQUE {best.chain} transfer "
            f"within {best_diff:.2f}% of amount and {best_delay / 3600:.1f}h to "
            "a DIFFERENT recipient address — an amount+time correlation with NO "
            "same-address link; a weak circumstantial lead (low confidence), "
            "NOT proof"
        )
    elif ambiguous:
        reason = (
            f"amount≈{source_amount} matched on {best.chain} within "
            f"{best_diff:.2f}% / {best_delay / 3600:.1f}h, but ≥1 other "
            "candidate is comparably close — manual review required "
            "(reported as a correlation lead, not a confirmed destination)"
        )
    else:
        reason = (
            f"amount≈{source_amount} matched a {best.chain} transfer within "
            f"{best_diff:.2f}% of amount and {best_delay / 3600:.1f}h of the "
            "bridge deposit — circumstantial cross-chain correlation, not proof"
        )

    return BridgeMatchResult(
        candidate=best,
        confidence=confidence,
        amount_diff_pct=best_diff,
        delay_seconds=best_delay,
        ambiguous=ambiguous,
        reason=reason,
    )


def candidates_from_transfers(
    transfers: list[object],
) -> list[BridgeMatchCandidate]:
    """Map domain ``Transfer`` objects into ``BridgeMatchCandidate``s.

    Integration seam: the caller fetches candidate destination-chain
    transfers (e.g. the perpetrator address's inbound transfers on each
    ``destination_chain_candidate`` within the settlement window) as the
    project's standard ``Transfer`` model, and this adapts them to the pure
    matcher's input. Kept duck-typed (no hard import of models) so the
    matcher stays a leaf module with no import cycle into the tracer.
    """
    out: list[BridgeMatchCandidate] = []
    for t in transfers:
        chain = getattr(t, "chain", None)
        chain_str = getattr(chain, "value", None) or (str(chain) if chain else "")
        amount = getattr(t, "amount_decimal", None)
        block_time = getattr(t, "block_time", None)
        if amount is None or block_time is None:
            continue
        token = getattr(t, "token", None)
        out.append(BridgeMatchCandidate(
            chain=chain_str,
            address=getattr(t, "to_address", "") or "",
            tx_hash=getattr(t, "tx_hash", "") or "",
            amount_decimal=amount,
            block_time=block_time,
            token_symbol=getattr(token, "symbol", None) if token else None,
            usd_value=getattr(t, "usd_value_at_tx", None),
            explorer_url=getattr(t, "explorer_url", None),
        ))
    return out
