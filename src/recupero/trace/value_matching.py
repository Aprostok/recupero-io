"""Value-directed onward-hop matching through high-fan-out nodes (v0.34).

The problem
-----------

When stolen funds pass through a high-fan-out node — a DeFi aggregator, a pool,
an OTC desk, an unlabeled service wallet — that node may emit hundreds or
thousands of outflows. Breadth-first "follow every edge" either explodes the
graph or (with the service-wallet gate) stops dead, and the per-address cap
just drops the tail. None of those reach the ONE real onward hop that carries
our funds. That is why a deep endpoint behind an aggregator was unreachable.

The elite technique (what TRM / Chainalysis do): don't follow every edge —
follow the edge whose **value matches** the funds that just arrived. Two
signals, in priority order:

  1. **Same-asset amount match.** The node received ``A`` units of token ``T``
     and, shortly after, forwarded ``≈A`` units of the SAME token ``T`` (within
     a small fee/rounding tolerance). This is plain forwarding / peeling and is
     the strongest signal.

  2. **USD-value match across an asset conversion.** The node received value
     ``$X`` and, shortly after, emitted ``≈$X`` in a DIFFERENT token (within a
     slippage tolerance). This is the swap case — e.g. a hub holding
     mSyrupUSDp/ETH that rests as DAI — where amounts can't line up but USD
     value approximately does.

Both require the outflow to occur AFTER the inflow and within a time window.

Confidence calibration (forensic posture)
-----------------------------------------

A value match is INFERENCE, never cryptographic identity or a label-DB hit, so
it is NEVER assigned "high" confidence. The single hard rule a forensic tracer
must obey — *never fabricate a destination* — is enforced by the UNIQUENESS
gate: a match is only promoted to ``medium`` when it is the SOLE strong
candidate. If several outflows match, the node is commingling and we cannot
honestly say which carried our funds, so every candidate is demoted to ``low``
and flagged ambiguous. Cross-asset (USD) matches top out at ``low`` because
slippage + coincidence make them inherently weaker than an exact-amount match.

  * sole same-asset amount match within tolerance  -> ``medium``
  * same-asset amount match but >1 candidate        -> ``low`` (ambiguous)
  * USD-value (cross-asset) match                   -> ``low``

The caller decides what to do with each tier (follow medium automatically;
surface low as a lead for manual review). This module only RANKS and SCORES;
it never decides the trace continues — and it returns an empty list rather than
guess when nothing matches.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

# Defaults — deliberately tight. Widen per-run via the caller, never here.
DEFAULT_AMOUNT_TOL_PCT = Decimal("2.0")   # same-asset fee/rounding slack
DEFAULT_USD_TOL_PCT = Decimal("5.0")      # cross-asset swap slippage slack
DEFAULT_TIME_WINDOW_HOURS = 72            # onward hop must follow within this


@dataclass(frozen=True)
class Leg:
    """A normalized transfer leg for matching. Decouples the matcher from the
    Transfer model so it is trivially unit-testable."""

    to_address: str
    tx_hash: str
    token_symbol: str
    amount: Decimal
    usd_value: Decimal | None
    when: datetime


@dataclass(frozen=True)
class OnwardMatch:
    """One ranked onward-hop candidate."""

    to_address: str
    tx_hash: str
    token_symbol: str
    amount: Decimal
    usd_value: Decimal | None
    kind: str            # "same_asset_amount" | "usd_value_cross_asset"
    basis: str           # human-readable explanation for the audit trail
    confidence: str      # "medium" | "low" — NEVER "high" (inference)
    score: float         # higher = tighter match; for ranking only
    ambiguous: bool      # True when >1 candidate matched in this kind


def _to_decimal(value: Any) -> Decimal | None:
    """Coerce to a finite Decimal, or None if absent / non-finite / unparseable."""
    if value is None:
        return None
    if isinstance(value, Decimal):
        return value if value.is_finite() else None
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return d if d.is_finite() else None


def leg_from_transfer(t: Any) -> Leg | None:
    """Adapt a Transfer-like object (pydantic model or dict) to a ``Leg``.

    Returns None if the essential fields (to_address, amount, time) can't be
    read — the matcher then skips it rather than guessing.
    """
    def _get(*names: str) -> Any:
        for n in names:
            if hasattr(t, n):
                v = getattr(t, n)
                if v is not None:
                    return v
            elif isinstance(t, dict) and n in t:
                v = t[n]
                if v is not None:
                    return v
        return None

    to_address = _get("to_address", "to", "recipient")
    tx_hash = _get("tx_hash", "txhash", "hash") or "<unknown>"
    when = _get("block_time", "when", "timestamp")
    amount = _to_decimal(_get("amount_decimal", "amount", "amount_decimal_value"))

    # token symbol: token.symbol (TokenRef) or a flat field
    symbol = None
    tok = _get("token")
    if tok is not None:
        symbol = getattr(tok, "symbol", None) if not isinstance(tok, dict) else tok.get("symbol")
    if symbol is None:
        symbol = _get("token_symbol", "symbol")

    usd = _to_decimal(_get("usd_value_at_tx", "usd_value", "value_usd"))

    if not to_address or amount is None or when is None or not isinstance(when, datetime):
        return None
    return Leg(
        to_address=str(to_address),
        tx_hash=str(tx_hash),
        token_symbol=str(symbol or "").upper(),
        amount=amount,
        usd_value=usd,
        when=when,
    )


def match_onward_transfers(
    inbound: Leg,
    candidates: list[Leg],
    *,
    amount_tol_pct: Decimal = DEFAULT_AMOUNT_TOL_PCT,
    usd_tol_pct: Decimal = DEFAULT_USD_TOL_PCT,
    time_window_hours: int = DEFAULT_TIME_WINDOW_HOURS,
    max_matches: int = 3,
) -> list[OnwardMatch]:
    """Rank a node's outflows by how well they match the inbound funds.

    Returns matches sorted best-first (highest score). Same-asset amount
    matches always outrank USD-value matches. Confidence is assigned per the
    uniqueness rule documented above. Returns ``[]`` when nothing matches —
    the matcher never guesses.

    Only outflows that occur AFTER ``inbound.when`` and within
    ``time_window_hours`` are considered. A candidate that IS the inbound tx
    (same tx_hash) is ignored.
    """
    if inbound.amount <= 0 and (inbound.usd_value is None or inbound.usd_value <= 0):
        # Nothing to match against (zero / unknown inbound value).
        return []

    window = timedelta(hours=time_window_hours)
    amount_matches: list[OnwardMatch] = []
    usd_matches: list[OnwardMatch] = []

    for c in candidates:
        if c.tx_hash == inbound.tx_hash:
            continue
        # Onward hop must come AFTER the inbound, within the window.
        if c.when < inbound.when or (c.when - inbound.when) > window:
            continue

        matched_amount = False
        # 1) Same-asset amount match (strongest).
        if (
            inbound.amount > 0
            and c.token_symbol
            and c.token_symbol == inbound.token_symbol
        ):
            diff_pct = abs(c.amount - inbound.amount) / inbound.amount * Decimal(100)
            if diff_pct <= amount_tol_pct:
                amount_matches.append(OnwardMatch(
                    to_address=c.to_address,
                    tx_hash=c.tx_hash,
                    token_symbol=c.token_symbol,
                    amount=c.amount,
                    usd_value=c.usd_value,
                    kind="same_asset_amount",
                    basis=(
                        f"same-asset amount match: {c.token_symbol} "
                        f"out={c.amount} vs in={inbound.amount} "
                        f"(Δ{diff_pct:.2f}% ≤ {amount_tol_pct}%)"
                    ),
                    confidence="low",  # finalized after uniqueness pass
                    score=float(Decimal(1000) - diff_pct),
                    ambiguous=False,
                ))
                matched_amount = True

        # 2) USD-value match across an asset conversion (weaker; only if the
        #    same-asset rule didn't already claim this outflow).
        if (
            not matched_amount
            and inbound.usd_value is not None and inbound.usd_value > 0
            and c.usd_value is not None and c.usd_value > 0
        ):
            usd_diff_pct = abs(c.usd_value - inbound.usd_value) / inbound.usd_value * Decimal(100)
            if usd_diff_pct <= usd_tol_pct:
                usd_matches.append(OnwardMatch(
                    to_address=c.to_address,
                    tx_hash=c.tx_hash,
                    token_symbol=c.token_symbol,
                    amount=c.amount,
                    usd_value=c.usd_value,
                    kind="usd_value_cross_asset",
                    basis=(
                        f"USD-value match across asset conversion: "
                        f"out=${c.usd_value} ({c.token_symbol}) vs "
                        f"in=${inbound.usd_value} ({inbound.token_symbol}) "
                        f"(Δ{usd_diff_pct:.2f}% ≤ {usd_tol_pct}%)"
                    ),
                    confidence="low",
                    score=float(Decimal(500) - usd_diff_pct),
                    ambiguous=False,
                ))

    # Uniqueness pass — the gate that prevents fabricating a destination.
    amount_ambiguous = len(amount_matches) > 1
    usd_ambiguous = len(usd_matches) > 1

    finalized: list[OnwardMatch] = []
    for m in amount_matches:
        # Sole same-asset amount match -> medium; otherwise low + ambiguous.
        conf = "medium" if not amount_ambiguous else "low"
        finalized.append(
            OnwardMatch(**{**m.__dict__, "confidence": conf, "ambiguous": amount_ambiguous})
        )
    for m in usd_matches:
        # Cross-asset never exceeds low; flag ambiguity when >1.
        finalized.append(
            OnwardMatch(**{**m.__dict__, "confidence": "low", "ambiguous": usd_ambiguous})
        )

    finalized.sort(key=lambda x: x.score, reverse=True)
    return finalized[:max_matches]
