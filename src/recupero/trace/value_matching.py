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
from datetime import UTC, datetime, timedelta
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
    # v0.34 forensic hardening: the canonical on-chain token identity (lowercased
    # contract address; None for the chain's native asset). A same-asset match
    # REQUIRES contract identity — comparing only ``token_symbol`` lets a
    # scam/spoof token with a colliding symbol (a fake "USDC") be matched as the
    # real asset and promoted to medium confidence, fabricating a destination.
    token_contract: str | None = None


def is_confusable_token_symbol(symbol: str | None) -> bool:
    """True if a token symbol is an address-poisoning / impersonation token —
    one whose symbol contains NON-ASCII characters (Cyrillic/Lisu/fullwidth
    homoglyphs, the ``₮`` glyph, etc.) used to mimic a real asset (e.g. the Lisu
    "ꓴꓢꓓС" mimicking "USDC", or "USD₮0" mimicking "USDT"). Legit token symbols
    are printable ASCII. The value-tracer must NEVER follow funds through such a
    token: with the v0.34.1 unpriced-same-asset follow, a large unpriced
    homoglyph-poison transfer would otherwise be chased as if it were the real
    asset, fabricating a destination. (Observed live: the Zigha seed's Arbitrum
    outflows were dominated by "ꓴꓢꓓС" poison interleaved with real USDC.)
    """
    if not symbol:
        return False
    return any(ord(c) > 0x7F for c in symbol)


def _same_token(a: str | None, b: str | None) -> bool:
    """Same on-chain asset? Requires contract identity when contracts are known;
    both-None means the native asset (matched by symbol). A known contract never
    matches an unknown one — so a spoof-symbol token is NOT treated as same-asset."""
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    return a.strip().lower() == b.strip().lower()


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

    # token symbol + canonical contract: token.symbol/.contract (TokenRef) or
    # flat fields. The contract is the on-chain identity used to defeat
    # symbol-spoofing in the same-asset match.
    symbol = None
    contract = None
    tok = _get("token")
    if tok is not None:
        if isinstance(tok, dict):
            symbol = tok.get("symbol")
            contract = tok.get("contract")
        else:
            symbol = getattr(tok, "symbol", None)
            contract = getattr(tok, "contract", None)
    if symbol is None:
        symbol = _get("token_symbol", "symbol")
    if contract is None:
        contract = _get("token_contract", "contract")

    usd = _to_decimal(_get("usd_value_at_tx", "usd_value", "value_usd"))

    if not to_address or amount is None or when is None or not isinstance(when, datetime):
        return None
    # v0.34.2: never build a matchable leg for a homoglyph/impersonation token —
    # the value-tracer must not follow funds through address-poisoning spam (a
    # large UNPRICED homoglyph "USDC" would otherwise be chased by the
    # unpriced-same-asset follow as if it were the real asset).
    if is_confusable_token_symbol(str(symbol or "")):
        return None
    # Normalize to tz-aware UTC: a naive block_time (dict path / hand-built seed)
    # vs an aware one would raise TypeError in the time-window comparison and
    # abort the whole wave aggregation.
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return Leg(
        to_address=str(to_address),
        tx_hash=str(tx_hash),
        token_symbol=str(symbol or "").upper(),
        amount=amount,
        usd_value=usd,
        when=when,
        token_contract=(str(contract).lower() if contract else None),
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
        # 1) Same-asset amount match (strongest). Requires the SAME on-chain
        #    token (canonical contract identity), not just a matching symbol —
        #    otherwise a spoof token with a colliding symbol is matched as the
        #    real asset and a fabricated destination is followed at medium.
        if (
            inbound.amount > 0
            and c.token_symbol
            and c.token_symbol == inbound.token_symbol
            and _same_token(inbound.token_contract, c.token_contract)
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


# --- 1:N split / peel detection (v0.34.6) ------------------------------------
# A laundering "peel" forwards the received funds onward as MANY smaller
# same-asset transfers whose SUM ≈ the inbound. The 1:1 matcher above misses
# this entirely (no single outflow is within tolerance of the inbound), so the
# trace dead-ends one hop short of the next layer — exactly the Lazarus/Ronin
# case, where each ~$30M-$99M consolidation wallet peeled its balance into many
# smaller ETH sends. detect_same_asset_split recovers the peel CONSERVATIVELY:
# same on-chain token only, greedy largest-first, the subset must reach the
# inbound sum within tolerance using a bounded number of legs — else it returns
# [] (an honest dead-end, never a guess). Following a split is a SET inference
# (which specific recipients are the laundered funds vs. the node's own change
# is not provable on-chain), so every leg is confidence="low" and flagged
# ambiguous whenever the node had same-asset outflows OUTSIDE the matched subset
# (commingling). It is NEVER "high"/"medium" — the same forensic doctrine as the
# rest of this module.
DEFAULT_SPLIT_TOL_PCT = Decimal("3.0")   # subset-sum vs inbound slack (looser
#                                          than the 1:1 2% — many legs accrue
#                                          per-tx gas/rounding)
DEFAULT_MAX_SPLIT_LEGS = 25              # more legs than this is not a clean
#                                          peel — bail rather than chase dust


def detect_same_asset_split(
    inbound: Leg,
    candidates: list[Leg],
    *,
    split_tol_pct: Decimal = DEFAULT_SPLIT_TOL_PCT,
    max_split_legs: int = DEFAULT_MAX_SPLIT_LEGS,
    time_window_hours: int = DEFAULT_TIME_WINDOW_HOURS,
) -> list[OnwardMatch]:
    """Detect a 1:N same-asset SPLIT/peel and return one ``OnwardMatch`` per
    subset leg (confidence ``low``, kind ``same_asset_split``).

    Intended to be called ONLY when ``match_onward_transfers`` returned nothing
    (no 1:1 hop) — it recovers the peel a 1:1 matcher cannot see. Returns ``[]``
    when no clean peel exists; it never guesses.

    Conservatism / forensic posture:
      * SAME on-chain token only (canonical contract identity, not symbol) — a
        spoof token with a colliding symbol is never summed.
      * Only outflows AFTER ``inbound.when`` within ``time_window_hours``.
      * A single leg larger than ``inbound × (1+tol)`` cannot be a peel leg and
        is excluded.
      * Greedy largest-first accumulation; the running sum must land in
        ``[inbound × (1-tol), inbound × (1+tol)]`` using ≥ 2 and
        ≤ ``max_split_legs`` legs. Undershoot (ran out of legs) or overshoot
        (last leg blew past the band) ⇒ ``[]``.
      * ``ambiguous=True`` when the node had same-asset outflows outside the
        matched subset (commingling) — surfaced, never silently resolved.
    """
    if inbound.amount <= 0:
        # Split-follow is same-asset only; needs a positive inbound amount.
        return []
    if max_split_legs < 2:
        return []  # a "split" is by definition ≥ 2 legs

    window = timedelta(hours=time_window_hours)
    lo = inbound.amount * (Decimal(100) - split_tol_pct) / Decimal(100)
    hi = inbound.amount * (Decimal(100) + split_tol_pct) / Decimal(100)

    pool: list[Leg] = []
    for c in candidates:
        if c.tx_hash == inbound.tx_hash:
            continue
        if c.when < inbound.when or (c.when - inbound.when) > window:
            continue
        if c.amount <= 0:
            continue
        if not (
            c.token_symbol
            and c.token_symbol == inbound.token_symbol
            and _same_token(inbound.token_contract, c.token_contract)
        ):
            continue
        if c.amount > hi:
            continue  # a single over-large leg cannot be part of the peel
        pool.append(c)

    if len(pool) < 2:
        return []

    pool.sort(key=lambda leg: leg.amount, reverse=True)
    subset: list[Leg] = []
    running = Decimal(0)
    for c in pool:
        if len(subset) >= max_split_legs:
            return []  # needs too many legs to reach the sum — not a clean peel
        subset.append(c)
        running += c.amount
        if running >= lo:
            break

    if not (lo <= running <= hi) or len(subset) < 2:
        # Undershoot or overshoot — no clean peel; honest dead-end.
        return []

    ambiguous = len(pool) > len(subset)
    delta_pct = (running - inbound.amount).copy_abs() / inbound.amount * Decimal(100)
    n = len(subset)
    matches = [
        OnwardMatch(
            to_address=c.to_address,
            tx_hash=c.tx_hash,
            token_symbol=c.token_symbol,
            amount=c.amount,
            usd_value=c.usd_value,
            kind="same_asset_split",
            basis=(
                f"same-asset split/peel: {n} legs of {c.token_symbol} "
                f"summing to {running} vs in={inbound.amount} "
                f"(Δ{delta_pct:.2f}% ≤ {split_tol_pct}%)"
                + ("; node also sent same-asset outflows outside this subset"
                   if ambiguous else "")
            ),
            confidence="low",  # SET inference — never medium/high
            score=float(c.amount),  # larger legs ranked first
            ambiguous=ambiguous,
        )
        for c in subset
    ]
    matches.sort(key=lambda x: x.score, reverse=True)
    return matches
