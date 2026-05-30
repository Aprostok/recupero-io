"""Peel-chain detection (trace-depth #1, go-deeper).

A "peel chain" is a classic laundering structure: an address holding a large
balance repeatedly sends a SMALL "peel" to a cash-out destination (an
exchange deposit, an OTC desk) and forwards the LARGE remainder to a fresh
"change" address it still controls — then the change address repeats. The
remainder hops form a chain A → R1 → R2 → … under one actor's control, while
each hop sheds a small peel to a cashout point. Bitcoin tumbler exits and
many EVM drainers use this to fragment a trail into many small,
individually-unremarkable transfers.

The tracer's BFS follows every hop, but it does NOT recognize the PATTERN:
that the remainder chain is one actor and the peels are cashout candidates.
This module recognizes it from the transfer graph (chain-agnostic — operates
on the normalized from→to→amount edges, so it works on Bitcoin UTXO-derived
transfers AND EVM), and surfaces the remainder chain + peel recipients.

FORENSIC INVARIANT: a peel chain is a structural INFERENCE about common
control, never proof. Confidence is "low"/"medium", NEVER "high". A short
or noisy chain stays "low"; only a long, clean, consistent chain earns
"medium". The detector is PURE (operates on `case.transfers`, no I/O), so it
is fully unit-testable and runs at brief-assembly time (no adapter needed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from recupero._common import canonical_address_key as _ck

__all__ = [
    "PeelHop",
    "PeelChain",
    "detect_peel_chains",
]

# A hop counts as a peel hop when ONE outflow ("remainder") carries at least
# this fraction of the address's total outflow value, AND at least one other
# (smaller) outflow exists (the peel). Tuned conservatively: a genuine peel
# keeps the bulk moving (typically >70%) and sheds a minority.
_REMAINDER_FRACTION = Decimal("0.6")
# A single peel should be a MINORITY of the hop's outflow — above this and
# it's a split, not a peel.
_MAX_PEEL_FRACTION = Decimal("0.4")
# Minimum chained peel hops to report a chain at all (2 peels off a 3-address
# remainder run). Below this it's just an ordinary forward.
_MIN_HOPS = 3
# A long, clean chain (this many hops or more) earns "medium"; shorter "low".
_MEDIUM_HOPS = 5


@dataclass(frozen=True)
class PeelHop:
    """One link in a peel chain: an address that forwarded a dominant
    remainder to the next change address and shed peel(s) to cashout(s)."""

    address: str                       # the (raw) address doing the peeling
    remainder_to: str                  # the next change address (raw)
    remainder_value: Decimal           # value forwarded as the remainder
    peel_recipients: tuple[str, ...]   # raw addresses that received peels
    peel_value_total: Decimal          # total value shed as peels at this hop
    valued_in: str                     # "usd" | "amount" (basis of the values)


@dataclass(frozen=True)
class PeelChain:
    """A detected peel chain — a remainder run under inferred common control
    plus the cashout candidates it shed along the way."""

    hops: tuple[PeelHop, ...]
    remainder_chain: tuple[str, ...]   # ordered raw addresses A, R1, R2, …
    peel_recipients: tuple[str, ...]   # de-duplicated cashout candidates
    total_peeled_value: Decimal
    valued_in: str                     # "usd" | "amount"
    confidence: str                    # "low" | "medium"  (NEVER "high")
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "heuristic": "peel_chain",
            "remainder_chain": list(self.remainder_chain),
            "peel_recipients": list(self.peel_recipients),
            "hop_count": len(self.hops),
            "total_peeled_value": str(self.total_peeled_value),
            "valued_in": self.valued_in,
            "attribution_confidence": self.confidence,
            "note": self.reason,
        }


@dataclass
class _AddrOut:
    """Accumulated outflows from one address (canonical-keyed)."""

    raw: str
    # canonical dest key -> [raw_dest, summed_usd, summed_amount]
    dests: dict[str, list[Any]] = field(default_factory=dict)
    total_usd: Decimal = Decimal("0")
    total_amount: Decimal = Decimal("0")


def _peel_hop_for(
    out: _AddrOut,
    *,
    remainder_fraction: Decimal,
    max_peel_fraction: Decimal,
) -> PeelHop | None:
    """Classify one address's outflows as a peel hop, or None.

    Prefers USD valuation; falls back to token amount when USD is unknown
    for the hop (a single hop is typically one asset, so amounts are
    comparable). Requires a dominant remainder + at least one minority peel.
    """
    use_usd = out.total_usd > 0
    total = out.total_usd if use_usd else out.total_amount
    valued_in = "usd" if use_usd else "amount"
    if total <= 0 or len(out.dests) < 2:
        return None  # need a remainder AND at least one peel

    idx = 1 if use_usd else 2  # position of usd / amount in the dest record

    # Find the dominant (remainder) destination.
    remainder_key = max(out.dests, key=lambda k: out.dests[k][idx])
    remainder_rec = out.dests[remainder_key]
    remainder_val = remainder_rec[idx]
    if remainder_val < remainder_fraction * total:
        return None  # no single dominant remainder → not a peel hop

    peels: list[str] = []
    peel_total = Decimal("0")
    for k, rec in out.dests.items():
        if k == remainder_key:
            continue
        val = rec[idx]
        # Each peel must be a minority of the hop (a peel, not a co-equal split).
        if val > max_peel_fraction * total:
            return None  # a second large leg → this is a split, not a peel
        peels.append(rec[0])
        peel_total += val
    if not peels:
        return None

    return PeelHop(
        address=out.raw,
        remainder_to=remainder_rec[0],
        remainder_value=remainder_val,
        peel_recipients=tuple(peels),
        peel_value_total=peel_total,
        valued_in=valued_in,
    )


def detect_peel_chains(
    case: Any,
    *,
    min_hops: int = _MIN_HOPS,
    remainder_fraction: Decimal = _REMAINDER_FRACTION,
    max_peel_fraction: Decimal = _MAX_PEEL_FRACTION,
) -> list[PeelChain]:
    """Detect peel chains in ``case.transfers``.

    Returns a deterministic, longest-first list of ``PeelChain``. Empty when
    no chain of ``min_hops`` consecutive peel hops exists. Pure — no network.
    """
    transfers = getattr(case, "transfers", None) or []
    if not transfers:
        return []

    # Build per-address outflow aggregates (canonical-keyed, raw preserved).
    outs: dict[str, _AddrOut] = {}
    for t in transfers:
        src_raw = getattr(t, "from_address", None)
        dst_raw = getattr(t, "to_address", None)
        src = _ck(src_raw or "")
        dst = _ck(dst_raw or "")
        if not src or not dst or src == dst:
            continue
        usd = getattr(t, "usd_value_at_tx", None)
        try:
            usd_d = Decimal(usd) if usd is not None else Decimal("0")
        except (TypeError, ValueError, ArithmeticError):
            usd_d = Decimal("0")
        amt = getattr(t, "amount_decimal", None)
        try:
            amt_d = Decimal(amt) if amt is not None else Decimal("0")
        except (TypeError, ValueError, ArithmeticError):
            amt_d = Decimal("0")
        ao = outs.get(src)
        if ao is None:
            ao = _AddrOut(raw=src_raw or src)
            outs[src] = ao
        rec = ao.dests.get(dst)
        if rec is None:
            rec = [dst_raw or dst, Decimal("0"), Decimal("0")]
            ao.dests[dst] = rec
        if usd_d > 0:
            rec[1] += usd_d
            ao.total_usd += usd_d
        if amt_d > 0:
            rec[2] += amt_d
            ao.total_amount += amt_d

    # Classify each address as a peel hop (or not), keyed canonically.
    hop_by_key: dict[str, PeelHop] = {}
    for key, ao in outs.items():
        hop = _peel_hop_for(
            ao, remainder_fraction=remainder_fraction,
            max_peel_fraction=max_peel_fraction,
        )
        if hop is not None:
            hop_by_key[key] = hop

    if not hop_by_key:
        return []

    # Chain peel hops by following each hop's remainder_to to the next hop.
    # A hop is a chain "start" if no other peel hop forwards its remainder TO
    # it (i.e. it is not the remainder_to of any peel hop) — that avoids
    # reporting every suffix of one chain.
    remainder_targets = {_ck(h.remainder_to) for h in hop_by_key.values()}
    starts = [k for k in hop_by_key if k not in remainder_targets]
    # Fallback: if every hop is someone's remainder target (a cycle), start
    # anywhere deterministically.
    if not starts:
        starts = sorted(hop_by_key)

    chains: list[PeelChain] = []
    for start in sorted(starts):
        seq: list[PeelHop] = []
        chain_addrs: list[str] = []
        visited: set[str] = set()
        cur = start
        while cur in hop_by_key and cur not in visited:
            visited.add(cur)
            hop = hop_by_key[cur]
            seq.append(hop)
            chain_addrs.append(hop.address)
            cur = _ck(hop.remainder_to)
        # The terminal remainder address (last change wallet) completes the
        # remainder chain even though it isn't itself a peel hop.
        if seq:
            chain_addrs.append(seq[-1].remainder_to)
        if len(seq) < min_hops:
            continue

        valued_in = "usd" if all(h.valued_in == "usd" for h in seq) else "amount"
        total_peeled = sum((h.peel_value_total for h in seq), start=Decimal("0"))
        peel_recipients: list[str] = []
        seen_peel: set[str] = set()
        for h in seq:
            for p in h.peel_recipients:
                pk = _ck(p)
                if pk and pk not in seen_peel:
                    seen_peel.add(pk)
                    peel_recipients.append(p)

        confidence = "medium" if len(seq) >= _MEDIUM_HOPS else "low"
        reason = (
            f"{len(seq)}-hop peel chain: a remainder run of {len(chain_addrs)} "
            f"addresses each forwarded >={int(remainder_fraction * 100)}% onward "
            f"while shedding {len(peel_recipients)} smaller peel(s) to cashout "
            "candidates. Structural common-control inference (the same actor "
            "likely controls the remainder chain; peels are likely cashout "
            "points) — a lead, NOT proof."
        )
        chains.append(PeelChain(
            hops=tuple(seq),
            remainder_chain=tuple(chain_addrs),
            peel_recipients=tuple(peel_recipients),
            total_peeled_value=total_peeled,
            valued_in=valued_in,
            confidence=confidence,
            reason=reason,
        ))

    # Longest chain first (most evidence), then by start address for stability.
    chains.sort(key=lambda c: (-len(c.hops), c.remainder_chain[0]))
    return chains
