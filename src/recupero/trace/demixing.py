"""Mixer demixing LEADS (v0.35.5) — probabilistic, never proof.

A mixer (Tornado Cash, etc.) cryptographically severs the on-chain link between
a deposit and its withdrawals. We never claim to defeat that. But user behavior
routinely *undermines* the anonymity set, and the same heuristics TRM /
Chainalysis use can reconnect a deposit to *candidate* withdrawals as
investigative LEADS — surfaced for manual review, NEVER asserted as the path.

The forensic doctrine of this module (hard rules):
  * Output confidence is ALWAYS ``low``. A demix correlation is an inference
    over a shared anonymity set — published de-anonymization rates are a
    MINORITY of flows (~5–35% depending on heuristic). It is never ``medium``
    or ``high`` and never a "destination" the tracer follows automatically.
  * We never FABRICATE a withdrawal — only real withdrawal events the caller
    supplies (from the same pool) are scored. Empty in ⇒ empty out.
  * Every lead carries the exact signals that fired (glass-box), so a reviewer
    can reproduce the reasoning and decide whether to act (e.g. subpoena).

Heuristics scored (each strengthens an existing same-pool candidate; none alone
is proof):
  * **address_reuse** — a withdrawal back to the SAME address that deposited
    (the classic Tornado mistake). The single strongest signal.
  * **relayer_fingerprint** — withdrawal used the same relayer as a known
    related withdrawal / the depositor's pattern.
  * **gas_price_fingerprint** — withdrawal's gas price exactly matches the
    deposit's (wallets reuse a configured gas price; an exact match in a busy
    pool is notable).
  * **fifo_timing** — the earliest withdrawal of the matching denomination
    after the deposit (first-in-first-out behavioral tendency). Weak alone.

This module is PURE — it scores a deposit against a caller-supplied list of
candidate withdrawals (fetched live elsewhere, behind an opt-in knob) and never
does I/O. That keeps it trivially unit-testable and keeps the (expensive,
opt-in) pool-event fetch out of the hot path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

# Default window after a deposit within which a withdrawal is a plausible
# same-actor candidate. 0 ⇒ unbounded (dormancy-aware), consistent with the
# value-match window — a depositor may withdraw weeks later.
DEFAULT_DEMIX_WINDOW_HOURS = 0
# Cap on leads returned per deposit (ranked best-first) — a reviewer triages a
# handful, not the whole pool.
DEFAULT_MAX_LEADS = 5


@dataclass(frozen=True)
class MixerEvent:
    """A mixer deposit or withdrawal (normalized; caller supplies from logs)."""
    address: str                 # depositor (deposit) / recipient (withdrawal)
    when: datetime
    pool: str                    # denomination / pool id, e.g. "100 ETH"
    tx_hash: str = ""
    gas_price: int | None = None
    relayer: str | None = None


@dataclass(frozen=True)
class DemixLead:
    """One candidate withdrawal linked to a deposit — a LEAD, not proof."""
    withdrawal_address: str
    withdrawal_tx: str
    pool: str
    score: float
    signals: tuple[str, ...] = field(default_factory=tuple)
    basis: str = ""
    confidence: str = "low"      # INVARIANT: always "low"


def _addr_eq(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and a.strip().lower() == b.strip().lower()


def demix_candidates(
    deposit: MixerEvent,
    withdrawals: list[MixerEvent],
    *,
    window_hours: int = DEFAULT_DEMIX_WINDOW_HOURS,
    max_leads: int = DEFAULT_MAX_LEADS,
    related_relayers: frozenset[str] | None = None,
) -> list[DemixLead]:
    """Score same-pool withdrawals against ``deposit`` → ranked LEADS.

    A candidate must be the SAME pool and occur AFTER the deposit (within
    ``window_hours``; 0 = unbounded). Candidates with no signal beyond
    "same pool + later" are NOT emitted (that's the whole anonymity set, not a
    lead) — only the FIFO-nearest one is kept as a weak timing lead, plus any
    candidate carrying a stronger signal (address reuse / relayer / gas-price).
    All leads are confidence ``low``. Returns ``[]`` when nothing qualifies.
    """
    if not withdrawals:
        return []
    window = None if window_hours <= 0 else timedelta(hours=window_hours)
    relayers = related_relayers or frozenset()

    # Same-pool, after-deposit candidates within the window.
    pool = (deposit.pool or "").strip().lower()
    cands: list[MixerEvent] = []
    for w in withdrawals:
        if (w.pool or "").strip().lower() != pool:
            continue
        if w.when < deposit.when:
            continue
        if window is not None and (w.when - deposit.when) > window:
            continue
        cands.append(w)
    if not cands:
        return []

    cands.sort(key=lambda w: w.when)  # FIFO order
    fifo_nearest_tx = cands[0].tx_hash

    leads: list[DemixLead] = []
    for w in cands:
        signals: list[str] = []
        score = 0.0
        if _addr_eq(w.address, deposit.address):
            signals.append("address_reuse")
            score += 100.0
        if w.relayer and (
            _addr_eq(w.relayer, deposit.relayer) or w.relayer.strip().lower()
            in {r.strip().lower() for r in relayers}
        ):
            signals.append("relayer_fingerprint")
            score += 25.0
        if (
            w.gas_price is not None
            and deposit.gas_price is not None
            and w.gas_price == deposit.gas_price
        ):
            signals.append("gas_price_fingerprint")
            score += 20.0
        if w.tx_hash and w.tx_hash == fifo_nearest_tx:
            signals.append("fifo_timing")
            score += 5.0

        # Emit only candidates with a real signal — a same-pool withdrawal with
        # NO signal is just a member of the anonymity set, not a lead.
        if not signals:
            continue
        leads.append(DemixLead(
            withdrawal_address=w.address,
            withdrawal_tx=w.tx_hash,
            pool=deposit.pool,
            score=score,
            signals=tuple(signals),
            basis=(
                f"demix LEAD (probabilistic, not proof): {deposit.pool} pool; "
                f"signals={'+'.join(signals)}"
            ),
            confidence="low",
        ))

    leads.sort(key=lambda lead: lead.score, reverse=True)
    return leads[:max_leads]


def demix_to_provenance(deposit: MixerEvent, leads: list[DemixLead]) -> dict[str, Any]:
    """Shape demix leads for the coverage audit trail / brief surfacing."""
    return {
        "deposit_address": deposit.address,
        "deposit_tx": deposit.tx_hash,
        "pool": deposit.pool,
        "leads": [
            {
                "withdrawal_address": le.withdrawal_address,
                "withdrawal_tx": le.withdrawal_tx,
                "score": le.score,
                "signals": list(le.signals),
                "confidence": le.confidence,
                "basis": le.basis,
            }
            for le in leads
        ],
        "note": (
            "Mixer demixing leads are PROBABILISTIC investigative leads, not "
            "proof of fund flow. A mixer cryptographically severs the deposit→"
            "withdrawal link; these candidates are surfaced for manual review / "
            "subpoena, never asserted as the traced path."
        ),
    }


__all__ = (
    "MixerEvent",
    "DemixLead",
    "demix_candidates",
    "demix_to_provenance",
    "DEFAULT_DEMIX_WINDOW_HOURS",
    "DEFAULT_MAX_LEADS",
)
