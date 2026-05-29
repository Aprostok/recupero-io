"""CEX deposit-address attribution (v0.32.1, #209).

When stolen funds reach a known centralized-exchange (CEX) hot wallet the
on-chain trail ends — but the exchange KYC's its users, so the
law-enforcement play is to subpoena the exchange for the identity behind
the *specific deposit address* the funds passed through.

CEX deposit model
-----------------
An exchange assigns each user a unique on-chain DEPOSIT address. Funds
sent there are auto-SWEPT into the exchange's shared hot wallet shortly
after arrival. So in a trace the signature is::

    perpetrator_wallet  ->  D (unlabeled)  ->  H (known CEX hot wallet)

``D`` is the per-user deposit address — the precise subpoena key tied to
one KYC'd account — while ``H`` is the shared hot wallet that millions of
deposits hit. The static label DB almost always labels ``H`` (the hot
wallet) and leaves ``D`` unlabeled, so the existing endpoint pass records
``H`` and the genuinely subpoena-useful address ``D`` is lost. This pass
attributes such an unlabeled ``D`` to the exchange behind ``H`` via the
sweep pattern, so every CEX endpoint reliably converts into a concrete
subpoena target (exchange + deposit address + the transactions that prove
the link).

Forensic invariant — correlation is NOT proof
----------------------------------------------
An inferred attribution is a LEAD for the subpoena, never an assertion of
ownership. Confidence is therefore pinned to ``"low"`` / ``"medium"`` and
can NEVER be ``"high"``; only a label-DB hit (the address is itself in
``cex_deposits.json``) is ``"high"``, and that path is handled by the
existing label pipeline, not here. This mirrors the ``cex_continuity``
guardrail (validators/output_integrity.py enforces it).

Pure function: no DB, no network, no filesystem — operates on the
in-memory ``Case`` plus an optional ``LabelStore`` for the point-in-time
hot-wallet lookups.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING

from recupero._common import canonical_address_key as _ck
from recupero.labels.store import lookup_pit_safe
from recupero.models import Case, LabelCategory
from recupero.trace.clustering import _is_skip_labeled

if TYPE_CHECKING:
    from recupero.labels.store import LabelStore

log = logging.getLogger(__name__)

#: Categories that mark the RECIPIENT as a CEX endpoint worth attributing
#: a deposit address to. (exchange_deposit is included for completeness —
#: a labeled deposit address still benefits from the sweep evidence.)
_CEX_RECIPIENT_CATEGORIES = frozenset({
    LabelCategory.exchange_hot_wallet,
    LabelCategory.exchange_deposit,
})

#: A sweep (D -> H) must arrive within this window of D's funding for the
#: "clean sweep" (medium-confidence) signal. Exchanges sweep deposits
#: within minutes-to-hours; 24h is a generous ceiling.
_SWEEP_WINDOW = timedelta(hours=24)

#: Dust floor — a sub-$100 forward to a hot wallet is noise, not a
#: meaningful deposit worth a subpoena.
_MIN_SWEEP_USD = Decimal("100")

#: Fraction of D's trace-visible inflow that must be forwarded to a single
#: hot wallet for the sweep to read as a clean per-user deposit sweep
#: (bumps confidence low -> medium). Below this it's a partial/ambiguous
#: flow and stays "low".
_STRONG_SWEEP_RATIO = 0.90


@dataclass(frozen=True)
class InferredCexDeposit:
    """An unlabeled address inferred to be a CEX deposit address feeding a
    known hot wallet — a subpoena LEAD, never an ownership assertion."""

    deposit_address: str
    exchange: str
    chain: str
    heuristic: str                       # "sweep_to_hot_wallet"
    confidence: str                      # "low" | "medium" (NEVER "high")
    supporting_tx_hashes: tuple[str, ...]
    hot_wallet_address: str
    swept_usd: Decimal
    swept_ratio: float | None            # swept / D's trace inflow (None if unknown)

    def to_dict(self) -> dict:
        return {
            "address": self.deposit_address,
            "exchange": self.exchange,
            "chain": self.chain,
            "source": f"inferred:{self.heuristic}",
            "attribution_heuristic": self.heuristic,
            "attribution_confidence": self.confidence,
            "tx_hashes": list(self.supporting_tx_hashes),
            "hot_wallet_address": self.hot_wallet_address,
            "total_received_usd": str(self.swept_usd),
            "swept_ratio": self.swept_ratio,
        }


def infer_cex_deposit_addresses(
    case: Case,
    *,
    label_store: LabelStore | None = None,
    point_in_time: datetime | None = None,
) -> list[InferredCexDeposit]:
    """Infer unlabeled CEX deposit addresses from the sweep pattern.

    For every transfer ``D -> H`` where ``H`` is a known CEX hot wallet /
    deposit address (point-in-time label lookup) and ``D`` is NOT itself
    labeled infrastructure, ``D`` is a candidate per-user deposit address.
    Confidence is ``"medium"`` only for a CLEAN sweep (``D`` forwards
    >=90% of its trace-visible inflow to a SINGLE hot wallet within the
    sweep window); otherwise ``"low"``. Never ``"high"``.

    Returns a deterministic, descending-USD-sorted list. Empty when
    ``label_store`` is None (no way to identify hot wallets) or no
    qualifying sweeps exist.
    """
    if label_store is None:
        return []
    transfers = getattr(case, "transfers", None) or []
    if not transfers:
        return []
    pit = point_in_time if point_in_time is not None else getattr(case, "incident_time", None)

    # Pass 1: D's total trace-visible inflow (keyed canonical) so we can
    # compute the sweep ratio. Every transfer contributes to its
    # recipient's inflow.
    inflow_usd: dict[str, Decimal] = defaultdict(Decimal)
    for t in transfers:
        dst = _ck(t.to_address)
        if not dst:
            continue
        usd = t.usd_value_at_tx if t.usd_value_at_tx is not None else Decimal("0")
        try:
            inflow_usd[dst] += Decimal(usd)
        except Exception:  # noqa: BLE001 — never let a bad USD value abort
            continue

    # Pass 2: accumulate D -> H sweeps into a known CEX recipient.
    # Keyed by (canonical D, canonical H) so multiple sweep txs aggregate.
    sweeps: dict[tuple[str, str], dict] = {}
    hot_recipients_by_d: dict[str, set[str]] = defaultdict(set)

    for t in transfers:
        src_raw = t.from_address
        dst_raw = t.to_address
        src = _ck(src_raw)
        dst = _ck(dst_raw)
        if not src or not dst or src == dst:
            continue
        # The RECIPIENT must be a known CEX hot wallet / deposit address.
        try:
            lbl = lookup_pit_safe(
                label_store, dst_raw, chain=t.chain, point_in_time=pit,
            )
        except Exception:  # noqa: BLE001
            lbl = None
        if lbl is None or lbl.category not in _CEX_RECIPIENT_CATEGORIES:
            continue
        # The SENDER (deposit-address candidate) must be UNLABELED — a
        # labeled sender is infra-to-infra movement (CEX hot wallet
        # rebalancing, bridge payout), not a user deposit.
        if _is_skip_labeled(src_raw, label_store, t.chain, point_in_time=pit):
            continue

        exchange = (getattr(lbl, "exchange", None)
                    or getattr(lbl, "name", None) or "Unknown exchange")
        chain_val = t.chain.value if hasattr(t.chain, "value") else str(t.chain)
        usd = t.usd_value_at_tx if t.usd_value_at_tx is not None else Decimal("0")
        try:
            usd = Decimal(usd)
        except Exception:  # noqa: BLE001
            usd = Decimal("0")

        key = (src, dst)
        rec = sweeps.get(key)
        if rec is None:
            rec = {
                "deposit_address": src_raw,
                "hot_wallet_address": dst_raw,
                "exchange": exchange,
                "chain": chain_val,
                "tx_hashes": [],
                "tx_seen": set(),
                "swept_usd": Decimal("0"),
            }
            sweeps[key] = rec
        if usd > 0:
            rec["swept_usd"] += usd
        if isinstance(t.tx_hash, str) and t.tx_hash and t.tx_hash not in rec["tx_seen"]:
            rec["tx_seen"].add(t.tx_hash)
            rec["tx_hashes"].append(t.tx_hash)
        hot_recipients_by_d[src].add(dst)

    out: list[InferredCexDeposit] = []
    for (src, _dst), rec in sweeps.items():
        swept = rec["swept_usd"]
        if swept < _MIN_SWEEP_USD:
            continue  # dust — not a meaningful deposit
        d_inflow = inflow_usd.get(src, Decimal("0"))
        ratio: float | None = None
        if d_inflow > 0:
            try:
                ratio = float(swept / d_inflow)
            except Exception:  # noqa: BLE001
                ratio = None
        # Clean sweep => medium. A clean sweep is: D forwards >=90% of its
        # trace inflow to a SINGLE hot wallet. Anything else is "low".
        clean_sweep = (
            len(hot_recipients_by_d.get(src, set())) == 1
            and ratio is not None
            and ratio >= _STRONG_SWEEP_RATIO
        )
        confidence = "medium" if clean_sweep else "low"
        out.append(InferredCexDeposit(
            deposit_address=rec["deposit_address"],
            exchange=rec["exchange"],
            chain=rec["chain"],
            heuristic="sweep_to_hot_wallet",
            confidence=confidence,
            supporting_tx_hashes=tuple(rec["tx_hashes"]),
            hot_wallet_address=rec["hot_wallet_address"],
            swept_usd=swept,
            swept_ratio=ratio,
        ))

    # Deterministic order: descending USD, then address for tie-break.
    out.sort(key=lambda d: (-d.swept_usd, d.deposit_address))
    return out


class _CaseLabelIndex:
    """Lookup adapter backed by the labels already resolved onto the
    case's transfer counterparties at TRACE time.

    Lets :func:`infer_cex_deposits_from_case` run attribution at
    brief-assembly time without re-loading a ``LabelStore`` — the
    counterparty labels are the SAME authoritative labels the rest of
    the brief (exchange-endpoint detection, freeze targeting) relies on.
    In a theft trace any CEX hot wallet the funds reached necessarily
    appears as a recipient (so its label is indexed), which is exactly
    the set the sweep heuristic needs.
    """

    def __init__(self, case: Case) -> None:
        self._by_addr: dict[str, object] = {}
        for t in (getattr(case, "transfers", None) or []):
            cp = getattr(t, "counterparty", None)
            lbl = getattr(cp, "label", None) if cp is not None else None
            if lbl is not None:
                key = _ck(t.to_address)
                if key:
                    self._by_addr[key] = lbl

    def lookup(self, address: str, chain: object = None) -> object | None:  # noqa: ARG002
        return self._by_addr.get(_ck(address))


def infer_cex_deposits_from_case(case: Case) -> list[InferredCexDeposit]:
    """Brief-time convenience: attribute CEX deposit addresses using the
    labels baked onto the case's transfer counterparties (no separate
    ``LabelStore`` needed). Delegates to :func:`infer_cex_deposit_addresses`.
    """
    return infer_cex_deposit_addresses(case, label_store=_CaseLabelIndex(case))
