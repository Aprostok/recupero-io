"""Issuer detection.

Given a list of dormant freeze candidates (each with token holdings), determine
WHO to contact to freeze each holding. Maps token contracts to issuer info
loaded from the seed `issuers.json`.

The output is a list of "freeze asks" — one per (candidate × freezable token),
ranked by USD value descending. Each ask carries everything an investigator
needs to send the request: address, amount, issuer name, contact email,
freeze-capability rating, and jurisdiction.

Limitations:
  - Tokens not in the issuer database show up as "unknown_issuer" — the
    investigator needs to research and add them. The database is intentionally
    a curated allow-list rather than a guess.
  - "Freeze capability" is a documentation hint, not a guarantee. Issuers'
    powers vary by jurisdiction, smart-contract permissions, and policies that
    change over time.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from recupero.dormant.finder import DormantCandidate, TokenHolding
from recupero.models import Chain

log = logging.getLogger(__name__)


_ISSUER_DB_PATH = Path(__file__).parent.parent / "labels" / "seeds" / "issuers.json"


@dataclass
class IssuerEntry:
    """One row from the issuer database."""
    chain: Chain
    contract: str           # always lowercased
    symbol: str
    issuer: str
    freeze_capability: str  # "yes", "limited", "no"
    freeze_notes: str
    primary_contact: str | None
    secondary_contact: str | None
    jurisdiction: str


@dataclass
class FreezeAsk:
    """One actionable freeze request to a single issuer about a single holding."""
    candidate_address: str          # the wallet holding the funds
    chain: Chain
    holding_symbol: str
    holding_decimal_amount: Decimal
    holding_usd_value: Decimal | None
    issuer: IssuerEntry             # who to contact
    explorer_url: str

    def short_summary(self) -> str:
        usd = f"${self.holding_usd_value:,.2f}" if self.holding_usd_value else "?"
        return (
            f"{self.holding_decimal_amount:,.2f} {self.holding_symbol} ({usd}) "
            f"at {self.candidate_address} → {self.issuer.issuer}"
        )


def load_issuer_db(path: Path | None = None) -> dict[tuple[Chain, str], IssuerEntry]:
    """Load issuers.json into a dict keyed by (chain, contract_lower)."""
    src = path or _ISSUER_DB_PATH
    raw = json.loads(src.read_text(encoding="utf-8"))
    out: dict[tuple[Chain, str], IssuerEntry] = {}
    for tok in raw.get("tokens", []):
        try:
            chain = Chain(tok["chain"])
        except (ValueError, KeyError):
            log.debug("skipping issuer entry with unknown chain: %s", tok)
            continue
        contract = (tok.get("contract") or "").lower()
        if not contract:
            continue
        out[(chain, contract)] = IssuerEntry(
            chain=chain,
            contract=contract,
            symbol=tok.get("symbol", "?"),
            issuer=tok.get("issuer", "Unknown"),
            freeze_capability=tok.get("freeze_capability", "unknown"),
            freeze_notes=tok.get("freeze_notes", ""),
            primary_contact=tok.get("primary_contact"),
            secondary_contact=tok.get("secondary_contact"),
            jurisdiction=tok.get("jurisdiction", "unknown"),
        )
    return out


def match_freeze_asks(
    candidates: list[DormantCandidate],
    *,
    issuer_db: dict[tuple[Chain, str], IssuerEntry] | None = None,
    min_holding_usd: Decimal = Decimal("1000"),
) -> tuple[list[FreezeAsk], list[TokenHolding]]:
    """For each candidate × token holding, look up issuer info and produce a
    FreezeAsk. Returns (matched_asks, unmatched_holdings).

    Holdings below ``min_holding_usd`` are dropped — even if a freeze is
    technically possible, the investigative cost outweighs sub-$1K seizures.

    Returns:
        matched_asks: sorted by USD value, descending.
        unmatched_holdings: tokens we don't have issuer info for. The user
                            should review these and add them to issuers.json
                            if they're worth chasing.
    """
    db = issuer_db if issuer_db is not None else load_issuer_db()
    matched: list[FreezeAsk] = []
    unmatched: list[TokenHolding] = []

    for candidate in candidates:
        for holding in candidate.holdings:
            if holding.usd_value is None or holding.usd_value < min_holding_usd:
                continue
            contract_lower = (holding.token.contract or "").lower()
            if not contract_lower:
                # Native token (ETH/SOL/etc.) — no issuer to contact for freeze
                unmatched.append(holding)
                continue
            key = (candidate.chain, contract_lower)
            issuer_entry = db.get(key)
            if issuer_entry is None:
                unmatched.append(holding)
                continue
            matched.append(FreezeAsk(
                candidate_address=candidate.address,
                chain=candidate.chain,
                holding_symbol=holding.token.symbol,
                holding_decimal_amount=holding.decimal_amount,
                holding_usd_value=holding.usd_value,
                issuer=issuer_entry,
                explorer_url=candidate.explorer_url,
            ))

    matched.sort(
        key=lambda a: a.holding_usd_value or Decimal("0"),
        reverse=True,
    )
    return matched, unmatched


def group_by_issuer(asks: list[FreezeAsk]) -> dict[str, list[FreezeAsk]]:
    """Group freeze asks by issuer name. Useful for sending one consolidated
    email per issuer rather than N separate emails."""
    out: dict[str, list[FreezeAsk]] = {}
    for ask in asks:
        out.setdefault(ask.issuer.issuer, []).append(ask)
    return out
