"""Issuer detection and exchange-deposit detection.

Given a list of dormant freeze candidates (each with token holdings), determine
WHO to contact to freeze each holding. Maps token contracts to issuer info
loaded from the seed `issuers.json`.

The output is a list of "freeze asks" — one per (candidate × freezable token),
ranked by USD value descending. Each ask carries everything an investigator
needs to send the request: address, amount, issuer name, contact email,
freeze-capability rating, and jurisdiction.

This module also handles exchange-deposit detection: scanning case transfers
for destinations labeled as CEX deposit addresses or hot wallets, so
investigators can issue subpoena-backed exchange letters (Exhibit C) in
addition to issuer freeze letters (Exhibit B).

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
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from recupero.dormant.finder import DormantCandidate, TokenHolding
from recupero.labels.store import LabelStore
from recupero.models import Case, Chain, Label, LabelCategory

log = logging.getLogger(__name__)


_ISSUER_DB_PATH = Path(__file__).parent.parent / "labels" / "seeds" / "issuers.json"


# ---------- Issuer models ---------- #


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


# ---------- Exchange deposit models ---------- #


@dataclass
class ExchangeDeposit:
    """One detected deposit to a CEX deposit address or hot wallet.

    Represents a single address (exchange-labeled) that received funds
    directly from any wallet in the trace. Total/count are aggregated
    across all inbound transfers in the case to this address.
    """
    candidate_address: str          # the exchange address funds were deposited TO
    chain: Chain
    exchange: str                    # "Binance", "Coinbase", etc. — from Label.exchange
    label_name: str                  # "Binance: Hot Wallet 14" — from Label.name
    label_category: str              # "exchange_deposit" | "exchange_hot_wallet"
    label_confidence: str            # "high" | "medium" | "low" — from Label.confidence
    total_deposited_usd: Decimal
    deposit_count: int               # how many separate transfers into this address
    first_deposit_at: datetime | None
    last_deposit_at: datetime | None
    explorer_url: str

    def short_summary(self) -> str:
        usd = f"${self.total_deposited_usd:,.2f}"
        return (
            f"{usd} in {self.deposit_count} deposit(s) at {self.candidate_address} "
            f"→ {self.exchange} ({self.label_category})"
        )


# ---------- Issuer loading & matching ---------- #


def load_issuer_db(path: Path | None = None) -> dict[tuple[Chain, str], IssuerEntry]:
    """Load issuers.json into a dict keyed by (chain, contract_lower)."""
    src = path or _ISSUER_DB_PATH
    raw = json.loads(src.read_text(encoding="utf-8-sig"))
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


# ---------- Exchange deposit detection ---------- #


def detect_exchange_deposits(
    case: Case,
    label_store: LabelStore,
    *,
    min_deposit_usd: Decimal = Decimal("1000"),
) -> list[ExchangeDeposit]:
    """Scan case.transfers for destinations labeled as exchange addresses.

    For each address in the trace that's tagged exchange_deposit or
    exchange_hot_wallet in the LabelStore, aggregate the inbound transfers
    and produce one ExchangeDeposit per address.

    Addresses with aggregate USD value below min_deposit_usd are dropped — a
    $50 sweep to Binance isn't worth a compliance letter.
    """
    # Group transfers by destination address, only for addresses that are
    # exchange-labeled. Track USD, count, first/last timestamps per address.
    per_addr_usd: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    per_addr_count: dict[str, int] = defaultdict(int)
    per_addr_first: dict[str, datetime] = {}
    per_addr_last: dict[str, datetime] = {}
    per_addr_label: dict[str, Label] = {}

    exchange_categories = {LabelCategory.exchange_deposit, LabelCategory.exchange_hot_wallet}

    for t in case.transfers:
        to_addr = t.to_address
        label = label_store.lookup(to_addr, chain=case.chain)
        if label is None or label.category not in exchange_categories:
            continue

        # Track aggregate inflows to this address
        if t.usd_value_at_tx is not None:
            per_addr_usd[to_addr] += t.usd_value_at_tx
        per_addr_count[to_addr] += 1
        per_addr_label[to_addr] = label
        bt = t.block_time
        if to_addr not in per_addr_first or bt < per_addr_first[to_addr]:
            per_addr_first[to_addr] = bt
        if to_addr not in per_addr_last or bt > per_addr_last[to_addr]:
            per_addr_last[to_addr] = bt

    out: list[ExchangeDeposit] = []
    for addr, total_usd in per_addr_usd.items():
        if total_usd < min_deposit_usd:
            continue
        label = per_addr_label[addr]
        # TODO: when multi-chain support ships, pick the right explorer base
        # from config.<chain>.explorer_base instead of hardcoding etherscan.io.
        out.append(ExchangeDeposit(
            candidate_address=addr,
            chain=case.chain,
            exchange=label.exchange or label.name,  # fallback to name if exchange field missing
            label_name=label.name,
            label_category=label.category.value,
            label_confidence=label.confidence,
            total_deposited_usd=total_usd,
            deposit_count=per_addr_count[addr],
            first_deposit_at=per_addr_first.get(addr),
            last_deposit_at=per_addr_last.get(addr),
            explorer_url=f"https://etherscan.io/address/{addr}",
        ))

    out.sort(key=lambda d: d.total_deposited_usd, reverse=True)
    return out


def group_exchange_deposits_by_exchange(
    deposits: list[ExchangeDeposit],
) -> dict[str, list[ExchangeDeposit]]:
    """Group exchange deposits by exchange name. Useful for sending one
    consolidated letter per exchange rather than N separate letters."""
    out: dict[str, list[ExchangeDeposit]] = {}
    for d in deposits:
        out.setdefault(d.exchange, []).append(d)
    return out
