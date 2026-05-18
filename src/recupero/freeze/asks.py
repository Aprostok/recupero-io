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
    """One row from the issuer database.

    ``delegates_to`` is the v0.7.5 addition. When set, this token's
    freeze action delegates to another token's issuer (the underlying).
    Example: Aave aUSDC delegates_to USDC's contract on the same chain
    — Circle freezing the underlying USDC effectively freezes the
    aUSDC position (the aToken is just a receipt for the underlying
    USDC deposit in Aave; on redeem, the user receives whatever the
    aToken contract holds, which is the underlying USDC, which is
    frozen).

    The downstream effect: when match_freeze_asks encounters a
    holding whose IssuerEntry has delegates_to set, it produces TWO
    actionable freeze targets — one against the wrapper's nominal
    issuer (often "no" freeze capability for protocols like Aave),
    and one against the underlying's issuer (the actual freeze
    point). The brief surfaces both so the operator can decide
    which letter to send.

    Format: lowercased contract address of the underlying token on
    the same chain. The loader resolves this at db-load time into
    a reference to the delegated IssuerEntry; consumers see a
    populated ``delegates_to_entry`` attribute on the wrapper.
    """
    chain: Chain
    contract: str           # always lowercased
    symbol: str
    issuer: str
    freeze_capability: str  # "yes", "limited", "no"
    freeze_notes: str
    primary_contact: str | None
    secondary_contact: str | None
    jurisdiction: str
    # v0.7.5 — see class docstring.
    delegates_to: str | None = None              # underlying contract
    delegates_to_entry: IssuerEntry | None = None  # resolved at load


@dataclass
class FreezeAsk:
    """One actionable freeze request to a single issuer about a single holding.

    Two evidence types coexist (v0.14.8):

      * ``'current_balance'`` — the address currently holds the
        described tokens. Highest-urgency: act fast, funds may still
        be there. Produced by ``match_freeze_asks(dormant_candidates)``.

      * ``'historical_inflow'`` — the trace shows this address
        RECEIVED stolen tokens at one point. Current balance may be
        zero. The letter to the issuer reads as an investigative
        request rather than a freeze-now-before-they-move-it
        urgency. Produced by ``synthesize_historical_freeze_asks(case)``.
        Critical for cases that hit Recupero weeks/months after the
        incident — the original funds have moved, but the trace
        evidence is still actionable for issuer outreach (and the
        next-hop subpoena workflow).
    """
    candidate_address: str          # the wallet holding the funds
    chain: Chain
    holding_symbol: str
    holding_decimal_amount: Decimal
    holding_usd_value: Decimal | None
    issuer: IssuerEntry             # who to contact
    explorer_url: str
    evidence_type: str = "current_balance"
    # When evidence_type='historical_inflow', this is the date the
    # inflow was observed in the trace. Used by the letter template.
    observed_at_iso: str | None = None
    # Number of distinct inbound transfers observed (for
    # historical_inflow). >1 indicates repeated dispersal pattern.
    observed_transfer_count: int = 1

    def short_summary(self) -> str:
        usd = f"${self.holding_usd_value:,.2f}" if self.holding_usd_value else "?"
        suffix = (
            f" [HISTORICAL — observed in trace]"
            if self.evidence_type == "historical_inflow" else ""
        )
        return (
            f"{self.holding_decimal_amount:,.2f} {self.holding_symbol} ({usd}) "
            f"at {self.candidate_address} → {self.issuer.issuer}{suffix}"
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


# ---------- Onward-CEX flow models (v0.14.10) ---------- #


@dataclass
class OnwardCEXFlow:
    """One detected flow where stolen funds passed FROM a freezable-
    token holding address TO a CEX deposit address.

    Pattern Jacob flagged: when address A (freeze-target, e.g. holds
    USDT) forwards to address B (CEX-labeled, e.g. Binance hot
    wallet), the recovery workflow needs BOTH:

      1. Freeze letter to Tether about address A (handled by the
         FreezeAsk pipeline — current_balance OR historical_inflow).
      2. Subpoena letter to the CEX about address B citing the
         documented theft trail from A → B (handled here).

    The subpoena letter to the CEX can demand:
      - KYC records on the customer who controlled B
      - Internal account activity post-deposit
      - On-platform onward routing / off-ramp records

    Without this linkage, the brief lists CEX deposits as a flat
    list. With it, each CEX deposit carries upstream context that
    makes the subpoena letter materially stronger.
    """
    upstream_address: str            # the freezable-token holder (address A)
    cex_address: str                 # the CEX deposit address (address B)
    chain: Chain
    exchange: str                    # "Binance", "Coinbase", etc.
    label_name: str
    label_category: str              # "exchange_deposit" | "exchange_hot_wallet"
    token_symbol: str                # what token flowed A→B (e.g., "USDT")
    flow_usd_value: Decimal
    flow_amount_decimal: Decimal
    transfer_count: int              # ≥1 transfers A→B
    first_flow_at: datetime
    last_flow_at: datetime
    upstream_explorer_url: str       # link to address A on the chain explorer
    cex_explorer_url: str            # link to address B
    tx_hashes: list[str]             # per-transfer evidence

    def short_summary(self) -> str:
        usd = f"${self.flow_usd_value:,.2f}"
        return (
            f"{usd} {self.token_symbol} flowed "
            f"{self.upstream_address[:10]}…{self.upstream_address[-6:]} "
            f"→ {self.exchange} ({self.cex_address[:10]}…{self.cex_address[-6:]}) "
            f"in {self.transfer_count} transfer(s)"
        )


def synthesize_onward_cex_subpoenas(
    case: Case,
    *,
    upstream_freeze_target_addresses: set[str],
    label_store: "LabelStore | None" = None,
    min_flow_usd: Decimal = Decimal("1000"),
) -> list[OnwardCEXFlow]:
    """Detect flows from freeze-target addresses to CEX deposit
    addresses, emit OnwardCEXFlow records for subpoena-letter
    generation (v0.14.10).

    Args:
      case: the trace.
      upstream_freeze_target_addresses: addresses already identified
        as freeze targets (from match_freeze_asks +
        synthesize_historical_freeze_asks). The synthesizer looks
        for transfers FROM these.
      label_store: optional preloaded LabelStore. If None, loads
        the default config-bound one.
      min_flow_usd: aggregate threshold for surfacing a flow.

    Returns: list of OnwardCEXFlow records sorted by USD desc.

    Returns [] when no upstream freeze-target addresses are supplied
    (which is the common case for early-pipeline runs — the
    operator runs list-freeze-targets which produces this set,
    then this function uses it).
    """
    upstream_lower = {a.lower() for a in upstream_freeze_target_addresses}
    if not upstream_lower:
        return []

    # Resolve label store. The function is callable without a config
    # bundle so tests can pass a dict-shaped stub.
    if label_store is None:
        try:
            from recupero.config import load_config as _load_config
            from recupero.labels.store import LabelStore as _LabelStore
            cfg, _env = _load_config()
            label_store = _LabelStore.load(cfg)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "synthesize_onward_cex_subpoenas: label_store load failed: %s",
                exc,
            )
            return []

    # Aggregate per (upstream_address, cex_address, token_symbol).
    agg: dict[tuple[str, str, str], dict] = {}
    for t in case.transfers:
        from_lower = (t.from_address or "").lower()
        if from_lower not in upstream_lower:
            continue
        to_addr = t.to_address or ""
        if not to_addr:
            continue
        # Check if the to_address has a CEX label.
        label = label_store.lookup(to_addr)
        if label is None:
            continue
        cat = (
            label.category.value if hasattr(label.category, "value")
            else str(label.category)
        )
        if cat not in ("exchange_deposit", "exchange_hot_wallet"):
            continue
        # Pull exchange name. Label.exchange is preferred; otherwise
        # parse from name (e.g. "Binance: Hot Wallet 14" → "Binance").
        exchange_name = getattr(label, "exchange", None)
        if not exchange_name:
            name = label.name or ""
            exchange_name = name.split(":")[0].strip() or "(unknown exchange)"

        key = (from_lower, to_addr.lower(), t.token.symbol)
        bucket = agg.setdefault(key, {
            "upstream_address": from_lower,
            "cex_address": to_addr.lower(),
            "chain": t.chain,
            "exchange": exchange_name,
            "label_name": label.name,
            "label_category": cat,
            "token_symbol": t.token.symbol,
            "flow_usd_value": Decimal("0"),
            "flow_amount_decimal": Decimal("0"),
            "transfer_count": 0,
            "first_flow_at": t.block_time,
            "last_flow_at": t.block_time,
            "tx_hashes": [],
        })
        if t.usd_value_at_tx is not None:
            bucket["flow_usd_value"] += t.usd_value_at_tx
        bucket["flow_amount_decimal"] += t.amount_decimal
        bucket["transfer_count"] += 1
        bucket["tx_hashes"].append(t.tx_hash)
        if t.block_time < bucket["first_flow_at"]:
            bucket["first_flow_at"] = t.block_time
        if t.block_time > bucket["last_flow_at"]:
            bucket["last_flow_at"] = t.block_time

    out: list[OnwardCEXFlow] = []
    for bucket in agg.values():
        if bucket["flow_usd_value"] < min_flow_usd:
            continue
        out.append(OnwardCEXFlow(
            upstream_address=bucket["upstream_address"],
            cex_address=bucket["cex_address"],
            chain=bucket["chain"],
            exchange=bucket["exchange"],
            label_name=bucket["label_name"],
            label_category=bucket["label_category"],
            token_symbol=bucket["token_symbol"],
            flow_usd_value=bucket["flow_usd_value"],
            flow_amount_decimal=bucket["flow_amount_decimal"],
            transfer_count=bucket["transfer_count"],
            first_flow_at=bucket["first_flow_at"],
            last_flow_at=bucket["last_flow_at"],
            upstream_explorer_url=_explorer_address_url(
                bucket["chain"], bucket["upstream_address"],
            ),
            cex_explorer_url=_explorer_address_url(
                bucket["chain"], bucket["cex_address"],
            ),
            tx_hashes=bucket["tx_hashes"],
        ))

    out.sort(key=lambda f: f.flow_usd_value, reverse=True)
    log.info(
        "synthesize_onward_cex_subpoenas: emitted %d flow(s) above $%.2f "
        "threshold from %d upstream freeze target(s)",
        len(out), float(min_flow_usd), len(upstream_lower),
    )
    return out


def group_onward_cex_flows_by_exchange(
    flows: list[OnwardCEXFlow],
) -> dict[str, list[OnwardCEXFlow]]:
    """Group onward-CEX flows by exchange name — operator sends ONE
    consolidated subpoena per exchange, not one per CEX address."""
    out: dict[str, list[OnwardCEXFlow]] = {}
    for f in flows:
        out.setdefault(f.exchange, []).append(f)
    return out


# ---------- Issuer loading & matching ---------- #


def load_issuer_db(path: Path | None = None) -> dict[tuple[Chain, str], IssuerEntry]:
    """Load issuers.json into a dict keyed by (chain, contract_lower).

    Two-pass loader:
      1. Pass 1 — instantiate every IssuerEntry with raw
         delegates_to contract string.
      2. Pass 2 — resolve delegates_to into a reference to the
         actual target IssuerEntry. Logs a warning + leaves the
         reference None if the target isn't in the same load
         (typo in delegates_to, target on a different chain,
         target not yet added).

    Two-pass shape is required because A.delegates_to may
    reference B which loads later in the JSON array.
    """
    src = path or _ISSUER_DB_PATH
    raw = json.loads(src.read_text(encoding="utf-8-sig"))
    out: dict[tuple[Chain, str], IssuerEntry] = {}
    # Pass 1: populate every entry.
    for tok in raw.get("tokens", []):
        try:
            chain = Chain(tok["chain"])
        except (ValueError, KeyError):
            log.debug("skipping issuer entry with unknown chain: %s", tok)
            continue
        contract = (tok.get("contract") or "").lower()
        if not contract:
            continue
        delegates_to_raw = tok.get("delegates_to")
        delegates_to = (
            delegates_to_raw.lower()
            if isinstance(delegates_to_raw, str) and delegates_to_raw.strip()
            else None
        )
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
            delegates_to=delegates_to,
        )
    # Pass 2: resolve cross-references.
    for entry in out.values():
        if entry.delegates_to is None:
            continue
        target = out.get((entry.chain, entry.delegates_to))
        if target is None:
            log.warning(
                "issuer %s/%s declares delegates_to=%s on chain %s, "
                "but no matching IssuerEntry was loaded; freeze action "
                "will fall back to wrapper's nominal issuer",
                entry.issuer, entry.symbol, entry.delegates_to,
                entry.chain.value,
            )
            continue
        entry.delegates_to_entry = target
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


def synthesize_historical_freeze_asks(
    case: Case,
    *,
    issuer_db: dict[tuple[Chain, str], IssuerEntry] | None = None,
    min_inflow_usd: Decimal = Decimal("1000"),
    exclude_addresses: set[str] | None = None,
) -> list[FreezeAsk]:
    """Generate FreezeAsk records from HISTORICAL trace evidence (v0.14.8).

    The dormant detector (`find_dormant_in_case`) only catches addresses
    that CURRENTLY hold balances. For cases that reach Recupero weeks or
    months after the incident, the perpetrator has typically moved the
    funds on — current balances are zero, and no freeze letters get
    generated.

    This function walks `case.transfers` directly and emits FreezeAsk
    records for any (address, token_contract) pair where:

      1. The token has an issuer entry in the issuer DB
         (USDT/USDC/cbBTC/PYUSD/etc. — the freezable set).
      2. The total observed inflow to the address is >= min_inflow_usd.

    Emitted asks carry `evidence_type='historical_inflow'`. The
    freeze-letter template uses this to switch language from
    "freeze NOW" → "investigative request: these tokens passed
    through this address as part of a documented theft on [date]".

    Args:
      case: the trace case.
      issuer_db: optional preloaded issuer DB (else loaded via
        load_issuer_db).
      min_inflow_usd: aggregate inflow threshold. Below this we skip
        — operator time outweighs sub-$1K investigative letters.
      exclude_addresses: addresses to skip (e.g. the victim's own
        seed wallet, or addresses already covered by
        current-balance freeze asks).

    Returns:
      List of FreezeAsk records sorted by holding_usd_value descending.
    """
    # Address normalization is chain-aware. EVM addresses are
    # case-insensitive hex; we lowercase for canonical keys. Tron /
    # Solana / Bitcoin addresses are base58 — lowercasing produces
    # invalid addresses that won't match anything. Preserve case for
    # those chains; the underlying address bytes ARE case-significant.
    chain_str = (
        case.chain.value
        if hasattr(case.chain, "value")
        else str(case.chain)
    ).lower()
    _CASE_SENSITIVE_CHAINS = {"tron", "solana", "bitcoin"}

    def _norm_addr(a: str | None) -> str:
        if not a:
            return ""
        return a if chain_str in _CASE_SENSITIVE_CHAINS else a.lower()

    db = issuer_db if issuer_db is not None else load_issuer_db()
    exclude = {_norm_addr(a) for a in (exclude_addresses or set())}
    if case.seed_address:
        exclude.add(_norm_addr(case.seed_address))

    # Aggregate per (to_address, token_contract): sum USD, sum decimal
    # amount, count transfers, earliest observation timestamp.
    agg: dict[tuple[str, str], dict] = {}
    for t in case.transfers:
        to_addr = _norm_addr(t.to_address)
        if not to_addr or to_addr in exclude:
            continue
        # Skip transfers FROM the to_addr to itself (rare but observed).
        if to_addr == _norm_addr(t.from_address):
            continue
        # Need a contract to match issuer DB (native ETH doesn't have
        # an issuer freeze pathway anyway). Contracts are token
        # identifiers — always lowercased for the DB lookup key
        # regardless of chain (issuers.json stores them lowercase).
        contract = (t.token.contract or "").lower()
        if not contract:
            continue
        key = (to_addr, contract)
        bucket = agg.setdefault(key, {
            "to_address": to_addr,
            "chain": t.chain,
            "token": t.token,
            "total_usd": Decimal("0"),
            "total_amount_decimal": Decimal("0"),
            "transfer_count": 0,
            "earliest_block_time": t.block_time,
            "explorer_url": t.explorer_url,
        })
        if t.usd_value_at_tx is not None:
            bucket["total_usd"] += t.usd_value_at_tx
        bucket["total_amount_decimal"] += t.amount_decimal
        bucket["transfer_count"] += 1
        if t.block_time < bucket["earliest_block_time"]:
            bucket["earliest_block_time"] = t.block_time
            # Store the FIRST observation's explorer URL as
            # representative for the letter.
            bucket["explorer_url"] = t.explorer_url

    out: list[FreezeAsk] = []
    for bucket in agg.values():
        if bucket["total_usd"] < min_inflow_usd:
            continue
        chain = bucket["chain"]
        contract_lower = (bucket["token"].contract or "").lower()
        issuer_entry = db.get((chain, contract_lower))
        if issuer_entry is None:
            # No issuer to contact — skip (these become
            # 'unmatched' equivalents handled by the operator review
            # flow, but historical-inflow asks intentionally only
            # surface addresses where issuer freeze is plausible).
            continue
        # Skip non-freezable issuer entries (e.g., Sky Protocol /
        # MakerDAO has freeze_capability='no'). A freeze letter to
        # them wastes everyone's time.
        if (issuer_entry.freeze_capability or "").lower() == "no":
            continue

        # Get the address-specific explorer URL via the chain
        # convention. Fall back to the tx URL if needed.
        addr_url = _explorer_address_url(chain, bucket["to_address"])
        observed_iso = bucket["earliest_block_time"].isoformat().replace("+00:00", "Z")

        out.append(FreezeAsk(
            candidate_address=bucket["to_address"],
            chain=chain,
            holding_symbol=bucket["token"].symbol,
            holding_decimal_amount=bucket["total_amount_decimal"],
            holding_usd_value=bucket["total_usd"],
            issuer=issuer_entry,
            explorer_url=addr_url or bucket["explorer_url"],
            evidence_type="historical_inflow",
            observed_at_iso=observed_iso,
            observed_transfer_count=bucket["transfer_count"],
        ))

    out.sort(
        key=lambda a: a.holding_usd_value or Decimal("0"),
        reverse=True,
    )
    log.info(
        "synthesize_historical_freeze_asks: emitted %d ask(s) above "
        "$%.2f threshold from %d transfer(s)",
        len(out), float(min_inflow_usd), len(case.transfers),
    )
    return out


def _explorer_address_url(chain: Chain, address: str) -> str:
    """Best-effort address-page URL per chain. Used when synthesizing
    historical freeze asks where we don't have a single representative
    tx URL handy.

    Sources the prefix from the centralized _common table so adding a
    new chain only requires one update.
    """
    from recupero._common import ADDRESS_EXPLORER_BY_CHAIN
    chain_value = chain.value if hasattr(chain, "value") else str(chain)
    prefix = ADDRESS_EXPLORER_BY_CHAIN.get(chain_value)
    if not prefix:
        return ""
    return f"{prefix}{address}"


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
        # Use the right explorer for the case's chain, not a hardcoded
        # etherscan URL (was wrong for Solana / Tron / Bitcoin CEX
        # deposits — addresses 404'd in operator click-throughs).
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
            explorer_url=_explorer_address_url(case.chain, addr),
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
