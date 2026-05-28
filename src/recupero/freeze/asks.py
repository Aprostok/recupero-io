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
from typing import Any

from recupero.dormant.finder import DormantCandidate, TokenHolding
from recupero.labels.store import LabelStore
from recupero.labels.store import lookup_pit_safe  # v0.31.4
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

    def __post_init__(self) -> None:
        """Guard against impossible negative, NaN, or Infinite amounts that
        would produce freeze letters saying 'freeze -$47,320' or 'freeze
        $Infinity' — rejected by compliance teams and a pipeline sign error.
        A malformed chain-adapter response (negative/NaN RPC balance) would
        silently propagate without this check.
        """
        # v0.20.10 (R14-D LOW): guard against NaN / Infinity in addition to
        # negatives. Decimal NaN raises InvalidOperation on comparison;
        # Decimal Infinity passes `>= 0` silently, rendering as "$Infinity"
        # on legal documents.
        for _field, _val in (
            ("holding_decimal_amount", self.holding_decimal_amount),
            ("holding_usd_value", self.holding_usd_value),
        ):
            if _val is None:
                continue
            if not _val.is_finite():
                raise ValueError(
                    f"FreezeAsk.{_field} must be a finite Decimal, "
                    f"got {_val!r}"
                )
            if _val < 0:
                raise ValueError(
                    f"FreezeAsk.{_field} must be >= 0, got {_val!r}"
                )

    def short_summary(self) -> str:
        usd = f"${self.holding_usd_value:,.2f}" if self.holding_usd_value else "?"
        suffix = (
            " [HISTORICAL — observed in trace]"
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
    label_store: LabelStore | None = None,
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
    # v0.18.0 (round-11 freeze.asks-CRIT-006/007): canonical-key the
    # upstream set AND pass `chain=case.chain` to label_store.lookup.
    # Pre-v0.18.0 base58 addresses were mangled (lowercased) so
    # upstream membership always missed for Solana/Tron/Bitcoin; AND
    # the label lookup defaulted to Chain.ethereum (since no `chain`
    # arg was passed), so `to_checksum_address` was attempted on a
    # base58 string → ValueError → label=None → every flow was
    # silently filtered out. Net effect: Solana/Tron CEX subpoena
    # recommendations always empty.
    from recupero._common import canonical_address_key as _ck
    upstream_lower = {_ck(a) for a in upstream_freeze_target_addresses}
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
        from_lower = _ck(t.from_address or "")
        if from_lower not in upstream_lower:
            continue
        to_addr = t.to_address or ""
        if not to_addr:
            continue
        # Check if the to_address has a CEX label.
        # v0.31.4 (Gap 1a): point-in-time lookup against case incident.
        label = lookup_pit_safe(label_store, to_addr, chain=case.chain, point_in_time=case.incident_time,)
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

        to_key = _ck(to_addr)
        key = (from_lower, to_key, t.token.symbol)
        bucket = agg.setdefault(key, {
            "upstream_address": from_lower,
            "cex_address": to_key,
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
        # v0.30.4 (V030_2_CORRECTNESS_AUDIT T1-B): finite-only sum on
        # the onward-flow USD bucket. A NaN poisons the per-issuer
        # asks accumulator; the freeze letter then shows `$NaN` as
        # the amount we're asking the issuer to freeze.
        if t.usd_value_at_tx is not None and t.usd_value_at_tx.is_finite():
            bucket["flow_usd_value"] += t.usd_value_at_tx
        if t.amount_decimal is not None and t.amount_decimal.is_finite():
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
    # v0.18.0 (round-11 pricing-CRIT-003/004): chain-aware
    # canonical-key normalization. Pre-v0.18.0 every contract was
    # unconditionally lowercased — which is fine for EVM hex
    # (case-insensitive) but PRODUCES INVALID on-chain addresses
    # for Solana / Tron / Bitcoin (base58 is case-sensitive at the
    # network layer). Solana USDC `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`
    # lowercased to `epjfwdd5...` is not a valid Solana mint
    # address, breaking dormant detection + pricing entirely on
    # those chains.
    from recupero._common import canonical_address_key as _ck
    # Pass 1: populate every entry.
    for tok in raw.get("tokens", []):
        try:
            chain = Chain(tok["chain"])
        except (ValueError, KeyError):
            log.debug("skipping issuer entry with unknown chain: %s", tok)
            continue
        contract = _ck(tok.get("contract") or "")
        if not contract:
            continue
        delegates_to_raw = tok.get("delegates_to")
        delegates_to = (
            _ck(delegates_to_raw)
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
    # v0.19.1 (round-12 forensic-HIGH-1): use the canonical key so the
    # consumer-side lookup matches the writer-side (load_issuer_db) which
    # v0.18.0 fixed to case-preserve Solana/Tron base58 mints. Pre-v0.19.1
    # this consumer kept the legacy `.lower()` so every Solana stablecoin
    # freeze ask (USDC `EPjFWdd5...`, USDT `Es9vMFrz...`) silently lower-
    # cased to a non-on-chain key, missed the DB lookup, and got routed
    # to `unmatched` — no freeze letters generated on Solana cases despite
    # the writer-side fix.
    from recupero._common import canonical_address_key as _ck
    db = issuer_db if issuer_db is not None else load_issuer_db()
    matched: list[FreezeAsk] = []
    unmatched: list[TokenHolding] = []

    # v0.20.1 (Jacob V-CFI01 residual #4): conservative absolute-value cap.
    # No legitimate single-victim recoverable balance exceeds this. The
    # biggest stolen-funds theft cases top out near $50M of a single
    # stablecoin at a single wallet; anything above $100M at a single
    # address holding a single token is overwhelmingly a protocol/pool
    # contract (Lido wstETH custody holds ~$8.8B of stETH; WETH9 holds
    # all wrapped ETH; etc.). Pre-v0.20.1 these contract balances got
    # emitted as freeze_asks; the brief writer's freeze_capability=no
    # tagging kept them out of customer letters, but they polluted the
    # freeze_asks.json file and the diagnostic surface area downstream
    # ops paths consume. The right place to stop them is at synthesis.
    _ABSOLUTE_CAP_USD = Decimal("100000000")  # $100M
    for candidate in candidates:
        for holding in candidate.holdings:
            # RIGOR-Jacob Z18-1 (HIGH, DoS): defense-in-depth — drop
            # non-finite usd_value BEFORE the comparator. ``TokenHolding``
            # is a plain dataclass with no Pydantic validator, so a
            # holding deserialized from a stale case.json whose price
            # cache was poisoned (RIGOR-Jacob F only hardened CoinGecko
            # ingest), OR built outside dormant.finder._check_one_address
            # (Z10's fix is local), can carry ``Decimal('NaN')`` or
            # ``Decimal('Infinity')``. Pre-fix:
            #   * NaN: the next line ``holding.usd_value < min_holding_usd``
            #     raises ``decimal.InvalidOperation`` → brief generator
            #     crashes mid-pipeline.
            #   * Infinity: silently absorbed by the $100M cap branch,
            #     which is misleading (it's not a giant pool, it's
            #     corrupted data).
            # Now: filter at the boundary, same semantics as a
            # holding whose price lookup failed (treated as unmatched
            # if no other holdings remain).
            if holding.usd_value is not None and not holding.usd_value.is_finite():
                log.warning(
                    "match_freeze_asks: dropping candidate %s holding of %s "
                    "with non-finite usd_value=%r — likely poisoned price "
                    "cache or hostile chain-adapter response",
                    candidate.address, holding.token.symbol,
                    holding.usd_value,
                )
                continue
            if holding.usd_value is None or holding.usd_value < min_holding_usd:
                continue
            if holding.usd_value > _ABSOLUTE_CAP_USD:
                log.warning(
                    "match_freeze_asks: skipping candidate %s holding %s of "
                    "%s ($%s) — exceeds the $100M absolute cap; "
                    "near-certain protocol/pool contract, not a wallet. "
                    "If this is a legitimate freeze target, please open "
                    "a manual review.",
                    candidate.address, holding.decimal_amount,
                    holding.token.symbol, holding.usd_value,
                )
                continue
            contract_key = _ck(holding.token.contract or "")
            if not contract_key:
                # Native token (ETH/SOL/etc.) — no issuer to contact for freeze
                unmatched.append(holding)
                continue
            key = (candidate.chain, contract_key)
            issuer_entry = db.get(key)
            if issuer_entry is None:
                unmatched.append(holding)
                continue
            # v0.27.2 (Jacob 0x52Aa bleed fix, small-item-3): drop
            # canonical-wrapper pseudo-issuer entries entirely. WETH +
            # similar wrappers in issuers.json carry the literal
            # sentinel "(none — canonical wrapper)" as their issuer
            # name (issuers.json:256) with freeze_capability="no" and
            # primary_contact=None. They have no real freeze pathway
            # — holdings reported as WETH should be treated as raw ETH
            # for seizure (per the issuers.json freeze_notes field).
            # Pre-fix these landed in freeze_asks.json under the
            # pseudo-issuer name and surfaced as a confusing extra
            # entry in the by_issuer breakdown. They still surface in
            # trace_report.html and investigator_findings.{csv,json}
            # for chain-of-custody completeness — they're just not a
            # freeze ask. Step-3 (subpoena-targets artifact family)
            # will give them a proper home.
            if (issuer_entry.issuer or "").strip().startswith("(none"):
                log.info(
                    "match_freeze_asks: dropping %s/%s holding at %s "
                    "(issuer='%s' — canonical wrapper / no real issuer)",
                    candidate.chain, holding.token.symbol,
                    candidate.address, issuer_entry.issuer,
                )
                continue
            # v0.20.2 (audit-round-2 finding #5): DO NOT skip
            # freeze_capability="no" holdings here. The v0.20.1 attempt
            # at this looked clean for freeze_asks.json hygiene but
            # caused a much worse downstream regression: emit_brief's
            # `_compute_perpetrator_holdings` iterates ONLY the
            # `freezable` list (which is built from these asks). Routing
            # freeze_capability=no holdings to `unmatched` silently
            # dropped them from the brief entirely — including the
            # $18M dormant DAI on Jacob's CFI-00265 case which was
            # advertised in this module's docstring as the framing
            # number for that case. Now: emit the ask; let the brief's
            # downstream `_extract_freezable` correctly tag it as
            # UNRECOVERABLE via `capability_blocks_freeze` so the perp
            # holdings still surface in the headline. The freeze-letter
            # template + customer summary already correctly filter on
            # `freeze_capability` when deciding what to send to whom.
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
    # v0.20.2 (audit-round-3 R3-7): use the centralized
    # `canonical_address_key` instead of the hand-rolled
    # chain-sensitivity table. The hand-rolled version had two
    # latent bugs:
    #   1. The CASE_SENSITIVE_CHAINS set only listed tron / solana /
    #      bitcoin — Hyperliquid + any new base58 chain were silently
    #      lower-cased into invalid addresses.
    #   2. The chain_str was derived from `case.chain` — for a
    #      cross-chain trace (EVM seed bridged to Tron USDT), the
    #      per-transfer chain didn't drive normalization, so the
    #      base58 Tron destinations got EVM-lowercased.
    # canonical_address_key is chain-agnostic: it sniffs `0x` + 40
    # hex and lowercases EVM, preserves case otherwise. One source
    # of truth across the codebase.
    from recupero._common import canonical_address_key as _norm_addr

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
        # an issuer freeze pathway anyway). v0.19.1 (round-12
        # forensic-HIGH-1): canonical_address_key — case-preserves
        # Solana/Tron base58 mints, lowercases EVM hex. Pre-v0.19.1
        # `.lower()` mangled Solana mints to a non-on-chain string and
        # missed the DB lookup for every Solana historical-inflow ask.
        from recupero._common import canonical_address_key as _ck_token
        contract = _ck_token(t.token.contract or "")
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
        # v0.30.4 (V030_2_CORRECTNESS_AUDIT T1-B): finite-only sum on
        # the historical-inflow USD bucket. Same defense-in-depth as
        # the flow_usd_value bucket above.
        if t.usd_value_at_tx is not None and t.usd_value_at_tx.is_finite():
            bucket["total_usd"] += t.usd_value_at_tx
        if t.amount_decimal is not None and t.amount_decimal.is_finite():
            bucket["total_amount_decimal"] += t.amount_decimal
        bucket["transfer_count"] += 1
        if t.block_time < bucket["earliest_block_time"]:
            bucket["earliest_block_time"] = t.block_time
            # Store the FIRST observation's explorer URL as
            # representative for the letter.
            bucket["explorer_url"] = t.explorer_url

    out: list[FreezeAsk] = []
    # v0.19.1 (round-12 forensic-HIGH-1): canonical key for the second
    # DB lookup, matching the writer-side issuers.json normalization.
    from recupero._common import canonical_address_key as _ck_bucket
    for bucket in agg.values():
        if bucket["total_usd"] < min_inflow_usd:
            continue
        chain = bucket["chain"]
        contract_key = _ck_bucket(bucket["token"].contract or "")
        issuer_entry = db.get((chain, contract_key))
        if issuer_entry is None:
            # No issuer to contact — skip (these become
            # 'unmatched' equivalents handled by the operator review
            # flow, but historical-inflow asks intentionally only
            # surface addresses where issuer freeze is plausible).
            continue
        # v0.20.2 (audit-round-3 R3-1): DO NOT skip
        # freeze_capability="no" issuers here. Same lesson as the
        # match_freeze_asks fix in audit-round-2 finding #5:
        # `_compute_perpetrator_holdings` and the brief's freezable
        # list need to SEE these holdings so the headline
        # perpetrator-holdings total includes UNRECOVERABLE rows
        # (e.g., DAI / Sky Protocol). The capability_blocks_freeze
        # filter at letter-generation time correctly suppresses the
        # actual freeze letter — but we must NOT drop the data here,
        # or downstream consumers silently lose visibility of those
        # funds. Pre-v0.20.2 a V-CFI01-shape historical-only case
        # with $18M DAI inflow showed $0 perpetrator-holdings.

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
    # v0.19.1 (round-12 forensic-HIGH-3): on Solana/Tron, the same CEX
    # wallet can arrive in mixed-case forms from different code paths
    # (adapter raw vs label-store post-normalize). Keying by raw t.to_address
    # split per-wallet aggregates into two ExchangeDeposit rows, each with
    # half the USD and split windows. Now: aggregate on canonical key,
    # preserve original case in a `display_addr` map for output. Mirrors
    # the v0.18.3 fix in `_compute_exchange_endpoints` (trace/tracer.py).
    from recupero._common import canonical_address_key as _ck_addr
    per_addr_display: dict[str, str] = {}
    # v0.20.2 (audit-round-3 R3-8): track per-deposit chain so a
    # cross-chain bridge → CEX deposit (drain on ETH, surfaces on
    # Tron Binance) records the right chain on the ExchangeDeposit
    # row. Pre-v0.20.2 we hardcoded `case.chain` for both the
    # `chain` field and the explorer URL — so a Tron Binance hot
    # wallet on an ETH-seeded case got an `etherscan.io/address/...`
    # URL → 404, and the operator's subpoena routing key (per-
    # chain MLAT) was wrong.
    per_addr_chain: dict[str, Any] = {}

    exchange_categories = {LabelCategory.exchange_deposit, LabelCategory.exchange_hot_wallet}

    for t in case.transfers:
        to_addr_raw = t.to_address
        # Per-transfer chain — needed both for the lookup and for
        # downstream chain-attribution of the deposit row.
        t_chain = t.chain if t.chain is not None else case.chain
        # v0.31.4 (Gap 1a): point-in-time lookup.
        label = lookup_pit_safe(label_store, to_addr_raw, chain=t_chain, point_in_time=case.incident_time,)
        if label is None or label.category not in exchange_categories:
            continue

        to_addr = _ck_addr(to_addr_raw)
        if not to_addr:
            continue
        # Remember the first-seen original case for display.
        per_addr_display.setdefault(to_addr, to_addr_raw)
        # First-seen chain wins (matches first-seen-display
        # convention). On the rare cross-chain CEX merge it'd be
        # operator-confusing to flip the chain mid-aggregate.
        per_addr_chain.setdefault(to_addr, t_chain)

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
    for canon_addr, total_usd in per_addr_usd.items():
        if total_usd < min_deposit_usd:
            continue
        # Aggregates keyed by canonical form; display form uses the
        # first-seen original case for explorer-link compatibility.
        addr = per_addr_display.get(canon_addr, canon_addr)
        deposit_chain = per_addr_chain.get(canon_addr, case.chain)
        label = per_addr_label[canon_addr]
        out.append(ExchangeDeposit(
            candidate_address=addr,
            chain=deposit_chain,
            exchange=label.exchange or label.name,  # fallback to name if exchange field missing
            label_name=label.name,
            label_category=label.category.value,
            label_confidence=label.confidence,
            total_deposited_usd=total_usd,
            deposit_count=per_addr_count[canon_addr],
            first_deposit_at=per_addr_first.get(canon_addr),
            last_deposit_at=per_addr_last.get(canon_addr),
            explorer_url=_explorer_address_url(deposit_chain, addr),
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
