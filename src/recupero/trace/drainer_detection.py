"""Drainer / approval-exploit signature detection (v0.10.1).

Wallet drainer scams follow a specific operational pattern:

  1. Victim signs a malicious permit / approval / setApprovalForAll
     transaction that grants the drainer infinite allowance over
     a token contract.
  2. The drainer immediately calls transferFrom (or batch-transfers
     via a router contract) to siphon the approved tokens into
     a perpetrator-controlled address.

The "approval" is the smoking gun for distinguishing drainer
theft (victim was deceived into signing) from operator error
(victim sent funds to wrong address). For a $499 diagnostic,
correctly classifying the case as drainer-theft drives:

  * The narrative tone in the victim_summary letter
  * The "Pink Drainer" / "Inferno Drainer" attribution if
    we recognize the perpetrator's fingerprints
  * The recovery path: drainer cases are subject to specific
    SAR / FinCEN reporting categories distinct from
    address-typo cases

This module:

  1. ``detect_approval_signatures(case)`` — scan ``case.transfers``
     for ERC-20 ``Approval`` / ``setApprovalForAll`` events where
     the victim's wallet approved a non-protocol contract. These
     are the smoking gun.

  2. ``detect_drainer_pattern(case)`` — combine approval +
     immediate transferFrom + outflow-to-known-drainer addresses
     to flag the drainer-theft classification with confidence.

  3. ``drainer_findings_to_brief_section(findings)`` — produces
     the JSON shape consumed by the brief.

Limitations
-----------

The Transfer model in the case schema captures ERC-20 transfer
events but not approval / permit events. v0.10.1 ships the
detection helpers + tests on synthetic data; full integration
requires the trace stage to also collect approval events, which
is a follow-up (the change is in the chain adapter, not here).

For now, this module operates on whatever signals the existing
case carries — primarily the ``counterparty.is_contract`` flag
and known-drainer address overlap from the high-risk DB.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from recupero.models import Case
    from recupero.trace.risk_scoring import HighRiskEntry

log = logging.getLogger(__name__)


# Method IDs of common drainer-exploit transactions. These are
# the function selectors that appear in the input data when a
# drainer exploits a victim approval. We can match against
# Transfer.tx_hash → fetch input → match method.
#
# Full integration awaits the trace stage capturing input_data;
# for now these constants are referenced by tests + documented
# as the targets for the v0.10.x integration.
# v0.32.1 test-public constants — ERC-20 Approval event topic0
# (keccak256 of "Approval(address,address,uint256)"). Used to match
# Approval logs against the drainer pattern.
APPROVAL_TOPIC0 = (
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
)


@dataclass(frozen=True)
class ApprovalEvent:
    """One ERC-20 / ERC-721 / ERC-1155 approval event suitable for
    drainer-pattern correlation.

    The fields mirror the on-chain Approval log shape after decoding,
    plus enough context (tx_hash, block_number, block_time) for the
    BFS to correlate with subsequent transferFrom outflows. v0.32.1
    added this as a first-class type so downstream consumers can
    type-check against an explicit dataclass rather than a free-form
    dict."""
    owner: str
    spender: str
    token_contract: str
    amount_raw: str
    tx_hash: str
    block_number: int
    block_time: datetime


_DRAINER_METHOD_SIGNATURES = {
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x42842e0e": "safeTransferFrom(address,address,uint256)",  # ERC-721
    "0xf242432a": "safeTransferFrom(address,address,uint256,uint256,bytes)",  # ERC-1155
    # Permit2 signatures — common in drainer kits since they let
    # the victim sign once for many tokens.
    "0xe7a050aa": "permitTransferFrom",
    "0x36c78516": "transferFrom(bytes,address,address,uint256)",
    # Common drainer batch routers
    "0xfa461e33": "drainTokens(address[],uint256[],address)",
}


@dataclass(frozen=True)
class DrainerSignal:
    """One detected drainer-pattern signal."""
    signal_type: str        # 'approval_to_unknown_contract' | 'transfer_from_pattern' | 'known_drainer_outflow' | 'permit_signature_observed'
    address: str            # the address THIS signal is about (typically the victim)
    counterparty: str       # the contract / drainer-controlled address
    counterparty_name: str  # 'Pink Drainer' / '(unknown contract)' / etc.
    severity: str           # 'critical' | 'high' | 'medium'
    description: str        # one-line explanation
    confidence: str         # 'high' | 'medium' | 'low'


@dataclass(frozen=True)
class DrainerEvent:
    """A concrete drainer-attack event surfaced to the BFS / brief
    timeline (v0.32.1, CRIT-4).

    Where DrainerSignal carries the narrative shape consumed by the
    classification section of the brief, DrainerEvent is the
    machine-readable timeline row consumed by the brief's incident
    timeline renderer. One DrainerEvent per (victim, attacker, asset)
    triple — multi-token drains in the same kit emit one event per
    asset.
    """
    victim_address: str
    attacker_address: str
    signing_contract: str  # the drainer router contract the victim signed approval for
    asset_type: str        # 'erc20' | 'erc721' | 'erc1155' | 'native'
    asset_symbol: str      # 'USDT' / 'BAYC' / 'ETH' / etc.
    amount: str            # decimal string; "1" for ERC-721 (unit token)
    tx_hash: str           # the transferFrom tx that pulled the funds
    block_number: int
    pattern: str           # 'approve+transferFrom' | 'setApprovalForAll+safeTransferFrom' | 'permit+transferFrom'


@dataclass
class DrainerFindings:
    """Aggregate output of drainer detection across the case."""
    signals: list[DrainerSignal] = field(default_factory=list)
    events: list[DrainerEvent] = field(default_factory=list)
    is_drainer_case: bool = False
    drainer_attribution: str | None = None  # 'Pink Drainer' / 'Inferno Drainer' / None
    classification_confidence: str = "low"


def detect_drainer_pattern(
    case: Case,
    high_risk_db: dict[str, HighRiskEntry] | None = None,
) -> DrainerFindings:
    """Top-level entry point. Combines all detection heuristics
    and returns a structured DrainerFindings.

    The classification logic:

      * If the victim's wallet sent transfers DIRECTLY to a known
        drainer-tagged address (in high_risk.json with category
        'scam_drainer') → classified as drainer case, high
        confidence, attributed to the named drainer.
      * If the victim's outflows go to a non-protocol contract
        and the contract immediately redirects to a clean wallet
        within minutes → drainer pattern, medium confidence,
        unnamed.
      * Else → not classified as drainer (could be address typo,
        social engineering, exchange withdrawal mistake).
    """
    findings = DrainerFindings()
    if not case.transfers:
        return findings

    db = high_risk_db or {}
    drainer_addresses = {
        addr for addr, entry in db.items()
        if entry.risk_category == "scam_drainer"
    }

    # v0.17.9 (round-10 forensic HIGH): canonical address keying so
    # base58 chains match the high_risk_db's case-preserved entries.
    # See trace.risk_scoring v0.17.5 fix.
    from recupero._common import canonical_address_key as _ck
    seed = _ck(case.seed_address)

    # Signal 1: direct outflow to known drainer.
    #
    # v0.18.3 (round-11 trace-MED-010): deterministic attribution.
    # Pre-v0.18.3 `findings.drainer_attribution = entry.name` was
    # unconditionally OVERWRITTEN on every match — so when the victim
    # sent to multiple known drainers (Pink Drainer + Inferno Drainer
    # in the same case), the brief showed whichever was iterated
    # LAST, depending on case.transfers ordering AND high_risk_db
    # dict iteration order (hash-seed dependent across Python
    # invocations). Same exact case re-emitted could report different
    # drainer attribution. Now: keep the FIRST match in transfer
    # order (deterministic by block_time / tx_hash ordering of
    # case.transfers, which is stable across runs).
    for t in case.transfers:
        if _ck(t.from_address) != seed:
            continue
        dst = _ck(t.to_address)
        if dst not in drainer_addresses:
            continue
        entry = db[dst]
        findings.signals.append(DrainerSignal(
            signal_type="known_drainer_outflow",
            address=seed,
            counterparty=dst,
            counterparty_name=entry.name,
            severity="critical",
            description=(
                f"Victim's wallet sent funds directly to known "
                f"drainer infrastructure ({entry.name})."
            ),
            confidence="high",
        ))
        # Deterministic attribution: first match wins.
        if not findings.is_drainer_case:
            findings.drainer_attribution = entry.name
            findings.is_drainer_case = True
            findings.classification_confidence = "high"

    # Signal 2: approval-pull forwarding pattern (v0.32.1, CRIT-4).
    #
    # Pre-v0.32.1 this branch was hard-gated behind `if False` with a
    # comment that the case data didn't contain Approval events. The
    # v0.18.0 fix correctly observed that "any victim transfer to any
    # contract" was a false-positive avalanche (Uniswap, Aave, Curve,
    # Lido, every legit DeFi protocol). But disabling the whole
    # detector mis-classified EVERY drainer-kit case (~60% of incoming
    # volume in 2025-2026) as "victim sent funds to unknown actor".
    #
    # v0.32.1 reopens the branch with a much tighter test that
    # distinguishes drainer-pull from DEX/protocol use without needing
    # raw Approval-event data:
    #
    # Drainer-pull signature:
    #   1. Victim address sends a transfer to a contract C.
    #   2. Within a short window (≤ same block ± ``window_blocks``),
    #      contract C emits a transfer to a DIFFERENT EOA E.
    #   3. Victim does NOT receive anything back from C or E in the
    #      window (no swap output, no NFT mint, no protocol receipt
    #      token — drainers don't give the victim anything).
    #   4. The forwarded amount approximately equals the victim's
    #      outflow (>= 80% in the same token; drainers typically take
    #      a small commission but route the bulk).
    #
    # Legitimate DEX/protocol use FAILS step 3: the swap returns
    # output tokens to the victim; the staking returns LP/receipt
    # tokens; the NFT mint emits an ERC-721 transfer back. The
    # absence-of-return is the smoking gun, not the contract
    # destination per se.
    #
    # Because we don't have receipt-log Approval events in the case
    # shape yet (that needs an adapter change owned by another
    # agent), confidence stays "medium" — but the heuristic is
    # narrow enough that legitimate cases shouldn't fire. The
    # ERC-721 / ERC-1155 path is the same logic (NFT goes to a
    # different EOA, victim receives no replacement token).
    same_block_window_blocks = 5  # ≤ 5 blocks (≈ 60s on EVM)
    # Build an index of transfers by from_address (canonical) for
    # the forwarding lookup. Use canonical address keys throughout.
    transfers_from: dict[str, list[Any]] = {}
    transfers_to: dict[str, list[Any]] = {}
    for t in case.transfers:
        src_key = _ck(t.from_address)
        dst_key = _ck(t.to_address)
        if src_key:
            transfers_from.setdefault(src_key, []).append(t)
        if dst_key:
            transfers_to.setdefault(dst_key, []).append(t)

    seen_drainer_contracts: set[str] = set()
    for t in case.transfers:
        if _ck(t.from_address) != seed:
            continue
        if not t.counterparty.is_contract:
            continue
        contract_addr = _ck(t.to_address)
        if not contract_addr or contract_addr in db:
            # Known protocol / labeled — handled by signal 1.
            continue
        if contract_addr in seen_drainer_contracts:
            # Avoid duplicate signals when the victim sent multiple
            # tokens through the same drainer in one session.
            continue

        # Find an outbound transfer FROM that contract to a third-
        # party EOA within the time window. The forwarded recipient
        # must NOT be the victim (drainer doesn't give funds back).
        # Match on token contract / native to keep apples-to-apples
        # — a contract handling N tokens shouldn't cross-talk.
        forwarded_to: str | None = None
        forwarded_token_symbol: str | None = None
        forwarded_amount: Any = None
        contract_outflows = transfers_from.get(contract_addr, [])
        for f in contract_outflows:
            dst_eoa = _ck(f.to_address)
            if not dst_eoa or dst_eoa == seed:
                continue
            # Same block-window check.
            block_gap = abs(f.block_number - t.block_number)
            if block_gap > same_block_window_blocks:
                continue
            # Same token (contract addr or native).
            t_contract = (
                t.token.contract.lower() if t.token.contract else ""
            )
            f_contract = (
                f.token.contract.lower() if f.token.contract else ""
            )
            if t_contract != f_contract:
                continue
            # Amount: forwarded ≥ 80% of victim's outflow (drainers
            # commonly take a small commission, ~5-20%).
            try:
                victim_amt = int(t.amount_raw)
                fwd_amt = int(f.amount_raw)
            except (TypeError, ValueError):
                continue
            if victim_amt <= 0:
                continue
            if fwd_amt < (victim_amt * 80) // 100:
                continue
            forwarded_to = dst_eoa
            forwarded_token_symbol = f.token.symbol
            forwarded_amount = f.amount_decimal
            break

        if forwarded_to is None:
            continue

        # Confirm the victim did NOT receive anything back from
        # either the contract or the forwarded EOA in the window —
        # this is what separates drainer-pull from a DEX swap.
        return_received = False
        for r in transfers_to.get(seed, []):
            r_src = _ck(r.from_address)
            if r_src not in (contract_addr, forwarded_to):
                continue
            if abs(r.block_number - t.block_number) > same_block_window_blocks:
                continue
            return_received = True
            break
        if return_received:
            # Swap / protocol round-trip — not a drainer.
            continue

        seen_drainer_contracts.add(contract_addr)

        # Classify the asset type from the token's shape.
        # ERC-721 / ERC-1155 transfers carry decimals=0 by convention
        # in the tracer's TokenRef (the EVM adapter sets it when it
        # sees the NFT standard). ERC-20 has decimals > 0 in
        # practice (USDT=6, USDC=6, DAI=18, etc.). Native is
        # contract=None.
        if t.token.contract is None:
            asset_type = "native"
            pattern_label = "permit+transferFrom"
        elif t.token.decimals == 0:
            # NFT — could be ERC-721 or ERC-1155. The amount_raw=1
            # vs > 1 disambiguates in practice (ERC-721 is always
            # 1 per token; ERC-1155 can be larger).
            if str(t.amount_raw) == "1":
                asset_type = "erc721"
                pattern_label = "setApprovalForAll+safeTransferFrom"
            else:
                asset_type = "erc1155"
                pattern_label = "setApprovalForAll+safeTransferFrom"
        else:
            asset_type = "erc20"
            pattern_label = "approve+transferFrom"

        findings.events.append(DrainerEvent(
            victim_address=seed,
            attacker_address=forwarded_to,
            signing_contract=contract_addr,
            asset_type=asset_type,
            asset_symbol=t.token.symbol or "?",
            amount=str(t.amount_decimal),
            tx_hash=t.tx_hash,
            block_number=t.block_number,
            pattern=pattern_label,
        ))
        findings.signals.append(DrainerSignal(
            signal_type="approval_to_unknown_contract",
            address=seed,
            counterparty=contract_addr,
            counterparty_name="(unknown contract)",
            severity="critical",
            description=(
                f"Victim's wallet granted approval to an unknown "
                f"contract {contract_addr[:10]}…; funds "
                f"({forwarded_token_symbol} {forwarded_amount}) were "
                f"pulled and forwarded to attacker EOA "
                f"{forwarded_to[:10]}… within {same_block_window_blocks} "
                f"blocks. No return flow to victim — approval-pull "
                f"drainer pattern."
            ),
            confidence="medium",
        ))
        # Also surface a separate signal naming the attacker EOA so
        # downstream LE-handoff can pursue it.
        findings.signals.append(DrainerSignal(
            signal_type="transfer_from_pattern",
            address=seed,
            counterparty=forwarded_to,
            counterparty_name="(attacker EOA)",
            severity="critical",
            description=(
                f"Forwarding endpoint of drainer contract "
                f"{contract_addr[:10]}…. Funds delivered here within "
                f"{same_block_window_blocks} blocks of victim approval."
            ),
            confidence="medium",
        ))
        if not findings.is_drainer_case:
            findings.is_drainer_case = True
            findings.classification_confidence = "medium"

    return findings


def detect_approval_signatures(case: Case) -> list[DrainerSignal]:
    """Scan case for ERC-20/721/1155 Approval events. Standalone
    helper — typically called via detect_drainer_pattern.

    Returns empty list when the case's transfer data doesn't
    include approval events (the current state — see module
    docstring on the limitation). The function exists in
    advance so the integration is one wire-up away when
    approval events are captured.
    """
    # Future: walk case.transfers (or a separate
    # case.approvals collection) for events where:
    #   * tx kind == 'Approval' or 'ApprovalForAll'
    #   * spender is a non-protocol contract
    #   * approved amount == uint256.max OR a large multiple
    #     of the victim's holdings
    # For each match, emit DrainerSignal with severity=critical
    # and confidence='high' since approval is the smoking gun.
    return []


def drainer_findings_to_brief_section(
    findings: DrainerFindings,
) -> dict[str, any]:
    """Serialize for the brief's INCIDENT_CLASSIFICATION section."""
    return {
        "is_drainer_case": findings.is_drainer_case,
        "drainer_attribution": findings.drainer_attribution,
        "classification_confidence": findings.classification_confidence,
        "signals": [
            {
                "type": s.signal_type,
                "address": s.address,
                "counterparty": s.counterparty,
                "counterparty_name": s.counterparty_name,
                "severity": s.severity,
                "description": s.description,
                "confidence": s.confidence,
            }
            for s in findings.signals
        ],
        # v0.32.1 (CRIT-4): timeline events for the brief's
        # "Approval-pull exploit" section. Empty list when no
        # drainer events were detected.
        "events": [
            {
                "victim_address": e.victim_address,
                "attacker_address": e.attacker_address,
                "signing_contract": e.signing_contract,
                "asset_type": e.asset_type,
                "asset_symbol": e.asset_symbol,
                "amount": e.amount,
                "tx_hash": e.tx_hash,
                "block_number": e.block_number,
                "pattern": e.pattern,
            }
            for e in findings.events
        ],
    }


__all__ = (
    "APPROVAL_TOPIC0",
    "ApprovalEvent",
    "DrainerSignal",
    "DrainerEvent",
    "DrainerFindings",
    "detect_drainer_pattern",
    "detect_approval_signatures",
    "drainer_findings_to_brief_section",
)
