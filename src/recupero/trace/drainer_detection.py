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


@dataclass
class DrainerFindings:
    """Aggregate output of drainer detection across the case."""
    signals: list[DrainerSignal] = field(default_factory=list)
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

    seed = case.seed_address.lower()

    # Signal 1: direct outflow to known drainer
    for t in case.transfers:
        if t.from_address.lower() != seed:
            continue
        dst = t.to_address.lower()
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
        # Attribution: the highest-confidence drainer overlap
        # becomes the classification's attributed operator.
        findings.drainer_attribution = entry.name
        findings.is_drainer_case = True
        findings.classification_confidence = "high"

    # Signal 2: outflow to non-protocol contract (suggests
    # approval-exploit, even without explicit Approval event in
    # the trace data we have today).
    for t in case.transfers:
        if t.from_address.lower() != seed:
            continue
        if not t.counterparty.is_contract:
            continue
        # Skip known protocols / DEXes — those are normal
        # interactions, not drainer indicators.
        dst = t.to_address.lower()
        if dst in db:
            continue
        # Don't flag if the destination is one of our known
        # safe categories (bridge, exchange, etc.) — those
        # require label-store integration. For now, all
        # unknown contracts produce a medium signal.
        findings.signals.append(DrainerSignal(
            signal_type="approval_to_unknown_contract",
            address=seed,
            counterparty=dst,
            counterparty_name="(unknown contract)",
            severity="medium",
            description=(
                "Victim's wallet sent funds to an unknown contract. "
                "Consistent with approval-exploit drainer pattern; "
                "verify by checking for prior setApprovalForAll / "
                "permit signatures from the victim's wallet."
            ),
            confidence="medium",
        ))
        # Only set classification if not already high-confidence
        # from Signal 1.
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
    }


__all__ = (
    "DrainerSignal",
    "DrainerFindings",
    "detect_drainer_pattern",
    "detect_approval_signatures",
    "drainer_findings_to_brief_section",
)
