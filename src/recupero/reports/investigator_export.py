"""Government / law-enforcement investigator exports (v0.9.2).

Renders the brief's structured data (cross-chain handoffs,
entity clusters, risk assessment, freezable holdings) as:

  * ``investigator_findings.csv`` — one row per actionable
    finding. Columns: type, address, counterparty, severity,
    USD amount, chain, tx_hash, timestamp, source. The CSV
    format is what FBI / IRS-CI / OFAC analysts ingest into
    their case-management tools.
  * ``investigator_findings.json`` — same data in structured
    JSON for tooling that prefers that format.

Both files are written next to the rest of the case
deliverables and listed in the brief's manifest. Government
testers cite these as "the data my team can actually work
with" — the customer-facing PDF is for the victim, but the
CSV is for the analyst.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class InvestigatorFinding:
    """One row in the investigator export.

    Wide schema deliberately — government tools (Excel, case
    management, Splunk) parse on column position. A finding
    that doesn't have a value for a field carries an empty
    string, not the column dropped.
    """
    finding_type: str        # 'freezable' | 'cross_chain_handoff' | 'risk_exposure' | 'entity_cluster' | 'destination'
    address: str             # the address THIS finding is about
    chain: str               # source chain
    severity: str            # 'critical' | 'high' | 'medium' | 'low' | 'info'
    headline: str            # one-sentence description
    counterparty: str        # related counterparty address (if any)
    counterparty_name: str   # human-readable name (if any)
    risk_category: str       # category tag (matches the high_risk seed schema)
    amount_usd: str          # formatted USD amount
    tx_hash: str             # source tx hash (if applicable)
    explorer_url: str        # explorer URL (if applicable)
    timestamp_iso: str       # ISO 8601 (if applicable)
    follow_up_url: str       # bridge explorer / OFAC ref URL (if applicable)
    notes: str               # free-form additional context


# Column ordering for the CSV. Lock this — government tools
# parse on position.
_CSV_COLUMNS = (
    "finding_type",
    "address",
    "chain",
    "severity",
    "headline",
    "counterparty",
    "counterparty_name",
    "risk_category",
    "amount_usd",
    "tx_hash",
    "explorer_url",
    "timestamp_iso",
    "follow_up_url",
    "notes",
)


def build_findings(brief: dict[str, Any]) -> list[InvestigatorFinding]:
    """Walk the brief's structured sections and produce one
    InvestigatorFinding per actionable item.

    The brief is the canonical source of truth — by reading
    from it (not from the underlying case.json), we ensure
    the CSV reflects exactly what's in the customer-facing
    PDF. No skew between the two.

    Sections covered (v0.10.x):
      * RISK_ASSESSMENT             — direct counterparty exposure
      * INDIRECT_EXPOSURE           — N-hop graph exposure (v0.10.0)
      * CROSS_CHAIN_HANDOFFS        — bridge-out events (v0.8.1)
      * FREEZABLE                   — issuer freeze targets
      * ENTITY_CLUSTERS             — same-actor groupings (v0.9.0)
      * INCIDENT_CLASSIFICATION     — drainer pattern (v0.10.1)
      * DEX_SWAPS                   — DEX router involvement (v0.10.2)
      * DESTINATIONS                — info-level (every dest)
    """
    findings: list[InvestigatorFinding] = []

    findings.extend(_findings_from_risk(brief))
    findings.extend(_findings_from_indirect_exposure(brief))
    findings.extend(_findings_from_cross_chain(brief))
    findings.extend(_findings_from_freezable(brief))
    findings.extend(_findings_from_clusters(brief))
    findings.extend(_findings_from_drainer(brief))
    findings.extend(_findings_from_dex_swaps(brief))
    findings.extend(_findings_from_destinations(brief))

    # Sort: SANCTIONED first, then by severity desc.
    _sev_rank = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
    }
    findings.sort(key=lambda f: _sev_rank.get(f.severity, 5))
    return findings


def write_csv(
    findings: list[InvestigatorFinding],
    out_path: Path,
) -> Path:
    """Write the findings CSV. Returns the path written."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for fnd in findings:
            writer.writerow({c: getattr(fnd, c, "") for c in _CSV_COLUMNS})
    log.info("wrote investigator CSV: %s (%d findings)", out_path, len(findings))
    return out_path


def write_json(
    findings: list[InvestigatorFinding],
    out_path: Path,
) -> Path:
    """Write the findings JSON. Structured form for tools that
    prefer JSON over CSV (Jupyter notebooks, Splunk forwarders,
    custom ingestion pipelines)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "generated_by": "recupero",
        "findings_count": len(findings),
        "findings": [
            {col: getattr(fnd, col, "") for col in _CSV_COLUMNS}
            for fnd in findings
        ],
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    log.info("wrote investigator JSON: %s (%d findings)", out_path, len(findings))
    return out_path


# ----- per-section builders ----- #


def _findings_from_risk(brief: dict[str, Any]) -> list[InvestigatorFinding]:
    """RISK_ASSESSMENT → one finding per (address, exposure) pair."""
    out: list[InvestigatorFinding] = []
    risk = brief.get("RISK_ASSESSMENT") or {}
    addresses = risk.get("addresses") or {}
    for addr, payload in addresses.items():
        verdict = payload.get("verdict", "")
        for exp in payload.get("exposures", []):
            sev_int = int(exp.get("severity", 3))
            sev = _severity_int_to_str(sev_int)
            risk_cat = exp.get("risk_category", "")
            counterparty_name = exp.get("counterparty_name", "")
            direction = exp.get("direction", "")
            headline = (
                f"{verdict.split('—')[0].strip()} — {direction} "
                f"{exp.get('total_usd', '')} with {counterparty_name}"
            )
            out.append(InvestigatorFinding(
                finding_type="risk_exposure",
                address=addr,
                chain=brief.get("PRIMARY_CHAIN", "").lower() or "ethereum",
                severity=sev,
                headline=headline,
                counterparty=exp.get("counterparty", ""),
                counterparty_name=counterparty_name,
                risk_category=risk_cat,
                amount_usd=exp.get("total_usd", ""),
                tx_hash="",
                explorer_url="",
                timestamp_iso="",
                follow_up_url="",
                notes=verdict,
            ))
    return out


def _findings_from_cross_chain(brief: dict[str, Any]) -> list[InvestigatorFinding]:
    """CROSS_CHAIN_HANDOFFS → one finding per bridge tx."""
    out: list[InvestigatorFinding] = []
    for handoff in brief.get("CROSS_CHAIN_HANDOFFS") or []:
        bridge_name = handoff.get("bridge_name", "(bridge)")
        amount = handoff.get("amount_usd") or handoff.get("amount_decimal", "")
        candidates = handoff.get("destination_chain_candidates") or []
        headline = (
            f"Cross-chain handoff to {bridge_name} → "
            f"{', '.join(candidates) if candidates else '(unknown)'}"
        )
        out.append(InvestigatorFinding(
            finding_type="cross_chain_handoff",
            address=handoff.get("source_address", ""),
            chain=handoff.get("source_chain", ""),
            severity="high",  # cross-chain is always high-priority for investigators
            headline=headline,
            counterparty=handoff.get("bridge_address", ""),
            counterparty_name=bridge_name,
            risk_category="cross_chain",
            amount_usd=str(amount or ""),
            tx_hash=handoff.get("tx_hash", ""),
            explorer_url=handoff.get("tx_explorer_url", ""),
            timestamp_iso=handoff.get("block_time", ""),
            follow_up_url=handoff.get("follow_up_url", ""),
            notes=handoff.get("investigator_note", ""),
        ))
    return out


def _findings_from_freezable(brief: dict[str, Any]) -> list[InvestigatorFinding]:
    """FREEZABLE → one finding per (issuer, address) holding."""
    out: list[InvestigatorFinding] = []
    for entry in brief.get("FREEZABLE") or []:
        issuer = entry.get("issuer", "?")
        token = entry.get("token", "?")
        capability = entry.get("freeze_capability", "")
        for holding in entry.get("holdings") or []:
            addr = (holding.get("address") or "").lower()
            usd_amt = holding.get("usd", "")
            sev = (
                "high" if capability.upper() == "HIGH"
                else "medium" if capability.upper() == "MEDIUM"
                else "low"
            )
            out.append(InvestigatorFinding(
                finding_type="freezable",
                address=addr,
                chain=brief.get("PRIMARY_CHAIN", "").lower() or "ethereum",
                severity=sev,
                headline=(
                    f"Freezable {usd_amt} {token} at {addr[:10]}... "
                    f"via {issuer} ({capability})"
                ),
                counterparty=issuer.lower().replace(" ", "_"),
                counterparty_name=issuer,
                risk_category="freezable",
                amount_usd=str(usd_amt),
                tx_hash="",
                explorer_url=holding.get("explorer_url", ""),
                timestamp_iso="",
                follow_up_url="",
                notes=entry.get("freeze_note", ""),
            ))
    return out


def _findings_from_clusters(brief: dict[str, Any]) -> list[InvestigatorFinding]:
    """ENTITY_CLUSTERS → one finding per cluster summarizing
    the addresses + evidence."""
    out: list[InvestigatorFinding] = []
    clusters = (brief.get("ENTITY_CLUSTERS") or {}).get("clusters") or []
    for cluster in clusters:
        addresses = cluster.get("addresses", [])
        size = cluster.get("size", len(addresses))
        balance = cluster.get("total_balance_usd") or ""
        evidence_summary = " | ".join(
            f"{e.get('heuristic')}({e.get('confidence')})"
            for e in cluster.get("evidence", [])
        )
        out.append(InvestigatorFinding(
            finding_type="entity_cluster",
            address=addresses[0] if addresses else "",
            chain=brief.get("PRIMARY_CHAIN", "").lower() or "ethereum",
            severity="medium",
            headline=(
                f"Entity cluster {cluster.get('cluster_id')}: "
                f"{size} addresses, total {balance or 'unknown balance'}"
            ),
            counterparty="",
            counterparty_name="",
            risk_category="entity_cluster",
            amount_usd=str(balance or ""),
            tx_hash="",
            explorer_url="",
            timestamp_iso="",
            follow_up_url="",
            notes=(
                f"Members: {', '.join(addresses[:5])}"
                + (f" (+{len(addresses)-5} more)" if len(addresses) > 5 else "")
                + f". Heuristics: {evidence_summary}"
            ),
        ))
    return out


def _findings_from_indirect_exposure(brief: dict[str, Any]) -> list[InvestigatorFinding]:
    """INDIRECT_EXPOSURE → one finding per (address, top-path) pair.

    v0.10.0 adds N-hop exposure attribution. Each address may have
    many upstream paths; we emit one finding per address using the
    highest-weight path (so investigators see the most-material
    exposure first, with the multi-hop nature explicit in the
    finding's notes).
    """
    out: list[InvestigatorFinding] = []
    section = brief.get("INDIRECT_EXPOSURE") or {}
    addresses = section.get("addresses") or {}
    for addr, payload in addresses.items():
        paths = payload.get("paths") or []
        if not paths:
            continue
        top_path = paths[0]
        sev_int = int(top_path.get("severity", 3))
        # Indirect OFAC is high-severity but not always
        # critical (multi-hop dilutes). Map sev=4 hop=1
        # to 'critical', sev=4 hop=2+ to 'high', etc.
        hop_count = int(top_path.get("hop_count", 1))
        risk_cat = top_path.get("risk_category", "")
        if risk_cat.startswith("ofac") and hop_count == 1:
            severity = "critical"
        elif risk_cat.startswith("ofac"):
            severity = "high"
        else:
            severity = _severity_int_to_str(sev_int)
        amount = payload.get("total_indirect_usd", "")
        source_name = top_path.get("source_name", "(unknown)")
        out.append(InvestigatorFinding(
            finding_type="indirect_exposure",
            address=addr,
            chain=brief.get("PRIMARY_CHAIN", "").lower() or "ethereum",
            severity=severity,
            headline=(
                f"Indirect exposure {amount} to {source_name} "
                f"({hop_count}-hop)"
            ),
            counterparty=top_path.get("source_address", ""),
            counterparty_name=source_name,
            risk_category=risk_cat,
            amount_usd=str(top_path.get("weighted_amount_usd", "")),
            tx_hash="",
            explorer_url="",
            timestamp_iso="",
            follow_up_url="",
            notes=(
                f"hop_count={hop_count}; "
                f"path: source → "
                + " → ".join(
                    a[:10] + "..."
                    for a in (top_path.get("path_addresses") or [])
                )
                + (
                    f"; {len(paths) - 1} additional path(s) "
                    f"to other sources"
                    if len(paths) > 1 else ""
                )
            ),
        ))
    return out


def _findings_from_drainer(brief: dict[str, Any]) -> list[InvestigatorFinding]:
    """INCIDENT_CLASSIFICATION → one finding when the case is
    classified as a drainer case + per-signal findings."""
    out: list[InvestigatorFinding] = []
    section = brief.get("INCIDENT_CLASSIFICATION") or {}
    if not section.get("is_drainer_case"):
        return out
    attribution = section.get("drainer_attribution") or "(unknown drainer)"
    confidence = section.get("classification_confidence", "low")
    out.append(InvestigatorFinding(
        finding_type="drainer_classification",
        address="(victim)",
        chain=brief.get("PRIMARY_CHAIN", "").lower() or "ethereum",
        severity="critical" if confidence == "high" else "high",
        headline=f"Case classified as wallet-drainer theft (operator: {attribution})",
        counterparty="",
        counterparty_name=attribution,
        risk_category="scam_drainer",
        amount_usd="",
        tx_hash="",
        explorer_url="",
        timestamp_iso="",
        follow_up_url="",
        notes=(
            f"Classification confidence: {confidence}. "
            f"{len(section.get('signals') or [])} signal(s) detected."
        ),
    ))
    # Also surface each signal individually
    for s in section.get("signals") or []:
        sev = s.get("severity", "medium")
        out.append(InvestigatorFinding(
            finding_type="drainer_signal",
            address=s.get("address", ""),
            chain=brief.get("PRIMARY_CHAIN", "").lower() or "ethereum",
            severity=sev,
            headline=s.get("description", "Drainer signal detected"),
            counterparty=s.get("counterparty", ""),
            counterparty_name=s.get("counterparty_name", ""),
            risk_category="scam_drainer",
            amount_usd="",
            tx_hash="",
            explorer_url="",
            timestamp_iso="",
            follow_up_url="",
            notes=f"Signal type: {s.get('type')}. Confidence: {s.get('confidence')}",
        ))
    return out


def _findings_from_dex_swaps(brief: dict[str, Any]) -> list[InvestigatorFinding]:
    """DEX_SWAPS → one finding per swap event. Severity='high'
    because each swap is a continuation point for the trace."""
    out: list[InvestigatorFinding] = []
    for swap in brief.get("DEX_SWAPS") or []:
        out.append(InvestigatorFinding(
            finding_type="dex_swap",
            address=swap.get("swapper", ""),
            chain=brief.get("PRIMARY_CHAIN", "").lower() or "ethereum",
            severity="high",
            headline=(
                f"Swap via {swap.get('router_name')}: "
                f"{swap.get('input_amount_usd') or swap.get('input_amount', '')} → "
                f"{swap.get('output_amount_usd') or swap.get('output_amount', '')}"
            ),
            counterparty=swap.get("output_recipient", "") or "",
            counterparty_name=swap.get("router_name", ""),
            risk_category="dex_swap",
            amount_usd=str(
                swap.get("output_amount_usd")
                or swap.get("input_amount_usd")
                or ""
            ),
            tx_hash=swap.get("tx_hash", ""),
            explorer_url=swap.get("explorer_url", ""),
            timestamp_iso=swap.get("block_time", ""),
            follow_up_url="",
            notes=swap.get("investigator_note", ""),
        ))
    return out


def _findings_from_destinations(brief: dict[str, Any]) -> list[InvestigatorFinding]:
    """DESTINATIONS → one finding per destination address (general
    visibility — most are info-level, not high-action)."""
    out: list[InvestigatorFinding] = []
    for dest in brief.get("DESTINATIONS") or []:
        addr = (dest.get("address") or "").lower()
        out.append(InvestigatorFinding(
            finding_type="destination",
            address=addr,
            chain=brief.get("PRIMARY_CHAIN", "").lower() or "ethereum",
            severity="info",
            headline=f"Destination {addr[:10]}... received {dest.get('total_usd', '')}",
            counterparty="",
            counterparty_name="",
            risk_category="destination",
            amount_usd=str(dest.get("total_usd", "")),
            tx_hash="",
            explorer_url=dest.get("explorer_url", ""),
            timestamp_iso="",
            follow_up_url="",
            notes=dest.get("note", ""),
        ))
    return out


def _severity_int_to_str(sev: int) -> str:
    if sev >= 4:
        return "critical"
    if sev == 3:
        return "high"
    if sev == 2:
        return "medium"
    if sev == 1:
        return "low"
    return "info"


__all__ = (
    "InvestigatorFinding",
    "build_findings",
    "write_csv",
    "write_json",
)
