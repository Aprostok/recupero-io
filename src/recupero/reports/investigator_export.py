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
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# v0.20.12 hardening: cells that begin with one of these characters are
# interpreted as a FORMULA by Excel / LibreOffice / Google Sheets when
# the analyst opens investigator_findings.csv (CWE-1236). Matches the
# OWASP-standard mitigation already in CaseStore._csv_safe.
_CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")

# Numeric tokens that would render as NaN / Inf when re-parsed by a
# downstream pandas / numpy / Excel ingestion. The InvestigatorFinding
# amount_usd field is typed `str` but operator/brief input can plant
# any string; reject the IEEE-754 sentinels.
_NUMERIC_NONFINITE_TOKENS = frozenset(
    {"nan", "+nan", "-nan", "inf", "+inf", "-inf", "infinity",
     "+infinity", "-infinity"}
)


def _csv_safe(value: Any) -> str:
    """Neutralize CSV formula-injection (CWE-1236) on a single cell.

    OWASP-standard mitigation: prefix a leading-trigger cell with a
    single quote so the spreadsheet treats it as literal text. This
    matches CaseStore._csv_safe (storage/case_store.py) so the same
    sanitizer applies across every CSV we ship to investigators.
    """
    s = "" if value is None else str(value)
    if not s:
        return s
    if s[0] in _CSV_FORMULA_TRIGGERS:
        return "'" + s
    return s


def _amount_safe(value: Any) -> str:
    """Strip non-finite numeric sentinels from amount_usd-style cells.

    The brief feeds operator-derived strings (e.g. "$1,234") directly
    into amount_usd; a poisoned upstream (price-oracle glitch, NaN
    aggregation in a prior stage) can plant ``"nan"``/``"Infinity"``.
    Rendering that into a government-ingested CSV is unsafe — pandas
    coerces it to float NaN and the row drops out of analyst counts.
    """
    s = "" if value is None else str(value)
    if not s:
        return s
    if s.strip().lower() in _NUMERIC_NONFINITE_TOKENS:
        return ""
    return s


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
    findings.extend(_findings_from_cross_case_correlation(brief))
    findings.extend(_findings_from_destinations(brief))

    # Dedupe destination-tier findings against more-specific ones at
    # the same address — the CSV must not show contradictory rows
    # (e.g., one "freezable" + one "destination" for the same wallet).
    findings = _dedupe_findings_by_address(findings)

    # Sort: SANCTIONED first, then by severity desc.
    _sev_rank = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
    }
    findings.sort(key=lambda f: _sev_rank.get(f.severity, 5))
    return findings


def _dedupe_findings_by_address(
    findings: list[InvestigatorFinding],
) -> list[InvestigatorFinding]:
    """Dedupe DESTINATION-tier findings against more-specific ones at
    the same address.

    A `destination` / `freezable_destination` / `investigate_destination`
    / `exchange_destination` / `unrecoverable_destination` finding is
    dropped when a non-destination finding (freezable / unrecoverable /
    risk-exposure / etc.) at the same (address, chain) already exists.
    Destination-tier findings dedupe against each other by priority
    (one row per address). Non-destination findings pass through
    untouched — a RISK_ASSESSMENT block with multiple exposures on
    the same address still produces multiple rows.
    """
    _DESTINATION_TIER = {
        "destination",
        "freezable_destination",
        "investigate_destination",
        "exchange_destination",
        "unrecoverable_destination",
    }
    # Step 1: find addresses with non-destination-tier findings.
    addresses_with_specific: set[tuple[str, str]] = set()
    for f in findings:
        if not f.address:
            continue
        if f.risk_category not in _DESTINATION_TIER:
            addresses_with_specific.add(
                (f.address.lower(), f.chain.lower())
            )
    # Step 2: dedupe destination-tier rows by priority. freezable_
    # destination beats the others because it represents an actionable
    # freeze letter; exchange is informational (separate CEX-subpoena
    # workflow).
    _dest_priority = {
        "freezable_destination": 0,
        "unrecoverable_destination": 1,
        "exchange_destination": 2,
        "investigate_destination": 3,
        "destination": 4,
    }
    kept_destinations: dict[tuple[str, str], InvestigatorFinding] = {}
    passthrough: list[InvestigatorFinding] = []
    for f in findings:
        if not f.address or f.risk_category not in _DESTINATION_TIER:
            passthrough.append(f)
            continue
        key = (f.address.lower(), f.chain.lower())
        if key in addresses_with_specific:
            # A specific finding already covers this address; drop
            # the destination-tier duplicate.
            continue
        prev = kept_destinations.get(key)
        if prev is None:
            kept_destinations[key] = f
            continue
        prev_prio = _dest_priority.get(prev.risk_category, 4)
        f_prio = _dest_priority.get(f.risk_category, 4)
        if f_prio < prev_prio:
            kept_destinations[key] = f
    return passthrough + list(kept_destinations.values())


def write_csv(
    findings: list[InvestigatorFinding],
    out_path: Path,
) -> Path:
    """Write the findings CSV. Returns the path written.

    v0.16.9 (round-9 output-artifacts LOW): explicit `lineterminator="\\n"`.
    csv.DictWriter's default uses `\\r\\n` on Windows which embedded
    a stray `\\r` inside multi-line cells when government tools
    (which key on LF-only) ingested the file — pandas read_csv on
    Linux interpreted the `\\r` as a column separator on certain
    cells. Fixed encoding to be cross-platform consistent.
    """
    # v0.20.11 (R15-C MEDIUM): atomic write via tmp + os.replace so a
    # SIGTERM mid-write can't leave a truncated CSV that gets synced to
    # FBI/IRS-CI analysts. Pattern matches _common.atomic_write_text but
    # adapted for CSV's file-object writer API.
    # v0.20.12 hardening: per-writer unique tmp suffix so two concurrent
    # writers (operator retry + sync worker) don't trample each other's
    # half-written tmp file and corrupt the os.replace. The amount_usd
    # column is filtered for NaN/Inf and every cell is run through
    # _csv_safe to neutralize CWE-1236 formula-injection.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(
        out_path.suffix + f".{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        with tmp_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=_CSV_COLUMNS, extrasaction="ignore",
                lineterminator="\n",
            )
            writer.writeheader()
            for fnd in findings:
                row = {}
                for c in _CSV_COLUMNS:
                    raw = getattr(fnd, c, "")
                    if c == "amount_usd":
                        raw = _amount_safe(raw)
                    row[c] = _csv_safe(raw)
                writer.writerow(row)
        os.replace(str(tmp_path), str(out_path))
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
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
    # v0.20.12 hardening: the JSON export targets tools that JSON-parse
    # then often coerce amount_usd to float. A literal "NaN"/"Infinity"
    # string survives the str-typed schema and re-parses to a real
    # NaN downstream — drop it the same way the CSV path does. We
    # intentionally do NOT csv-escape JSON cells (the formula trigger
    # only matters in spreadsheet ingestion).
    def _build_row(fnd: InvestigatorFinding) -> dict[str, str]:
        row: dict[str, str] = {}
        for col in _CSV_COLUMNS:
            raw = getattr(fnd, col, "")
            if col == "amount_usd":
                raw = _amount_safe(raw)
            row[col] = "" if raw is None else str(raw)
        return row
    payload = {
        "schema_version": 1,
        "generated_by": "recupero",
        "findings_count": len(findings),
        "findings": [_build_row(fnd) for fnd in findings],
    }
    # v0.20.11 (R15-C MEDIUM): atomic write via _common.atomic_write_text
    # so a SIGTERM mid-write can't produce a truncated JSON file.
    from recupero._common import atomic_write_text
    atomic_write_text(out_path, json.dumps(payload, indent=2, allow_nan=False, ensure_ascii=False))
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
    """FREEZABLE → one finding per (issuer, address) holding.

    risk_category honors the issuer's freeze_capability:
      * yes / HIGH       → "freezable"            (severity high)
      * limited / MEDIUM → "freezable_limited"    (severity medium)
      * no / LOW         → "unrecoverable"        (severity low)
      * "" / other       → "freezable" + low      (back-compat)

    Accepts both the raw freeze_asks form ('yes'/'limited'/'no') and
    the display-mapped form ('HIGH'/'MEDIUM'/'LOW') because emit_brief
    maps for display but the skip_editorial fallback passes through
    raw values.
    """
    out: list[InvestigatorFinding] = []
    for entry in brief.get("FREEZABLE") or []:
        issuer = entry.get("issuer", "?")
        token = entry.get("token", "?")
        capability = entry.get("freeze_capability", "")
        cap_lower = capability.lower()
        if cap_lower in ("yes", "high"):
            sev = "high"
            risk_category = "freezable"
            headline_verb = "Freezable"
        elif cap_lower in ("limited", "medium"):
            sev = "medium"
            risk_category = "freezable_limited"
            headline_verb = "Freezable (limited capability)"
        elif cap_lower in ("no", "low"):
            # DAI / similar non-freezable tokens get the unrecoverable
            # tag so the structured export agrees with the rest of the
            # artifacts (which correctly mark these as unrecoverable).
            sev = "low"
            risk_category = "unrecoverable"
            headline_verb = "Held but unrecoverable"
        else:
            sev = "low"
            risk_category = "freezable"
            headline_verb = "Freezable"
        for holding in entry.get("holdings") or []:
            addr = (holding.get("address") or "").lower()
            usd_amt = holding.get("usd", "")
            # Surface evidence_type in the headline + notes so an
            # analyst can distinguish "$X currently held" from "$X
            # received historically at this address" — the trace
            # USD on a historical_inflow row is the inflow sum, not
            # a present-day balance.
            ev_type = holding.get("evidence_type") or "current_balance"
            observed_at = holding.get("observed_at")
            evidence_phrase = (
                "historical receipt"
                if ev_type == "historical_inflow"
                else "current balance"
            )
            headline = (
                f"{headline_verb} {usd_amt} {token} at {addr[:10]}... "
                f"via {issuer} (capability: {capability or 'unknown'}; "
                f"{evidence_phrase})"
            )
            existing_note = entry.get("freeze_note") or ""
            notes_parts: list[str] = []
            if ev_type == "historical_inflow":
                if observed_at:
                    notes_parts.append(
                        f"Evidence: historical_inflow observed at "
                        f"{observed_at}; current balance pending issuer "
                        f"verification."
                    )
                else:
                    notes_parts.append(
                        "Evidence: historical_inflow; current balance "
                        "pending issuer verification."
                    )
            if existing_note:
                notes_parts.append(existing_note)
            out.append(InvestigatorFinding(
                finding_type=risk_category,
                address=addr,
                chain=brief.get("PRIMARY_CHAIN", "").lower() or "ethereum",
                severity=sev,
                headline=headline,
                counterparty=issuer.lower().replace(" ", "_"),
                counterparty_name=issuer,
                risk_category=risk_category,
                amount_usd=str(usd_amt),
                tx_hash="",
                explorer_url=holding.get("explorer_url", ""),
                timestamp_iso=observed_at or "",
                follow_up_url="",
                notes=" ".join(notes_parts),
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


def _findings_from_cross_case_correlation(
    brief: dict[str, Any],
) -> list[InvestigatorFinding]:
    """CROSS_CASE_CORRELATION → one finding per recidivist address.

    Severity calibration:
      * OFAC-exposed in any prior case → critical
      * Drainer-attributed in any prior case → critical
      * Appeared in 3+ prior cases → high (repeat offender pattern)
      * Mixer-exposed in any prior case → high
      * Otherwise (single prior appearance, clean) → medium
        (still actionable: this address recycled across cases,
        worth subpoenaing the prior-case file)
    """
    out: list[InvestigatorFinding] = []
    section = brief.get("CROSS_CASE_CORRELATION") or {}
    addresses = section.get("addresses") or {}
    for addr, payload in addresses.items():
        prior_count = int(payload.get("total_prior_cases", 0))
        if prior_count <= 0:
            continue

        ofac_count = int(payload.get("prior_ofac_exposed_count", 0))
        drainer_count = int(payload.get("prior_drainer_attributed_count", 0))
        mixer_count = int(payload.get("prior_mixer_exposed_count", 0))

        if ofac_count > 0 or drainer_count > 0:
            sev = "critical"
        elif prior_count >= 3 or mixer_count > 0:
            sev = "high"
        else:
            sev = "medium"

        # Headline: lead with the worst flag.
        if ofac_count > 0:
            headline = (
                f"Recidivist address — OFAC-exposed in {ofac_count} of "
                f"{prior_count} prior cases"
            )
        elif drainer_count > 0:
            headline = (
                f"Recidivist address — drainer-attributed in "
                f"{drainer_count} of {prior_count} prior cases"
            )
        elif mixer_count > 0:
            headline = (
                f"Recidivist address — mixer-exposed in {mixer_count} of "
                f"{prior_count} prior cases"
            )
        else:
            headline = (
                f"Recidivist address — appeared in {prior_count} prior "
                f"{'case' if prior_count == 1 else 'cases'}"
            )

        # Notes: pack the prior-case IDs + roles + USD into a
        # single readable string so the analyst can subpoena
        # the prior cases.
        appearances = payload.get("prior_case_appearances") or []
        sample = "; ".join(
            f"case={a.get('case_id', '')} role={a.get('role', '')} "
            f"usd={a.get('usd_flowed', '')}"
            for a in appearances[:5]
        )
        notes_parts = [payload.get("investigator_note", "")]
        if sample:
            notes_parts.append(f"PRIOR_CASES: {sample}")
        notes = " — ".join(p for p in notes_parts if p)

        out.append(InvestigatorFinding(
            finding_type="cross_case_correlation",
            address=addr,
            chain=payload.get("chain", "") or (
                brief.get("PRIMARY_CHAIN", "").lower() or "ethereum"
            ),
            severity=sev,
            headline=headline,
            counterparty="",
            counterparty_name="",
            risk_category="recidivist",
            amount_usd=payload.get("prior_total_usd_flowed", ""),
            tx_hash="",
            explorer_url="",
            timestamp_iso="",
            follow_up_url="",
            notes=notes,
        ))
    return out


def _findings_from_destinations(brief: dict[str, Any]) -> list[InvestigatorFinding]:
    """DESTINATIONS → one finding per destination address (general
    visibility — most are info-level, not high-action).

    v0.16.0 fix (Jacob V-CFI01 bug 4): previously this read
    ``dest.get('total_usd', '')`` which silently returned "" because
    the DESTINATIONS dict produced by emit_brief._extract_destinations
    uses ``usd_received_in_trace`` (and ``usd_holding_now``), not
    ``total_usd``. The trailing-space tell-tale ("Destination 0xXXXX...
    received ") was the symptom — empty amount_usd, empty headline
    tail, empty counterparty across 12 of 13 findings was the impact.

    Now we read the actual keys, populate counterparty + role from
    the dest's ``role`` field (which encodes whether this is a
    freezable / mixer / labeled / intermediate destination), and
    raise severity above "info" for non-intermediate destinations so
    investigators get a useful triage view.
    """
    out: list[InvestigatorFinding] = []
    for dest in brief.get("DESTINATIONS") or []:
        addr = (dest.get("address") or "").lower()
        # The destinations dict carries usd_received_in_trace + usd_holding_now.
        # The headline + amount come from received-in-trace, since this is the
        # "destination" finding (what flowed in via the trace); the held-now
        # number is supplementary and goes in notes.
        usd_received = dest.get("usd_received_in_trace") or "$0"
        usd_holding_now = dest.get("usd_holding_now") or ""
        role = dest.get("role") or "Intermediate wallet"
        status = dest.get("status") or ""
        # status is one of: 🟩 FREEZABLE / 🟧 INVESTIGATE / 🟦 EXCHANGE /
        # ⬛ UNRECOVERABLE — extract for severity assignment.
        if "FREEZABLE" in status:
            severity = "high"
            risk_category = "freezable_destination"
        elif "UNRECOVERABLE" in status or "mixer" in role.lower():
            severity = "medium"
            risk_category = "unrecoverable_destination"
        elif "EXCHANGE" in status or "exchange" in role.lower():
            severity = "medium"
            risk_category = "exchange_destination"
        elif "INVESTIGATE" in status:
            severity = "low"
            risk_category = "investigate_destination"
        else:
            severity = "info"
            risk_category = "destination"
        # The counterparty/counterparty_name carries the role string
        # so downstream tooling can group by destination type. When
        # the trace identified a specific label (Binance, Tornado, etc.)
        # the role contains that name.
        counterparty_slug = role.lower().replace(" ", "_").replace("/", "_")[:64]
        # Trim trailing punctuation / extra whitespace; keep the
        # human-readable form in counterparty_name.
        headline = (
            f"Destination {addr[:10]}... received {usd_received} ({role})"
        )
        # Notes carry the supplementary held-now number + any
        # AI editorial / mechanical note so the operator has full
        # context per finding.
        existing_notes = (dest.get("notes") or dest.get("note") or "").strip()
        notes_parts: list[str] = []
        if usd_holding_now and usd_holding_now not in ("$0", "$0.00", "unknown (see explorer)"):
            notes_parts.append(f"Currently holds {usd_holding_now}.")
        if existing_notes:
            notes_parts.append(existing_notes)
        notes = " ".join(notes_parts)

        out.append(InvestigatorFinding(
            finding_type="destination",
            address=addr,
            chain=brief.get("PRIMARY_CHAIN", "").lower() or "ethereum",
            severity=severity,
            headline=headline,
            counterparty=counterparty_slug,
            counterparty_name=role,
            risk_category=risk_category,
            amount_usd=str(usd_received),
            tx_hash="",
            explorer_url=dest.get("explorer_url", ""),
            timestamp_iso="",
            follow_up_url="",
            notes=notes,
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
