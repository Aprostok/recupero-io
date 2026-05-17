"""Address risk scoring (v0.9.1).

Computes a per-address risk score based on:

  * Direct interaction with OFAC-sanctioned addresses (Lazarus
    Group, Garantex, sanctioned mixers).
  * Direct interaction with known mixers (Tornado Cash, Sinbad,
    Railgun).
  * Direct interaction with sanctioned darknet markets
    (Hydra, Garantex).
  * Direct interaction with documented scam/drainer services.

The score is the SUM of severity-weighted exposures, where each
"exposure" is one transfer to or from a known-risky address.
Severity is on a 1-4 scale:
  4 = critical (OFAC-sanctioned, criminal)
  3 = high (non-sanctioned mixer, scam drainer)
  2 = concerning (degraded reputation, no formal sanction)
  1 = minor (advisory only)

A "verdict" string summarizes the score for the brief:
  > 0    "SANCTIONED — direct exposure to OFAC SDN List"
  3-7    "HIGH-RISK — significant exposure to mixers or scam ops"
  1-2    "MODERATE — limited high-risk exposure"
  0      "CLEAN — no detected high-risk interactions"

Why this matters
----------------

For a government / law-enforcement investigator, OFAC exposure
is dispositive — they need to know IMMEDIATELY whether the
perpetrator addresses interacted with sanctioned entities,
because that elevates the case from civil/state to federal
jurisdiction (specifically: Treasury / OFAC / FBI counterterror).

For a compliance team at an issuer (Circle, Tether) evaluating
a freeze request, OFAC-flagged addresses move faster — the
issuer has its own SAR (Suspicious Activity Report) filing
obligations and a clear sanctions hit shortens their decision
window from days to hours.

Output shape (consumed by emit_brief)
--------------------------------------

  {
    "addresses": {
      "0xabc...": {
        "score": 8,
        "verdict": "SANCTIONED",
        "exposures": [
          {"counterparty": "0xdef...",
           "name": "Lazarus Group (DPRK) — Ronin Bridge",
           "risk_category": "ofac_sanctioned",
           "severity": 4,
           "direction": "outflow",
           "tx_count": 1,
           "total_usd": "$50,000.00"}
        ]
      }
    },
    "summary": {
      "addresses_assessed": 5,
      "ofac_exposed_count": 2,
      "mixer_exposed_count": 1,
      "highest_score": 8,
      "highest_score_address": "0xabc..."
    }
  }
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

from recupero.models import Case

log = logging.getLogger(__name__)


# Path to the high-risk seed file. Lives alongside the existing
# labels seeds.
_HIGH_RISK_SEED_PATH = (
    Path(__file__).parent.parent / "labels" / "seeds" / "high_risk.json"
)
_MIXERS_SEED_PATH = (
    Path(__file__).parent.parent / "labels" / "seeds" / "mixers.json"
)
_RANSOMWARE_SEED_PATH = (
    Path(__file__).parent.parent / "labels" / "seeds" / "ransomware.json"
)


@dataclass(frozen=True)
class HighRiskEntry:
    """One entry from the high-risk seed files. Built from both
    high_risk.json and mixers.json (legacy)."""
    address: str
    name: str
    risk_category: str         # 'ofac_sanctioned' | 'mixer_sanctioned' | 'mixer_high_risk' | 'scam_drainer' | 'darknet_market'
    severity: int              # 1-4 (4 = critical)
    notes: str | None = None
    confidence: str = "high"
    ofac_listing_date: str | None = None


@dataclass
class AddressExposure:
    """One exposure event tying an address in the case to a
    high-risk counterparty."""
    counterparty: str
    counterparty_name: str
    risk_category: str
    severity: int
    direction: str       # 'inflow' | 'outflow'
    tx_count: int
    total_usd: Decimal


@dataclass
class AddressRiskScore:
    """Aggregate risk score for one address in the case."""
    address: str
    score: int = 0
    verdict: str = "CLEAN"
    exposures: list[AddressExposure] = field(default_factory=list)


def load_high_risk_db(
    high_risk_path: Path | None = None,
    mixers_path: Path | None = None,
    ransomware_path: Path | None = None,
) -> dict[str, HighRiskEntry]:
    """Load high-risk address labels from THREE seed files.

    Sources (in priority order — more specific overrides less):
      * high_risk.json — v0.9.1 format with risk_category + severity
        + ofac_listing_date.
      * ransomware.json — v0.9.3 format. Same shape as high_risk
        but operator-tagged.
      * mixers.json — legacy flat array, no severity. We promote
        each entry to severity=4 (mixer = sanctioned equivalent
        for risk-scoring purposes) and category
        "mixer_sanctioned".

    Returns ``{lowercased_address: HighRiskEntry}``.
    """
    out: dict[str, HighRiskEntry] = {}

    # high_risk.json — v0.9.1 schema
    hr_path = high_risk_path or _HIGH_RISK_SEED_PATH
    try:
        raw = json.loads(hr_path.read_text(encoding="utf-8-sig"))
        for entry in raw.get("addresses", []):
            if not isinstance(entry, dict):
                continue
            addr = entry.get("address")
            if not isinstance(addr, str) or not addr.strip():
                continue
            try:
                severity = int(entry.get("severity", 3))
            except (TypeError, ValueError):
                severity = 3
            out[addr.lower()] = HighRiskEntry(
                address=addr.lower(),
                name=entry.get("name", "(unknown)"),
                risk_category=entry.get("risk_category", "unknown"),
                severity=severity,
                notes=entry.get("notes"),
                confidence=entry.get("confidence", "high"),
                ofac_listing_date=entry.get("ofac_listing_date"),
            )
    except FileNotFoundError:
        log.info("high_risk seed not found at %s — risk scoring degraded", hr_path)
    except Exception as exc:  # noqa: BLE001
        log.warning("high_risk seed load failed: %s", exc)

    # ransomware.json — v0.9.3 schema
    rw_path = ransomware_path or _RANSOMWARE_SEED_PATH
    try:
        raw = json.loads(rw_path.read_text(encoding="utf-8-sig"))
        for entry in raw.get("addresses", []):
            if not isinstance(entry, dict):
                continue
            addr = entry.get("address")
            if not isinstance(addr, str) or not addr.strip():
                continue
            addr_lower = addr.lower()
            # high_risk.json entries take precedence (more curated).
            if addr_lower in out:
                continue
            try:
                severity = int(entry.get("severity", 4))
            except (TypeError, ValueError):
                severity = 4
            out[addr_lower] = HighRiskEntry(
                address=addr_lower,
                name=entry.get("name", "(ransomware)"),
                risk_category=entry.get("risk_category", "ransomware"),
                severity=severity,
                notes=entry.get("notes"),
                confidence=entry.get("confidence", "medium"),
            )
    except FileNotFoundError:
        log.debug("ransomware seed not found at %s", rw_path)
    except Exception as exc:  # noqa: BLE001
        log.warning("ransomware seed load failed: %s", exc)

    # mixers.json — legacy schema (treat all entries as
    # mixer_sanctioned severity=4)
    mx_path = mixers_path or _MIXERS_SEED_PATH
    try:
        raw = json.loads(mx_path.read_text(encoding="utf-8-sig"))
        if isinstance(raw, list):
            for entry in raw:
                if not isinstance(entry, dict):
                    continue
                addr = entry.get("address")
                if not isinstance(addr, str) or not addr.strip():
                    continue
                # Don't overwrite high_risk.json entries if there's
                # a duplicate; the more specific entry wins.
                addr_lower = addr.lower()
                if addr_lower in out:
                    continue
                notes = entry.get("notes") or ""
                # If notes mention OFAC, treat as sanctioned;
                # otherwise mixer_high_risk.
                is_sanctioned = "ofac" in notes.lower() or "sanction" in notes.lower()
                out[addr_lower] = HighRiskEntry(
                    address=addr_lower,
                    name=entry.get("name", "(mixer)"),
                    risk_category=(
                        "mixer_sanctioned" if is_sanctioned
                        else "mixer_high_risk"
                    ),
                    severity=4 if is_sanctioned else 3,
                    notes=notes or None,
                    confidence=entry.get("confidence", "high"),
                )
    except FileNotFoundError:
        log.debug("mixers seed not found at %s", mx_path)
    except Exception as exc:  # noqa: BLE001
        log.warning("mixers seed load failed: %s", exc)

    log.debug("loaded %d high-risk address labels", len(out))
    return out


def score_addresses(
    case: Case,
    high_risk_db: dict[str, HighRiskEntry] | None = None,
) -> dict[str, AddressRiskScore]:
    """Compute per-address risk scores from the case transfers.

    Returns ``{address: AddressRiskScore}`` for every address
    in the case that has at least one high-risk exposure.
    Addresses with no exposures aren't included (so the result
    dict is naturally focused on the addresses an investigator
    needs to act on).

    Best-effort: failure to load the seed → empty dict, never
    raises.
    """
    db = high_risk_db if high_risk_db is not None else load_high_risk_db()
    if not db:
        return {}

    # Aggregate exposures by (address-in-case, counterparty,
    # direction). Each unique combination becomes one
    # AddressExposure entry.
    agg: dict[tuple[str, str, str], dict[str, Any]] = {}
    for t in case.transfers:
        usd = t.usd_value_at_tx or Decimal("0")
        src = t.from_address.lower()
        dst = t.to_address.lower()

        # Check both ends: if either side matches a high-risk entry,
        # the OTHER side gets an exposure record.
        if src in db:
            key = (dst, src, "inflow")  # dst received from risky src
            entry = db[src]
            agg.setdefault(key, {
                "name": entry.name, "category": entry.risk_category,
                "severity": entry.severity, "tx_count": 0,
                "total_usd": Decimal("0"),
            })
            agg[key]["tx_count"] += 1
            agg[key]["total_usd"] += usd
        if dst in db:
            key = (src, dst, "outflow")  # src sent to risky dst
            entry = db[dst]
            agg.setdefault(key, {
                "name": entry.name, "category": entry.risk_category,
                "severity": entry.severity, "tx_count": 0,
                "total_usd": Decimal("0"),
            })
            agg[key]["tx_count"] += 1
            agg[key]["total_usd"] += usd

    # Build AddressRiskScore objects, aggregating per address.
    scores: dict[str, AddressRiskScore] = {}
    for (addr, counterparty, direction), data in agg.items():
        score = scores.setdefault(addr, AddressRiskScore(address=addr))
        exposure = AddressExposure(
            counterparty=counterparty,
            counterparty_name=data["name"],
            risk_category=data["category"],
            severity=data["severity"],
            direction=direction,
            tx_count=data["tx_count"],
            total_usd=data["total_usd"],
        )
        score.exposures.append(exposure)
        score.score += data["severity"] * data["tx_count"]

    # Finalize verdicts.
    for score in scores.values():
        score.verdict = _verdict_for_score(score)
        score.exposures.sort(key=lambda e: e.severity, reverse=True)

    return scores


def risk_scores_to_brief_section(
    scores: dict[str, AddressRiskScore],
) -> dict[str, Any]:
    """Serialize per-address risk scores to the brief JSON shape."""
    ofac_exposed = 0
    mixer_exposed = 0
    highest_score = 0
    highest_address = None
    addresses_payload: dict[str, Any] = {}

    for addr, score in scores.items():
        # Per-address categorization for the summary
        cats = {e.risk_category for e in score.exposures}
        if any(c.startswith("ofac") for c in cats):
            ofac_exposed += 1
        if any("mixer" in c for c in cats):
            mixer_exposed += 1
        if score.score > highest_score:
            highest_score = score.score
            highest_address = addr

        addresses_payload[addr] = {
            "score": score.score,
            "verdict": score.verdict,
            "exposures": [
                {
                    "counterparty": e.counterparty,
                    "counterparty_name": e.counterparty_name,
                    "risk_category": e.risk_category,
                    "severity": e.severity,
                    "direction": e.direction,
                    "tx_count": e.tx_count,
                    "total_usd": f"${e.total_usd:,.2f}",
                }
                for e in score.exposures
            ],
        }

    return {
        "addresses": addresses_payload,
        "summary": {
            "addresses_assessed": len(scores),
            "ofac_exposed_count": ofac_exposed,
            "mixer_exposed_count": mixer_exposed,
            "highest_score": highest_score,
            "highest_score_address": highest_address,
        },
    }


# ----- helpers ----- #


def _verdict_for_score(score: AddressRiskScore) -> str:
    """Map (score + exposure categories) to a verdict string.

    OFAC exposure is dispositive — any direct contact with a
    sanctioned address triggers SANCTIONED regardless of
    numeric score. This matches how Treasury views the
    50% Rule (any transaction with a sanctioned entity is
    a sanctioned transaction).
    """
    cats = {e.risk_category for e in score.exposures}
    if any(c.startswith("ofac") for c in cats):
        return "SANCTIONED — direct exposure to OFAC SDN List"
    if any(c == "mixer_sanctioned" for c in cats):
        return "SANCTIONED — direct exposure to sanctioned mixer"
    if score.score >= 8:
        return "CRITICAL — extensive exposure to mixers / scam ops"
    if score.score >= 3:
        return "HIGH-RISK — significant exposure to mixers or scam ops"
    if score.score >= 1:
        return "MODERATE — limited high-risk exposure"
    return "CLEAN — no detected high-risk interactions"


__all__ = (
    "AddressExposure",
    "AddressRiskScore",
    "HighRiskEntry",
    "load_high_risk_db",
    "risk_scores_to_brief_section",
    "score_addresses",
)
