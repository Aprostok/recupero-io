"""Pure address-screening function (v0.12.1).

No on-chain calls — pulls everything from the local seed DBs and
(optionally) the cross-case correlation index. Latency: <50ms with
DB lookup, <5ms without.

The screening output is structured to drop straight into a REST
response or an exchange's compliance dashboard.
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass, field
from decimal import Decimal
from typing import Any

from recupero.trace.risk_scoring import HighRiskEntry, load_high_risk_db

log = logging.getLogger(__name__)


# ----- Result types ----- #


@dataclass
class ScreeningLabel:
    """One label hit on the screened address."""
    name: str
    category: str          # 'ofac_sanctioned' | 'ransomware' | 'mixer_*' | 'scam_drainer' | etc.
    severity: int          # 1..4 (1=low, 4=critical)
    confidence: str        # 'high' | 'medium' | 'low'
    source: str            # 'high_risk_seed' | 'ofac_live' | 'mixers_seed' | 'ransomware_seed'
    notes: str | None = None
    ofac_listing_date: str | None = None


@dataclass
class ScreeningCorrelation:
    """Aggregated cross-case correlation for the screened address."""
    prior_case_count: int = 0
    prior_ofac_exposed_count: int = 0
    prior_mixer_exposed_count: int = 0
    prior_drainer_attributed_count: int = 0
    prior_total_usd_flowed: Decimal = field(default_factory=lambda: Decimal("0"))
    prior_roles_seen: list[str] = field(default_factory=list)


@dataclass
class ScreeningResult:
    """Wallet-screening API response.

    The verdict is the top-level summary; the structured fields below
    let the caller build their own UI / triage logic.
    """
    address: str
    chain: str
    risk_verdict: str          # 'sanctioned' | 'high' | 'medium' | 'low' | 'clean'
    risk_score: int            # 0..10 (higher = riskier)
    is_ofac_sanctioned: bool
    is_mixer: bool
    is_ransomware: bool
    is_drainer: bool
    labels: list[ScreeningLabel] = field(default_factory=list)
    correlation: ScreeningCorrelation = field(default_factory=ScreeningCorrelation)
    investigator_note: str = ""
    # Provenance — lets the caller verify what data was used.
    data_sources_used: list[str] = field(default_factory=list)

    def to_json_safe(self) -> dict[str, Any]:
        """Serialize for REST / CLI output. Decimal → str."""
        d = asdict(self)
        d["correlation"]["prior_total_usd_flowed"] = (
            str(self.correlation.prior_total_usd_flowed)
        )
        return d


# ----- Screening logic ----- #


def screen_address(
    address: str,
    *,
    chain: str = "ethereum",
    use_correlation_db: bool = True,
    dsn: str | None = None,
    high_risk_db: dict[str, HighRiskEntry] | None = None,
) -> ScreeningResult:
    """Score a single address against the local risk DB + correlation index.

    Args:
      address: the address to screen (EVM lowercase, Tron base58check,
        etc. — caller is responsible for normalizing to the chain's
        canonical form).
      chain: chain hint for the correlation DB lookup.
      use_correlation_db: if False, skip the DB call entirely (useful
        for completely-offline screening — only the local seed
        files are consulted).
      dsn: override the SUPABASE_DB_URL env var. If both are unset
        and use_correlation_db=True, the correlation lookup is
        silently skipped (graceful degradation).
      high_risk_db: caller-injected db (so a long-running screener
        can load once and reuse). If None we load on each call.

    Returns:
      A ScreeningResult with the verdict + structured details.
    """
    addr_norm = _normalize_for_lookup(address, chain=chain)

    db = high_risk_db if high_risk_db is not None else load_high_risk_db()
    sources_used: list[str] = ["local_seeds"]
    labels: list[ScreeningLabel] = []
    is_ofac = False
    is_mixer = False
    is_ransomware = False
    is_drainer = False

    entry = db.get(addr_norm)
    if entry is not None:
        cat = (entry.risk_category or "").lower()
        if cat.startswith("ofac"):
            is_ofac = True
        if "mixer" in cat:
            is_mixer = True
        if "ransomware" in cat:
            is_ransomware = True
        if "drainer" in cat or "scam" in cat:
            is_drainer = True
        labels.append(ScreeningLabel(
            name=entry.name,
            category=entry.risk_category,
            severity=entry.severity,
            confidence=entry.confidence,
            source=_source_for_category(cat),
            notes=entry.notes,
            ofac_listing_date=entry.ofac_listing_date,
        ))

    # Correlation lookup
    correlation = ScreeningCorrelation()
    if use_correlation_db:
        resolved_dsn = dsn or os.environ.get("SUPABASE_DB_URL", "").strip()
        if resolved_dsn:
            try:
                correlation = _lookup_correlation_for_address(
                    addr_norm, chain=chain, dsn=resolved_dsn,
                )
                sources_used.append("correlation_db")
            except Exception as exc:  # noqa: BLE001
                log.debug("screen correlation lookup failed: %s", exc)

    # Risk score: combine label severity + correlation history.
    score = _compute_score(
        entry=entry,
        correlation=correlation,
    )

    verdict = _verdict_for(
        is_ofac=is_ofac,
        is_mixer=is_mixer,
        is_ransomware=is_ransomware,
        is_drainer=is_drainer,
        score=score,
        correlation=correlation,
    )

    note = _build_investigator_note(
        address=addr_norm, verdict=verdict, entry=entry,
        correlation=correlation, is_ofac=is_ofac, is_mixer=is_mixer,
        is_ransomware=is_ransomware, is_drainer=is_drainer,
    )

    return ScreeningResult(
        address=addr_norm,
        chain=chain,
        risk_verdict=verdict,
        risk_score=score,
        is_ofac_sanctioned=is_ofac,
        is_mixer=is_mixer,
        is_ransomware=is_ransomware,
        is_drainer=is_drainer,
        labels=labels,
        correlation=correlation,
        investigator_note=note,
        data_sources_used=sources_used,
    )


# ----- helpers ----- #


def _normalize_for_lookup(address: str, *, chain: str) -> str:
    """Canonicalize an address for DB lookup."""
    if not isinstance(address, str):
        raise TypeError(f"address must be str, got {type(address)!r}")
    address = address.strip()
    if not address:
        raise ValueError("address is empty")

    if chain == "tron":
        # Tron addresses are base58check; case is meaningful.
        return address
    if chain == "bitcoin":
        return address
    # Default: treat as EVM. Lowercase canonical.
    if address.startswith("0x") or address.startswith("0X"):
        return address.lower()
    return address.lower()


def _source_for_category(cat_lower: str) -> str:
    if cat_lower.startswith("ofac"):
        return "ofac"
    if "ransomware" in cat_lower:
        return "ransomware_seed"
    if "mixer" in cat_lower:
        return "mixers_seed"
    return "high_risk_seed"


def _lookup_correlation_for_address(
    address: str, *, chain: str, dsn: str,
) -> ScreeningCorrelation:
    """Single-address aggregated correlation lookup.

    Mirrors trace/correlation.lookup_correlations but rolled up
    into one row per address (the screening use case doesn't need
    per-case appearance detail — it needs aggregated counts).
    """
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:
        return ScreeningCorrelation()

    sql = """
        SELECT
            COUNT(DISTINCT case_id) FILTER (WHERE case_id IS NOT NULL)
                                                         AS prior_case_count,
            COUNT(DISTINCT case_id) FILTER (WHERE is_ofac_exposed
                                              AND case_id IS NOT NULL)
                                                         AS prior_ofac_exposed_count,
            COUNT(DISTINCT case_id) FILTER (WHERE is_mixer_exposed
                                              AND case_id IS NOT NULL)
                                                         AS prior_mixer_exposed_count,
            COUNT(DISTINCT case_id) FILTER (WHERE is_drainer_attributed
                                              AND case_id IS NOT NULL)
                                                         AS prior_drainer_attributed_count,
            COALESCE(SUM(usd_flowed), 0)                 AS prior_total_usd_flowed,
            ARRAY_AGG(DISTINCT role)                     AS roles_seen
          FROM public.address_observations
         WHERE address = %(addr)s
           AND chain = %(chain)s;
    """
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, {"addr": address, "chain": chain})
            row = cur.fetchone() or {}

    return ScreeningCorrelation(
        prior_case_count=int(row.get("prior_case_count") or 0),
        prior_ofac_exposed_count=int(row.get("prior_ofac_exposed_count") or 0),
        prior_mixer_exposed_count=int(row.get("prior_mixer_exposed_count") or 0),
        prior_drainer_attributed_count=int(
            row.get("prior_drainer_attributed_count") or 0
        ),
        prior_total_usd_flowed=Decimal(str(row.get("prior_total_usd_flowed") or 0)),
        prior_roles_seen=sorted([r for r in (row.get("roles_seen") or []) if r]),
    )


def _compute_score(
    *,
    entry: HighRiskEntry | None,
    correlation: ScreeningCorrelation,
) -> int:
    """0..10 risk score combining seed severity + correlation history.

    Calibration:
      * OFAC-listed (sev 4) directly                     → 10
      * Ransomware / mixer-sanctioned                    → 9
      * Drainer (sev 3)                                  → 7
      * Other high-risk seed entry                       → 5
      * No seed hit, but OFAC-exposed in correlation     → 6
      * No seed hit, but drainer-attributed in corr      → 5
      * No seed hit, 3+ prior cases                      → 3
      * No seed hit, 1-2 prior cases                     → 1
      * Otherwise                                        → 0
    """
    if entry is not None:
        cat = (entry.risk_category or "").lower()
        if cat.startswith("ofac"):
            return 10
        if "ransomware" in cat or cat == "mixer_sanctioned":
            return 9
        if "drainer" in cat or "scam" in cat:
            return 7
        return max(5, entry.severity * 2)

    # No seed hit — fall back to correlation history.
    if correlation.prior_ofac_exposed_count > 0:
        return 6
    if correlation.prior_drainer_attributed_count > 0:
        return 5
    if correlation.prior_case_count >= 3:
        return 3
    if correlation.prior_case_count >= 1:
        return 1
    return 0


def _verdict_for(
    *,
    is_ofac: bool,
    is_mixer: bool,
    is_ransomware: bool,
    is_drainer: bool,
    score: int,
    correlation: ScreeningCorrelation,
) -> str:
    """Map (flags + score) to a verdict string.

    Matches the taxonomy used by RISK_ASSESSMENT in the brief so
    downstream consumers can union the two outputs cleanly.
    """
    if is_ofac:
        return "sanctioned"
    if is_ransomware:
        return "sanctioned"
    if is_mixer:
        return "sanctioned"
    if is_drainer:
        return "high"
    if score >= 6 or correlation.prior_ofac_exposed_count > 0:
        return "high"
    if score >= 3 or correlation.prior_case_count >= 3:
        return "medium"
    if score >= 1 or correlation.prior_case_count >= 1:
        return "low"
    return "clean"


def _build_investigator_note(
    *,
    address: str,
    verdict: str,
    entry: HighRiskEntry | None,
    correlation: ScreeningCorrelation,
    is_ofac: bool,
    is_mixer: bool,
    is_ransomware: bool,
    is_drainer: bool,
) -> str:
    """One-sentence human-readable verdict."""
    if is_ofac:
        listing = (
            f" (listed {entry.ofac_listing_date})"
            if entry and entry.ofac_listing_date else ""
        )
        return (
            f"SANCTIONED — direct OFAC SDN hit{listing}: "
            f"{entry.name if entry else 'OFAC entry'}. "
            "Do not transact with this address."
        )
    if is_ransomware:
        return (
            f"SANCTIONED — ransomware attribution: "
            f"{entry.name if entry else 'unknown operator'}. "
            "Treat as ransomware payment endpoint."
        )
    if is_mixer:
        return (
            f"SANCTIONED — mixer/obfuscation contract: "
            f"{entry.name if entry else 'unknown'}. "
            "Funds passing through here lose recoverability."
        )
    if is_drainer:
        return (
            f"HIGH-RISK — known drainer infrastructure "
            f"({entry.name if entry else 'unknown'}). "
            "Address typically receives stolen funds from approval exploits."
        )
    if correlation.prior_ofac_exposed_count > 0:
        return (
            f"HIGH-RISK — appeared in {correlation.prior_case_count} prior "
            f"cases; OFAC-exposed in "
            f"{correlation.prior_ofac_exposed_count}. "
            "Indirect exposure; verify before clearing."
        )
    if verdict == "high":
        return "HIGH-RISK — significant exposure indicators present."
    if verdict == "medium":
        return (
            f"MEDIUM — appeared in {correlation.prior_case_count} prior "
            "case(s). Worth reviewing prior-case context before clearing."
        )
    if verdict == "low":
        return (
            f"LOW — appeared in {correlation.prior_case_count} prior "
            "case(s) with no high-risk attribution."
        )
    return "CLEAN — no detected high-risk indicators."


__all__ = (
    "ScreeningLabel",
    "ScreeningCorrelation",
    "ScreeningResult",
    "screen_address",
)
