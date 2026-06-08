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

from recupero._common import db_connect
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


def _safe_int(val: Any, default: int = 0) -> int:
    """Coerce an arbitrary DB / caller-supplied value to int.

    Z1-1 hardening: DB rows may surface non-numeric strings ("NaN",
    "abc") after a schema migration glitch. ``int('NaN')`` raises
    ``ValueError`` and propagates out of the screener. Degrade to
    ``default`` instead.
    """
    if val is None:
        return default
    if isinstance(val, bool):
        return int(val)
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        if val != val or val in (float("inf"), float("-inf")):
            return default
        try:
            return int(val)
        except (ValueError, OverflowError):
            return default
    # Decimal: W13-04 fuzzer caught `Decimal('Infinity')` → OverflowError
    # from int() propagating out of this helper. Check finiteness first.
    if isinstance(val, Decimal):
        if not val.is_finite():
            return default
        try:
            return int(val)
        except (ValueError, OverflowError):
            return default
    try:
        return int(val)
    except (TypeError, ValueError, OverflowError):
        try:
            d = Decimal(str(val))
            if not d.is_finite():
                return default
            return int(d)
        except Exception:  # noqa: BLE001
            return default


def _safe_decimal(val: Any, default: Decimal = Decimal("0")) -> Decimal:
    """Coerce an arbitrary value to a finite, non-negative Decimal.

    Z1-2 hardening: a corrupted ``SUM(usd_flowed)`` column may carry
    the string ``"NaN"`` or a negative number (corruption). Replace
    with ``default`` rather than letting NaN poison every downstream
    comparison.
    """
    if val is None:
        return default
    try:
        d = Decimal(str(val))
    except Exception:  # noqa: BLE001
        return default
    if not d.is_finite():
        return default
    if d < 0:
        return default
    return d


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

    # Z1-6: reject non-dict high_risk_db at the boundary so callers
    # see a clean TypeError rather than an AttributeError from
    # `db.get(addr_norm)` deep inside the screener.
    if high_risk_db is not None and not isinstance(high_risk_db, dict):
        raise TypeError(
            "high_risk_db must be a dict/mapping, got "
            f"{type(high_risk_db).__name__}"
        )

    db = high_risk_db if high_risk_db is not None else load_high_risk_db()
    sources_used: list[str] = ["local_seeds"]
    labels: list[ScreeningLabel] = []
    is_ofac = False
    is_mixer = False
    is_mixer_sanctioned = False
    is_ransomware = False
    is_drainer = False

    entry = db.get(addr_norm)
    if entry is not None:
        cat = (entry.risk_category or "").lower()
        if cat.startswith("ofac"):
            is_ofac = True
        if "mixer" in cat:
            is_mixer = True
        # Only a CURRENTLY OFAC-sanctioned mixer (mixer_sanctioned, e.g.
        # Sinbad/Blender) yields a "sanctioned" verdict. A "mixer_high_risk"
        # entry (e.g. OFAC-DELISTED Tornado Cash, Railgun, FixedFloat) is
        # high-risk but NOT sanctioned — collapsing it to "sanctioned" would
        # re-assert an OFAC designation that does not exist (the same defect
        # the Tornado seed reclassification fixed).
        if cat == "mixer_sanctioned":
            is_mixer_sanctioned = True
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
        is_mixer_sanctioned=is_mixer_sanctioned,
        is_ransomware=is_ransomware,
        is_drainer=is_drainer,
        score=score,
        correlation=correlation,
    )

    note = _build_investigator_note(
        address=addr_norm, verdict=verdict, entry=entry,
        correlation=correlation, is_ofac=is_ofac, is_mixer=is_mixer,
        is_mixer_sanctioned=is_mixer_sanctioned,
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
    """Canonicalize an address for DB lookup.

    v0.17.5 (round-10 forensic HIGH): pre-v0.17.5 the chain hint was
    the sole arbiter — calls that defaulted to chain="ethereum" but
    passed a Solana/Tron base58 address ended up lowercased and
    never matched the high-risk seed (which now case-preserves base58
    after v0.17.5 trace.risk_scoring fix). Be defensive: any address
    that doesn't LOOK like a hex EVM address preserves case, even
    when the explicit chain hint says ethereum.
    """
    if not isinstance(address, str):
        raise TypeError(f"address must be str, got {type(address)!r}")
    address = address.strip()
    if not address:
        raise ValueError("address is empty")

    # Z1-5: reject unreasonably long inputs at the boundary. Real
    # EVM/Tron/BTC/Solana addresses are <= 64 chars; even with
    # base58check overhead, 128 is generous. A 1MB string is hostile.
    if len(address) > 128:
        raise ValueError(
            f"address too long: {len(address)} chars (max 128)"
        )

    # Z1-4: reject NUL bytes (Postgres UntranslatableCharacter) and
    # Unicode bidi-override controls (audit-log spoof). The character
    # set inside a real on-chain address is alnum + a few separators
    # only — bail on any C0 / C1 / bidi control codepoint.
    for ch in address:
        cp = ord(ch)
        if cp == 0:
            raise ValueError(
                "address contains a NUL byte (invalid control character)"
            )
        # C0 controls (\x00-\x1F) + DEL (\x7F) + C1 controls (\x80-\x9F).
        if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            raise ValueError(
                f"address contains a control character (codepoint {cp:#06x})"
            )
        # Unicode bidi controls — RLO/LRO/RLE/LRE/PDF/RLM/LRM/etc.
        if cp in (0x200E, 0x200F, 0x202A, 0x202B, 0x202C,
                  0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
            raise ValueError(
                "address contains a Unicode bidi-override control "
                f"(codepoint {cp:#06x}) — invalid"
            )

    # Case-sensitive chains: base58 / base58check encode the address
    # bytes in a way that's case-meaningful. Lowercasing produces
    # wrong addresses that won't match any DB entry.
    if chain in ("tron", "bitcoin", "solana"):
        return address
    # Defensive shape-check: even when chain="ethereum" (the default),
    # if the address doesn't look like 0x + 40 hex it's almost certainly
    # a misrouted base58 lookup. Preserve case.
    if address.startswith("0x") and len(address) == 42:
        return address.lower()
    return address


def _source_for_category(cat_lower: str) -> str:
    if cat_lower.startswith("ofac"):
        return "ofac"
    if "ransomware" in cat_lower:
        return "ransomware_seed"
    if "mixer" in cat_lower:
        return "mixers_seed"
    if "internal_blacklist" in cat_lower:
        return "internal_blacklist"
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
    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute(sql, {"addr": address, "chain": chain})
        row = cur.fetchone() or {}

    return ScreeningCorrelation(
        prior_case_count=_safe_int(row.get("prior_case_count")),
        prior_ofac_exposed_count=_safe_int(row.get("prior_ofac_exposed_count")),
        prior_mixer_exposed_count=_safe_int(row.get("prior_mixer_exposed_count")),
        prior_drainer_attributed_count=_safe_int(
            row.get("prior_drainer_attributed_count")
        ),
        prior_total_usd_flowed=_safe_decimal(row.get("prior_total_usd_flowed")),
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
        # Z1-3: severity may be non-int (None, str — legacy mixer
        # seed rows pre-v0.9 had no severity field) or out-of-range
        # (attacker-controlled HighRiskEntry). Clamp to 0..4 before
        # the *2 doubling and floor the result to 0..10 so the
        # documented contract holds.
        raw_sev = getattr(entry, "severity", None)
        sev = _safe_int(raw_sev)
        if sev < 0:
            sev = 0
        if sev > 4:
            sev = 4
        score = max(5, sev * 2)
        if score > 10:
            score = 10
        return score

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
    is_mixer_sanctioned: bool = False,
) -> str:
    """Map (flags + score) to a verdict string.

    Matches the taxonomy used by RISK_ASSESSMENT in the brief
    (risk_scoring._verdict_for_score) so downstream consumers can union the
    two outputs cleanly. "sanctioned" is reserved for a CURRENT OFAC SDN hit:
    a direct OFAC entry or a still-sanctioned mixer (mixer_sanctioned, e.g.
    Sinbad/Blender). Ransomware attribution, OFAC-DELISTED / high-risk mixers
    (mixer_high_risk, e.g. Tornado Cash post-2025-03-21, Railgun, FixedFloat),
    and drainers are serious but are NOT OFAC sanctions — they map to "high",
    never "sanctioned" (asserting a non-existent OFAC designation in a
    compliance-facing verdict is a forensic/legal defect).
    """
    if is_ofac or is_mixer_sanctioned:
        return "sanctioned"
    if is_ransomware or is_mixer or is_drainer:
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
    is_mixer_sanctioned: bool = False,
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
    if is_mixer_sanctioned:
        listing = (
            f" (listed {entry.ofac_listing_date})"
            if entry and entry.ofac_listing_date else ""
        )
        return (
            f"SANCTIONED — OFAC-sanctioned mixer{listing}: "
            f"{entry.name if entry else 'unknown'}. "
            "Funds passing through here lose recoverability."
        )
    if is_ransomware:
        return (
            f"HIGH-RISK — ransomware attribution: "
            f"{entry.name if entry else 'unknown operator'}. "
            "Treat as ransomware payment endpoint (CISA/DOJ attribution; "
            "NOT an OFAC sanction)."
        )
    if is_mixer:
        return (
            f"HIGH-RISK — high-risk mixer/obfuscation contract: "
            f"{entry.name if entry else 'unknown'}. "
            "Funds passing through here lose recoverability "
            "(high-risk, NOT OFAC-sanctioned)."
        )
    if is_drainer:
        return (
            f"HIGH-RISK — known drainer infrastructure "
            f"({entry.name if entry else 'unknown'}). "
            "Address typically receives stolen funds from approval exploits."
        )
    if entry is not None and (entry.risk_category or "").lower() == "internal_blacklist":
        return (
            f"HIGH-RISK — internal blacklist hit: {entry.name}. "
            f"{entry.notes or 'Appeared as known-bad in a prior Recupero investigation.'} "
            "Re-trace this routing — treat as known-bad from our own casework "
            "(internal attribution, NOT an OFAC sanction)."
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
