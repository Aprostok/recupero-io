"""SAR / STR regulatory-filing draft generator (v0.35.10 — roadmap E3).

We already render MLAT / 314(b) / subpoena drafts (``legal_requests.py``). This
adds the suspicious-activity report family: a FinCEN SAR (US), an NCA SAR (UK),
or an AMLD STR (EU/goAML) DRAFT package assembled from a case's
``freeze_brief.json``.

**Drafts only — Recupero is NOT a filer.** A SAR/STR is filed by an *obligated
financial institution* (or, for the UK, a reporter under POCA 2002). Recupero
has no filing obligation and no BSA-E-Filing / goAML credentials. These documents
compress the analyst's drafting work into a reviewable package the obligated FI's
compliance officer completes (institution identifiers + officer attestation) and
submits. The narrative + structured activity fields are derived ENTIRELY from the
traced case — no fabricated subjects, amounts, dates, or institutions.

Pipeline (after ``recupero emit-brief CASE_ID``):
    recupero sar-filing CASE_ID --jurisdiction us   # FinCEN SAR (Form 111)
    recupero sar-filing CASE_ID --jurisdiction uk   # NCA SAR (POCA 2002)
    recupero sar-filing CASE_ID --jurisdiction eu   # AMLD STR (goAML)
→ writes ``regulatory_filing/<jurisdiction>_sar.html`` next to the brief.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recupero._common import atomic_write_text
from recupero.reports.legal_requests import _build_base_context, load_brief

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


# Jurisdiction → the regulator labels + statutory framing. The case-derived
# body (subjects / activity / narrative) is jurisdiction-neutral; only these
# labels and the legal citation differ. Aliases map operator-friendly inputs.
_JURISDICTIONS: dict[str, dict[str, str]] = {
    "us_fincen": {
        "report_acronym": "SAR",
        "report_name": "Suspicious Activity Report",
        "regulator": "Financial Crimes Enforcement Network (FinCEN)",
        "form_reference": "FinCEN Report 111 (SAR)",
        "statute": "31 U.S.C. § 5318(g); 31 CFR § 1020.320 et seq.",
        "filing_portal": "FinCEN BSA E-Filing System (bsaefiling.fincen.gov)",
        "characterization": (
            "suspected proceeds of a computer-intrusion / unauthorized "
            "electronic-funds-transfer cyber event (cf. FinCEN SAR Activity "
            "Type 'Cyber Event')"
        ),
    },
    "uk_nca": {
        "report_acronym": "SAR",
        "report_name": "Suspicious Activity Report",
        "regulator": "National Crime Agency (NCA), UK Financial Intelligence Unit",
        "form_reference": "NCA SAR (UKFIU SAR Online)",
        "statute": (
            "Proceeds of Crime Act 2002, ss. 330/331/338; "
            "Terrorism Act 2000, s. 21A"
        ),
        "filing_portal": "NCA SAR Online (sars.ukfiu.nca.gov.uk)",
        "characterization": (
            "property suspected to constitute or represent the proceeds of "
            "criminal conduct (theft / fraud by false representation)"
        ),
    },
    "eu_goaml": {
        "report_acronym": "STR",
        "report_name": "Suspicious Transaction Report",
        "regulator": "the competent national Financial Intelligence Unit (FIU)",
        "form_reference": "AMLD Suspicious Transaction Report (goAML)",
        "statute": (
            "Directive (EU) 2015/849 (4AMLD), Art. 33; "
            "Regulation (EU) 2023/1113"
        ),
        "filing_portal": "the national FIU goAML portal",
        "characterization": (
            "a transaction suspected of involving the proceeds of criminal "
            "activity (asset misappropriation)"
        ),
    },
}

# Operator-friendly aliases.
_JURISDICTION_ALIASES: dict[str, str] = {
    "us": "us_fincen", "usa": "us_fincen", "fincen": "us_fincen",
    "us_fincen": "us_fincen",
    "uk": "uk_nca", "gb": "uk_nca", "nca": "uk_nca", "uk_nca": "uk_nca",
    "eu": "eu_goaml", "str": "eu_goaml", "goaml": "eu_goaml",
    "eu_goaml": "eu_goaml",
}

SAR_JURISDICTIONS = tuple(_JURISDICTIONS.keys())


@dataclass(frozen=True)
class SarFilingRender:
    """Result of rendering one SAR/STR draft."""
    jurisdiction: str
    report_acronym: str
    output_path: Path
    html_size_bytes: int
    subject_count: int


def _resolve_jurisdiction(value: str | None) -> str:
    key = (value or "us").strip().lower().replace("-", "_")
    resolved = _JURISDICTION_ALIASES.get(key)
    if resolved is None:
        raise ValueError(
            f"jurisdiction {value!r} not recognized. Use one of: "
            f"us / uk / eu (or {sorted(SAR_JURISDICTIONS)})."
        )
    return resolved


def _amount_to_float(raw: Any) -> float:
    """Parse a '$1,234.56'-style value to float; non-finite/garbage → 0.0."""
    import math
    try:
        cleaned = str(raw).replace("$", "").replace(",", "").strip()
        v = float(cleaned) if cleaned else 0.0
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(v) or math.isinf(v) or v < 0:
        return 0.0
    return v


def _build_subjects(brief: dict[str, Any]) -> list[dict[str, str]]:
    """Assemble SAR subject rows from the brief — the on-chain addresses that
    received / hold the suspected proceeds. NEVER fabricated: only addresses
    already present in the brief's EXCHANGES / DESTINATIONS / FREEZABLE.

    Subjects are wallet addresses (we have no natural-person identity); the
    filing FI attaches any KYC-resolved identity it holds.
    """
    seen: set[str] = set()
    subjects: list[dict[str, str]] = []

    def _add(address: Any, *, role: str, venue: str, usd: Any, chain: Any) -> None:
        addr = str(address or "").strip()
        if not addr:
            return
        key = addr.lower()
        if key in seen:
            return
        seen.add(key)
        subjects.append({
            "address": addr,
            "chain": str(chain or "").strip() or "ethereum",
            "role": role,
            "venue": str(venue or "").strip(),
            # Always normalize through the finite-float parser so a poisoned
            # "Infinity" / "NaN" string (price-oracle glitch) collapses to
            # $0.00 instead of typesetting "$Infinity" into a SAR. Pre-
            # formatted "$1,234.00" round-trips cleanly.
            "amount_usd": f"${_amount_to_float(usd):,.2f}",
        })

    for ex in (brief.get("EXCHANGES") or []):
        if isinstance(ex, dict):
            _add(
                ex.get("address"),
                role="VASP deposit address (proceeds destination)",
                venue=ex.get("exchange") or ex.get("exchange_name") or "",
                usd=ex.get("total_received_usd") or ex.get("usd"),
                chain=ex.get("chain"),
            )
    for d in (brief.get("FREEZABLE") or []):
        if isinstance(d, dict):
            _add(
                d.get("address"),
                role="current holder of suspected proceeds (freezable)",
                venue=d.get("issuer") or d.get("token") or "",
                usd=d.get("usd") or d.get("usd_value"),
                chain=d.get("chain"),
            )
    for d in (brief.get("DESTINATIONS") or []):
        if isinstance(d, dict):
            _add(
                d.get("address"),
                role="downstream destination of suspected proceeds",
                venue=d.get("label") or d.get("category") or "",
                usd=d.get("total_usd") or d.get("usd"),
                chain=d.get("chain"),
            )
    return subjects


def _activity_date_range(base_ctx: dict[str, Any]) -> tuple[str, str]:
    """Derive (date_from, date_to) from tx evidence block-times, falling back
    to the incident date. Returns ISO-ish strings or '' when unknown."""
    times = sorted(
        str(tx.get("block_time") or "").strip()
        for tx in (base_ctx.get("tx_evidence") or [])
        if str(tx.get("block_time") or "").strip()
    )
    if times:
        return times[0][:19], times[-1][:19]
    incident = str(base_ctx.get("incident_date") or "").strip()
    return incident, incident


def build_sar_context(brief: dict[str, Any], *, jurisdiction: str) -> dict[str, Any]:
    """PURE: brief → SAR/STR render context. No network, no clock beyond the
    shared render-time in ``_build_base_context``.

    Reuses ``legal_requests._build_base_context`` (which already sanitizes
    victim/investigator/incident free-text against placeholder-sentinel leaks)
    and adds the suspicious-activity structured fields + a fact-derived
    narrative + the jurisdiction's regulator labels.
    """
    jkey = _resolve_jurisdiction(jurisdiction)
    labels = _JURISDICTIONS[jkey]
    base = _build_base_context(brief)
    subjects = _build_subjects(brief)
    date_from, date_to = _activity_date_range(base)

    total_loss = base.get("total_loss_usd") or "$0.00"
    n_vasp = sum(1 for s in subjects if "VASP" in s["role"])
    n_dest = len(subjects)

    # Fact-derived Part-V-style narrative. Every clause is grounded in the
    # brief; nothing is invented. Kept neutral across jurisdictions.
    narrative = (
        f"On or about {base.get('incident_date') or '[incident date]'}, "
        f"{base['victim']['name']} ({base['victim']['jurisdiction']}) reported "
        f"{base.get('incident_type') or 'the underlying incident'} resulting in "
        f"the misappropriation of digital assets totalling approximately "
        f"{total_loss} in U.S.-dollar equivalent. On-chain tracing — producing "
        f"chain-of-custody-preserved, independently verifiable evidence — "
        f"established that the suspected proceeds moved to "
        f"{n_dest} identified destination address(es)"
        + (f", including {n_vasp} VASP deposit address(es)" if n_vasp else "")
        + ". The transactions giving rise to this report are itemized in the "
        "supporting-evidence table; each is verifiable on the public "
        f"blockchain. The activity is characterized as {labels['characterization']}."
    )

    return {
        **base,
        "jurisdiction_key": jkey,
        "labels": labels,
        "subjects": subjects,
        "activity": {
            "amount_usd": total_loss,
            "date_from": date_from,
            "date_to": date_to,
            "characterization": labels["characterization"],
        },
        "sar_narrative": narrative,
    }


def render_sar_filing(
    brief: dict[str, Any],
    *,
    jurisdiction: str,
    output_dir: Path,
) -> SarFilingRender:
    """Render the SAR/STR draft to ``regulatory_filing/<jurisdiction>_sar.html``."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ctx = build_sar_context(brief, jurisdiction=jurisdiction)

    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)
    template = env.get_template("regulatory_sar_filing.html.j2")
    html = template.render(**ctx)

    out_path = output_dir / f"{ctx['jurisdiction_key']}_sar.html"
    atomic_write_text(out_path, html)
    log.info(
        "rendered %s draft (%s): %s (%d bytes, %d subjects)",
        ctx["labels"]["report_acronym"], ctx["jurisdiction_key"],
        out_path, out_path.stat().st_size, len(ctx["subjects"]),
    )
    return SarFilingRender(
        jurisdiction=ctx["jurisdiction_key"],
        report_acronym=ctx["labels"]["report_acronym"],
        output_path=out_path,
        html_size_bytes=out_path.stat().st_size,
        subject_count=len(ctx["subjects"]),
    )


def render_case_sar(
    case_dir: Path, *, jurisdiction: str, output_dir: Path | None = None,
) -> SarFilingRender:
    """Convenience: load freeze_brief.json from ``case_dir`` and render."""
    brief = load_brief(case_dir)
    out = output_dir or (case_dir / "regulatory_filing")
    return render_sar_filing(brief, jurisdiction=jurisdiction, output_dir=out)


__all__ = (
    "SAR_JURISDICTIONS",
    "SarFilingRender",
    "build_sar_context",
    "render_sar_filing",
    "render_case_sar",
)
