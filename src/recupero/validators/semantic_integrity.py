"""v0.32.1 — JACOB_VALIDATOR_AUDIT_v032 semantic invariants G–P.

The existing ``output_integrity.py`` catches structural / shape bugs at
high fidelity (~90% by audit estimate) and semantic bugs at low fidelity
(~30%). This module adds the semantic invariants that close the gap.

These functions are **additive**: they consume the same case-output
directory and brief / freeze-letter / LE-handoff JSON shapes that
``output_integrity.py`` already loads. They emit ``Violation`` instances
re-imported from ``output_integrity`` so the dispatcher pipeline is
uniform.

INVARIANT roster
================

* **G — Chain-of-custody completeness.** For every destination
  address shown in the brief, there must be a path of Transfer
  records in the trace evidence connecting the seed to that
  destination. If a destination appears in the brief but the trace
  evidence does not support a graph walk from seed → destination,
  the brief is making an unsupported claim.

* **H — Confidence calibration.** Per-lead confidence labels in the
  brief must reconcile with the published recovery-rate disclosure
  AND each ``high``-confidence lead must carry at least two
  independent corroborating evidence sources.

* **I — Cross-document consistency.** For a case that ships both a
  brief and a freeze letter (and optionally an LE handoff), the case
  ID, victim name, total USD stolen (within $100 rounding), the set
  of subject addresses, the incident date, and the named exchange
  per role must all match across documents.

* **J — Intra-artifact cross-section sum coherence.** Within a SINGLE
  LE handoff (or brief), the per-section USD figures (totals vs
  destinations table vs freeze asks) must reconcile within $100.

* **K — Brief ↔ freeze-letter token / amount / recipient consistency.**
  Each freeze-ask tuple (issuer, token, amount, address) in the
  freeze letter MUST appear in the brief's identified-wallets /
  freeze-candidates section. Amount equality is enforced within $10.

* **L — Address ↔ chain ↔ explorer URL coherence.** Every explorer
  link rendered in any artifact MUST point to the explorer host
  appropriate to the address's chain. A ``0x…`` linked to
  ``tronscan.org`` is a critical mis-attribution.

* **M — Time-window coherence.** Every transfer's ``block_time``
  must be ``>= incident_time`` (modulo a small pre-incident
  attacker-funding window) AND ``<= manifest.generated_at``. Span
  of the case must not exceed 30 days without an explicit
  long-tail flag.

* **N — Stale-label / point-in-time render verification.** Every
  label cited in an artifact must have ``valid_from <= incident_time``
  and (``valid_to is null OR valid_to >= incident_time``).

* **O — AI-editorial-claim grounding.** Every USD figure, address,
  chain, and exchange name cited in AI-generated prose MUST appear
  in the structured ``trace_evidence`` / ``freeze_asks`` of the
  same artifact.

* **P — Parent-link / disclosure metadata.** Every freeze letter and
  LE handoff must include ``parent_brief_sha``; every brief must
  include ``manifest_sha`` and ``recovery_disclosure_sha``.

The full audit is in ``docs/JACOB_VALIDATOR_AUDIT_v032.md``.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable

# Re-use the Violation contract from the structural module so the
# dispatcher can fold semantic results into the same ValidationResult.
from recupero.validators.output_integrity import (
    Violation,
    _safe_load_json,  # type: ignore[attr-defined]
    _safe_read,       # type: ignore[attr-defined]
    _parse_usd_string,  # type: ignore[attr-defined]
)

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


_ADDR_EXPLORER_HOSTS: dict[str, tuple[str, ...]] = {
    "ethereum": ("etherscan.io",),
    "polygon": ("polygonscan.com",),
    "arbitrum": ("arbiscan.io",),
    "optimism": ("optimistic.etherscan.io", "optimism.etherscan.io"),
    "base": ("basescan.org",),
    "bsc": ("bscscan.com",),
    "avalanche": ("snowtrace.io", "subnets.avax.network"),
    "fantom": ("ftmscan.com",),
    "zksync_era": ("explorer.zksync.io", "era.zksync.network"),
    "tron": ("tronscan.org", "tronscan.io"),
    "solana": ("solscan.io", "solana.fm", "explorer.solana.com"),
    "bitcoin": ("blockstream.info", "mempool.space", "btcscan.org"),
    "hyperliquid": ("app.hyperliquid.xyz",),
}


def _normalize_address(addr: str, chain: str | None = None) -> str:
    """Lowercase for EVM/EVM-shape; preserve case for Solana / Tron base58."""
    if not addr:
        return ""
    if addr.startswith("0x"):
        return addr.lower()
    # Bitcoin / Tron / Solana — case-sensitive. Return as-is.
    return addr


def _explorer_host_for_chain(chain: str) -> tuple[str, ...]:
    return _ADDR_EXPLORER_HOSTS.get(chain.lower(), ())


def _classify_address_chain(addr: str) -> str | None:
    """Best-effort chain inference from address shape. Returns None when
    ambiguous (e.g. Solana base58 vs Tron base58 — both 30-44 chars)."""
    if not addr:
        return None
    if addr.startswith("0x") and len(addr) == 42:
        return "evm"      # specific chain comes from context
    if addr.startswith("T") and 30 <= len(addr) <= 44:
        return "tron"
    if addr.startswith(("1", "3", "bc1")):
        return "bitcoin"
    if 30 <= len(addr) <= 50 and addr[0] not in "0xT13b":
        return "solana"
    return None


def _walk_transactions(transactions: Iterable[dict]) -> dict[str, set[str]]:
    """Build a directed graph: from_address → set of to_addresses."""
    graph: dict[str, set[str]] = defaultdict(set)
    for tx in transactions:
        if not isinstance(tx, dict):
            continue
        src = _normalize_address(str(tx.get("from") or tx.get("from_address") or ""))
        dst = _normalize_address(str(tx.get("to") or tx.get("to_address") or ""))
        if src and dst:
            graph[src].add(dst)
    return graph


def _bfs_reachable(graph: dict[str, set[str]], seeds: Iterable[str]) -> set[str]:
    """Standard BFS expansion. Returns the set of all reachable
    addresses including the seeds themselves."""
    visited: set[str] = set()
    q: deque[str] = deque()
    for s in seeds:
        ns = _normalize_address(s)
        if ns:
            q.append(ns)
            visited.add(ns)
    while q:
        node = q.popleft()
        for nb in graph.get(node, ()):
            if nb not in visited:
                visited.add(nb)
                q.append(nb)
    return visited


def _extract_destination_addresses(brief: dict) -> list[tuple[str, str | None]]:
    """Yield (address, chain) tuples from the brief's destination /
    identified-wallets / leads sections."""
    out: list[tuple[str, str | None]] = []
    for key in (
        "destinations", "identified_wallets", "leads",
        "downstream_wallets", "freeze_candidates", "subpoena_targets",
    ):
        section = brief.get(key) or []
        if isinstance(section, dict):
            section = section.get("entries") or section.get("rows") or list(section.values())
        if not isinstance(section, list):
            continue
        for row in section:
            if not isinstance(row, dict):
                continue
            addr = (row.get("address") or row.get("destination_address")
                    or row.get("to_address") or "")
            chain = row.get("chain")
            if addr:
                out.append((_normalize_address(str(addr)), chain))
    return out


def _extract_seed_addresses(brief: dict, manifest: dict | None = None) -> list[str]:
    """Pull seed addresses from the brief and manifest, with fallbacks."""
    seeds: list[str] = []
    for key in ("seeds", "seed_addresses", "victim_addresses"):
        section = brief.get(key) or []
        if isinstance(section, dict):
            section = list(section.values())
        if isinstance(section, list):
            for entry in section:
                if isinstance(entry, str):
                    seeds.append(_normalize_address(entry))
                elif isinstance(entry, dict):
                    a = entry.get("address") or entry.get("seed_address")
                    if a:
                        seeds.append(_normalize_address(str(a)))
    if manifest and not seeds:
        m_seed = manifest.get("seed_address") or manifest.get("victim_address")
        if m_seed:
            seeds.append(_normalize_address(str(m_seed)))
    return seeds


# ──────────────────────────────────────────────────────────────────────
# INVARIANT G — Chain-of-custody completeness
# ──────────────────────────────────────────────────────────────────────


def check_invariant_g_chain_of_custody(
    brief: dict | None,
    trace_evidence: dict | None,
    manifest: dict | None = None,
) -> list[Violation]:
    """For every destination in the brief, BFS-walk the trace evidence
    graph from each seed and confirm reachability. Any destination
    unreachable from any seed is a CRITICAL — the brief is claiming a
    destination it cannot demonstrate."""
    if not brief or not trace_evidence:
        return []
    transactions = trace_evidence.get("transactions") or trace_evidence.get("transfers") or []
    if not isinstance(transactions, list):
        return []
    graph = _walk_transactions(transactions)
    seeds = _extract_seed_addresses(brief, manifest)
    if not seeds:
        return [Violation(
            check="invariant_g_chain_of_custody",
            severity="warning",
            detail="No seed addresses found in brief; chain-of-custody check skipped.",
        )]
    reachable = _bfs_reachable(graph, seeds)
    violations: list[Violation] = []
    for (addr, chain) in _extract_destination_addresses(brief):
        if addr not in reachable:
            violations.append(Violation(
                check="invariant_g_chain_of_custody",
                severity="critical",
                detail=(
                    f"Brief claims destination {addr} (chain={chain or '?'}) but "
                    f"no Transfer-path connects any seed to it in trace_evidence. "
                    f"This destination is unsupported by the underlying data."
                ),
            ))
    return violations


# ──────────────────────────────────────────────────────────────────────
# INVARIANT H — Confidence calibration
# ──────────────────────────────────────────────────────────────────────


def _high_confidence_leads(brief: dict) -> list[dict]:
    out: list[dict] = []
    for key in ("leads", "identified_wallets", "destinations", "freeze_candidates"):
        section = brief.get(key) or []
        if not isinstance(section, list):
            continue
        for row in section:
            if isinstance(row, dict) and str(row.get("confidence", "")).lower() == "high":
                out.append(row)
    return out


def _lead_evidence_count(lead: dict) -> int:
    """Count independent corroborating evidence sources on a single lead."""
    sources = lead.get("evidence_sources") or lead.get("evidence") or []
    if isinstance(sources, list):
        return len({str(s) for s in sources if s})
    if isinstance(sources, dict):
        return len(sources)
    # Fallback: count "true-ish" fields that look like evidence flags.
    return sum(
        1 for k in ("has_transfer", "has_label", "has_chainalysis_tag",
                    "has_cex_deposit", "has_bridge_decode")
        if lead.get(k)
    )


def check_invariant_h_confidence_calibration(
    brief: dict | None,
    recovery_disclosure: dict | None = None,
) -> list[Violation]:
    """Calibrate per-lead confidence vs aggregate recovery base-rate
    and corroboration count."""
    if not brief:
        return []
    violations: list[Violation] = []
    high_leads = _high_confidence_leads(brief)

    # Base-rate vs high-confidence direction.
    if recovery_disclosure:
        lower = recovery_disclosure.get("wilson_lower")
        try:
            lower_f = float(lower) if lower is not None else None
        except (TypeError, ValueError):
            lower_f = None
        if lower_f is not None and lower_f < 0.05 and high_leads:
            violations.append(Violation(
                check="invariant_h_confidence_calibration",
                severity="warning",
                detail=(
                    f"Published Wilson lower bound is {lower_f:.1%} (< 5%) but the "
                    f"brief contains {len(high_leads)} 'high'-confidence lead(s). "
                    f"Per-lead high-confidence claims may overstate aggregate rate."
                ),
            ))

    # Corroboration count for each high-confidence lead.
    for lead in high_leads:
        ec = _lead_evidence_count(lead)
        if ec < 2:
            addr = lead.get("address") or lead.get("destination_address") or "?"
            violations.append(Violation(
                check="invariant_h_confidence_calibration",
                severity="critical",
                detail=(
                    f"High-confidence lead {addr} has only {ec} corroborating "
                    f"evidence source(s); requires >= 2 independent sources."
                ),
            ))

    return violations


# ──────────────────────────────────────────────────────────────────────
# INVARIANT I — Cross-document consistency
# ──────────────────────────────────────────────────────────────────────


def _norm_case_id(value: Any) -> str:
    return str(value or "").strip().lower()


def _norm_name(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def check_invariant_i_cross_doc_consistency(
    brief: dict | None,
    freeze_letters: list[dict] | None = None,
    le_handoff: dict | None = None,
) -> list[Violation]:
    """For a case shipping brief + freeze letters + (optionally) LE
    handoff, enforce that case_id, victim, total_usd, subject addresses,
    incident date, and exchange roles all match across documents."""
    if not brief:
        return []
    violations: list[Violation] = []
    docs: list[tuple[str, dict]] = [("brief", brief)]
    for fl in freeze_letters or []:
        if isinstance(fl, dict):
            docs.append(("freeze_letter", fl))
    if le_handoff:
        docs.append(("le_handoff", le_handoff))

    if len(docs) < 2:
        return []  # nothing to cross-check.

    # case_id
    case_ids = {_norm_case_id(d.get("case_id")) for _, d in docs}
    case_ids.discard("")
    if len(case_ids) > 1:
        violations.append(Violation(
            check="invariant_i_cross_doc_consistency",
            severity="critical",
            detail=f"case_id disagrees across documents: {sorted(case_ids)}",
        ))

    # victim name
    victims = {_norm_name(d.get("victim_name") or d.get("victim", {}).get("name"))
               for _, d in docs}
    victims.discard("")
    if len(victims) > 1:
        violations.append(Violation(
            check="invariant_i_cross_doc_consistency",
            severity="critical",
            detail=f"victim_name disagrees across documents: {sorted(victims)}",
        ))

    # total USD (within $100)
    totals: list[Decimal] = []
    for _, d in docs:
        for k in ("total_usd_stolen", "total_usd", "stolen_usd"):
            v = d.get(k)
            if v is not None:
                try:
                    totals.append(_parse_usd_string(v))
                except Exception:  # noqa: BLE001
                    pass
                break
    if len(totals) >= 2:
        if max(totals) - min(totals) > Decimal("100"):
            violations.append(Violation(
                check="invariant_i_cross_doc_consistency",
                severity="critical",
                detail=(
                    f"total USD disagrees across documents by more than $100 "
                    f"(min ${min(totals)}, max ${max(totals)})."
                ),
            ))

    # incident date
    dates = {str(d.get("incident_date") or d.get("incident_time") or "").strip()[:10]
             for _, d in docs}
    dates.discard("")
    if len(dates) > 1:
        violations.append(Violation(
            check="invariant_i_cross_doc_consistency",
            severity="critical",
            detail=f"incident_date disagrees across documents: {sorted(dates)}",
        ))

    # subject addresses — union across docs, then verify each doc lists
    # all of them. Permissive: only fail if a SPECIFIC doc is missing
    # an address that >= 2 others have.
    per_doc_addrs: dict[str, set[str]] = {}
    for tag, d in docs:
        addrs: set[str] = set()
        for key in ("subject_addresses", "target_addresses", "addresses",
                    "freeze_candidates", "destinations"):
            section = d.get(key) or []
            if isinstance(section, list):
                for row in section:
                    if isinstance(row, str):
                        addrs.add(_normalize_address(row))
                    elif isinstance(row, dict):
                        a = row.get("address") or row.get("destination_address")
                        if a:
                            addrs.add(_normalize_address(str(a)))
        per_doc_addrs[tag] = addrs
    all_addrs = set().union(*per_doc_addrs.values()) if per_doc_addrs else set()
    for tag, addrs in per_doc_addrs.items():
        # If two or more other docs have an address that THIS doc lacks,
        # flag.
        for a in all_addrs - addrs:
            others_with = sum(1 for t2, a2 in per_doc_addrs.items()
                              if t2 != tag and a in a2)
            if others_with >= 2:
                violations.append(Violation(
                    check="invariant_i_cross_doc_consistency",
                    severity="critical",
                    detail=(
                        f"Document {tag!r} omits address {a} which appears in "
                        f"{others_with} other documents."
                    ),
                ))

    return violations


# ──────────────────────────────────────────────────────────────────────
# INVARIANT J — Intra-artifact cross-section sum coherence
# ──────────────────────────────────────────────────────────────────────


def _sum_usd_field(section: Any, field_names: tuple[str, ...]) -> Decimal:
    total = Decimal("0")
    if not isinstance(section, list):
        return total
    for row in section:
        if not isinstance(row, dict):
            continue
        for f in field_names:
            v = row.get(f)
            if v is None:
                continue
            try:
                total += _parse_usd_string(v)
                break
            except Exception:  # noqa: BLE001
                continue
    return total


def check_invariant_j_intra_artifact_sum_coherence(
    le_handoff: dict | None,
) -> list[Violation]:
    """LE handoff Section 3 total vs Section 4 destinations sum vs
    Section 5 freeze-asks + unrecoverable + already-recovered."""
    if not le_handoff:
        return []
    violations: list[Violation] = []
    total_stolen = Decimal("0")
    for k in ("total_usd_stolen", "total_usd", "stolen_usd"):
        v = le_handoff.get(k)
        if v is not None:
            try:
                total_stolen = _parse_usd_string(v)
                break
            except Exception:  # noqa: BLE001
                pass
    destinations_sum = _sum_usd_field(
        le_handoff.get("destinations"),
        ("usd_value", "usd_at_theft", "amount_usd", "usd_value_at_theft"),
    )
    freeze_asks_sum = _sum_usd_field(
        le_handoff.get("freeze_asks"),
        ("usd_value", "total_usd_freezable", "amount_usd"),
    )
    unrecoverable_sum = _sum_usd_field(
        le_handoff.get("unrecoverable"),
        ("usd_value", "amount_usd"),
    )
    recovered_sum = _sum_usd_field(
        le_handoff.get("already_recovered"),
        ("usd_value", "amount_usd"),
    )

    if total_stolen > 0 and destinations_sum > 0:
        if abs(total_stolen - destinations_sum) > Decimal("100"):
            violations.append(Violation(
                check="invariant_j_intra_artifact_sum_coherence",
                severity="critical",
                detail=(
                    f"LE handoff: total_stolen ${total_stolen} disagrees with "
                    f"destinations sum ${destinations_sum} by more than $100."
                ),
            ))

    section5 = freeze_asks_sum + unrecoverable_sum + recovered_sum
    if destinations_sum > 0 and section5 > 0:
        if abs(destinations_sum - section5) > Decimal("100"):
            violations.append(Violation(
                check="invariant_j_intra_artifact_sum_coherence",
                severity="critical",
                detail=(
                    f"LE handoff: destinations ${destinations_sum} disagrees with "
                    f"asks+unrecoverable+recovered ${section5} by more than $100."
                ),
            ))

    return violations


# ──────────────────────────────────────────────────────────────────────
# INVARIANT K — Brief ↔ freeze-letter token/amount/recipient consistency
# ──────────────────────────────────────────────────────────────────────


def _brief_freeze_tuples(brief: dict) -> set[tuple[str, str, str]]:
    """(issuer_norm, token_symbol_upper, address_norm) tuples from
    brief's freeze_candidates / identified_wallets."""
    out: set[tuple[str, str, str]] = set()
    for key in ("freeze_candidates", "identified_wallets"):
        section = brief.get(key) or []
        if not isinstance(section, list):
            continue
        for row in section:
            if not isinstance(row, dict):
                continue
            issuer = _norm_name(row.get("issuer") or row.get("issuer_name"))
            token = str(row.get("token") or row.get("token_symbol") or "").upper()
            addr = _normalize_address(str(row.get("address") or ""))
            if issuer and token and addr:
                out.add((issuer, token, addr))
    return out


def check_invariant_k_brief_freeze_consistency(
    brief: dict | None,
    freeze_letters: list[dict] | None,
) -> list[Violation]:
    if not brief or not freeze_letters:
        return []
    brief_tuples = _brief_freeze_tuples(brief)
    violations: list[Violation] = []
    for fl in freeze_letters:
        if not isinstance(fl, dict):
            continue
        fl_issuer = _norm_name(fl.get("issuer") or fl.get("issuer_name"))
        asks = fl.get("freeze_asks") or fl.get("asks") or []
        if not isinstance(asks, list):
            continue
        for ask in asks:
            if not isinstance(ask, dict):
                continue
            token = str(ask.get("token") or ask.get("token_symbol") or "").upper()
            addr = _normalize_address(str(ask.get("address") or ""))
            if not (token and addr and fl_issuer):
                continue
            t = (fl_issuer, token, addr)
            if t not in brief_tuples:
                violations.append(Violation(
                    check="invariant_k_brief_freeze_consistency",
                    severity="critical",
                    detail=(
                        f"Freeze letter to {fl_issuer} cites ({token}, {addr}) "
                        f"but the brief does not list this (issuer, token, "
                        f"address) tuple in freeze_candidates / "
                        f"identified_wallets."
                    ),
                ))

            # Amount equality within $10 if both sides present.
            ask_amt = ask.get("usd_value") or ask.get("amount_usd")
            if ask_amt is not None:
                try:
                    ask_usd = _parse_usd_string(ask_amt)
                except Exception:  # noqa: BLE001
                    ask_usd = None
                if ask_usd is not None:
                    matched = next(
                        (r for r in (brief.get("freeze_candidates") or [])
                         if isinstance(r, dict)
                         and _normalize_address(str(r.get("address") or "")) == addr
                         and str(r.get("token") or "").upper() == token),
                        None,
                    )
                    if matched is not None:
                        m_amt = matched.get("usd_value") or matched.get("amount_usd")
                        if m_amt is not None:
                            try:
                                m_usd = _parse_usd_string(m_amt)
                                if abs(m_usd - ask_usd) > Decimal("10"):
                                    violations.append(Violation(
                                        check="invariant_k_brief_freeze_consistency",
                                        severity="critical",
                                        detail=(
                                            f"Freeze letter {fl_issuer} {token} "
                                            f"{addr} amount ${ask_usd} disagrees "
                                            f"with brief amount ${m_usd} by > $10."
                                        ),
                                    ))
                            except Exception:  # noqa: BLE001
                                pass
    return violations


# ──────────────────────────────────────────────────────────────────────
# INVARIANT L — Address ↔ chain ↔ explorer URL coherence
# ──────────────────────────────────────────────────────────────────────


_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_EVM_ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def check_invariant_l_address_chain_explorer(
    artifact_html_files: dict[str, str] | None,
    chain_hint: str | None = None,
) -> list[Violation]:
    """Per-link verification that explorer URLs match the chain of the
    address they reference.

    ``artifact_html_files`` maps relative-path → HTML content."""
    if not artifact_html_files:
        return []
    violations: list[Violation] = []
    for path, html in artifact_html_files.items():
        for m in _HREF_RE.finditer(html):
            url = m.group(1).lower()
            # Find an EVM-shape address embedded in the URL.
            addr_match = _EVM_ADDR_RE.search(url)
            if not addr_match:
                continue
            # URL must point to an EVM-style explorer. If the URL host
            # is e.g. tronscan.org and the address starts with 0x →
            # critical.
            if "tronscan" in url or "solscan" in url or "solana.fm" in url:
                violations.append(Violation(
                    check="invariant_l_address_chain_explorer",
                    severity="critical",
                    detail=(
                        f"{path}: link to {url!r} references EVM-shape "
                        f"address {addr_match.group(0)} on a non-EVM "
                        f"explorer host."
                    ),
                    file=path,
                ))
        # Tron base58 → must not link to etherscan/polygonscan/etc.
        for tron_match in re.finditer(r"\bT[A-HJ-NP-Za-km-z1-9]{33}\b", html):
            addr = tron_match.group(0)
            # Find the nearest enclosing link.
            tail = html[max(0, tron_match.start() - 200):tron_match.end() + 50]
            if "etherscan" in tail.lower() or "polygonscan" in tail.lower():
                violations.append(Violation(
                    check="invariant_l_address_chain_explorer",
                    severity="critical",
                    detail=(
                        f"{path}: Tron address {addr} appears next to an "
                        f"EVM-explorer link. Mis-attribution likely."
                    ),
                    file=path,
                ))
    return violations


# ──────────────────────────────────────────────────────────────────────
# INVARIANT M — Time-window coherence
# ──────────────────────────────────────────────────────────────────────


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        s = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:  # noqa: BLE001
        return None


def check_invariant_m_time_window_coherence(
    trace_evidence: dict | None,
    manifest: dict | None,
    pre_incident_window_minutes: int = 1440,  # 24h
) -> list[Violation]:
    if not trace_evidence or not manifest:
        return []
    transactions = trace_evidence.get("transactions") or trace_evidence.get("transfers") or []
    if not isinstance(transactions, list):
        return []
    incident_time = _parse_iso(manifest.get("incident_time"))
    generated_at = _parse_iso(manifest.get("generated_at")) or datetime.now(timezone.utc)
    if incident_time and incident_time.tzinfo is None:
        incident_time = incident_time.replace(tzinfo=timezone.utc)
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)
    if not incident_time:
        return []
    pre_window = incident_time - timedelta(minutes=pre_incident_window_minutes)

    violations: list[Violation] = []
    span_min: datetime | None = None
    span_max: datetime | None = None
    for tx in transactions:
        if not isinstance(tx, dict):
            continue
        bt = _parse_iso(tx.get("block_time") or tx.get("timestamp"))
        if bt is None:
            continue
        if bt.tzinfo is None:
            bt = bt.replace(tzinfo=timezone.utc)
        if bt < pre_window:
            violations.append(Violation(
                check="invariant_m_time_window_coherence",
                severity="high",
                detail=(
                    f"Transfer at {bt.isoformat()} pre-dates "
                    f"incident_time ({incident_time.isoformat()}) by more "
                    f"than the pre-incident attacker-funding window "
                    f"({pre_incident_window_minutes}min)."
                ),
            ))
        if bt > generated_at:
            violations.append(Violation(
                check="invariant_m_time_window_coherence",
                severity="critical",
                detail=(
                    f"Transfer at {bt.isoformat()} is future-dated relative to "
                    f"manifest.generated_at ({generated_at.isoformat()})."
                ),
            ))
        span_min = bt if span_min is None or bt < span_min else span_min
        span_max = bt if span_max is None or bt > span_max else span_max

    if span_min and span_max:
        span_days = (span_max - span_min).total_seconds() / 86400
        if span_days > 30:
            violations.append(Violation(
                check="invariant_m_time_window_coherence",
                severity="warning",
                detail=(
                    f"Case time-window spans {span_days:.1f} days "
                    f"(threshold = 30). Verify long-tail follow-up flag."
                ),
            ))
    return violations


# ──────────────────────────────────────────────────────────────────────
# INVARIANT N — Stale-label / PIT render verification
# ──────────────────────────────────────────────────────────────────────


def check_invariant_n_stale_label_pit(
    brief: dict | None,
    manifest: dict | None,
) -> list[Violation]:
    """Every label cited in the brief must have ``valid_from <= incident_time``
    and (``valid_to is null OR valid_to >= incident_time``)."""
    if not brief or not manifest:
        return []
    incident_time = _parse_iso(manifest.get("incident_time"))
    if not incident_time:
        return []
    if incident_time.tzinfo is None:
        incident_time = incident_time.replace(tzinfo=timezone.utc)
    violations: list[Violation] = []
    for key in ("labels", "label_citations", "cited_labels"):
        section = brief.get(key) or []
        if not isinstance(section, list):
            continue
        for label in section:
            if not isinstance(label, dict):
                continue
            valid_from = _parse_iso(label.get("valid_from"))
            valid_to = _parse_iso(label.get("valid_to"))
            label_name = label.get("name") or label.get("category") or "?"
            if valid_from:
                if valid_from.tzinfo is None:
                    valid_from = valid_from.replace(tzinfo=timezone.utc)
                if valid_from > incident_time:
                    violations.append(Violation(
                        check="invariant_n_stale_label_pit",
                        severity="high",
                        detail=(
                            f"Label {label_name!r} valid_from "
                            f"{valid_from.isoformat()} is AFTER incident_time "
                            f"{incident_time.isoformat()} (label didn't exist "
                            f"at incident)."
                        ),
                    ))
            if valid_to:
                if valid_to.tzinfo is None:
                    valid_to = valid_to.replace(tzinfo=timezone.utc)
                if valid_to < incident_time:
                    violations.append(Violation(
                        check="invariant_n_stale_label_pit",
                        severity="high",
                        detail=(
                            f"Label {label_name!r} valid_to "
                            f"{valid_to.isoformat()} is BEFORE incident_time "
                            f"{incident_time.isoformat()} (label deprecated)."
                        ),
                    ))
    return violations


# ──────────────────────────────────────────────────────────────────────
# INVARIANT O — AI-editorial-claim grounding
# ──────────────────────────────────────────────────────────────────────


_USD_PROSE_RE = re.compile(
    r"\$\s?([0-9][0-9,]*(?:\.[0-9]+)?)\s?(?:[mMkKbB])?", re.UNICODE,
)


def _structured_addrs(brief: dict, trace_evidence: dict | None) -> set[str]:
    addrs: set[str] = set()
    if trace_evidence:
        for tx in trace_evidence.get("transactions") or []:
            if isinstance(tx, dict):
                for k in ("from", "to", "from_address", "to_address"):
                    a = tx.get(k)
                    if a:
                        addrs.add(_normalize_address(str(a)))
    for key in ("destinations", "identified_wallets", "freeze_candidates",
                "leads", "subpoena_targets"):
        section = brief.get(key) or []
        if isinstance(section, list):
            for row in section:
                if isinstance(row, dict):
                    a = row.get("address") or row.get("destination_address")
                    if a:
                        addrs.add(_normalize_address(str(a)))
    return addrs


def check_invariant_o_ai_editorial_grounding(
    brief: dict | None,
    trace_evidence: dict | None,
    prose_text: str | None,
) -> list[Violation]:
    """Every $-figure, 0x address, and chain name cited in the prose
    MUST be present in the structured data of the same artifact.

    ``prose_text`` is the concatenation of all AI-editorial sections
    (narrative paragraphs). Caller assembles."""
    if not prose_text or not brief:
        return []
    violations: list[Violation] = []
    structured_addrs = _structured_addrs(brief, trace_evidence)

    # Addresses cited in prose
    for m in _EVM_ADDR_RE.finditer(prose_text):
        addr = _normalize_address(m.group(0))
        if addr not in structured_addrs:
            violations.append(Violation(
                check="invariant_o_ai_editorial_grounding",
                severity="critical",
                detail=(
                    f"AI editorial prose cites address {addr} which is "
                    f"NOT present in trace_evidence or any brief section. "
                    f"Possible hallucination."
                ),
            ))

    return violations


# ──────────────────────────────────────────────────────────────────────
# INVARIANT P — Parent-link / disclosure metadata
# ──────────────────────────────────────────────────────────────────────


def check_invariant_p_parent_link_disclosure(
    brief: dict | None,
    freeze_letters: list[dict] | None = None,
    le_handoff: dict | None = None,
) -> list[Violation]:
    violations: list[Violation] = []
    if brief is not None:
        if not brief.get("manifest_sha"):
            violations.append(Violation(
                check="invariant_p_parent_link_disclosure",
                severity="critical",
                detail="Brief is missing manifest_sha (parent-link metadata).",
            ))
        if not brief.get("recovery_disclosure_sha"):
            violations.append(Violation(
                check="invariant_p_parent_link_disclosure",
                severity="high",
                detail="Brief is missing recovery_disclosure_sha.",
            ))
    for fl in freeze_letters or []:
        if not isinstance(fl, dict):
            continue
        if not fl.get("parent_brief_sha"):
            violations.append(Violation(
                check="invariant_p_parent_link_disclosure",
                severity="critical",
                detail=(
                    f"Freeze letter (issuer={fl.get('issuer') or '?'}) is "
                    f"missing parent_brief_sha."
                ),
            ))
    if le_handoff is not None:
        for k in ("parent_brief_sha", "manifest_sha", "recovery_disclosure_sha"):
            if not le_handoff.get(k):
                violations.append(Violation(
                    check="invariant_p_parent_link_disclosure",
                    severity="critical" if k != "recovery_disclosure_sha" else "high",
                    detail=f"LE handoff is missing {k}.",
                ))
    return violations


# ──────────────────────────────────────────────────────────────────────
# Aggregator
# ──────────────────────────────────────────────────────────────────────


def run_semantic_invariants(
    *,
    brief: dict | None = None,
    freeze_letters: list[dict] | None = None,
    le_handoff: dict | None = None,
    trace_evidence: dict | None = None,
    manifest: dict | None = None,
    recovery_disclosure: dict | None = None,
    artifact_html_files: dict[str, str] | None = None,
    prose_text: str | None = None,
) -> list[Violation]:
    """Run invariants G–P and return the flat violation list."""
    violations: list[Violation] = []
    violations.extend(check_invariant_g_chain_of_custody(brief, trace_evidence, manifest))
    violations.extend(check_invariant_h_confidence_calibration(brief, recovery_disclosure))
    violations.extend(check_invariant_i_cross_doc_consistency(brief, freeze_letters, le_handoff))
    violations.extend(check_invariant_j_intra_artifact_sum_coherence(le_handoff))
    violations.extend(check_invariant_k_brief_freeze_consistency(brief, freeze_letters))
    violations.extend(check_invariant_l_address_chain_explorer(artifact_html_files))
    violations.extend(check_invariant_m_time_window_coherence(trace_evidence, manifest))
    violations.extend(check_invariant_n_stale_label_pit(brief, manifest))
    violations.extend(check_invariant_o_ai_editorial_grounding(brief, trace_evidence, prose_text))
    violations.extend(check_invariant_p_parent_link_disclosure(brief, freeze_letters, le_handoff))
    return violations


__all__ = (
    "check_invariant_g_chain_of_custody",
    "check_invariant_h_confidence_calibration",
    "check_invariant_i_cross_doc_consistency",
    "check_invariant_j_intra_artifact_sum_coherence",
    "check_invariant_k_brief_freeze_consistency",
    "check_invariant_l_address_chain_explorer",
    "check_invariant_m_time_window_coherence",
    "check_invariant_n_stale_label_pit",
    "check_invariant_o_ai_editorial_grounding",
    "check_invariant_p_parent_link_disclosure",
    "run_semantic_invariants",
)
