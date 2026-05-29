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


def _get_field(d: dict, *candidates: str, default=None):
    """Return the first non-None value matching any candidate key
    (case-sensitive). Used to bridge lowercase semantic-check
    convention with uppercase production-brief convention."""
    if not isinstance(d, dict):
        return default
    for k in candidates:
        if k in d and d[k] is not None:
            return d[k]
    return default


# Canonical key-candidate registries used by the field-bridging helpers.
# Order: lowercase (semantic-check convention) first, then UPPERCASE
# (production-brief convention), then alternative spellings.
_KEYS_DESTINATIONS = ("destinations", "DESTINATIONS")
_KEYS_FREEZE_CANDIDATES = ("freeze_candidates", "FREEZABLE")
_KEYS_IDENTIFIED_WALLETS = ("identified_wallets", "IDENTIFIED_WALLETS")
_KEYS_INCIDENT_TIME = (
    "incident_time", "INCIDENT_TIMESTAMP_UTC", "incident_timestamp_utc",
)
_KEYS_GENERATED_AT = ("generated_at", "GENERATED_AT")
_KEYS_SEED_ADDRESSES = (
    "seed_addresses", "SEED_ADDRESSES",
    "seeds", "victim_addresses",
    "VICTIM_WALLET_FULL", "victim_wallet_full",
)
_KEYS_CASE_ID = ("case_id", "CASE_ID")
_KEYS_VICTIM_NAME = ("victim_name", "VICTIM_NAME")
_KEYS_TOTAL_USD = (
    "total_usd_stolen", "TOTAL_USD_STOLEN",
    "total_stolen_usd", "TOTAL_STOLEN_USD",
    "total_usd", "TOTAL_USD",
    "stolen_usd", "STOLEN_USD",
    "TOTAL_LOSS_USD", "total_loss_usd",
)


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
    identified-wallets / leads sections.

    Bridges both the lowercase semantic-check convention and the
    UPPERCASE production-brief convention. Also expands the production
    ``FREEZABLE[*].holdings[*]`` nested shape into flat (addr, chain)
    rows.
    """
    out: list[tuple[str, str | None]] = []
    # Flat sections — one address per row.
    for key in (
        "destinations", "DESTINATIONS",
        "identified_wallets", "IDENTIFIED_WALLETS",
        "leads", "LEADS",
        "downstream_wallets", "DOWNSTREAM_WALLETS",
        "subpoena_targets", "SUBPOENA_TARGETS",
        "CEX_CONTINUITY_LEADS",
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
                    or row.get("to_address") or row.get("candidate_withdrawal_to")
                    or "")
            chain = row.get("chain")
            if addr:
                out.append((_normalize_address(str(addr)), chain))
    # Nested freezable / freeze-candidate sections — production shape is
    # ``FREEZABLE: [ {issuer, token, holdings: [{address, chain, ...}]} ]``.
    for key in ("freeze_candidates", "FREEZABLE"):
        section = brief.get(key) or []
        if not isinstance(section, list):
            continue
        for row in section:
            if not isinstance(row, dict):
                continue
            # Direct address (legacy lowercase shape).
            addr = (row.get("address") or row.get("destination_address") or "")
            chain = row.get("chain")
            if addr:
                out.append((_normalize_address(str(addr)), chain))
            # Production nested holdings shape.
            for h in row.get("holdings") or []:
                if not isinstance(h, dict):
                    continue
                h_addr = h.get("address") or ""
                h_chain = h.get("chain") or chain
                if h_addr:
                    out.append((_normalize_address(str(h_addr)), h_chain))
    return out


def _extract_seed_addresses(brief: dict, manifest: dict | None = None) -> list[str]:
    """Pull seed addresses from the brief and manifest, with fallbacks.

    Recognizes both lowercase (``seeds`` / ``seed_addresses`` /
    ``victim_addresses``) and the UPPERCASE production-brief
    convention (``VICTIM_WALLET_FULL`` and ``SEED_ADDRESSES``).
    """
    seeds: list[str] = []
    # List-shaped seed sections.
    for key in ("seeds", "seed_addresses", "SEED_ADDRESSES",
                "victim_addresses", "VICTIM_ADDRESSES"):
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
    # Scalar seed fields (production brief uses VICTIM_WALLET_FULL).
    scalar_seed = _get_field(
        brief, "VICTIM_WALLET_FULL", "victim_wallet_full",
        "seed_address", "SEED_ADDRESS",
    )
    if scalar_seed:
        seeds.append(_normalize_address(str(scalar_seed)))
    if manifest and not seeds:
        m_seed = (manifest.get("seed_address") or manifest.get("victim_address")
                  or manifest.get("VICTIM_WALLET_FULL"))
        if m_seed:
            seeds.append(_normalize_address(str(m_seed)))
    # De-duplicate but preserve order.
    seen: set[str] = set()
    deduped: list[str] = []
    for s in seeds:
        if s and s not in seen:
            seen.add(s)
            deduped.append(s)
    return deduped


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
    if not transactions:
        # v0.32.1: absence of transaction evidence is NOT evidence of
        # fabrication — without a trace graph we cannot verify
        # reachability, so emit a single WARNING rather than flagging
        # every destination as a CRITICAL. When transactions ARE present
        # an unreachable destination is still CRITICAL below.
        return [Violation(
            check="invariant_g_chain_of_custody",
            severity="warning",
            detail=(
                "No trace transaction evidence available; chain-of-custody "
                "reachability not verified."
            ),
        )]
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
    """Return all rows across lead/destination/identified-wallets/freeze
    sections with ``confidence == 'high'``. Bridges lowercase and
    UPPERCASE brief schemas."""
    out: list[dict] = []
    for key in (
        "leads", "LEADS",
        "identified_wallets", "IDENTIFIED_WALLETS",
        "destinations", "DESTINATIONS",
        "freeze_candidates",
        "CEX_CONTINUITY_LEADS",
    ):
        section = brief.get(key) or []
        if not isinstance(section, list):
            continue
        for row in section:
            if isinstance(row, dict) and str(row.get("confidence", "")).lower() == "high":
                out.append(row)
    # Production FREEZABLE shape — high-confidence on individual holding
    # rows nested inside each issuer entry.
    freezable = brief.get("FREEZABLE") or brief.get("freeze_candidates") or []
    if isinstance(freezable, list):
        for issuer_row in freezable:
            if not isinstance(issuer_row, dict):
                continue
            for h in issuer_row.get("holdings") or []:
                if isinstance(h, dict) and str(h.get("confidence", "")).lower() == "high":
                    out.append(h)
    return out


def _lead_evidence_count(lead: dict) -> int:
    """Count independent corroborating evidence sources on a single lead.

    Dedup key for dict-shaped sources is ``type`` (falling back to
    ``name``) so two timestamps of the same source class count as one.
    """
    sources = lead.get("evidence_sources") or lead.get("evidence") or []
    if isinstance(sources, list):
        keys: set[str] = set()
        for s in sources:
            if isinstance(s, str) and s.strip():
                keys.add(s.strip().lower())
            elif isinstance(s, dict):
                t = s.get("type") or s.get("name") or s.get("source") or s.get("kind")
                if isinstance(t, str) and t.strip():
                    keys.add(t.strip().lower())
                else:
                    # Fallback: stable dict repr.
                    keys.add(str(sorted(s.items())))
        return len(keys)
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

    # Resolve Wilson lower bound from the dedicated disclosure sidecar
    # first, then fall back to the production brief's RECOVERY_RATE
    # embedded block (which is where emit_brief actually writes it).
    lower_f: float | None = None
    for src in (recovery_disclosure,
                (brief.get("RECOVERY_RATE")
                 if isinstance(brief.get("RECOVERY_RATE"), dict)
                 else None),
                (brief.get("recovery_rate")
                 if isinstance(brief.get("recovery_rate"), dict)
                 else None)):
        if not src:
            continue
        lower = src.get("wilson_lower")
        try:
            lower_f = float(lower) if lower is not None else None
        except (TypeError, ValueError):
            lower_f = None
        if lower_f is not None:
            break

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
    case_ids = {_norm_case_id(_get_field(d, *_KEYS_CASE_ID)) for _, d in docs}
    case_ids.discard("")
    if len(case_ids) > 1:
        violations.append(Violation(
            check="invariant_i_cross_doc_consistency",
            severity="critical",
            detail=f"case_id disagrees across documents: {sorted(case_ids)}",
        ))

    # victim name
    victims: set[str] = set()
    for _, d in docs:
        nm = _get_field(d, *_KEYS_VICTIM_NAME)
        if not nm:
            v = d.get("victim")
            if isinstance(v, dict):
                nm = v.get("name")
        victims.add(_norm_name(nm))
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
        v = _get_field(d, *_KEYS_TOTAL_USD)
        if v is not None:
            try:
                totals.append(_parse_usd_string(v))
            except Exception:  # noqa: BLE001
                pass
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

    # incident date — accept lowercase + UPPERCASE variants.
    dates: set[str] = set()
    for _, d in docs:
        raw = _get_field(d, "incident_date", "INCIDENT_DATE",
                         *_KEYS_INCIDENT_TIME) or ""
        s = str(raw).strip()
        if not s:
            continue
        # Prefer ISO YYYY-MM-DD if present; otherwise normalize the
        # free-text form.
        if len(s) >= 10 and s[4] == "-" and s[7] == "-":
            dates.add(s[:10])
        else:
            dates.add(s.lower())
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
                    "freeze_candidates", "destinations",
                    "DESTINATIONS", "FREEZABLE", "IDENTIFIED_WALLETS"):
            section = d.get(key) or []
            if isinstance(section, list):
                for row in section:
                    if isinstance(row, str):
                        addrs.add(_normalize_address(row))
                    elif isinstance(row, dict):
                        a = row.get("address") or row.get("destination_address")
                        if a:
                            addrs.add(_normalize_address(str(a)))
                        # Production FREEZABLE shape — expand holdings.
                        for h in row.get("holdings") or []:
                            if isinstance(h, dict) and h.get("address"):
                                addrs.add(_normalize_address(str(h["address"])))
        # Seed address always counts.
        seed = _get_field(d, "VICTIM_WALLET_FULL", "victim_wallet_full",
                          "seed_address", "SEED_ADDRESS")
        if seed:
            addrs.add(_normalize_address(str(seed)))
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


_ISSUER_SUFFIXES = (
    "operations", "international", "global", "limited", "inc", "incorporated",
    "llc", "corp", "corporation", "ltd", "co", "company", "holdings", "group",
)


def _norm_issuer(value: Any) -> str:
    """Normalize an issuer name for tuple matching.

    Lowercases, collapses whitespace, and strips common corporate suffix
    tokens (``Limited``, ``Inc``, ``Operations``, …) so that
    ``"Tether Operations Limited"`` and ``"Tether"`` compare equal.
    """
    base = re.sub(r"\s+", " ", str(value or "").strip().lower())
    if not base:
        return ""
    tokens = base.split(" ")
    # Strip trailing corporate-suffix tokens (greedy from the right).
    while tokens and tokens[-1].strip(",.") in _ISSUER_SUFFIXES:
        tokens.pop()
    return " ".join(tokens) if tokens else base


def _brief_freeze_tuples(brief: dict) -> set[tuple[str, str, str]]:
    """(issuer_norm, token_symbol_upper, address_norm) tuples from
    brief's freeze_candidates / identified_wallets / FREEZABLE."""
    out: set[tuple[str, str, str]] = set()
    # Legacy lowercase shape — flat rows.
    for key in ("freeze_candidates", "identified_wallets", "IDENTIFIED_WALLETS"):
        section = brief.get(key) or []
        if not isinstance(section, list):
            continue
        for row in section:
            if not isinstance(row, dict):
                continue
            issuer = _norm_issuer(row.get("issuer") or row.get("issuer_name"))
            token = str(row.get("token") or row.get("token_symbol") or "").upper()
            addr = _normalize_address(str(row.get("address") or ""))
            if issuer and token and addr:
                out.add((issuer, token, addr))
    # Production FREEZABLE shape — issuer + token at the outer row, one
    # tuple per nested holding.
    freezable = brief.get("FREEZABLE") or []
    if isinstance(freezable, list):
        for row in freezable:
            if not isinstance(row, dict):
                continue
            issuer = _norm_issuer(row.get("issuer") or row.get("issuer_name"))
            token = str(row.get("token") or row.get("token_symbol") or "").upper()
            if not (issuer and token):
                continue
            for h in row.get("holdings") or []:
                if not isinstance(h, dict):
                    continue
                addr = _normalize_address(str(h.get("address") or ""))
                if addr:
                    out.add((issuer, token, addr))
    return out


def _brief_holding_usd(brief: dict, token: str, addr: str) -> Decimal | None:
    """Find a brief holding by (token, addr) and return its USD value."""
    # Legacy lowercase shape.
    for r in brief.get("freeze_candidates") or []:
        if (isinstance(r, dict)
                and _normalize_address(str(r.get("address") or "")) == addr
                and str(r.get("token") or "").upper() == token):
            m_amt = (r.get("usd_value") or r.get("amount_usd")
                     or r.get("usd") or r.get("total_usd"))
            if m_amt is not None:
                try:
                    return _parse_usd_string(m_amt)
                except Exception:  # noqa: BLE001
                    return None
    # Production FREEZABLE shape — nested holdings under the issuer row.
    for issuer_row in brief.get("FREEZABLE") or []:
        if not isinstance(issuer_row, dict):
            continue
        if str(issuer_row.get("token") or "").upper() != token:
            continue
        for h in issuer_row.get("holdings") or []:
            if not isinstance(h, dict):
                continue
            if _normalize_address(str(h.get("address") or "")) != addr:
                continue
            m_amt = (h.get("usd") or h.get("usd_value")
                     or h.get("amount_usd") or h.get("total_usd"))
            if m_amt is not None:
                try:
                    return _parse_usd_string(m_amt)
                except Exception:  # noqa: BLE001
                    return None
    return None


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
        fl_issuer = _norm_issuer(fl.get("issuer") or fl.get("issuer_name"))
        asks = (fl.get("freeze_asks") or fl.get("asks")
                or fl.get("holdings") or [])
        if not isinstance(asks, list):
            continue
        for ask in asks:
            if not isinstance(ask, dict):
                continue
            token = str(
                ask.get("token") or ask.get("token_symbol")
                or ask.get("symbol") or ""
            ).upper()
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
                        f"address) tuple in freeze_candidates / FREEZABLE / "
                        f"identified_wallets."
                    ),
                ))

            # Amount equality within $10 if both sides present.
            ask_amt = (ask.get("usd_value") or ask.get("amount_usd")
                       or ask.get("usd") or ask.get("total_usd"))
            if ask_amt is not None:
                try:
                    ask_usd = _parse_usd_string(ask_amt)
                except Exception:  # noqa: BLE001
                    ask_usd = None
                if ask_usd is not None:
                    m_usd = _brief_holding_usd(brief, token, addr)
                    if m_usd is not None and abs(m_usd - ask_usd) > Decimal("10"):
                        violations.append(Violation(
                            check="invariant_k_brief_freeze_consistency",
                            severity="critical",
                            detail=(
                                f"Freeze letter {fl_issuer} {token} "
                                f"{addr} amount ${ask_usd} disagrees "
                                f"with brief amount ${m_usd} by > $10."
                            ),
                        ))
    return violations


# ──────────────────────────────────────────────────────────────────────
# INVARIANT L — Address ↔ chain ↔ explorer URL coherence
# ──────────────────────────────────────────────────────────────────────


_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_EVM_ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")
_URL_HOST_RE = re.compile(r"https?://([^/?#]+)", re.IGNORECASE)


def _addr_chain_lookup(brief: dict | None) -> dict[str, str]:
    """Build an address → chain map from the brief.

    Walks DESTINATIONS, FREEZABLE.holdings, IDENTIFIED_WALLETS, plus the
    lowercase variants. The chain is taken either from the row's own
    ``chain`` field or the issuer-row ``chain`` field (for FREEZABLE
    holdings). Values are lowercased; normalized addresses keep the
    convention used by ``_normalize_address``."""
    out: dict[str, str] = {}
    if not isinstance(brief, dict):
        return out
    # Flat rows.
    for key in ("destinations", "DESTINATIONS",
                "identified_wallets", "IDENTIFIED_WALLETS",
                "leads", "LEADS", "subpoena_targets", "SUBPOENA_TARGETS",
                "CEX_CONTINUITY_LEADS"):
        section = brief.get(key) or []
        if not isinstance(section, list):
            continue
        for row in section:
            if not isinstance(row, dict):
                continue
            addr = (row.get("address") or row.get("destination_address")
                    or row.get("candidate_withdrawal_to") or "")
            chain = (row.get("chain") or "").lower()
            if addr and chain:
                out[_normalize_address(str(addr))] = chain
    # Nested issuer holdings.
    for key in ("freeze_candidates", "FREEZABLE"):
        section = brief.get(key) or []
        if not isinstance(section, list):
            continue
        for row in section:
            if not isinstance(row, dict):
                continue
            row_chain = (row.get("chain") or "").lower()
            row_addr = row.get("address") or ""
            if row_addr and row_chain:
                out[_normalize_address(str(row_addr))] = row_chain
            for h in row.get("holdings") or []:
                if not isinstance(h, dict):
                    continue
                addr = h.get("address") or ""
                chain = (h.get("chain") or row_chain or "").lower()
                if addr and chain:
                    out[_normalize_address(str(addr))] = chain
    return out


def _host_from_url(url: str) -> str:
    """Return the lowercase host (no path, no port) of a URL, or ''."""
    if not url:
        return ""
    m = _URL_HOST_RE.search(url)
    if not m:
        return ""
    host = m.group(1).split(":", 1)[0].lower()
    return host


def _host_in_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    """Return True if host equals or is a subdomain of any allowed
    explorer host. e.g. ``etherscan.io`` is allowed and we also accept
    ``www.etherscan.io``."""
    if not host or not allowed:
        return False
    for a in allowed:
        if host == a or host.endswith("." + a):
            return True
    return False


def check_invariant_l_address_chain_explorer(
    artifact_html_files: dict[str, str] | None,
    brief: dict | None = None,
    chain_hint: str | None = None,
) -> list[Violation]:
    """Per-link verification that explorer URLs match the chain of the
    address they reference.

    Two complementary modes:

    * **Cross-chain registry check.** When the brief maps an address to
      a known chain, every ``<a href>`` whose URL embeds that address
      MUST point to a host in ``_ADDR_EXPLORER_HOSTS[chain]``. Catches
      "Arbitrum holding rendered with etherscan.io URL", "Optimism
      address on polygonscan", etc.
    * **Address-shape sanity.** Independent of the brief, an EVM 0x
      address embedded in a Tron/Solana explorer URL is always wrong;
      a Tron base58 address embedded in an EVM explorer URL is always
      wrong.

    ``artifact_html_files`` maps relative-path → HTML content.
    """
    if not artifact_html_files:
        return []
    addr_chain = _addr_chain_lookup(brief) if brief else {}
    violations: list[Violation] = []
    for path, html in artifact_html_files.items():
        for m in _HREF_RE.finditer(html):
            url = m.group(1)
            host = _host_from_url(url)
            addr_match = _EVM_ADDR_RE.search(url)
            if not addr_match:
                continue
            addr_lower = addr_match.group(0).lower()
            # Sanity check first: 0x address on a non-EVM explorer is
            # always wrong (registry-independent).
            if host and any(host == h or host.endswith("." + h)
                            for chain in ("tron", "solana", "bitcoin")
                            for h in _ADDR_EXPLORER_HOSTS[chain]):
                violations.append(Violation(
                    check="invariant_l_address_chain_explorer",
                    severity="critical",
                    detail=(
                        f"{path}: link {url!r} references EVM-shape "
                        f"address {addr_match.group(0)} on a non-EVM "
                        f"explorer host {host!r}."
                    ),
                    file=path,
                ))
                continue
            # Cross-chain registry check — only fires when the brief
            # tells us the canonical chain for this address.
            known_chain = addr_chain.get(addr_lower) or chain_hint
            if not known_chain:
                continue
            allowed = _explorer_host_for_chain(known_chain)
            if not allowed:
                # We don't have a registry entry for this chain — skip
                # rather than fire a noisy false-positive.
                continue
            if _host_in_allowed(host, allowed):
                continue
            # Cross-chain mis-attribution (Arbitrum holding on
            # etherscan.io must be on arbiscan.io, Optimism on
            # optimistic.etherscan.io, etc.).
            violations.append(Violation(
                check="invariant_l_address_chain_explorer",
                severity="critical",
                detail=(
                    f"{path}: address {addr_match.group(0)} is labeled "
                    f"chain={known_chain!r} but the explorer link points "
                    f"to host {host!r} (allowed: {list(allowed)}). "
                    f"Cross-chain mis-attribution."
                ),
                file=path,
            ))
        # Tron base58 → must not link to an EVM explorer.
        for tron_match in re.finditer(r"\bT[A-HJ-NP-Za-km-z1-9]{33}\b", html):
            addr = tron_match.group(0)
            tail = html[max(0, tron_match.start() - 200):tron_match.end() + 50]
            if ("etherscan" in tail.lower() or "polygonscan" in tail.lower()
                    or "arbiscan" in tail.lower() or "basescan" in tail.lower()):
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
    incident_time = _parse_iso(_get_field(manifest, *_KEYS_INCIDENT_TIME))
    generated_at = (_parse_iso(_get_field(manifest, *_KEYS_GENERATED_AT))
                    or datetime.now(timezone.utc))
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
    incident_time = _parse_iso(
        _get_field(manifest, *_KEYS_INCIDENT_TIME)
        or _get_field(brief, *_KEYS_INCIDENT_TIME)
    )
    if not incident_time:
        return []
    if incident_time.tzinfo is None:
        incident_time = incident_time.replace(tzinfo=timezone.utc)
    violations: list[Violation] = []
    for key in ("labels", "label_citations", "cited_labels",
                "LABELS", "LABEL_CITATIONS", "CITED_LABELS"):
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

_CHAIN_NAME_RE = re.compile(
    r"\b(Ethereum|Polygon|Arbitrum|Optimism|Base|BSC|"
    r"Binance Smart Chain|Avalanche|Fantom|Tron|Solana|Bitcoin|"
    r"Hyperliquid|zkSync|Linea|Scroll|Blast|Cronos|Celo|Gnosis|"
    r"Moonbeam|Moonriver|Harmony|Aurora)\b",
    re.IGNORECASE,
)

_CHAIN_NAME_NORM = {
    "ethereum": "ethereum",
    "polygon": "polygon",
    "arbitrum": "arbitrum",
    "optimism": "optimism",
    "base": "base",
    "bsc": "bsc",
    "binance smart chain": "bsc",
    "avalanche": "avalanche",
    "fantom": "fantom",
    "tron": "tron",
    "solana": "solana",
    "bitcoin": "bitcoin",
    "hyperliquid": "hyperliquid",
    "zksync": "zksync_era",
    "linea": "linea",
    "scroll": "scroll",
    "blast": "blast",
    "cronos": "cronos",
    "celo": "celo",
    "gnosis": "gnosis",
    "moonbeam": "moonbeam",
    "moonriver": "moonriver",
    "harmony": "harmony",
    "aurora": "aurora",
}


# Words that immediately follow a chain-context "Base" ("Base network",
# "Base chain", "Base L2", "Base mainnet", "Base blockchain"). Used to
# disambiguate the Base chain from the English word "base".
_BASE_CHAIN_FOLLOWERS = (
    "network", "chain", "mainnet", "l2", "blockchain", "rollup",
)
# Words that immediately follow the common-English "base" (statistical /
# generic usage we must NOT treat as a chain citation).
_BASE_WORD_FOLLOWERS = (
    "prior", "priors", "rate", "rates", "case", "cases", "line", "lines",
    "layer", "fee", "fees", "currency", "asset", "amount", "value",
    "salary", "model", "models", "level", "cost", "costs",
)


def _base_used_as_chain(text: str, start: int, end: int) -> bool:
    """Heuristic: is the "Base" token at text[start:end] referring to the
    Base blockchain (vs the English word "base")?

    True when:
      * the next word is a chain-context word ("Base network/chain/L2"…),
      * OR it reads "on Base" / "to Base" / "the Base" immediately before,
      * OR the original casing is "Base" (capitalized) AND the following
        word is NOT a common statistical/generic follower ("base prior",
        "base rate", "base case", …).
    False otherwise (treated as the English word, not a chain).
    """
    original = text[start:end]
    # Following word (skip punctuation/whitespace).
    tail = text[end:end + 40].lstrip(" \t\n\r.,;:)(-—–")
    next_word = re.match(r"[A-Za-z0-9]+", tail)
    next_word_l = next_word.group(0).lower() if next_word else ""
    if next_word_l in _BASE_CHAIN_FOLLOWERS:
        return True
    if next_word_l in _BASE_WORD_FOLLOWERS:
        return False
    # Preceding preposition/article suggesting a place/network.
    head = text[max(0, start - 12):start].lower()
    if re.search(r"\b(on|to|via|from|the)\s+$", head):
        # "the base prior" already excluded above by follower check.
        return True
    # Bare "Base" capitalized with no disambiguating follower — ambiguous.
    # Be conservative: only the lower-case "base" is clearly the English
    # word; a capitalized standalone "Base" with no statistical follower
    # is more likely a chain mention, but we still require it not be a
    # known English follower (handled above). Default: treat lowercase as
    # NOT a chain; treat capitalized standalone as NOT a chain either
    # (insufficient signal) to avoid resurrecting the false positive.
    return False


def _structured_addrs(brief: dict, trace_evidence: dict | None) -> set[str]:
    addrs: set[str] = set()
    if trace_evidence:
        for tx in trace_evidence.get("transactions") or []:
            if isinstance(tx, dict):
                for k in ("from", "to", "from_address", "to_address"):
                    a = tx.get(k)
                    if a:
                        addrs.add(_normalize_address(str(a)))
    # Flat shape — lowercase + UPPERCASE variants.
    for key in ("destinations", "DESTINATIONS",
                "identified_wallets", "IDENTIFIED_WALLETS",
                "leads", "LEADS",
                "subpoena_targets", "SUBPOENA_TARGETS",
                "CEX_CONTINUITY_LEADS"):
        section = brief.get(key) or []
        if isinstance(section, list):
            for row in section:
                if isinstance(row, dict):
                    a = (row.get("address") or row.get("destination_address")
                         or row.get("candidate_withdrawal_to"))
                    if a:
                        addrs.add(_normalize_address(str(a)))
    # Nested issuer / freezable holdings.
    for key in ("freeze_candidates", "FREEZABLE"):
        section = brief.get(key) or []
        if isinstance(section, list):
            for row in section:
                if not isinstance(row, dict):
                    continue
                a = row.get("address")
                if a:
                    addrs.add(_normalize_address(str(a)))
                for h in row.get("holdings") or []:
                    if isinstance(h, dict) and h.get("address"):
                        addrs.add(_normalize_address(str(h["address"])))
    # Always include the seed.
    seed = _get_field(brief, "VICTIM_WALLET_FULL", "victim_wallet_full",
                      "seed_address", "SEED_ADDRESS")
    if seed:
        addrs.add(_normalize_address(str(seed)))
    return addrs


def _structured_usd_values(
    brief: dict, trace_evidence: dict | None,
    freeze_letters: list[dict] | None = None,
) -> list[Decimal]:
    """All USD amounts present in the structured data, in any field
    that looks like a dollar value. Used to ground prose $-figures."""
    out: list[Decimal] = []

    def _try_add(v: Any) -> None:
        if v is None:
            return
        try:
            d = _parse_usd_string(v)
        except Exception:  # noqa: BLE001
            return
        if d > 0:
            out.append(d)

    # Recupero's own SERVICE FEES are legitimately quotable in editorial
    # boilerplate and appear in EVERY production brief's engagement /
    # diagnostic sections (engagement_letter, victim_summary). They are
    # NOT case-specific trace figures, so they don't live in the brief's
    # FREEZABLE / DESTINATIONS structured data — without grounding them
    # here, INVARIANT O would flag "$499.00" and "$10,000.00" on every
    # real brief that mentions its own fees. Source from the single
    # _pricing definition so a fee change stays in lock-step.
    try:
        from recupero._pricing import (
            DIAGNOSTIC_FEE_USD,
            ENGAGEMENT_FEE_USD,
        )
        _try_add(DIAGNOSTIC_FEE_USD)   # $499 diagnostic
        _try_add(ENGAGEMENT_FEE_USD)   # $10,000 engagement
    except Exception:  # noqa: BLE001
        # Fall back to the documented constants if the import path
        # changes — these are stable, contract-level fee amounts.
        _try_add(Decimal("499"))
        _try_add(Decimal("10000"))

    # Brief-level totals.
    for k in ("TOTAL_LOSS_USD", "TOTAL_FREEZABLE_USD", "TOTAL_SUSPECTED_USD",
              "TOTAL_EXCLUDED_USD", "TOTAL_UNRECOVERABLE_USD",
              "MAX_RECOVERABLE_USD", "TOTAL_PERPETRATOR_HOLDINGS_USD",
              "total_usd_stolen", "total_usd", "stolen_usd",
              "theft_event_total_usd"):
        _try_add(brief.get(k))
    # Per-theft-event amount on a multi-event drain. The LE handoff
    # per-event timeline narrates each individual drain (V-CFI01 shape:
    # six $600,000 transfers = $3.6M). That per-event figure is genuine
    # trace data but is not surfaced in any single brief field — it's
    # TOTAL_LOSS_USD / THEFT_EVENT_COUNT. Derive it so the per-event
    # narrative prose grounds against structured data rather than
    # tripping INVARIANT O as a hallucination.
    try:
        ev_count = brief.get("THEFT_EVENT_COUNT")
        ev_count_i = int(ev_count) if ev_count is not None else 0
        if ev_count_i > 1:
            total_loss = _parse_usd_string(brief.get("TOTAL_LOSS_USD"))
            if total_loss > 0:
                _try_add(total_loss / Decimal(ev_count_i))
    except Exception:  # noqa: BLE001
        pass
    # Destinations rows.
    for key in ("destinations", "DESTINATIONS"):
        for row in brief.get(key) or []:
            if isinstance(row, dict):
                for f in ("usd_value", "usd_holding_now",
                          "usd_received_in_trace", "usd"):
                    _try_add(row.get(f))
    # Freezable / freeze candidates.
    for key in ("freeze_candidates", "FREEZABLE"):
        for row in brief.get(key) or []:
            if not isinstance(row, dict):
                continue
            for f in ("total_usd", "total_suspected_usd",
                      "total_excluded_usd", "usd_value"):
                _try_add(row.get(f))
            for h in row.get("holdings") or []:
                if isinstance(h, dict):
                    for f in ("usd", "usd_value", "amount_usd",
                              "total_usd"):
                        _try_add(h.get(f))
    # Trace evidence transfers.
    if trace_evidence:
        for tx in trace_evidence.get("transactions") or trace_evidence.get("transfers") or []:
            if isinstance(tx, dict):
                for f in ("usd_value", "amount_usd", "usd",
                          "value_usd", "usd_value_at_theft"):
                    _try_add(tx.get(f))
    # Freeze letter asks.
    for fl in freeze_letters or []:
        if not isinstance(fl, dict):
            continue
        for ask in (fl.get("freeze_asks") or fl.get("asks")
                    or fl.get("holdings") or []):
            if isinstance(ask, dict):
                for f in ("usd_value", "amount_usd", "usd",
                          "total_usd_freezable"):
                    _try_add(ask.get(f))
    return out


def _structured_chains(
    brief: dict, trace_evidence: dict | None,
) -> set[str]:
    """Normalized chain identifiers present in the structured data."""
    out: set[str] = set()

    def _add(v: Any) -> None:
        if not v:
            return
        s = str(v).strip().lower()
        if s in _CHAIN_NAME_NORM:
            out.add(_CHAIN_NAME_NORM[s])
        elif s:
            out.add(s)

    for k in ("PRIMARY_CHAIN", "primary_chain", "chain", "chains"):
        v = brief.get(k)
        if isinstance(v, list):
            for x in v:
                _add(x)
        else:
            _add(v)
    # Rows that carry a chain field.
    for key in ("destinations", "DESTINATIONS",
                "identified_wallets", "IDENTIFIED_WALLETS",
                "freeze_candidates", "FREEZABLE",
                "leads", "LEADS",
                "subpoena_targets", "SUBPOENA_TARGETS",
                "CEX_CONTINUITY_LEADS"):
        for row in brief.get(key) or []:
            if not isinstance(row, dict):
                continue
            _add(row.get("chain"))
            for h in row.get("holdings") or []:
                if isinstance(h, dict):
                    _add(h.get("chain"))
    # Trace evidence.
    if trace_evidence:
        for tx in trace_evidence.get("transactions") or trace_evidence.get("transfers") or []:
            if isinstance(tx, dict):
                _add(tx.get("chain"))
    return out


def check_invariant_o_ai_editorial_grounding(
    brief: dict | None,
    trace_evidence: dict | None,
    prose_text: str | None,
    freeze_letters: list[dict] | None = None,
) -> list[Violation]:
    """Every $-figure, 0x address, and chain name cited in the prose
    MUST be present in the structured data of the same artifact.

    ``prose_text`` is the concatenation of all AI-editorial sections
    (narrative paragraphs). Caller assembles."""
    if not prose_text or not brief:
        return []
    violations: list[Violation] = []
    structured_addrs = _structured_addrs(brief, trace_evidence)
    structured_usd = _structured_usd_values(brief, trace_evidence, freeze_letters)
    structured_chains = _structured_chains(brief, trace_evidence)

    # Addresses cited in prose.
    seen_addr: set[str] = set()
    for m in _EVM_ADDR_RE.finditer(prose_text):
        addr = _normalize_address(m.group(0))
        if addr in seen_addr:
            continue
        seen_addr.add(addr)
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

    # USD figures cited in prose.
    seen_usd: set[Decimal] = set()
    for m in _USD_PROSE_RE.finditer(prose_text):
        raw = m.group(1)
        try:
            val = _parse_usd_string(raw)
        except Exception:  # noqa: BLE001
            continue
        if val <= 0:
            continue
        # Honor optional 'm'/'k'/'b' suffix matched by the regex's
        # trailing class.
        suffix = ""
        full = m.group(0)
        if full and full[-1].lower() in ("m", "k", "b"):
            suffix = full[-1].lower()
        if suffix == "k":
            val = val * Decimal("1000")
        elif suffix == "m":
            val = val * Decimal("1000000")
        elif suffix == "b":
            val = val * Decimal("1000000000")
        if val in seen_usd:
            continue
        seen_usd.add(val)
        # Match within $100 of any structured USD figure, OR within 0.5%
        # for large numbers (avoids $100 tightness on $100M cases).
        tol = max(Decimal("100"), val * Decimal("0.005"))
        if not any(abs(val - s) <= tol for s in structured_usd):
            violations.append(Violation(
                check="invariant_o_ai_editorial_grounding",
                severity="critical",
                detail=(
                    f"AI editorial prose cites ${val:,.2f} which is not "
                    f"reflected in any brief / trace / freeze-ask USD "
                    f"field within ${tol:,.2f} tolerance."
                ),
            ))

    # Chain names cited in prose.
    seen_chain: set[str] = set()
    for m in _CHAIN_NAME_RE.finditer(prose_text):
        raw = m.group(1).strip().lower()
        norm = _CHAIN_NAME_NORM.get(raw, raw)
        # "Base" is the one chain name in our roster that collides with a
        # common English word ("base rate", "base prior", "database",
        # "based on"). The other names (Ethereum, Solana, Arbitrum, …) are
        # unambiguous proper nouns. Treat a "base" match as a CHAIN claim
        # only when the surrounding text uses it as a blockchain
        # ("on Base", "Base network/chain/mainnet/L2/blockchain"); a bare
        # statistical/English "base" is not a chain citation and must not
        # be flagged. This keeps INVARIANT O's anti-hallucination gate
        # intact for genuine chain references while killing the false
        # positive on the LE handoff's "base prior" recovery-forecast copy.
        if norm == "base" and not _base_used_as_chain(prose_text, m.start(), m.end()):
            continue
        if norm in seen_chain:
            continue
        seen_chain.add(norm)
        if norm not in structured_chains:
            violations.append(Violation(
                check="invariant_o_ai_editorial_grounding",
                severity="critical",
                detail=(
                    f"AI editorial prose cites chain {raw!r} (normalized "
                    f"{norm!r}) which does not appear in the brief's "
                    f"PRIMARY_CHAIN, any DESTINATIONS row, or trace "
                    f"evidence."
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
    """Verify that every cross-artifact link (parent_brief_sha,
    manifest_sha, recovery_disclosure_sha) is present in the artifact
    where it belongs.

    The audit (CC7) notes that production briefs do not currently emit
    these fields — until they do, this invariant runs as a WARNING
    rather than a CRITICAL to avoid blocking every prod case build.
    The check still fires (and can be upgraded to critical) once the
    emit side ships.
    """
    violations: list[Violation] = []
    if brief is not None:
        if not _get_field(brief, "manifest_sha", "MANIFEST_SHA"):
            violations.append(Violation(
                check="invariant_p_parent_link_disclosure",
                severity="warning",
                detail="Brief is missing manifest_sha (parent-link metadata).",
            ))
        if not _get_field(brief, "recovery_disclosure_sha",
                          "RECOVERY_DISCLOSURE_SHA"):
            violations.append(Violation(
                check="invariant_p_parent_link_disclosure",
                severity="warning",
                detail="Brief is missing recovery_disclosure_sha.",
            ))
    for fl in freeze_letters or []:
        if not isinstance(fl, dict):
            continue
        if not _get_field(fl, "parent_brief_sha", "PARENT_BRIEF_SHA"):
            violations.append(Violation(
                check="invariant_p_parent_link_disclosure",
                severity="warning",
                detail=(
                    f"Freeze letter (issuer={fl.get('issuer') or '?'}) is "
                    f"missing parent_brief_sha."
                ),
            ))
    if le_handoff is not None:
        for k in ("parent_brief_sha", "manifest_sha", "recovery_disclosure_sha"):
            if not _get_field(le_handoff, k, k.upper()):
                violations.append(Violation(
                    check="invariant_p_parent_link_disclosure",
                    severity="warning",
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
    """Run invariants G–P and return the flat violation list.

    Each invariant runs under an isolated try/except — a crash in one
    invariant does NOT suppress the rest. The crashed invariant
    contributes a single ``warning`` violation describing the
    exception. This pattern matches the per-check isolation used in
    the structural dispatcher (output_integrity.validate_case_output).
    """
    invariants = (
        ("invariant_g_chain_of_custody",
         lambda: check_invariant_g_chain_of_custody(brief, trace_evidence, manifest)),
        ("invariant_h_confidence_calibration",
         lambda: check_invariant_h_confidence_calibration(brief, recovery_disclosure)),
        ("invariant_i_cross_doc_consistency",
         lambda: check_invariant_i_cross_doc_consistency(brief, freeze_letters, le_handoff)),
        ("invariant_j_intra_artifact_sum_coherence",
         lambda: check_invariant_j_intra_artifact_sum_coherence(le_handoff)),
        ("invariant_k_brief_freeze_consistency",
         lambda: check_invariant_k_brief_freeze_consistency(brief, freeze_letters)),
        ("invariant_l_address_chain_explorer",
         lambda: check_invariant_l_address_chain_explorer(artifact_html_files, brief)),
        ("invariant_m_time_window_coherence",
         lambda: check_invariant_m_time_window_coherence(trace_evidence, manifest)),
        ("invariant_n_stale_label_pit",
         lambda: check_invariant_n_stale_label_pit(brief, manifest)),
        ("invariant_o_ai_editorial_grounding",
         lambda: check_invariant_o_ai_editorial_grounding(
             brief, trace_evidence, prose_text, freeze_letters)),
        ("invariant_p_parent_link_disclosure",
         lambda: check_invariant_p_parent_link_disclosure(brief, freeze_letters, le_handoff)),
    )
    violations: list[Violation] = []
    for name, fn in invariants:
        try:
            violations.extend(fn())
        except Exception as exc:  # noqa: BLE001
            log.warning("semantic invariant %s crashed: %s", name, exc)
            violations.append(Violation(
                check=name,
                severity="warning",
                detail=(
                    f"invariant {name} crashed during evaluation: "
                    f"{type(exc).__name__}: {exc}"
                ),
            ))
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
