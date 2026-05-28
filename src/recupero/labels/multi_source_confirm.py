"""Multi-source confirmation for high-impact label promotions.

JACOB_ADVERSARY_AUDIT_v032.md poisoning attacks P1-P4 showed that an
adversary can submit a fake "Binance Hot Wallet" tag to Tronscan (or
"SuperBridge" to DeFiLlama) for an EOA they control. Auto-ingest
picks it up at ``proposed_confidence='low'``. An operator under
review-queue fatigue promotes it. Now the seed file has an attacker
EOA labeled as a CEX hot wallet (or a labeled "bridge" that swallows
the trace).

The downstream consequences are catastrophic:

* Freeze letter goes to Binance for funds Binance never custodied.
* Trace BFS terminates at attacker EOA labeled as "bridge", losing
  the actual destination.

Defense (M-1 in the audit's mitigation list): **for HIGH-IMPACT
categories, do not promote a label unless at least two INDEPENDENT
upstream sources agree on the (category, name) tuple.** Independence
is defined by upstream-domain: Tronscan + Solscan don't count as
independent (both are operator-editable public tags from the same
"trust me bro" tier); but DeFiLlama + Etherscan-contract-source do
count as independent (one is a community submission, one is an
on-chain ContractName field).

This module is **read-only**: it does not write to the seed files
and does not mutate auto-ingest state. It exposes a pure decision
function that the promote-endpoint can call BEFORE writing the seed.
The caller is responsible for fetching the other sources' candidate
records and passing them in. (We intentionally don't fetch here so
this module stays trivially testable.)
"""

from __future__ import annotations

from dataclasses import dataclass, field


#: Categories whose mislabeling causes operationally-catastrophic
#: outcomes (wrong-entity freeze letter, swallowed trace). All other
#: categories (dex_pool, lp_token, defi_protocol, etc.) can be
#: single-source-promoted because their mislabeling only loses signal,
#: not direction.
HIGH_IMPACT_CATEGORIES: frozenset[str] = frozenset({
    "exchange_hot_wallet",
    "exchange_deposit",
    "mixer",
    "sanctioned",
    "ofac",
    "custodian",
    "bridge",
})


#: Source identifiers grouped into "trust tiers" for independence
#: scoring. Two sources are INDEPENDENT iff they come from different
#: tier-groups (a Tronscan tag and a Solscan tag are both
#: "operator-editable public tag" tier — same group, not independent).
#: The 'high_trust' tier is operator-curated upstream data
#: (DeFiLlama protocol registry, Etherscan ContractName field) where
#: the upstream review process IS load-bearing. The 'low_trust' tier
#: is public-tag scraping (Tronscan tag1/tag2/tag3, Solscan account
#: labels) where the upstream "review" is essentially captcha-only.
#: Manual operator additions go in the 'manual' tier and count as
#: high_trust BUT only after a code review (PR landing in the seed).
_SOURCE_TIER: dict[str, str] = {
    # high-trust tier: review process is meaningful upstream
    "defillama_new_protocol": "high_trust",
    "defillama_protocols": "high_trust",
    "defillama_cex": "high_trust",
    "etherscan_contract_source": "high_trust",
    "chainalysis_sanctions": "high_trust",
    "ofac_sdn_list": "high_trust",
    # low-trust tier: operator-editable public tags
    "tronscan_tag": "low_trust",
    "tronscan_bridges": "low_trust",
    "tronscan_exchanges": "low_trust",
    "solscan_tag": "low_trust",
    "solscan_account_label": "low_trust",
    "etherscan_public_tag": "low_trust",
    # manual: code-reviewed seed PRs (the historical baseline)
    "manual": "manual",
}


def _source_tier(source: str) -> str:
    """Resolve a source identifier to its trust tier.

    Unknown sources default to ``"low_trust"`` (fail-closed). A new
    source must be explicitly added to ``_SOURCE_TIER`` to be eligible
    for "independent corroboration" status — otherwise an attacker
    who can register a new upstream source can bootstrap their own
    "second source."
    """
    return _SOURCE_TIER.get(source, "low_trust")


@dataclass(frozen=True)
class ConfirmationResult:
    """Decision returned by :func:`confirm_via_secondary_sources`.

    Attributes:
        confidence: One of ``"high"`` (2+ independent sources agree),
            ``"medium"`` (1 corroborating source), or ``"low"`` (none).
            For HIGH-IMPACT categories on Tron the ONLY acceptable
            confidence is ``"high"``; the promote-endpoint must reject
            a ``"low"`` result.
        supporting_sources: The source identifiers that supported the
            label (deduplicated, sorted alphabetically for stable
            rendering in the brief).
        reason: Operator-readable one-liner explaining the decision.
            Used in the rejection error message AND in the audit log
            so a reviewer can see WHY a candidate was held.
        accepted: True iff the result clears the promote-gate for the
            category. False iff the operator must wait for more
            corroboration OR the candidate is rejected outright.
    """

    confidence: str
    supporting_sources: list[str] = field(default_factory=list)
    reason: str = ""
    accepted: bool = False


def requires_multi_source_confirm(label_proposal: dict) -> bool:
    """Return True iff the proposed category requires multi-source confirmation.

    ``label_proposal`` is a dict-shaped candidate record. We look at
    ``proposed_category`` first, falling back to ``category`` for
    callers that already use the seed-file field name.
    """
    if not isinstance(label_proposal, dict):
        return False
    category = (
        label_proposal.get("proposed_category")
        or label_proposal.get("category")
        or ""
    )
    if not isinstance(category, str):
        return False
    return category.strip().lower() in HIGH_IMPACT_CATEGORIES


def _normalize_name(name: str) -> str:
    """Normalize a label name for comparison across sources.

    Different sources spell the same entity slightly differently:
    Tronscan says "Binance Hot Wallet 12"; DeFiLlama says
    "Binance"; Etherscan says "Binance: Hot Wallet 12". We strip
    punctuation and lowercase + collapse whitespace so the equality
    check is meaningful. We intentionally do NOT do fuzzy / Levenshtein
    matching — that's the wrong abstraction here. Two sources that
    spell the entity differently SHOULD require operator review.
    """
    if not isinstance(name, str):
        return ""
    # Collapse all non-alphanumeric runs to a single space.
    out_chars: list[str] = []
    last_was_space = False
    for ch in name.lower():
        if ch.isalnum():
            out_chars.append(ch)
            last_was_space = False
        else:
            if not last_was_space:
                out_chars.append(" ")
                last_was_space = True
    return "".join(out_chars).strip()


def confirm_via_secondary_sources(
    address: str,
    claimed_category: str,
    claimed_name: str,
    sources_seen: list[str],
    chain: str,
) -> ConfirmationResult:
    """Verify 2+ independent sources support the same (category, name).

    Args:
        address: The candidate address. Used in the reason string but
            not in the trust decision itself.
        claimed_category: The category from the candidate being
            evaluated. Must be lowercase canonical (e.g. ``"bridge"``).
        claimed_name: The proposed display name. Used in the
            ``reason`` for operator context.
        sources_seen: All source identifiers that have proposed this
            ``(address, category, name)`` triple. May include the
            primary source plus 0+ corroborations. Duplicates allowed
            (we deduplicate internally).
        chain: The chain enum value as a string. Tron + HIGH-IMPACT
            unconditionally requires ``confidence == "high"`` — the
            Tronscan public-tag attack is the audit's top vector.

    Returns:
        :class:`ConfirmationResult` with the decision.

    Notes:
        * If ``claimed_category`` is NOT high-impact, the function
          returns ``accepted=True`` with ``confidence="medium"`` for
          a single source — the gate doesn't apply.
        * Independence is computed by trust tier (see
          ``_SOURCE_TIER``). Two ``low_trust`` sources do not satisfy
          the 2-source gate; one ``low_trust`` + one ``high_trust``
          does.
        * Tron + high-impact + only-low-trust-sources: rejected even
          with 5 low_trust sources (which is what the attack would
          produce — adversary spams Tronscan + Solscan + Etherscan
          public tag with the same fake label).
    """
    cat = (claimed_category or "").strip().lower()
    chain_norm = (chain or "").strip().lower()

    # Dedup and grade the sources.
    unique_sources = sorted({str(s).strip() for s in (sources_seen or []) if s})
    if not unique_sources:
        return ConfirmationResult(
            confidence="low",
            supporting_sources=[],
            reason="No sources provided.",
            accepted=False,
        )

    tiers_present = {_source_tier(s) for s in unique_sources}
    has_high_trust = "high_trust" in tiers_present or "manual" in tiers_present
    n_distinct_tiers = len(tiers_present)

    # ── Non-high-impact: 1 source is fine. ─────────────────────────────
    if cat not in HIGH_IMPACT_CATEGORIES:
        return ConfirmationResult(
            confidence="medium" if len(unique_sources) >= 2 else "low",
            supporting_sources=unique_sources,
            reason=(
                f"Category {cat!r} is not high-impact; single source "
                "sufficient."
            ),
            accepted=True,
        )

    # ── High-impact path ──────────────────────────────────────────────

    # Tron + high-impact + no high-trust source = ALWAYS reject.
    # This is the audit's primary attack: Tronscan tag1/2/3 says
    # "Binance Hot Wallet" on attacker EOA. Even if Solscan also
    # tagged it (different chain, but adversary can spam both),
    # both are low_trust tier — no real corroboration.
    if chain_norm == "tron" and not has_high_trust:
        return ConfirmationResult(
            confidence="low",
            supporting_sources=unique_sources,
            reason=(
                f"Tron + high-impact category {cat!r} requires at least "
                "one high-trust source (DeFiLlama / Etherscan-contract-source "
                "/ Chainalysis / OFAC). Only low-trust sources present: "
                f"{unique_sources}. Refusing — see "
                "JACOB_ADVERSARY_AUDIT_v032 poisoning attack P3."
            ),
            accepted=False,
        )

    # General gate: need >= 2 INDEPENDENT (distinct-tier) sources.
    if n_distinct_tiers >= 2:
        return ConfirmationResult(
            confidence="high",
            supporting_sources=unique_sources,
            reason=(
                f"2+ independent sources corroborate "
                f"({claimed_name!r} as {cat!r}): "
                f"{unique_sources}. Tiers: {sorted(tiers_present)}."
            ),
            accepted=True,
        )

    # Single tier, but might be >=2 sources within same tier
    # (e.g. two low_trust). We accept this only if the tier is
    # high_trust / manual — multiple high-trust sources is still
    # corroboration. Multiple low-trust sources is NOT.
    if has_high_trust and len(unique_sources) >= 2:
        return ConfirmationResult(
            confidence="high",
            supporting_sources=unique_sources,
            reason=(
                f"2+ high-trust sources corroborate ({claimed_name!r}): "
                f"{unique_sources}."
            ),
            accepted=True,
        )

    if has_high_trust:
        # Exactly one high-trust source, no other corroboration.
        return ConfirmationResult(
            confidence="medium",
            supporting_sources=unique_sources,
            reason=(
                f"Single high-trust source for high-impact category "
                f"{cat!r}: {unique_sources}. Need 1 more independent "
                "source before promote. Hold candidate."
            ),
            accepted=False,
        )

    # Only low-trust sources (non-Tron). Same fail-closed result.
    return ConfirmationResult(
        confidence="low",
        supporting_sources=unique_sources,
        reason=(
            f"High-impact category {cat!r} backed only by low-trust "
            f"sources: {unique_sources}. Need >= 1 high-trust source."
        ),
        accepted=False,
    )
