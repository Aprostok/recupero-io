"""Wire the (otherwise dormant) MistTrack attribution provider into the label
candidate review pipeline.

MistTrack (SlowMist) is paid by-address attribution -- its strongest coverage is
exactly recupero's #1 gap vs Chainalysis: Tron/USDT laundering routes and
scam/drainer/pig-butchering entity labels. The provider
(``labels/providers/misttrack.py``) resolves a single address to a LOW-confidence
``CandidateLabel`` and is INERT without ``MISTTRACK_API_KEY``. Until now it had
ZERO call sites -- a complete, correct provider that nothing invoked.

This module batches a target address list through the provider and persists the
results into the operator review queue (``public.label_candidates``,
``pending_review``). Two doctrines are enforced by construction:

  * **Never auto-promoted.** MistTrack is an EXTERNAL inference, not ground truth.
    Every row lands ``pending_review`` at ``low`` confidence (the CandidateLabel
    default); an operator upgrades it during promotion after their own
    verification. We never fabricate and never trust a third party as evidence.
  * **Inert without a key.** No ``MISTTRACK_API_KEY`` -> a complete no-op: zero
    network calls, zero DB writes, an ``EnrichmentResult(enabled=False, ...)``.

``limit`` caps the number of *paid* upstream queries (cost control), counted
BEFORE the per-address result is known.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class EnrichmentResult:
    """Outcome of a batch enrichment run (all counts are post-dedup)."""

    enabled: bool       # was a MistTrack key available?
    targets: int        # unique, non-empty input addresses considered
    queried: int        # addresses actually sent to the paid API (<= targets, <= limit)
    resolved: int       # addresses MistTrack returned a usable label for
    persisted: int      # NEW review-queue rows inserted (post (chain,address) dedup)

    def as_dict(self) -> dict:
        return asdict(self)


def _dedup_clean(addresses: list[str]) -> list[str]:
    """Unique, stripped, non-empty addresses preserving input order."""
    out: list[str] = []
    seen: set[str] = set()
    for addr in addresses or []:
        if not isinstance(addr, str):
            continue
        norm = addr.strip()
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def _has_key(api_key: str | None) -> bool:
    """True iff an explicit key was passed OR MISTTRACK_API_KEY is set."""
    if api_key and api_key.strip():
        return True
    from recupero.labels.providers.misttrack import misttrack_enabled
    return misttrack_enabled()


def resolve_targets(
    addresses: list[str],
    *,
    chain: str = "ethereum",
    api_key: str | None = None,
    http_client=None,
    limit: int | None = None,
) -> list:
    """Resolve a batch of addresses to MistTrack ``CandidateLabel`` objects.

    Deduplicates input; stops after ``limit`` PAID queries (not results). Returns
    an empty list (and makes no network call) when no key is available. Never
    raises -- the underlying provider swallows all per-address failures to None.
    """
    if not _has_key(api_key):
        return []
    from recupero.labels.providers.misttrack import resolve_attribution

    out: list = []
    # ``queried`` is the 0-based index = number of paid queries already made;
    # break once it reaches ``limit`` so we send exactly ``limit`` queries.
    for queried, addr in enumerate(_dedup_clean(addresses)):
        if limit is not None and queried >= limit:
            break
        cand = resolve_attribution(
            addr, chain=chain, api_key=api_key, http_client=http_client,
        )
        if cand is not None:
            out.append(cand)
    return out


def run_misttrack_enrichment(
    addresses: list[str],
    *,
    chain: str = "ethereum",
    api_key: str | None = None,
    http_client=None,
    dsn: str | None = None,
    limit: int | None = None,
) -> EnrichmentResult:
    """Enrich ``addresses`` via MistTrack and persist any hits to the review queue.

    No key -> a no-op ``EnrichmentResult(enabled=False, ...)`` (no network, no DB).
    ``persist_candidates`` is itself a no-op (returns 0) when no DSN /
    ``SUPABASE_DB_URL`` is configured, so this is safe to call in local dev.
    """
    uniq = _dedup_clean(addresses)
    if not _has_key(api_key):
        log.info(
            "misttrack-enrich: MISTTRACK_API_KEY unset -- no-op "
            "(%d target(s) would have been queried).", len(uniq),
        )
        return EnrichmentResult(
            enabled=False, targets=len(uniq), queried=0, resolved=0, persisted=0,
        )

    queried = len(uniq) if limit is None else min(len(uniq), max(0, limit))
    candidates = resolve_targets(
        uniq, chain=chain, api_key=api_key, http_client=http_client, limit=limit,
    )
    if not candidates:
        return EnrichmentResult(
            enabled=True, targets=len(uniq), queried=queried,
            resolved=0, persisted=0,
        )

    from recupero.labels.auto_ingest import persist_candidates
    persisted = persist_candidates(candidates, dsn=dsn)
    log.info(
        "misttrack-enrich: %d/%d address(es) resolved -> %d new candidate(s) "
        "persisted (pending_review).", len(candidates), queried, persisted,
    )
    return EnrichmentResult(
        enabled=True, targets=len(uniq), queried=queried,
        resolved=len(candidates), persisted=persisted,
    )
