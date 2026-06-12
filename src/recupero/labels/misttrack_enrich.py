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


def select_attribution_targets(observations, *, include_test=False):
    """Pick the UNLABELED addresses from a case's observations worth attributing.

    An observation that already carries a ``label_category`` or ``label_name`` is
    an attributed entity (a known exchange/bridge/service) -- skip it. We keep
    only the unknowns (``hop`` / ``unlabeled`` with no label), which is exactly
    what a MistTrack lookup might illuminate. Test-fixture cases are excluded
    unless ``include_test=True`` (paid queries should not be spent on fixtures).

    Returns ``(addresses, chain)``: every observation in a case shares one chain,
    so ``chain`` is that common value (or ``None`` when there are no targets).
    """
    from recupero._common import canonical_address_key as _ck

    addrs: list[str] = []
    seen: set[str] = set()
    chain = None
    for o in observations or []:
        if getattr(o, "case_is_test", False) and not include_test:
            continue
        if getattr(o, "label_category", None) or getattr(o, "label_name", None):
            continue  # already attributed -- nothing for MistTrack to add
        addr = getattr(o, "address", None)
        if not addr:
            continue
        key = _ck(addr)
        if key in seen:
            continue
        seen.add(key)
        addrs.append(addr)
        if chain is None:
            chain = getattr(o, "chain", None)
    return addrs, chain


def targets_from_case(case_id, *, include_test=False):
    """Load a single case from the Supabase corpus and return its UNLABELED
    attribution targets as ``(addresses, chain)``.

    Thin + fully guarded: returns ``([], None)`` when the Supabase case store is
    not enabled or on ANY read/parse failure -- never raises (mirrors
    ``intel_harvest``'s thin-I/O convention). The pure selection logic lives in
    ``select_attribution_targets`` and is unit-tested.
    """
    try:
        import json as _json

        from recupero.api import _supabase_case_source as sb
        from recupero.api.case_index_api import classify_is_test
        from recupero.config import load_config
        from recupero.intel_harvest import enumerate_case_observations
        from recupero.models import Case
        from recupero.storage.supabase_case_store import SupabaseCaseStore

        if not sb.enabled():
            log.warning(
                "misttrack targets_from_case: Supabase case store not enabled "
                "(set RECUPERO_CASE_STORE=supabase + creds).")
            return [], None

        cfg, _ = load_config()
        url, key, bucket = sb._creds()
        store = SupabaseCaseStore(
            cfg, supabase_url=url, service_role_key=key,
            investigation_id=case_id, bucket=bucket,
        )
        try:
            case = Case.model_validate(
                _json.loads(store.read_artifact("case.json").decode("utf-8-sig")))
            try:
                freeze_asks = _json.loads(
                    store.read_artifact("freeze_asks.json").decode("utf-8-sig"))
            except Exception:  # noqa: BLE001 -- optional artifact
                freeze_asks = {}
            try:
                from recupero.intel_harvest import _victim_name_from_bytes
                has_v, vname = _victim_name_from_bytes(
                    store.read_artifact("victim.json"))
            except Exception:  # noqa: BLE001
                has_v, vname = False, None
        finally:
            store.close()

        is_test, _reason = classify_is_test(vname, has_victim_json=has_v)
        obs = enumerate_case_observations(
            case, freeze_asks, investigation_id=case_id, case_is_test=is_test)
        return select_attribution_targets(obs, include_test=include_test)
    except Exception as exc:  # noqa: BLE001 -- thin guarded I/O
        log.warning("misttrack targets_from_case(%s) failed: %s", case_id, exc)
        return [], None
