"""Cross-case address correlation (v0.11.0).

Every case the worker traces APPENDS rows to ``public.address_observations``
in Supabase. The Nth case automatically benefits from address sightings
in cases 1..N-1 — when an address appears in a new case, the brief now
shows::

  "This address has appeared in 3 prior cases (V-CFI-001, V-CFI-007,
   V-CFI-014). In 2 of those cases it was attributed to known
   drainer infrastructure (Inferno Drainer) and in 1 case it received
   direct funds from an OFAC-sanctioned wallet."

This is the compounding-moat capability behind TRM Labs and
Chainalysis: per-case isolated forensics is straightforward, but the
ability to say "this wallet has done this 47 times before" requires a
durable index of every prior trace.

Why it lives in ``trace/`` and not ``worker/``
----------------------------------------------

The recorder is invoked from the brief-assembly path
(``reports/emit_brief.py``) so case files generated outside the
Phase-2 worker (CLI users, R&D scripts) still populate the index.
The actual DB I/O is wrapped in try/except so any DB unavailability
degrades gracefully — the brief still renders, just without the
CROSS_CASE_CORRELATION section.

Operational notes
-----------------

  * Single-write: no batching. A typical case has 20-200 addresses;
    that's well within psycopg's per-statement budget. If we ever hit
    cases in the 10k+ address range we can switch to COPY FROM STDIN.
  * Lookup-then-record: callers wanting the correlation report for
    THIS case must call lookup FIRST (so the data reflects only
    prior cases, not the current one), then record after.
  * Recorder is idempotent at the (address, chain, case_id, role)
    level via the UNIQUE constraint; the upsert uses ON CONFLICT DO
    UPDATE so re-running a case updates the snapshot fields without
    multiplying rows.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID

from recupero._common import canonical_address_key as _ck

# v0.17.5 (round-10 forensic HIGH): canonical address keying.
# EVM → lower, base58 → preserve case. Pre-v0.17.5 every site here
# called ``addr.lower()`` directly, mangling Solana / Tron / Bitcoin
# entries written into address_observations. A correlation lookup
# from a future case that pastes the canonical mixed-case form
# would miss every prior sighting.
from recupero._common import db_connect

if TYPE_CHECKING:  # pragma: no cover
    from recupero.models import Case

log = logging.getLogger(__name__)


# Role taxonomy mirrors the watchlist table so cross-table joins
# stay clean. Any role not in this set gets bucketed as 'unlabeled'
# by the recorder.
_KNOWN_ROLES = frozenset([
    "victim",
    "perpetrator_hub",
    "hop",
    "exchange_deposit",
    "high_risk_destination",
    "bridge",
    "mixer",
    "dex_router",
    "drainer_contract",
    "unlabeled",
    "manual",
])


# Max addresses we'll record per case. Defensive cap — a runaway
# trace could theoretically blow this up, and we don't want a
# correlation-DB write storm taking down a brief render.
_MAX_OBSERVATIONS_PER_CASE = 5_000


# Per-correlation-lookup cap on prior-case names we surface in the
# brief. Trims the section so it stays readable when a hot-wallet
# address has been seen in 100 cases.
_MAX_PRIOR_CASES_IN_SUMMARY = 10


# ----- Models ----- #


@dataclass(frozen=True)
class AddressObservation:
    """One observation of an address in a case. Built by the
    recorder and serialized to ``public.address_observations``."""
    address: str
    chain: str
    case_id: UUID | None
    investigation_id: UUID | None
    role: str
    label_category: str | None
    label_name: str | None
    usd_flowed: Decimal | None
    risk_score: int | None
    risk_verdict: str | None
    is_ofac_exposed: bool
    is_mixer_exposed: bool
    is_drainer_attributed: bool


@dataclass
class PriorCaseAppearance:
    """One prior-case appearance of an address."""
    case_id: UUID
    role: str
    label_category: str | None
    label_name: str | None
    usd_flowed: Decimal | None
    risk_verdict: str | None
    observed_at_iso: str


@dataclass
class CorrelationResult:
    """Cross-case correlation for one address."""
    address: str
    chain: str
    total_prior_cases: int
    prior_ofac_exposed_count: int
    prior_mixer_exposed_count: int
    prior_drainer_attributed_count: int
    prior_total_usd_flowed: Decimal
    prior_roles_seen: list[str]   # distinct roles, e.g. ['hop', 'perpetrator_hub']
    prior_case_appearances: list[PriorCaseAppearance] = field(default_factory=list)


# ----- Recorder ----- #


def build_observations(
    case: Case,
    *,
    case_id: UUID | None = None,
    investigation_id: UUID | None = None,
    risk_assessment: dict[str, Any] | None = None,
    drainer_findings: Any | None = None,
    freeze_targets_by_addr: dict[str, Any] | None = None,
    address_balances: dict[str, Decimal] | None = None,
) -> list[AddressObservation]:
    """Build the observation set for a case without touching the DB.

    Pure function — exposed so callers can preview what would be
    written (and tests can verify the shape without psycopg).

    Inputs roughly mirror what ``emit_brief`` already computes; we
    accept them by reference rather than re-running analyzers.
    """
    risk_assessment = risk_assessment or {"addresses": {}}
    freeze_targets_by_addr = freeze_targets_by_addr or {}
    address_balances = address_balances or {}

    # Walk every transfer's from/to to enumerate addresses we touched
    # in this case, summing per-address USD flow.
    usd_flow_by_addr: dict[str, Decimal] = {}
    chains_seen: dict[str, str] = {}  # address -> chain
    for t in case.transfers:
        chain = t.token.chain.value if hasattr(t.token.chain, "value") else str(t.token.chain)
        for raw_addr in (t.from_address, t.to_address):
            addr = _ck(raw_addr)
            chains_seen.setdefault(addr, chain)
            usd = t.usd_value_at_tx or Decimal("0")
            usd_flow_by_addr[addr] = usd_flow_by_addr.get(addr, Decimal("0")) + usd

    # Special-case the seed address — always the victim, regardless
    # of whether it appears in any transfer (e.g. zero-value cases).
    victim_addr = _ck(case.seed_address or "")
    if victim_addr and victim_addr not in chains_seen:
        chains_seen[victim_addr] = (
            case.chain.value if hasattr(case.chain, "value") else str(case.chain)
        )

    # Drainer attribution: extract addresses involved in critical
    # drainer signals so we can flag this column for future lookups.
    drainer_attributed: set[str] = set()
    if drainer_findings is not None:
        # v0.18.3 (round-11 trace-CRIT-001): pre-v0.18.3 this block
        # was DOUBLY broken:
        #   1. `DrainerSignal.severity` is a STRING ("critical" /
        #      "high" / "medium" / "low"), but the code did
        #      `>= 3` against it → TypeError → swallowed by bare
        #      except → `drainer_attributed` stayed empty FOREVER.
        #   2. `DrainerSignal` exposes `address` (singular), NOT
        #      `addresses` (plural) — even if the type bug were
        #      fixed, the iteration would land on an empty list.
        # Net effect: `is_drainer_attributed` was permanently False
        # on every observation written to public.address_observations,
        # SILENTLY DEFEATING the compounding-moat capability
        # ("this wallet has been seen as drainer infrastructure in
        # N prior cases"). Now: map severity string → int, iterate
        # the singular `address` field.
        _SEVERITY_TO_INT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        try:
            signals = getattr(drainer_findings, "signals", []) or []
            for sig in signals:
                raw_sev = getattr(sig, "severity", None)
                sev_int = (
                    _SEVERITY_TO_INT.get(raw_sev.lower(), 0)
                    if isinstance(raw_sev, str)
                    else (int(raw_sev) if raw_sev is not None else 0)
                )
                if sev_int >= 3:
                    addr = getattr(sig, "address", None) or getattr(sig, "counterparty", None)
                    if addr:
                        drainer_attributed.add(_ck(addr))
        except Exception:  # noqa: BLE001
            # Defensive — if drainer_findings doesn't conform to the
            # expected shape, just skip this enrichment.
            pass

    observations: list[AddressObservation] = []
    seen_role_per_addr: set[tuple[str, str]] = set()  # dedupe (addr, role)

    def _emit(addr: str, role: str, label_cat: str | None = None,
              label_name: str | None = None) -> None:
        addr = _ck(addr)
        if not addr:
            return
        key = (addr, role)
        if key in seen_role_per_addr:
            return
        if len(observations) >= _MAX_OBSERVATIONS_PER_CASE:
            return
        seen_role_per_addr.add(key)

        chain = chains_seen.get(addr) or (
            case.chain.value if hasattr(case.chain, "value") else str(case.chain)
        )
        risk_entry = risk_assessment.get("addresses", {}).get(addr, {})
        score = risk_entry.get("score")
        verdict = risk_entry.get("verdict")
        exposures = risk_entry.get("exposures", []) or []
        cats = {e.get("risk_category", "") for e in exposures}
        ofac_exposed = any(c.startswith("ofac") for c in cats)
        mixer_exposed = any("mixer" in c for c in cats)

        observations.append(AddressObservation(
            address=addr,
            chain=chain,
            case_id=case_id,
            investigation_id=investigation_id,
            role=role if role in _KNOWN_ROLES else "unlabeled",
            label_category=label_cat,
            label_name=label_name,
            usd_flowed=usd_flow_by_addr.get(addr),
            risk_score=score if isinstance(score, int) else None,
            risk_verdict=verdict if isinstance(verdict, str) else None,
            is_ofac_exposed=bool(ofac_exposed),
            is_mixer_exposed=bool(mixer_exposed),
            is_drainer_attributed=addr in drainer_attributed,
        ))

    # 1. Seed address — always 'victim'.
    if victim_addr:
        _emit(victim_addr, "victim")

    # 2. Counterparties live on each Transfer; dedupe per address.
    # The same address can appear as the counterparty in many transfers
    # — we take the FIRST labeled instance (labels are stable; the
    # first one we hit is fine).
    counterparties_seen: dict[str, Any] = {}
    for t in case.transfers:
        cp = t.counterparty
        if cp is None:
            continue
        addr = _ck(cp.address or "")
        if not addr or addr in counterparties_seen:
            continue
        counterparties_seen[addr] = cp

    for addr, cp in counterparties_seen.items():
        label = cp.label
        if label is None:
            role = "hop"
            label_cat = None
            label_name = None
        else:
            label_cat = (
                label.category.value if hasattr(label.category, "value")
                else str(label.category)
            )
            label_name = label.name
            role = _role_from_label_category(label_cat)
        _emit(addr, role, label_cat=label_cat, label_name=label_name)

    # 3. Anything in freeze_targets_by_addr that isn't already
    # bucketed is a freezable exchange/issuer deposit → 'exchange_deposit'.
    # (Historic comment said 'high_risk_destination'; the code has always
    # emitted 'exchange_deposit' — a freezable destination is NOT
    # perpetrator-controlled, so it must never bind a cross-case cluster.)
    for addr in freeze_targets_by_addr.keys():
        _emit(_ck(addr), "exchange_deposit")

    # 4. Drainer-attributed addresses we haven't already labeled get
    # the 'drainer_contract' role even if they had no counterparty.
    for addr in drainer_attributed:
        _emit(addr, "drainer_contract")

    # 5. Backfill: any address that appeared in a transfer but
    # didn't get a role yet → 'hop'. This is the long tail of
    # in-trace addresses we have nothing labeled for.
    for addr in usd_flow_by_addr:
        # If it already has any role recorded, skip.
        if any(o.address == addr for o in observations):
            continue
        _emit(addr, "hop")

    return observations


def _role_from_label_category(label_category: str) -> str:
    """Map a LabelCategory enum value to an address_observations.role."""
    if label_category == "victim":
        return "victim"
    if label_category == "perpetrator":
        return "perpetrator_hub"
    if label_category in ("exchange_deposit", "exchange_hot_wallet"):
        return "exchange_deposit"
    if label_category == "bridge":
        return "bridge"
    if label_category == "mixer":
        return "mixer"
    if label_category == "defi_protocol":
        return "dex_router"
    return "unlabeled"


def record_observations(
    observations: list[AddressObservation],
    *,
    dsn: str,
) -> int:
    """Upsert observations into ``public.address_observations``.

    Returns the number of rows written. Idempotent at the
    (address, chain, case_id, role) level via the UNIQUE constraint
    — re-running a case updates the snapshot columns in place
    rather than appending dupe rows.

    On any DB error, logs + returns 0 (best-effort; brief assembly
    must not fail because the correlation DB is unavailable).
    """
    if not observations:
        return 0
    try:
        import psycopg
    except ImportError:  # pragma: no cover
        log.warning("psycopg not installed — correlation recording skipped")
        return 0

    sql = """
        INSERT INTO public.address_observations (
            address, chain, case_id, investigation_id, role,
            label_category, label_name, usd_flowed,
            risk_score, risk_verdict,
            is_ofac_exposed, is_mixer_exposed, is_drainer_attributed
        ) VALUES (
            %(address)s, %(chain)s, %(case_id)s, %(investigation_id)s, %(role)s,
            %(label_category)s, %(label_name)s, %(usd_flowed)s,
            %(risk_score)s, %(risk_verdict)s,
            %(is_ofac_exposed)s, %(is_mixer_exposed)s, %(is_drainer_attributed)s
        )
        ON CONFLICT (address, chain, case_id, role)
        DO UPDATE SET
            investigation_id      = EXCLUDED.investigation_id,
            label_category        = EXCLUDED.label_category,
            label_name            = EXCLUDED.label_name,
            usd_flowed            = EXCLUDED.usd_flowed,
            risk_score            = EXCLUDED.risk_score,
            risk_verdict          = EXCLUDED.risk_verdict,
            is_ofac_exposed       = EXCLUDED.is_ofac_exposed,
            is_mixer_exposed      = EXCLUDED.is_mixer_exposed,
            is_drainer_attributed = EXCLUDED.is_drainer_attributed,
            observed_at           = NOW();
    """
    written = 0
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            for obs in observations:
                cur.execute(sql, {
                    "address": obs.address,
                    "chain": obs.chain,
                    "case_id": obs.case_id,
                    "investigation_id": obs.investigation_id,
                    "role": obs.role,
                    "label_category": obs.label_category,
                    "label_name": obs.label_name,
                    "usd_flowed": obs.usd_flowed,
                    "risk_score": obs.risk_score,
                    "risk_verdict": obs.risk_verdict,
                    "is_ofac_exposed": obs.is_ofac_exposed,
                    "is_mixer_exposed": obs.is_mixer_exposed,
                    "is_drainer_attributed": obs.is_drainer_attributed,
                })
                written += 1
    except Exception as exc:  # noqa: BLE001
        log.warning("correlation recording failed: %s", exc)
        return 0
    return written


# ----- Lookup ----- #


def lookup_correlations(
    addresses: list[str],
    *,
    dsn: str,
    exclude_case_id: UUID | None = None,
) -> dict[str, CorrelationResult]:
    """Look up cross-case correlations for a batch of addresses.

    ``exclude_case_id`` filters out the current case so the lookup
    only returns PRIOR appearances (otherwise an address would
    correlate with itself).

    Returns ``{lowercased_address: CorrelationResult}`` for each
    address with at least one prior observation. Addresses with no
    prior history are omitted (callers should treat them as
    "no correlation").

    DB-unavailable → empty dict (best-effort).
    """
    if not addresses:
        return {}
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:  # pragma: no cover
        log.warning("psycopg not installed — correlation lookup skipped")
        return {}

    # v0.18.3 (round-11 arch-CRIT-002 + trace-HIGH-002): canonical
    # address keying. Pre-v0.18.3 the function did `addr.strip()`
    # + `addr.strip().lower()` and queried BOTH via UNION-style ANY(),
    # claiming "we can't reliably tell here without a chain hint".
    # But (a) we DO have a chain-aware heuristic via _ck, and (b)
    # writers (build_observations + recorder) now use _ck so the
    # rows in address_observations are stored canonical-keyed.
    # Mixed-case EVM inputs match the lowercased rows; base58
    # inputs match the case-preserved rows. Single-query, deterministic.
    queries: list[str] = []
    for a in addresses:
        canon = _ck(a)
        if canon:
            queries.append(canon)
    # Defense-in-depth: also include the raw lowercased form for
    # legacy rows that may have been written pre-v0.17.5 (when the
    # writer was unconditional .lower()). Cheap union; no false
    # positives because EVM canonical form == lowercase form anyway.
    legacy_lowered: list[str] = []
    for a in addresses:
        a_stripped = (a or "").strip()
        if a_stripped:
            lower = a_stripped.lower()
            canon = _ck(a_stripped)
            if lower != canon:  # only add if it would expand coverage
                legacy_lowered.append(lower)
    queries.extend(legacy_lowered)
    if not queries:
        return {}

    sql = """
        SELECT
            address, chain, case_id, role,
            label_category, label_name, usd_flowed,
            risk_verdict,
            is_ofac_exposed, is_mixer_exposed, is_drainer_attributed,
            observed_at
          FROM public.address_observations
         WHERE address = ANY(%(addresses)s)
           AND (%(exclude_case)s::uuid IS NULL OR case_id IS DISTINCT FROM %(exclude_case)s::uuid)
         ORDER BY observed_at DESC
         LIMIT 10000;
    """
    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(sql, {
                "addresses": queries,
                "exclude_case": exclude_case_id,
            })
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        log.warning("correlation lookup failed: %s", exc)
        return {}

    # Bucket rows by (address, chain) and aggregate.
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (row["address"], row["chain"])
        by_key.setdefault(key, []).append(row)

    out: dict[str, CorrelationResult] = {}
    for (addr, chain), case_rows in by_key.items():
        # Distinct prior cases — addresses can appear with multiple
        # roles in the same case so we dedupe on case_id.
        case_ids_seen: set[UUID] = set()
        prior_appearances: list[PriorCaseAppearance] = []
        ofac_cases: set[UUID] = set()
        mixer_cases: set[UUID] = set()
        drainer_cases: set[UUID] = set()
        roles_seen: set[str] = set()
        total_usd = Decimal("0")

        for row in case_rows:
            cid = row.get("case_id")
            if cid is None:
                continue
            roles_seen.add(row.get("role") or "unlabeled")
            usd = row.get("usd_flowed") or Decimal("0")
            if isinstance(usd, (int, float)):
                usd = Decimal(str(usd))
            # Aggregate USD across all observations.
            total_usd += usd
            if row.get("is_ofac_exposed"):
                ofac_cases.add(cid)
            if row.get("is_mixer_exposed"):
                mixer_cases.add(cid)
            if row.get("is_drainer_attributed"):
                drainer_cases.add(cid)

            if cid in case_ids_seen:
                continue
            case_ids_seen.add(cid)
            if len(prior_appearances) < _MAX_PRIOR_CASES_IN_SUMMARY:
                observed_at = row.get("observed_at")
                observed_at_iso = (
                    observed_at.isoformat().replace("+00:00", "Z")
                    if observed_at is not None else ""
                )
                prior_appearances.append(PriorCaseAppearance(
                    case_id=cid,
                    role=row.get("role") or "unlabeled",
                    label_category=row.get("label_category"),
                    label_name=row.get("label_name"),
                    usd_flowed=Decimal(str(usd)) if usd else None,
                    risk_verdict=row.get("risk_verdict"),
                    observed_at_iso=observed_at_iso,
                ))

        if not case_ids_seen:
            continue

        out[addr] = CorrelationResult(
            address=addr,
            chain=chain,
            total_prior_cases=len(case_ids_seen),
            prior_ofac_exposed_count=len(ofac_cases),
            prior_mixer_exposed_count=len(mixer_cases),
            prior_drainer_attributed_count=len(drainer_cases),
            prior_total_usd_flowed=total_usd,
            prior_roles_seen=sorted(roles_seen),
            prior_case_appearances=prior_appearances,
        )
    return out


def correlations_to_brief_section(
    correlations: dict[str, CorrelationResult],
) -> dict[str, Any]:
    """Serialize for the brief's CROSS_CASE_CORRELATION section."""
    addresses_payload: dict[str, Any] = {}
    total_recidivist = 0
    ofac_recidivist = 0
    drainer_recidivist = 0
    highest_count = 0
    highest_addr: str | None = None

    for addr, corr in correlations.items():
        if corr.total_prior_cases <= 0:
            continue
        total_recidivist += 1
        if corr.prior_ofac_exposed_count > 0:
            ofac_recidivist += 1
        if corr.prior_drainer_attributed_count > 0:
            drainer_recidivist += 1
        if corr.total_prior_cases > highest_count:
            highest_count = corr.total_prior_cases
            highest_addr = addr

        addresses_payload[addr] = {
            "chain": corr.chain,
            "total_prior_cases": corr.total_prior_cases,
            "prior_ofac_exposed_count": corr.prior_ofac_exposed_count,
            "prior_mixer_exposed_count": corr.prior_mixer_exposed_count,
            "prior_drainer_attributed_count": corr.prior_drainer_attributed_count,
            "prior_total_usd_flowed": f"${corr.prior_total_usd_flowed:,.2f}",
            "prior_roles_seen": corr.prior_roles_seen,
            "prior_case_appearances": [
                {
                    "case_id": str(a.case_id),
                    "role": a.role,
                    "label_category": a.label_category,
                    "label_name": a.label_name,
                    "usd_flowed": (
                        f"${a.usd_flowed:,.2f}" if a.usd_flowed is not None else None
                    ),
                    "risk_verdict": a.risk_verdict,
                    "observed_at": a.observed_at_iso,
                }
                for a in corr.prior_case_appearances
            ],
            "investigator_note": _build_correlation_note(corr),
        }

    return {
        "addresses": addresses_payload,
        "summary": {
            "recidivist_address_count": total_recidivist,
            "ofac_recidivist_count": ofac_recidivist,
            "drainer_recidivist_count": drainer_recidivist,
            "highest_prior_case_count": highest_count,
            "highest_prior_case_address": highest_addr,
        },
    }


def _build_correlation_note(corr: CorrelationResult) -> str:
    """Investigator-actionable one-liner."""
    base = (
        f"This address has appeared in {corr.total_prior_cases} prior "
        f"{'case' if corr.total_prior_cases == 1 else 'cases'} "
        f"(${corr.prior_total_usd_flowed:,.2f} aggregate USD flow). "
    )
    flags: list[str] = []
    if corr.prior_ofac_exposed_count > 0:
        flags.append(
            f"OFAC-exposed in {corr.prior_ofac_exposed_count} prior "
            f"{'case' if corr.prior_ofac_exposed_count == 1 else 'cases'}"
        )
    if corr.prior_drainer_attributed_count > 0:
        flags.append(
            f"attributed to drainer infrastructure in "
            f"{corr.prior_drainer_attributed_count} prior "
            f"{'case' if corr.prior_drainer_attributed_count == 1 else 'cases'}"
        )
    if corr.prior_mixer_exposed_count > 0:
        flags.append(
            f"mixer-exposed in {corr.prior_mixer_exposed_count} prior "
            f"{'case' if corr.prior_mixer_exposed_count == 1 else 'cases'}"
        )
    if flags:
        base += "Flagged: " + "; ".join(flags) + ". "
    base += (
        "Subpoena the perpetrator's full case history — same wallet "
        "recycling across victims is a strong pattern indicator."
    )
    return base


# ----- Convenience wrapper for emit_brief ----- #


def run_correlation_pass(
    case: Case,
    *,
    case_id: UUID | None = None,
    investigation_id: UUID | None = None,
    risk_assessment: dict[str, Any] | None = None,
    drainer_findings: Any | None = None,
    freeze_targets_by_addr: dict[str, Any] | None = None,
    address_balances: dict[str, Decimal] | None = None,
    dsn: str | None = None,
) -> dict[str, Any]:
    """End-to-end correlation pass invoked from emit_brief.

    1. Build observations for this case (pure).
    2. Lookup PRIOR observations for those addresses (DB read,
       excluding the current case_id so we only see history).
    3. Record the new observations (DB write, idempotent).
    4. Return the serialized brief section.

    DSN resolution: caller may pass ``dsn`` explicitly; otherwise we
    read ``SUPABASE_DB_URL`` from the environment. If both are
    absent (CLI use without a DB) we return an empty section.
    """
    resolved_dsn = dsn or os.environ.get("SUPABASE_DB_URL", "").strip()
    if not resolved_dsn:
        return _empty_section()

    try:
        observations = build_observations(
            case,
            case_id=case_id,
            investigation_id=investigation_id,
            risk_assessment=risk_assessment,
            drainer_findings=drainer_findings,
            freeze_targets_by_addr=freeze_targets_by_addr,
            address_balances=address_balances,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("correlation build_observations failed: %s", exc)
        return _empty_section()

    addresses_to_lookup = [o.address for o in observations]
    correlations = lookup_correlations(
        addresses_to_lookup,
        dsn=resolved_dsn,
        exclude_case_id=case_id,
    )
    # Fire-and-forget the recorder; we already have the lookup
    # results that matter for this brief.
    record_observations(observations, dsn=resolved_dsn)
    return correlations_to_brief_section(correlations)


def _empty_section() -> dict[str, Any]:
    return {
        "addresses": {},
        "summary": {
            "recidivist_address_count": 0,
            "ofac_recidivist_count": 0,
            "drainer_recidivist_count": 0,
            "highest_prior_case_count": 0,
            "highest_prior_case_address": None,
        },
    }


__all__ = (
    "AddressObservation",
    "CorrelationResult",
    "PriorCaseAppearance",
    "build_observations",
    "record_observations",
    "lookup_correlations",
    "correlations_to_brief_section",
    "run_correlation_pass",
)
