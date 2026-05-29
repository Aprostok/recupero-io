"""Cross-victim correlation / class-action surfacing (v0.14.3).

When the same perpetrator infrastructure hits multiple victims,
the right play isn't 30 individual freeze letters — it's a
coordinated action with a much larger combined recovery target.
This module surfaces multi-victim patterns by querying the
address_observations + watchlist tables for shared perp hubs.

TRM/Chainalysis can't build this — they're not the recovery
operator, they don't see your case roster.

What surfaces in the brief
--------------------------

When a new case's perp hub OR primary destinations have appeared
in prior cases:

  CLASS_ACTION_OPPORTUNITY: {
    "potential_co_victim_cases": 4,
    "shared_addresses": [
      {"address": "0xperp...", "role": "perpetrator_hub",
       "appeared_in_cases": ["V-CFI-001", "V-CFI-007", ...]},
    ],
    "estimated_combined_loss": "$8,300,000",
    "investigator_note": "This case shares its perpetrator hub
       with 4 prior cases totaling $8.3M in combined victim loss.
       Coordinated multi-victim action recommended over individual
       letters — pooled recovery target qualifies for class-action
       legal representation."
  }

Operator workflow
-----------------

1. Trace runs and produces case.json.
2. emit_brief.py calls find_co_victim_cases(case) which queries
   address_observations for addresses in this case appearing in
   prior cases.
3. If the overlap is >= the threshold (default: 2 prior cases
   sharing the perp_hub), the brief surfaces the
   CLASS_ACTION_OPPORTUNITY section.
4. The investigator can run `recupero-ops class-action-report
   <case_id>` to render the consolidated view across all
   matching cases.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:  # pragma: no cover
    from recupero.models import Case

log = logging.getLogger(__name__)


# Minimum number of prior cases sharing an address before we trigger
# a class-action surfacing. Below this, the noise floor (random
# CEX hot wallets) drowns out signal.
_MIN_PRIOR_CASES_FOR_CLASS_ACTION = 2

# Cap on the number of prior cases shown in the brief section.
_MAX_PRIOR_CASES_IN_SECTION = 20


# Roles where a shared address is a STRONG class-action signal.
# CEX hot wallets, mixers, bridges shared across cases are NOT
# class-action signals — those addresses are public infrastructure
# that's expected to appear in many cases.
_CLASS_ACTION_QUALIFYING_ROLES = frozenset([
    "perpetrator_hub",
    "drainer_contract",
    "high_risk_destination",
])

# Roles where a shared address is NOISE (don't trigger on these
# alone).
_PUBLIC_INFRASTRUCTURE_ROLES = frozenset([
    "exchange_deposit",
    "exchange_hot_wallet",
    "bridge",
    "dex_router",
    "mixer",
])


@dataclass
class SharedAddress:
    """One address that appears in BOTH the current case and one
    or more prior cases."""
    address: str
    role_in_current_case: str
    appeared_in_case_ids: list[UUID]
    appeared_in_case_count: int
    total_usd_across_prior_cases: Decimal
    prior_ofac_exposed: bool
    prior_drainer_attributed: bool


@dataclass
class ClassActionOpportunity:
    """Top-level brief section payload."""
    potential_co_victim_case_count: int
    shared_addresses: list[SharedAddress]
    estimated_combined_loss: Decimal       # sum of total_usd across prior cases
    qualifying_share_count: int            # how many shared addrs match qualifying roles
    investigator_note: str
    triggered: bool                        # True if class-action surfacing is justified

    def to_json_safe(self) -> dict[str, Any]:
        return {
            "triggered": self.triggered,
            "potential_co_victim_case_count": self.potential_co_victim_case_count,
            "qualifying_share_count": self.qualifying_share_count,
            "estimated_combined_loss": f"${self.estimated_combined_loss:,.2f}",
            "shared_addresses": [
                {
                    "address": s.address,
                    "role_in_current_case": s.role_in_current_case,
                    "appeared_in_case_ids": [str(c) for c in s.appeared_in_case_ids],
                    "appeared_in_case_count": s.appeared_in_case_count,
                    "total_usd_across_prior_cases": (
                        f"${s.total_usd_across_prior_cases:,.2f}"
                    ),
                    "prior_ofac_exposed": s.prior_ofac_exposed,
                    "prior_drainer_attributed": s.prior_drainer_attributed,
                }
                for s in self.shared_addresses
            ],
            "investigator_note": self.investigator_note,
        }


# ---- Detection ---- #


def compute_class_action_opportunity(
    *,
    case: Case,
    correlations: dict[str, Any],
    current_case_id: UUID | None = None,
) -> ClassActionOpportunity:
    """Pure function over the correlation lookup output.

    Inputs:
      case: the current case (used for address enumeration)
      correlations: output from
        recupero.trace.correlation.lookup_correlations(addresses) —
        a dict[lowercased_address, CorrelationResult]. Already
        excludes the current case_id.
      current_case_id: the UUID of THIS case, for fallback exclusion

    Returns a ClassActionOpportunity with .triggered=True iff:
      * >= 2 prior cases share an address in qualifying roles, OR
      * Any single prior case shares 2+ addresses with the current
        case (strong indicator of same-perpetrator).
    """
    if not correlations:
        return _empty_opportunity()

    # Build per-prior-case index: how many of the current-case's
    # addresses appeared in each prior case.
    by_prior_case_id: dict[UUID, list[str]] = {}
    for addr, corr in correlations.items():
        for appearance in (corr.prior_case_appearances or []):
            cid = appearance.case_id
            if cid == current_case_id:
                continue
            by_prior_case_id.setdefault(cid, []).append(addr)

    if not by_prior_case_id:
        return _empty_opportunity()

    # Build the shared-address list, filtered to qualifying roles.
    # We also surface non-qualifying shares (CEX, etc.) for context,
    # but only qualifying ones COUNT for the triggered decision.
    shared: list[SharedAddress] = []
    qualifying_count = 0
    total_loss_estimate = Decimal("0")
    seen_case_ids: set[UUID] = set()
    for addr, corr in correlations.items():
        # Take the role from the first prior appearance (could vary
        # per case; we use 'role_in_current_case' as a label hint).
        roles = {a.role for a in (corr.prior_case_appearances or [])}
        is_qualifying = bool(roles & _CLASS_ACTION_QUALIFYING_ROLES)
        is_pure_infrastructure = roles.issubset(_PUBLIC_INFRASTRUCTURE_ROLES)
        if is_pure_infrastructure:
            continue  # exclude entirely — these are noise

        appearance_case_ids = []
        for a in (corr.prior_case_appearances or []):
            cid = a.case_id
            if cid == current_case_id:
                continue
            appearance_case_ids.append(cid)
            seen_case_ids.add(cid)
        if not appearance_case_ids:
            continue

        # Total prior USD: use the corr's aggregated figure.
        # NB (round-12): an audit pass flagged this as a potential
        # double-count when multiple addresses share one prior case.
        # The metric is intentionally per-address-aggregate ("USD that
        # flowed through addresses linking this case to priors") rather
        # than per-case-loss; we don't carry per-case loss data through
        # the correlation pipeline, so the per-case-max alternative
        # isn't computable without a schema change. The headline note
        # text is already hedged ("estimated combined loss"); operators
        # reviewing the brief understand it as an exposure aggregate,
        # not a victim-loss tally.
        total_loss_estimate += corr.prior_total_usd_flowed or Decimal("0")

        # Take a representative role. Prefer a qualifying role
        # (perpetrator_hub > beneficiary > etc.) when present so the
        # representative reflects the most-actionable signal; fall
        # back to sorted role name for stable ordering across runs.
        # Pre-fix this used `next(iter(roles))` which is non-deterministic
        # for string sets when PYTHONHASHSEED is randomized — same
        # case re-emitted twice could produce different
        # `role_in_current_case` values.
        qualifying_roles = sorted(roles & _CLASS_ACTION_QUALIFYING_ROLES)
        if qualifying_roles:
            rep_role = qualifying_roles[0]
        elif roles:
            rep_role = sorted(roles)[0]
        else:
            rep_role = "unlabeled"

        if is_qualifying:
            qualifying_count += 1

        shared.append(SharedAddress(
            address=addr,
            role_in_current_case=rep_role,
            appeared_in_case_ids=appearance_case_ids[:_MAX_PRIOR_CASES_IN_SECTION],
            appeared_in_case_count=len(appearance_case_ids),
            total_usd_across_prior_cases=corr.prior_total_usd_flowed or Decimal("0"),
            prior_ofac_exposed=corr.prior_ofac_exposed_count > 0,
            prior_drainer_attributed=corr.prior_drainer_attributed_count > 0,
        ))

    # Sort shared addresses by qualifying-role first, then by USD.
    shared.sort(
        key=lambda s: (
            s.role_in_current_case in _CLASS_ACTION_QUALIFYING_ROLES,
            s.total_usd_across_prior_cases,
        ),
        reverse=True,
    )

    # Trigger logic:
    #   - 2+ qualifying-role shared addresses → triggered
    #   - OR any single prior case sharing 2+ addresses with this
    #     one (strong same-perpetrator signal)
    multi_share_prior_cases = sum(
        1 for addrs_in_prior in by_prior_case_id.values()
        if len(addrs_in_prior) >= 2
    )
    triggered = (
        qualifying_count >= _MIN_PRIOR_CASES_FOR_CLASS_ACTION
        or multi_share_prior_cases >= 1
    )

    note = _build_class_action_note(
        triggered=triggered,
        prior_case_count=len(seen_case_ids),
        shared_addresses=shared,
        combined_loss=total_loss_estimate,
        qualifying_count=qualifying_count,
        multi_share_prior_cases=multi_share_prior_cases,
    )

    return ClassActionOpportunity(
        potential_co_victim_case_count=len(seen_case_ids),
        shared_addresses=shared,
        estimated_combined_loss=total_loss_estimate,
        qualifying_share_count=qualifying_count,
        investigator_note=note,
        triggered=triggered,
    )


def _empty_opportunity() -> ClassActionOpportunity:
    return ClassActionOpportunity(
        potential_co_victim_case_count=0,
        shared_addresses=[],
        estimated_combined_loss=Decimal("0"),
        qualifying_share_count=0,
        investigator_note=(
            "No prior cases share addresses with this one. Standard "
            "individual-case workflow applies."
        ),
        triggered=False,
    )


def _build_class_action_note(
    *,
    triggered: bool,
    prior_case_count: int,
    shared_addresses: list[SharedAddress],
    combined_loss: Decimal,
    qualifying_count: int,
    multi_share_prior_cases: int,
) -> str:
    if not triggered:
        if prior_case_count > 0:
            return (
                f"This case shares {len(shared_addresses)} address(es) "
                f"with {prior_case_count} prior case(s), but the matches "
                "are public infrastructure (exchange / bridge / mixer). "
                "Standard individual-case workflow applies."
            )
        return _empty_opportunity().investigator_note

    base = (
        f"CLASS-ACTION OPPORTUNITY: this case shares "
        f"{qualifying_count} perpetrator-controlled address(es) "
        f"with {prior_case_count} prior case(s); "
        f"~${combined_loss:,.2f} in aggregate USD flowed through those "
        "shared addresses across prior cases (exposure estimate — may "
        "double-count where multiple shared addresses touch the same "
        "prior case). "
    )
    if multi_share_prior_cases > 0:
        base += (
            f"{multi_share_prior_cases} prior case(s) share 2+ addresses "
            "with this one — strong same-perpetrator signal. "
        )
    base += (
        "Recommend coordinated multi-victim action: pooled freeze "
        "request to issuer compliance teams citing the combined "
        "loss figure, and class-action referral to recovery counsel. "
        "Combined recovery target may exceed individual-case "
        "engagement thresholds where individual cases did not."
    )
    return base


# ---- Convenience wrapper for emit_brief ---- #


def run_class_action_pass(
    case: Case,
    *,
    dsn: str | None = None,
    current_case_id: UUID | None = None,
) -> dict[str, Any]:
    """End-to-end class-action surfacing for the brief.

    1. Enumerate the case's significant addresses.
    2. Look up correlations against prior cases.
    3. Compute the ClassActionOpportunity.
    4. Return the JSON-safe brief section.

    DB-unavailable → empty (untriggered) section. Doesn't fail the
    brief.
    """
    resolved_dsn = dsn or os.environ.get("SUPABASE_DB_URL", "").strip()
    if not resolved_dsn:
        return _empty_opportunity().to_json_safe()

    try:
        from recupero.trace.correlation import (
            build_observations,
            lookup_correlations,
        )
        observations = build_observations(case, case_id=current_case_id)
        addresses = [o.address for o in observations]
        correlations = lookup_correlations(
            addresses, dsn=resolved_dsn, exclude_case_id=current_case_id,
        )
        opp = compute_class_action_opportunity(
            case=case,
            correlations=correlations,
            current_case_id=current_case_id,
        )
        return opp.to_json_safe()
    except Exception as exc:  # noqa: BLE001
        log.warning("class action pass failed: %s", exc)
        return _empty_opportunity().to_json_safe()


__all__ = (
    "SharedAddress",
    "ClassActionOpportunity",
    "compute_class_action_opportunity",
    "run_class_action_pass",
)
