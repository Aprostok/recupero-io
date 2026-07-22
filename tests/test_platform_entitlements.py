"""Unit tests for the plan feature-entitlements backbone.

Three layers, no live DB:
* the pure plan→features map + helpers (tenancy);
* the require_entitlement dependency gate (call its inner _dep directly — FastAPI
  Depends is bypassed on a direct call);
* the /v2/entitlements + /v2/me handlers (monkeypatch store.get_org).
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from recupero.platform import deps, router, store, tenancy

# --------------------------------------------------------------------------- #
# pure plan → features map
# --------------------------------------------------------------------------- #

def test_tiers_are_strictly_inclusive() -> None:
    free = tenancy.plan_features("free")
    pro = tenancy.plan_features("pro")
    ent = tenancy.plan_features("enterprise")
    assert free < pro < ent          # proper supersets, progressive unlock
    assert ent == tenancy.ALL_FEATURES


def test_free_taste_and_paid_gates() -> None:
    # Free gets a real taste...
    assert tenancy.has_feature("free", tenancy.FEATURE_BRIEF)
    assert tenancy.has_feature("free", tenancy.FEATURE_TRACE_BASIC)
    # ...but deep reach / all-chains / graph are paid.
    assert not tenancy.has_feature("free", tenancy.FEATURE_TRACE_DEEP_REACH)
    assert not tenancy.has_feature("free", tenancy.FEATURE_CHAINS_ALL)
    assert tenancy.has_feature("pro", tenancy.FEATURE_TRACE_DEEP_REACH)
    # Litigation artifacts are enterprise-only.
    assert not tenancy.has_feature("pro", tenancy.FEATURE_LITIGATION_ARTIFACTS)
    assert tenancy.has_feature("enterprise", tenancy.FEATURE_LITIGATION_ARTIFACTS)


def test_unknown_plan_falls_to_least_privilege() -> None:
    # Unknown / None plan → default (free) features, never a crash.
    assert tenancy.plan_features("does-not-exist") == tenancy.plan_features("free")
    assert tenancy.plan_features(None) == tenancy.plan_features("free")


def test_add_on_features_union_in() -> None:
    extra = frozenset({tenancy.FEATURE_MONITORING})
    got = tenancy.plan_features("free", extra=extra)
    assert tenancy.FEATURE_MONITORING in got
    assert tenancy.FEATURE_BRIEF in got  # base plan features still present
    assert tenancy.has_feature("free", tenancy.FEATURE_MONITORING, extra=extra)


def test_plan_carries_features_and_count_unchanged() -> None:
    assert set(tenancy.PLANS) == {"free", "pro", "enterprise"}  # retention test invariant
    for plan in tenancy.PLANS.values():
        assert isinstance(plan.features, frozenset)


# --------------------------------------------------------------------------- #
# require_entitlement dependency gate
# --------------------------------------------------------------------------- #

def _principal(plan: str) -> store.OrgContext:
    return store.OrgContext(org_id="o", plan=plan, user_id="u", role="owner")


def test_require_entitlement_allows_when_unlocked() -> None:
    dep = deps.require_entitlement(tenancy.FEATURE_TRACE_DEEP_REACH)
    p = _principal("pro")
    assert dep(principal=p) is p


def test_require_entitlement_402_when_locked() -> None:
    dep = deps.require_entitlement(tenancy.FEATURE_LITIGATION_ARTIFACTS)
    with pytest.raises(HTTPException) as ei:
        dep(principal=_principal("pro"))
    assert ei.value.status_code == 402
    assert "litigation_artifacts" in ei.value.detail
    assert "Upgrade" in ei.value.detail


def test_require_entitlement_needs_all_of_several() -> None:
    dep = deps.require_entitlement(
        tenancy.FEATURE_TRACE_DEEP_REACH, tenancy.FEATURE_LITIGATION_ARTIFACTS,
    )
    # enterprise has both → ok
    p = _principal("enterprise")
    assert dep(principal=p) is p
    # pro has deep_reach but NOT litigation → 402 naming only the missing one
    with pytest.raises(HTTPException) as ei:
        dep(principal=_principal("pro"))
    assert "litigation_artifacts" in ei.value.detail
    assert "trace.deep_reach" not in ei.value.detail


# --------------------------------------------------------------------------- #
# /v2/entitlements + /v2/me handlers
# --------------------------------------------------------------------------- #

def test_entitlements_endpoint_reports_unlocked_and_locked(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_org", lambda conn, org_id: {"plan": "free", "status": "active"})
    out = router.entitlements(principal=_principal("free"), conn=object())
    assert out["plan"] == "free"
    assert tenancy.FEATURE_BRIEF in out["features"]
    assert tenancy.FEATURE_LITIGATION_ARTIFACTS in out["locked"]
    assert set(out["all_features"]) == set(tenancy.ALL_FEATURES)
    # features and locked partition the catalog
    assert set(out["features"]).isdisjoint(out["locked"])
    assert set(out["features"]) | set(out["locked"]) == set(tenancy.ALL_FEATURES)


def test_entitlements_reads_plan_fresh_from_org(monkeypatch) -> None:
    # principal JWT says free, but the org has since upgraded to pro → report pro.
    monkeypatch.setattr(store, "get_org", lambda conn, org_id: {"plan": "pro", "status": "active"})
    out = router.entitlements(principal=_principal("free"), conn=object())
    assert out["plan"] == "pro"
    assert tenancy.FEATURE_TRACE_DEEP_REACH in out["features"]


def test_me_includes_features(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_org", lambda conn, org_id: {
        "plan": "pro", "status": "active", "period_start": None, "plan_renews_at": None,
        "stripe_customer_id": None,
    })
    monkeypatch.setattr(store, "traces_used_this_period", lambda conn, org_id: 0)
    out = router.me(principal=_principal("pro"), conn=object())
    assert tenancy.FEATURE_GRAPH in out["features"]
    assert tenancy.FEATURE_LITIGATION_ARTIFACTS not in out["features"]
