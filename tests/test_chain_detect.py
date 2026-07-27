"""Chain auto-detection from address shape (the guided "start a recovery" flow)
+ its wiring as the /v2 submit fallback (chain optional, inferred from the seed).

Detection is checksum-verified (reuses the per-chain address validators), so the
tests pin real, valid sample addresses per chain and the None (no-match) path.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from recupero.chains.detect import EVM_DEFAULT_CHAIN, detect_chain, is_evm_family
from recupero.platform import router, store, tenancy
from recupero.platform.router import TraceIn

# Confirmed-valid samples (verified against the validators).
_EVM = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
_TRON = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"
_BTC_BECH32 = "bc1qs604c7jv6amk4cxqlnvuxv26hv3e48cds4m0ew"
_BTC_B58 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
_SOL = "So11111111111111111111111111111111111111112"


# --------------------------------------------------------------------------- #
# pure detector
# --------------------------------------------------------------------------- #

def test_detect_each_chain() -> None:
    assert detect_chain(_EVM) == "ethereum"       # EVM family default
    assert detect_chain(_EVM) == EVM_DEFAULT_CHAIN
    assert detect_chain(_TRON) == "tron"
    assert detect_chain(_BTC_BECH32) == "bitcoin"
    assert detect_chain(_BTC_B58) == "bitcoin"
    assert detect_chain(_SOL) == "solana"


def test_detect_none_on_unrecognized() -> None:
    for bad in ["", "   ", "hello-world", "0xnothex", "0x123", None, 42]:
        assert detect_chain(bad) is None  # type: ignore[arg-type]


def test_detect_is_mutually_exclusive() -> None:
    # Each real sample resolves to exactly one chain; only EVM is the 0x family.
    assert is_evm_family(_EVM) is True
    for a in (_TRON, _BTC_BECH32, _BTC_B58, _SOL):
        assert is_evm_family(a) is False


def test_evm_detection_is_case_and_whitespace_tolerant() -> None:
    assert detect_chain(f"  {_EVM.upper().replace('0X', '0x')}  ") == "ethereum"


# --------------------------------------------------------------------------- #
# /v2 submit fallback wiring
# --------------------------------------------------------------------------- #

def _principal() -> store.OrgContext:
    return store.OrgContext(org_id="org1", plan="pro", user_id="u", role="owner")


def _patch_store(monkeypatch) -> dict:
    captured: dict = {}
    # Don't pollute the global metrics registry (a separate test asserts it's
    # empty) — submit_trace records a platform-request counter otherwise.
    monkeypatch.setattr(router.obs_metrics, "record_platform_request", lambda *a, **k: None)
    monkeypatch.setattr(store, "get_org", lambda conn, org_id: {"status": "active", "plan": "pro"})
    monkeypatch.setattr(store, "traces_used_this_period", lambda conn, org_id: 0)

    def _enqueue(conn, **kw):
        captured.update(kw)
        return "inv-1", True

    monkeypatch.setattr(store, "enqueue_trace", _enqueue)
    return captured


def test_submit_infers_chain_when_omitted(monkeypatch) -> None:
    captured = _patch_store(monkeypatch)
    body = TraceIn(chain=None, seed_address=_TRON, incident_time="2024-01-01T00:00:00Z")
    out = router.submit_trace(body=body, principal=_principal(), conn=object(), idempotency_key=None)
    assert captured["chain"] == "tron"        # inferred from the seed shape
    assert out["chain"] == "tron"             # echoed back to the caller


def test_submit_explicit_chain_wins_over_detection(monkeypatch) -> None:
    captured = _patch_store(monkeypatch)
    # An EVM address but the caller explicitly says base — explicit must win.
    body = TraceIn(chain="base", seed_address=_EVM, incident_time="2024-01-01T00:00:00Z")
    router.submit_trace(body=body, principal=_principal(), conn=object(), idempotency_key=None)
    assert captured["chain"] == "base"


def test_submit_422_when_chain_undetectable(monkeypatch) -> None:
    _patch_store(monkeypatch)
    body = TraceIn(chain=None, seed_address="not-an-address", incident_time="2024-01-01T00:00:00Z")
    with pytest.raises(HTTPException) as ei:
        router.submit_trace(body=body, principal=_principal(), conn=object(), idempotency_key=None)
    assert ei.value.status_code == 422
    assert "chain" in ei.value.detail.lower()


def test_submit_still_meters_and_quota_gates(monkeypatch) -> None:
    # Sanity: an over-quota free org is still 402'd regardless of detection.
    _patch_store(monkeypatch)
    monkeypatch.setattr(store, "get_org", lambda conn, org_id: {"status": "active", "plan": "free"})
    monkeypatch.setattr(store, "traces_used_this_period", lambda conn, org_id: 9999)
    body = TraceIn(chain=None, seed_address=_EVM, incident_time="2024-01-01T00:00:00Z")
    with pytest.raises(HTTPException) as ei:
        router.submit_trace(body=body, principal=_principal(), conn=object(), idempotency_key=None)
    assert ei.value.status_code == 402


def test_tenancy_plans_unchanged() -> None:
    # Guardrail: this slice must not touch the plan set.
    assert set(tenancy.PLANS) == {"free", "pro", "enterprise"}
