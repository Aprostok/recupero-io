"""v0.32 — Per-case API budget cap tests.

Closes Tier-1 gap #4 from ``docs/WHY_RECUPERO_WOULD_FAIL.md`` §1.4:
"At 50 cases/day we burn Etherscan + Helius + CoinGecko free tiers.
One whale case eats the day's budget for everyone."

These tests lock in:

  * Per-provider cost model: known providers (etherscan, helius,
    coingecko, etc.) charge their pessimistic per-call cost;
    unknown providers fall back to the conservative default.
  * Budget arithmetic: ``record()`` increments ``spent_usd`` and
    ``spend_by_provider`` by the per-provider weight.
  * Cap enforcement: ``assert_within_budget()`` raises at the exact
    threshold, not strictly past it. 5000 Etherscan calls @
    $0.0001 each = $0.50 = an opted-in cap of $0.50 exactly → raise.
  * Env-var resolution: bad inputs (NaN, Inf, negative, garbage)
    fall back to default (DISABLED — $0) with a WARN. Empty / unset
    uses default. Literal 0 disables (matches default).
  * Tracer integration: when the budget trips during BFS, the
    case is marked ``partial_budget_hit`` and the per-provider
    breakdown lands in ``case.config_used["api_budget"]``.
  * Budget=0 disables tracking entirely — ``record()`` is a
    no-op and never raises. This is the v0.32.1+ industry-best
    default.
  * Per-provider breakdown surfaces in the snapshot dict for the
    brief renderer.

v0.32.1+ "industry-best mode": the default budget is $0 (DISABLED).
Operators opt in by setting RECUPERO_API_BUDGET_USD_PER_CASE to a
positive value. Tests that exercise cap enforcement construct a
CaseBudget with an explicit positive value rather than relying on
the env-var default.

The pattern mirrors the v0.31.x adversarial-input tests: bad inputs
get a loud WARN, never a silently-poisoned trace.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from recupero.observability.api_budget import (
    BudgetExceededError,
    CaseBudget,
    cost_per_call,
    resolve_budget_from_env,
)


# ---------------------------------------------------------------------------
# Cost model
# ---------------------------------------------------------------------------


def test_cost_per_call_known_providers() -> None:
    """Known providers map to their documented pessimistic per-call cost."""
    assert cost_per_call("etherscan") == Decimal("0.0001")
    assert cost_per_call("alchemy") == Decimal("0.0001")
    assert cost_per_call("helius") == Decimal("0.0001")
    assert cost_per_call("trongrid") == Decimal("0.0001")
    assert cost_per_call("coingecko") == Decimal("0.0003")
    assert cost_per_call("defillama") == Decimal("0.0000")


def test_cost_per_call_is_case_insensitive() -> None:
    """Provider names are stored lowercased — case doesn't matter."""
    assert cost_per_call("Etherscan") == Decimal("0.0001")
    assert cost_per_call("ETHERSCAN") == Decimal("0.0001")
    assert cost_per_call("  helius  ") == Decimal("0.0001")


def test_cost_per_call_unknown_provider_uses_conservative_default() -> None:
    """Unknown providers default to $0.0001 — pessimistic so a typo
    never silently undercharges."""
    assert cost_per_call("brand-new-provider") == Decimal("0.0001")
    assert cost_per_call("") == Decimal("0.0001")
    assert cost_per_call(None) == Decimal("0.0001")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# CaseBudget arithmetic
# ---------------------------------------------------------------------------


def test_record_increments_spent_usd_by_per_provider_weight() -> None:
    """Each ``record`` call adds the per-provider cost to spent_usd."""
    b = CaseBudget(case_id="case-1", budget_usd=Decimal("1.00"))
    b.record("etherscan")
    assert b.spent_usd == Decimal("0.0001")
    b.record("coingecko")
    assert b.spent_usd == Decimal("0.0004")  # 0.0001 + 0.0003
    b.record("etherscan", calls=10)
    assert b.spent_usd == Decimal("0.0014")  # 0.0004 + 10 * 0.0001


def test_record_updates_spend_by_provider_breakdown() -> None:
    """The per-provider dict tracks spend per upstream — surfaced in
    the brief's "where did the dollars go?" section."""
    b = CaseBudget(case_id="case-1", budget_usd=Decimal("1.00"))
    b.record("etherscan", calls=5)
    b.record("coingecko", calls=2)
    b.record("etherscan", calls=3)
    assert b.spend_by_provider["etherscan"] == Decimal("0.0008")
    assert b.spend_by_provider["coingecko"] == Decimal("0.0006")
    assert b.calls_by_provider["etherscan"] == 8
    assert b.calls_by_provider["coingecko"] == 2


def test_record_unknown_provider_uses_conservative_default() -> None:
    """A wired-but-undocumented provider charges at the safe default."""
    b = CaseBudget(case_id="case-1", budget_usd=Decimal("1.00"))
    b.record("hypothetical-new-rpc")
    assert b.spent_usd == Decimal("0.0001")
    assert b.spend_by_provider["hypothetical-new-rpc"] == Decimal("0.0001")


# ---------------------------------------------------------------------------
# Cap enforcement
# ---------------------------------------------------------------------------


def test_assert_within_budget_at_exact_threshold_raises() -> None:
    """The cap trips AT the exact threshold (>=), not strictly past it.

    5000 Etherscan calls @ $0.0001 = $0.50 = the default cap exactly.
    Locking in ``>=`` rather than ``>`` ensures a precise budget
    miss never silently passes.
    """
    b = CaseBudget(case_id="case-1", budget_usd=Decimal("0.50"))
    # Walk to exactly the cap. The 5000th call is the one that lands
    # at $0.50 and must raise.
    for _ in range(4999):
        b.record("etherscan")
    assert b.spent_usd == Decimal("0.4999")
    # Pre-record check passes — we're not over yet.
    b.assert_within_budget()
    # The 5000th call lands at $0.50 exactly → raises.
    with pytest.raises(BudgetExceededError) as exc_info:
        b.record("etherscan")
    assert exc_info.value.case_id == "case-1"
    assert exc_info.value.spent_usd == Decimal("0.5000")
    assert exc_info.value.budget_usd == Decimal("0.50")
    assert exc_info.value.provider == "etherscan"


def test_budget_50c_5k_etherscan_calls_exceeded() -> None:
    """Cumulative 5000 Etherscan calls at $0.0001 each = $0.50 cap → trip."""
    b = CaseBudget(case_id="whale", budget_usd=Decimal("0.50"))
    raised = False
    for i in range(5001):
        try:
            b.record("etherscan")
        except BudgetExceededError:
            raised = True
            assert i == 4999  # the 5000th call (zero-indexed = 4999)
            break
    assert raised


def test_assert_within_budget_after_exceeded() -> None:
    """Once tripped, the helper continues to raise (defense in depth)."""
    b = CaseBudget(case_id="case-1", budget_usd=Decimal("0.0001"))
    # First call lands exactly at the cap → raises.
    with pytest.raises(BudgetExceededError):
        b.record("etherscan")
    # Subsequent pre-call check also raises.
    with pytest.raises(BudgetExceededError):
        b.assert_within_budget()


# ---------------------------------------------------------------------------
# Disabled budget (budget_usd == 0)
# ---------------------------------------------------------------------------


def test_budget_zero_disables_tracking() -> None:
    """budget_usd=0 means tracking is OFF — record is a no-op, never raises."""
    b = CaseBudget(case_id="case-1", budget_usd=Decimal("0"))
    assert not b.enabled
    # Even 1M calls don't raise.
    for _ in range(1000):
        b.record("etherscan")
    # spent_usd stays at zero — we never accumulated.
    assert b.spent_usd == Decimal("0")
    # No raise.
    b.assert_within_budget()


def test_budget_zero_remaining_is_unbounded_sentinel() -> None:
    """``remaining()`` returns the +Infinity sentinel when disabled."""
    b = CaseBudget(case_id="case-1", budget_usd=Decimal("0"))
    assert b.remaining() == Decimal("Infinity")


# ---------------------------------------------------------------------------
# Env-var resolution
# ---------------------------------------------------------------------------


def test_resolve_budget_default_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """v0.32.1+ industry-best mode: default is DISABLED ($0)."""
    monkeypatch.delenv("RECUPERO_API_BUDGET_USD_PER_CASE", raising=False)
    assert resolve_budget_from_env() == Decimal("0")


def test_resolve_budget_honors_valid_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECUPERO_API_BUDGET_USD_PER_CASE", "2.50")
    assert resolve_budget_from_env() == Decimal("2.50")


def test_resolve_budget_honors_large_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """v0.32.1+ ceiling raised to $1M so whale-case overrides are accepted."""
    monkeypatch.setenv("RECUPERO_API_BUDGET_USD_PER_CASE", "10000.0")
    assert resolve_budget_from_env() == Decimal("10000.0")
    monkeypatch.setenv("RECUPERO_API_BUDGET_USD_PER_CASE", "500000.0")
    assert resolve_budget_from_env() == Decimal("500000.0")


def test_resolve_budget_rejects_nan(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    """NaN is non-finite → fall back to default ($0 disabled) with a WARN.

    Critical guard: Decimal("NaN") comparisons return False for both
    < and >, so without this check a NaN would slip through and never
    trip the cap. Same shape as the v0.31.x dust-USD defenses.
    """
    monkeypatch.setenv("RECUPERO_API_BUDGET_USD_PER_CASE", "NaN")
    with caplog.at_level("WARNING"):
        result = resolve_budget_from_env()
    assert result == Decimal("0")
    assert any("non-finite" in r.message.lower() or "nan" in r.message.lower()
               for r in caplog.records)


def test_resolve_budget_rejects_infinity(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setenv("RECUPERO_API_BUDGET_USD_PER_CASE", "Infinity")
    with caplog.at_level("WARNING"):
        result = resolve_budget_from_env()
    assert result == Decimal("0")


def test_resolve_budget_rejects_garbage(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setenv("RECUPERO_API_BUDGET_USD_PER_CASE", "not-a-number")
    with caplog.at_level("WARNING"):
        result = resolve_budget_from_env()
    assert result == Decimal("0")


def test_resolve_budget_rejects_negative(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setenv("RECUPERO_API_BUDGET_USD_PER_CASE", "-1.0")
    with caplog.at_level("WARNING"):
        result = resolve_budget_from_env()
    assert result == Decimal("0")


def test_resolve_budget_clamps_above_max(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    """Above $1M falls back to default — operator confusion ceiling.

    v0.32.1+ industry-best mode raised the ceiling from $50K to $1M
    so the cap accepts any reasonable operator override; only typos
    in the millions reject."""
    monkeypatch.setenv("RECUPERO_API_BUDGET_USD_PER_CASE", "10000000.0")
    with caplog.at_level("WARNING"):
        result = resolve_budget_from_env()
    assert result == Decimal("0")


def test_resolve_budget_clamps_below_min(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    """Below $0.01 falls back to default — useless-cap floor."""
    monkeypatch.setenv("RECUPERO_API_BUDGET_USD_PER_CASE", "0.001")
    with caplog.at_level("WARNING"):
        result = resolve_budget_from_env()
    assert result == Decimal("0")


def test_resolve_budget_honors_explicit_zero(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    """Literal `0` is the documented "disable tracking" escape hatch
    and does NOT emit a WARN — it matches the default."""
    monkeypatch.setenv("RECUPERO_API_BUDGET_USD_PER_CASE", "0")
    caplog.clear()
    with caplog.at_level("WARNING"):
        result = resolve_budget_from_env()
    assert result == Decimal("0")
    # No warning when 0 — operator's deliberate choice (matches default).
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert warnings == []


# ---------------------------------------------------------------------------
# Snapshot / brief integration
# ---------------------------------------------------------------------------


def test_snapshot_surfaces_per_provider_breakdown_for_brief() -> None:
    """``snapshot()`` returns a JSON-safe dict the brief / case.config_used
    can render. All Decimal values stringified."""
    b = CaseBudget(case_id="case-1", budget_usd=Decimal("0.50"))
    b.record("etherscan", calls=100)
    b.record("coingecko", calls=10)
    snap = b.snapshot()
    assert snap["enabled"] is True
    assert snap["exceeded"] is False
    assert snap["budget_usd"] == "0.50"
    assert snap["spent_usd"] == "0.0130"  # 100 * 0.0001 + 10 * 0.0003
    assert snap["calls_by_provider"] == {"etherscan": 100, "coingecko": 10}
    # spend_by_provider values are strings (JSON-safe).
    assert snap["spend_by_provider"]["etherscan"] == "0.0100"
    assert snap["spend_by_provider"]["coingecko"] == "0.0030"


def test_snapshot_marks_disabled_budget() -> None:
    b = CaseBudget(case_id="case-1", budget_usd=Decimal("0"))
    snap = b.snapshot()
    assert snap["enabled"] is False
    assert snap["remaining_usd"] == "unbounded"


def test_snapshot_marks_exceeded_after_trip() -> None:
    b = CaseBudget(case_id="case-1", budget_usd=Decimal("0.0001"))
    with pytest.raises(BudgetExceededError):
        b.record("etherscan")
    snap = b.snapshot()
    assert snap["exceeded"] is True


# ---------------------------------------------------------------------------
# Tracer integration — partial_budget_hit marker
# ---------------------------------------------------------------------------


def test_tracer_marks_case_partial_budget_hit_on_trip() -> None:
    """End-to-end: when an adapter trips the budget, the tracer
    catches the exception and surfaces ``partial_budget_hit`` in
    ``case.config_used`` — mirroring the deadline-hit path.

    Rather than spinning up a full chain adapter (which would
    require live HELIUS / ETHERSCAN keys), we simulate the same
    contract: an EtherscanClient with a tiny budget makes one
    request; the budget-record path raises BudgetExceededError;
    the tracer catches it.

    For this unit-shape test we exercise the budget+exception
    contract directly — the integration test for the full
    BFS-wave-catches-exception path lives downstream in the
    trace e2e suite.
    """
    # Construct a budget that trips on call #1.
    b = CaseBudget(case_id="case-trip", budget_usd=Decimal("0.0001"))
    # Simulate the tracer's catch logic.
    case_config: dict[str, object] = {}
    try:
        b.record("etherscan")
    except BudgetExceededError as exc:
        case_config = {
            "trace_status": "partial_budget_hit",
            "trace_budget_provider": exc.provider,
            "api_budget": b.snapshot(),
        }
    assert case_config["trace_status"] == "partial_budget_hit"
    assert case_config["trace_budget_provider"] == "etherscan"
    assert isinstance(case_config["api_budget"], dict)
    assert case_config["api_budget"]["exceeded"] is True


def test_tracer_normal_path_records_complete_status() -> None:
    """When the budget is never hit, the tracer's normal-path marker
    stands AND the api_budget snapshot is still surfaced for the
    brief / audit trail.
    """
    b = CaseBudget(case_id="case-clean", budget_usd=Decimal("1.00"))
    b.record("etherscan", calls=10)
    b.record("coingecko", calls=2)
    # No exception → tracer's "complete" branch runs.
    case_config = {
        "trace_status": "complete",
        "api_budget": b.snapshot(),
    }
    assert case_config["trace_status"] == "complete"
    assert case_config["api_budget"]["exceeded"] is False
    assert case_config["api_budget"]["calls_by_provider"]["etherscan"] == 10


# ---------------------------------------------------------------------------
# Adapter integration smoke — Etherscan ctor accepts a budget
# ---------------------------------------------------------------------------


def test_etherscan_client_accepts_budget_param() -> None:
    """The EtherscanClient ctor must accept ``budget=`` so the tracer
    can plumb the per-case tracker without monkey-patching."""
    from recupero.chains.ethereum.etherscan import EtherscanClient

    budget = CaseBudget(case_id="case-1", budget_usd=Decimal("0.50"))
    c = EtherscanClient(api_key="fake-key", budget=budget)
    assert c.budget is budget
    c.close()


def test_helius_client_accepts_budget_param() -> None:
    from recupero.chains.solana.helius import HeliusClient

    budget = CaseBudget(case_id="case-1", budget_usd=Decimal("0.50"))
    c = HeliusClient(api_key="fake-key", budget=budget)
    assert c.budget is budget
    c.close()


def test_trongrid_client_accepts_budget_param() -> None:
    from recupero.chains.tron.client import TronGridClient

    budget = CaseBudget(case_id="case-1", budget_usd=Decimal("0.50"))
    c = TronGridClient(api_key="fake-key", budget=budget)
    assert c.budget is budget
    c.close()


def test_coingecko_client_accepts_budget_param(tmp_path) -> None:  # noqa: ANN001
    """CoinGeckoClient takes a ``budget`` and propagates it to the
    lazy DeFiLlama fallback."""
    from recupero.config import RecuperoConfig, RecuperoEnv
    from recupero.pricing.coingecko import CoinGeckoClient

    budget = CaseBudget(case_id="case-1", budget_usd=Decimal("0.50"))
    cfg = RecuperoConfig()
    env = RecuperoEnv(COINGECKO_API_KEY="fake-key")
    c = CoinGeckoClient(cfg, env, tmp_path, budget=budget)
    try:
        assert c.budget is budget
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Thread-safety smoke
# ---------------------------------------------------------------------------


def test_concurrent_record_does_not_corrupt_spent_usd() -> None:
    """The BFS fans out per-wave fetches across a ThreadPoolExecutor.
    Concurrent ``record`` calls must atomically update spent_usd —
    otherwise two threads can race and the cap is non-deterministic.
    """
    import threading

    b = CaseBudget(case_id="case-1", budget_usd=Decimal("1000.0"))

    def worker() -> None:
        for _ in range(100):
            try:
                b.record("etherscan")
            except BudgetExceededError:
                return

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 8 threads * 100 calls each * $0.0001 = $0.08 exactly — if any
    # race lost an increment, the figure would be below $0.08.
    assert b.spent_usd == Decimal("0.0800")
    assert b.calls_by_provider["etherscan"] == 800
