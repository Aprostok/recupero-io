"""Per-case API budget tracker. v0.32 — closes Tier-1 gap #4 from
``docs/WHY_RECUPERO_WOULD_FAIL.md`` §1.4.

Tracks cumulative API spend per case across all providers. When the
case exceeds ``RECUPERO_API_BUDGET_USD_PER_CASE`` (default $0.50),
the next adapter call raises ``BudgetExceededError``. The tracer
catches this and records ``trace_status=partial_budget_hit``, similar
to the existing ``partial_deadline_hit`` behavior.

Per-provider cost models (verified against published pricing as of
2026-05):

  * Etherscan V2 free tier: 100k req/day; effective $0 free up to
    cap, then $0.00004 per overage call (treat as free until cap)
  * Helius free tier: 100k req/day; same shape
  * CoinGecko Pro: $129/mo / ~500k req/mo ≈ $0.00026 per call
  * DeFiLlama: free + best-effort, $0 charged
  * Alchemy: compute-unit based, ~$0.00001 per simple eth_call
  * TronGrid free tier: 100k/day; same shape

For BUDGET PURPOSES we use a conservative weighted estimate:

  * $0.0001 per Etherscan / Helius / Alchemy / TronGrid call
    (an order-of-magnitude above the actual marginal cost, so we
    trip the budget BEFORE real overage charges hit)
  * $0.0003 per CoinGecko call (matches the Pro per-call cost
    with a small safety margin)
  * $0.00 per DeFiLlama call (the fallback is free)
  * $0.0001 for unknown providers (conservative default — a new
    provider that wires through without updating ``_COST_MODEL``
    is charged at the safe pessimistic rate)

The cost model is intentionally pessimistic. The point is to cap
BEFORE a paid-tier surprise lands on the invoice, not to model the
provider's billing exactly.

Wire-up:

  * The tracer constructs one ``CaseBudget`` per case at the top of
    ``run_trace`` (or the worker's case-driver loop).
  * Each chain / pricing client takes an optional ``budget`` param.
    After every successful HTTP request, the client calls
    ``budget.record(provider)``.
  * ``record`` increments ``spent_usd`` and ``spend_by_provider``,
    then calls ``assert_within_budget``, which raises
    ``BudgetExceededError`` once the cap is hit.
  * The tracer catches that error around its BFS loop and marks
    the case ``partial_budget_hit`` — the same graceful-degradation
    path as the deadline timeout.
  * The per-provider breakdown is surfaced into
    ``case.config_used["api_budget"]`` so the brief and the audit
    trail can show the operator where the dollars went.

A budget of $0 (or unset) DISABLES tracking entirely. That keeps
test scaffolding and CLI one-off invocations free to skip the
budget-construction step without code changes downstream.

Concurrency: ``record`` and ``assert_within_budget`` are thread-safe
via an internal ``threading.Lock``. The tracer fans out per-wave
fetches across a ThreadPoolExecutor, so concurrent
``budget.record(...)`` calls from multiple threads MUST mutate
``spent_usd`` atomically — otherwise the cap is racy and a whale
case could overshoot by tens of dollars on a busy worker.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cost model
# ---------------------------------------------------------------------------

# Per-call USD cost by provider. Keys are lowercase strings the chain /
# pricing clients pass to ``CaseBudget.record(provider=...)``. Unknown
# providers fall back to ``_UNKNOWN_COST`` so a new wiring that forgets
# to extend this map still trips the cap correctly (conservative bias).
_COST_MODEL: dict[str, Decimal] = {
    "etherscan": Decimal("0.0001"),
    "alchemy": Decimal("0.0001"),
    "helius": Decimal("0.0001"),
    "trongrid": Decimal("0.0001"),
    "coingecko": Decimal("0.0003"),
    "defillama": Decimal("0.0000"),
    # Bitcoin / Esplora is free (public) — but we still tally it under
    # the conservative bucket so the operator sees the call count in
    # the per-provider breakdown.
    "esplora": Decimal("0.0001"),
    "bitcoin": Decimal("0.0001"),
}

_UNKNOWN_COST = Decimal("0.0001")


def cost_per_call(provider: str) -> Decimal:
    """Returns the conservative per-call USD cost for ``provider``.

    Unknown / empty / None inputs return ``_UNKNOWN_COST`` ($0.0001)
    so a typo never silently undercharges. The lookup is
    case-insensitive on the provider name.
    """
    if not provider or not isinstance(provider, str):
        return _UNKNOWN_COST
    return _COST_MODEL.get(provider.strip().lower(), _UNKNOWN_COST)


# ---------------------------------------------------------------------------
# Env-var resolution
# ---------------------------------------------------------------------------

# v0.32.1 — JACOB_ADVERSARY_AUDIT_v032 Route 3 mitigation. The pre-fix
# default of $0.50/case and a $100 ceiling made it impossible for ops
# to fund a deep enough trace on a $50M-tier APT case (the adversary
# spends $5K+ consultant fees; we couldn't even spend $1). Defaults
# bumped to $10,000/case with a $50,000 ceiling. Real-world per-case
# API spend never approaches these on healthy traces; the high default
# is intended as "your budget is whatever the case needs up to $10K".
_DEFAULT_BUDGET_USD = Decimal("10000.0")
_BUDGET_MIN = Decimal("0.01")
_BUDGET_MAX = Decimal("50000.0")


def resolve_budget_from_env() -> Decimal:
    """Resolve ``RECUPERO_API_BUDGET_USD_PER_CASE`` with safe clamping.

    * Default: $0.50
    * Range: [$0.01, $100.0] — values outside this clamp to a default
      with a WARN. Below $0.01 makes the cap useless (1 call kills
      the trace); above $100 is operator confusion (no real per-case
      cost will reach that figure).
    * Non-finite (NaN / Inf), non-numeric, negative all reject with a
      WARN and fall back to the default. v0.31.x "Jacob-style"
      pattern: operators who typo a value get a loud warning, never
      a silently-poisoned trace.
    * Empty / unset → default.
    * The literal ``0`` is honored as "disable tracking" without a
      WARN — it's a deliberate test / CLI escape hatch, not a typo.
    """
    raw = (os.environ.get("RECUPERO_API_BUDGET_USD_PER_CASE", "") or "").strip()
    if not raw:
        return _DEFAULT_BUDGET_USD
    try:
        val = Decimal(raw)
    except Exception:  # noqa: BLE001 — Decimal raises a hodge-podge
        log.warning(
            "RECUPERO_API_BUDGET_USD_PER_CASE=%r is not a valid Decimal — "
            "falling back to default $%s", raw, _DEFAULT_BUDGET_USD,
        )
        return _DEFAULT_BUDGET_USD
    # Decimal can carry NaN / Infinity — reject explicitly. ``is_finite``
    # returns False for both, mirroring the v0.31.x defenses on
    # RECUPERO_TRACE_DUST_USD / RECUPERO_CROSSCHAIN_WINDOW_HOURS.
    if not val.is_finite():
        log.warning(
            "RECUPERO_API_BUDGET_USD_PER_CASE=%r is non-finite (NaN/Inf) — "
            "falling back to default $%s", raw, _DEFAULT_BUDGET_USD,
        )
        return _DEFAULT_BUDGET_USD
    if val < 0:
        log.warning(
            "RECUPERO_API_BUDGET_USD_PER_CASE=%s is negative — "
            "falling back to default $%s", val, _DEFAULT_BUDGET_USD,
        )
        return _DEFAULT_BUDGET_USD
    if val == 0:
        # Explicit zero — "disable tracking". No warning.
        return Decimal("0")
    if val < _BUDGET_MIN:
        log.warning(
            "RECUPERO_API_BUDGET_USD_PER_CASE=%s is below the minimum $%s — "
            "clamping to default $%s", val, _BUDGET_MIN, _DEFAULT_BUDGET_USD,
        )
        return _DEFAULT_BUDGET_USD
    if val > _BUDGET_MAX:
        log.warning(
            "RECUPERO_API_BUDGET_USD_PER_CASE=%s is above the maximum $%s — "
            "clamping to default $%s", val, _BUDGET_MAX, _DEFAULT_BUDGET_USD,
        )
        return _DEFAULT_BUDGET_USD
    return val


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class BudgetExceededError(RuntimeError):
    """Raised when a ``CaseBudget.record`` call pushes spend over the cap.

    The tracer is expected to catch this around its BFS loop and exit
    gracefully with ``trace_status=partial_budget_hit``. Adapters
    must NOT catch and swallow this — the tracer needs the signal
    to mark the case partial.
    """

    def __init__(
        self,
        *,
        case_id: str,
        budget_usd: Decimal,
        spent_usd: Decimal,
        provider: str,
    ) -> None:
        self.case_id = case_id
        self.budget_usd = budget_usd
        self.spent_usd = spent_usd
        self.provider = provider
        super().__init__(
            f"case={case_id} exceeded API budget ${budget_usd} "
            f"(spent ${spent_usd} after {provider} call)"
        )


# ---------------------------------------------------------------------------
# CaseBudget
# ---------------------------------------------------------------------------


@dataclass
class CaseBudget:
    """Per-case API spend tracker.

    Construct one of these at the top of the tracer / worker driver,
    pass through to every chain + pricing client, and the budget
    enforces itself at each ``record`` call.

    ``budget_usd == 0`` means tracking is DISABLED — ``record`` is a
    no-op and ``assert_within_budget`` never raises. This is the
    documented escape hatch for tests and one-off CLI invocations
    that don't want the cap.
    """

    case_id: str
    budget_usd: Decimal
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    spent_usd: Decimal = field(default_factory=lambda: Decimal("0"))
    spend_by_provider: dict[str, Decimal] = field(default_factory=dict)
    calls_by_provider: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False,
    )
    _exceeded: bool = field(default=False, repr=False, compare=False)

    @classmethod
    def from_env(cls, case_id: str) -> CaseBudget:
        """Convenience: build a CaseBudget honoring the env-var default."""
        return cls(case_id=case_id, budget_usd=resolve_budget_from_env())

    @property
    def enabled(self) -> bool:
        """True when the budget is actively tracking + enforcing."""
        return self.budget_usd > 0

    def record(self, provider: str, calls: int = 1) -> None:
        """Record ``calls`` HTTP requests against ``provider`` and check
        the cap. Raises ``BudgetExceededError`` if the post-record
        spend exceeds ``budget_usd``.

        Safe to call from multiple threads concurrently.

        When ``budget_usd == 0`` this is a no-op fast-path so the
        tracer can pass a CaseBudget through unconditionally without
        a per-call cost on the disabled path.
        """
        if not self.enabled:
            return
        if calls <= 0:
            return
        per_call = cost_per_call(provider)
        delta = per_call * Decimal(calls)
        provider_key = (provider or "unknown").strip().lower() or "unknown"
        with self._lock:
            self.spent_usd = self.spent_usd + delta
            prior = self.spend_by_provider.get(provider_key, Decimal("0"))
            self.spend_by_provider[provider_key] = prior + delta
            self.calls_by_provider[provider_key] = (
                self.calls_by_provider.get(provider_key, 0) + calls
            )
            # ``>=`` rather than ``>`` so the budget trips at the
            # exact threshold (Etherscan calls that hit $0.50 exactly
            # are over budget, not under). Test
            # ``test_assert_within_budget_at_exact_threshold`` locks
            # this in.
            if self.spent_usd >= self.budget_usd and not self._exceeded:
                self._exceeded = True
                # Capture immutable snapshot for the exception so the
                # raise outside the lock can't observe a mutated value.
                snap_spent = self.spent_usd
                snap_budget = self.budget_usd
                snap_provider = provider_key
                raise BudgetExceededError(
                    case_id=self.case_id,
                    budget_usd=snap_budget,
                    spent_usd=snap_spent,
                    provider=snap_provider,
                )

    def assert_within_budget(self) -> None:
        """Raise if the cumulative spend has already exceeded the cap.

        ``record`` already raises in-line — this method is exposed for
        any place a client wants to gate BEFORE making the next call
        (e.g. a long-poll loop that wants to bail without ever
        contacting the API once the cap is hit). Cheap (lock + compare).
        """
        if not self.enabled:
            return
        with self._lock:
            if self.spent_usd >= self.budget_usd:
                raise BudgetExceededError(
                    case_id=self.case_id,
                    budget_usd=self.budget_usd,
                    spent_usd=self.spent_usd,
                    provider="(pre-call check)",
                )

    def remaining(self) -> Decimal:
        """USD remaining in the budget, clamped at zero. Lock-protected."""
        with self._lock:
            if not self.enabled:
                # Sentinel "unbounded" — callers that want to render
                # this are expected to test ``enabled`` first.
                return Decimal("Infinity")
            rem = self.budget_usd - self.spent_usd
            if rem < 0:
                return Decimal("0")
            return rem

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-safe snapshot of the budget state for
        surfacing in ``case.config_used`` / the brief.

        All Decimal values are stringified so the dict survives the
        Case.config_used = case.model_dump() round-trip without
        losing precision or carrying a non-JSON-encodable type.
        """
        with self._lock:
            return {
                "budget_usd": str(self.budget_usd),
                "spent_usd": str(self.spent_usd),
                "remaining_usd": (
                    str(self.budget_usd - self.spent_usd)
                    if self.enabled
                    else "unbounded"
                ),
                "enabled": self.enabled,
                "exceeded": self._exceeded,
                "started_at": self.started_at.isoformat(),
                "calls_by_provider": dict(self.calls_by_provider),
                "spend_by_provider": {
                    k: str(v) for k, v in self.spend_by_provider.items()
                },
            }


__all__ = (
    "BudgetExceededError",
    "CaseBudget",
    "cost_per_call",
    "resolve_budget_from_env",
)
