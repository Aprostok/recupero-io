"""v0.34: ``RECUPERO_ETHERSCAN_RPS`` env knob for the Etherscan V2 client rate.

Lets a paid Etherscan tier be driven at full throughput by setting one env var
(no code change). The default stays free-tier-safe on purpose — raising it
would only add 429 backoffs on the free tier and make traces slower, so paid
throughput is opt-in via the env var.
"""

from __future__ import annotations

from recupero.chains.evm.adapter import (
    _DEFAULT_ETHERSCAN_RPS,
    _MAX_ETHERSCAN_RPS,
    _resolve_etherscan_rps,
)


def test_default_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_ETHERSCAN_RPS", raising=False)
    assert _resolve_etherscan_rps() == _DEFAULT_ETHERSCAN_RPS


def test_paid_tier_override(monkeypatch) -> None:
    """A paid ~20 rps tier: set the env var, get 20."""
    monkeypatch.setenv("RECUPERO_ETHERSCAN_RPS", "20")
    assert _resolve_etherscan_rps() == 20.0


def test_clamped_to_max(monkeypatch) -> None:
    """An absurd value is clamped to the ceiling, never unbounded."""
    monkeypatch.setenv("RECUPERO_ETHERSCAN_RPS", "100000")
    assert _resolve_etherscan_rps() == _MAX_ETHERSCAN_RPS


def test_bad_or_nonpositive_values_fall_back_to_default(monkeypatch) -> None:
    """Empty / whitespace / non-numeric / zero / negative / NaN all fall back
    to the free-tier-safe default rather than disabling or breaking the rate
    limiter."""
    for bad in ("", "   ", "abc", "0", "-3", "nan"):
        monkeypatch.setenv("RECUPERO_ETHERSCAN_RPS", bad)
        assert _resolve_etherscan_rps() == _DEFAULT_ETHERSCAN_RPS, bad
