"""Burn-sink surfacing in the trace report (dormant-capability sweep).

Activates the complete-but-dormant ``trace.burn_sinks`` registry: funds sent to
a provably-unspendable address (0x0 / 0xdEaD / chain incinerator) are summarized
in a guarded "Section 9 — Burned / Provably-Destroyed Funds" so the recoverable
total isn't overstated.

Pins:
  * ``burn_label`` registry lookup (EVM case-insensitive; cross-chain rejected);
  * ``_build_burn_sinks`` aggregation over case.transfers (pure, no fetch),
    the mixer-exclusion (Tornado is in BOTH registries → handled as a mixer
    terminal, never double-counted as a burn), non-finite-USD guard, and the
    ``None``-when-empty contract (so the StrictUndefined template omits it).
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

from recupero.trace.burn_sinks import burn_label
from recupero.worker._trace_report import _build_burn_sinks

_ZERO = "0x0000000000000000000000000000000000000000"
_DEAD = "0x000000000000000000000000000000000000dEaD"  # mixed case on purpose
_TORNADO = "0xa160cdab225685da1d56aa342ad8841c3b53f291"  # mixer AND in burn registry
_NORMAL = "0x" + "11" * 20


def _t(to: str, *, chain: str = "ethereum", usd: str | None = "100"):
    return SimpleNamespace(
        to_address=to,
        chain=SimpleNamespace(value=chain),
        usd_value_at_tx=(Decimal(usd) if usd is not None else None),
    )


def _case(transfers):
    return SimpleNamespace(transfers=transfers)


# ----- burn_label -----

def test_burn_label_zero_address() -> None:
    assert burn_label(_ZERO, "ethereum") == "zero-address"


def test_burn_label_dead_case_insensitive_on_evm() -> None:
    # mixed-case 0xdEaD lowercases to a registry key. (The registry stores both
    # a "dead-address" and a "dead-shortform" entry on the same lowercased key,
    # so either label is acceptable — the point is the mixed-case form resolves
    # to a dead-burn classification, proving EVM case-insensitivity.)
    assert burn_label(_DEAD, "ethereum") in ("dead-address", "dead-shortform")


def test_burn_label_tron_burn_case_sensitive() -> None:
    assert burn_label("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb", "tron") == "tron-burn"


def test_burn_label_non_burn_is_none() -> None:
    assert burn_label(_NORMAL, "ethereum") is None


def test_burn_label_cross_chain_rejected() -> None:
    # the EVM zero address has no meaning on bitcoin → not a burn there
    assert burn_label(_ZERO, "bitcoin") is None


def test_burn_label_garbage_is_none() -> None:
    assert burn_label(None, "ethereum") is None
    assert burn_label(_ZERO, None) is None


# ----- _build_burn_sinks -----

def test_build_burn_sinks_detects_zero_address() -> None:
    out = _build_burn_sinks(_case([_t(_ZERO, usd="100")]))
    assert out is not None and len(out) == 1
    row = out[0]
    assert row["address"] == _ZERO
    assert row["burn_type"] == "zero-address"
    assert row["chain"] == "ethereum"
    assert row["count"] == 1
    assert "100" in row["total_usd"]


def test_build_burn_sinks_aggregates_and_sorts_by_value() -> None:
    out = _build_burn_sinks(_case([
        _t(_ZERO, usd="100"), _t(_ZERO, usd="50"),   # same burn → aggregate
        _t(_DEAD, usd="500"),                          # bigger → sorts first
    ]))
    assert out is not None and len(out) == 2
    assert out[0]["address"] == _DEAD                  # $500 burn sorts first
    assert "500" in out[0]["total_usd"]
    zero_row = next(r for r in out if r["burn_type"] == "zero-address")
    assert zero_row["count"] == 2                      # 100 + 50 aggregated


def test_build_burn_sinks_excludes_mixer_pool() -> None:
    # Tornado is in the burn registry too, but it's a MIXER terminal — must NOT
    # be double-counted as a burn.
    assert _build_burn_sinks(_case([_t(_TORNADO, usd="1000")])) is None


def test_build_burn_sinks_none_when_no_burns() -> None:
    assert _build_burn_sinks(_case([_t(_NORMAL, usd="100")])) is None
    assert _build_burn_sinks(_case([])) is None


def test_build_burn_sinks_non_finite_usd_guarded() -> None:
    # a NaN usd value must not poison the total (counted, value skipped)
    out = _build_burn_sinks(_case([
        _t(_ZERO, usd="100"),
        SimpleNamespace(to_address=_ZERO,
                        chain=SimpleNamespace(value="ethereum"),
                        usd_value_at_tx=Decimal("NaN")),
    ]))
    assert out is not None and out[0]["count"] == 2
    assert "100" in out[0]["total_usd"]  # NaN did not corrupt the sum
