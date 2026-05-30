"""v0.34 Wave F — lock-mint candidate ordering uses the decoded chain first.

A decoder (e.g. the Orbiter amount-suffix decoder) that names the destination
chain is authoritative, so the lock-and-mint search should try it FIRST and
stop on a match — cutting latency and the coincidental-match surface a
multi-chain bridge's full candidate list creates. With no decoded chain the
original order is preserved exactly (no behavior change for other bridges).
"""

from __future__ import annotations

from recupero.trace.tracer import _ordered_lockmint_candidates


def test_decoded_chain_goes_first() -> None:
    out = _ordered_lockmint_candidates(
        "base", ["arbitrum", "optimism", "base", "polygon"]
    )
    assert out[0] == "base"
    assert out == ["base", "arbitrum", "optimism", "polygon"]  # deduped, order kept


def test_decoded_chain_not_in_candidates_is_still_prepended() -> None:
    # The decoder is authoritative even if the bridge's supports_to_chains
    # list didn't enumerate it.
    out = _ordered_lockmint_candidates("scroll", ["arbitrum", "optimism"])
    assert out == ["scroll", "arbitrum", "optimism"]


def test_no_decoded_chain_preserves_original_order() -> None:
    cands = ["arbitrum", "optimism", "base"]
    assert _ordered_lockmint_candidates(None, cands) == cands
    assert _ordered_lockmint_candidates("", cands) == cands
    assert _ordered_lockmint_candidates("   ", cands) == cands


def test_dedup_and_empty_dropped() -> None:
    out = _ordered_lockmint_candidates(
        "base", ["base", "", "arbitrum", "arbitrum", "base"]
    )
    assert out == ["base", "arbitrum"]


def test_only_decoded_when_no_candidates() -> None:
    assert _ordered_lockmint_candidates("base", []) == ["base"]


def test_empty_everything() -> None:
    assert _ordered_lockmint_candidates(None, []) == []
