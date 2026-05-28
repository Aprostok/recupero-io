"""Tests for v0.31.4 output-integrity INVARIANTS F-J.

These invariants validate the v0.31.x brief JSON sections that the
gap-audit identified as uncovered by INVARIANTS A-E:

  F. MEV_SIGNALS — confidence/signal_type/tx_hash well-formedness.
  G. INDIRECT_EXPOSURE_V031 — exposure score / hop / USD range.
  H. WALLET_CLUSTERS — cluster_id format, heuristic enum, disjoint
     members, explicit-label suppression.
  I. CEX_CONTINUITY_LEADS — lead_only framing + bounded numeric
     ranges + top-5 cap + no destination_* keys.
  J. CROSS_CHAIN_HANDOFFS.decoded_* — internal consistency between
     decoded_confidence and decoded_destination_*.

Test strategy per invariant:
  * Happy path: well-formed section produces zero violations.
  * Each rule trips on a targeted malformation.
  * Empty / missing section is NOT a violation.
  * NaN/Inf in numeric fields is caught.
  * Top-N cap enforcement caught (where applicable).

Final cross-invariant test: a brief with all v0.31.x sections
well-formed passes ALL invariants together.
"""

from __future__ import annotations

import math

import pytest

from recupero.validators.output_integrity import (
    _check_cex_continuity_leads_framed,
    _check_decoded_handoffs_consistent,
    _check_indirect_exposure_v031_scores_in_range,
    _check_mev_signals_well_formed,
    _check_wallet_clusters_contract,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ok_mev_brief():
    return {
        "MEV_SIGNALS": {
            "detected": True,
            "signal_count": 2,
            "suppressed_low_confidence_count": 0,
            "signals": [
                {
                    "tx_hash": "0x" + "a" * 64,
                    "signal_type": "flashbots_bundle",
                    "confidence": 0.95,
                    "forensic_note": "Bundle tx, gasPrice=0",
                    "address": None,
                    "builder_name": "Flashbots: Builder",
                },
                {
                    "tx_hash": "0x" + "b" * 64,
                    "signal_type": "sandwich",
                    "confidence": 0.7,
                    "forensic_note": "Sandwich detected",
                    "address": "0x" + "1" * 40,
                    "builder_name": None,
                },
            ],
        }
    }


def _ok_exposure_brief():
    return {
        "INDIRECT_EXPOSURE_V031": {
            "top_addresses": [
                {
                    "address": "0x" + "a" * 40,
                    "primary_label_category": "mixer",
                    "hops_from_victim": 2,
                    "exposure_score": 0.85,
                    "total_usd_flow": "$1,000.00",
                },
                {
                    "address": "0x" + "b" * 40,
                    "primary_label_category": "unknown",
                    "hops_from_victim": None,
                    "exposure_score": 0.3,
                    "total_usd_flow": None,
                },
            ],
            "summary": {
                "scored_addresses": 2,
                "addresses_above_surface_threshold": 2,
                "surface_threshold": 0.1,
                "max_hops": 4,
            },
        }
    }


def _ok_clusters_brief():
    return {
        "WALLET_CLUSTERS": {
            "clusters": [
                {
                    "cluster_id": "cluster_abcd1234",
                    "addresses": ["0x" + "1" * 40, "0x" + "2" * 40],
                    "size": 2,
                    "confidence": "high",
                    "heuristics": ["co_spending"],
                    "evidence": [{
                        "heuristic": "co_spending",
                        "confidence": "high",
                        "details": "same-tx inputs",
                    }],
                },
                {
                    "cluster_id": "cluster_deadbeef",
                    "addresses": ["0x" + "3" * 40, "0x" + "4" * 40],
                    "size": 2,
                    "confidence": "medium",
                    "heuristics": ["common_funding"],
                    "evidence": [{
                        "heuristic": "common_funding",
                        "confidence": "medium",
                        "details": "same funder",
                    }],
                },
            ]
        }
    }


def _ok_cex_continuity_brief():
    return {
        "CEX_CONTINUITY_LEADS": [
            {
                "lead_only": True,
                "framing": "LEAD ONLY — same-hot-wallet correlation",
                "confidence": "low",
                "deposit_tx_hash": "0x" + "a" * 64,
                "deposit_address": "0x" + "1" * 40,
                "deposit_amount_usd": "$10,000.00",
                "deposit_token_symbol": "USDT",
                "deposit_block_time": "2026-01-01T00:00:00Z",
                "cex_name": "Coinbase",
                "candidate_withdrawal_tx_hash": "0x" + "b" * 64,
                "candidate_withdrawal_to": "0x" + "2" * 40,
                "candidate_amount_usd": "$10,050.00",
                "candidate_block_time": "2026-01-01T02:00:00Z",
                "delta_hours": 2.0,
                "amount_match_pct": 0.005,
                "investigator_note": "Subpoena the CEX",
            }
        ]
    }


def _ok_decoded_handoffs_brief():
    return {
        "CROSS_CHAIN_HANDOFFS": [
            {
                "source_chain": "ethereum",
                "tx_hash": "0x" + "a" * 64,
                "bridge_name": "Stargate",
                "decoded_destination_chain": "solana",
                "decoded_destination_address": (
                    "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
                ),
                "decoded_confidence": "high",
            },
            {
                "source_chain": "ethereum",
                "tx_hash": "0x" + "b" * 64,
                "bridge_name": "Hop",
                "decoded_destination_chain": "arbitrum",
                "decoded_destination_address": None,
                "decoded_confidence": "medium",
            },
            {
                "source_chain": "ethereum",
                "tx_hash": "0x" + "c" * 64,
                "bridge_name": "Synapse",
                "decoded_destination_chain": None,
                "decoded_destination_address": None,
                "decoded_confidence": "low",
            },
            # Handoff without decoded_confidence — entirely skipped.
            {
                "source_chain": "ethereum",
                "tx_hash": "0x" + "d" * 64,
                "bridge_name": "Unknown",
            },
        ]
    }


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT F — MEV signals
# ─────────────────────────────────────────────────────────────────────────────


def test_invariant_f_mev_happy_path():
    assert _check_mev_signals_well_formed(_ok_mev_brief()) == []


def test_invariant_f_mev_missing_section_is_not_violation():
    assert _check_mev_signals_well_formed({}) == []
    assert _check_mev_signals_well_formed({"MEV_SIGNALS": None}) == []


def test_invariant_f_mev_empty_signals_list_is_not_violation():
    brief = {"MEV_SIGNALS": {"detected": False, "signals": []}}
    assert _check_mev_signals_well_formed(brief) == []


def test_invariant_f_mev_confidence_out_of_range():
    brief = _ok_mev_brief()
    brief["MEV_SIGNALS"]["signals"][0]["confidence"] = 1.5
    violations = _check_mev_signals_well_formed(brief)
    assert any("confidence" in v.detail for v in violations)


def test_invariant_f_mev_confidence_nan_inf_caught():
    for bad in (float("nan"), float("inf"), float("-inf"), "0.9", None):
        brief = _ok_mev_brief()
        brief["MEV_SIGNALS"]["signals"][0]["confidence"] = bad
        violations = _check_mev_signals_well_formed(brief)
        assert violations, f"NaN/Inf/string conf {bad!r} should violate"
        assert all(v.severity in ("high", "critical") for v in violations)


def test_invariant_f_mev_confidence_below_render_floor():
    brief = _ok_mev_brief()
    # 0.3 < 0.5 render floor — surfacing this entry in signals[] is a bug.
    brief["MEV_SIGNALS"]["signals"][0]["confidence"] = 0.3
    violations = _check_mev_signals_well_formed(brief)
    assert any("render floor" in v.detail for v in violations)


def test_invariant_f_mev_unknown_signal_type():
    brief = _ok_mev_brief()
    brief["MEV_SIGNALS"]["signals"][0]["signal_type"] = "nope"
    violations = _check_mev_signals_well_formed(brief)
    assert any("signal_type" in v.detail for v in violations)


def test_invariant_f_mev_bad_tx_hash():
    brief = _ok_mev_brief()
    brief["MEV_SIGNALS"]["signals"][0]["tx_hash"] = "0xnotahash"
    violations = _check_mev_signals_well_formed(brief)
    assert any(
        "0x[0-9a-fA-F]{64}" in v.detail
        or "tx hash" in v.detail.lower()
        for v in violations
    )


def test_invariant_f_mev_sandwich_requires_outer_address():
    brief = _ok_mev_brief()
    brief["MEV_SIGNALS"]["signals"][1]["address"] = None
    brief["MEV_SIGNALS"]["signals"][1].pop("outer_address", None)
    violations = _check_mev_signals_well_formed(brief)
    assert any("sandwich" in v.detail for v in violations)


def test_invariant_f_mev_sandwich_rejects_zero_outer_address():
    brief = _ok_mev_brief()
    brief["MEV_SIGNALS"]["signals"][1]["address"] = "0x" + "0" * 40
    violations = _check_mev_signals_well_formed(brief)
    assert any("sandwich" in v.detail for v in violations)


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT G — Indirect exposure scores in range
# ─────────────────────────────────────────────────────────────────────────────


def test_invariant_g_exposure_happy_path():
    assert _check_indirect_exposure_v031_scores_in_range(
        _ok_exposure_brief()
    ) == []


def test_invariant_g_exposure_missing_section_is_not_violation():
    assert _check_indirect_exposure_v031_scores_in_range({}) == []
    assert _check_indirect_exposure_v031_scores_in_range(
        {"INDIRECT_EXPOSURE_V031": None}
    ) == []


def test_invariant_g_exposure_score_out_of_range():
    for bad in (-0.1, 1.5, 2.0):
        brief = _ok_exposure_brief()
        brief["INDIRECT_EXPOSURE_V031"]["top_addresses"][0]["exposure_score"] = bad
        violations = _check_indirect_exposure_v031_scores_in_range(brief)
        assert any("exposure_score" in v.detail for v in violations), bad


def test_invariant_g_exposure_score_nan_inf_caught():
    for bad in (float("nan"), float("inf")):
        brief = _ok_exposure_brief()
        brief["INDIRECT_EXPOSURE_V031"]["top_addresses"][0]["exposure_score"] = bad
        violations = _check_indirect_exposure_v031_scores_in_range(brief)
        assert violations
        assert any("exposure_score" in v.detail for v in violations)


def test_invariant_g_exposure_hops_out_of_range():
    brief = _ok_exposure_brief()
    brief["INDIRECT_EXPOSURE_V031"]["top_addresses"][0]["hops_from_victim"] = 99
    violations = _check_indirect_exposure_v031_scores_in_range(brief)
    assert any("hops_from_victim" in v.detail for v in violations)


def test_invariant_g_exposure_hops_negative():
    brief = _ok_exposure_brief()
    brief["INDIRECT_EXPOSURE_V031"]["top_addresses"][0]["hops_from_victim"] = -1
    violations = _check_indirect_exposure_v031_scores_in_range(brief)
    assert any("hops_from_victim" in v.detail for v in violations)


def test_invariant_g_exposure_usd_nan_caught():
    brief = _ok_exposure_brief()
    brief["INDIRECT_EXPOSURE_V031"]["top_addresses"][0]["total_usd_flow"] = "$NaN"
    violations = _check_indirect_exposure_v031_scores_in_range(brief)
    assert any("total_usd_flow" in v.detail for v in violations)


def test_invariant_g_exposure_top_n_cap_enforced():
    brief = _ok_exposure_brief()
    # 11 entries — top-N cap is 10.
    entries = [
        {
            "address": f"0x{i:040x}",
            "primary_label_category": "unknown",
            "hops_from_victim": 1,
            "exposure_score": 0.5,
            "total_usd_flow": None,
        }
        for i in range(11)
    ]
    brief["INDIRECT_EXPOSURE_V031"]["top_addresses"] = entries
    violations = _check_indirect_exposure_v031_scores_in_range(brief)
    assert any("top-N cap" in v.detail for v in violations)


def test_invariant_g_exposure_address_uppercase_evm_rejected():
    brief = _ok_exposure_brief()
    # An EVM address with mixed case is not canonical (the codebase
    # uses lowercase-only canonical keys).
    brief["INDIRECT_EXPOSURE_V031"]["top_addresses"][0]["address"] = (
        "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
    )
    violations = _check_indirect_exposure_v031_scores_in_range(brief)
    assert any("lowercase canonical" in v.detail for v in violations)


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT H — Wallet clusters
# ─────────────────────────────────────────────────────────────────────────────


def test_invariant_h_clusters_happy_path():
    assert _check_wallet_clusters_contract(_ok_clusters_brief()) == []


def test_invariant_h_clusters_missing_section_is_not_violation():
    assert _check_wallet_clusters_contract({}) == []
    assert _check_wallet_clusters_contract({"WALLET_CLUSTERS": None}) == []
    assert _check_wallet_clusters_contract(
        {"WALLET_CLUSTERS": {"clusters": []}}
    ) == []


def test_invariant_h_clusters_bad_cluster_id():
    brief = _ok_clusters_brief()
    brief["WALLET_CLUSTERS"]["clusters"][0]["cluster_id"] = "C-1"
    violations = _check_wallet_clusters_contract(brief)
    assert any("cluster_id" in v.detail for v in violations)


def test_invariant_h_clusters_bad_confidence():
    brief = _ok_clusters_brief()
    brief["WALLET_CLUSTERS"]["clusters"][0]["confidence"] = "definitely"
    violations = _check_wallet_clusters_contract(brief)
    assert any("confidence" in v.detail for v in violations)


def test_invariant_h_clusters_unknown_heuristic():
    brief = _ok_clusters_brief()
    brief["WALLET_CLUSTERS"]["clusters"][0]["heuristics"] = ["wild_guess"]
    # Need to also clear evidence so the validator doesn't pull from there.
    brief["WALLET_CLUSTERS"]["clusters"][0]["evidence"] = []
    violations = _check_wallet_clusters_contract(brief)
    assert any("heuristic" in v.detail for v in violations)


def test_invariant_h_clusters_disjoint_violation():
    brief = _ok_clusters_brief()
    # Reassign the shared addr "0x...1" to cluster 2 — should trip
    # disjointness.
    brief["WALLET_CLUSTERS"]["clusters"][1]["addresses"] = [
        "0x" + "1" * 40, "0x" + "5" * 40,
    ]
    violations = _check_wallet_clusters_contract(brief)
    assert any("disjoint" in v.detail for v in violations)


def test_invariant_h_clusters_empty_members():
    brief = _ok_clusters_brief()
    brief["WALLET_CLUSTERS"]["clusters"][0]["addresses"] = []
    violations = _check_wallet_clusters_contract(brief)
    assert any("member" in v.detail for v in violations)


def test_invariant_h_clusters_forbidden_label_member():
    brief = _ok_clusters_brief()
    # Tag the cluster's first address as a bridge in the LABELS map.
    brief["LABELS"] = {
        "0x" + "1" * 40: {"category": "bridge"},
    }
    violations = _check_wallet_clusters_contract(brief)
    assert any(
        "forbidden label" in v.detail.lower()
        or "explicit-label suppression" in v.detail
        for v in violations
    )


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT I — CEX continuity leads
# ─────────────────────────────────────────────────────────────────────────────


def test_invariant_i_cex_continuity_happy_path():
    assert _check_cex_continuity_leads_framed(_ok_cex_continuity_brief()) == []


def test_invariant_i_cex_continuity_missing_section_is_not_violation():
    assert _check_cex_continuity_leads_framed({}) == []
    assert _check_cex_continuity_leads_framed(
        {"CEX_CONTINUITY_LEADS": None}
    ) == []
    assert _check_cex_continuity_leads_framed(
        {"CEX_CONTINUITY_LEADS": []}
    ) == []


def test_invariant_i_cex_lead_only_must_be_true():
    brief = _ok_cex_continuity_brief()
    brief["CEX_CONTINUITY_LEADS"][0]["lead_only"] = False
    violations = _check_cex_continuity_leads_framed(brief)
    assert any("lead_only" in v.detail for v in violations)


def test_invariant_i_cex_confidence_must_be_low():
    for bad in ("high", "medium", "", None):
        brief = _ok_cex_continuity_brief()
        brief["CEX_CONTINUITY_LEADS"][0]["confidence"] = bad
        violations = _check_cex_continuity_leads_framed(brief)
        assert any("confidence" in v.detail for v in violations), bad


def test_invariant_i_cex_amount_match_out_of_range():
    for bad in (-0.01, 0.11, 1.0):
        brief = _ok_cex_continuity_brief()
        brief["CEX_CONTINUITY_LEADS"][0]["amount_match_pct"] = bad
        violations = _check_cex_continuity_leads_framed(brief)
        assert any("amount_match_pct" in v.detail for v in violations), bad


def test_invariant_i_cex_delta_hours_out_of_range():
    for bad in (-1.0, 200.0, float("nan"), float("inf")):
        brief = _ok_cex_continuity_brief()
        brief["CEX_CONTINUITY_LEADS"][0]["delta_hours"] = bad
        violations = _check_cex_continuity_leads_framed(brief)
        assert any("delta_hours" in v.detail for v in violations), bad


def test_invariant_i_cex_nan_pct_caught():
    brief = _ok_cex_continuity_brief()
    brief["CEX_CONTINUITY_LEADS"][0]["amount_match_pct"] = float("nan")
    violations = _check_cex_continuity_leads_framed(brief)
    assert any("amount_match_pct" in v.detail for v in violations)


def test_invariant_i_cex_destination_chain_forbidden():
    brief = _ok_cex_continuity_brief()
    brief["CEX_CONTINUITY_LEADS"][0]["destination_chain"] = "ethereum"
    violations = _check_cex_continuity_leads_framed(brief)
    assert any("destination_chain" in v.detail for v in violations)


def test_invariant_i_cex_destination_address_forbidden():
    brief = _ok_cex_continuity_brief()
    brief["CEX_CONTINUITY_LEADS"][0]["destination_address"] = "0x" + "5" * 40
    violations = _check_cex_continuity_leads_framed(brief)
    assert any("destination_address" in v.detail for v in violations)


def test_invariant_i_cex_top_5_cap_enforced():
    brief = _ok_cex_continuity_brief()
    template = brief["CEX_CONTINUITY_LEADS"][0]
    # 6 entries — top-N cap is 5.
    brief["CEX_CONTINUITY_LEADS"] = [dict(template) for _ in range(6)]
    violations = _check_cex_continuity_leads_framed(brief)
    assert any("top-N cap" in v.detail for v in violations)


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT J — Decoded cross-chain handoffs
# ─────────────────────────────────────────────────────────────────────────────


def test_invariant_j_handoffs_happy_path():
    assert _check_decoded_handoffs_consistent(_ok_decoded_handoffs_brief()) == []


def test_invariant_j_handoffs_missing_section_is_not_violation():
    assert _check_decoded_handoffs_consistent({}) == []
    assert _check_decoded_handoffs_consistent(
        {"CROSS_CHAIN_HANDOFFS": None}
    ) == []
    assert _check_decoded_handoffs_consistent(
        {"CROSS_CHAIN_HANDOFFS": []}
    ) == []


def test_invariant_j_handoff_without_decoded_confidence_is_skipped():
    brief = {
        "CROSS_CHAIN_HANDOFFS": [
            {
                "source_chain": "ethereum",
                "tx_hash": "0x" + "a" * 64,
                "bridge_name": "X",
                # No decoded_confidence — the decoded contract doesn't apply.
            }
        ]
    }
    assert _check_decoded_handoffs_consistent(brief) == []


def test_invariant_j_high_requires_both_fields():
    brief = _ok_decoded_handoffs_brief()
    # Strip the address from the high-confidence entry.
    brief["CROSS_CHAIN_HANDOFFS"][0]["decoded_destination_address"] = None
    violations = _check_decoded_handoffs_consistent(brief)
    assert any("high" in v.detail and "BOTH" in v.detail for v in violations)


def test_invariant_j_medium_requires_at_least_one():
    brief = _ok_decoded_handoffs_brief()
    # Strip both from the medium-confidence entry.
    brief["CROSS_CHAIN_HANDOFFS"][1]["decoded_destination_chain"] = None
    brief["CROSS_CHAIN_HANDOFFS"][1]["decoded_destination_address"] = None
    violations = _check_decoded_handoffs_consistent(brief)
    assert any("medium" in v.detail for v in violations)


def test_invariant_j_low_requires_both_null():
    brief = _ok_decoded_handoffs_brief()
    # The "low" entry must have BOTH null — set the chain to a value
    # to trip the rule.
    brief["CROSS_CHAIN_HANDOFFS"][2]["decoded_destination_chain"] = "ethereum"
    violations = _check_decoded_handoffs_consistent(brief)
    assert any(
        "low" in v.detail and "null" in v.detail for v in violations
    )


def test_invariant_j_unknown_chain_enum():
    brief = _ok_decoded_handoffs_brief()
    brief["CROSS_CHAIN_HANDOFFS"][0]["decoded_destination_chain"] = "klaytn"
    violations = _check_decoded_handoffs_consistent(brief)
    assert any("Chain enum" in v.detail for v in violations)


def test_invariant_j_bad_evm_address_format():
    brief = _ok_decoded_handoffs_brief()
    # Replace solana address with EVM-shaped wrong-chain garbage.
    brief["CROSS_CHAIN_HANDOFFS"][0]["decoded_destination_chain"] = "ethereum"
    brief["CROSS_CHAIN_HANDOFFS"][0]["decoded_destination_address"] = (
        "0xnothex_definitely_bad"
    )
    violations = _check_decoded_handoffs_consistent(brief)
    assert any("address format" in v.detail for v in violations)


def test_invariant_j_invalid_decoded_confidence_value():
    brief = _ok_decoded_handoffs_brief()
    brief["CROSS_CHAIN_HANDOFFS"][0]["decoded_confidence"] = "ultra-high"
    violations = _check_decoded_handoffs_consistent(brief)
    assert any("decoded_confidence" in v.detail for v in violations)


# ─────────────────────────────────────────────────────────────────────────────
# Cross-invariant: a brief with all v0.31.x sections well-formed
# passes ALL invariants together.
# ─────────────────────────────────────────────────────────────────────────────


def test_all_v031_sections_well_formed_passes_all_invariants():
    brief = {
        **_ok_mev_brief(),
        **_ok_exposure_brief(),
        **_ok_clusters_brief(),
        **_ok_cex_continuity_brief(),
        **_ok_decoded_handoffs_brief(),
    }
    assert _check_mev_signals_well_formed(brief) == []
    assert _check_indirect_exposure_v031_scores_in_range(brief) == []
    assert _check_wallet_clusters_contract(brief) == []
    assert _check_cex_continuity_leads_framed(brief) == []
    assert _check_decoded_handoffs_consistent(brief) == []


def test_invariants_never_raise_on_garbage_brief():
    """Defensive: invariants must NEVER raise even on adversarial input."""
    garbage = {
        "MEV_SIGNALS": "not a dict or list",
        "INDIRECT_EXPOSURE_V031": 12345,
        "WALLET_CLUSTERS": [{"cluster_id": None, "addresses": None}],
        "CEX_CONTINUITY_LEADS": "should be list",
        "CROSS_CHAIN_HANDOFFS": "should be list",
    }
    # Each invariant returns violations, never raises.
    _check_mev_signals_well_formed(garbage)
    _check_indirect_exposure_v031_scores_in_range(garbage)
    _check_wallet_clusters_contract(garbage)
    _check_cex_continuity_leads_framed(garbage)
    _check_decoded_handoffs_consistent(garbage)


def test_invariants_handle_none_brief():
    """Defensive: invariants must handle a None brief gracefully."""
    assert _check_mev_signals_well_formed(None) == []
    assert _check_indirect_exposure_v031_scores_in_range(None) == []
    assert _check_wallet_clusters_contract(None) == []
    assert _check_cex_continuity_leads_framed(None) == []
    assert _check_decoded_handoffs_consistent(None) == []
