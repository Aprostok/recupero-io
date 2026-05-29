"""Tests for INVARIANTS G / H / I in
``recupero.validators.output_integrity``.

INVARIANT G — Chain-of-custody completeness:
  Every brief-cited destination must be reachable from the seed via
  the trace transactions graph (BFS).

INVARIANT H — Confidence calibration:
  Aggregate Wilson lower bound vs per-lead confidence labels +
  high-confidence leads must cite ≥ 2 independent evidence sources.

INVARIANT I — Cross-document consistency:
  Case id, victim name, total USD (±$100), addresses, incident date,
  and exchange role agreement across brief + freeze letter + LE
  handoff.
"""

from __future__ import annotations

import json
from pathlib import Path

from recupero.validators.output_integrity import (
    ValidationResult,
    check_invariant_g,
    check_invariant_h,
    check_invariant_i,
    validate_case_output,
)

# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────


SEED = "0x" + "a" * 40
HOP1 = "0x" + "b" * 40
HOP2 = "0x" + "c" * 40
DEST_REACHABLE = "0x" + "d" * 40
DEST_UNREACHABLE = "0x" + "e" * 40
DEST_DISCONNECTED = "0x" + "f" * 40


def _three_hop_chain_tx() -> list[dict]:
    """seed → hop1 → hop2 → dest_reachable. Each tx has a tx_hash."""
    return [
        {"from_address": SEED, "to_address": HOP1,
         "tx_hash": "0xtx1", "chain": "ethereum"},
        {"from_address": HOP1, "to_address": HOP2,
         "tx_hash": "0xtx2", "chain": "ethereum"},
        {"from_address": HOP2, "to_address": DEST_REACHABLE,
         "tx_hash": "0xtx3", "chain": "ethereum"},
    ]


def _brief_with_destinations(
    destinations: list[str],
    *,
    seed: str = SEED,
    transactions: list[dict] | None = None,
    extra: dict | None = None,
) -> dict:
    """Construct a freeze_brief dict with the given destination
    addresses and (embedded) transaction list."""
    brief = {
        "CASE_ID": "TEST-G",
        "VICTIM_WALLET_FULL": seed,
        "PRIMARY_CHAIN": "ethereum",
        "DESTINATIONS": [
            {"address": addr, "chain": "ethereum"} for addr in destinations
        ],
    }
    if transactions is not None:
        brief["trace_evidence"] = {"transactions": transactions}
    if extra:
        brief.update(extra)
    return brief


def _write_case_with_trace(
    tmp_path: Path,
    freeze_brief: dict,
    *,
    trace_transactions: list[dict] | None = None,
    write_briefs_dir: bool = False,
) -> Path:
    """Create a case_dir/, optionally write trace_evidence.json + the
    briefs/ subdir (empty). Returns the case_dir path."""
    case_dir = tmp_path / "case"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "freeze_brief.json").write_text(
        json.dumps(freeze_brief), encoding="utf-8",
    )
    if trace_transactions is not None:
        (case_dir / "trace_evidence.json").write_text(
            json.dumps({
                "seed_address": freeze_brief.get("VICTIM_WALLET_FULL"),
                "transactions": trace_transactions,
            }),
            encoding="utf-8",
        )
    if write_briefs_dir:
        (case_dir / "briefs").mkdir(exist_ok=True)
    return case_dir


# ─────────────────────────────────────────────────────────────────────
# INVARIANT G — Chain-of-custody completeness
# ─────────────────────────────────────────────────────────────────────


class TestInvariantG:
    """3 positive (clean) + 3 violation cases."""

    # --- positive cases ---

    def test_g_clean_single_hop(self, tmp_path):
        brief = _brief_with_destinations(
            [HOP1],
            transactions=[
                {"from_address": SEED, "to_address": HOP1,
                 "tx_hash": "0xtx1", "chain": "ethereum"},
            ],
        )
        result = check_invariant_g(tmp_path, brief)
        assert result == []

    def test_g_clean_three_hop_chain(self, tmp_path):
        brief = _brief_with_destinations(
            [DEST_REACHABLE],
            transactions=_three_hop_chain_tx(),
        )
        assert check_invariant_g(tmp_path, brief) == []

    def test_g_clean_no_destinations_skips(self, tmp_path):
        # No destinations to claim → no violations even with zero
        # transactions.
        brief = {
            "CASE_ID": "TEST-G",
            "VICTIM_WALLET_FULL": SEED,
            "DESTINATIONS": [],
        }
        assert check_invariant_g(tmp_path, brief) == []

    # --- violation cases ---

    def test_g_destination_not_in_trace(self, tmp_path):
        # Brief claims DEST_UNREACHABLE but the trace only reaches
        # HOP1.
        brief = _brief_with_destinations(
            [DEST_UNREACHABLE],
            transactions=[
                {"from_address": SEED, "to_address": HOP1,
                 "tx_hash": "0xtx1", "chain": "ethereum"},
            ],
        )
        result = check_invariant_g(tmp_path, brief)
        assert len(result) == 1
        assert result[0].severity == "critical"
        assert "not reachable" in result[0].detail.lower()

    def test_g_disconnected_component(self, tmp_path):
        # Brief claims DEST_DISCONNECTED but the trace has it appear
        # only as the destination of a tx whose source isn't in the
        # reachable set from SEED.
        brief = _brief_with_destinations(
            [DEST_DISCONNECTED],
            transactions=[
                # Reachable component: seed → hop1
                {"from_address": SEED, "to_address": HOP1,
                 "tx_hash": "0xtx1", "chain": "ethereum"},
                # Disconnected component: hop2 → dest_disconnected
                {"from_address": HOP2, "to_address": DEST_DISCONNECTED,
                 "tx_hash": "0xtx-disconnected", "chain": "ethereum"},
            ],
        )
        result = check_invariant_g(tmp_path, brief)
        assert len(result) == 1
        assert result[0].severity == "critical"

    def test_g_seed_missing(self, tmp_path):
        # Brief claims destinations but has no seed address — every
        # claim is unsupported by construction.
        brief = {
            "CASE_ID": "TEST-G",
            "DESTINATIONS": [
                {"address": DEST_REACHABLE, "chain": "ethereum"},
            ],
            "trace_evidence": {"transactions": _three_hop_chain_tx()},
        }
        result = check_invariant_g(tmp_path, brief)
        assert len(result) == 1
        assert result[0].severity == "critical"
        assert "seed" in result[0].detail.lower()

    # --- bonus: empty trace + claimed destinations ---

    def test_g_empty_trace_with_claimed_destinations(self, tmp_path):
        brief = _brief_with_destinations(
            [DEST_REACHABLE],
            transactions=[],
        )
        result = check_invariant_g(tmp_path, brief)
        assert len(result) == 1
        assert result[0].severity == "critical"


# ─────────────────────────────────────────────────────────────────────
# INVARIANT H — Confidence calibration
# ─────────────────────────────────────────────────────────────────────


class TestInvariantH:
    """2 positive + 4 violation cases."""

    # --- positive cases ---

    def test_h_high_conf_with_two_sources_passes(self):
        brief = {
            "RECOVERY_RATE": {"wilson_lower": 0.10, "wilson_upper": 0.30},
            "DESTINATIONS": [
                {
                    "address": "0x" + "1" * 40,
                    "confidence": "high",
                    "evidence_sources": [
                        {"type": "on_chain_transfer"},
                        {"type": "exchange_label"},
                    ],
                },
            ],
        }
        assert check_invariant_h(brief) == []

    def test_h_low_conf_lead_below_base_rate_passes(self):
        # Wilson lower < 5% but the lead is low-confidence — no
        # disagreement.
        brief = {
            "RECOVERY_RATE": {"wilson_lower": 0.01, "wilson_upper": 0.04},
            "CEX_CONTINUITY_LEADS": [
                {
                    "candidate_withdrawal_to": "0x" + "2" * 40,
                    "confidence": "low",
                },
            ],
        }
        assert check_invariant_h(brief) == []

    # --- violation cases ---

    def test_h_high_conf_when_base_low_fires_warning(self):
        brief = {
            "RECOVERY_RATE": {"wilson_lower": 0.02, "wilson_upper": 0.06},
            "DESTINATIONS": [
                {
                    "address": "0x" + "3" * 40,
                    "confidence": "high",
                    "evidence_sources": [
                        {"type": "on_chain_transfer"},
                        {"type": "exchange_label"},
                    ],
                },
            ],
        }
        result = check_invariant_h(brief)
        # Expect a single WARN for the base-rate disagreement; the
        # evidence-count check is satisfied so no critical.
        warnings = [v for v in result if v.severity == "warning"]
        criticals = [v for v in result if v.severity == "critical"]
        assert len(warnings) == 1
        assert len(criticals) == 0
        assert "wilson" in warnings[0].detail.lower()

    def test_h_high_conf_with_one_source_fires_critical(self):
        brief = {
            "DESTINATIONS": [
                {
                    "address": "0x" + "4" * 40,
                    "confidence": "high",
                    "evidence_sources": ["on_chain_transfer"],
                },
            ],
        }
        result = check_invariant_h(brief)
        criticals = [v for v in result if v.severity == "critical"]
        assert len(criticals) == 1
        assert "1 independent" in criticals[0].detail.lower() or "only 1" in criticals[0].detail.lower()

    def test_h_high_conf_with_zero_sources_fires_critical(self):
        brief = {
            "DESTINATIONS": [
                {
                    "address": "0x" + "5" * 40,
                    "confidence": "high",
                    # No evidence_sources field at all.
                },
            ],
        }
        result = check_invariant_h(brief)
        criticals = [v for v in result if v.severity == "critical"]
        assert len(criticals) == 1
        assert "0" in criticals[0].detail or "only 0" in criticals[0].detail.lower()

    def test_h_broken_corroboration_duplicate_type_fires_critical(self):
        # Two evidence entries, both same `type` — counts as 1
        # independent source, not 2.
        brief = {
            "DESTINATIONS": [
                {
                    "address": "0x" + "6" * 40,
                    "confidence": "high",
                    "evidence_sources": [
                        {"type": "on_chain_transfer"},
                        {"type": "on_chain_transfer"},
                    ],
                },
            ],
        }
        result = check_invariant_h(brief)
        criticals = [v for v in result if v.severity == "critical"]
        assert len(criticals) == 1


# ─────────────────────────────────────────────────────────────────────
# INVARIANT I — Cross-document consistency
# ─────────────────────────────────────────────────────────────────────


def _write_case_with_docs(
    tmp_path: Path,
    *,
    case_id: str = "TEST-I",
    victim_name: str = "Alice Victim",
    total_loss_usd: str = "$1,000,000.00",
    addresses: list[str] | None = None,
    incident_date: str = "April 19, 2026",
    incident_ts: str = "2026-04-19T12:00:00Z",
    exchanges: list[str] | None = None,
    # Per-doc overrides — allow tests to break consistency.
    freeze_case_id: str | None = None,
    le_case_id: str | None = None,
    freeze_total: str | None = None,
    le_total: str | None = None,
    freeze_victim: str | None = None,
    le_victim: str | None = None,
    freeze_addr: str | None = None,
    le_addr: str | None = None,
    freeze_date: str | None = None,
    le_date: str | None = None,
    freeze_slug: str | None = None,
    include_le: bool = True,
) -> Path:
    """Create a case_dir/ with freeze_brief.json + freeze_request +
    optionally le_handoff HTML files. Returns the case_dir path.

    Each per-doc override lets a test inject a divergence to verify
    the cross-document check fires."""
    if addresses is None:
        addresses = ["0x" + "a" * 40, "0x" + "b" * 40]
    if exchanges is None:
        exchanges = ["Tether"]

    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True, exist_ok=True)

    brief = {
        "CASE_ID": case_id,
        "VICTIM_NAME": victim_name,
        "victim": {"name": victim_name},
        "VICTIM_WALLET_FULL": addresses[0],
        "PRIMARY_CHAIN": "ethereum",
        "INCIDENT_DATE": incident_date,
        "INCIDENT_TIMESTAMP_UTC": incident_ts,
        "TOTAL_LOSS_USD": total_loss_usd,
        "TOTAL_FREEZABLE_USD": total_loss_usd,
        "EXCHANGES": [
            {"name": n, "role": "destination"} for n in exchanges
        ],
        "FREEZABLE": [
            {
                "issuer": exchanges[0] if exchanges else "Tether",
                "token": "USDT",
                "freeze_capability": "yes",
                "holdings": [
                    {"address": addresses[1], "chain": "ethereum",
                     "status": "FREEZABLE"},
                ],
            },
        ],
        "DESTINATIONS": [
            {"address": addr, "chain": "ethereum"}
            for addr in addresses[1:]
        ],
    }
    (case_dir / "freeze_brief.json").write_text(
        json.dumps(brief), encoding="utf-8",
    )

    slug = (freeze_slug or (exchanges[0] if exchanges else "tether")).lower()
    freeze_html = (
        "<!DOCTYPE html>\n<html><head>"
        f"<title>Freeze Request — {exchanges[0] if exchanges else 'Tether'}</title>"
        "</head><body>"
        f"<h1>Freeze Request — {exchanges[0] if exchanges else 'Tether'}</h1>"
        f"<p>CASE_ID: {freeze_case_id or case_id}</p>"
        f"<p>Victim: {freeze_victim or victim_name}</p>"
        f"<p>Total: {freeze_total or total_loss_usd}</p>"
        f"<p>Date: {freeze_date or incident_date}</p>"
        f"<p>Wallet: {freeze_addr or addresses[0]}</p>"
        "</body></html>"
    )
    (briefs / f"freeze_request_{slug}_BRIEF-{case_id}-x.html").write_text(
        freeze_html, encoding="utf-8",
    )

    if include_le:
        le_html = (
            "<!DOCTYPE html>\n<html><head>"
            f"<title>LE Handoff — {exchanges[0] if exchanges else 'Tether'}</title>"
            "</head><body>"
            f"<h1>LE Handoff — {exchanges[0] if exchanges else 'Tether'}</h1>"
            f"<p>CASE_ID: {le_case_id or case_id}</p>"
            f"<p>Victim: {le_victim or victim_name}</p>"
            f"<p>Total stolen: {le_total or total_loss_usd}</p>"
            f"<p>Incident date: {le_date or incident_date}</p>"
            f"<p>Victim wallet: {le_addr or addresses[0]}</p>"
            "</body></html>"
        )
        (briefs / f"le_handoff_{slug}_BRIEF-{case_id}-x.html").write_text(
            le_html, encoding="utf-8",
        )
    return case_dir


class TestInvariantI:
    """2 positive + 5 violation cases."""

    def _load_brief(self, case_dir: Path) -> dict:
        return json.loads(
            (case_dir / "freeze_brief.json").read_text(encoding="utf-8")
        )

    # --- positive cases ---

    def test_i_all_docs_agree_passes(self, tmp_path):
        case_dir = _write_case_with_docs(tmp_path)
        brief = self._load_brief(case_dir)
        assert check_invariant_i(case_dir, brief) == []

    def test_i_le_handoff_absent_skips_gracefully(self, tmp_path):
        # No LE handoff on disk — INVARIANT I still runs against the
        # freeze letter; the missing LE doesn't itself violate.
        case_dir = _write_case_with_docs(tmp_path, include_le=False)
        brief = self._load_brief(case_dir)
        assert check_invariant_i(case_dir, brief) == []

    # --- violation cases ---

    def test_i_case_id_mismatch_fires(self, tmp_path):
        case_dir = _write_case_with_docs(
            tmp_path, freeze_case_id="WRONG-CASE",
        )
        brief = self._load_brief(case_dir)
        result = check_invariant_i(case_dir, brief)
        crit = [v for v in result if v.severity == "critical"]
        assert any("case_id" in v.detail.lower() for v in crit), \
            f"expected case_id violation, got {result}"

    def test_i_total_usd_off_by_10k_fires(self, tmp_path):
        # Brief says $1,000,000; freeze letter says $1,010,000 — well
        # outside the $100 tolerance.
        case_dir = _write_case_with_docs(
            tmp_path,
            total_loss_usd="$1,000,000.00",
            freeze_total="$1,010,000.00",
        )
        brief = self._load_brief(case_dir)
        result = check_invariant_i(case_dir, brief)
        crit = [v for v in result if v.severity == "critical"]
        assert any("total" in v.detail.lower() or "usd" in v.detail.lower()
                   for v in crit), f"expected USD violation, got {result}"

    def test_i_address_missing_in_freeze_letter_fires(self, tmp_path):
        # The freeze letter omits every brief address.
        case_dir = _write_case_with_docs(
            tmp_path,
            addresses=["0x" + "a" * 40, "0x" + "b" * 40],
            freeze_addr="0x" + "9" * 40,
        )
        brief = self._load_brief(case_dir)
        # Drop the wallet from the brief to leave only the FREEZABLE
        # holding address (also "0xbbb...") — to ensure no address
        # from the brief appears in the doc, we also rewrite the
        # freeze HTML to a different one (already done via
        # freeze_addr). Also need the brief's FREEZABLE address to
        # not appear in the html; the simple template embeds only
        # the seed address, so freeze_addr override is enough.
        # But the html template embeds VICTIM_WALLET only — we need
        # to also remove the FREEZABLE-address appearance. The
        # default template doesn't reference it; freeze_addr above
        # rewrites VICTIM_WALLET. So we additionally remove the
        # FREEZABLE holding from the brief to guarantee zero overlap.
        brief["FREEZABLE"] = []
        # Persist the modified brief back to disk (so the validator
        # reads the same shape).
        (case_dir / "freeze_brief.json").write_text(
            json.dumps(brief), encoding="utf-8",
        )
        result = check_invariant_i(case_dir, brief)
        crit = [v for v in result if v.severity == "critical"]
        assert any(
            "address" in v.detail.lower() or "subject" in v.detail.lower()
            for v in crit
        ), f"expected address violation, got {result}"

    def test_i_exchange_name_mismatch_fires(self, tmp_path):
        # The freeze letter slug points at an exchange the brief
        # never named.
        case_dir = _write_case_with_docs(
            tmp_path,
            exchanges=["Tether"],
            freeze_slug="coinbase",
        )
        brief = self._load_brief(case_dir)
        result = check_invariant_i(case_dir, brief)
        crit = [v for v in result if v.severity == "critical"]
        assert any(
            "exchange" in v.detail.lower() or "issuer" in v.detail.lower()
            for v in crit
        ), f"expected exchange-role violation, got {result}"

    def test_i_date_mismatch_fires(self, tmp_path):
        # The freeze letter cites a wrong date (and we override the
        # ISO timestamp doc-string so it's not found either).
        case_dir = _write_case_with_docs(
            tmp_path,
            incident_date="April 19, 2026",
            incident_ts="2026-04-19T12:00:00Z",
            freeze_date="January 1, 2020",
        )
        brief = self._load_brief(case_dir)
        result = check_invariant_i(case_dir, brief)
        crit = [v for v in result if v.severity == "critical"]
        assert any(
            "date" in v.detail.lower() or "incident" in v.detail.lower()
            for v in crit
        ), f"expected date violation, got {result}"


# ─────────────────────────────────────────────────────────────────────
# Regression: A–F still work + dispatcher returns G/H/I results
# ─────────────────────────────────────────────────────────────────────


class TestDispatcherRegression:

    def test_dispatcher_runs_all_invariants_including_g_h_i(self, tmp_path):
        """After wiring G/H/I, the dispatcher's checks_run list MUST
        include the 3 new invariant identifiers AND continue to run
        all prior A–F invariants."""
        case_dir = _write_case_with_docs(tmp_path)
        result: ValidationResult = validate_case_output(case_dir)
        assert isinstance(result, ValidationResult)
        # Pre-existing invariants must still be in checks_run.
        for expected in (
            "filename_content_consistency",
            "html_files_contain_html",
            "json_files_parse_as_json",
            "freeze_ask_targets_not_investigate_tagged",
            "destinations_superset_of_ground_truth",
            "subpoena_targets_cover_non_freezable",
            "mev_signals_well_formed",
            # New ones:
            "invariant_g_chain_of_custody",
            "invariant_h_confidence_calibration",
            "invariant_i_cross_document_consistency",
        ):
            assert expected in result.checks_run, \
                f"{expected!r} missing from checks_run={result.checks_run}"

    def test_g_h_i_do_not_block_clean_case(self, tmp_path):
        """A fully-consistent case (matching docs + reachable
        destinations + no high-conf leads) must not surface any new
        critical/high violations from G/H/I."""
        # Build a case where every claim is supported.
        addresses = ["0x" + "a" * 40, "0x" + "b" * 40]
        case_dir = _write_case_with_docs(tmp_path, addresses=addresses)
        # Add a trace_evidence.json with edges making every claimed
        # destination reachable.
        brief = json.loads(
            (case_dir / "freeze_brief.json").read_text(encoding="utf-8")
        )
        # Seed → DESTINATIONS[0]. brief's FREEZABLE holding address
        # (addresses[1]) is the only destination.
        (case_dir / "trace_evidence.json").write_text(
            json.dumps({
                "seed_address": addresses[0],
                "transactions": [
                    {"from_address": addresses[0],
                     "to_address": addresses[1],
                     "tx_hash": "0xtx1",
                     "chain": "ethereum"},
                ],
            }),
            encoding="utf-8",
        )
        # Sanity-check each new invariant individually.
        assert check_invariant_g(case_dir, brief) == []
        assert check_invariant_h(brief) == []
        assert check_invariant_i(case_dir, brief) == []
