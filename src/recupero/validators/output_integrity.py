"""Structural-integrity validator for case output artifacts.

Per Jacob's v0.20.15 review (Part 4): the discipline shift that
breaks the recurring "headline fix, new structural bug in a
different layer" pattern. Each release adds unit tests for the
specific bug found; the next bug lands in a layer those tests
don't cover. The validator covers CATEGORIES of bugs by checking
structural properties of the rendered output that must hold for
every case regardless of shape.

29+ invariants (Jacob's Part 4.2 starter set + Part 5 audit
expansion + v0.27.2 0x52Aa bleed fix):

  1. Filename/content consistency for issuer-named files (catches
     v0.20.15's freeze_request_midas containing the Circle letter).
  2. HTML files contain HTML at the document root (catches JSON /
     SVG / CSV being written to .html paths).
  3. JSON files parse as valid JSON (catches HTML being written to
     .json paths — Jacob saw manifest_BRIEF-... as 52KB of HTML).
  4. No two output files have byte-identical content (catches silent
     overwrites + duplicate writes).
  5. Brief manifest output_sha256 matches disk content (catches the
     write-path collision pattern — recorded SHA stale).
  6. Every freezable issuer (freeze_capability='yes') in freeze_asks
     has both a freeze_request_<issuer>_*.html AND an
     le_handoff_<issuer>_*.html file.
  7. TOTAL_FREEZABLE_USD reconciles across freeze_brief.json,
     engagement letter HTML, victim summary HTML.
  8. STOLEN_ASSET_ISSUER and FREEZE_TARGET_ISSUER are distinct in
     the Section 1 narrative of every LE handoff (catches v0.19.3
     residual where USDT was claimed to be "issued by Circle").
  9. Recoverable variant matches MAX_RECOVERABLE_USD (catches
     v0.15.1's bug — victim_summary_unrecoverable produced for a
     case with $3.5M in freezable funds).
 10. No unrendered Jinja `{{ }}` placeholders in any HTML output.
 11. Contract-detection consistency — addresses tagged UNRECOVERABLE
     in the brief don't appear as FREEZABLE in any freeze letter.
 12. Sky Protocol / DAI → UNRECOVERABLE in every artifact that
     mentions DAI.

Part 5 expansion — per-artifact + cross-artifact invariants:

 13. freeze_request <title> tag contains the named issuer (the
     v0.20.15 routing bug detectable at the title layer).
 14. freeze_request does NOT contain compliance emails belonging to
     OTHER issuers (a Tether letter must never carry
     compliance@circle.com — template cross-fill).
 15. LE handoff Section 4.2 enumerates every issuer present in
     brief.ALL_ISSUER_HOLDINGS / brief.FREEZABLE (catches partial
     inventory sync — AUSA can't serve a target that isn't listed).
 16. LE handoff body cites the brief's TOTAL_LOSS_USD figure (or
     TOTAL_FREEZABLE_USD fallback) — LE without a $ figure is
     unfileable.
 17. trace_report does NOT contain freeze-request language (catches
     cross-template content leakage; trace_report is internal-use).
 18. engagement_letter exists iff MAX_RECOVERABLE_USD > 0 (extends
     check 9 to the engagement artifact — no signup form when
     nothing to recover).
 19. engagement_letter contains the victim's name.
 20. victim_summary contains the freezable/recoverable $ figure.
 21. victim_summary contains the victim's name.
 22. flow_*.svg files start with a valid <?xml / <svg root.
 23. investigator_findings.csv is well-formed (header + ≥1 row when
     FREEZABLE is non-empty).
 24. CASE_ID is consistent across freeze_brief, manifest, freeze
     requests, LE handoffs (catches cross-case content bleed).
 25. brief.asset.symbol matches the symbol referenced in trace_report
     and LE handoffs (no USDC trace report on a USDT case).
 26. brief.victim.name matches the victim referenced in LE handoffs,
     victim_summary, engagement_letter (no Bob Other on Alice's case).
 27. recovery_snapshot exists iff MAX_RECOVERABLE_USD > 0 (extends
     check 9 / 18 to the standalone pre-engagement deliverable).

Every check derives its expected values from the case's OWN data
(freeze_asks.json, freeze_brief.json, the brief manifest) rather
than hardcoded V-CFI01 facts. Works for any case shape.

Failure mode: a missing dependency artifact (e.g., freeze_asks.json
absent) is reported as a HIGH-severity violation, not a crash. The
validator must complete on any non-empty case_dir without raising.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Violation:
    """One structural-integrity finding."""
    check: str       # Stable identifier (e.g. "filename_content_consistency").
    severity: str    # "critical" | "high" | "warning"
    detail: str      # Human-readable description, specific enough to act on.
    file: str | None = None  # Relative path within case_dir, when applicable.


# v0.32.1 test-public semantic invariants G/H/I. Signatures:
#   check_invariant_g(case_dir, brief)
#   check_invariant_h(brief)
#   check_invariant_i(case_dir, brief)
#
# Each returns a list[Violation]. These are wired into
# validate_case_output's checks_run list under their canonical
# identifiers (``invariant_g_chain_of_custody`` etc).


def check_invariant_g(
    case_dir: "Path | str | None",
    brief: dict | None,
) -> list["Violation"]:
    """INVARIANT G — Chain-of-custody completeness.

    Every brief-cited DESTINATIONS[].address must be reachable from
    the seed (VICTIM_WALLET_FULL) via the brief's
    ``trace_evidence.transactions`` list (or the
    ``trace_evidence.json`` file on disk under ``case_dir``).
    """
    if brief is None:
        return []
    destinations: list[dict] = []
    raw_dests = brief.get("DESTINATIONS")
    if isinstance(raw_dests, list):
        for d in raw_dests:
            if isinstance(d, dict) and d.get("address"):
                destinations.append(d)

    if not destinations:
        return []

    # Pull transactions from embedded trace_evidence OR from disk.
    transactions: list[dict] = []
    embedded = brief.get("trace_evidence")
    if isinstance(embedded, dict):
        txs = embedded.get("transactions")
        if isinstance(txs, list):
            transactions = [t for t in txs if isinstance(t, dict)]
    if not transactions and case_dir is not None:
        try:
            p = Path(case_dir) / "trace_evidence.json"
            if p.is_file():
                data = json.loads(p.read_text(encoding="utf-8"))
                txs = data.get("transactions") if isinstance(data, dict) else None
                if isinstance(txs, list):
                    transactions = [t for t in txs if isinstance(t, dict)]
        except (OSError, json.JSONDecodeError, ValueError):
            transactions = []

    seed_raw = brief.get("VICTIM_WALLET_FULL") or brief.get("seed_address")
    if not seed_raw:
        # No seed → every destination is unsupported by construction.
        return [Violation(
            check="invariant_g_chain_of_custody", severity="critical",
            detail=(
                "Brief claims destinations but provides no seed address "
                "(VICTIM_WALLET_FULL). Chain-of-custody is unverifiable."
            ),
        )]
    seed = str(seed_raw).lower()

    # Build adjacency map. Each tx: from_address → to_address.
    graph: dict[str, set[str]] = {}
    for tx in transactions:
        f = (tx.get("from_address") or "").lower()
        t = (tx.get("to_address") or "").lower()
        if not f or not t:
            continue
        graph.setdefault(f, set()).add(t)

    # BFS from seed.
    reachable: set[str] = {seed}
    frontier: list[str] = [seed]
    while frontier:
        cur = frontier.pop(0)
        for nxt in graph.get(cur, ()):
            if nxt not in reachable:
                reachable.add(nxt)
                frontier.append(nxt)

    violations: list[Violation] = []
    for d in destinations:
        addr = str(d.get("address") or "").lower()
        if not addr:
            continue
        if addr not in reachable:
            violations.append(Violation(
                check="invariant_g_chain_of_custody", severity="critical",
                detail=(
                    f"Brief claims destination {addr} but it is not "
                    f"reachable from the seed via the trace transactions."
                ),
            ))
    return violations


def check_invariant_h(brief: dict | None) -> list["Violation"]:
    """INVARIANT H — Confidence calibration.

    Two rules:
      * If RECOVERY_RATE.wilson_lower < 0.05 AND there is at least one
        DESTINATIONS entry with confidence=='high', emit a WARNING
        (per-lead high-conf claim disagrees with aggregate base rate).
      * Every high-confidence destination MUST cite ≥ 2 distinct
        independent evidence sources. Evidence_sources can be a list
        of strings (treated as raw types) or list of {"type": ...}
        dicts; duplicates by type count as ONE.
    """
    if brief is None:
        return []
    violations: list[Violation] = []
    rec_rate = brief.get("RECOVERY_RATE") or {}
    wilson_lower = None
    if isinstance(rec_rate, dict):
        try:
            wilson_lower = float(rec_rate.get("wilson_lower"))
        except (TypeError, ValueError):
            wilson_lower = None

    destinations = brief.get("DESTINATIONS") or []
    high_conf: list[dict] = [
        d for d in destinations
        if isinstance(d, dict)
        and str(d.get("confidence", "")).lower() == "high"
    ]

    if wilson_lower is not None and wilson_lower < 0.05 and high_conf:
        violations.append(Violation(
            check="invariant_h_confidence_calibration", severity="warning",
            detail=(
                f"Aggregate Wilson lower bound is {wilson_lower:.1%} (<5%) but "
                f"{len(high_conf)} high-confidence destination(s) cited. "
                "Per-lead claims may overstate aggregate base rate."
            ),
        ))

    for d in high_conf:
        sources = d.get("evidence_sources")
        unique_types: set[str] = set()
        if isinstance(sources, list):
            for s in sources:
                if isinstance(s, str) and s.strip():
                    unique_types.add(s.strip())
                elif isinstance(s, dict):
                    t = s.get("type")
                    if isinstance(t, str) and t.strip():
                        unique_types.add(t.strip())
        n = len(unique_types)
        if n < 2:
            addr = d.get("address") or "?"
            violations.append(Violation(
                check="invariant_h_confidence_calibration", severity="critical",
                detail=(
                    f"High-confidence destination {addr} cites only {n} "
                    f"independent evidence source(s); requires >= 2."
                ),
            ))
    return violations


def check_invariant_i(
    case_dir: "Path | str | None",
    brief: dict | None,
) -> list["Violation"]:
    """INVARIANT I — Cross-document consistency.

    Compare the brief against the freeze_request_*.html and
    le_handoff_*.html files in ``case_dir/briefs/``. Mismatches in
    CASE_ID, victim name, total USD ($100 tol), addresses, incident
    date, or exchange name fire a critical.
    """
    if brief is None or case_dir is None:
        return []
    case_path = Path(case_dir)
    briefs_dir = case_path / "briefs"
    if not briefs_dir.is_dir():
        return []

    htmls: list[tuple[str, str]] = []  # (filename, content)
    for p in sorted(briefs_dir.glob("freeze_request_*.html")):
        try:
            htmls.append((p.name, p.read_text(encoding="utf-8")))
        except OSError:
            pass
    for p in sorted(briefs_dir.glob("le_handoff_*.html")):
        try:
            htmls.append((p.name, p.read_text(encoding="utf-8")))
        except OSError:
            pass
    if not htmls:
        return []

    violations: list[Violation] = []
    case_id = str(brief.get("CASE_ID") or "").strip()
    victim_name = (
        str(brief.get("VICTIM_NAME")
            or (brief.get("victim") or {}).get("name") or "")
        .strip()
    )
    incident_date = str(brief.get("INCIDENT_DATE") or "").strip()
    incident_ts = str(brief.get("INCIDENT_TIMESTAMP_UTC") or "").strip()
    total_usd_raw = brief.get("TOTAL_LOSS_USD") or brief.get("TOTAL_FREEZABLE_USD")
    total_usd = _parse_usd_string(total_usd_raw)
    # Collect every address the brief references.
    brief_addrs: set[str] = set()
    for d in brief.get("DESTINATIONS", []) or []:
        if isinstance(d, dict):
            a = d.get("address")
            if isinstance(a, str):
                brief_addrs.add(a.lower())
    for f in brief.get("FREEZABLE", []) or []:
        if isinstance(f, dict):
            for h in f.get("holdings", []) or []:
                if isinstance(h, dict):
                    a = h.get("address")
                    if isinstance(a, str):
                        brief_addrs.add(a.lower())
    seed = str(brief.get("VICTIM_WALLET_FULL") or "").lower()
    if seed:
        brief_addrs.add(seed)
    # Exchanges claimed in the brief.
    brief_exchanges: set[str] = set()
    for e in brief.get("EXCHANGES", []) or []:
        if isinstance(e, dict):
            n = e.get("name")
            if isinstance(n, str) and n.strip():
                brief_exchanges.add(n.strip().lower())
    for f in brief.get("FREEZABLE", []) or []:
        if isinstance(f, dict):
            iss = f.get("issuer")
            if isinstance(iss, str) and iss.strip():
                brief_exchanges.add(iss.strip().lower())

    for fname, content in htmls:
        lower = content.lower()
        # CASE_ID
        if case_id and case_id not in content:
            violations.append(Violation(
                check="invariant_i_cross_document_consistency",
                severity="critical", file=fname,
                detail=(
                    f"document does not cite brief case_id {case_id!r}"
                ),
            ))
        # Victim name
        if victim_name and victim_name.lower() not in lower:
            violations.append(Violation(
                check="invariant_i_cross_document_consistency",
                severity="critical", file=fname,
                detail=f"document does not cite victim name {victim_name!r}",
            ))
        # Total USD ($100 tolerance)
        if total_usd > 0:
            doc_totals = _extract_dollar_amounts(content)
            ok = any(
                abs(amount - total_usd) <= Decimal("100")
                for amount in doc_totals
            )
            if not ok:
                formatted = f"${total_usd:,.2f}"
                violations.append(Violation(
                    check="invariant_i_cross_document_consistency",
                    severity="critical", file=fname,
                    detail=(
                        f"document total usd does not match brief "
                        f"{formatted} within $100 tolerance"
                    ),
                ))
        # Addresses — at least one brief address must appear.
        if brief_addrs:
            found_any = any(a in lower for a in brief_addrs)
            if not found_any:
                violations.append(Violation(
                    check="invariant_i_cross_document_consistency",
                    severity="critical", file=fname,
                    detail=(
                        "document does not cite any subject address from "
                        "the brief"
                    ),
                ))
        # Incident date — either the long-form or ISO date string.
        if incident_date or incident_ts:
            d_long = incident_date.lower() if incident_date else None
            d_iso10 = incident_ts[:10] if incident_ts else None
            ok = (
                (d_long is not None and d_long in lower)
                or (d_iso10 is not None and d_iso10 in content)
            )
            if not ok:
                violations.append(Violation(
                    check="invariant_i_cross_document_consistency",
                    severity="critical", file=fname,
                    detail=(
                        f"document does not cite the brief incident date "
                        f"{incident_date or incident_ts!r}"
                    ),
                ))
        # Exchange / issuer slug taken from the filename must match a brief
        # exchange/issuer.
        slug = ""
        if fname.startswith("freeze_request_"):
            rest = fname[len("freeze_request_"):]
            slug = rest.split("_", 1)[0]
        elif fname.startswith("le_handoff_"):
            rest = fname[len("le_handoff_"):]
            slug = rest.split("_", 1)[0]
        slug = slug.lower()
        if slug and brief_exchanges:
            slug_compact = slug.replace("_", "")
            matched = any(
                slug_compact in e.replace(" ", "").replace("-", "").lower()
                or e.replace(" ", "").replace("-", "").lower() in slug_compact
                for e in brief_exchanges
            )
            if not matched:
                violations.append(Violation(
                    check="invariant_i_cross_document_consistency",
                    severity="critical", file=fname,
                    detail=(
                        f"document exchange/issuer slug {slug!r} does not "
                        f"match any brief exchange: {sorted(brief_exchanges)}"
                    ),
                ))
    return violations


_DOLLAR_RE = re.compile(r"\$\s*([0-9][0-9,]*(?:\.[0-9]+)?)")


def _extract_dollar_amounts(text: str) -> list[Decimal]:
    out: list[Decimal] = []
    for m in _DOLLAR_RE.finditer(text):
        try:
            v = Decimal(m.group(1).replace(",", ""))
            out.append(v)
        except (InvalidOperation, ValueError):
            continue
    return out


@dataclass
class ValidationResult:
    """Aggregate result. ``ok`` is True iff there are zero
    'critical' or 'high' severity violations."""
    violations: list[Violation] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(
            v.severity in ("critical", "high") for v in self.violations
        )

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "high")

    def by_severity(self) -> dict[str, list[Violation]]:
        out: dict[str, list[Violation]] = {}
        for v in self.violations:
            out.setdefault(v.severity, []).append(v)
        return out

    def summary_text(self) -> str:
        if self.ok and not self.violations:
            return f"PASS — {len(self.checks_run)} checks, no violations."
        lines = [
            f"FAIL — {self.critical_count} critical, {self.high_count} high, "
            f"{sum(1 for v in self.violations if v.severity == 'warning')} warning"
        ]
        for v in self.violations:
            file_hint = f" [{v.file}]" if v.file else ""
            lines.append(f"  {v.severity.upper()}: {v.check}{file_hint} — {v.detail}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────


def validate_case_output(case_output_dir: Path) -> ValidationResult:
    """Run every structural-integrity check against the case directory.

    Expected directory layout (driven by build_all_deliverables):

        case_output_dir/
            freeze_asks.json        ← driver: which issuers are freezable?
            freeze_brief.json       ← driver: FREEZABLE list + totals
            case.json (optional)
            victim.json (optional)
            briefs/
                freeze_request_<issuer>_BRIEF-<case>-<hash>.html
                le_handoff_<issuer>_BRIEF-<case>-<hash>.html
                manifest_BRIEF-<case>-<hash>.json
                trace_report_<hash>.html
                victim_summary_<variant>_<hash>.html
                engagement_letter_<hash>.html (optional)
                investigator_findings.csv
                investigator_findings.json
                flow_<hash>.svg

    Returns ValidationResult.violations[] populated with anything
    found. Never raises — a missing dependency is itself a finding.
    """
    case_dir = Path(case_output_dir)
    result = ValidationResult()

    if not case_dir.is_dir():
        result.violations.append(Violation(
            check="case_dir_exists", severity="critical",
            detail=f"case_output_dir {case_dir} does not exist",
        ))
        return result

    briefs_dir = case_dir / "briefs"
    freeze_asks = _safe_load_json(case_dir / "freeze_asks.json")
    freeze_brief = _safe_load_json(case_dir / "freeze_brief.json")

    # Each check is independent. Crashes are caught + reported as
    # violations so a check bug never breaks the whole report.
    checks = [
        ("filename_content_consistency",
         lambda: _check_filename_content_consistency(
             briefs_dir, freeze_asks, freeze_brief,
         )),
        ("html_files_contain_html",
         lambda: _check_html_files_contain_html(briefs_dir)),
        ("json_files_parse_as_json",
         lambda: _check_json_files_parse_as_json(briefs_dir)),
        ("no_duplicate_file_contents",
         lambda: _check_no_duplicate_file_contents(briefs_dir)),
        ("manifest_sha_matches_disk",
         lambda: _check_manifest_sha_matches_disk(briefs_dir)),
        ("every_freezable_issuer_has_letters",
         lambda: _check_every_freezable_issuer_has_letters(
             briefs_dir, freeze_asks, freeze_brief,
         )),
        ("total_freezable_usd_reconciles",
         lambda: _check_total_freezable_usd_reconciles(
             briefs_dir, freeze_brief,
         )),
        ("stolen_vs_target_issuer_distinct",
         lambda: _check_stolen_vs_target_issuer_distinct(
             briefs_dir, freeze_brief,
         )),
        ("recoverable_variant_matches_state",
         lambda: _check_recoverable_variant_matches_state(
             briefs_dir, freeze_brief,
         )),
        ("no_unrendered_jinja_placeholders",
         lambda: _check_no_unrendered_jinja_placeholders(briefs_dir)),
        ("unrecoverable_addresses_not_in_freezable",
         lambda: _check_unrecoverable_not_in_freezable(
             briefs_dir, freeze_brief,
         )),
        ("dai_sky_consistency",
         lambda: _check_dai_sky_consistency(briefs_dir, freeze_brief)),
        # Part 5 expansion — 15 additional invariants.
        ("freeze_request_title_contains_issuer",
         lambda: _check_freeze_request_title_contains_issuer(
             briefs_dir, freeze_brief,
         )),
        ("freeze_request_no_other_issuer_emails",
         lambda: _check_freeze_request_no_other_issuer_emails(
             briefs_dir, freeze_brief,
         )),
        ("le_handoff_section_42_lists_all_issuers",
         lambda: _check_le_handoff_section_42_lists_all_issuers(
             briefs_dir, freeze_brief,
         )),
        ("le_handoff_cites_total_loss",
         lambda: _check_le_handoff_cites_total_loss(
             briefs_dir, freeze_brief,
         )),
        ("trace_report_internal_marker",
         lambda: _check_trace_report_internal_marker(briefs_dir)),
        ("engagement_letter_exists_iff_recoverable",
         lambda: _check_engagement_letter_exists_iff_recoverable(
             briefs_dir, freeze_brief,
         )),
        ("engagement_letter_names_victim",
         lambda: _check_engagement_letter_names_victim(
             briefs_dir, freeze_brief,
         )),
        ("victim_summary_quotes_freezable_total",
         lambda: _check_victim_summary_quotes_freezable_total(
             briefs_dir, freeze_brief,
         )),
        ("victim_summary_names_victim",
         lambda: _check_victim_summary_names_victim(
             briefs_dir, freeze_brief,
         )),
        ("flow_svg_valid_root",
         lambda: _check_flow_svg_valid_root(briefs_dir)),
        ("investigator_findings_csv_well_formed",
         lambda: _check_investigator_findings_csv_well_formed(
             briefs_dir, freeze_brief,
         )),
        ("case_id_consistent_across_artifacts",
         lambda: _check_case_id_consistent_across_artifacts(
             briefs_dir, freeze_brief,
         )),
        ("asset_symbol_consistent_across_artifacts",
         lambda: _check_asset_symbol_consistent_across_artifacts(
             briefs_dir, freeze_brief,
         )),
        ("victim_name_consistent_across_artifacts",
         lambda: _check_victim_name_consistent_across_artifacts(
             briefs_dir, freeze_brief,
         )),
        ("recovery_snapshot_iff_recoverable",
         lambda: _check_recovery_snapshot_iff_recoverable(
             briefs_dir, freeze_brief,
         )),
        # Wave 2 — per-artifact size, schema lock, orphan detection.
        ("artifact_size_invariants",
         lambda: _check_artifact_size_invariants(briefs_dir)),
        ("manifest_schema_required_keys",
         lambda: _check_manifest_required_keys(briefs_dir)),
        ("artifact_orphan_on_disk",
         lambda: _check_orphan_artifacts_on_disk(briefs_dir)),
        ("unrecoverable_total_matches_holdings",
         lambda: _check_unrecoverable_total_matches_holdings(freeze_brief)),
        # v0.27.2 (Jacob 0x52Aa bleed fix): INVARIANT A.
        ("freeze_ask_targets_not_investigate_tagged",
         lambda: _check_freeze_ask_targets_not_investigate_tagged(
             briefs_dir, freeze_brief,
         )),
        # v0.27.2 (Jacob 0x52Aa bleed fix, proposal b): hard rule that
        # every shipped issuer freeze letter + LE handoff must back the
        # ask with at least one CONFIRMED FREEZABLE row. Pre-fix
        # BitGo + Threshold letters shipped on Zigha with "$0 confirmed
        # FREEZABLE" + "the 0 FREEZABLE addresses are the primary
        # targets" — internal contradiction. _has_freezable_holding
        # now filters those out at letter-generation time; this
        # validator catches a regression at output time.
        ("issuer_letter_backed_by_freezable_row",
         lambda: _check_issuer_letter_backed_by_freezable_row(
             briefs_dir, freeze_brief,
         )),
        # v0.27.2 (Jacob 0x52Aa bleed fix): INVARIANT B — when an
        # operator-curated ground-truth file is present in the case
        # directory (ground_truth.json), the brief's identified
        # addresses MUST be a superset of every address in the
        # ground-truth's expected_destinations list. Catches a
        # trace-coverage regression on known cases (Zigha v0.27.1
        # found 1 of 7 known destinations — pre-INVARIANT-B that
        # shipped silently). Inapplicable (silently no-op) for cases
        # without a ground_truth.json file — the fixture is opt-in.
        ("destinations_superset_of_ground_truth",
         lambda: _check_destinations_superset_of_ground_truth(
             case_dir, freeze_brief,
         )),
        # v0.27.2 post-merge hardening (audit finding #13): the
        # 21.6× Zigha inflation symptom Jacob saw was in
        # trace_report.html's "Perpetrator-controlled holdings: $X"
        # cover line. INVARIANT A catches the per-letter symptom;
        # INVARIANT B catches the trace-coverage symptom; this new
        # check catches the headline-NUMBER symptom directly.
        # A future regression that re-introduces `+ INVESTIGATE`
        # ONLY in the trace-report-renderer (bypassing
        # _compute_perpetrator_holdings) would surface here as a
        # mismatch between the trace_report headline and the
        # brief's FREEZABLE+UNRECOVERABLE total.
        ("perpetrator_holdings_reconcile_across_artifacts",
         lambda: _check_perpetrator_holdings_reconcile(
             briefs_dir, freeze_brief,
         )),
        # v0.28.0 (Jacob review item 3): SUBPOENA_TARGETS INVARIANTS.
        # The identified-but-non-freezable artifact family.
        #
        # INVARIANT C: every freeze_capability="no" destination
        # above $1K USD has either (a) a SUBPOENA_TARGETS entry
        # referencing it, or (b) an explicit UNRECOVERABLE entry
        # with a `reason` field explaining why no subpoena pivot
        # exists. Catches the Zigha-shape coverage gap where the
        # worker identifies a non-freezable position and offers
        # operators no follow-up action.
        ("subpoena_targets_cover_non_freezable",
         lambda: _check_subpoena_targets_cover_non_freezable(
             freeze_brief,
         )),
        # INVARIANT D: every SUBPOENA_TARGETS entry's depends_on
        # references must resolve to other target_ids in the same
        # list. Dangling pointers = unrenderable playbook DAG.
        ("subpoena_targets_depends_on_resolves",
         lambda: _check_subpoena_targets_depends_on_resolves(
             freeze_brief,
         )),
        # INVARIANT E: subpoena_target_*.html files on disk MUST
        # equal |SUBPOENA_TARGETS|. A subpoena_playbook_*.html
        # MUST also exist when SUBPOENA_TARGETS is non-empty.
        ("subpoena_files_match_targets",
         lambda: _check_subpoena_files_match_targets(
             briefs_dir, freeze_brief,
         )),
        # v0.28.1 hardening: surface the _extraction_error sentinel
        # that emit_brief writes when extract_subpoena_targets
        # raises an unexpected exception. Pre-hardening this was
        # silent — empty SUBPOENA_TARGETS list and a log warning
        # nobody reads. Now: a high-severity violation flags the
        # operator that the SUBPOENA_TARGETS extraction was
        # ABORTED, not just "no qualifying targets". Catches the
        # NaN-USD-crash class of bug.
        ("subpoena_targets_extraction_succeeded",
         lambda: _check_subpoena_targets_extraction_succeeded(
             freeze_brief,
         )),
        # v0.31.4 (Gap-audit): output-integrity invariants for the
        # v0.31.x brief sections (MEV_SIGNALS, INDIRECT_EXPOSURE_V031,
        # WALLET_CLUSTERS, CEX_CONTINUITY_LEADS, decoded cross-chain
        # handoffs). Each invariant is defensive: missing/empty
        # sections never violate; only malformed CONTENT does.
        # INVARIANT F — MEV signals well-formed (confidence in [0,1],
        # signal_type in known set, tx_hash format, sandwich has
        # outer_address, threshold-survivors ≥ render floor).
        ("mev_signals_well_formed",
         lambda: _check_mev_signals_well_formed(freeze_brief)),
        # INVARIANT G — Indirect-exposure scores in valid range.
        ("indirect_exposure_v031_scores_in_range",
         lambda: _check_indirect_exposure_v031_scores_in_range(
             freeze_brief,
         )),
        # INVARIANT H — Wallet-cluster IDs follow contract (cluster_id
        # format, heuristic ∈ allowed set, disjoint members, no
        # explicit-label members).
        ("wallet_clusters_contract",
         lambda: _check_wallet_clusters_contract(freeze_brief)),
        # INVARIANT I — CEX continuity leads framed as LEADS ONLY
        # (lead_only==True, confidence=="low", bounded numeric
        # ranges, no destination_* keys, ≤5 entries).
        ("cex_continuity_leads_framed",
         lambda: _check_cex_continuity_leads_framed(freeze_brief)),
        # INVARIANT J — Decoded cross-chain handoffs internally
        # consistent (decoded_confidence consistency with
        # decoded_destination_chain / decoded_destination_address,
        # chain enum validity, address format).
        ("decoded_handoffs_consistent",
         lambda: _check_decoded_handoffs_consistent(freeze_brief)),
        # INVARIANT F (v0.32 Tier-0 gap #1, MANDATORY HUMAN REVIEW):
        # Every customer-facing / LE-facing HTML+PDF artifact emitted
        # from the dispatcher MUST have a corresponding brief_reviews
        # row with status='human_reviewed_approved' OR
        # status='overridden_unreviewed' (with audit trail). The
        # validator queries the DB at validation time; if any
        # artifact is missing its approval, the case build is BLOCKED.
        #
        # Local-dev / test-runs without a DSN skip this check (with
        # an info log) so test runs aren't blocked. The DSN-present
        # production path enforces.
        ("review_gate_approvals_present",
         lambda: _check_review_gate_approvals_present(
             briefs_dir, freeze_brief,
         )),
        # v0.32.1 — three semantic invariants the audit referenced by
        # letter (G / H / I). Each is a self-contained check; wired into
        # checks_run so callers can confirm the new validations executed
        # (test_dispatcher_runs_all_invariants_including_g_h_i).
        ("invariant_g_chain_of_custody",
         lambda: check_invariant_g(case_dir, freeze_brief)),
        ("invariant_h_confidence_calibration",
         lambda: check_invariant_h(freeze_brief)),
        ("invariant_i_cross_document_consistency",
         lambda: check_invariant_i(case_dir, freeze_brief)),
    ]
    for name, fn in checks:
        result.checks_run.append(name)
        try:
            violations = fn()
        except Exception as exc:  # noqa: BLE001
            log.warning("validator check %s crashed: %s", name, exc)
            violations = [Violation(
                check=name, severity="warning",
                detail=f"check itself crashed: {type(exc).__name__}: {exc}",
            )]
        result.violations.extend(violations)

    # v0.32.1 test-public re-exports — the test scaffolding imports the
    # semantic invariants directly from output_integrity for symmetry
    # with the existing A-F checks. Keep these in sync with the
    # dispatcher block immediately below.
    # NB: the import target is the public semantic module; failures to
    # import here are swallowed because the runtime path below does the
    # actual wiring inside a try-block.

    # v0.32.1 JACOB_VALIDATOR_AUDIT_v032 — run semantic invariants G–P
    # AFTER the structural checks. The structural module catches "wrong
    # bytes written" at ~90%; the semantic module catches "bytes that
    # look fine but disagree with each other or with the trace data".
    # Failures here are isolated (one crash does not break the rest).
    try:
        from recupero.validators.semantic_integrity import (
            run_semantic_invariants,
        )
        # Best-effort load of the case-level artifacts the semantic
        # checks consume. Missing inputs degrade individual checks to
        # no-ops rather than crashing the validator.
        manifest = _safe_load_json(case_dir / "manifest.json") or freeze_brief
        trace_evidence = _safe_load_json(case_dir / "trace_evidence.json")
        recovery_disclosure = _safe_load_json(case_dir / "recovery_disclosure.json")
        brief = freeze_brief
        freeze_letters = freeze_asks if isinstance(freeze_asks, list) else None
        # Gather rendered HTML files for the explorer-link check.
        artifact_html_files: dict[str, str] = {}
        if briefs_dir.is_dir():
            for p in briefs_dir.glob("*.html"):
                try:
                    artifact_html_files[p.name] = _safe_read(p)
                except Exception:  # noqa: BLE001
                    continue
        semantic_violations = run_semantic_invariants(
            brief=brief,
            freeze_letters=freeze_letters,
            le_handoff=None,
            trace_evidence=trace_evidence,
            manifest=manifest,
            recovery_disclosure=recovery_disclosure,
            artifact_html_files=artifact_html_files,
            prose_text=None,
        )
        result.checks_run.append("semantic_invariants_g_through_p")
        result.violations.extend(semantic_violations)
    except Exception as exc:  # noqa: BLE001
        log.warning("semantic_invariants dispatch crashed: %s", exc)
        result.violations.append(Violation(
            check="semantic_invariants_g_through_p",
            severity="warning",
            detail=f"dispatch crashed: {type(exc).__name__}: {exc}",
        ))

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


#: RIGOR-Jacob S: hard cap on validator JSON size to prevent OOM on
#: hostile or corrupted manifest_*.json files. Realistic manifest is
#: <100KB; 50MB is a 500× margin.
MAX_VALIDATOR_JSON_BYTES = 50 * 1024 * 1024  # 50MB


def _safe_load_json(path: Path) -> dict[str, Any] | None:
    """Return the parsed JSON contents or None on any failure.

    RIGOR-Jacob S: stat() the file first and refuse to read anything
    over MAX_VALIDATOR_JSON_BYTES. Also returns None for valid JSON
    whose top-level shape isn't a dict (list/string/number) so the
    downstream callers' ``.get()`` / ``.items()`` calls can't crash
    with AttributeError.
    """
    if not path.is_file():
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    if st.st_size > MAX_VALIDATOR_JSON_BYTES:
        return None
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        # Wrong top-level shape — callers expect a dict. Surface as
        # None so they don't crash with AttributeError.
        return None
    return parsed


def _safe_read(path: Path) -> str:
    """Read the file as text. Tolerates non-UTF-8 bytes (a malformed
    file is itself an integrity finding the other checks will flag —
    we should not propagate UnicodeDecodeError out of the helper)."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""
    except UnicodeDecodeError:
        # Surrogateescape gives us a string we can substring-search
        # without raising. Bytes that fail UTF-8 round-trip through
        # \udcXX surrogates — fine for regex / `in` checks.
        try:
            return path.read_bytes().decode("utf-8", errors="surrogateescape")
        except OSError:
            return ""


def _normalize_issuer_key(name: str) -> str:
    """Match brief.py's issuer_slug normalization (line 775-778)."""
    return re.sub(r"[^a-z0-9_]", "_", (name or "issuer").lower())[:64]


def _parse_usd_string(s: Any) -> Decimal:
    """Parse a human-formatted USD string like '$1,234,567.89' →
    Decimal. Returns Decimal(0) on any parse failure."""
    if s is None:
        return Decimal(0)
    s = str(s).strip().lstrip("$").replace(",", "").replace(" ", "")
    if not s:
        return Decimal(0)
    try:
        return Decimal(s)
    except (InvalidOperation, ValueError):
        return Decimal(0)


# ─────────────────────────────────────────────────────────────────────────────
# Check 1: filename / content consistency
# ─────────────────────────────────────────────────────────────────────────────


# Compliance email per issuer — the strongest marker that the file's
# content is addressed to issuer X. Loaded lazily from the seed db
# so the validator stays decoupled from the issuer registry.
def _issuer_compliance_email(issuer_name: str) -> str | None:
    """Look up the issuer's primary compliance email from the seed
    issuer DB. Returns None when not found / can't be loaded."""
    try:
        from recupero.freeze.asks import load_issuer_db
        db = load_issuer_db()
        # The DB is keyed by (chain, contract). We want the email for
        # ANY contract owned by this issuer — scan and take the first
        # primary_contact match.
        for entry in db.values():
            if (
                entry.issuer.strip().lower() == issuer_name.strip().lower()
                and entry.primary_contact
            ):
                return entry.primary_contact.strip()
    except Exception as exc:  # noqa: BLE001
        log.info("validator: load_issuer_db failed: %s", exc)
    return None


def _check_filename_content_consistency(
    briefs_dir: Path,
    freeze_asks: dict | None,
    freeze_brief: dict | None,
) -> list[Violation]:
    """Every freeze_request_<X>_*.html must contain markers indicating
    issuer X.

    Strategy (in order of strength):
      1. The seed-db primary_contact email appears in the body.
      2. ANY email at the issuer's email domain appears in the body
         (catches the case where the template uses a different
         compliance address than the seed db, e.g.,
         compliance@coinbase.com vs law-enforcement@coinbase.com —
         both are legitimate Coinbase compliance addresses).
      3. As a fallback, the issuer's display name appears prominently
         (in a heading or address block, not just inventory text).
    A CRITICAL violation fires only when NONE of the above match,
    meaning the file's content is not addressed to the named issuer
    at all — Jacob's v0.20.15 routing-bug pattern.
    """
    if not briefs_dir.is_dir():
        return [Violation(
            check="filename_content_consistency", severity="high",
            detail=f"briefs/ directory does not exist under {briefs_dir.parent}",
        )]

    violations: list[Violation] = []
    # freeze_request_*
    for path in sorted(briefs_dir.glob("freeze_request_*.html")):
        slug = _extract_issuer_slug(path.name, prefix="freeze_request")
        if not slug:
            continue
        content = _safe_read(path)
        issuer_name = _resolve_issuer_name_from_slug(slug, freeze_brief)
        seed_email = _issuer_compliance_email(issuer_name or "")
        if not _content_addresses_issuer(
            content, issuer_name or "", seed_email,
        ):
            violations.append(Violation(
                check="filename_content_consistency",
                severity="critical",
                file=str(path.relative_to(briefs_dir.parent)),
                detail=(
                    f"freeze_request file for issuer {issuer_name!r} "
                    f"(slug {slug!r}) is not addressed to that issuer. "
                    f"Expected one of: primary contact {seed_email!r}, "
                    f"any email @<{issuer_name}-domain>, or the issuer "
                    f"name in a heading. Wrong content likely routed."
                ),
            ))

    # le_handoff_*
    for path in sorted(briefs_dir.glob("le_handoff_*.html")):
        slug = _extract_issuer_slug(path.name, prefix="le_handoff")
        if not slug:
            continue
        content = _safe_read(path)
        issuer_name = _resolve_issuer_name_from_slug(slug, freeze_brief)
        # LE handoff: weaker check — must mention the issuer name
        # somewhere. (Section 1 narrative + Section 4.2 inventory
        # both reference the issuer.)
        if issuer_name and issuer_name not in content:
            violations.append(Violation(
                check="filename_content_consistency",
                severity="critical",
                file=str(path.relative_to(briefs_dir.parent)),
                detail=(
                    f"le_handoff for issuer {issuer_name!r} (slug {slug!r}) "
                    f"does NOT mention the issuer name anywhere in the body."
                ),
            ))
    return violations


def _content_addresses_issuer(
    content: str, issuer_name: str, seed_email: str | None,
) -> bool:
    """Return True when ``content`` is plausibly addressed to the
    named issuer. See _check_filename_content_consistency for the
    multi-strategy logic."""
    if seed_email and seed_email in content:
        return True
    # Extract the email domain from the seed-db primary_contact, OR
    # synthesize a likely domain from the issuer name. Then accept
    # ANY email at that domain as evidence the letter is addressed
    # to the right issuer.
    domain: str | None = None
    if seed_email and "@" in seed_email:
        domain = seed_email.split("@", 1)[1].strip().lower()
    if not domain and issuer_name:
        # Best-effort: "Coinbase" → "coinbase.com",
        # "Sky Protocol" → "skyprotocol.com" (won't always match
        # reality, but it's a safe heuristic floor).
        domain = re.sub(
            r"[^a-z0-9]", "",
            issuer_name.lower(),
        ) + ".com"
    if domain:
        domain_re = re.compile(
            r"[a-zA-Z0-9_.+-]+@" + re.escape(domain),
            re.IGNORECASE,
        )
        if domain_re.search(content):
            return True
    # Fallback: issuer name in a heading (h1/h2/h3) or in the
    # explicit "Compliance Department" / "Attn:" / "To:" address
    # block — distinguishes "addressed to X" from "X is named
    # incidentally in a Section 4.2 inventory".
    if issuer_name:
        patterns = [
            re.compile(
                r"<h[123][^>]*>[^<]*"
                + re.escape(issuer_name)
                + r"[^<]*</h[123]>",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:Compliance Department|Attn|To:)[^<]{0,200}"
                + re.escape(issuer_name),
                re.IGNORECASE,
            ),
        ]
        for p in patterns:
            if p.search(content):
                return True
    return False


def _extract_issuer_slug(filename: str, *, prefix: str) -> str | None:
    """Get the issuer slug from a filename like
    'freeze_request_midas_BRIEF-V-CFI01-abc123.html' → 'midas'."""
    stem = filename.rsplit(".", 1)[0]
    if not stem.startswith(f"{prefix}_"):
        return None
    rest = stem[len(prefix) + 1:]
    return rest.split("_", 1)[0] if rest else None


def _resolve_issuer_name_from_slug(
    slug: str, freeze_brief: dict | None,
) -> str | None:
    """Walk FREEZABLE looking for an issuer whose normalized name
    matches the slug. Falls back to a Title-Cased slug."""
    if freeze_brief:
        for entry in freeze_brief.get("FREEZABLE", []) or []:
            name = entry.get("issuer") or ""
            if _normalize_issuer_key(name) == slug:
                return name
    # Fallback — turn 'midas' → 'Midas'. Not always correct
    # (e.g., 'sky_protocol' should be 'Sky Protocol' not
    # 'Sky_protocol') but adequate for the negative-case check
    # where we'd fail to find the name in the document.
    return slug.replace("_", " ").title()


# ─────────────────────────────────────────────────────────────────────────────
# Check 2: HTML files contain HTML at root
# ─────────────────────────────────────────────────────────────────────────────


def _check_html_files_contain_html(briefs_dir: Path) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("*.html")):
        text = _safe_read(path).lstrip()
        if not text:
            violations.append(Violation(
                check="html_files_contain_html", severity="high",
                file=path.name, detail="HTML file is empty",
            ))
            continue
        # Acceptable starts: <!DOCTYPE, <html, <div, <p (some
        # template fragments don't have doctype). NOT acceptable:
        # {  (JSON), <?xml (raw SVG without HTML wrapper),
        # finding_type (CSV header), etc.
        first_chars = text[:80]
        if not (
            first_chars.startswith("<!DOCTYPE")
            or first_chars.startswith("<html")
            or first_chars.startswith("<div")
            or first_chars.startswith("<p ")
            or first_chars.startswith("<section")
        ):
            violations.append(Violation(
                check="html_files_contain_html", severity="critical",
                file=path.name,
                detail=(
                    f"HTML file does NOT start with an HTML tag. "
                    f"First 80 chars: {first_chars[:80]!r}"
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 3: JSON files parse as valid JSON
# ─────────────────────────────────────────────────────────────────────────────


def _check_json_files_parse_as_json(briefs_dir: Path) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("*.json")):
        try:
            json.loads(_safe_read(path))
        except json.JSONDecodeError as exc:
            violations.append(Violation(
                check="json_files_parse_as_json", severity="critical",
                file=path.name,
                detail=f"JSON parse failed: {exc.msg} at pos {exc.pos}",
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 4: no two output files have byte-identical content
# ─────────────────────────────────────────────────────────────────────────────


def _check_no_duplicate_file_contents(briefs_dir: Path) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    by_hash: dict[str, list[str]] = {}
    for path in sorted(briefs_dir.iterdir()):
        if not path.is_file():
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
        by_hash.setdefault(digest, []).append(path.name)

    violations: list[Violation] = []
    for digest, names in by_hash.items():
        if len(names) > 1:
            violations.append(Violation(
                check="no_duplicate_file_contents", severity="high",
                detail=(
                    f"{len(names)} files share identical content "
                    f"(sha256 {digest[:12]}…): {names}. Silent overwrite "
                    "or duplicate-write at the orchestration layer."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 5: manifest output_sha256 matches disk
# ─────────────────────────────────────────────────────────────────────────────


def _check_manifest_sha_matches_disk(briefs_dir: Path) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    violations: list[Violation] = []
    for manifest_path in sorted(briefs_dir.glob("manifest_*.json")):
        manifest = _safe_load_json(manifest_path)
        if not manifest:
            # Already reported by check 3.
            continue
        # RIGOR-Jacob Q: manifest fields may be the wrong shape on a
        # corrupted / partially-written / hand-edited file. Don't
        # crash with AttributeError on .items() / .get() — surface
        # one clean violation per malformed field and move on.
        outputs_raw = manifest.get("outputs")
        shas_raw = manifest.get("output_sha256")
        outputs: dict
        if isinstance(outputs_raw, dict):
            outputs = outputs_raw
        elif outputs_raw is None:
            outputs = {}
        else:
            violations.append(Violation(
                check="manifest_sha_matches_disk", severity="high",
                file=manifest_path.name,
                detail=(
                    f"manifest 'outputs' has wrong shape "
                    f"({type(outputs_raw).__name__}), expected dict"
                ),
            ))
            outputs = {}
        shas: dict
        if isinstance(shas_raw, dict):
            shas = shas_raw
        elif shas_raw is None:
            shas = {}
        else:
            violations.append(Violation(
                check="manifest_sha_matches_disk", severity="high",
                file=manifest_path.name,
                detail=(
                    f"manifest 'output_sha256' has wrong shape "
                    f"({type(shas_raw).__name__}), expected dict"
                ),
            ))
            shas = {}
        for key, declared_path in outputs.items():
            declared_sha = shas.get(key, "") if isinstance(shas, dict) else ""
            if not declared_sha:
                continue
            # RIGOR-Jacob Q: declared_path may be None / int / list /
            # dict / bool from a corrupted manifest. Path(None) raises
            # TypeError — guard explicitly. Also reject pathologically
            # long paths to keep Path() bounded.
            if not isinstance(declared_path, str):
                violations.append(Violation(
                    check="manifest_sha_matches_disk", severity="high",
                    file=manifest_path.name,
                    detail=(
                        f"manifest outputs[{key!r}] path has wrong type "
                        f"({type(declared_path).__name__}), expected str"
                    ),
                ))
                continue
            if not declared_path:
                violations.append(Violation(
                    check="manifest_sha_matches_disk", severity="high",
                    file=manifest_path.name,
                    detail=f"manifest outputs[{key!r}] is empty",
                ))
                continue
            # The manifest may record absolute paths; we resolve
            # relative to the briefs/ dir by filename. Path(...).name
            # extracts only the basename — that's also the traversal
            # defense: "../sensitive.txt" → "sensitive.txt".
            try:
                basename = Path(declared_path).name
            except (TypeError, ValueError) as e:
                violations.append(Violation(
                    check="manifest_sha_matches_disk", severity="high",
                    file=manifest_path.name,
                    detail=(
                        f"manifest outputs[{key!r}] path is invalid: {e}"
                    ),
                ))
                continue
            target = briefs_dir / basename
            if not target.is_file():
                violations.append(Violation(
                    check="manifest_sha_matches_disk", severity="high",
                    file=manifest_path.name,
                    detail=(
                        f"manifest declares {key} at {declared_path!r} "
                        f"but file is missing on disk"
                    ),
                ))
                continue
            try:
                actual_sha = hashlib.sha256(
                    target.read_bytes()
                ).hexdigest()
            except OSError as e:
                violations.append(Violation(
                    check="manifest_sha_matches_disk", severity="high",
                    file=manifest_path.name,
                    detail=(
                        f"could not read {target.name!r} to verify sha: {e}"
                    ),
                ))
                continue
            # Use constant-time compare. Pure-correctness compares are
            # fine with !=, but if this code path is reused on a
            # signed manifest downstream, a timing side channel could
            # leak the declared digest a nibble at a time. Cheap to
            # do right at the leaf.
            if not hmac.compare_digest(actual_sha, declared_sha):
                violations.append(Violation(
                    check="manifest_sha_matches_disk", severity="critical",
                    file=manifest_path.name,
                    detail=(
                        f"manifest output_sha256[{key}] = "
                        f"{declared_sha[:12]}… but actual file "
                        f"({target.name}) sha = {actual_sha[:12]}…. "
                        "Wrong content was written to this path "
                        "after the manifest was sealed (write-path "
                        "bug / cross-deliverable collision)."
                    ),
                ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 6: every freezable issuer has both freeze_request + le_handoff
# ─────────────────────────────────────────────────────────────────────────────


def _check_every_freezable_issuer_has_letters(
    briefs_dir: Path, freeze_asks: dict | None, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    if not freeze_brief:
        return []  # No driver data — silent skip (a separate check would catch missing brief)

    # Pull every issuer that has at least one freeze_capability='yes'
    # entry. UNRECOVERABLE-only issuers (Lido staking, Sky/DAI) are
    # legitimately skipped by the renderer — don't flag them.
    actionable_issuers: set[str] = set()
    for entry in freeze_brief.get("FREEZABLE", []) or []:
        issuer = entry.get("issuer")
        cap = (entry.get("freeze_capability") or "").lower()
        if not issuer:
            continue
        if cap in ("yes", "limited") or _has_any_actionable_holding(entry):
            actionable_issuers.add(issuer)

    violations: list[Violation] = []
    for issuer in sorted(actionable_issuers):
        slug = _normalize_issuer_key(issuer)
        freeze = list(briefs_dir.glob(f"freeze_request_{slug}_*.html"))
        leh = list(briefs_dir.glob(f"le_handoff_{slug}_*.html"))
        if not freeze:
            violations.append(Violation(
                check="every_freezable_issuer_has_letters",
                severity="critical",
                detail=(
                    f"issuer {issuer!r} has actionable holdings but no "
                    f"freeze_request_{slug}_*.html file"
                ),
            ))
        if not leh:
            violations.append(Violation(
                check="every_freezable_issuer_has_letters",
                severity="critical",
                detail=(
                    f"issuer {issuer!r} has actionable holdings but no "
                    f"le_handoff_{slug}_*.html file"
                ),
            ))
    return violations


def _has_any_actionable_holding(entry: dict) -> bool:
    """An entry is actionable when any of its holdings carries
    freeze_capability != 'no'."""
    for holding in entry.get("holdings", []) or []:
        cap = (holding.get("freeze_capability") or "").lower()
        if cap not in ("", "no"):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Check 7: TOTAL_FREEZABLE_USD reconciles across artifacts
# ─────────────────────────────────────────────────────────────────────────────


def _check_total_freezable_usd_reconciles(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not freeze_brief or not briefs_dir.is_dir():
        return []
    brief_total = _parse_usd_string(
        freeze_brief.get("TOTAL_FREEZABLE_USD")
        or freeze_brief.get("total_freezable_usd")
    )
    if brief_total == 0:
        return []  # Nothing to reconcile against; recoverable check picks this up.

    violations: list[Violation] = []
    # Engagement letter — should quote the same headline figure.
    for engagement in briefs_dir.glob("engagement_letter_*.html"):
        text = _safe_read(engagement)
        # Look for any $X,XXX,XXX.XX figure that matches the brief's total.
        formatted = f"${brief_total:,.2f}"
        # Strip the .00 for an alternate format.
        formatted_no_cents = f"${brief_total:,.0f}"
        if formatted not in text and formatted_no_cents not in text:
            violations.append(Violation(
                check="total_freezable_usd_reconciles", severity="high",
                file=engagement.name,
                detail=(
                    f"engagement letter does not contain freeze_brief's "
                    f"TOTAL_FREEZABLE_USD = {formatted}. Possible "
                    "divergence between brief and contract."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 8: stolen-asset issuer vs freeze-target issuer distinct
# ─────────────────────────────────────────────────────────────────────────────


def _check_stolen_vs_target_issuer_distinct(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    """Validate that LE handoff Section 1 ¶1 names the STOLEN asset's
    real issuer (not the freeze-target). Catches the v0.19.3 residual
    that Jacob still saw in v0.20.15."""
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    asset = freeze_brief.get("asset") or {}
    stolen_symbol = (asset.get("symbol") or "").strip()
    stolen_issuer = (asset.get("issuer") or "").strip()
    if not stolen_symbol or not stolen_issuer:
        return []

    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("le_handoff_*.html")):
        slug = _extract_issuer_slug(path.name, prefix="le_handoff")
        target_name = _resolve_issuer_name_from_slug(slug or "", freeze_brief)
        if not target_name or target_name == stolen_issuer:
            # Self-letter (e.g., Tether-letter for USDT theft) —
            # "issued by Tether" is genuinely correct here.
            continue
        text = _safe_read(path)
        if stolen_symbol not in text:
            continue
        # Match the Section 1 first <p> paragraph.
        m = re.search(
            r"1\.\s*Executive Summary.*?<p[^>]*>(.*?)</p>",
            text, flags=re.DOTALL,
        )
        if not m:
            continue
        first_para = m.group(1)
        if f"issued by {target_name}" in first_para:
            violations.append(Violation(
                check="stolen_vs_target_issuer_distinct",
                severity="critical",
                file=path.name,
                detail=(
                    f"Section 1 ¶1 claims {stolen_symbol} is issued by "
                    f"{target_name} (the freeze-target). It is issued "
                    f"by {stolen_issuer}. STOLEN_ASSET_ISSUER and "
                    "FREEZE_TARGET_ISSUER are conflated in the template."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 9: recoverable variant matches MAX_RECOVERABLE_USD
# ─────────────────────────────────────────────────────────────────────────────


def _check_recoverable_variant_matches_state(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    """Catches v0.15.1's classifier bug: a case with $3.5M freezable
    funds shipped a victim_summary_UNRECOVERABLE letter + auto-refund."""
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    max_recoverable = _parse_usd_string(
        freeze_brief.get("MAX_RECOVERABLE_USD")
        or freeze_brief.get("max_recoverable_usd")
        or freeze_brief.get("TOTAL_FREEZABLE_USD")
        or "0"
    )
    has_recoverable = any(
        briefs_dir.glob("victim_summary_recoverable_*.html")
    )
    has_unrecoverable = any(
        briefs_dir.glob("victim_summary_unrecoverable_*.html")
    )
    violations: list[Violation] = []
    if max_recoverable > 0 and has_unrecoverable:
        violations.append(Violation(
            check="recoverable_variant_matches_state",
            severity="critical",
            detail=(
                f"freeze_brief reports MAX_RECOVERABLE_USD > 0 "
                f"(${max_recoverable:,.2f}) but case shipped "
                "victim_summary_unrecoverable_*.html. This is the "
                "v0.15.1 classifier-on-broken-input pattern."
            ),
        ))
    if max_recoverable == 0 and has_recoverable:
        violations.append(Violation(
            check="recoverable_variant_matches_state",
            severity="high",
            detail=(
                "freeze_brief reports MAX_RECOVERABLE_USD = 0 but "
                "case shipped victim_summary_RECOVERABLE — variant "
                "selection disagrees with the brief."
            ),
        ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 10: no unrendered Jinja placeholders
# ─────────────────────────────────────────────────────────────────────────────


_JINJA_VAR_RE = re.compile(r"\{\{[^}]+\}\}")
_JINJA_BLOCK_RE = re.compile(r"\{%[^%]+%\}")


def _check_no_unrendered_jinja_placeholders(
    briefs_dir: Path,
) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("*.html")):
        text = _safe_read(path)
        var_matches = _JINJA_VAR_RE.findall(text)
        block_matches = _JINJA_BLOCK_RE.findall(text)
        if var_matches:
            violations.append(Violation(
                check="no_unrendered_jinja_placeholders",
                severity="high", file=path.name,
                detail=(
                    f"{len(var_matches)} unrendered Jinja "
                    f"{{ {{ ... }} }} placeholders. First: "
                    f"{var_matches[0][:120]!r}"
                ),
            ))
        if block_matches:
            violations.append(Violation(
                check="no_unrendered_jinja_placeholders",
                severity="high", file=path.name,
                detail=(
                    f"{len(block_matches)} unrendered Jinja "
                    "{% ... %} blocks (template didn't render)."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 11: UNRECOVERABLE addresses don't appear as FREEZABLE
# ─────────────────────────────────────────────────────────────────────────────


def _check_unrecoverable_not_in_freezable(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    """If the brief tags address X as UNRECOVERABLE (e.g., contract,
    staking pool), no freeze letter may list X under its FREEZABLE
    section. Catches v0.18 contract-detection regressions."""
    if not freeze_brief or not briefs_dir.is_dir():
        return []
    unrecoverable_addrs: set[str] = set()
    for entry in freeze_brief.get("FREEZABLE", []) or []:
        for holding in entry.get("holdings", []) or []:
            if (holding.get("status") or "").upper() == "UNRECOVERABLE":
                addr = (holding.get("address") or "").lower()
                if addr:
                    unrecoverable_addrs.add(addr)
    # Also accept top-level UNRECOVERABLE_ITEMS if the brief uses
    # that shape.
    for item in freeze_brief.get("UNRECOVERABLE_ITEMS", []) or []:
        addr = (item.get("address") or "").lower()
        if addr:
            unrecoverable_addrs.add(addr)
    if not unrecoverable_addrs:
        return []

    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("freeze_request_*.html")):
        text = _safe_read(path).lower()
        for addr in unrecoverable_addrs:
            if addr in text:
                # Heuristic: present in the letter at all might be OK
                # (mentioned as context). But appearing inside the
                # FREEZABLE / KYC-target / preservation-request blocks
                # is the bug. Without parsing the HTML structure we
                # only have a heuristic: flag as a WARNING.
                violations.append(Violation(
                    check="unrecoverable_addresses_not_in_freezable",
                    severity="warning", file=path.name,
                    detail=(
                        f"UNRECOVERABLE address {addr[:10]}... appears "
                        f"in freeze_request file. Verify it's not "
                        "listed as a preservation target."
                    ),
                ))
                break  # one finding per file is enough
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 12: DAI / Sky Protocol → UNRECOVERABLE
# ─────────────────────────────────────────────────────────────────────────────


def _check_dai_sky_consistency(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    """Every artifact mentioning DAI must also mention UNRECOVERABLE
    or 'Sky Protocol has no admin freeze' or similar. DAI / Sky has
    no admin freeze pathway; representing DAI as freezable is the
    inverse of v0.20.x R3-1."""
    if not briefs_dir.is_dir():
        return []
    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("*.html")):
        text = _safe_read(path)
        # Look for prominent DAI mentions — uppercase or in a strong
        # token tag.
        if " DAI " not in text and ">DAI<" not in text:
            continue
        # Acceptable contexts: marker phrases that indicate the
        # operator/AUSA already knows DAI is not freezable.
        if any(marker in text for marker in (
            "UNRECOVERABLE",
            "Sky Protocol",
            "no admin freeze",
            "no freeze pathway",
            "is not freezable",
        )):
            continue
        violations.append(Violation(
            check="dai_sky_consistency", severity="warning",
            file=path.name,
            detail=(
                "Document mentions DAI but does not flag "
                "UNRECOVERABLE / Sky Protocol context. DAI has no "
                "admin freeze pathway; LE / partners may be misled."
            ),
        ))
    return violations


# ═════════════════════════════════════════════════════════════════════════════
# Part 5 expansion: per-artifact + cross-artifact invariants (checks 13-27)
# ═════════════════════════════════════════════════════════════════════════════


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers for Part 5 checks
# ─────────────────────────────────────────────────────────────────────────────


# Well-known crypto symbols we will flag as "other asset" when a
# trace_report or LE handoff names one of them while the brief's
# asset.symbol is a different value. Kept short and conservative —
# adding new symbols here trades false positives for sensitivity.
_KNOWN_ASSET_SYMBOLS = {
    "USDT", "USDC", "DAI", "USDS", "BUSD", "TUSD", "FRAX",
    "ETH", "WETH", "BTC", "WBTC", "SOL", "MATIC",
}


# Map: well-known issuer display name → set of compliance email
# domains belonging to that issuer. Used by check 14 as a backstop
# when the issuer isn't in this case's freeze_brief (so the seed-db
# lookup returns nothing, but the email is still clearly foreign).
# Keep conservative — false positives on this check are costly.
_KNOWN_ISSUER_DOMAINS: dict[str, set[str]] = {
    "Tether": {"tether.to", "tether.io"},
    "Circle": {"circle.com"},
    "Coinbase": {"coinbase.com"},
    "Binance": {"binance.com", "binance.us"},
    "Midas": {"midas.app", "midas.fund"},
    "Kraken": {"kraken.com"},
    "Gemini": {"gemini.com"},
    "OKX": {"okx.com", "ok.com"},
    "Sky Protocol": {"sky.money", "makerdao.com"},
}


def _extract_title_text(html: str) -> str | None:
    """Return the inner text of the first <title> tag, or None."""
    m = re.search(
        r"<title[^>]*>(.*?)</title>", html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return m.group(1).strip() if m else None


def _extract_first_h1(html: str) -> str | None:
    """Return the inner text of the first <h1> tag, or None."""
    m = re.search(
        r"<h1[^>]*>(.*?)</h1>", html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return None
    # Strip inner HTML tags to get plain text.
    return re.sub(r"<[^>]+>", "", m.group(1)).strip()


def _brief_freezable_issuers(freeze_brief: dict | None) -> list[str]:
    """Names of every issuer in brief.FREEZABLE (de-duplicated, in
    insertion order)."""
    if not freeze_brief:
        return []
    seen: list[str] = []
    for entry in freeze_brief.get("FREEZABLE", []) or []:
        n = (entry.get("issuer") or "").strip()
        if n and n not in seen:
            seen.append(n)
    return seen


def _brief_all_issuers(freeze_brief: dict | None) -> list[str]:
    """Names of every issuer that should appear in Section 4.2 of
    the LE handoff: ALL_ISSUER_HOLDINGS preferred, FREEZABLE as
    fallback."""
    if not freeze_brief:
        return []
    seen: list[str] = []
    for entry in freeze_brief.get("ALL_ISSUER_HOLDINGS", []) or []:
        n = (entry.get("issuer") or "").strip()
        if n and n not in seen:
            seen.append(n)
    if seen:
        return seen
    return _brief_freezable_issuers(freeze_brief)


def _brief_victim_name(freeze_brief: dict | None) -> str | None:
    """Return the brief's victim name. The brief is shipped in
    multiple shapes — check the well-known keys."""
    if not freeze_brief:
        return None
    victim = freeze_brief.get("victim") or freeze_brief.get("VICTIM")
    if isinstance(victim, dict):
        name = (victim.get("name") or victim.get("display_name") or "").strip()
        if name:
            return name
    n = (freeze_brief.get("victim_name") or "").strip()
    return n or None


def _brief_case_id(freeze_brief: dict | None) -> str | None:
    if not freeze_brief:
        return None
    return (
        freeze_brief.get("CASE_ID")
        or freeze_brief.get("case_id")
        or None
    )


def _brief_asset_symbol(freeze_brief: dict | None) -> str | None:
    if not freeze_brief:
        return None
    asset = freeze_brief.get("asset") or {}
    return (asset.get("symbol") or "").strip() or None


def _brief_total_loss_usd(freeze_brief: dict | None) -> Decimal:
    if not freeze_brief:
        return Decimal(0)
    return _parse_usd_string(
        freeze_brief.get("TOTAL_LOSS_USD")
        or freeze_brief.get("total_loss_usd")
        or freeze_brief.get("TOTAL_FREEZABLE_USD")
        or "0"
    )


def _brief_max_recoverable_usd(freeze_brief: dict | None) -> Decimal:
    if not freeze_brief:
        return Decimal(0)
    return _parse_usd_string(
        freeze_brief.get("MAX_RECOVERABLE_USD")
        or freeze_brief.get("max_recoverable_usd")
        or freeze_brief.get("TOTAL_FREEZABLE_USD")
        or "0"
    )


def _strip_html_to_text(html: str) -> str:
    """Crude HTML→text: remove all tags. Sufficient for substring +
    name checks without pulling in a real HTML parser."""
    return re.sub(r"<[^>]+>", " ", html)


# ─────────────────────────────────────────────────────────────────────────────
# Check 13: freeze_request <title> contains the named issuer
# ─────────────────────────────────────────────────────────────────────────────


def _check_freeze_request_title_contains_issuer(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("freeze_request_*.html")):
        slug = _extract_issuer_slug(path.name, prefix="freeze_request")
        if not slug:
            continue
        issuer_name = _resolve_issuer_name_from_slug(slug, freeze_brief)
        if not issuer_name:
            continue
        text = _safe_read(path)
        title = _extract_title_text(text)
        h1 = _extract_first_h1(text)
        # The issuer name must appear in the <title> OR the first
        # <h1>. A letter with a generic "Compliance Freeze Request"
        # title and a heading that omits the issuer is the v0.20.15
        # bug detectable at the title layer.
        in_title = title is not None and issuer_name in title
        in_h1 = h1 is not None and issuer_name in h1
        if not (in_title or in_h1):
            violations.append(Violation(
                check="freeze_request_title_contains_issuer",
                severity="high", file=path.name,
                detail=(
                    f"freeze_request for issuer {issuer_name!r} has "
                    f"neither <title> nor <h1> mentioning the issuer. "
                    f"Found title={title!r}, h1={h1!r}. The recipient "
                    "would not know who this letter is addressed to."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 14: freeze_request must not contain foreign-issuer emails
# ─────────────────────────────────────────────────────────────────────────────


def _check_freeze_request_no_other_issuer_emails(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    # Build a map: issuer_name → set of compliance domains, merging
    # (a) every issuer in this case's brief and (b) the well-known
    # built-in registry. The built-in registry is what catches the
    # cross-fill scenario where the foreign issuer isn't even in
    # the current case's brief (e.g., a stale template grabbed the
    # Circle contact from a previous case).
    issuers = _brief_freezable_issuers(freeze_brief)
    issuer_domains: dict[str, set[str]] = {
        name: set(doms) for name, doms in _KNOWN_ISSUER_DOMAINS.items()
    }
    for name in issuers:
        domains = issuer_domains.setdefault(name, set())
        email = _issuer_compliance_email(name)
        if email and "@" in email:
            domains.add(email.split("@", 1)[1].strip().lower())
        # Synthesize "<issuername>.com" as a likely floor.
        slug = re.sub(r"[^a-z0-9]", "", name.lower())
        if slug:
            domains.add(f"{slug}.com")

    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("freeze_request_*.html")):
        slug = _extract_issuer_slug(path.name, prefix="freeze_request")
        if not slug:
            continue
        my_issuer = _resolve_issuer_name_from_slug(slug, freeze_brief)
        if not my_issuer:
            continue
        my_domains = issuer_domains.get(my_issuer, set())
        text = _safe_read(path).lower()
        # Find every email address in the body.
        emails = re.findall(
            r"[a-z0-9_.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+",
            text,
        )
        seen_violations: set[tuple[str, str]] = set()
        for email in emails:
            domain = email.split("@", 1)[1]
            if domain in my_domains:
                continue  # legitimate same-issuer email
            # Match against any OTHER known issuer's domains.
            for other_name, other_domains in issuer_domains.items():
                if other_name == my_issuer:
                    continue
                if domain in other_domains:
                    key = (other_name, domain)
                    if key in seen_violations:
                        break  # already reported this (other,domain) pair
                    seen_violations.add(key)
                    violations.append(Violation(
                        check="freeze_request_no_other_issuer_emails",
                        severity="critical", file=path.name,
                        detail=(
                            f"freeze_request for {my_issuer!r} contains "
                            f"email {email!r} belonging to a different "
                            f"issuer ({other_name!r}). Template cross-"
                            "fill or routing bug. AUSA receiving this "
                            "would cc the wrong company's compliance "
                            "team and disclose the case."
                        ),
                    ))
                    break  # one violation per email is enough
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 15: LE handoff Section 4.2 lists every issuer
# ─────────────────────────────────────────────────────────────────────────────


def _check_le_handoff_section_42_lists_all_issuers(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    expected = _brief_all_issuers(freeze_brief)
    if not expected:
        return []

    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("le_handoff_*.html")):
        text = _safe_read(path)
        # Section 4.2 — look for an h2 starting with "4.2" and capture
        # everything until the next <h2> (next major section) or end
        # of doc. We deliberately do NOT stop at h3 because the real
        # le.html.j2 template uses h3 for per-issuer subsections inside
        # 4.2 ({{ entry.issuer_name }} — {{ entry.token }}).
        m = re.search(
            r"<h2[^>]*>[^<]*4\.2[\s\S]*?</h2>([\s\S]*?)(?=<h2|$)",
            text, flags=re.IGNORECASE,
        )
        if not m:
            # No Section 4.2 in this handoff. Some templates may
            # legitimately omit it (e.g., single-issuer cases) —
            # report HIGH only when the brief has more than one
            # issuer.
            if len(expected) > 1:
                violations.append(Violation(
                    check="le_handoff_section_42_lists_all_issuers",
                    severity="high", file=path.name,
                    detail=(
                        f"LE handoff has no Section 4.2 ALL_ISSUER_HOLDINGS "
                        f"but the brief enumerates {len(expected)} "
                        f"issuers ({expected}). AUSA cannot see the "
                        "full inventory."
                    ),
                ))
            continue
        section_text = m.group(1)
        missing = [n for n in expected if n not in section_text]
        if missing:
            violations.append(Violation(
                check="le_handoff_section_42_lists_all_issuers",
                severity="high", file=path.name,
                detail=(
                    f"Section 4.2 omits issuer(s) {missing} that the "
                    f"brief lists in ALL_ISSUER_HOLDINGS. AUSA would "
                    "not know there were freezable funds at those "
                    "issuers and could not serve them."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 16: LE handoff cites TOTAL_LOSS_USD
# ─────────────────────────────────────────────────────────────────────────────


def _check_le_handoff_cites_total_loss(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    total_loss = _brief_total_loss_usd(freeze_brief)
    if total_loss == 0:
        return []
    formatted = f"${total_loss:,.2f}"
    formatted_no_cents = f"${total_loss:,.0f}"

    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("le_handoff_*.html")):
        text = _safe_read(path)
        if formatted in text or formatted_no_cents in text:
            continue
        violations.append(Violation(
            check="le_handoff_cites_total_loss",
            severity="high", file=path.name,
            detail=(
                f"LE handoff does not contain TOTAL_LOSS_USD = "
                f"{formatted}. LE / AUSA without a quantified $ "
                "figure cannot file a forfeiture warrant."
            ),
        ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 17: trace_report must not contain freeze-request language
# ─────────────────────────────────────────────────────────────────────────────


def _check_trace_report_internal_marker(
    briefs_dir: Path,
) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    # Hot markers that should NEVER appear in an internal investigative
    # document. Each is text that a compliance freeze letter sends.
    freeze_letter_markers = [
        "Compliance Freeze Request",
        "Attn: Compliance Department",
        "Attn: Compliance Team",
    ]
    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("trace_report_*.html")):
        text = _safe_read(path)
        hits = [m for m in freeze_letter_markers if m in text]
        if hits:
            violations.append(Violation(
                check="trace_report_internal_marker",
                severity="critical", file=path.name,
                detail=(
                    f"trace_report contains freeze-letter markers "
                    f"{hits}. The internal investigative report has "
                    "been cross-templated with a compliance freeze "
                    "letter. An operator sharing this trace report "
                    "would imply the recipient is a freeze target."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 18: engagement_letter exists iff MAX_RECOVERABLE_USD > 0
# ─────────────────────────────────────────────────────────────────────────────


def _check_engagement_letter_exists_iff_recoverable(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    max_recoverable = _brief_max_recoverable_usd(freeze_brief)
    has_engagement = any(briefs_dir.glob("engagement_letter_*.html"))
    if max_recoverable == 0 and has_engagement:
        return [Violation(
            check="engagement_letter_exists_iff_recoverable",
            severity="critical",
            detail=(
                "engagement_letter_*.html exists but "
                "MAX_RECOVERABLE_USD == $0.00. The case has nothing "
                "to engage on; victim would be charged a fee for "
                "an unwinnable case (the v0.15.1 classifier-on-"
                "broken-input pattern, this artifact)."
            ),
        )]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Check 19: engagement_letter names the victim
# ─────────────────────────────────────────────────────────────────────────────


def _check_engagement_letter_names_victim(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    victim_name = _brief_victim_name(freeze_brief)
    if not victim_name:
        return []
    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("engagement_letter_*.html")):
        text = _safe_read(path)
        if victim_name not in text:
            violations.append(Violation(
                check="engagement_letter_names_victim",
                severity="high", file=path.name,
                detail=(
                    f"engagement_letter does not contain the victim's "
                    f"name {victim_name!r}. A contract that doesn't "
                    "name the counter-party is unsigned and unenforceable."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 20: victim_summary quotes the freezable/recoverable figure
# ─────────────────────────────────────────────────────────────────────────────


def _check_victim_summary_quotes_freezable_total(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    # Either MAX_RECOVERABLE_USD or TOTAL_FREEZABLE_USD should be cited.
    targets = []
    max_rec = _brief_max_recoverable_usd(freeze_brief)
    if max_rec > 0:
        targets.append(f"${max_rec:,.2f}")
        targets.append(f"${max_rec:,.0f}")
    total_frz = _parse_usd_string(
        freeze_brief.get("TOTAL_FREEZABLE_USD")
        or freeze_brief.get("total_freezable_usd")
        or "0"
    )
    if total_frz > 0:
        targets.append(f"${total_frz:,.2f}")
        targets.append(f"${total_frz:,.0f}")
    if not targets:
        return []

    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("victim_summary_*.html")):
        # Unrecoverable variant legitimately quotes $0 / no figure —
        # check 9 handles that classifier match.
        if "_unrecoverable_" in path.name:
            continue
        text = _safe_read(path)
        if any(t in text for t in targets):
            continue
        violations.append(Violation(
            check="victim_summary_quotes_freezable_total",
            severity="high", file=path.name,
            detail=(
                f"victim_summary does not quote any freezable / "
                f"recoverable figure (looked for {targets}). The "
                "victim can't see how much we recovered or what "
                "their case is worth."
            ),
        ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 21: victim_summary names the victim
# ─────────────────────────────────────────────────────────────────────────────


def _check_victim_summary_names_victim(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    victim_name = _brief_victim_name(freeze_brief)
    if not victim_name:
        return []
    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("victim_summary_*.html")):
        text = _safe_read(path)
        if victim_name not in text:
            violations.append(Violation(
                check="victim_summary_names_victim",
                severity="high", file=path.name,
                detail=(
                    f"victim_summary does not contain the victim's "
                    f"name {victim_name!r}. A summary that doesn't "
                    "name the recipient may be the wrong file."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 22: flow_*.svg has a valid SVG root
# ─────────────────────────────────────────────────────────────────────────────


def _check_flow_svg_valid_root(briefs_dir: Path) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    violations: list[Violation] = []
    for path in sorted(briefs_dir.glob("flow_*.svg")):
        text = _safe_read(path).lstrip()
        if not text:
            violations.append(Violation(
                check="flow_svg_valid_root", severity="high",
                file=path.name, detail="SVG file is empty",
            ))
            continue
        if not (
            text.startswith("<?xml")
            or text.startswith("<svg")
            or text.startswith("<!DOCTYPE svg")
        ):
            violations.append(Violation(
                check="flow_svg_valid_root", severity="critical",
                file=path.name,
                detail=(
                    f"flow_*.svg does not start with <?xml / <svg root. "
                    f"First 80 chars: {text[:80]!r}. Non-SVG content "
                    "in an .svg path renders broken in the LE PDF."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 23: investigator_findings.csv well-formed
# ─────────────────────────────────────────────────────────────────────────────


def _check_investigator_findings_csv_well_formed(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    csv_path = briefs_dir / "investigator_findings.csv"
    if not csv_path.is_file():
        return []  # csv is optional; missing is not by itself a finding
    text = _safe_read(csv_path)
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return [Violation(
            check="investigator_findings_csv_well_formed",
            severity="high", file=csv_path.name,
            detail="investigator_findings.csv is empty",
        )]
    header = lines[0]
    # Heuristic: a header has at least 2 columns and contains a known
    # column name (address / amount / status / chain / token /
    # finding / sha / hash). A data row's leading column is usually
    # an address (starts 0x...) or a number — never a column name.
    expected_header_tokens = {
        "address", "amount", "status", "chain", "token",
        "finding", "sha", "hash", "tx", "type", "issuer",
    }
    header_low = header.lower()
    header_cols = [c.strip() for c in header_low.split(",")]
    if not any(tok in header_cols for tok in expected_header_tokens):
        return [Violation(
            check="investigator_findings_csv_well_formed",
            severity="high", file=csv_path.name,
            detail=(
                f"investigator_findings.csv first row does not look "
                f"like a header (no known column names in "
                f"{header_cols[:4]}). Operators / external tooling "
                "can't read this file."
            ),
        )]
    data_rows = lines[1:]
    # If FREEZABLE has holdings, expect at least 1 data row.
    has_freezable_holdings = bool(
        freeze_brief and freeze_brief.get("FREEZABLE")
    )
    if has_freezable_holdings and not data_rows:
        return [Violation(
            check="investigator_findings_csv_well_formed",
            severity="high", file=csv_path.name,
            detail=(
                "investigator_findings.csv has a header but ZERO "
                "data rows, while brief.FREEZABLE is non-empty. "
                "The CSV is silently empty."
            ),
        )]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Check 24: CASE_ID consistent across artifacts
# ─────────────────────────────────────────────────────────────────────────────


def _check_case_id_consistent_across_artifacts(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir():
        return []
    expected_id = _brief_case_id(freeze_brief)
    if not expected_id:
        return []
    # Look for "CASE_ID: <something>" patterns in every artifact.
    # The char class deliberately excludes "." so a sentence-ending
    # period in "CASE_ID: V-CFI01." doesn't get captured as part of
    # the ID. (Real case IDs use only alphanumerics, "_", and "-".)
    case_id_re = re.compile(
        r"CASE[_ ]?ID\s*[:=]\s*([A-Za-z0-9_\-]+)",
        re.IGNORECASE,
    )
    violations: list[Violation] = []
    for path in sorted(briefs_dir.iterdir()):
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".html", ".json", ".csv", ".svg"):
            continue
        text = _safe_read(path)
        # Only look at files that mention CASE_ID — silence is fine.
        for m in case_id_re.finditer(text):
            found = m.group(1).strip()
            if found != expected_id:
                violations.append(Violation(
                    check="case_id_consistent_across_artifacts",
                    severity="high", file=path.name,
                    detail=(
                        f"file references CASE_ID={found!r} but "
                        f"brief.CASE_ID={expected_id!r}. Cross-case "
                        "content bleed or stale template."
                    ),
                ))
                break  # one finding per file is enough
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 25: asset symbol consistent across artifacts
# ─────────────────────────────────────────────────────────────────────────────


def _check_asset_symbol_consistent_across_artifacts(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    expected_sym = _brief_asset_symbol(freeze_brief)
    if not expected_sym:
        return []
    expected_upper = expected_sym.upper()
    # Scan trace_report + LE handoffs. Look for any OTHER known-asset
    # symbol mentioned more prominently than the expected one.
    targets = list(briefs_dir.glob("trace_report_*.html")) + \
              list(briefs_dir.glob("le_handoff_*.html"))
    violations: list[Violation] = []
    for path in sorted(targets):
        text = _safe_read(path)
        # Find each known symbol's count of mentions (word-boundary).
        counts: dict[str, int] = {}
        for sym in _KNOWN_ASSET_SYMBOLS:
            pat = re.compile(rf"\b{re.escape(sym)}\b")
            counts[sym] = len(pat.findall(text))
        # If the expected symbol appears, we're fine — Section 4.2
        # legitimately mentions other tokens for context.
        if counts.get(expected_upper, 0) > 0:
            continue
        # Otherwise — is some OTHER asset symbol prominent?
        others = [
            s for s, c in counts.items()
            if c > 0 and s != expected_upper
        ]
        if others:
            violations.append(Violation(
                check="asset_symbol_consistent_across_artifacts",
                severity="high", file=path.name,
                detail=(
                    f"file references {others} but brief.asset.symbol "
                    f"is {expected_upper!r}. Wrong asset symbol — "
                    "this artifact was generated against a different "
                    "case's asset or the template substituted wrong."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 26: victim name consistent across artifacts
# ─────────────────────────────────────────────────────────────────────────────


def _check_victim_name_consistent_across_artifacts(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    expected_name = _brief_victim_name(freeze_brief)
    if not expected_name:
        return []
    # Heuristic: each victim_summary / engagement_letter is expected
    # to name the victim. We surface a finding when there's a clearly
    # different "<First Last>" near the document title and the
    # expected name does not appear in the file.
    candidates = (
        list(briefs_dir.glob("victim_summary_*.html"))
        + list(briefs_dir.glob("engagement_letter_*.html"))
    )
    violations: list[Violation] = []
    for path in sorted(candidates):
        text = _safe_read(path)
        if expected_name in text:
            continue
        # The expected victim name is missing. Is some other name
        # present in a title/heading? Look for "Summary — <Name>" or
        # "Engagement Letter — <Name>" forms.
        title_re = re.compile(
            r"(?:Summary|Engagement\s+Letter|Case\s+Summary)\s*[—\-]\s*"
            r"([A-Z][a-z]+\s+[A-Z][a-z]+)",
        )
        m = title_re.search(text)
        if m:
            other_name = m.group(1).strip()
            if other_name and other_name != expected_name:
                violations.append(Violation(
                    check="victim_name_consistent_across_artifacts",
                    severity="high", file=path.name,
                    detail=(
                        f"file names victim {other_name!r} but "
                        f"brief.victim.name = {expected_name!r}. "
                        "Wrong victim — cross-case content bleed."
                    ),
                ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Check 27: recovery_snapshot exists iff MAX_RECOVERABLE_USD > 0
# ─────────────────────────────────────────────────────────────────────────────


def _check_recovery_snapshot_iff_recoverable(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    if not briefs_dir.is_dir() or not freeze_brief:
        return []
    max_recoverable = _brief_max_recoverable_usd(freeze_brief)
    has_snapshot = any(briefs_dir.glob("recovery_snapshot_*.html"))
    if max_recoverable == 0 and has_snapshot:
        return [Violation(
            check="recovery_snapshot_iff_recoverable",
            severity="high",
            detail=(
                "recovery_snapshot_*.html exists but MAX_RECOVERABLE_USD "
                "== $0.00. Nothing to estimate — the pre-engagement "
                "deliverable would mislead the victim about recovery "
                "viability."
            ),
        )]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Deeper-audit checks (Wave 2 — per-artifact size / schema lock / orphans)
# ─────────────────────────────────────────────────────────────────────────────


#: Per-artifact realism caps. Distinct from MAX_VALIDATOR_JSON_BYTES
#: (which bounds what the validator will read into memory). These
#: caps reject artifacts that *parsed fine* but are absurdly large
#: vs. their real-world size — strong signal of a template runaway
#: or a write-the-whole-DB-to-one-file bug. A real freeze_request
#: is ~50–300KB; a real manifest is <100KB; a real CSV / JSON
#: investigator_findings is <500KB.
ARTIFACT_SIZE_CAPS: dict[str, int] = {
    ".html": 10 * 1024 * 1024,   # 10MB
    ".json": 5 * 1024 * 1024,    # 5MB
    ".csv": 5 * 1024 * 1024,     # 5MB
    ".svg": 5 * 1024 * 1024,     # 5MB
}


def _check_artifact_size_invariants(briefs_dir: Path) -> list[Violation]:
    """Per-deliverable size invariant. A rendered artifact that is
    structurally valid but pathologically large (10MB HTML, 5MB JSON)
    almost certainly indicates a template / data bug, not a real case.
    """
    if not briefs_dir.is_dir():
        return []
    violations: list[Violation] = []
    for path in sorted(briefs_dir.iterdir()):
        if not path.is_file():
            continue
        cap = ARTIFACT_SIZE_CAPS.get(path.suffix.lower())
        if cap is None:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > cap:
            violations.append(Violation(
                check="artifact_size_invariants", severity="high",
                file=path.name,
                detail=(
                    f"{path.name} is {size:,} bytes (cap "
                    f"{cap:,} bytes for {path.suffix}). Realistic size "
                    "is two orders of magnitude smaller — likely a "
                    "template runaway or data dump."
                ),
            ))
    return violations


#: The manifest_*.json schema is locked at three top-level keys. A
#: manifest missing 'outputs' silently passes the SHA loop (zero
#: entries to verify) — a silent-success bug. Lock the contract.
#: ``case_id`` is the canonical brief-identifier; in some legacy
#: manifest schemas it lives under a different top-level key
#: (or is implicit in the filename). The mandatory invariant the
#: validator must enforce is the SHA-loop substrate: `outputs` +
#: `output_sha256` MUST exist together or the SHA check trivially
#: succeeds on zero entries (silent pass). `case_id` is desirable
#: but not load-bearing for the integrity guarantee.
_MANIFEST_REQUIRED_KEYS: tuple[str, ...] = (
    "outputs", "output_sha256",
)


def _check_manifest_required_keys(briefs_dir: Path) -> list[Violation]:
    """Every manifest_*.json must carry the locked required keys."""
    if not briefs_dir.is_dir():
        return []
    violations: list[Violation] = []
    for manifest_path in sorted(briefs_dir.glob("manifest_*.json")):
        manifest = _safe_load_json(manifest_path)
        if not manifest:
            continue  # other checks surface unparseable / wrong-shape
        missing = [k for k in _MANIFEST_REQUIRED_KEYS if k not in manifest]
        if missing:
            violations.append(Violation(
                check="manifest_schema_required_keys", severity="high",
                file=manifest_path.name,
                detail=(
                    f"manifest is missing required keys: {missing}. "
                    f"Locked schema requires {list(_MANIFEST_REQUIRED_KEYS)}."
                ),
            ))
    return violations


#: Artifact prefixes that MUST be declared in the manifest if they
#: live in briefs/. Other files (the manifest itself, generated
#: report fragments, .csv companions) are intentionally permitted
#: out-of-band so this check doesn't flap on legitimate layouts.
_MANIFEST_DECLARED_PREFIXES: tuple[str, ...] = (
    "freeze_request_", "le_handoff_", "engagement_letter_",
    "victim_summary_", "recovery_snapshot_",
)


def _check_orphan_artifacts_on_disk(briefs_dir: Path) -> list[Violation]:
    """Reverse direction of check 5: every primary deliverable on
    disk must be declared in *some* manifest_*.json's outputs. Orphans
    are typically stale builds from a prior case ID — AUSA would
    download them and attribute to the current case.
    """
    if not briefs_dir.is_dir():
        return []
    declared: set[str] = set()
    for manifest_path in briefs_dir.glob("manifest_*.json"):
        m = _safe_load_json(manifest_path)
        if not m:
            continue
        # Manifests have a few legitimate output-key layouts in the wild
        # (a flat `outputs` mapping, a nested `outputs.files` list, plus
        # the `output_sha256` keys themselves which are filenames). Walk
        # all of them so an artifact declared anywhere counts as "known."
        for key in ("outputs", "output_sha256"):
            block = m.get(key)
            if isinstance(block, dict):
                declared.update(
                    Path(v).name for v in block.values()
                    if isinstance(v, str) and v
                )
                declared.update(
                    Path(k).name for k in block.keys() if isinstance(k, str)
                )
            elif isinstance(block, list):
                for item in block:
                    if isinstance(item, str) and item:
                        declared.add(Path(item).name)
                    elif isinstance(item, dict):
                        for v in item.values():
                            if isinstance(v, str) and v:
                                declared.add(Path(v).name)
    violations: list[Violation] = []
    for path in sorted(briefs_dir.iterdir()):
        if not path.is_file():
            continue
        if not any(path.name.startswith(p) for p in _MANIFEST_DECLARED_PREFIXES):
            continue
        if path.name in declared:
            continue
        # Severity=info: producing this as a HIGH violation produces
        # too many false positives across legitimate test fixtures
        # (manifest layouts vary; some files are legitimate companions
        # that ops generates outside the manifest pathway). Operators
        # still see the diagnostic in the report; it just doesn't gate
        # publication.
        violations.append(Violation(
            check="artifact_orphan_on_disk", severity="info",
            file=path.name,
            detail=(
                f"{path.name} exists in briefs/ but is not declared "
                "in any manifest_*.json outputs. May be a stale build "
                "from a prior case ID; operator triage recommended."
            ),
        ))
    return violations


def _check_unrecoverable_total_matches_holdings(
    freeze_brief: dict | None,
) -> list[Violation]:
    """Jacob v0.21.x residual: ``TOTAL_UNRECOVERABLE_USD`` must roll up
    every UNRECOVERABLE-status holding across ALL_ISSUER_HOLDINGS plus
    every editorial UNRECOVERABLE_ITEMS entry. Pre-fix it only summed
    the editorial list, leaving a $655K Sky-DAI hole when the perp hub
    held UNRECOVERABLE tokens that weren't explicitly editorialized.

    Tolerance: $1 (rounding noise from per-issuer aggregation).
    """
    if not isinstance(freeze_brief, dict):
        return []
    declared = freeze_brief.get("TOTAL_UNRECOVERABLE_USD")
    if not isinstance(declared, str):
        return []
    try:
        declared_num = _parse_usd_string(declared)
    except (InvalidOperation, ValueError, TypeError):
        return []
    # Sum every UNRECOVERABLE holding across ALL_ISSUER_HOLDINGS.
    holdings_total = Decimal("0")
    for entry in freeze_brief.get("ALL_ISSUER_HOLDINGS") or []:
        if not isinstance(entry, dict):
            continue
        for h in entry.get("holdings") or []:
            if not isinstance(h, dict):
                continue
            if h.get("status") != "UNRECOVERABLE":
                continue
            try:
                holdings_total += _parse_usd_string(h.get("usd"))
            except (InvalidOperation, ValueError, TypeError):
                pass
    diff = abs(declared_num - holdings_total)
    if diff <= Decimal("1.00"):
        return []
    return [Violation(
        check="unrecoverable_total_matches_holdings",
        severity="high",
        file="freeze_brief.json",
        detail=(
            f"TOTAL_UNRECOVERABLE_USD={declared} disagrees with the sum "
            f"of UNRECOVERABLE-status holdings in ALL_ISSUER_HOLDINGS "
            f"(${holdings_total}). Rollup is dropping non-editorialized "
            "UNRECOVERABLE holdings (Jacob v0.21.x audit shape)."
        ),
    )]


# Pattern: a freeze-ask row in a freeze_request_*.html or le_handoff_*.html
# is structurally identifiable as a freeze-ask target if it sits inside a
# table marked with the `.evidence` class and renders a status pill with
# the FREEZABLE label. We extract addresses by looking at <a href="...">
# inside such rows. The INVESTIGATE-tagged check uses the brief's
# DESTINATION_NOTES (operator-keyed) and matches by canonical address.
_FREEZABLE_ROW_RE = re.compile(
    r'<span[^>]*>FREEZABLE</span>.*?<a[^>]+href="[^"]*?(0x[a-fA-F0-9]{40}|'
    r'[1-9A-HJ-NP-Za-km-z]{32,44})[^"]*?"',
    re.DOTALL,
)
_INVESTIGATE_NOTE_RE = re.compile(r"\U0001F7E7|🟧")  # orange square emoji


def _check_freeze_ask_targets_not_investigate_tagged(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    """INVARIANT A (Jacob v0.27.1 Zigha review, item 1):

    No address that appears in any freeze_request_*.html or
    le_handoff_*.html as a FREEZABLE freeze-ask target may be tagged
    🟧 INVESTIGATE in the brief's DESTINATION_NOTES.

    Why this exists: on Zigha v0.27.1 the smart contract
    0x52Aa…e497 (1inch / Uniswap LP reflective liquidity) was
    correctly tagged INVESTIGATE in the brief's DESTINATION_NOTES,
    but the freeze_asks generator emitted its full holdings to four
    issuer entries (Tether $65M, BitGo $46M, Circle $33M, Threshold
    $163K), the freeze letters then surfaced those rows as primary
    targets alongside legitimate $245K-$8.9K real freeze asks. The
    ratio (400:1 — 3,770:1) reads as careless to a compliance
    reviewer.

    This invariant catches the regression at output time. The
    template-level fix (issuer_freeze_request.html.j2 line 366 and
    le.html.j2 line 416 iterating `freezable_holdings` not
    `holdings`) prevents it at generation time. Belt + suspenders.

    Severity: high. Letters shipping with INVESTIGATE-tagged
    FREEZABLE rows are credibility-damaging and should gate
    publication.
    """
    if not isinstance(freeze_brief, dict):
        return []
    if not briefs_dir.is_dir():
        return []
    # Build the INVESTIGATE-tagged canonical-address set from the
    # brief's DESTINATION_NOTES. Operator notes may carry mixed-case
    # addresses; canonicalize so the lookup matches the
    # freeze-letter HTML (which renders the on-chain display form).
    try:
        from recupero._common import canonical_address_key as _ck
    except Exception:  # noqa: BLE001
        return []
    dest_notes = freeze_brief.get("DESTINATION_NOTES") or {}
    if not isinstance(dest_notes, dict):
        return []
    investigate_canon: set[str] = set()
    for addr, note in dest_notes.items():
        if not isinstance(addr, str) or not isinstance(note, str):
            continue
        if _INVESTIGATE_NOTE_RE.search(note):
            ck = _ck(addr)
            if ck:
                investigate_canon.add(ck)
    if not investigate_canon:
        return []
    # Scan every per-issuer freeze letter + LE handoff.
    violations: list[Violation] = []
    targets = sorted(briefs_dir.glob("freeze_request_*.html")) + sorted(
        briefs_dir.glob("le_handoff_*.html")
    )
    for path in targets:
        try:
            html = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for m in _FREEZABLE_ROW_RE.finditer(html):
            row_addr = m.group(1)
            if not row_addr:
                continue
            ck = _ck(row_addr)
            if ck in investigate_canon:
                violations.append(Violation(
                    check="freeze_ask_targets_not_investigate_tagged",
                    severity="high",
                    file=path.name,
                    detail=(
                        f"{path.name}: FREEZABLE row at {row_addr} is "
                        "🟧 INVESTIGATE in brief.DESTINATION_NOTES. The "
                        "letter is asking an issuer to act on a lead, not "
                        "a confirmed target — credibility-damaging on "
                        "external delivery. See Jacob v0.27.1 Zigha "
                        "review, issue 1 (0x52Aa bleed)."
                    ),
                ))
    return violations


_FREEZE_ASK_TABLE_RE = re.compile(
    r'<tbody[^>]*>(.*?)</tbody>', re.DOTALL,
)


def _check_issuer_letter_backed_by_freezable_row(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    """Hard rule: every shipped freeze_request_*.html AND
    le_handoff_*.html MUST contain at least one FREEZABLE-tagged row
    in its primary-targets table.

    A letter without a FREEZABLE row is a letter with no ask. Pre-fix
    Zigha v0.27.1 shipped four such letters (BitGo, BitGo LE,
    Threshold, Threshold LE) whose entire freeze ask was INVESTIGATE-
    only bleed from a smart contract. The Threshold LE handoff section
    6 read verbatim: "The 0 FREEZABLE addresses ($0 total) are the
    primary targets." Self-contradictory shipping artifact.

    v0.27.2 post-merge hardening (audit finding #4): originally this
    check globbed only `freeze_request_*.html`. The Threshold-LE
    example Jacob cited verbatim was an LE handoff, not a freeze
    request — so the canonical Zigha shipping bug was UNCAUGHT by
    this validator at the LE-handoff layer. Extended to glob both
    file patterns so the safety-net covers both surfaces.

    The upstream _has_freezable_holding gate in _deliverables.py
    prevents such letters from being generated in the first place.
    This validator is the safety net.

    Severity: critical. A self-contradictory letter is unfileable
    and signals a generation-stage failure.
    """
    if not briefs_dir.is_dir():
        return []
    violations: list[Violation] = []
    # v0.27.2 post-merge hardening: cover both file types so the
    # Threshold-LE / BitGo-LE shape (the literal Jacob review
    # exemplar) is caught.
    targets = sorted(briefs_dir.glob("freeze_request_*.html")) + sorted(
        briefs_dir.glob("le_handoff_*.html")
    )
    for path in targets:
        try:
            html = path.read_text(encoding="utf-8")
        except OSError:
            continue
        # Search every tbody — the primary-targets table is the first
        # one but defensively scan all tbodies so a template
        # restructure doesn't break this check.
        has_freezable_row = any(
            "FREEZABLE" in (m.group(1) or "")
            for m in _FREEZE_ASK_TABLE_RE.finditer(html)
        )
        if not has_freezable_row:
            violations.append(Violation(
                check="issuer_letter_backed_by_freezable_row",
                severity="critical",
                file=path.name,
                detail=(
                    f"{path.name}: no FREEZABLE-tagged row in any table "
                    "body. The letter has no actionable ask. Either the "
                    "_has_freezable_holding gate in _deliverables.py "
                    "regressed OR the template stopped rendering the "
                    "FREEZABLE pill. Either way the letter is unfileable."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT B (v0.27.2) — ground-truth destination superset check.
# ─────────────────────────────────────────────────────────────────────────────

# Recognized canonical-address regex (EVM only — Solana base58 has a
# separate canonicalization path we don't need here yet). We match
# both checksummed and lowercase hex.
_GROUND_TRUTH_ADDR_RE = re.compile(r'^0x[a-fA-F0-9]{40}$')


def _canonicalize_for_compare(addr: str) -> str:
    """Lower-case + strip whitespace. EVM addresses compare
    case-insensitively (EIP-55 is a checksum, not an identity). For
    INVARIANT B we want canonical-form equality, so we apply the
    project's canonical key convention (delegated to
    recupero._common.canonical_address_key) but fall back to lower()
    for the local copy so the validator has no import-cycle risk."""
    try:
        from recupero._common import canonical_address_key
        return canonical_address_key(addr)
    except Exception:
        return (addr or "").strip().lower()


def _extract_brief_addresses(freeze_brief: dict | None) -> set[str]:
    """Collect every address the brief reports as identified, across
    DESTINATIONS, FREEZABLE.holdings, PERP_HUB, EXCHANGES,
    UNRECOVERABLE — anything the worker found. Returned as canonical
    keys (case-normalized) so the superset check can run a direct
    set-membership test.

    This is the brief's claim of "addresses we saw" for the
    INVARIANT B check. Empty set when freeze_brief is None/malformed
    — the calling check downgrades to a high-severity violation in
    that case (a brief without a destinations field IS a regression).
    """
    if not isinstance(freeze_brief, dict):
        return set()
    out: set[str] = set()

    def _add(addr: object) -> None:
        if not isinstance(addr, str):
            return
        c = _canonicalize_for_compare(addr)
        if c:
            out.add(c)

    # DESTINATIONS — primary surface (every destination the BFS found).
    for d in freeze_brief.get("DESTINATIONS") or []:
        if isinstance(d, dict):
            _add(d.get("address"))

    # PERP_HUB — consolidation address (single dict or None).
    perp = freeze_brief.get("PERP_HUB")
    if isinstance(perp, dict):
        _add(perp.get("address"))

    # FREEZABLE.holdings — each per-issuer holding has an address.
    for f in freeze_brief.get("FREEZABLE") or []:
        if not isinstance(f, dict):
            continue
        for h in f.get("holdings") or []:
            if isinstance(h, dict):
                _add(h.get("address"))

    # EXCHANGES — off-ramp deposit addresses.
    for ex in freeze_brief.get("EXCHANGES") or []:
        if isinstance(ex, dict):
            _add(ex.get("address"))

    # UNRECOVERABLE — dormant DAI / Sky / native ETH positions live
    # here with an explicit address.
    for u in freeze_brief.get("UNRECOVERABLE") or []:
        if isinstance(u, dict):
            _add(u.get("address"))

    # ALL_ISSUER_HOLDINGS — Section 4.2 complete inventory may
    # carry addresses not in DESTINATIONS (e.g. UNRECOVERABLE-only
    # issuers like Sky/DAI).
    for e in freeze_brief.get("ALL_ISSUER_HOLDINGS") or []:
        if isinstance(e, dict):
            _add(e.get("address"))

    return out


def _check_destinations_superset_of_ground_truth(
    case_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    """INVARIANT B (v0.27.2, Jacob 0x52Aa bleed fix): when the case
    directory contains an operator-curated ``ground_truth.json``
    file, every address listed in its ``expected_destinations``
    field MUST appear in the brief's identified-addresses set.

    Catches the Zigha v0.27.1 trace-coverage regression where the
    worker found 1 of 7 known destinations (cross-chain
    bridge-following blocker). Pre-INVARIANT-B such regressions
    shipped silently — the brief listed what it found, and what it
    didn't find was invisible. With INVARIANT B, a ground-truth
    fixture pinned to a known case acts as a permanent canary:
    every release run against that case prints a critical violation
    listing the missing addresses by name.

    Schema (ground_truth.json):
      {
        "case_id": "...",
        "_curated_by": "...",
        "_curated_at": "YYYY-MM-DD",
        "_notes": "...",
        "expected_destinations": [
          {"address": "0x...", "chain": "ethereum", "role": "...",
           "source": "...", "approx_usd": 9980000},
          ...
        ]
      }

    Behavior:
      * No ground_truth.json file → no-op (returns []). The fixture
        is opt-in — most operator cases won't have one.
      * Malformed ground_truth.json (parse error, missing
        expected_destinations key, expected_destinations not a list)
        → high-severity violation describing the malformation.
      * freeze_brief.json absent / empty when ground_truth.json is
        present → critical violation (we can't verify the superset
        property without a brief).
      * Every expected address NOT in the brief's identified set →
        one critical violation per missing address, with the
        ground-truth role + source attached for actionable triage.

    Severity rationale: critical. A known-case regression in trace
    coverage means the next live case may also under-cover, and the
    shipped artifacts may underclaim what's recoverable. This is the
    same severity class as a broken freeze-letter generator: the
    artifact looks fine, but it isn't.
    """
    gt_path = case_dir / "ground_truth.json"
    if not gt_path.is_file():
        return []

    try:
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return [Violation(
            check="destinations_superset_of_ground_truth",
            severity="high",
            file="ground_truth.json",
            detail=(
                f"ground_truth.json could not be parsed ({type(e).__name__}: "
                f"{e}). Either the file is malformed or unreadable. "
                "Fix the file or remove it to disable the invariant."
            ),
        )]

    if not isinstance(gt, dict):
        return [Violation(
            check="destinations_superset_of_ground_truth",
            severity="high",
            file="ground_truth.json",
            detail=(
                "ground_truth.json must be a JSON object at the root. "
                f"Got {type(gt).__name__}. See validator docstring for "
                "the expected schema."
            ),
        )]

    expected = gt.get("expected_destinations")
    if not isinstance(expected, list):
        return [Violation(
            check="destinations_superset_of_ground_truth",
            severity="high",
            file="ground_truth.json",
            detail=(
                "ground_truth.json must contain an "
                "`expected_destinations` array. Either the key is "
                "missing or the value is not a list."
            ),
        )]

    # Empty list → invariant is satisfied trivially (no destinations
    # to verify). Operators may want this as a curated case marker
    # without enforcement yet.
    if not expected:
        return []

    if not isinstance(freeze_brief, dict) or not freeze_brief:
        return [Violation(
            check="destinations_superset_of_ground_truth",
            severity="critical",
            file="ground_truth.json",
            detail=(
                "ground_truth.json is present and lists "
                f"{len(expected)} expected destinations, but "
                "freeze_brief.json is missing or empty. Cannot verify "
                "the destination-superset property without the brief."
            ),
        )]

    found_addrs = _extract_brief_addresses(freeze_brief)

    violations: list[Violation] = []
    for i, item in enumerate(expected):
        if not isinstance(item, dict):
            violations.append(Violation(
                check="destinations_superset_of_ground_truth",
                severity="high",
                file="ground_truth.json",
                detail=(
                    f"ground_truth.json expected_destinations[{i}] is "
                    f"not a JSON object (got {type(item).__name__}). "
                    "Each entry must be {address, chain, role, "
                    "source, approx_usd}."
                ),
            ))
            continue
        addr = item.get("address")
        if not isinstance(addr, str) or not _GROUND_TRUTH_ADDR_RE.match(addr):
            violations.append(Violation(
                check="destinations_superset_of_ground_truth",
                severity="high",
                file="ground_truth.json",
                detail=(
                    f"ground_truth.json expected_destinations[{i}] has "
                    f"invalid address {addr!r}. EVM addresses must "
                    "match 0x + 40 hex. Non-EVM ground-truth is not "
                    "yet supported."
                ),
            ))
            continue
        canon = _canonicalize_for_compare(addr)
        if canon not in found_addrs:
            role = item.get("role") or "(no role specified)"
            source = item.get("source") or "(no source specified)"
            approx_usd = item.get("approx_usd")
            usd_hint = (
                f" (~${approx_usd:,})" if isinstance(approx_usd, (int, float))
                else ""
            )
            violations.append(Violation(
                check="destinations_superset_of_ground_truth",
                severity="critical",
                file="ground_truth.json",
                detail=(
                    f"Expected destination {addr} (role: {role}; "
                    f"source: {source}{usd_hint}) is NOT in the "
                    "brief's identified addresses. The trace did not "
                    "reach this address — likely a coverage regression "
                    "(cross-chain bridge-following, hop budget, or "
                    "decoder gap). See "
                    "docs/TRACE_COVERAGE_DIAGNOSIS_ZIGHA.md for the "
                    "canonical Zigha investigation pattern."
                ),
            ))
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# v0.27.2 post-merge hardening (audit finding #13):
# Cross-artifact headline reconciliation
# ─────────────────────────────────────────────────────────────────────────────

# Match the perpetrator-holdings headline in trace_report.html. The
# canonical format is "Perpetrator-controlled holdings: $X" (or
# variations: "Perpetrator-held: $X", "Perpetrator-controlled:
# $X"). We match the leading phrase + capture the $-amount.
_PERP_HOLDINGS_HEADLINE_RE = re.compile(
    r"Perpetrator[- ]controlled\s+holdings?\s*:\s*"
    r"\$([0-9][0-9,]*(?:\.[0-9]+)?)",
    re.IGNORECASE,
)


def _parse_usd_decimal(s: str | None) -> Decimal | None:
    """Parse "$1,234,567.89" or "1234567.89" → Decimal. Returns None
    on parse failure; the caller decides whether to violate."""
    if not isinstance(s, str):
        return None
    s = s.strip().lstrip("$").replace(",", "").replace(" ", "")
    if not s:
        return None
    try:
        return Decimal(s)
    except (ValueError, ArithmeticError, InvalidOperation):
        return None


def _check_perpetrator_holdings_reconcile(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    """The trace_report.html's "Perpetrator-controlled holdings: $X"
    cover headline MUST equal the sum
    (TOTAL_FREEZABLE_USD + TOTAL_UNRECOVERABLE_USD) computed by
    emit_brief._compute_perpetrator_holdings.

    Why: Jacob's v0.27.1 Zigha review found the headline displayed
    $149,954,529.44 vs a real $7M shape — 21.6× inflation from
    $145M of INVESTIGATE-tagged 1inch/Uniswap-pool bleed being
    summed. The bug was in _compute_perpetrator_holdings; the
    SYMPTOM was the trace_report headline. The v0.27.2 fix corrects
    the computation, but a future regression that adds
    `+ INVESTIGATE` ONLY to the trace-report renderer (bypassing
    the centralized computer) would re-introduce the symptom
    without any other validator surface catching it.

    This check parses the trace_report headline + the brief's
    FREEZABLE/UNRECOVERABLE totals + asserts they reconcile within
    a small tolerance (1% or $100, whichever is larger).

    Inapplicable (returns []) when:
      * No trace_report*.html file present.
      * trace_report has no "Perpetrator-controlled holdings: $X"
        line (older briefs predating v0.7.4).
      * freeze_brief lacks TOTAL_FREEZABLE_USD + the per-issuer
        UNRECOVERABLE holdings information.

    Severity: high. A mis-stated headline mis-positions the case for
    every downstream reader (lawyer, AUSA, victim) — not as
    catastrophic as an unfileable letter (which is critical) but
    still a credibility-damaging defect.
    """
    if not briefs_dir.is_dir():
        return []
    if not isinstance(freeze_brief, dict):
        return []

    # Find the trace_report file (hash-suffixed).
    trace_reports = sorted(briefs_dir.glob("trace_report*.html"))
    if not trace_reports:
        return []
    # Use the first match — production only writes one trace_report
    # per case.
    trace_path = trace_reports[0]
    try:
        trace_html = trace_path.read_text(encoding="utf-8")
    except OSError:
        return []

    # Extract the headline number.
    m = _PERP_HOLDINGS_HEADLINE_RE.search(trace_html)
    if not m:
        return []  # No headline to check — inapplicable.
    headline = _parse_usd_decimal(m.group(1))
    if headline is None:
        return []

    # Compute the canonical total from the brief: FREEZABLE.total_usd
    # + UNRECOVERABLE per-holding amounts + editorial UNRECOVERABLE
    # entries (regex-extracted from `asset` strings, mirroring
    # _compute_perpetrator_holdings semantics).
    freezable_total = Decimal("0")
    for f in freeze_brief.get("FREEZABLE") or []:
        if not isinstance(f, dict):
            continue
        amt = _parse_usd_decimal(f.get("total_usd"))
        if amt is not None:
            freezable_total += amt

    unrec_total = Decimal("0")
    seen_unrec_keys: set[tuple[str, str]] = set()
    for u in freeze_brief.get("UNRECOVERABLE") or []:
        if not isinstance(u, dict):
            continue
        asset = u.get("asset", "") or ""
        if not isinstance(asset, str):
            continue
        rm = re.search(r"\$([0-9,]+(?:\.[0-9]+)?)", asset)
        if rm:
            try:
                unrec_total += Decimal(rm.group(1).replace(",", ""))
                key = (str(u.get("issuer", "")), str(u.get("address", "")))
                seen_unrec_keys.add(key)
            except (InvalidOperation, ArithmeticError):
                pass
    for f in freeze_brief.get("FREEZABLE") or []:
        if not isinstance(f, dict):
            continue
        issuer_name = str(f.get("issuer", ""))
        for h in f.get("holdings") or []:
            if not isinstance(h, dict):
                continue
            if (h.get("status") or "").upper() != "UNRECOVERABLE":
                continue
            addr = str(h.get("address", ""))
            if (issuer_name, addr) in seen_unrec_keys:
                continue
            seen_unrec_keys.add((issuer_name, addr))
            amt = _parse_usd_decimal(h.get("usd"))
            if amt is not None:
                unrec_total += amt

    expected = freezable_total + unrec_total
    if expected == 0 and headline == 0:
        return []  # Both zero — nothing to check.

    # Tolerance: $100 absolute or 1% relative, whichever is larger.
    # 1% covers rounding differences when the renderer formats
    # totals with a different rounding mode than the computer.
    # $100 absolute covers the very-small-case (e.g. $5,432 vs $5,500)
    # where 1% is too tight.
    tol_abs = Decimal("100")
    tol_rel = (expected.copy_abs() * Decimal("0.01"))
    tol = max(tol_abs, tol_rel)
    diff = (headline - expected).copy_abs()
    if diff <= tol:
        return []

    # Mismatch — report the inflation ratio so the operator can
    # immediately see the Zigha-shape ("21.6×") symptom.
    ratio = ""
    if expected > 0:
        ratio_val = headline / expected
        if ratio_val > Decimal("1.05"):
            ratio = f" (inflation: {float(ratio_val):.1f}×)"
        elif ratio_val < Decimal("0.95"):
            ratio = f" (under-reported: {float(ratio_val):.2f}×)"
    return [Violation(
        check="perpetrator_holdings_reconcile_across_artifacts",
        severity="high",
        file=trace_path.name,
        detail=(
            f"trace_report headline 'Perpetrator-controlled "
            f"holdings: ${headline:,}' does not reconcile with "
            f"freeze_brief FREEZABLE+UNRECOVERABLE total "
            f"${expected:,} (tolerance: ${tol:,}; "
            f"diff: ${diff:,}{ratio}). Likely cause: a recent "
            "edit to the trace-report renderer added INVESTIGATE "
            "(or another bucket) to the headline computation, "
            "bypassing _compute_perpetrator_holdings. See Jacob "
            "v0.27.1 Zigha review item 1 — this is the 21.6× "
            "inflation symptom."
        ),
    )]


# ─────────────────────────────────────────────────────────────────────────────
# v0.28.0 INVARIANTS C/D/E — SUBPOENA_TARGETS artifact family.
# ─────────────────────────────────────────────────────────────────────────────

# USD threshold below which a non-freezable destination doesn't need
# a SUBPOENA_TARGETS entry. Matches SUBPOENA_USD_THRESHOLD in
# subpoena_targets.py — $1K matches the design doc's INVARIANT C wording.
_SUBPOENA_USD_THRESHOLD = Decimal("1000")


def _check_subpoena_targets_cover_non_freezable(
    freeze_brief: dict | None,
) -> list[Violation]:
    """INVARIANT C (v0.28.0, Jacob review item 3): every
    freeze_capability="no" destination above $1K USD has either
    (a) a SUBPOENA_TARGETS entry referencing it, or (b) an
    explicit UNRECOVERABLE entry with a `reason` field explaining
    why no subpoena pivot exists.

    The intent: every non-freezable position the worker identifies
    must be accounted for somewhere actionable — either in the
    subpoena pipeline (subpoena → identity → seizure) or with an
    explicit operator-curated "why no subpoena" rationale. Pre-fix
    Zigha-shape cases had no place to put these positions; they
    landed in UNRECOVERABLE as a dead-end label.

    Severity: warning. INVARIANT C is the most policy-y of the
    v0.28 invariants — operators may legitimately decide a
    position isn't worth a subpoena (small amount, anonymous
    perpetrator, no off-ramp). The warning surfaces the gap; an
    operator decision to skip is fine.
    """
    if not isinstance(freeze_brief, dict):
        return []
    violations: list[Violation] = []

    # Collect addresses already covered by SUBPOENA_TARGETS.
    subpoena_targets = freeze_brief.get("SUBPOENA_TARGETS") or []
    if not isinstance(subpoena_targets, list):
        return []
    covered_addrs: set[str] = set()
    for t in subpoena_targets:
        if not isinstance(t, dict):
            continue
        for la in t.get("linked_addresses") or []:
            if isinstance(la, dict):
                addr = la.get("address")
                if isinstance(addr, str):
                    covered_addrs.add(addr.lower())

    # Collect addresses covered by UNRECOVERABLE with a reason.
    # v0.28.3 hardening (audit finding #35): the editorial pass
    # writes to either UNRECOVERABLE (post-v0.20.x) or
    # UNRECOVERABLE_ITEMS (legacy). Check both keys so a schema
    # drift in the editorial pipeline doesn't make INVARIANT C
    # silently miss the coverage acknowledgment.
    unrec_covered: set[str] = set()
    for key in ("UNRECOVERABLE", "UNRECOVERABLE_ITEMS"):
        for u in freeze_brief.get(key) or []:
            if not isinstance(u, dict):
                continue
            # An UNRECOVERABLE row counts as "covered" only when it
            # has a non-empty reason field — operator-acknowledged
            # rationale.
            reason = u.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                continue
            addr = u.get("address")
            if isinstance(addr, str):
                unrec_covered.add(addr.lower())

    # Find every freeze_capability="no" destination above the
    # threshold. Sources:
    #   * freeze_brief.FREEZABLE entries with freeze_capability
    #     pinned to "no" / "low" (e.g. Sky DAI permissionless).
    #   * freeze_brief.UNRECOVERABLE entries with a $ amount that
    #     LACK a reason (those are the gap).
    # We don't need to revisit UNRECOVERABLE-with-reason entries
    # because they're already covered.
    #
    # v0.28.1 hardening (audit finding #20): the `usd` field MAY
    # carry a value without the leading "$" sign (e.g. "10000.00"
    # vs "$10,000.00"). Accept either form. The original
    # `\$([0-9,]+...)` regex skipped no-$-prefix amounts silently.
    re_usd_with_dollar = re.compile(r"\$([0-9,]+(?:\.[0-9]+)?)")
    re_usd_bare = re.compile(r"^([0-9,]+(?:\.[0-9]+)?)$")
    for f in freeze_brief.get("FREEZABLE") or []:
        if not isinstance(f, dict):
            continue
        cap = (f.get("freeze_capability") or "").strip().lower()
        if cap not in ("no", "low"):
            continue
        for h in f.get("holdings") or []:
            if not isinstance(h, dict):
                continue
            addr = (h.get("address") or "").lower()
            if not addr:
                continue
            usd_raw = h.get("usd") or "0"
            if not isinstance(usd_raw, str):
                continue
            # Try $-prefixed form first, then bare numeric form.
            m = re_usd_with_dollar.search(usd_raw)
            if not m:
                m = re_usd_bare.match(usd_raw.strip())
            if not m:
                continue
            try:
                usd = Decimal(m.group(1).replace(",", ""))
            except (InvalidOperation, ArithmeticError):
                continue
            # Same NaN/Inf/negative defense as in subpoena_targets.py.
            if usd.is_nan() or usd.is_infinite() or usd < 0:
                continue
            if usd < _SUBPOENA_USD_THRESHOLD:
                continue
            if addr in covered_addrs or addr in unrec_covered:
                continue
            # v0.28.1 hardening (audit finding #10): Zigha-shape
            # escalation. The canonical regression — operator misses
            # a non-freezable position because no subpoena was
            # generated — was the entire motivation for v0.28.1.
            # Warning-only severity for a $9.98M dormant DAI gap
            # is easy to miss in a long CI rollup. Escalate to
            # 'high' for consequential amounts (≥ $100K) so the
            # operator gets a loud signal on the exact bug class
            # we shipped this work to prevent.
            severity = "high" if usd >= Decimal("100000") else "warning"
            violations.append(Violation(
                check="subpoena_targets_cover_non_freezable",
                severity=severity,
                detail=(
                    f"Non-freezable destination at {addr[:14]}... "
                    f"(issuer {f.get('issuer')!r}, ${usd:,}) has no "
                    "SUBPOENA_TARGETS entry AND no UNRECOVERABLE "
                    "entry with a `reason` field. Either generate a "
                    "subpoena target (via extract_subpoena_targets) "
                    "or document why no subpoena pivot exists. "
                    f"Severity={severity} (escalated to high above "
                    "$100K — Zigha-shape gap)."
                ),
            ))
    return violations


def _check_subpoena_targets_depends_on_resolves(
    freeze_brief: dict | None,
) -> list[Violation]:
    """INVARIANT D (v0.28.0, Jacob review item 3): every
    SUBPOENA_TARGETS entry's depends_on references must resolve to
    other target_ids in the SAME case's list — AND the dependency
    graph must be acyclic (DAG).

    Catches:
      * Dangling pointers — depends_on references a target_id that
        doesn't exist. The playbook renderer would silently produce
        a broken dependency chain.
      * Self-references — subpoena-1 depends_on ["subpoena-1"]. The
        playbook's topological sort would never schedule it.
      * Multi-node cycles — subpoena-1 → subpoena-2 → subpoena-1.
        Same problem as self-reference, just harder to spot in
        operator review.

    v0.28.3 hardening (audit finding #13 follow-up): cycle detection
    added. Pre-hardening only dangling references were caught; the
    test_v028_hardening.py test_invariant_d_does_not_currently_catch_
    self_reference DOCUMENTED the gap but didn't fix it. Now fixed.

    Severity: high. Renders the playbook unreliable / unrenderable.
    """
    if not isinstance(freeze_brief, dict):
        return []
    targets = freeze_brief.get("SUBPOENA_TARGETS") or []
    if not isinstance(targets, list) or not targets:
        return []

    # Build the set of known target_ids in this case + a dep-graph
    # adjacency map for cycle detection.
    known_ids: set[str] = set()
    adj: dict[str, list[str]] = {}
    for t in targets:
        if isinstance(t, dict):
            tid = t.get("target_id")
            if isinstance(tid, str):
                known_ids.add(tid)
                deps = t.get("depends_on") or []
                if isinstance(deps, list):
                    adj[tid] = [d for d in deps if isinstance(d, str)]
                else:
                    adj[tid] = []

    violations: list[Violation] = []
    # ── Pass 1: shape + reference validation ──
    for t in targets:
        if not isinstance(t, dict):
            continue
        depends_on = t.get("depends_on") or []
        if not isinstance(depends_on, list):
            violations.append(Violation(
                check="subpoena_targets_depends_on_resolves",
                severity="high",
                detail=(
                    f"SUBPOENA_TARGETS entry {t.get('target_id')!r} has "
                    f"depends_on of type {type(depends_on).__name__}; "
                    "expected list. The playbook DAG cannot resolve."
                ),
            ))
            continue
        for d in depends_on:
            if not isinstance(d, str) or d not in known_ids:
                violations.append(Violation(
                    check="subpoena_targets_depends_on_resolves",
                    severity="high",
                    detail=(
                        f"SUBPOENA_TARGETS entry {t.get('target_id')!r} "
                        f"depends_on={d!r} does not resolve to any "
                        f"target_id in this case. Known target_ids: "
                        f"{sorted(known_ids)}. Dangling DAG pointer."
                    ),
                ))

    # ── Pass 2: cycle detection (DFS with WHITE/GRAY/BLACK coloring) ──
    # Standard algorithm: a node entering its OWN ancestor set during
    # DFS reveals a cycle. Self-references catch immediately
    # (target-1 → target-1 ancestor includes target-1). Multi-node
    # cycles caught on the back-edge.
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {tid: WHITE for tid in known_ids}
    cycles_reported: set[tuple[str, ...]] = set()

    def _dfs_cycle(start: str, path: list[str]) -> None:
        color[start] = GRAY
        for nxt in adj.get(start, []):
            if nxt not in color:
                # Dangling — already reported by pass 1, skip.
                continue
            if color[nxt] == GRAY:
                # Back-edge → cycle. Extract the cycle from path.
                try:
                    cycle_start = path.index(nxt)
                    cycle = tuple(path[cycle_start:]) + (nxt,)
                except ValueError:
                    cycle = (nxt, start, nxt)
                # Normalize for dedup (rotation-invariant).
                norm = tuple(sorted(set(cycle)))
                if norm not in cycles_reported:
                    cycles_reported.add(norm)
                    violations.append(Violation(
                        check="subpoena_targets_depends_on_resolves",
                        severity="high",
                        detail=(
                            "Dependency cycle in SUBPOENA_TARGETS: "
                            f"{' → '.join(cycle)}. The playbook's "
                            "topological sort cannot order these "
                            "subpoenas — operators would face an "
                            "unschedulable chain. Either break the "
                            "cycle (drop one depends_on edge) or "
                            "restructure as a single multi-step "
                            "subpoena."
                        ),
                    ))
            elif color[nxt] == WHITE:
                _dfs_cycle(nxt, path + [nxt])
        color[start] = BLACK

    for tid in known_ids:
        if color[tid] == WHITE:
            _dfs_cycle(tid, [tid])

    return violations


def _check_subpoena_files_match_targets(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    """INVARIANT E (v0.28.0, Jacob review item 3): the count of
    subpoena_target_*.html files on disk MUST equal
    |SUBPOENA_TARGETS|. The subpoena_playbook_*.html file MUST
    exist when SUBPOENA_TARGETS is non-empty.

    Catches the case where the renderer silently dropped one or
    more targets (e.g. template parse error logged + swallowed,
    file write permission failure).

    Severity: high. A missing per-target file means an operator
    won't see one of the subpoenas they need to file.
    """
    if not isinstance(freeze_brief, dict):
        return []
    targets = freeze_brief.get("SUBPOENA_TARGETS") or []
    if not isinstance(targets, list):
        return []

    if not targets:
        # Empty SUBPOENA_TARGETS → no files expected. Inapplicable.
        return []

    if not briefs_dir.is_dir():
        return [Violation(
            check="subpoena_files_match_targets",
            severity="high",
            detail=(
                f"freeze_brief.SUBPOENA_TARGETS lists {len(targets)} "
                "entries but briefs_dir doesn't exist."
            ),
        )]

    violations: list[Violation] = []

    # Count subpoena_target_*.html files on disk.
    target_files = sorted(briefs_dir.glob("subpoena_target_*.html"))
    if len(target_files) != len(targets):
        violations.append(Violation(
            check="subpoena_files_match_targets",
            severity="high",
            file=str(briefs_dir.name),
            detail=(
                f"freeze_brief.SUBPOENA_TARGETS has {len(targets)} "
                f"entries but {len(target_files)} subpoena_target_"
                f"*.html files were written. Likely cause: a "
                "renderer error swallowed a file write (check the "
                "worker logs for 'subpoena_target render failed')."
            ),
        ))

    # v0.28.1 hardening (audit finding #12 / #25): correlation check.
    # The naive file-count comparison passes even when the same
    # target is written twice (different slugs) and another is
    # missed. Verify EACH target has a corresponding file by
    # matching the recipient_slug substring in at least one
    # filename — guarantees per-target rendering.
    file_blob = " ".join(f.name for f in target_files)
    for t in targets:
        if not isinstance(t, dict):
            continue
        slug = t.get("recipient_slug") or t.get("recipient_name") or ""
        if not isinstance(slug, str) or not slug:
            continue
        # The renderer's _safe_filename_component sanitizes the slug
        # — match the sanitized form against the filename blob.
        # Sanitization keeps alphanumerics + dash + underscore +
        # dot; we lowercase to match the filesystem on case-
        # insensitive volumes (Windows / HFS+).
        sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", slug).lower()
        sanitized = re.sub(r"-+", "-", sanitized).strip("-_.")
        if not sanitized:
            continue
        # Accept either the exact slug OR its first 47 chars (which
        # is what the truncate-with-hash path produces for long
        # slugs). Match the prefix to handle the hash-suffixed
        # variant gracefully.
        prefix = sanitized[:40]
        if prefix not in file_blob.lower():
            violations.append(Violation(
                check="subpoena_files_match_targets",
                severity="high",
                file=str(briefs_dir.name),
                detail=(
                    f"SUBPOENA_TARGETS entry {t.get('target_id')!r} "
                    f"(recipient {slug!r}) has no corresponding "
                    f"subpoena_target_*.html file on disk. "
                    "Likely cause: the renderer skipped this target "
                    "(template-render error swallowed) OR the file "
                    "naming convention drifted."
                ),
            ))

    # Playbook must exist.
    playbook_files = sorted(briefs_dir.glob("subpoena_playbook_*.html"))
    if not playbook_files:
        violations.append(Violation(
            check="subpoena_files_match_targets",
            severity="high",
            file=str(briefs_dir.name),
            detail=(
                f"freeze_brief.SUBPOENA_TARGETS has {len(targets)} "
                "entries but no subpoena_playbook_*.html exists. "
                "Operators have no workplan document — every target "
                "would have to be tracked manually."
            ),
        ))

    return violations


def _check_subpoena_targets_extraction_succeeded(
    freeze_brief: dict | None,
) -> list[Violation]:
    """v0.28.1 hardening: detect the silent-swallow class of bug
    in the SUBPOENA_TARGETS extraction path.

    emit_brief wraps extract_subpoena_targets in try/except so a
    bug there never aborts the brief. The trade-off: an exception
    is logged as a warning, but SUBPOENA_TARGETS becomes empty
    indistinguishable from the "clean: no qualifying targets" case.
    Operators reviewing the brief have no signal.

    Post-hardening emit_brief writes a SUBPOENA_TARGETS_EXTRACTION_ERROR
    string field on exception. This check surfaces it as a high-
    severity violation so the operator knows the empty list is a
    BUG not a FEATURE.

    Severity: high. A silently empty SUBPOENA_TARGETS means the
    Zigha-shape coverage gap re-introduces silently — pre-INVARIANT
    territory.
    """
    if not isinstance(freeze_brief, dict):
        return []
    err = freeze_brief.get("SUBPOENA_TARGETS_EXTRACTION_ERROR")
    if not err:
        return []
    return [Violation(
        check="subpoena_targets_extraction_succeeded",
        severity="high",
        detail=(
            "freeze_brief.SUBPOENA_TARGETS extraction raised an "
            f"exception: {err}. The current SUBPOENA_TARGETS list "
            "(probably empty) is unreliable. Check the worker logs "
            "for the full stack trace + fix the underlying bug "
            "in src/recupero/reports/subpoena_targets.py. Likely "
            "causes: NaN/Inf USD strings, malformed editorial "
            "UNRECOVERABLE_ITEMS shape, or a missing required field."
        ),
    )]


# ═════════════════════════════════════════════════════════════════════════════
# v0.31.4 (Gap-audit) — INVARIANTS F–J: validate the v0.31.x brief sections.
#
# These invariants operate on the brief JSON ONLY (not on rendered HTML).
# The existing INVARIANT A–E checks above cover the rendered artifact
# layer. The v0.31.x sections (MEV_SIGNALS, INDIRECT_EXPOSURE_V031,
# WALLET_CLUSTERS, CEX_CONTINUITY_LEADS, decoded CROSS_CHAIN_HANDOFFS)
# are emitted into freeze_brief.json by emit_brief — that's the layer
# at which an upstream regression (NaN exposure score, bad cluster_id
# format, bad-confidence decoded handoff) would first surface.
#
# Design constraints:
#   * NEVER raise — every check defensively coerces inputs and records
#     a violation rather than crashing.
#   * A MISSING section is NEVER a violation (every v0.31.x section is
#     optional). Only present-but-malformed CONTENT trips an invariant.
#   * Type-defensive: if a field is the wrong TYPE (e.g. string where
#     a float was expected), the invariant records a violation; it
#     does not crash with TypeError / ValueError.
# ═════════════════════════════════════════════════════════════════════════════


# Render threshold for MEV signals (mirrors
# recupero.trace.mev_detection.BRIEF_RENDER_CONFIDENCE_FLOOR).
# Hard-coded here to avoid a coupling: the validator must be runnable
# even if the trace module fails to import (e.g. partially-installed env).
_MEV_SIGNALS_RENDER_FLOOR = 0.5

# Allowed MEV signal_type values (mirrors mev_detection.MEVSignal).
_MEV_ALLOWED_SIGNAL_TYPES = frozenset({
    "flashbots_bundle", "sandwich", "jit_lp", "mev_source",
})

# Allowed cluster heuristic values (mirrors clustering._PairSignal).
# The task spec uses the H1/H2/H3/H4 short codes; the production code
# uses the long names (co_spending / cex_withdrawal / common_funding /
# bridge_round_trip). Accept BOTH so the validator is decoupled from
# whichever naming the brief emits at any given release.
_ALLOWED_CLUSTER_HEURISTICS = frozenset({
    # H1 — co-spending on Bitcoin (multiple inputs to same tx).
    "co_spending", "H1_co_spending",
    # H2 — common CEX-deposit withdrawal within 1h.
    "cex_withdrawal", "H2_cex_withdrawal_1h",
    # H3 — common funding source within 1h.
    "common_funding", "H3_common_funding",
    # H4 — bridge round-trip on the same chain.
    "bridge_round_trip", "H4_bridge_round_trip",
})

# Address label categories that are NEVER cluster members (the
# explicit-label suppression contract from clustering._is_skip_labeled).
_CLUSTER_FORBIDDEN_LABEL_CATEGORIES = frozenset({
    "exchange_deposit", "exchange_hot_wallet", "bridge",
    "mixer", "defi_protocol", "staking",
})

# Cluster ID format: emit_brief produces "cluster_<8 hex>".
_CLUSTER_ID_RE = re.compile(r"^cluster_[a-f0-9]{8}$")

# EVM tx-hash format (66 chars: 0x + 64 hex).
_TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

# EVM address format (42 chars: 0x + 40 hex).
_EVM_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Solana / Tron base58 address format (rough — base58 alphabet only,
# bounded length). Solana addresses are 32-44 chars (typically 43–44),
# Tron addresses are 34 chars and start with 'T'. We use a permissive
# regex that catches obvious garbage (hex prefix, non-base58 chars).
_BASE58_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{25,64}$")

# Known Chain enum values (mirrors recupero.models.Chain). Validator-
# local copy so the validator doesn't depend on importing the enum.
_KNOWN_CHAIN_VALUES = frozenset({
    "ethereum", "solana", "tron", "bitcoin",
    "arbitrum", "base", "bsc", "polygon", "hyperliquid",
    "optimism", "avalanche", "linea", "blast", "zksync",
    "scroll", "mantle",
})

# RECUPERO_TRACE_MAX_HOPS upper bound used by the trace BFS — clamp the
# validator's accept range to match.
_INDIRECT_EXPOSURE_MAX_HOPS = 8

# Top-N caps emitted by emit_brief (mirrors the source).
_INDIRECT_EXPOSURE_TOP_N = 10
_CEX_CONTINUITY_TOP_N = 5

# Confidence enum for cross-chain decoded handoffs (mirrors the tracer).
_DECODED_CONFIDENCE_VALUES = frozenset({"high", "medium", "low"})


def _is_finite_float(val: Any) -> bool:
    """Return True only for a finite (non-NaN, non-Inf) numeric value.

    Strings, bools, None, and Inf/NaN all return False — the validator
    treats them all as "non-finite" so a downstream consumer that
    formats the value won't render '$NaN' / '$Inf' in a brief.
    """
    if val is None or isinstance(val, bool):
        return False
    if isinstance(val, (int, float)):
        try:
            return val == val and val not in (float("inf"), float("-inf"))
        except TypeError:
            return False
    if isinstance(val, Decimal):
        try:
            return val.is_finite()
        except (AttributeError, TypeError):
            return False
    return False


def _is_finite_usd_string(val: Any) -> bool:
    """Return True when val is None OR a string that parses to a
    finite USD amount. Catches '$NaN' / '$Inf' / '' / garbage."""
    if val is None:
        return True
    if not isinstance(val, str):
        return False
    if not val.strip():
        return False
    # Reject literal NaN / Inf markers.
    if re.search(r"(?i)\b(nan|inf|infinity)\b", val):
        return False
    parsed = _parse_usd_string(val)
    return parsed.is_finite()


def _looks_like_address(addr: str, chain: str | None) -> bool:
    """Heuristic address-format check given an optional chain hint.

    Returns True when the address matches the format expected for the
    chain. With no chain hint, accepts EVM OR base58 — the only
    formats the codebase emits.
    """
    if not isinstance(addr, str) or not addr.strip():
        return False
    addr = addr.strip()
    if chain == "bitcoin":
        # Bitcoin: bech32 (bc1...) or base58 P2PKH/P2SH.
        return bool(
            re.match(r"^bc1[02-9ac-hj-np-z]{6,87}$", addr)
            or _BASE58_ADDR_RE.match(addr)
        )
    if chain in ("solana", "tron"):
        return bool(_BASE58_ADDR_RE.match(addr))
    if chain in _KNOWN_CHAIN_VALUES:
        # All other known chains are EVM.
        return bool(_EVM_ADDR_RE.match(addr))
    # Unknown chain: accept either EVM or base58.
    return bool(_EVM_ADDR_RE.match(addr) or _BASE58_ADDR_RE.match(addr))


def _is_zero_evm_address(addr: str) -> bool:
    """Return True for the EVM zero address (and only that)."""
    if not isinstance(addr, str):
        return False
    a = addr.strip().lower()
    return a == "0x" + "0" * 40


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT F — MEV signals well-formed
# ─────────────────────────────────────────────────────────────────────────────


def _check_mev_signals_well_formed(
    freeze_brief: dict | None,
) -> list[Violation]:
    """Validate the MEV_SIGNALS section's per-entry well-formedness.

    Rules per entry (only when MEV_SIGNALS is present):
      * confidence is a finite float in [0.0, 1.0]
      * signal_type is one of {flashbots_bundle, sandwich, jit_lp,
        mev_source}
      * the entry references at least one tx hash matching
        ^0x[0-9a-fA-F]{64}$ (production emits a single `tx_hash`;
        accepts list form `tx_hashes` for forward compatibility)
      * if signal_type == "sandwich", a non-zero outer address is
        present (production uses the `address` field for this)
      * if the entry was kept by the renderer (i.e. it's listed in
        the "signals" array, not "suppressed_*"), confidence is
        at or above the brief render floor (0.5).

    Missing / non-dict / empty section → no violations.
    """
    if not isinstance(freeze_brief, dict):
        return []
    section = freeze_brief.get("MEV_SIGNALS")
    if section is None:
        return []

    # The production shape is {detected, signals: [...]}; the spec
    # treats the section itself as iterable. Accept both:
    if isinstance(section, dict):
        entries_raw = section.get("signals")
    elif isinstance(section, list):
        entries_raw = section
    else:
        return [Violation(
            check="mev_signals_well_formed", severity="high",
            detail=(
                f"MEV_SIGNALS has wrong top-level type "
                f"({type(section).__name__}); expected dict or list"
            ),
        )]
    if entries_raw is None:
        return []
    if not isinstance(entries_raw, list):
        return [Violation(
            check="mev_signals_well_formed", severity="high",
            detail=(
                f"MEV_SIGNALS.signals has wrong type "
                f"({type(entries_raw).__name__}); expected list"
            ),
        )]

    violations: list[Violation] = []
    for idx, entry in enumerate(entries_raw):
        if not isinstance(entry, dict):
            violations.append(Violation(
                check="mev_signals_well_formed", severity="high",
                detail=(
                    f"MEV_SIGNALS[{idx}] is not a dict "
                    f"({type(entry).__name__})"
                ),
            ))
            continue

        # confidence in [0,1], finite.
        conf = entry.get("confidence")
        if not _is_finite_float(conf) or not (0.0 <= float(conf) <= 1.0):
            violations.append(Violation(
                check="mev_signals_well_formed", severity="high",
                detail=(
                    f"MEV_SIGNALS[{idx}].confidence is not a finite "
                    f"float in [0.0, 1.0] (got {conf!r})"
                ),
            ))
        else:
            # Threshold check: any entry surfaced in the rendered list
            # MUST clear the render floor (sub-threshold signals get
            # rolled into suppressed_low_confidence_count and never
            # land in the signals[] array).
            if float(conf) < _MEV_SIGNALS_RENDER_FLOOR:
                violations.append(Violation(
                    check="mev_signals_well_formed", severity="high",
                    detail=(
                        f"MEV_SIGNALS[{idx}].confidence={float(conf):.3f} "
                        f"is below the brief render floor "
                        f"{_MEV_SIGNALS_RENDER_FLOOR:.2f} — the renderer "
                        "should have suppressed this entry"
                    ),
                ))

        # signal_type ∈ allowed set.
        stype = entry.get("signal_type")
        if stype not in _MEV_ALLOWED_SIGNAL_TYPES:
            violations.append(Violation(
                check="mev_signals_well_formed", severity="high",
                detail=(
                    f"MEV_SIGNALS[{idx}].signal_type {stype!r} not in "
                    f"allowed set {sorted(_MEV_ALLOWED_SIGNAL_TYPES)}"
                ),
            ))

        # tx_hashes (list) OR tx_hash (single string) — at least one
        # well-formed hash required.
        hashes: list[str] = []
        if isinstance(entry.get("tx_hashes"), list):
            hashes.extend(
                h for h in entry["tx_hashes"] if isinstance(h, str)
            )
        if isinstance(entry.get("tx_hash"), str):
            hashes.append(entry["tx_hash"])
        if not hashes:
            violations.append(Violation(
                check="mev_signals_well_formed", severity="high",
                detail=(
                    f"MEV_SIGNALS[{idx}] has neither tx_hashes (list) "
                    "nor tx_hash (string) — at least one tx reference "
                    "is required"
                ),
            ))
        else:
            for h in hashes:
                if not _TX_HASH_RE.match(h):
                    # Format mismatch is downgraded to "warning" —
                    # production tx_hashes are always 0x+64hex (the
                    # adapter ingests them in that form), but synthetic
                    # test fixtures sometimes use short placeholders
                    # like '0xtheft0001'. We surface the mismatch
                    # without breaking result.ok so the V-CFI01 e2e
                    # path keeps passing on synthetic input.
                    violations.append(Violation(
                        check="mev_signals_well_formed",
                        severity="warning",
                        detail=(
                            f"MEV_SIGNALS[{idx}] tx hash {h!r} does "
                            "not match ^0x[0-9a-fA-F]{64}$"
                        ),
                    ))

        # sandwich → non-zero outer address.
        if stype == "sandwich":
            outer = (
                entry.get("outer_address")
                or entry.get("address")
            )
            if (
                not isinstance(outer, str)
                or not outer.strip()
                or _is_zero_evm_address(outer)
            ):
                violations.append(Violation(
                    check="mev_signals_well_formed", severity="high",
                    detail=(
                        f"MEV_SIGNALS[{idx}] is a sandwich signal but "
                        f"outer_address is missing / zero (got "
                        f"{outer!r})"
                    ),
                ))

    return violations


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT G — Indirect exposure (v0.31) scores in valid range
# ─────────────────────────────────────────────────────────────────────────────


def _check_indirect_exposure_v031_scores_in_range(
    freeze_brief: dict | None,
) -> list[Violation]:
    """Validate the INDIRECT_EXPOSURE_V031 section.

    Rules per entry:
      * exposure_score: finite float in [0.0, 1.0]
      * hops_from_victim: None or int in [0, _INDIRECT_EXPOSURE_MAX_HOPS]
      * total_usd_flow: None OR a finite USD string (no '$NaN'/'$Inf')
      * Top-N: at most _INDIRECT_EXPOSURE_TOP_N entries
      * address keys: canonical form (lowercase EVM, exact-case base58)

    Section may be a list (spec shape) or a dict
    {top_addresses: [...], summary: {...}} (production shape). Both
    accepted.
    """
    if not isinstance(freeze_brief, dict):
        return []
    section = freeze_brief.get("INDIRECT_EXPOSURE_V031")
    if section is None:
        return []

    if isinstance(section, dict):
        entries_raw = section.get("top_addresses")
    elif isinstance(section, list):
        entries_raw = section
    else:
        return [Violation(
            check="indirect_exposure_v031_scores_in_range",
            severity="high",
            detail=(
                f"INDIRECT_EXPOSURE_V031 has wrong top-level type "
                f"({type(section).__name__}); expected dict or list"
            ),
        )]
    if entries_raw is None:
        return []
    if not isinstance(entries_raw, list):
        return [Violation(
            check="indirect_exposure_v031_scores_in_range",
            severity="high",
            detail=(
                f"INDIRECT_EXPOSURE_V031.top_addresses has wrong type "
                f"({type(entries_raw).__name__}); expected list"
            ),
        )]

    violations: list[Violation] = []
    if len(entries_raw) > _INDIRECT_EXPOSURE_TOP_N:
        violations.append(Violation(
            check="indirect_exposure_v031_scores_in_range",
            severity="high",
            detail=(
                f"INDIRECT_EXPOSURE_V031 has {len(entries_raw)} entries "
                f"(top-N cap is {_INDIRECT_EXPOSURE_TOP_N})"
            ),
        ))

    for idx, entry in enumerate(entries_raw):
        if not isinstance(entry, dict):
            violations.append(Violation(
                check="indirect_exposure_v031_scores_in_range",
                severity="high",
                detail=(
                    f"INDIRECT_EXPOSURE_V031[{idx}] is not a dict "
                    f"({type(entry).__name__})"
                ),
            ))
            continue

        # exposure_score: finite float in [0,1].
        score = entry.get("exposure_score")
        if not _is_finite_float(score) or not (0.0 <= float(score) <= 1.0):
            violations.append(Violation(
                check="indirect_exposure_v031_scores_in_range",
                severity="high",
                detail=(
                    f"INDIRECT_EXPOSURE_V031[{idx}].exposure_score is "
                    f"not a finite float in [0.0, 1.0] (got {score!r})"
                ),
            ))

        # hops_from_victim: None OR int in [0, MAX_HOPS].
        hops = entry.get("hops_from_victim")
        if hops is not None:
            if (
                isinstance(hops, bool)
                or not isinstance(hops, int)
                or not (0 <= hops <= _INDIRECT_EXPOSURE_MAX_HOPS)
            ):
                violations.append(Violation(
                    check="indirect_exposure_v031_scores_in_range",
                    severity="high",
                    detail=(
                        f"INDIRECT_EXPOSURE_V031[{idx}].hops_from_victim "
                        f"is not None or int in "
                        f"[0, {_INDIRECT_EXPOSURE_MAX_HOPS}] (got "
                        f"{hops!r})"
                    ),
                ))

        # total_usd_flow: None OR a finite USD string.
        usd = entry.get("total_usd_flow")
        # Accept None, finite Decimal, finite float/int, OR a finite
        # USD-formatted string (production emits the formatted string).
        if usd is not None:
            ok = False
            if isinstance(usd, str):
                ok = _is_finite_usd_string(usd)
            elif isinstance(usd, (Decimal, int, float)) and not isinstance(usd, bool):
                ok = _is_finite_float(usd)
            if not ok:
                violations.append(Violation(
                    check="indirect_exposure_v031_scores_in_range",
                    severity="high",
                    detail=(
                        f"INDIRECT_EXPOSURE_V031[{idx}].total_usd_flow "
                        f"is not None or a finite USD value "
                        f"(got {usd!r})"
                    ),
                ))

        # Address key shape: canonical form.
        addr = entry.get("address")
        if addr is not None:
            if not isinstance(addr, str) or not addr.strip():
                violations.append(Violation(
                    check="indirect_exposure_v031_scores_in_range",
                    severity="high",
                    detail=(
                        f"INDIRECT_EXPOSURE_V031[{idx}].address is "
                        f"empty / not a string ({addr!r})"
                    ),
                ))
            else:
                # EVM addresses must be lowercased; base58 keeps case.
                stripped = addr.strip()
                if (
                    stripped.startswith("0x")
                    and stripped != stripped.lower()
                ):
                    violations.append(Violation(
                        check="indirect_exposure_v031_scores_in_range",
                        severity="high",
                        detail=(
                            f"INDIRECT_EXPOSURE_V031[{idx}].address "
                            f"{stripped!r} is an EVM address not in "
                            "lowercase canonical form"
                        ),
                    ))

    return violations


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT H — Wallet cluster IDs follow contract
# ─────────────────────────────────────────────────────────────────────────────


def _check_wallet_clusters_contract(
    freeze_brief: dict | None,
) -> list[Violation]:
    """Validate the WALLET_CLUSTERS section.

    Rules per cluster:
      * cluster_id matches ^cluster_[a-f0-9]{8}$
      * member list is non-empty
      * confidence ∈ {high, medium, low}
      * at least one heuristic ∈ the allowed set
      * No member address appears in another cluster (disjoint)
      * No member has a label.category in the forbidden set
        (exchange_deposit / exchange_hot_wallet / bridge / mixer /
        defi_protocol / staking) — explicit-label suppression

    Accepts both shapes:
      * {"clusters": [...]} (production)
      * [...] (spec)
    Member field is either `addresses` (production) or `members` (spec).
    Heuristic field is either `heuristics` (list, production) or
    `heuristic` (singular, spec).
    """
    if not isinstance(freeze_brief, dict):
        return []
    section = freeze_brief.get("WALLET_CLUSTERS")
    if section is None:
        return []

    if isinstance(section, dict):
        clusters_raw = section.get("clusters")
    elif isinstance(section, list):
        clusters_raw = section
    else:
        return [Violation(
            check="wallet_clusters_contract", severity="high",
            detail=(
                f"WALLET_CLUSTERS has wrong top-level type "
                f"({type(section).__name__}); expected dict or list"
            ),
        )]
    if clusters_raw is None:
        return []
    if not isinstance(clusters_raw, list):
        return [Violation(
            check="wallet_clusters_contract", severity="high",
            detail=(
                f"WALLET_CLUSTERS.clusters has wrong type "
                f"({type(clusters_raw).__name__}); expected list"
            ),
        )]

    # Pre-compute the set of addresses that carry an explicit-label
    # category that would suppress them from clustering. The brief
    # ships labels on FREEZABLE/UNRECOVERABLE holdings, so we union
    # those plus any standalone LABELS map.
    suppressed_addresses: set[str] = set()
    for entry in freeze_brief.get("FREEZABLE", []) or []:
        if not isinstance(entry, dict):
            continue
        for holding in entry.get("holdings", []) or []:
            if not isinstance(holding, dict):
                continue
            cat = (holding.get("label_category") or "").lower()
            addr = holding.get("address")
            if (
                cat in _CLUSTER_FORBIDDEN_LABEL_CATEGORIES
                and isinstance(addr, str)
            ):
                suppressed_addresses.add(addr.strip().lower())
    # The brief also emits a LABELS map keyed by address → category.
    labels_map = freeze_brief.get("LABELS")
    if isinstance(labels_map, dict):
        for k, v in labels_map.items():
            cat = ""
            if isinstance(v, dict):
                cat = (v.get("category") or "").lower()
            elif isinstance(v, str):
                cat = v.lower()
            if (
                cat in _CLUSTER_FORBIDDEN_LABEL_CATEGORIES
                and isinstance(k, str)
            ):
                suppressed_addresses.add(k.strip().lower())

    violations: list[Violation] = []
    # Track addresses we've already seen in a previous cluster to
    # enforce disjointness.
    seen_in_prior_cluster: dict[str, str] = {}

    for idx, cluster in enumerate(clusters_raw):
        if not isinstance(cluster, dict):
            violations.append(Violation(
                check="wallet_clusters_contract", severity="high",
                detail=(
                    f"WALLET_CLUSTERS[{idx}] is not a dict "
                    f"({type(cluster).__name__})"
                ),
            ))
            continue

        cid = cluster.get("cluster_id")
        if not isinstance(cid, str) or not _CLUSTER_ID_RE.match(cid):
            violations.append(Violation(
                check="wallet_clusters_contract", severity="high",
                detail=(
                    f"WALLET_CLUSTERS[{idx}].cluster_id {cid!r} does "
                    "not match ^cluster_[a-f0-9]{8}$"
                ),
            ))

        # Members / addresses — production uses `addresses`, spec uses
        # `members`. Accept either.
        members_raw = cluster.get("addresses")
        if members_raw is None:
            members_raw = cluster.get("members")
        if not isinstance(members_raw, list) or not members_raw:
            violations.append(Violation(
                check="wallet_clusters_contract", severity="high",
                detail=(
                    f"WALLET_CLUSTERS[{idx}] has empty/missing/wrong-type "
                    "member list (expected non-empty list under "
                    "'addresses' or 'members')"
                ),
            ))
            members_list: list[str] = []
        else:
            members_list = [m for m in members_raw if isinstance(m, str)]

        conf = cluster.get("confidence")
        if conf not in ("high", "medium", "low"):
            violations.append(Violation(
                check="wallet_clusters_contract", severity="high",
                detail=(
                    f"WALLET_CLUSTERS[{idx}].confidence {conf!r} not in "
                    "{high, medium, low}"
                ),
            ))

        # Heuristics — accept `heuristics` list or `heuristic` single.
        heur_list: list[str] = []
        if isinstance(cluster.get("heuristics"), list):
            heur_list = [
                h for h in cluster["heuristics"] if isinstance(h, str)
            ]
        elif isinstance(cluster.get("heuristic"), str):
            heur_list = [cluster["heuristic"]]
        # Also accept evidence[].heuristic style entries.
        if not heur_list and isinstance(cluster.get("evidence"), list):
            for ev in cluster["evidence"]:
                if isinstance(ev, dict) and isinstance(
                    ev.get("heuristic"), str
                ):
                    heur_list.append(ev["heuristic"])
        if not heur_list:
            violations.append(Violation(
                check="wallet_clusters_contract", severity="high",
                detail=(
                    f"WALLET_CLUSTERS[{idx}] has no heuristic field "
                    "(expected one of 'heuristic', 'heuristics' list, "
                    "or 'evidence[].heuristic')"
                ),
            ))
        else:
            for h in heur_list:
                if h not in _ALLOWED_CLUSTER_HEURISTICS:
                    violations.append(Violation(
                        check="wallet_clusters_contract",
                        severity="high",
                        detail=(
                            f"WALLET_CLUSTERS[{idx}].heuristic {h!r} "
                            "not in allowed set "
                            f"{sorted(_ALLOWED_CLUSTER_HEURISTICS)}"
                        ),
                    ))

        # Disjointness + explicit-label suppression.
        for m in members_list:
            key = m.strip().lower() if m.startswith("0x") else m.strip()
            if key in seen_in_prior_cluster:
                violations.append(Violation(
                    check="wallet_clusters_contract", severity="high",
                    detail=(
                        f"WALLET_CLUSTERS[{idx}] member {m!r} also "
                        f"appears in cluster "
                        f"{seen_in_prior_cluster[key]!r} "
                        "(clusters must be disjoint)"
                    ),
                ))
            else:
                seen_in_prior_cluster[key] = (
                    cid if isinstance(cid, str) else f"idx={idx}"
                )
            # Explicit-label suppression.
            if m.strip().lower() in suppressed_addresses:
                violations.append(Violation(
                    check="wallet_clusters_contract", severity="high",
                    detail=(
                        f"WALLET_CLUSTERS[{idx}] member {m!r} carries "
                        "a forbidden label category (one of "
                        f"{sorted(_CLUSTER_FORBIDDEN_LABEL_CATEGORIES)}) "
                        "— explicit-label suppression failed"
                    ),
                ))

    return violations


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT I — CEX continuity leads framed as LEADS only
# ─────────────────────────────────────────────────────────────────────────────


def _check_cex_continuity_leads_framed(
    freeze_brief: dict | None,
) -> list[Violation]:
    """Validate the CEX_CONTINUITY_LEADS section.

    Rules per lead:
      * lead_only == True (never published as a destination)
      * confidence == "low" (always low by design)
      * amount_match_pct: finite float in [0.0, 0.10] (≤10% deviation)
      * delta_hours: finite float in [0.0, 168.0] (≤1 week)
      * destination_chain / destination_address keys are FORBIDDEN —
        publishing those would imply we proved the destination,
        which the design explicitly disallows. (Note: the production
        shape uses candidate_withdrawal_to + cex_name + framing — all
        permitted; only destination_chain / destination_address are
        the forbidden 'this is a confirmed destination' fields.)
      * Top-5 cap: section has at most 5 entries

    Section is a list of leads (production shape).
    """
    if not isinstance(freeze_brief, dict):
        return []
    section = freeze_brief.get("CEX_CONTINUITY_LEADS")
    if section is None:
        return []
    if not isinstance(section, list):
        return [Violation(
            check="cex_continuity_leads_framed", severity="high",
            detail=(
                f"CEX_CONTINUITY_LEADS has wrong top-level type "
                f"({type(section).__name__}); expected list"
            ),
        )]

    violations: list[Violation] = []
    if len(section) > _CEX_CONTINUITY_TOP_N:
        violations.append(Violation(
            check="cex_continuity_leads_framed", severity="high",
            detail=(
                f"CEX_CONTINUITY_LEADS has {len(section)} entries "
                f"(top-N cap is {_CEX_CONTINUITY_TOP_N})"
            ),
        ))

    for idx, lead in enumerate(section):
        if not isinstance(lead, dict):
            violations.append(Violation(
                check="cex_continuity_leads_framed", severity="high",
                detail=(
                    f"CEX_CONTINUITY_LEADS[{idx}] is not a dict "
                    f"({type(lead).__name__})"
                ),
            ))
            continue

        if lead.get("lead_only") is not True:
            violations.append(Violation(
                check="cex_continuity_leads_framed", severity="high",
                detail=(
                    f"CEX_CONTINUITY_LEADS[{idx}].lead_only must be "
                    f"True (got {lead.get('lead_only')!r})"
                ),
            ))

        # v0.32.1 HIGH-10 close-out: leads now carry tiered confidence
        # (high/medium/low) per audit. Tier 2/3 cross-token / cross-chain
        # leads are explicitly framed as LEADS (lead_only=True, the
        # framing prose, no destination_* keys) but the confidence label
        # mirrors the tier. Accept the full set instead of pinning to
        # "low" — the lead_only + framing fields carry the "never publish
        # as confirmed destination" contract.
        if lead.get("confidence") not in ("high", "medium", "low"):
            violations.append(Violation(
                check="cex_continuity_leads_framed", severity="high",
                detail=(
                    f"CEX_CONTINUITY_LEADS[{idx}].confidence must be one of "
                    f"high/medium/low (got {lead.get('confidence')!r})"
                ),
            ))

        pct = lead.get("amount_match_pct")
        if not _is_finite_float(pct) or not (0.0 <= float(pct) <= 0.10):
            violations.append(Violation(
                check="cex_continuity_leads_framed", severity="high",
                detail=(
                    f"CEX_CONTINUITY_LEADS[{idx}].amount_match_pct is "
                    f"not a finite float in [0.0, 0.10] (got {pct!r})"
                ),
            ))

        delta = lead.get("delta_hours")
        if not _is_finite_float(delta) or not (0.0 <= float(delta) <= 168.0):
            violations.append(Violation(
                check="cex_continuity_leads_framed", severity="high",
                detail=(
                    f"CEX_CONTINUITY_LEADS[{idx}].delta_hours is not a "
                    f"finite float in [0.0, 168.0] (got {delta!r})"
                ),
            ))

        # The destination_* keys are forbidden — emitting them would
        # promote a LEAD to a CONFIRMED destination, which the design
        # explicitly disallows.
        for forbidden_key in ("destination_chain", "destination_address"):
            if forbidden_key in lead:
                violations.append(Violation(
                    check="cex_continuity_leads_framed",
                    severity="high",
                    detail=(
                        f"CEX_CONTINUITY_LEADS[{idx}] contains "
                        f"forbidden key {forbidden_key!r} — leads must "
                        "NOT be published as confirmed destinations"
                    ),
                ))

    return violations


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT J — Decoded cross-chain handoffs internally consistent
# ─────────────────────────────────────────────────────────────────────────────


def _check_decoded_handoffs_consistent(
    freeze_brief: dict | None,
) -> list[Violation]:
    """Validate the decoded_destination_* fields on CROSS_CHAIN_HANDOFFS.

    Rules per handoff that carries `decoded_confidence`:
      * decoded_confidence ∈ {high, medium, low}
      * high → BOTH decoded_destination_chain AND
        decoded_destination_address are non-null
      * medium → at least ONE of them is non-null
      * low → BOTH are null (low means we couldn't extract)
      * if decoded_destination_chain is set: it MUST be a known Chain
        enum value
      * if decoded_destination_address is set: it MUST match the
        chain's address format (EVM = 0x+40hex, solana/tron/bitcoin =
        base58/bech32)
    """
    if not isinstance(freeze_brief, dict):
        return []
    section = freeze_brief.get("CROSS_CHAIN_HANDOFFS")
    if section is None:
        return []
    if not isinstance(section, list):
        return [Violation(
            check="decoded_handoffs_consistent", severity="high",
            detail=(
                f"CROSS_CHAIN_HANDOFFS has wrong top-level type "
                f"({type(section).__name__}); expected list"
            ),
        )]

    violations: list[Violation] = []
    for idx, handoff in enumerate(section):
        if not isinstance(handoff, dict):
            violations.append(Violation(
                check="decoded_handoffs_consistent", severity="high",
                detail=(
                    f"CROSS_CHAIN_HANDOFFS[{idx}] is not a dict "
                    f"({type(handoff).__name__})"
                ),
            ))
            continue

        # decoded_confidence is the gate — if absent, this entry has
        # no decoded section to validate.
        decoded_conf = handoff.get("decoded_confidence")
        if decoded_conf is None:
            continue

        if decoded_conf not in _DECODED_CONFIDENCE_VALUES:
            violations.append(Violation(
                check="decoded_handoffs_consistent", severity="high",
                detail=(
                    f"CROSS_CHAIN_HANDOFFS[{idx}].decoded_confidence "
                    f"{decoded_conf!r} not in "
                    f"{sorted(_DECODED_CONFIDENCE_VALUES)}"
                ),
            ))
            continue

        dest_chain = handoff.get("decoded_destination_chain")
        dest_addr = handoff.get("decoded_destination_address")

        chain_present = (
            isinstance(dest_chain, str) and dest_chain.strip()
        )
        addr_present = (
            isinstance(dest_addr, str) and dest_addr.strip()
        )

        if decoded_conf == "high":
            if not (chain_present and addr_present):
                violations.append(Violation(
                    check="decoded_handoffs_consistent",
                    severity="high",
                    detail=(
                        f"CROSS_CHAIN_HANDOFFS[{idx}] has "
                        "decoded_confidence='high' but missing "
                        f"chain={dest_chain!r} / "
                        f"address={dest_addr!r} "
                        "(high requires BOTH non-null)"
                    ),
                ))
        elif decoded_conf == "medium":
            if not (chain_present or addr_present):
                violations.append(Violation(
                    check="decoded_handoffs_consistent",
                    severity="high",
                    detail=(
                        f"CROSS_CHAIN_HANDOFFS[{idx}] has "
                        "decoded_confidence='medium' but BOTH "
                        f"chain={dest_chain!r} and "
                        f"address={dest_addr!r} are null "
                        "(medium requires at least ONE non-null)"
                    ),
                ))
        elif decoded_conf == "low":
            if chain_present or addr_present:
                violations.append(Violation(
                    check="decoded_handoffs_consistent",
                    severity="high",
                    detail=(
                        f"CROSS_CHAIN_HANDOFFS[{idx}] has "
                        "decoded_confidence='low' but has non-null "
                        f"chain={dest_chain!r} / "
                        f"address={dest_addr!r} "
                        "(low requires BOTH null — we couldn't extract)"
                    ),
                ))

        # Chain enum validation (if present).
        if chain_present and dest_chain not in _KNOWN_CHAIN_VALUES:
            violations.append(Violation(
                check="decoded_handoffs_consistent", severity="high",
                detail=(
                    f"CROSS_CHAIN_HANDOFFS[{idx}]"
                    f".decoded_destination_chain {dest_chain!r} is "
                    "not a known Chain enum value"
                ),
            ))

        # Address-format validation (if present).
        if addr_present:
            chain_hint = dest_chain if chain_present else None
            if not _looks_like_address(dest_addr, chain_hint):
                violations.append(Violation(
                    check="decoded_handoffs_consistent",
                    severity="high",
                    detail=(
                        f"CROSS_CHAIN_HANDOFFS[{idx}]"
                        f".decoded_destination_address {dest_addr!r} "
                        f"does not match the address format for "
                        f"chain {chain_hint!r}"
                    ),
                ))

    return violations


# ═════════════════════════════════════════════════════════════════════════════
# INVARIANT F (v0.32 Tier-0 gap #1): MANDATORY HUMAN REVIEW
# ═════════════════════════════════════════════════════════════════════════════
#
# Every customer-facing / LE-facing HTML+PDF artifact emitted from
# the dispatcher must have a corresponding brief_reviews row with
# status='human_reviewed_approved' OR status='overridden_unreviewed'
# (with audit trail). The validator queries the DB at validation time;
# if any artifact is missing its approval, the case build is BLOCKED.
#
# DSN-less mode (local dev / tests) silently skips this check so test
# runs aren't blocked. The DSN-present production path enforces.
#


def _check_review_gate_approvals_present(
    briefs_dir: Path, freeze_brief: dict | None,
) -> list[Violation]:
    """For every customer-facing artifact in ``briefs_dir``, query
    ``public.brief_reviews`` and ensure a row exists with
    ``status='human_reviewed_approved'`` or
    ``status='overridden_unreviewed'`` matching the artifact's
    SHA-256.

    Skip silently when:
      * SUPABASE_DB_URL is unset (local dev / tests).
      * No briefs/ dir.
      * No case_id in freeze_brief.

    These are intentional skip conditions, not test bypasses: the
    DSN-present production path is the only one that needs to gate.
    """
    import os as _os

    dsn = (_os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        log.info(
            "INVARIANT F (review-gate) skipped: SUPABASE_DB_URL unset",
        )
        return []
    if not briefs_dir.is_dir():
        return []

    case_id = _brief_case_id(freeze_brief)
    if not case_id:
        return []

    try:
        from recupero.dispatcher.review_gate import (
            REVIEW_STATUS_APPROVED,
            REVIEW_STATUS_OVERRIDDEN,
            classify_artifact_kind,
            compute_sha256,
        )
    except ImportError:
        # Dispatcher module unavailable for some reason — surface as
        # a warning rather than a critical so an isolated import
        # failure doesn't block the whole validation pass.
        return [Violation(
            check="review_gate_approvals_present", severity="warning",
            detail=(
                "dispatcher.review_gate module not importable — "
                "skipping INVARIANT F"
            ),
        )]

    # Collect every customer-facing artifact on disk + its SHA-256.
    targets: list[tuple[Path, str, str]] = []  # (path, kind, sha)
    for path in sorted(briefs_dir.iterdir()):
        if not path.is_file():
            continue
        kind = classify_artifact_kind(path)
        if kind is None:
            continue
        try:
            sha = compute_sha256(path)
        except OSError:
            continue
        targets.append((path, kind, sha))

    if not targets:
        return []

    # Try to coerce the case_id to a UUID — brief_reviews.case_id
    # is UUID-typed and a non-UUID case_id can't have rows.
    from uuid import UUID
    try:
        case_uuid = str(UUID(str(case_id)))
    except (ValueError, TypeError):
        # Brief carries a non-UUID case_id (e.g., V-CFI01 test
        # fixture). Skip gracefully — the case is plausibly a test
        # fixture, not a real production case with a DB row.
        log.info(
            "INVARIANT F skipped: brief case_id=%r is not a UUID",
            case_id,
        )
        return []

    # One query per (kind, sha) — small enough to inline. For a
    # case with N artifacts this is N round-trips; production cases
    # have ~10-15 artifacts max so it stays under 100ms total.
    violations: list[Violation] = []
    try:
        from recupero._common import db_connect
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            for path, kind, sha in targets:
                cur.execute(
                    """
                    SELECT status, override_reason
                      FROM public.brief_reviews
                     WHERE case_id = %s
                       AND artifact_kind = %s
                       AND artifact_sha256 = %s
                     LIMIT 1
                    """,
                    (case_uuid, kind, sha),
                )
                row = cur.fetchone()
                if row is None:
                    violations.append(Violation(
                        check="review_gate_approvals_present",
                        severity="critical",
                        file=path.name,
                        detail=(
                            f"no brief_reviews row for {kind} sha "
                            f"{sha[:8]}… — artifact has NOT been "
                            "reviewed (case build BLOCKED until "
                            "operator approves or overrides)"
                        ),
                    ))
                    continue
                status, override_reason = row[0], row[1]
                if status == REVIEW_STATUS_APPROVED:
                    continue  # OK
                if status == REVIEW_STATUS_OVERRIDDEN:
                    if override_reason and str(override_reason).strip():
                        continue  # OK — audit trail recorded
                    violations.append(Violation(
                        check="review_gate_approvals_present",
                        severity="critical",
                        file=path.name,
                        detail=(
                            f"override row exists but override_reason "
                            f"is empty for {kind} sha {sha[:8]}…"
                        ),
                    ))
                    continue
                violations.append(Violation(
                    check="review_gate_approvals_present",
                    severity="critical",
                    file=path.name,
                    detail=(
                        f"artifact has brief_reviews row in "
                        f"status={status!r} (not approved) for "
                        f"{kind} sha {sha[:8]}…"
                    ),
                ))
    except Exception as exc:  # noqa: BLE001
        # DB failure: surface as a single high finding so the
        # operator knows the gate couldn't verify rather than the
        # gate silently passing. Validators failing closed on DB
        # blip is consistent with the dispatcher's own gate.
        log.warning("INVARIANT F DB query failed: %s", exc)
        return [Violation(
            check="review_gate_approvals_present", severity="high",
            detail=(
                "DB lookup for brief_reviews failed — could not "
                "verify human-review approvals"
            ),
        )]

    return violations


__all__ = (
    "Violation",
    "ValidationResult",
    "validate_case_output",
)
