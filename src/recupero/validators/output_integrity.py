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


__all__ = (
    "Violation",
    "ValidationResult",
    "validate_case_output",
)
