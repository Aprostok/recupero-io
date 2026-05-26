"""Per-issuer freeze briefs + LE handoff generation for the worker.

Runs in the ``building_package`` pipeline stage. For each unique issuer that
the freeze stage identified as holding stolen funds (i.e. each issuer in
``freeze_brief.json`` ``FREEZABLE`` list), this generates a freeze-request
HTML letter addressed to that issuer. A single LE handoff HTML is generated
covering the entire case.

Inputs come from already-written artifacts in ``case_dir``:

* ``case.json``       — the structured trace (Case + transfers + endpoints)
* ``victim.json``     — VictimInfo
* ``freeze_brief.json`` — the customer-facing brief (FREEZABLE list)

Outputs land in ``case_dir/briefs/`` and get synced to the bucket by the
calling stage. Filenames include the issuer slug so per-issuer briefs don't
overwrite each other:

    case_dir/briefs/freeze_request_circle_<brief_id>.html
    case_dir/briefs/freeze_request_tether_<brief_id>.html
    case_dir/briefs/le_handoff_<brief_id>.html
    case_dir/briefs/manifest_<brief_id>.json

If the trace produced no transfers (empty case), the freeze letters
+ LE handoff are skipped (there are no destinations to name), but
``trace_report.html`` still ships. The trace report is the operator's
record that the trace ran and found nothing — itself useful, and
required by the admin UI's wallet-trace view.
"""

from __future__ import annotations

import html as _html
import logging
import os
from decimal import Decimal
from pathlib import Path
from typing import Any

from recupero.models import Case
from recupero.reports.brief import (
    MIDAS_ISSUER,  # used as the canonical fully-filled IssuerInfo when name matches
    InvestigatorInfo,
    IssuerInfo,
    generate_briefs,
)
from recupero.reports.victim import VictimInfo

log = logging.getLogger(__name__)


# Default investigator info when the cases row doesn't carry it (the
# schema doesn't have an investigator column today). Each Railway
# deployment can override via RECUPERO_INVESTIGATOR_* env vars.
#
# v0.19.0 (round-11 arch follow-up): build the dataclass at call-time
# (not module-load), and source fields from the canonical
# `_common.investigator_defaults()` so an unconfigured deploy ships
# obvious placeholders rather than the developer's name signing legal
# documents. Pre-v0.19.0 a module-load build cached "Alec Prostok" /
# "alec@recupero.io" as the fallback the moment the worker booted —
# rotating the env var later did nothing for already-loaded workers
# AND the dev's name signed every letter when env was unset.


def _default_investigator() -> InvestigatorInfo:
    from recupero._common import investigator_defaults
    inv = investigator_defaults()
    return InvestigatorInfo(
        name=inv["INVESTIGATOR_NAME"],
        organization=inv["INVESTIGATOR_ENTITY"],
        email=inv["INVESTIGATOR_EMAIL"],
        phone=os.environ.get("RECUPERO_INVESTIGATOR_PHONE") or None,
    )


def build_all_deliverables(
    *,
    case: Case,
    victim: VictimInfo,
    freeze_brief: dict[str, Any],
    case_dir: Path,
    investigator: InvestigatorInfo | None = None,
    skip_freeze_briefs: bool = False,
    investigation_id: str | None = None,
    label: str | None = None,
) -> list[Path]:
    """Generate one freeze-request HTML per unique issuer in FREEZABLE,
    plus one LE handoff. Returns the list of paths written.

    Also unconditionally emits ``trace_report_<hash>.html`` — the new
    internal-facing data summary every investigation ships (Phase 4).
    On wallet traces (skip_freeze_briefs=True, often with case_id=NULL)
    the trace report is the only HTML produced.

    Skip conditions for the customer-facing freeze letters (still
    emits trace_report, returns the trace_report path):

      * ``skip_freeze_briefs=True`` — wallet trace / R&D run.
      * The case has no transfers — nothing to seize.
      * FREEZABLE is empty — no labeled-issuer holding to address.
        This is the right outcome for cases that route entirely to
        exchange deposits / mixers / unlabeled wallets.

    The legacy ``recupero brief`` CLI command remains available for
    one-off overrides if an operator wants to manually generate a
    letter to a specific issuer that wasn't matched automatically.
    """
    # An empty transfers list is a valid outcome for wallet-trace runs
    # (the seed address may legitimately have no on-chain activity in
    # the trace window) — we still emit the trace_report.html so the
    # operator has a record of the "found nothing" finding. The early
    # return was masking this: removing it means trace_report ships
    # even when transfers is empty.
    has_transfers = bool(case.transfers)
    if not has_transfers:
        log.info(
            "case has 0 transfers — skipping freeze letters / LE handoff, "
            "but still emitting trace_report.html",
        )

    freezable = freeze_brief.get("FREEZABLE") or []

    # Build the set of unique issuers from FREEZABLE. Each issuer becomes one
    # freeze-request brief AND one per-issuer LE handoff, both named with
    # the issuer slug (e.g. le_handoff_circle_<id>.html) so they do NOT
    # overwrite each other. Every LE handoff carries the full Section 4.2
    # all-issuers inventory (all_issuers_freezable) so LE can see the
    # complete picture in any one of the N per-issuer letters.
    #
    # Filter: skip issuers where every holding is UNRECOVERABLE. Lido staking
    # contracts are the canonical example — we surface them in the trace
    # because stETH technically has an issuer, but Lido has no power to
    # freeze stETH at a staking contract (it's a public-good system, not a
    # custodial one). Sending Lido a freeze request for these is wrong and
    # makes us look uninformed. emit_brief.py already excludes their USD
    # value from TOTAL_FREEZABLE_USD; we just need to also skip generating
    # the letter.
    issuers_seen: dict[str, IssuerInfo] = {}
    for entry in freezable:
        # Adversarial-input audit: a buggy upstream writer can drop a
        # non-dict element (e.g., a stray string) into FREEZABLE. Pre-fix
        # `entry.get` raised AttributeError, killing every other issuer's
        # brief generation. Skip non-dicts defensively.
        if not isinstance(entry, dict):
            log.warning(
                "skipping non-dict FREEZABLE entry (%r) — malformed brief",
                type(entry).__name__,
            )
            continue
        issuer_name = entry.get("issuer")
        if not issuer_name or issuer_name in issuers_seen:
            continue
        # Reject non-string issuer names (e.g., int 123 from a bad JSON
        # cast) — they'd crash `_issuer_info_for(name).split(" ")`.
        if not isinstance(issuer_name, str):
            log.warning(
                "skipping FREEZABLE entry with non-string issuer name (%r)",
                type(issuer_name).__name__,
            )
            continue
        if not _has_actionable_holding(entry):
            log.info(
                "skipping freeze brief for issuer=%s — every holding marked "
                "UNRECOVERABLE (e.g. staking contract, no freeze authority)",
                issuer_name,
            )
            continue
        issuers_seen[issuer_name] = _issuer_info_for(issuer_name, entry)

    # NB: we no longer early-return when issuers_seen is empty — the
    # trace_report still ships on every investigation. The customer-
    # facing freeze letters are the only thing skipped on the
    # empty-FREEZABLE path.
    if not issuers_seen:
        log.info(
            "FREEZABLE list is empty — skipping customer-facing freeze "
            "letters but still emitting trace_report.html",
        )

    investigator = investigator or _default_investigator()

    # Render the fund-flow SVG once into briefs/flow_<hash>.svg.
    # Letters reference this file as an attachment-pointer in
    # section 3; no inline embed (per Jacob's spec — the inline
    # SVG was unreadable when recipients printed the letter to
    # PDF and re-printed to portrait). The standalone file ships
    # alongside the HTMLs/PDFs in briefs/ and gets its own
    # WeasyPrint-rendered PDF for sharing-without-the-letter
    # workflows.
    flow_filename: str | None = None
    flow_svg_path: Path | None = None
    try:
        import hashlib

        from recupero.worker._flow_diagram import render_flow_diagram
        briefs_dir = case_dir / "briefs"
        briefs_dir.mkdir(parents=True, exist_ok=True)
        # RIGOR-3: deterministic SVG filename via content-based hash.
        # Pre-RIGOR-3 this was `flow_{uuid4().hex[:8]}.svg` — random
        # per run, so two runs of the same case produced different
        # filenames and non-byte-identical letters that referenced the
        # SVG name. Jacob's `diff -r run_a/ run_b/` would catch it.
        # The hash inputs are the case fixed identifiers + the
        # transfer count + the seed_address; together these uniquely
        # identify a case's flow graph regardless of when it runs.
        case_id_for_hash = (
            getattr(case, "case_id", None)
            or getattr(case, "case_number", None)
            or "no-case"
        )
        flow_hash_seed = (
            f"{case_id_for_hash}|{case.seed_address or ''}|"
            f"{len(case.transfers or [])}"
        ).encode("utf-8")
        flow_hex = hashlib.sha256(flow_hash_seed).hexdigest()[:8]
        candidate_path = briefs_dir / f"flow_{flow_hex}.svg"
        # Pass freeze_brief so wallets in the FREEZABLE list get
        # promoted to "Circle holding (USDC)" / "Tether holding"
        # / etc. labeled circles in the diagram. The trace itself
        # often doesn't carry counterparty labels on these wallets,
        # so without the cross-ref they'd render as anonymous
        # rounded-rect nodes — uninformative on the very wallets
        # the letter is asking to freeze.
        if render_flow_diagram(
            case, candidate_path, freeze_brief=freeze_brief,
        ) is not None:
            flow_filename = candidate_path.name
            flow_svg_path = candidate_path
    except Exception as e:  # noqa: BLE001
        log.warning("flow diagram generation failed (continuing without it): %s", e)

    written: list[Path] = []
    html_paths: list[Path] = []  # HTMLs we should also produce PDFs for

    # Trace report — internal-facing data summary, always emitted
    # regardless of skip_freeze_briefs / FREEZABLE / case_id. This
    # is the artifact the admin UI's "Wallet trace" detail page
    # surfaces as the primary deliverable.
    try:
        from recupero.worker._trace_report import render_trace_report
        briefs_dir = case_dir / "briefs"
        briefs_dir.mkdir(parents=True, exist_ok=True)
        trace_report_path = render_trace_report(
            case=case,
            freeze_brief=freeze_brief,
            briefs_dir=briefs_dir,
            flow_filename=flow_filename,
            investigation_id=investigation_id,
            label=label,
        )
        if trace_report_path is not None:
            written.append(trace_report_path)
            html_paths.append(trace_report_path)
            log.info("wrote trace report: %s", trace_report_path.name)
    except Exception as e:  # noqa: BLE001
        log.warning("trace_report generation failed (continuing): %s", e)

    # v0.22.0 — Recovery Snapshot. Pre-engagement deliverable:
    # 1-page HTML summarising recommendation + headline ROI +
    # per-issuer breakdown + drivers. Designed to be shared with
    # the victim BEFORE they pay the engagement fee. Always
    # emitted when freeze_brief carries a RECOVERY_ESTIMATE.
    try:
        if freeze_brief.get("RECOVERY_ESTIMATE"):
            from recupero.reports.recovery_snapshot import render_recovery_snapshot
            briefs_dir = case_dir / "briefs"
            briefs_dir.mkdir(parents=True, exist_ok=True)
            snapshot_path = render_recovery_snapshot(
                case_id=freeze_brief.get("CASE_ID") or case.case_id,
                recovery_estimate=freeze_brief["RECOVERY_ESTIMATE"],
                briefs_dir=briefs_dir,
            )
            if snapshot_path is not None:
                written.append(snapshot_path)
                html_paths.append(snapshot_path)
                log.info("wrote recovery snapshot: %s", snapshot_path.name)
    except Exception as e:  # noqa: BLE001
        log.warning(
            "recovery_snapshot generation failed (non-fatal): %s", e,
        )

    # v0.9.2 — investigator-facing CSV + JSON exports. Government /
    # law-enforcement analysts (FBI, IRS-CI, OFAC) parse these
    # directly into their case-management tools; the customer-facing
    # PDF is for the victim but the CSV is for the analyst.
    try:
        from recupero.reports.investigator_export import (
            build_findings,
            write_csv,
            write_json,
        )
        briefs_dir = case_dir / "briefs"
        briefs_dir.mkdir(parents=True, exist_ok=True)
        findings = build_findings(freeze_brief)
        csv_path = write_csv(findings, briefs_dir / "investigator_findings.csv")
        json_path = write_json(findings, briefs_dir / "investigator_findings.json")
        written.append(csv_path)
        written.append(json_path)
        log.info(
            "wrote investigator exports: %s + %s (%d findings)",
            csv_path.name, json_path.name, len(findings),
        )
    except Exception as e:  # noqa: BLE001
        log.warning("investigator export failed (continuing): %s", e)

    # Victim-facing summary letter. Skipped on wallet traces
    # (skip_freeze_briefs=True / case_id=NULL) — those rows don't
    # have a real victim to address the letter to. Only ships on
    # case-driven runs where we have a VictimInfo with a real name +
    # email. Two variants selected automatically based on whether
    # freezable funds were found; see worker/_victim_summary.py for
    # the dispatch + template logic.
    is_recoverable = False
    total_freezable_usd = Decimal(0)
    total_suspected_usd = Decimal(0)
    if not skip_freeze_briefs:
        # CRIT-2 fix: classification runs in its own try/except so the
        # engagement-letter decision is never silently suppressed by a
        # victim-summary rendering failure. Pre-fix, a Jinja error in
        # render_victim_summary would leave is_recoverable=False and
        # skip the engagement letter even on a fully recoverable case.
        try:
            from recupero.worker._victim_summary import classify_recovery_prospects
            is_recoverable, total_freezable_usd, total_suspected_usd = (
                classify_recovery_prospects(freeze_brief)
            )
        except Exception as e:  # noqa: BLE001
            log.warning("classify_recovery_prospects failed (using defaults): %s", e)

        try:
            from recupero.worker._victim_summary import render_victim_summary
            briefs_dir = case_dir / "briefs"
            briefs_dir.mkdir(parents=True, exist_ok=True)
            victim_summary_path = render_victim_summary(
                case=case,
                victim=victim,
                investigator=investigator,
                freeze_brief=freeze_brief,
                briefs_dir=briefs_dir,
                flow_filename=flow_filename,
            )
            if victim_summary_path is not None:
                written.append(victim_summary_path)
                html_paths.append(victim_summary_path)
                log.info("wrote victim summary: %s", victim_summary_path.name)
        except Exception as e:  # noqa: BLE001
            log.error("victim summary generation failed (continuing): %s", e)

    # Tier-2 engagement letter — the legal contract the customer
    # signs to engage active recovery. Pre-generated for every
    # recoverable case so the operator has it ready to send when a
    # customer says yes. Skipped on wallet traces and on
    # unrecoverable cases (where there's nothing to engage on).
    engagement_path = None
    if not skip_freeze_briefs and is_recoverable:
        try:
            from recupero.worker._engagement_letter import render_engagement_letter
            briefs_dir = case_dir / "briefs"
            briefs_dir.mkdir(parents=True, exist_ok=True)
            engagement_path = render_engagement_letter(
                case=case,
                victim=victim,
                investigator=investigator,
                freeze_brief=freeze_brief,
                briefs_dir=briefs_dir,
                total_freezable_usd=total_freezable_usd,
                total_suspected_usd=total_suspected_usd,
            )
            if engagement_path is not None:
                written.append(engagement_path)
                html_paths.append(engagement_path)
                log.info("wrote engagement letter: %s", engagement_path.name)
        except Exception as e:  # noqa: BLE001
            log.warning("engagement letter generation failed (continuing): %s", e)

    if skip_freeze_briefs:
        log.info(
            "skip_freeze_briefs=true — emitting only trace_report; "
            "customer-facing freeze letters + LE handoffs not generated",
        )
    elif not has_transfers:
        # No transfers means nothing to seize — freeze letters would
        # be addressed to issuers with no destinations to name. Skip
        # the loop; trace_report already shipped above.
        pass
    else:
        # Index freeze_brief.FREEZABLE entries by issuer name so each
        # per-issuer letter gets the holdings list for THAT specific
        # issuer — Circle's letter asks for USDC at Circle-controlled
        # addresses, Tether's letter asks for USDT at Tether-controlled
        # addresses, etc. Pre-fix every letter asked for the original
        # theft asset (e.g., 130 ETH) at the first hop, which is the
        # wrong question for stablecoin issuers (they don't control ETH).
        freezable_by_issuer: dict[str, dict] = {}
        for entry in freezable:
            issuer_name = entry.get("issuer")
            if issuer_name:
                freezable_by_issuer[issuer_name] = entry

        # v0.19.1 (round-12 PDF-CRIT-1): wire IC3 case ID + DRAFT flag
        # through the worker → brief boundary. Pre-v0.19.1 the v0.18.6
        # `ic3_case_id` / `draft` kwargs were added to generate_briefs()
        # but the worker (the only path that runs in production) never
        # passed them, so every production LE handoff rendered without
        # the IC3 Reference row — FBI couldn't match the case to the
        # IC3 complaint record.
        _ic3_case_id = (freeze_brief.get("IC3_CASE_ID") or "").strip() or None
        _draft = bool(freeze_brief.get("DRAFT") or freeze_brief.get("draft"))
        _draft_label = freeze_brief.get("DRAFT_LABEL") or freeze_brief.get("draft_label")

        # v0.21.0: fetch live filing status once (per case, not per
        # issuer) so the LE handoff Section 5.5 renders the current
        # state of every freeze letter dispatched for this case. On
        # the FIRST render (immediately after emit_brief, no letters
        # mailed yet) this returns an empty LiveFilingStatus and the
        # template renders the "Pending issuer outreach" branch.
        #
        # v0.21.1 (audit-fix CRITICAL A1): pass investigation_id (the
        # worker passes its UUID through this function) so the SQL
        # filters by freeze_letters_sent.investigation_id rather than
        # case_id — case_id on that table references cases.id (UUID)
        # while case.case_id here is a brief identifier string, so the
        # pre-fix query never matched and Section 5.5 silently rendered
        # the empty-state branch even after letters and outcomes existed.
        _live_status = None
        try:
            import os as _os
            _dsn = _os.environ.get("SUPABASE_DB_URL", "").strip() or None
            if _dsn:
                from recupero.freeze_learning.status import fetch_live_filing_status
                _live_status = fetch_live_filing_status(
                    case_id=getattr(case, "case_id", None),
                    investigation_id=investigation_id,
                    dsn=_dsn,
                )
        except Exception as _exc:  # noqa: BLE001 — non-fatal
            log.warning(
                "fetch_live_filing_status failed (non-fatal, "
                "template falls back to pending branch): %s", _exc,
            )

        # v0.24.0: cross-case cooperation profiles for every issuer in
        # the freeze ask list. Surfaces in LE Section 5.7 with a
        # recommended legal instrument per issuer. Best-effort —
        # failure returns empty dict (template hides Section 5.7).
        _cooperation_profiles: dict = {}
        try:
            import os as _os
            _dsn = _os.environ.get("SUPABASE_DB_URL", "").strip() or None
            if _dsn and issuers_seen:
                from recupero.monitoring.cooperation_intelligence import (
                    build_cooperation_profile,
                    recommend_legal_instrument,
                )
                # Pull OFAC + IC3 signals for the instrument recommender.
                _ofac_exposed = bool(
                    (freeze_brief.get("RISK_ASSESSMENT") or {}).get("ofac_exposure")
                )
                _ic3_case_id_for_rec = (
                    (freeze_brief.get("IC3_CASE_ID") or "").strip() or None
                )
                for _iss_name, _iss_info in issuers_seen.items():
                    _prof = build_cooperation_profile(_iss_name, dsn=_dsn)
                    _rec = recommend_legal_instrument(
                        _prof,
                        jurisdiction=getattr(_iss_info, "jurisdiction", None),
                        ofac_exposed=_ofac_exposed,
                        ic3_case_id=_ic3_case_id_for_rec,
                    )
                    # Flatten to a template-friendly dict (the template
                    # uses .get(key) so missing keys degrade cleanly).
                    _cooperation_profiles[_iss_name] = {
                        "issuer": _prof.issuer,
                        "n_letters_sent": _prof.n_letters_sent,
                        "n_responded": _prof.n_responded,
                        "n_silent": _prof.n_silent,
                        "response_rate": _prof.response_rate,
                        "full_freeze_rate": _prof.full_freeze_rate,
                        "partial_freeze_rate": _prof.partial_freeze_rate,
                        "declined_rate": _prof.declined_rate,
                        "silence_rate": _prof.silence_rate,
                        "median_response_hours": _prof.median_response_hours,
                        "avg_response_hours": _prof.avg_response_hours,
                        "is_black_hole": _prof.is_black_hole,
                        "has_confident_profile": _prof.has_confident_profile,
                        "recommended_instrument": _rec.instrument,
                        "recommended_instrument_reason": _rec.reason,
                        "estimated_response_days": _rec.estimated_response_days,
                    }
        except Exception as _exc:  # noqa: BLE001 — non-fatal
            log.warning(
                "build cooperation_profiles failed (non-fatal, "
                "LE Section 5.7 will be hidden): %s", _exc,
            )

        for issuer_name, issuer_info in issuers_seen.items():
            try:
                bundle = generate_briefs(
                    primary_case=case,
                    linked_cases=[],
                    victim=victim,
                    investigator=investigator,
                    case_dir=case_dir,
                    issuer=issuer_info,
                    flow_filename=flow_filename,
                    issuer_freezable=freezable_by_issuer.get(issuer_name),
                    # v0.20.3 (render-sim audit CRIT): pass ALL issuer
                    # holdings so the LE handoff Section 4.2 renders the
                    # complete inventory — Tether/Circle/Coinbase holdings
                    # AND Sky Protocol UNRECOVERABLE were invisible to LE
                    # before this fix because the production worker never
                    # passed all_issuers_freezable (only the test harness
                    # did). Now wired through from freeze_brief directly.
                    all_issuers_freezable=freeze_brief.get("ALL_ISSUER_HOLDINGS") or None,
                    ic3_case_id=_ic3_case_id,
                    live_status=_live_status,
                    # v0.21.0: surface recovery probability on the LE
                    # handoff cover. Computed by emit_brief via the
                    # scorer; lives in freeze_brief.RECOVERY_ESTIMATE.
                    recovery_estimate=freeze_brief.get("RECOVERY_ESTIMATE") or None,
                    # v0.23.0: surface multi-victim cluster membership.
                    # Populated by cluster_builder at emit_brief tail; None
                    # for cases with no cross-case perp overlap.
                    cluster_membership=freeze_brief.get("CLUSTER_MEMBERSHIP") or None,
                    # v0.24.0: per-issuer cooperation profiles (Section 5.7).
                    cooperation_profiles=_cooperation_profiles,
                    draft=_draft,
                    draft_label=_draft_label,
                )
                written.append(bundle.maple_path)
                written.append(bundle.le_path)
                written.append(bundle.manifest_path)
                html_paths.extend([bundle.maple_path, bundle.le_path])
                log.info(
                    "wrote freeze brief for issuer=%s file=%s",
                    issuer_name, bundle.maple_path.name,
                )
            except Exception as e:  # noqa: BLE001
                # One issuer's brief failing shouldn't kill the whole stage —
                # log and continue so other issuers still get briefs.
                log.warning("brief generation failed for issuer=%s: %s",
                            issuer_name, e)

    # v0.28.0 (Jacob review item 3): render the SUBPOENA_TARGETS
    # artifact family — one subpoena_target_*.html per entry +
    # one subpoena_playbook_*.html per case. These are operator-
    # facing legal-process workplans for cases where the
    # perpetrator-controlled position is real but not issuer-
    # freezable (DAI / native ETH / Sky / WETH).
    try:
        from recupero.reports.subpoena_renderer import (
            render_subpoena_artifacts,
        )
        subpoena_paths = render_subpoena_artifacts(
            case=case,
            victim=victim,
            investigator=investigator,
            freeze_brief=freeze_brief,
            case_dir=case_dir,
        )
        for p in subpoena_paths:
            written.append(p)
            html_paths.append(p)
        if subpoena_paths:
            log.info(
                "wrote %d subpoena artifact(s) for case=%s",
                len(subpoena_paths), case.case_id,
            )
    except Exception as _exc:  # noqa: BLE001
        # Subpoena render failure is non-fatal — log + continue so
        # the rest of the deliverables still ship. INVARIANT E will
        # surface the gap at validation time.
        log.warning(
            "subpoena artifact rendering failed (non-fatal, "
            "INVARIANT E will flag at validation): %s", _exc,
        )

    # Generate PDF versions of every HTML deliverable + the standalone
    # flow SVG. Best-effort — a WeasyPrint failure on one file logs a
    # warning but doesn't kill the stage (operators can still hand-deliver
    # the HTML / SVG to compliance teams that don't strictly require PDF).
    #
    # Kill-switch: RECUPERO_DISABLE_PDF_RENDER=1 skips WeasyPrint
    # entirely. On a memory-constrained Railway container with 8
    # PDFs to render per case (4 issuers × 2 letter types), the
    # combined memory footprint of WeasyPrint + inline-SVG filters
    # has been observed to OOM the worker. Disabling PDF render
    # ships the HTML deliverables alone — they still embed the new
    # appendix + clickable Etherscan links + are readable in any
    # browser; compliance teams that need PDFs can print-to-PDF
    # from the browser.
    if os.environ.get("RECUPERO_DISABLE_PDF_RENDER", "").strip() == "1":
        log.info("PDF render skipped — RECUPERO_DISABLE_PDF_RENDER=1")
        pdf_paths: list[Path] = []
    else:
        pdf_paths = _emit_pdfs(html_paths, flow_svg_path=flow_svg_path if flow_filename else None)
    written.extend(pdf_paths)

    # Case-level manifest: declares every case-scoped artifact
    # (engagement_letter, victim_summary, recovery_snapshot, trace_report,
    # flow svg, findings csv/json + their PDF siblings). Per-issuer
    # manifests already cover freeze_request + le_handoff. With both,
    # every primary deliverable on disk is declared in *some* manifest
    # and the chain-of-custody validator's orphan check goes clean.
    _write_case_manifest(
        briefs_dir=case_dir / "briefs",
        case=case,
        written=written,
    )

    # Auto-send the victim-summary letter to the victim. Skipped on
    # wallet traces (no real victim email), on cases without a
    # victim email (operator didn't capture one), and on cases
    # we've already sent for (idempotency via emails_sent audit log).
    # Disable globally with RECUPERO_DISABLE_EMAIL=1 for local dev.
    _maybe_auto_send_victim_summary(
        investigation_id=investigation_id,
        # Plumb the case UUID through so the auto-send can mint a
        # portal token for /portal/<token>. case.case_id is a str on
        # the Pydantic model; the portal tokens.generate_token call
        # converts via UUID() inside.
        case_id=str(case.case_id) if case.case_id else None,
        victim=victim,
        case_dir=case_dir,
        pdf_paths=pdf_paths,
        skip=skip_freeze_briefs,
    )

    log.info("deliverables done: %d file(s) under %s/briefs/",
             len(written), case_dir.name)
    return written


# Filename prefixes for case-level (non per-issuer) artifacts that must
# appear in the case manifest so the chain-of-custody validator's
# `_check_orphan_artifacts_on_disk` sees them as declared. Per-issuer
# files (freeze_request_*, le_handoff_*) are covered by the per-issuer
# manifests written from brief.py.
_CASE_MANIFEST_PREFIXES = (
    "engagement_letter_",
    "victim_summary_",
    "recovery_snapshot_",
    "trace_report_",
    "flow_",
    "investigator_findings",  # .csv + .json
)


def _write_case_manifest(
    *, briefs_dir: Path, case: Case, written: list[Path]
) -> None:
    """Emit ``manifest_case_<case_id>.json`` declaring every case-scoped
    artifact under briefs/. Hashes are computed from on-disk bytes (the
    canonical thing the validator will hash later), so atomic-write
    races between HTML emission and the manifest write resolve to
    whatever ended up on disk.

    Best-effort: any failure logs a warning and leaves the case-level
    manifest unwritten. The per-issuer manifests are still in place,
    so the case still has chain-of-custody coverage for the freeze
    letters + LE handoffs; only the supplementary deliverables fall
    back to orphan-info severity.
    """
    import hashlib
    import json

    from recupero._common import atomic_write_text
    # Honor SOURCE_DATE_EPOCH for reproducible-builds workflows so the
    # case manifest's `generated_at` field doesn't break byte-identical
    # idempotency checks (RIGOR-7 E2E). Falls back to wall-clock when
    # the env var is absent.
    from recupero.reports.brief import _resolve_render_time

    if not briefs_dir.is_dir():
        return
    try:
        outputs: dict[str, str] = {}
        shas: dict[str, str] = {}
        for path in sorted(briefs_dir.iterdir()):
            if not path.is_file():
                continue
            if not any(path.name.startswith(p) for p in _CASE_MANIFEST_PREFIXES):
                continue
            # Use the full filename as the manifest key. Stable, unique,
            # and the validator's orphan-check matches against Path(v).name
            # anyway so a self-naming key is the most direct contract.
            # Filename (not absolute path) — manifest is co-located with
            # the files it declares, and absolute paths break SOURCE_DATE_
            # EPOCH-honored byte-identical idempotency (different temp
            # dirs per test run, different container roots in prod, etc.).
            outputs[path.name] = path.name
            shas[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if not outputs:
            return  # nothing to declare; skip the empty manifest
        case_id_str = (
            str(case.case_id) if getattr(case, "case_id", None) else "unknown"
        )
        manifest = {
            "kind": "case_manifest",
            "case_id": case_id_str,
            "generated_at": _resolve_render_time().isoformat(),
            "outputs": outputs,
            "output_sha256": shas,
        }
        manifest_path = briefs_dir / f"manifest_case_{case_id_str}.json"
        atomic_write_text(
            manifest_path,
            json.dumps(
                manifest, indent=2, sort_keys=True,
                allow_nan=False, ensure_ascii=False,
            ),
        )
        written.append(manifest_path)
        log.info(
            "wrote case-level manifest: %s (%d artifact(s))",
            manifest_path.name, len(outputs),
        )
    except Exception as e:  # noqa: BLE001
        log.warning("case manifest write failed (continuing): %s", e)


def _maybe_auto_send_victim_summary(
    *,
    investigation_id: str | None,
    case_id: str | None,
    victim: VictimInfo,
    case_dir: Path,
    pdf_paths: list[Path],
    skip: bool,
) -> None:
    """Send the victim summary letter to the victim if eligible.

    Eligibility:
      * Not a wallet trace (skip == False, i.e., case-driven)
      * Victim has an email address on file
      * Investigation_id is known (needed for audit + idempotency)
      * No prior successful send for this (investigation_id,
        victim_summary) pair

    Sends the victim_summary HTML + attaches:
      * trace_report.pdf
      * flow_*.pdf
      * victim_summary_*.pdf
      * engagement_letter_*.pdf (if recoverable)

    The freeze-letter PDFs are NOT attached to the victim email —
    those are operator-controlled sends to compliance teams.
    """
    if skip or not investigation_id or not victim.email:
        return

    try:
        from recupero.worker._email import has_been_sent, send_email
    except Exception as e:  # noqa: BLE001
        log.warning("email module import failed (skipping auto-send): %s", e)
        return

    if has_been_sent(
        investigation_id=investigation_id,
        email_type="victim_summary",
    ):
        log.info(
            "auto-send skip: victim_summary already sent for inv=%s",
            investigation_id,
        )
        return

    # Find the rendered victim_summary HTML.
    # Use the most-recently-modified file when multiple exist (e.g. on a
    # re-run) so the Pay-Now banner detection (filename-based) picks the
    # correct variant. glob() returns paths in filesystem order which is
    # non-deterministic; picking [0] blindly could choose the wrong variant.
    briefs_dir = case_dir / "briefs"
    summary_htmls = list(briefs_dir.glob("victim_summary_*.html"))
    if not summary_htmls:
        log.info(
            "auto-send skip: no victim_summary HTML found for inv=%s",
            investigation_id,
        )
        return
    if len(summary_htmls) > 1:
        log.warning(
            "found %d victim_summary HTML files for inv=%s; using most recent",
            len(summary_htmls), investigation_id,
        )
    summary_html_path = max(summary_htmls, key=lambda p: p.stat().st_mtime)

    # Build attachment list — customer-relevant PDFs only
    attachment_globs = [
        "trace_report_*.pdf",
        "flow_*.pdf",
        "victim_summary_*.pdf",
        "engagement_letter_*.pdf",
        # v0.22.1 (audit-fix H2): the Recovery Snapshot is the
        # pre-engagement decision-support deliverable. The whole point
        # is for the victim to see it BEFORE paying — so it MUST be
        # attached to the victim summary email alongside the other
        # PDFs. Pre-v0.22.1 the snapshot was generated to disk but
        # never delivered.
        "recovery_snapshot_*.pdf",
    ]
    attachments: list[Path] = []
    for pattern in attachment_globs:
        attachments.extend(briefs_dir.glob(pattern))

    subject = f"Recupero Investigation Summary — Case {investigation_id[:8]}"
    html_body = summary_html_path.read_text(encoding="utf-8")
    preview = (
        f"Recupero forensic-trace results for {victim.name}. "
        "Findings and next-step options inside."
    )

    # Mint a customer-portal token + inject a banner at the top of
    # the email body. This is the link the victim clicks to view
    # case status, download artifacts, and e-sign the engagement
    # letter — without it the portal we shipped in v0.5.0 has no
    # delivery channel. Failure to mint a token is non-fatal: we
    # still send the email (with the existing PDF attachments) but
    # without the banner. The operator can re-issue manually via
    # `recupero-ops generate-customer-link`.
    portal_banner = _build_portal_banner_html(case_id=case_id)

    # On recoverable cases, ALSO inject a Pay-Now button for the
    # engagement fee, so the customer can convert directly from
    # the inbox. We detect recoverable from the rendered
    # template filename (set at render time by
    # _victim_summary.render_victim_summary based on
    # classify_recovery_prospects).
    is_recoverable = summary_html_path.name.startswith(
        "victim_summary_recoverable_"
    )
    pay_banner = ""
    if is_recoverable and investigation_id:
        pay_banner = _build_pay_engagement_banner_html(
            investigation_id=investigation_id,
            victim_email=victim.email,
        )

    if portal_banner or pay_banner:
        html_body = portal_banner + pay_banner + html_body

    try:
        from recupero.worker._email import _mask_email_for_log
        result = send_email(
            to=victim.email,
            subject=subject,
            html=html_body,
            investigation_id=investigation_id,
            email_type="victim_summary",
            attachments=attachments,
            preview_text=preview,
        )
        masked_to = _mask_email_for_log(victim.email)
        if result.success:
            log.info(
                "auto-sent victim summary to=%s inv=%s message_id=%s "
                "(%d attachment(s))",
                masked_to, investigation_id,
                result.message_id, len(attachments),
            )
        elif result.skipped:
            log.info("auto-send skipped (RECUPERO_DISABLE_EMAIL=1): inv=%s",
                     investigation_id)
        else:
            log.warning("auto-send victim summary FAILED to=%s inv=%s err=%s",
                        masked_to, investigation_id, result.error)
    except Exception as e:  # noqa: BLE001
        log.warning("auto-send victim summary unexpected error: %s", e)


def _build_portal_banner_html(*, case_id: str | None) -> str:
    """Mint a customer-portal token for `case_id` and return the
    HTML banner that prepends the auto-sent victim-summary email.

    Returns an empty string (so the prepend is a no-op) on any of:
      * case_id is None (wallet trace — no real case → no portal)
      * SUPABASE_DB_URL env var unset (we can't reach the tokens table)
      * Token generation fails for any reason

    The banner is intentionally self-contained — inline-styled, no
    external assets — so it renders consistently across Gmail /
    Outlook / Apple Mail without depending on the recipient mail
    client's CSS support.
    """
    if not case_id:
        return ""
    import os
    from uuid import UUID
    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        log.info("portal banner skipped: no SUPABASE_DB_URL")
        return ""
    try:
        from recupero.portal.tokens import generate_token, public_portal_url
    except Exception as exc:  # noqa: BLE001
        log.warning("portal banner: import failed (%s) — skipping", exc)
        return ""
    try:
        _, token, _ = generate_token(
            case_id=UUID(case_id),
            dsn=dsn,
            ttl_days=90,
            label="auto-from-victim-summary",
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("portal banner: token mint failed (%s) — skipping", exc)
        return ""
    url = public_portal_url(token=token)
    # Inline styles only — Gmail strips <style> blocks aggressively.
    # Colors mirror the portal's own brand pallet (deep green accent
    # on light-cream background).
    return (
        '<div style="margin:0 0 24px;padding:20px 24px;'
        'background:#f7f5ed;border-left:4px solid #2a5e3e;'
        'border-radius:4px;font-family:-apple-system,BlinkMacSystemFont,'
        '\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;">'
        '<div style="font-size:13px;color:#555;'
        'text-transform:uppercase;letter-spacing:0.05em;'
        'font-weight:600;margin-bottom:8px;">Your Recupero case page</div>'
        '<div style="font-size:15px;color:#1a1a1a;line-height:1.5;'
        'margin-bottom:14px;">'
        'View case status, download your artifacts, and (if applicable) '
        'sign the engagement letter electronically from one place.'
        '</div>'
        f'<a href="{_html.escape(url, quote=True)}" '
        'style="display:inline-block;background:#2a5e3e;color:#ffffff;'
        'text-decoration:none;padding:10px 18px;border-radius:5px;'
        'font-weight:600;font-size:14px;">Open case page →</a>'
        '<div style="font-size:12px;color:#888;margin-top:14px;">'
        'This link is private to your case and expires in 90 days. '
        'If you ever lose it, reply to this email and we will reissue.'
        '</div>'
        '</div>'
    )


def _build_pay_engagement_banner_html(
    *,
    investigation_id: str,
    victim_email: str | None,
) -> str:
    """Build the inline-styled Pay-Now banner for the engagement
    fee. Mints a Stripe Payment Link URL with the
    investigation_id encoded in client_reference_id so the
    dispatcher can correlate the payment back when the webhook
    fires.

    Returns an empty string (no-op prepend) when:
      * RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK is unset
      * URL build raises for any reason

    The banner sits BELOW the portal banner in the email — portal
    first because customers will check status more often than they
    convert, and visual hierarchy matters. Different accent color
    (warm amber vs the portal's deep green) so the two banners
    read as distinct CTAs.
    """
    try:
        from uuid import UUID as _UUID

        from recupero._pricing import ENGAGEMENT_FEE_USD, fmt_usd_short
        from recupero.payments.payment_links import (
            PaymentLinkConfigError,
            build_engagement_link,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("pay banner: import failed (%s) — skipping", exc)
        return ""
    try:
        url = build_engagement_link(
            investigation_id=_UUID(investigation_id),
            prefilled_email=victim_email,
        )
    except PaymentLinkConfigError as exc:
        # Env var unset — expected on dev / pre-Stripe deployments.
        # Log at INFO level so it doesn't show up as a warning.
        log.info("pay banner skipped: %s", exc)
        return ""
    except Exception as exc:  # noqa: BLE001
        log.warning("pay banner: URL build failed (%s) — skipping", exc)
        return ""

    fee_short = fmt_usd_short(ENGAGEMENT_FEE_USD)

    # Same inline-style discipline as the portal banner: Gmail
    # strips <style> blocks, so every visual property is inline.
    return (
        '<div style="margin:0 0 24px;padding:20px 24px;'
        'background:#fff7e6;border-left:4px solid #c47a00;'
        'border-radius:4px;font-family:-apple-system,BlinkMacSystemFont,'
        '\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;">'
        '<div style="font-size:13px;color:#7a4d00;'
        'text-transform:uppercase;letter-spacing:0.05em;'
        'font-weight:600;margin-bottom:8px;">Ready to begin recovery?</div>'
        '<div style="font-size:15px;color:#1a1a1a;line-height:1.5;'
        'margin-bottom:14px;">'
        f'Your case is recoverable. The next step is the {fee_short} '
        'engagement that activates 30 days of compliance freeze '
        'requests, law-enforcement coordination, and weekly status '
        'updates.'
        '</div>'
        f'<a href="{_html.escape(url, quote=True)}" '
        'style="display:inline-block;background:#c47a00;color:#ffffff;'
        'text-decoration:none;padding:10px 18px;border-radius:5px;'
        f'font-weight:600;font-size:14px;">Begin recovery — {fee_short} →</a>'
        '<div style="font-size:12px;color:#888;margin-top:14px;">'
        'Payment processed by Stripe. Recovery is not guaranteed; '
        'see the attached engagement letter PDF for full terms.'
        '</div>'
        '</div>'
    )


def _emit_pdfs(html_paths: list[Path], *, flow_svg_path: Path | None) -> list[Path]:
    """Render PDFs for each HTML deliverable plus the flow-diagram SVG.

    Lazy-imports WeasyPrint so any code path that lacks the apt-installed
    Pango/Cairo libs (CLI, dev machines without GTK stack) can still run
    the rest of the pipeline.

    Returns the list of PDFs written. Each failure logs a warning and
    continues — the HTML deliverable is still on disk, so partial output
    is more useful than failing the entire building_package stage.

    On EVM-flavored fund-flow SVGs, WeasyPrint preserves the per-node
    ``xlink:href`` Etherscan URLs as PDF link annotations so the PDF
    output stays clickable.
    """
    out: list[Path] = []
    try:
        from weasyprint import HTML  # noqa: F401  (lazy import)
    except Exception as e:  # noqa: BLE001
        log.warning(
            "PDF generation skipped (WeasyPrint not importable): %s. "
            "HTML deliverables still on disk; operators can print-to-PDF "
            "from the browser if needed.", e,
        )
        return out

    for html_path in html_paths:
        pdf_path = html_path.with_suffix(".pdf")
        try:
            _html_to_pdf(html_path, pdf_path)
            # Post-process to inject missing chain-explorer /Link
            # annotations.
            #
            # Default: OFF. Three successive Railway deployments of
            # this patcher (subprocess-isolated + page-capped) have
            # left workers hung mid-building_package — same symptom
            # every time: heartbeat stops at the building_package
            # status flip, reaper picks it up 300s later. The
            # patcher works perfectly locally (adds 11 /Link
            # annotations to the exact same Railway-produced PDF
            # in <1s) so we have an environment-specific bug we
            # haven't reproduced yet.
            #
            # To unblock shipping today, the patcher is now opt-in
            # via RECUPERO_ENABLE_LINK_PATCH=1. Production runs with
            # the WeasyPrint native ~54% link coverage until we have
            # a reproduction trace of the Railway-side hang.
            link_patch_env = os.environ.get(
                "RECUPERO_ENABLE_LINK_PATCH", ""
            ).strip()
            if link_patch_env == "1":
                log.info("link patch starting for %s (opt-in)", pdf_path.name)
                try:
                    _patch_pdf_links_subprocess(pdf_path)
                    log.info("link patch finished for %s", pdf_path.name)
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "link patch subprocess failed for %s "
                        "(continuing with WeasyPrint output): %s",
                        pdf_path.name, exc,
                    )
            else:
                log.debug(
                    "link patch skipped for %s "
                    "(set RECUPERO_ENABLE_LINK_PATCH=1 to enable)",
                    pdf_path.name,
                )
            out.append(pdf_path)
            log.info("rendered PDF: %s (%d bytes)", pdf_path.name, pdf_path.stat().st_size)
        except Exception as e:  # noqa: BLE001
            log.warning("PDF render failed for %s: %s", html_path.name, e)

    if flow_svg_path is not None and flow_svg_path.exists():
        pdf_path = flow_svg_path.with_suffix(".pdf")
        try:
            _svg_to_pdf(flow_svg_path, pdf_path)
            out.append(pdf_path)
            log.info("rendered PDF: %s (%d bytes)", pdf_path.name, pdf_path.stat().st_size)
        except Exception as e:  # noqa: BLE001
            log.warning("PDF render failed for %s: %s", flow_svg_path.name, e)

    return out


def validate_url_for_weasyprint(url: str, base_dir: str) -> None:
    """Reject any URL WeasyPrint should not fetch.

    Allowlist policy (anything outside this raises ``ValueError``):

      * Empty / ``file:`` schemes whose resolved path lies *inside*
        ``base_dir`` (case_dir). Symlinks are resolved via realpath
        before the boundary check so a symlink-inside-case_dir
        pointing at ``/etc/shadow`` is rejected.
      * Boundary check uses ``os.path.commonpath`` (not naive
        ``startswith``) so sibling paths like ``/case_dir_evil/...``
        cannot bypass via prefix overlap.

    Everything else — ``http``, ``https``, ``ftp``, ``data``, ``gopher``,
    ``sftp``, ``jar``, ``javascript``, any unknown scheme — is rejected.
    The pre-W7-02 fetcher rejected only http/https/ftp explicitly and
    fell through to ``default_url_fetcher`` for every other scheme,
    including ``data:`` (an editorial-AI prompt injection vector since
    ``<img src="data:text/html;base64,...">`` could carry arbitrary
    payloads that WeasyPrint's data-URL handler would gladly decode).
    """
    from urllib.parse import urlparse
    p = urlparse(url)
    scheme = p.scheme.lower()
    # Windows drive letters ("C:\\...") parse with scheme="c" — treat
    # any single-character scheme as a bare local path, not a URL scheme.
    if len(scheme) == 1:
        scheme = ""
    # Allowlist: only empty + file: are candidates for local fetch.
    if scheme not in ("", "file"):
        raise ValueError(
            f"WeasyPrint refused fetch for disallowed scheme "
            f"{scheme!r}: {url}"
        )
    # Resolve the path. file:// URLs use p.path; bare paths fall through
    # via the url itself. realpath resolves symlinks so an in-tree
    # symlink can't point at /etc/shadow and pass the boundary check.
    # For Windows drive-letter "URLs" we discarded the scheme above, so
    # use the original `url` (urlparse will have placed "\\..." in p.path,
    # losing the drive).
    raw = url if len(p.scheme) == 1 else (p.path or url)
    resolved = os.path.realpath(os.path.abspath(raw))
    base_resolved = os.path.realpath(os.path.abspath(base_dir))
    # commonpath raises ValueError for cross-drive paths on Windows
    # (e.g., C: vs D:). Treat that as an out-of-tree reject.
    try:
        common = os.path.commonpath([resolved, base_resolved])
    except ValueError:
        raise ValueError(
            f"WeasyPrint refused out-of-tree fetch (cross-drive): {url}"
        )
    if common != base_resolved:
        raise ValueError(
            f"WeasyPrint refused out-of-tree fetch: {url} "
            f"(resolved={resolved}, base={base_resolved})"
        )


def _html_to_pdf(html_path: Path, pdf_path: Path) -> None:
    """Render an HTML deliverable to PDF in an isolated subprocess.

    Each render runs in its own Python process so a WeasyPrint OOM
    (8 PDFs per case × SVG-filter-heavy diagrams can blow past a
    512MB Railway container) kills only the subprocess, never the
    parent worker. The parent catches the non-zero exit, logs the
    error, and moves on to the next PDF — partial PDF output is
    more useful than failing the entire building_package stage.

    Timeout: 120s per PDF. A typical render is 1-3s; >30s suggests
    something pathological in the SVG and is better killed than
    pinned forever.
    """
    # v0.16.7 (round-9 audit CRIT): set PDF /Info metadata (Title,
    # Author, Subject, Producer) explicitly. Banks and LE archival
    # systems routinely reject PDFs with empty Title fields; chain-of-
    # custody verification needs an embedded producer record. The
    # title is derived from the source HTML filename so multiple
    # artifacts (engagement_letter.pdf, freeze_brief.pdf, …) get
    # distinguishable metadata without per-artifact code paths.
    #
    # v0.17.2 (output polish POLISH-1): when RECUPERO_PDF_VARIANT=pdf/a-3b
    # is set, render archive-grade PDF/A-3b. PDF/A is the standard
    # bank/LE archival systems expect for evidence retention; refuses
    # to render when fonts aren't embedded (which is why POLISH-2
    # bundles them). Default off because PDF/A is stricter — operators
    # opt in once the font-embedding work is verified for their deploy.
    #
    # The subprocess script is built as a sys.argv passthrough so the
    # render stays isolated from the parent worker's address space.
    #
    # v0.18.2 (round-11 sec-HIGH-008): SSRF lockdown. Pre-v0.18.2
    # WeasyPrint's default url_fetcher resolved any <img src>,
    # @font-face url(), or <link href> over HTTP — including
    # http://169.254.169.254 (cloud metadata service), http://railway.internal,
    # http://localhost:8080. The editorial AI is a prompt-injection
    # vector controlling text in INCIDENT_NARRATIVE_*; an attacker
    # who slipped <img src=http://169.254.169.254/...> into editorial
    # JSON would have WeasyPrint fetch IAM credentials. New: refuse
    # any URL scheme outside `file://` rooted at the case_dir.
    # W7-02 (sec-HIGH): strict allowlist fetcher — refuse every scheme
    # except in-tree file:// resources. Pre-W7-02 the fetcher rejected
    # only http/https/ftp explicitly and fell through to the default
    # fetcher for `data:`, `gopher:`, `sftp:`, `jar:`, etc. The boundary
    # check is also tightened: realpath + commonpath instead of naive
    # startswith (which would have allowed `/case_dir_evil/...`).
    script = (
        "import os, sys\n"
        "from weasyprint import HTML\n"
        "from urllib.parse import urlparse\n"
        "\n"
        "_case_dir = os.path.realpath(os.path.dirname(os.path.abspath(sys.argv[1])))\n"
        "\n"
        "def _no_network_fetcher(url, timeout=10, ssl_context=None):\n"
        "    p = urlparse(url)\n"
        "    scheme = p.scheme.lower()\n"
        "    if scheme not in ('', 'file'):\n"
        "        raise ValueError(f'WeasyPrint refused scheme {scheme!r}: {url}')\n"
        "    raw = p.path or url\n"
        "    resolved = os.path.realpath(os.path.abspath(raw))\n"
        "    try:\n"
        "        common = os.path.commonpath([resolved, _case_dir])\n"
        "    except ValueError:\n"
        "        raise ValueError(f'WeasyPrint refused cross-drive path: {url}')\n"
        "    if common != _case_dir:\n"
        "        raise ValueError(f'WeasyPrint refused out-of-tree path: {url}')\n"
        "    from weasyprint.urls import default_url_fetcher\n"
        "    return default_url_fetcher(url, timeout=timeout, ssl_context=ssl_context)\n"
        "\n"
        "variant = os.environ.get('RECUPERO_PDF_VARIANT', '').strip()\n"
        "kwargs = {\n"
        "    'pdf_identifier': sys.argv[1].encode('utf-8'),\n"
        "    'custom_metadata': True,\n"
        "}\n"
        "if variant:\n"
        "    kwargs['pdf_variant'] = variant\n"
        "HTML(filename=sys.argv[1], url_fetcher=_no_network_fetcher)"
        ".write_pdf(sys.argv[2], **kwargs)\n"
    )
    # v0.18.4 (round-11 worker-HIGH-009/013): atomic write. Render
    # to a sibling tempfile, then os.replace() onto the final path
    # so a SIGTERM / OOM-kill mid-render can't leave a truncated PDF
    # that the bucket sync would then ship to compliance teams. Same
    # contract as _common.atomic_write_text but adapted for PDFs
    # (binary, written by a subprocess).
    #
    # Adversarial-input audit: the tmp filename must be process-unique
    # so two concurrent workers running on the same case_dir don't smash
    # each other's tmp file (and os.replace one worker's partial PDF
    # over the other's complete render). Tag the sibling with pid+tid
    # so the names diverge per writer.
    import os as _os_uniq
    import threading as _threading_uniq
    _uniq = f".{_os_uniq.getpid()}.{_threading_uniq.get_ident()}"
    tmp_path = pdf_path.with_suffix(pdf_path.suffix + _uniq + ".tmp")
    _render_pdf_in_subprocess(
        script=script,
        args=[str(html_path), str(tmp_path)],
        label=html_path.name,
    )
    # If the subprocess succeeded the tmp file is complete. Atomic
    # rename onto the final path. If it didn't succeed,
    # _render_pdf_in_subprocess already raised — we never reach here.
    # v0.20.10 (R14-C MEDIUM): wrap os.replace in try/finally so the
    # .pdf.tmp file is always cleaned up even if the rename itself fails
    # (e.g., cross-device rename, permissions error, disk-full).
    # Matches the _svg_to_pdf pattern added in v0.20.8.
    import os as _os
    try:
        _os.replace(str(tmp_path), str(pdf_path))
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass


def _svg_to_pdf(svg_path: Path, pdf_path: Path) -> None:
    """Render a standalone SVG to PDF (subprocess-isolated, see above).

    WeasyPrint doesn't render SVG files directly; it renders HTML
    documents. Wrapping the SVG payload in a no-margin HTML shell lets
    us emit a single-page PDF whose page size auto-fits the SVG's
    intrinsic dimensions and preserves all ``href`` link annotations.
    """
    # ``errors="replace"`` so a rogue byte from Graphviz doesn't fail
    # the entire upload step — match read_inline_svg's tolerance.
    svg_content = svg_path.read_text(encoding="utf-8", errors="replace")
    # @page rule with size:auto picks up the SVG's width/height so the
    # PDF page doesn't stretch or crop the diagram.
    html_shell = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<style>@page{size:auto;margin:0}body{margin:0;padding:0}"
        "svg{display:block}</style></head><body>"
        f"{svg_content}</body></html>"
    )
    # Write the shell to a tempfile so the subprocess can read it
    # without inheriting any Python state from the parent.
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".html",
        delete=False, dir=str(svg_path.parent),
    ) as tmp:
        tmp.write(html_shell)
        shell_path = Path(tmp.name)
    # v0.20.8 (final-audit pipeline-CRIT-3): atomic write — render to a
    # sibling .tmp file then os.replace() onto the final path so a
    # SIGTERM / OOM mid-render can't leave a truncated PDF. Mirrors the
    # v0.18.4 fix applied to _html_to_pdf that was never backported here.
    #
    # Adversarial-input audit: same per-worker uniqueness as
    # _html_to_pdf — pid+tid tag prevents concurrent-worker tmp-file
    # collision on the same case_dir.
    import os as _os_uniq
    import threading as _threading_uniq
    _uniq = f".{_os_uniq.getpid()}.{_threading_uniq.get_ident()}"
    tmp_pdf_path = pdf_path.with_suffix(pdf_path.suffix + _uniq + ".tmp")
    try:
        # v0.18.2 (round-11 sec-HIGH-008): same SSRF lockdown as the
        # HTML→PDF path. SVG documents can carry <image href="http://...">
        # which WeasyPrint would otherwise fetch.
        _render_pdf_in_subprocess(
            script=(
                # W7-02: same strict allowlist + realpath+commonpath
                # boundary as the HTML→PDF path. SVG documents can carry
                # <image href="data:..."> or <image href="http://...">;
                # both must be refused.
                "import os, sys\n"
                "from urllib.parse import urlparse\n"
                "from weasyprint import HTML\n"
                "from weasyprint.urls import default_url_fetcher\n"
                "_base = os.path.realpath(os.path.abspath(sys.argv[3]))\n"
                "def _no_net(url, timeout=10, ssl_context=None):\n"
                "    p = urlparse(url)\n"
                "    scheme = p.scheme.lower()\n"
                "    if scheme not in ('','file'):\n"
                "        raise ValueError(f'refused scheme {scheme!r}: {url}')\n"
                "    raw = p.path or url\n"
                "    resolved = os.path.realpath(os.path.abspath(raw))\n"
                "    try:\n"
                "        common = os.path.commonpath([resolved, _base])\n"
                "    except ValueError:\n"
                "        raise ValueError(f'refused cross-drive: {url}')\n"
                "    if common != _base:\n"
                "        raise ValueError(f'out-of-tree path: {url}')\n"
                "    return default_url_fetcher(url, timeout=timeout, ssl_context=ssl_context)\n"
                "HTML(filename=sys.argv[1], base_url=sys.argv[3], url_fetcher=_no_net)"
                ".write_pdf(sys.argv[2])"
            ),
            args=[str(shell_path), str(tmp_pdf_path), str(svg_path.parent)],
            label=svg_path.name,
        )
        os.replace(str(tmp_pdf_path), str(pdf_path))
    finally:
        try:
            shell_path.unlink()
        except OSError:
            pass
        # Clean up partial tmp PDF if subprocess failed or rename raised
        try:
            tmp_pdf_path.unlink(missing_ok=True)
        except OSError:
            pass


def _subprocess_safe_env() -> dict[str, str]:
    """Return a minimal env dict for render / patcher subprocesses.

    v0.17.7 (round-10 PDF/Output security HIGH): pre-v0.17.7 every
    subprocess.Popen inherited the worker's full env, including:

      * ANTHROPIC_API_KEY (editorial-stage credentials)
      * SUPABASE_DB_URL (Postgres password embedded)
      * HELIUS_API_KEY (Solana RPC creds)
      * COINGECKO_API_KEY (pricing creds)
      * RECUPERO_TOKEN_PEPPER (portal-token HMAC pepper)
      * SMTP / SendGrid creds
      * Sentry DSN

    If WeasyPrint or any of its deep deps (pango, cairo, fontconfig,
    pypdf) ever dumped env-var contents into a crash trace, the
    stderr-capture tempfile would land in Railway logs — every
    secret leaked at once. The render + patcher subprocesses read
    NO secrets, so we hand them the minimum needed to find Python,
    fonts, and tempdirs.

    Allowed keys:
      * PATH, HOME, LANG/LC_* — POSIX basics
      * TMPDIR/TEMP/TMP — scratch space
      * PYTHONPATH/PYTHONHOME/PYTHONIOENCODING — Python interp
      * XDG_*, FONTCONFIG_*, PANGO_*, CAIRO_* — render cache dirs
      * SYSTEMROOT, WINDIR, USERPROFILE, APPDATA, LOCALAPPDATA —
        Windows DLL search path
    """
    _ALLOWED_ENV_KEYS = (
        "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE",
        "TMPDIR", "TEMP", "TMP",
        "PYTHONPATH", "PYTHONHOME", "PYTHONIOENCODING",
        "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME",
        "SYSTEMROOT", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        "FONTCONFIG_FILE", "FONTCONFIG_PATH",
    )
    import os as _os
    return {
        k: v for k, v in _os.environ.items()
        if k in _ALLOWED_ENV_KEYS
        or k.startswith("PANGO_")
        or k.startswith("CAIRO_")
    }


def _patch_pdf_links_subprocess(
    pdf_path: Path, *, timeout_sec: float = 60.0,
) -> None:
    """Invoke worker._pdf_links.patch_pdf_links in a subprocess so a
    hang (pypdf is pure-Python and GIL-bound — a slow text-extraction
    walk on a large PDF starves the parent worker's heartbeat thread,
    leading to a stale-reap reap and a failed-state investigation).

    Subprocess isolation means a hang kills only the patcher
    subprocess after the timeout; the parent worker keeps
    heartbeating and proceeds to the next PDF.

    Uses Popen + poll() loop rather than subprocess.run(timeout=) so
    the parent thread returns to the GIL every 1s during the wait.
    On CPU-throttled containers (Railway free tier under contention),
    a 30s patcher run inside subprocess.run blocks the heartbeat
    thread from getting CPU; the reaper then kills the investigation
    even though the subprocess itself is making progress. The poll
    loop costs ~0 (a single os.read or wait check per second) and
    keeps the parent's heartbeat thread alive.

    Best-effort: a non-zero exit / timeout / import failure logs a
    warning. The WeasyPrint-native PDF is shipped unchanged.

    Subprocess stderr is written to a tempfile (not PIPE) — pypdf
    can emit substantial warning output on PDFs with deprecated
    features, and the default 64KB pipe buffer can deadlock when
    we'd otherwise read it only after subprocess completion.
    """
    import subprocess
    import sys
    import tempfile
    import time
    # Pass html_path explicitly so the patcher can build its
    # address→href map. The html lives at the same stem with
    # ``.html`` extension — building_package writes both side
    # by side.
    html_path = pdf_path.with_suffix(".html")
    script = (
        "import sys; "
        "from pathlib import Path; "
        "from recupero.worker._pdf_links import patch_pdf_links; "
        "n = patch_pdf_links(Path(sys.argv[1]), Path(sys.argv[2])); "
        "print(f'patched {n}')"
    )

    # SIM115 doesn't apply here: we MUST hold the file open past the
    # `with`-block boundary so subprocess can write to it from another
    # process, then we read it back after .wait(). `delete=False` is
    # required so the path persists across the close in the OS-level
    # cleanup below.
    stderr_file = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w+b", delete=False, prefix="recupero-patcher-stderr-",
    )
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", script, str(pdf_path), str(html_path)],
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            # v0.17.7: same env-strip rationale as
            # _render_pdf_in_subprocess. The pypdf patcher reads no
            # secrets either, so we hand it the minimal env.
            env=_subprocess_safe_env(),
        )
        deadline = time.monotonic() + timeout_sec
        # Poll loop — yields CPU back to other threads (heartbeat)
        # every second instead of blocking on a single .wait() call.
        while True:
            ret = proc.poll()
            if ret is not None:
                break
            if time.monotonic() >= deadline:
                proc.kill()
                proc.wait(timeout=5)
                raise RuntimeError(
                    f"pypdf patcher timed out after {timeout_sec}s "
                    f"on {pdf_path.name}"
                )
            time.sleep(1.0)

        out_msg = b""
        if proc.stdout is not None:
            try:
                out_msg = proc.stdout.read() or b""
            finally:
                proc.stdout.close()

        stderr_file.flush()
        stderr_file.seek(0)
        err_bytes = stderr_file.read()

        out_decoded = out_msg.decode("utf-8", errors="replace").strip()
        err_decoded = err_bytes.decode("utf-8", errors="replace").strip()
        if out_decoded:
            log.info("link patcher stdout on %s: %s",
                     pdf_path.name, out_decoded)
        if err_decoded:
            log.warning("link patcher stderr on %s: %s",
                        pdf_path.name, err_decoded[-500:])

        if ret != 0:
            raise RuntimeError(
                f"pypdf patcher exit={ret} on {pdf_path.name}; "
                f"see prior stderr log line"
            )
    finally:
        stderr_file.close()
        try:
            Path(stderr_file.name).unlink()
        except OSError:
            pass


def _render_pdf_in_subprocess(
    *, script: str, args: list[str], label: str,
    timeout_sec: float = 120.0,
) -> None:
    """Invoke a one-shot Python subprocess that runs ``script`` with
    ``args``. Isolates WeasyPrint memory + GC churn from the parent
    worker process so a render-time OOM doesn't take down the cron.

    Uses Popen + poll loop (not subprocess.run(timeout=)) so the
    parent thread yields CPU to the heartbeat thread every second.
    On CPU-throttled containers a 30s WeasyPrint render inside
    subprocess.run blocks the heartbeat thread from getting CPU;
    the reaper then kills the row. The poll loop is the standard
    fix.

    Stderr lands in a tempfile so a large WeasyPrint warning dump
    can't deadlock on the default 64KB pipe buffer.

    Surfaces non-zero exit + timeout + stderr tail as a RuntimeError
    so the caller's try/except can log them. Stdout is captured but
    ignored (WeasyPrint normally writes nothing useful to stdout).
    """
    import subprocess
    import sys
    import tempfile
    import time
    cmd = [sys.executable, "-c", script, *args]

    # SIM115 doesn't apply: same rationale as the patcher above — the
    # subprocess writes to this file from another process; we need the
    # path to persist across .close() and be readable after .wait().
    stderr_file = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w+b", delete=False, prefix="recupero-render-stderr-",
    )
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=stderr_file,
            env=_subprocess_safe_env(),
        )
        deadline = time.monotonic() + timeout_sec
        while True:
            ret = proc.poll()
            if ret is not None:
                break
            if time.monotonic() >= deadline:
                proc.kill()
                proc.wait(timeout=5)
                raise RuntimeError(
                    f"weasyprint subprocess timed out after {timeout_sec}s "
                    f"on {label}"
                )
            time.sleep(1.0)

        if proc.stdout is not None:
            try:
                proc.stdout.read()
            finally:
                proc.stdout.close()

        if ret != 0:
            stderr_file.flush()
            stderr_file.seek(0)
            tail = stderr_file.read()[-500:].decode("utf-8", errors="replace")
            raise RuntimeError(
                f"weasyprint subprocess exit={ret} on {label}: ...{tail}"
            )
    finally:
        stderr_file.close()
        try:
            Path(stderr_file.name).unlink()
        except OSError:
            pass


def _has_freezable_holding(freezable_entry: dict[str, Any]) -> bool:
    """True iff the entry has at least one confirmed-FREEZABLE holding.

    v0.27.2 (Jacob 0x52Aa bleed fix, item 1 / proposal b): the previous
    name + semantic (``_has_actionable_holding``: any non-UNRECOVERABLE)
    let issuers through whose entire freeze ask was INVESTIGATE-only
    bleed from a smart contract reflecting protocol liquidity. The
    resulting letters had ``$0`` confirmed FREEZABLE totals and shipped
    the contradiction "the 0 FREEZABLE addresses ($0 total) are the
    primary targets" — a credibility-killer Jacob caught on v0.27.1.

    The correct semantic: only emit a freeze letter when at least one
    address is CONFIRMED holding the issuer's token AND eligible for
    freeze action. INVESTIGATE-tagged addresses are leads, not asks;
    UNRECOVERABLE-tagged addresses have no freeze pathway by definition.
    The letter we send to an issuer must be backed by at least one row
    we are asking them to act on.
    """
    holdings = freezable_entry.get("holdings") or []
    # Adversarial-input audit: holdings may arrive non-list (dict) or
    # contain non-dict elements (string slipped in by a buggy writer).
    # Defensively coerce / skip rather than letting `.get` crash and
    # kill the entire stage.
    if not isinstance(holdings, list):
        return False
    for h in holdings:
        if not isinstance(h, dict):
            continue
        if (h.get("status") or "").upper() == "FREEZABLE":
            return True
    return False


# Back-compat alias — there are existing imports / tests that reference
# the old name. New code should call _has_freezable_holding directly.
# Remove this alias in a follow-up once we've verified no in-tree
# callers + any external scripts have caught up.
_has_actionable_holding = _has_freezable_holding


def _issuer_info_for(name: str, freezable_entry: dict[str, Any]) -> IssuerInfo:
    """Best-effort IssuerInfo for any issuer.

    Uses MIDAS_ISSUER as the source for hardcoded specifics (Midas/Maple
    case is fully filled out). For other issuers, synthesizes from
    freeze_brief data + sensible defaults — the resulting brief renders
    cleanly because the j2 templates are defensively wrapped in
    ``{% if issuer.X %}`` blocks for the optional fields.
    """
    if name == MIDAS_ISSUER.name:
        return MIDAS_ISSUER

    # Short-name slug used for the output filename.
    # Adversarial-input audit: brief.py also sanitizes the slug, but we
    # belt-and-brace here so the IssuerInfo dataclass never carries a
    # short_name with path separators or parent-dir tokens. Defense in
    # depth against a future call site that doesn't run the brief.py
    # sanitization pass.
    short_name = name.split(" ")[0].split("/")[0].split("\\")[0].lower()
    short_name = short_name.replace("..", "_").strip("._-")
    if not short_name:
        short_name = "issuer"

    # freeze_brief.json's contact key is literally "contact_email" (see
    # the v0.2.0 schema in freeze_brief.json — earlier code looked up
    # "primary_contact" and always got the empty fallback, which is why
    # rendered LE handoffs read "Issue a preservation request to Circle ()"
    # with empty parens. Fix: use the right key.
    return IssuerInfo(
        name=name,
        short_name=short_name.title(),
        contact_email=(
            freezable_entry.get("contact_email")
            or freezable_entry.get("primary_contact")
            or ""
        ),
        jurisdiction=None,  # not in freeze_brief; template handles None
        regulatory_framework=None,
        secondary_party=None,
        secondary_role=None,
        asset_description=None,
        kyc_required=False,
        kyc_minimum=None,
    )
