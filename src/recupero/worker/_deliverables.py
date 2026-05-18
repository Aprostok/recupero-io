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


# Default investigator info when the cases row doesn't carry it (the schema
# doesn't have an investigator column today). Each Railway deployment can
# override via RECUPERO_INVESTIGATOR_* env vars; the fallback values
# match the solo-operator setup. When the cases table eventually carries
# a per-case investigator field, those values will flow through and these
# only apply for legacy rows.
_DEFAULT_INVESTIGATOR = InvestigatorInfo(
    name=os.environ.get("RECUPERO_INVESTIGATOR_NAME", "Alec Prostok"),
    organization=os.environ.get("RECUPERO_INVESTIGATOR_ENTITY", "Recupero LLC"),
    email=os.environ.get("RECUPERO_INVESTIGATOR_EMAIL", "alec@recupero.io"),
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
    # freeze-request brief addressed to that entity. The LE handoff template
    # is tailored to one issuer at a time too (le.html.j2 references issuer
    # heavily), so when there are multiple matches, the last iteration's
    # le_handoff_*.html overwrites earlier ones with that issuer's framing.
    # That's a known minor quirk of generate_briefs; multi-issuer LE
    # production is a follow-up.
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
        issuer_name = entry.get("issuer")
        if not issuer_name or issuer_name in issuers_seen:
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

    investigator = investigator or _DEFAULT_INVESTIGATOR

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
        from uuid import uuid4

        from recupero.worker._flow_diagram import render_flow_diagram
        briefs_dir = case_dir / "briefs"
        briefs_dir.mkdir(parents=True, exist_ok=True)
        candidate_path = briefs_dir / f"flow_{uuid4().hex[:8]}.svg"
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
        try:
            from recupero.worker._victim_summary import (
                classify_recovery_prospects,
                render_victim_summary,
            )
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
            # Capture the classification for the engagement-letter
            # decision below — same recoverability call should drive
            # both decisions for consistency.
            is_recoverable, total_freezable_usd, total_suspected_usd = (
                classify_recovery_prospects(freeze_brief)
            )
        except Exception as e:  # noqa: BLE001
            log.warning("victim summary generation failed (continuing): %s", e)

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

    # Find the rendered victim_summary HTML
    briefs_dir = case_dir / "briefs"
    summary_htmls = list(briefs_dir.glob("victim_summary_*.html"))
    if not summary_htmls:
        log.info(
            "auto-send skip: no victim_summary HTML found for inv=%s",
            investigation_id,
        )
        return
    summary_html_path = summary_htmls[0]

    # Build attachment list — customer-relevant PDFs only
    attachment_globs = [
        "trace_report_*.pdf",
        "flow_*.pdf",
        "victim_summary_*.pdf",
        "engagement_letter_*.pdf",
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
        result = send_email(
            to=victim.email,
            subject=subject,
            html=html_body,
            investigation_id=investigation_id,
            email_type="victim_summary",
            attachments=attachments,
            preview_text=preview,
        )
        if result.success:
            log.info(
                "auto-sent victim summary to=%s inv=%s message_id=%s "
                "(%d attachment(s))",
                victim.email, investigation_id, result.message_id,
                len(attachments),
            )
        elif result.skipped:
            log.info("auto-send skipped (RECUPERO_DISABLE_EMAIL=1): inv=%s",
                     investigation_id)
        else:
            log.warning("auto-send victim summary FAILED to=%s inv=%s err=%s",
                        victim.email, investigation_id, result.error)
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
        f'<a href="{url}" '
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
        f'<a href="{url}" '
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
    _render_pdf_in_subprocess(
        script=(
            "import sys; from weasyprint import HTML; "
            "HTML(filename=sys.argv[1]).write_pdf(sys.argv[2])"
        ),
        args=[str(html_path), str(pdf_path)],
        label=html_path.name,
    )


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
    try:
        _render_pdf_in_subprocess(
            script=(
                "import sys; from weasyprint import HTML; "
                "HTML(filename=sys.argv[1], base_url=sys.argv[3])"
                ".write_pdf(sys.argv[2])"
            ),
            args=[str(shell_path), str(pdf_path), str(svg_path.parent)],
            label=svg_path.name,
        )
    finally:
        try:
            shell_path.unlink()
        except OSError:
            pass


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

    stderr_file = tempfile.NamedTemporaryFile(
        mode="w+b", delete=False, prefix="recupero-patcher-stderr-",
    )
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", script, str(pdf_path), str(html_path)],
            stdout=subprocess.PIPE,
            stderr=stderr_file,
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

    stderr_file = tempfile.NamedTemporaryFile(
        mode="w+b", delete=False, prefix="recupero-render-stderr-",
    )
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=stderr_file,
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


def _has_actionable_holding(freezable_entry: dict[str, Any]) -> bool:
    """True if at least one holding in the entry is not UNRECOVERABLE.

    The freeze_brief writer (emit_brief.py) classifies each holding's
    ``status`` as ``RECOVERABLE`` (high-confidence freeze target),
    ``INVESTIGATE`` (worth asking about), or ``UNRECOVERABLE`` (technically
    held by issuer's token but not freezable — e.g. funds at a Lido
    staking contract). If every holding is UNRECOVERABLE we have no
    business sending the issuer a freeze letter.
    """
    holdings = freezable_entry.get("holdings") or []
    for h in holdings:
        if (h.get("status") or "").upper() != "UNRECOVERABLE":
            return True
    return False


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
    short_name = name.split(" ")[0].split("/")[0].lower()

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
