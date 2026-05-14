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

If the trace produced no transfers (empty case), no deliverables are
written — the building_package stage no-ops gracefully.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from recupero.models import Case
from recupero.reports.brief import (
    InvestigatorInfo,
    IssuerInfo,
    MIDAS_ISSUER,  # used as the canonical fully-filled IssuerInfo when name matches
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
) -> list[Path]:
    """Generate one freeze-request HTML per unique issuer in FREEZABLE,
    plus one LE handoff. Returns the list of paths written.

    Skip conditions (return empty list, log, no error):

      * The case has no transfers — nothing to seize.
      * FREEZABLE is empty — no labeled-issuer holding to address.
        This is the right outcome for cases that route entirely to
        exchange deposits / mixers / unlabeled wallets: those paths
        need different deliverables (exchange subpoena, mixer report)
        that the worker doesn't generate today, and producing a
        canned letter to a random issuer (e.g. defaulting to Midas)
        would be misleading. Operators see no briefs/ subdir → handle
        the case via the appropriate other path.

    The legacy ``recupero brief`` CLI command remains available for
    one-off overrides if an operator wants to manually generate a
    letter to a specific issuer that wasn't matched automatically.
    """
    if not case.transfers:
        log.info("no transfers in case; skipping deliverable generation")
        return []

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

    if not issuers_seen:
        log.info(
            "FREEZABLE list is empty (no labeled-issuer holdings matched). "
            "Skipping HTML deliverable generation — no canned letter applies. "
            "Operator should review freeze_asks.json's exchange_deposits and "
            "the case.json transfers for non-issuer recovery paths.",
        )
        return []

    investigator = investigator or _DEFAULT_INVESTIGATOR

    # Render the fund-flow SVG once into briefs/flow_<hash>.svg. The
    # SVG now ships in two ways:
    #
    #   1. As an inline block at the END of each HTML deliverable
    #      (Appendix A: Fund Flow Diagram). The compact TRM-style
    #      renderer produces a letter-landscape-shaped SVG sized to
    #      fit a single page, so inlining it no longer breaks PDF
    #      output the way the old 21:1-aspect-ratio version did.
    #
    #   2. As a standalone SVG file in the briefs/ directory, with a
    #      matching standalone PDF rendered by _emit_pdfs. Operators
    #      who want to share just the flow diagram (without the whole
    #      letter) use this artifact.
    #
    # Both letters and LE handoffs receive the inline SVG via
    # ``flow_inline_svg``; the templates render it as the final
    # appendix so the case narrative isn't interrupted mid-section.
    flow_filename: str | None = None
    flow_svg_path: Path | None = None
    flow_inline_svg: str | None = None
    try:
        from recupero.worker._flow_diagram import read_inline_svg, render_flow_diagram
        from uuid import uuid4
        briefs_dir = case_dir / "briefs"
        briefs_dir.mkdir(parents=True, exist_ok=True)
        candidate_path = briefs_dir / f"flow_{uuid4().hex[:8]}.svg"
        # Pass freeze_brief so wallets in the FREEZABLE list (which
        # the trace may not have labeled at counterparty time) get
        # promoted to "Circle holding (USDC)" / "Tether holding
        # (USDT)" / etc. labeled circles in the diagram. Otherwise
        # those wallets render as anonymous rounded-rect nodes even
        # though the letter is asking the issuer to freeze them —
        # the diagram visually surfaces exactly what's being requested.
        if render_flow_diagram(
            case, candidate_path, freeze_brief=freeze_brief,
        ) is not None:
            flow_filename = candidate_path.name
            flow_svg_path = candidate_path
            flow_inline_svg = read_inline_svg(candidate_path)
            if flow_inline_svg is None:
                log.warning("flow SVG inline-read returned None; appendix will be skipped")
    except Exception as e:  # noqa: BLE001
        log.warning("flow diagram generation failed (continuing without it): %s", e)

    written: list[Path] = []
    html_paths: list[Path] = []  # HTMLs we should also produce PDFs for
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
                flow_inline_svg=flow_inline_svg,
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

    log.info("deliverables done: %d file(s) under %s/briefs/",
             len(written), case_dir.name)
    return written


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
    from weasyprint import HTML
    HTML(filename=str(html_path)).write_pdf(str(pdf_path))


def _svg_to_pdf(svg_path: Path, pdf_path: Path) -> None:
    """Render a standalone SVG to PDF by wrapping it in minimal HTML.

    WeasyPrint doesn't render SVG files directly; it renders HTML
    documents. Wrapping the SVG payload in a no-margin HTML shell lets
    us emit a single-page PDF whose page size auto-fits the SVG's
    intrinsic dimensions and preserves all ``href`` link annotations.
    """
    from weasyprint import HTML
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
    HTML(string=html_shell, base_url=str(svg_path.parent)).write_pdf(str(pdf_path))


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

    return IssuerInfo(
        name=name,
        short_name=short_name.title(),
        contact_email=freezable_entry.get("primary_contact") or "",
        jurisdiction=None,  # not in freeze_brief; template handles None
        regulatory_framework=None,
        secondary_party=None,
        secondary_role=None,
        asset_description=None,
        kyc_required=False,
        kyc_minimum=None,
    )
