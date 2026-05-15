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
        from recupero.worker._flow_diagram import render_flow_diagram
        from uuid import uuid4
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

    if skip_freeze_briefs:
        log.info(
            "skip_freeze_briefs=true — emitting only trace_report; "
            "customer-facing freeze letters + LE handoffs not generated",
        )
    else:
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

    Best-effort: a non-zero exit / timeout / import failure logs a
    warning. The WeasyPrint-native PDF is shipped unchanged.
    """
    import subprocess
    import sys
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
    try:
        result = subprocess.run(
            [sys.executable, "-c", script, str(pdf_path), str(html_path)],
            capture_output=True, timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"pypdf patcher timed out after {timeout_sec}s on {pdf_path.name}"
        ) from exc

    # Surface subprocess output for visibility regardless of exit
    # status — silent subprocess crashes are otherwise invisible
    # in Railway logs and a recurring root-cause for "patcher did
    # nothing" symptoms.
    out_msg = (result.stdout or b"").decode("utf-8", errors="replace").strip()
    err_msg = (result.stderr or b"").decode("utf-8", errors="replace").strip()
    if out_msg:
        log.info("link patcher stdout on %s: %s", pdf_path.name, out_msg)
    if err_msg:
        log.warning("link patcher stderr on %s: %s",
                    pdf_path.name, err_msg[-500:])

    if result.returncode != 0:
        raise RuntimeError(
            f"pypdf patcher exit={result.returncode} on {pdf_path.name}; "
            f"see prior stderr log line"
        )


def _render_pdf_in_subprocess(
    *, script: str, args: list[str], label: str,
    timeout_sec: float = 120.0,
) -> None:
    """Invoke a one-shot Python subprocess that runs ``script`` with
    ``args``. Isolates WeasyPrint memory + GC churn from the parent
    worker process so a render-time OOM doesn't take down the cron.

    Surfaces non-zero exit + timeout + stderr tail as a RuntimeError
    so the caller's try/except can log them. Stdout is captured but
    ignored (WeasyPrint normally writes nothing useful to stdout).
    """
    import subprocess
    import sys
    cmd = [sys.executable, "-c", script, *args]
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"weasyprint subprocess timed out after {timeout_sec}s "
            f"on {label}"
        ) from exc
    if result.returncode != 0:
        tail = (result.stderr or b"").decode("utf-8", errors="replace")[-500:]
        raise RuntimeError(
            f"weasyprint subprocess exit={result.returncode} on {label}: "
            f"...{tail}"
        )


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
