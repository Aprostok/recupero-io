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
# doesn't have an investigator column today). Operators can edit the
# generated HTML before sending if specifics need to change.
_DEFAULT_INVESTIGATOR = InvestigatorInfo(
    name="Recupero Investigation Team",
    organization="Recupero",
    email="contact@recupero.io",
    phone=None,
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

    # Render the fund-flow SVG once. All issuer briefs + the LE handoff(s)
    # embed the same diagram inline. We also write a standalone .svg in
    # briefs/ so operators can pull the diagram into separate decks/PDFs.
    flow_svg_inline = ""
    try:
        from recupero.worker._flow_diagram import render_flow_diagram
        from uuid import uuid4
        briefs_dir = case_dir / "briefs"
        briefs_dir.mkdir(parents=True, exist_ok=True)
        flow_svg_path = briefs_dir / f"flow_{uuid4().hex[:8]}.svg"
        if render_flow_diagram(case, flow_svg_path) is not None:
            flow_svg_inline = _strip_svg_preamble(
                flow_svg_path.read_text(encoding="utf-8")
            )
    except Exception as e:  # noqa: BLE001
        log.warning("flow diagram generation failed (continuing without it): %s", e)

    written: list[Path] = []
    for issuer_name, issuer_info in issuers_seen.items():
        try:
            bundle = generate_briefs(
                primary_case=case,
                linked_cases=[],
                victim=victim,
                investigator=investigator,
                case_dir=case_dir,
                issuer=issuer_info,
                flow_svg=flow_svg_inline or None,
            )
            written.append(bundle.maple_path)
            written.append(bundle.le_path)
            written.append(bundle.manifest_path)
            log.info(
                "wrote freeze brief for issuer=%s file=%s",
                issuer_name, bundle.maple_path.name,
            )
        except Exception as e:  # noqa: BLE001
            # One issuer's brief failing shouldn't kill the whole stage —
            # log and continue so other issuers still get briefs.
            log.warning("brief generation failed for issuer=%s: %s",
                        issuer_name, e)

    log.info("deliverables done: %d file(s) under %s/briefs/",
             len(written), case_dir.name)
    return written


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


def _strip_svg_preamble(svg_text: str) -> str:
    """Remove ``<?xml ...?>`` and ``<!DOCTYPE ...>`` lines so the SVG
    can be embedded inline in HTML without confusing the HTML parser.
    Keeps everything from ``<svg`` onward."""
    idx = svg_text.find("<svg")
    if idx == -1:
        return svg_text
    return svg_text[idx:]


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
