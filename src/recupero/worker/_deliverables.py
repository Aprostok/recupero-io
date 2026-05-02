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
    MIDAS_ISSUER,
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

    Skips deliverable generation entirely if the case has no transfers
    (nothing to seize) — returns an empty list, no error.
    """
    if not case.transfers:
        log.info("no transfers in case; skipping deliverable generation")
        return []

    investigator = investigator or _DEFAULT_INVESTIGATOR
    freezable = freeze_brief.get("FREEZABLE") or []

    # Build the set of unique issuers from FREEZABLE. Each issuer becomes one
    # freeze-request brief addressed to that entity.
    issuers_seen: dict[str, IssuerInfo] = {}
    for entry in freezable:
        issuer_name = entry.get("issuer")
        if not issuer_name or issuer_name in issuers_seen:
            continue
        issuers_seen[issuer_name] = _issuer_info_for(issuer_name, entry)

    # Always produce at least one brief — if FREEZABLE is empty (no labeled
    # tokens matched), default to the Midas issuer so the operator gets an
    # editable template they can re-address rather than a blank case dir.
    if not issuers_seen:
        log.info(
            "FREEZABLE list is empty; emitting one Midas-default brief as a "
            "starting template the operator can re-address",
        )
        issuers_seen["Midas Software GmbH"] = MIDAS_ISSUER

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
