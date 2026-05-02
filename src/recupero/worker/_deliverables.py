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
    issuers_seen: dict[str, IssuerInfo] = {}
    for entry in freezable:
        issuer_name = entry.get("issuer")
        if not issuer_name or issuer_name in issuers_seen:
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
