"""Statute-of-limitations reference — citable info, never fabricated.

A victim of crypto theft is racing two clocks: the *practical* clock (funds can
be withdrawn from an exchange within minutes) and the *legal* clock (criminal
and civil limitation periods bar prosecution / suit once they run). Counsel
owns the legal clock — but a tracer that says nothing about it leaves victims
blind to a deadline that can extinguish recovery entirely.

This module resolves limitation-period references for a jurisdiction by merging
two layers, exactly like ``freeze/exchange_contacts.py``:

1. **Operator/counsel override** — ``labels/seeds/statute_limitations.json``.
   A firm fills this in with the *controlling* periods for the jurisdictions it
   works, each with a real citation, and flips ``verified`` to true. This layer
   wins.
2. **Seeded baseline** — a SMALL set of periods Recupero can cite accurately
   today (US federal criminal limitations). Each carries its real U.S.C.
   citation.

Safety rails (the legal-track equivalent of "never fabricate an address"):
  * Every reference MUST carry a non-empty ``citation``. The override loader
    drops any entry without one and logs a warning — a period with no citation
    is never shipped.
  * ``verified`` means "Recupero/counsel confirmed this citation against the
    statute," NOT "this period applies to your case." Whether a given period
    governs a specific matter (which offense, tolling, the discovery rule) is
    always counsel's call — the rendered advisory says so prominently.
  * An unknown jurisdiction resolves to an explicit "confirm with counsel"
    posture (no seeded entries), never an invented period.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_OVERRIDES_PATH = (
    Path(__file__).parent.parent / "labels" / "seeds" / "statute_limitations.json"
)

_VALID_CLAIM_KINDS = frozenset({"criminal", "civil"})


@dataclass(frozen=True)
class LimitationReference:
    """A single limitation-period reference.

    ``verified`` gates trust: an unverified reference is a starting point for
    counsel to confirm, not an authoritative period. ``illustrative`` flags an
    entry that is a *jurisdiction example* (e.g. one US state) rather than the
    controlling period for the victim's actual jurisdiction — the renderer must
    surface it as such so it is never mistaken for the governing deadline.
    """

    jurisdiction: str          # canonical key, e.g. "US", "UK", "EU"
    claim_kind: str            # "criminal" | "civil"
    label: str                 # human display, e.g. "Federal wire fraud (general)"
    period: str                # human display, e.g. "5 years"
    citation: str              # REQUIRED real statutory citation (never empty)
    accrual: str | None        # when the clock starts / discovery-rule note
    note: str | None           # applicability caveats
    verified: bool             # citation confirmed against the statute
    illustrative: bool         # a jurisdiction *example*, not the controlling period
    source: str | None


def normalize_jurisdiction(value: str | None) -> str | None:
    """Map a free-form jurisdiction string (as it appears in a brief or the
    recovery scorer's table) to a canonical key. Returns ``None`` when the
    input is empty or unrecognized (caller then uses the confirm-with-counsel
    posture)."""
    if not value or not str(value).strip():
        return None
    v = str(value).strip().lower()
    aliases = {
        "us": "US", "usa": "US", "u.s.": "US", "u.s.a.": "US",
        "united states": "US", "united states of america": "US",
        "uk": "UK", "u.k.": "UK", "united kingdom": "UK",
        "great britain": "UK", "england": "UK",
        "eu": "EU", "european union": "EU",
        "canada": "CA", "ca": "CA",
        "australia": "AU", "au": "AU",
        "singapore": "SG", "sg": "SG",
    }
    return aliases.get(v)


# --- Seeded baseline -------------------------------------------------------
#
# Only periods we can cite accurately are seeded here. Each is a statement of
# what the cited statute provides; whether it governs a particular matter is
# counsel's call (the advisory says so). Sources are the public-law citations
# themselves — these are verifiable against the U.S. Code.
_SEED: tuple[LimitationReference, ...] = (
    LimitationReference(
        jurisdiction="US",
        claim_kind="criminal",
        label="Federal criminal offenses (general)",
        period="5 years",
        citation="18 U.S.C. § 3282(a)",
        accrual="Runs from commission of the offense (subject to statutory tolling).",
        note=(
            "The general federal criminal limitation period for non-capital "
            "offenses unless another statute provides otherwise. Which offense "
            "and which period actually govern is for prosecutors / counsel."
        ),
        verified=True,
        illustrative=False,
        source="18 U.S.C. § 3282(a)",
    ),
    LimitationReference(
        jurisdiction="US",
        claim_kind="criminal",
        label="Mail/wire fraud affecting a financial institution",
        period="10 years",
        citation="18 U.S.C. § 3293(2)",
        accrual="Runs from commission of the offense.",
        note=(
            "Extends the limitation period to 10 years for 18 U.S.C. § 1341 / "
            "§ 1343 violations that affect a financial institution. Whether the "
            "offense 'affects a financial institution' is a legal determination."
        ),
        verified=True,
        illustrative=False,
        source="18 U.S.C. § 3293",
    ),
    LimitationReference(
        jurisdiction="US",
        claim_kind="civil",
        label="Conversion — New York (example only)",
        period="3 years",
        citation="N.Y. C.P.L.R. § 214(3)",
        accrual="Generally accrues at the time of the conversion.",
        note=(
            "ILLUSTRATIVE — New York. Civil limitation periods for conversion / "
            "fraud vary by U.S. state and cause of action; this is shown only to "
            "convey that a civil clock also runs. Confirm the controlling state's "
            "period and accrual/discovery rule with counsel."
        ),
        verified=True,
        illustrative=True,
        source="N.Y. C.P.L.R. § 214(3)",
    ),
    LimitationReference(
        jurisdiction="US",
        claim_kind="civil",
        label="Fraud — New York (example only)",
        period="6 years, or 2 years from discovery if later",
        citation="N.Y. C.P.L.R. § 213(8); § 203(g)",
        accrual="Greater of 6 years from the fraud or 2 years from discovery.",
        note=(
            "ILLUSTRATIVE — New York. Shown only to convey that fraud claims "
            "carry their own (often discovery-based) clock. The controlling "
            "period depends on the victim's jurisdiction — confirm with counsel."
        ),
        verified=True,
        illustrative=True,
        source="N.Y. C.P.L.R. § 213(8), § 203(g)",
    ),
)


def _norm_kind(value: object) -> str | None:
    k = str(value or "").strip().lower()
    return k if k in _VALID_CLAIM_KINDS else None


def load_limitation_overrides(
    path: Path | None = None,
) -> dict[str, list[LimitationReference]]:
    """Load the operator/counsel override file, keyed by canonical jurisdiction.

    Underscore-prefixed keys (``_README`` / ``_schema`` / ``_example``) are
    documentation and skipped. Returns ``{}`` if the file is missing or
    unparseable (never raises). An entry is dropped (with a warning) if it lacks
    a real ``citation`` or a valid ``claim_kind`` — a period with no citation is
    never surfaced. ``verified`` is coerced to ``False`` unless the entry also
    carries a ``source``.
    """
    p = path or _OVERRIDES_PATH
    try:
        raw = json.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        log.warning("statute_limitations: could not read %s: %s", p, exc)
        return {}
    if not isinstance(raw, dict):
        return {}

    out: dict[str, list[LimitationReference]] = {}
    for key, entries in raw.items():
        if key.startswith("_"):
            continue
        canon = normalize_jurisdiction(key) or str(key).strip().upper()
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            citation = str(entry.get("citation") or "").strip()
            kind = _norm_kind(entry.get("claim_kind"))
            if not citation or kind is None:
                log.warning(
                    "statute_limitations: dropping %s entry without a real "
                    "citation and/or valid claim_kind: %r",
                    canon, entry.get("label") or entry,
                )
                continue
            period = str(entry.get("period") or "").strip()
            if not period:
                log.warning(
                    "statute_limitations: dropping %s entry %r without a period.",
                    canon, citation,
                )
                continue
            source = entry.get("source") or None
            verified = bool(entry.get("verified"))
            if verified and not source:
                log.warning(
                    "statute_limitations: %s entry %r marked verified but lacks "
                    "a source — downgrading to unverified.",
                    canon, citation,
                )
                verified = False
            out.setdefault(canon, []).append(
                LimitationReference(
                    jurisdiction=canon,
                    claim_kind=kind,
                    label=str(entry.get("label") or citation),
                    period=period,
                    citation=citation,
                    accrual=entry.get("accrual") or None,
                    note=entry.get("note") or None,
                    verified=verified,
                    illustrative=bool(entry.get("illustrative")),
                    source=source,
                )
            )
    return out


def resolve_limitations(
    jurisdiction: str | None,
    *,
    overrides: dict[str, list[LimitationReference]] | None = None,
) -> list[LimitationReference]:
    """Resolve limitation references for a jurisdiction.

    Override entries for the jurisdiction are returned FIRST (a firm's
    confirmed, controlling periods), followed by any seeded baseline entries
    for the same jurisdiction that the overrides did not already cover (matched
    by citation, so a firm's confirmed period supersedes the seed). Returns
    ``[]`` for an unknown jurisdiction — the caller then renders the explicit
    "confirm with counsel" posture rather than guessing.
    """
    canon = normalize_jurisdiction(jurisdiction)
    if canon is None:
        return []
    ov = overrides if overrides is not None else load_limitation_overrides()
    result: list[LimitationReference] = list(ov.get(canon, []))
    seen_citations = {r.citation.strip().lower() for r in result}
    for ref in _SEED:
        if ref.jurisdiction == canon and ref.citation.strip().lower() not in seen_citations:
            result.append(ref)
    return result


__all__ = (
    "LimitationReference",
    "load_limitation_overrides",
    "normalize_jurisdiction",
    "resolve_limitations",
)
