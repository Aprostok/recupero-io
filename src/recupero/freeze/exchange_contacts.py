"""Exchange FREEZE-contact resolution (freeze-track P0 foundation).

Major centralized exchanges freeze deposits on a documented theft trail within
hours — but historically the pipeline only produced a *subpoena* (KYC records
request), never a time-critical *freeze* request, and there was no
freeze-specific contact data: no LE-portal URL, no freeze-capability flag, no
"have we actually verified this channel" marker. ``reports/legal_requests.py``
carries an ``_EXCHANGE_COMPLIANCE_CONTACTS`` dict, but those are unverified
pattern-style ``compliance@<exchange>`` guesses.

This module resolves an :class:`ExchangeFreezeContact` for an exchange name by
merging two layers:

1. **Verified override** — ``labels/seeds/exchange_freeze_contacts.json``, a
   user-maintained file. An operator fills it in as they CONFIRM each exchange's
   law-enforcement freeze channel and flips ``verified`` to true. This layer
   wins.
2. **Unverified base** — the existing ``_EXCHANGE_COMPLIANCE_CONTACTS`` starter
   emails, surfaced as ``verified=False`` so the operator sees a starting point
   but the rendered letter can flag it UNVERIFIED — confirm before sending.

Safety: we NEVER fabricate a contact. An override entry is honored as
``verified`` only when it carries a real channel (email or portal) AND a source;
otherwise the loader downgrades it to unverified and logs a warning (so a typo
in the seed file degrades safely instead of shipping a false "verified" claim).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_OVERRIDES_PATH = (
    Path(__file__).parent.parent / "labels" / "seeds" / "exchange_freeze_contacts.json"
)

_VALID_CAPABILITIES = frozenset({"yes", "limited", "no", "unknown"})
_VALID_CHANNELS = frozenset({"portal", "email", "both"})


@dataclass(frozen=True)
class ExchangeFreezeContact:
    """A resolved exchange freeze contact. ``verified`` is the trust gate:
    a renderer MUST surface an unverified contact as "confirm channel before
    sending" rather than presenting it as authoritative."""

    name: str
    legal_name: str
    compliance_email: str | None
    le_portal_url: str | None
    freeze_capability: str  # yes | limited | no | unknown
    freeze_request_channel: str | None  # portal | email | both | None
    verified: bool
    source: str | None
    notes: str | None

    @property
    def has_channel(self) -> bool:
        """True if there is at least one contact channel to act on."""
        return bool(self.compliance_email or self.le_portal_url)


def _norm(name: str) -> str:
    return (name or "").strip().lower().replace(" ", "")


def load_exchange_freeze_overrides(
    path: Path | None = None,
) -> dict[str, dict[str, object]]:
    """Load the user-maintained override file, keyed by normalized name.

    Underscore-prefixed keys (``_README`` / ``_schema`` / ``_example``) are
    documentation and are skipped. Returns ``{}`` if the file is missing or
    unparseable (never raises — a broken seed file must not break the pipeline).

    Each surviving entry is sanitized: ``verified`` is coerced to ``False``
    unless the entry has a real channel AND a source. ``freeze_capability`` is
    coerced to ``"unknown"`` if not one of the valid values.
    """
    p = path or _OVERRIDES_PATH
    try:
        raw = json.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        log.warning("exchange_freeze_contacts: could not read %s: %s", p, exc)
        return {}
    if not isinstance(raw, dict):
        return {}

    out: dict[str, dict[str, object]] = {}
    for key, entry in raw.items():
        if key.startswith("_") or not isinstance(entry, dict):
            continue
        email = entry.get("compliance_email") or None
        portal = entry.get("le_portal_url") or None
        source = entry.get("source") or None
        cap = entry.get("freeze_capability") or "unknown"
        if cap not in _VALID_CAPABILITIES:
            cap = "unknown"
        channel = entry.get("freeze_request_channel") or None
        if channel is not None and channel not in _VALID_CHANNELS:
            channel = None
        verified = bool(entry.get("verified"))
        # Trust gate: a "verified" claim requires a real channel + a source.
        if verified and not ((email or portal) and source):
            log.warning(
                "exchange_freeze_contacts: entry %r marked verified=true but "
                "lacks a channel and/or source — downgrading to unverified.",
                key,
            )
            verified = False
        out[_norm(key)] = {
            "name": str(key),
            "legal_name": str(entry.get("legal_name") or key),
            "compliance_email": email,
            "le_portal_url": portal,
            "freeze_capability": cap,
            "freeze_request_channel": channel,
            "verified": verified,
            "source": source,
            "notes": entry.get("notes") or None,
        }
    return out


def _base_contacts() -> dict[str, dict[str, str]]:
    """The unverified starter contacts. Lazy import to avoid any import cycle
    with the reports layer and to keep this module dependency-light."""
    try:
        from recupero.reports.legal_requests import _EXCHANGE_COMPLIANCE_CONTACTS
    except Exception as exc:  # noqa: BLE001
        log.debug("exchange_freeze_contacts: base contacts unavailable: %s", exc)
        return {}
    return _EXCHANGE_COMPLIANCE_CONTACTS


def resolve_exchange_freeze_contact(
    name: str,
    *,
    overrides: dict[str, dict[str, object]] | None = None,
) -> ExchangeFreezeContact | None:
    """Resolve a freeze contact for ``name`` (case/space-insensitive).

    Returns the VERIFIED override if present; else an UNVERIFIED contact built
    from the starter email; else ``None`` for an unknown exchange. The caller
    (letter renderer) MUST honor ``.verified`` — unverified contacts are a
    starting point to confirm, not an authoritative channel.
    """
    if not name or not name.strip():
        return None
    key = _norm(name)
    ov = overrides if overrides is not None else load_exchange_freeze_overrides()
    if key in ov:
        e = ov[key]
        return ExchangeFreezeContact(
            name=str(e["name"]),
            legal_name=str(e["legal_name"]),
            compliance_email=e["compliance_email"],  # type: ignore[arg-type]
            le_portal_url=e["le_portal_url"],  # type: ignore[arg-type]
            freeze_capability=str(e["freeze_capability"]),
            freeze_request_channel=e["freeze_request_channel"],  # type: ignore[arg-type]
            verified=bool(e["verified"]),
            source=e["source"],  # type: ignore[arg-type]
            notes=e["notes"],  # type: ignore[arg-type]
        )
    # Fall back to the unverified starter contacts.
    for known_name, meta in _base_contacts().items():
        if _norm(known_name) == key:
            return ExchangeFreezeContact(
                name=known_name,
                legal_name=meta.get("legal_name", known_name),
                compliance_email=meta.get("compliance_email") or None,
                le_portal_url=None,
                freeze_capability="unknown",
                freeze_request_channel="email" if meta.get("compliance_email") else None,
                verified=False,
                source=None,
                notes="Starter contact (unverified pattern email) — confirm the "
                "exchange's law-enforcement freeze channel before sending.",
            )
    return None


__all__ = (
    "ExchangeFreezeContact",
    "load_exchange_freeze_overrides",
    "resolve_exchange_freeze_contact",
)
