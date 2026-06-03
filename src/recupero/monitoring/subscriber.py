"""Auto-subscribe perp wallets when emit_brief produces a freeze_brief.

The pre-v0.21.0 workflow was: investigator runs the trace, generates
the brief, mails the freeze letters, then *separately* configures
monitoring subscriptions for the wallets they care about. In
practice that second step never happened — by the time a wallet
moved, the operator had already moved on to the next case.

This module bridges the gap. The tail of `run_emit_brief` walks the
freezable destinations + the perp hub and inserts a
``monitoring_subscriptions`` row per (address, chain) with the
investigator's email as the alert channel. The next monitor_tick
picks it up and starts polling.

Idempotent: ``UNIQUE (address, chain, created_by)`` with a
case-scoped ``created_by = 'emit_brief:<case_id>'`` means re-running
emit_brief on the same case no-ops cleanly. Re-running on a
*different* case with overlapping addresses (recidivist perp)
creates a second subscription with that case's created_by — which
is intentional: each case wants its own audit trail.

Failure mode: every database operation is wrapped so a Supabase
outage cannot break brief emission. Brief writing must succeed
even when monitoring bookkeeping fails — the investigator can
re-seed subscriptions manually via the ops CLI later.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

log = logging.getLogger(__name__)


# Trigger type strings — matches monitoring_subscriptions.trigger_type
# CHECK constraint and poller.TRIGGER_* constants.
_TRIGGER_ANY_MOVEMENT = "any_movement"
_TRIGGER_OFAC_CONTACT = "ofac_contact"

# freeze_capability display values that mean "do not monitor"
# (no freeze pathway exists; monitoring would just generate noise).
# Pre-v0.21.0 these were the literal strings "LOW" / "NO"; the
# display layer in capability_display() emits "LOW" for "no"
# capability, but historical briefs may also carry the raw "NO".
_SKIP_CAPABILITIES = frozenset({"LOW", "NO"})

# v0.37.2 (deep-reach #5): minimum current holding for a non-issuer
# DESTINATION to be auto-subscribed to movement monitoring. Below this the
# residual balance is dust and a subscription would just be noise.
_DEST_MONITOR_MIN_USD = 1000.0


def _parse_usd_amount(raw: object) -> float | None:
    """Parse a brief USD string like ``"$655,751.45"`` to a float. Returns
    None for missing / non-numeric values (e.g. ``"unknown (see explorer)"``)."""
    if raw is None:
        return None
    s = str(raw).strip().replace("$", "").replace(",", "")
    if not s:
        return None
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class SubscriptionSeed:
    """Row-shaped data for one prospective ``monitoring_subscriptions``
    insertion. Constructed by ``derive_subscriptions_from_brief`` and
    consumed by ``persist_subscriptions``.
    """
    address: str
    chain: str
    trigger_type: str
    alert_email: str | None
    case_id: str            # external case id (e.g. RCP-2026-0427)
    investigation_id: UUID | None
    label: str
    created_by: str


def _canonical_addr(address: str) -> str:
    """Lowercase EVM addresses for dedup; preserve case for base58.

    Mirrors recupero._common.canonical_address_key but kept local so
    this module stays import-light (the subscriber is called at the
    tail of emit_brief and shouldn't pull in the full _common surface).
    """
    if not address:
        return address
    # Case-insensitive 0x check — upstream briefs occasionally arrive
    # with the prefix upper-cased (Etherscan UI export quirk).
    if address[:2].lower() == "0x" and len(address) == 42:
        return address.lower()
    return address


# v0.21.0 cranky-fermat audit: label values flow into Postgres TEXT
# columns. NUL bytes are rejected outright by libpq; CR/LF in audit
# labels break downstream log parsing. Strip both.
_LABEL_BAD_CHARS = str.maketrans({"\x00": "", "\r": " ", "\n": " "})


def _sanitize_label(label: str) -> str:
    return label.translate(_LABEL_BAD_CHARS)[:200]


def _collect_ofac_addresses(brief: dict[str, Any]) -> set[str]:
    """Build the set of canonical addresses flagged as OFAC-exposed
    in either the direct risk assessment or the indirect-exposure
    section. These get ``trigger_type='ofac_contact'`` so the
    dispatcher fires on any-direction transfer (not just outflow).
    """
    flagged: set[str] = set()
    for section_key in ("RISK_ASSESSMENT", "INDIRECT_EXPOSURE"):
        section = brief.get(section_key) or {}
        addr_map = section.get("addresses") or {}
        for addr, data in addr_map.items():
            if not isinstance(data, dict):
                continue
            # Two signal shapes in the brief: an explicit
            # ofac_exposed bool, OR an exposures list with an entry
            # whose risk_category contains "ofac" / "sanctions".
            if data.get("ofac_exposed"):
                flagged.add(_canonical_addr(addr))
                continue
            for exp in data.get("exposures") or []:
                if not isinstance(exp, dict):
                    continue
                cat = (exp.get("risk_category") or "").lower()
                if "ofac" in cat or "sanction" in cat:
                    flagged.add(_canonical_addr(addr))
                    break
    return flagged


def derive_subscriptions_from_brief(
    brief: dict[str, Any],
    *,
    case_id: str,
    investigation_id: UUID | None = None,
    investigator_email: str | None = None,
) -> list[SubscriptionSeed]:
    """Walk the brief and produce a deduplicated list of subscription seeds.

    Coverage:
      * ``PERP_HUB`` — always subscribed (the hub is the most
        actionable single watchpoint).
      * ``ALL_ISSUER_HOLDINGS`` — every holding except those under an
        issuer with capability LOW/NO (e.g. Sky Protocol / DAI —
        no freeze pathway, monitoring would just create noise).

    Trigger type:
      * ``ofac_contact`` when the address is flagged in
        ``RISK_ASSESSMENT`` or ``INDIRECT_EXPOSURE`` as OFAC-exposed.
      * ``any_movement`` otherwise.

    Dedup key is (canonical_address, chain) — duplicates across
    ``PERP_HUB`` + ``ALL_ISSUER_HOLDINGS`` collapse to one seed.
    The first seed encountered wins (PERP_HUB is processed first
    so the hub's label is preserved when it overlaps with a holding).
    """
    primary_chain = brief.get("PRIMARY_CHAIN") or "ethereum"
    primary_chain_lc = primary_chain.lower() if isinstance(primary_chain, str) else "ethereum"

    ofac_addresses = _collect_ofac_addresses(brief)
    seeds: dict[tuple[str, str], SubscriptionSeed] = {}
    created_by = f"emit_brief:{case_id}"

    def _add(*, address: str | None, chain: str | None, label: str) -> None:
        if not address or not chain:
            return
        canon = _canonical_addr(address)
        chain_lc = chain.lower() if isinstance(chain, str) else primary_chain_lc
        key = (canon, chain_lc)
        if key in seeds:
            return
        trigger = (
            _TRIGGER_OFAC_CONTACT if canon in ofac_addresses
            else _TRIGGER_ANY_MOVEMENT
        )
        seeds[key] = SubscriptionSeed(
            # Persist the CANONICAL form so the DB unique constraint
            # (address, chain, created_by) stays stable across reruns
            # where upstream brief casing drifts (v0.21.0 cranky-fermat).
            address=canon,
            chain=chain_lc,
            trigger_type=trigger,
            alert_email=investigator_email,
            case_id=case_id,
            investigation_id=investigation_id,
            label=_sanitize_label(label),
            created_by=created_by,
        )

    # 1) PERP_HUB — always seed, regardless of capability. The hub
    # itself doesn't have a freeze_capability field, but it's the
    # most actionable single watchpoint in the case.
    hub = brief.get("PERP_HUB") or {}
    hub_addr = hub.get("address")
    if hub_addr:
        _add(
            address=hub_addr,
            chain=hub.get("chain") or primary_chain_lc,
            label=f"Perp hub — case {case_id}",
        )

    # 2) ALL_ISSUER_HOLDINGS — comprehensive list including
    # UNRECOVERABLE entries. Skip the LOW/NO capability tier per
    # the plan's Sky-Protocol-style carve-out.
    for entry in brief.get("ALL_ISSUER_HOLDINGS") or []:
        if not isinstance(entry, dict):
            continue
        capability = (entry.get("freeze_capability") or "").upper()
        skip_issuer = capability in _SKIP_CAPABILITIES
        issuer = entry.get("issuer") or "(unknown issuer)"
        for holding in entry.get("holdings") or []:
            if not isinstance(holding, dict):
                continue
            # v0.34.4: even under a LOW/NO-capability issuer (DAI / Sky etc.),
            # a TRACKED holding — funds we've IDENTIFIED that still sit there —
            # MUST be watched: if they later move to a freezable venue we want
            # the alert so we can act for recovery. That's the whole point of
            # the TRACKED category. Non-TRACKED holdings under such issuers stay
            # carved out (monitoring them would just be noise).
            hstatus = (holding.get("status") or "").upper()
            if skip_issuer and hstatus != "TRACKED":
                log.debug(
                    "subscriber: skipping %s holding under issuer %s "
                    "(freeze_capability=%s, status=%s)",
                    holding.get("address"), entry.get("issuer"), capability, hstatus,
                )
                continue
            label = f"{issuer} — case {case_id}"
            if hstatus == "TRACKED":
                label += " [TRACKED — monitor for movement]"
            _add(
                address=holding.get("address"),
                chain=holding.get("chain") or primary_chain_lc,
                label=label,
            )

    # 3) v0.37.2 (deep-reach #5): value-holding DESTINATIONS that are NOT
    # issuer-keyed — e.g. a dormant native-asset (ETH/etc.) EOA the BFS
    # reached. The ALL_ISSUER_HOLDINGS pass only covers issuer tokens, so such
    # a holder would never be watched; subscribe any destination currently
    # holding material value so the nightly watch_tick re-sweep alerts when the
    # perpetrator finally moves those parked funds (the "perp just moved the
    # dormant $10M" signal without needing a fresh trace). INVESTIGATE
    # destinations (contract-bleed / pool liquidity) are skipped — monitoring
    # protocol liquidity for "movement" is pure noise. Dedup via _add means an
    # address already seeded above (hub / issuer holding) is not double-counted.
    for dest in brief.get("DESTINATIONS") or []:
        if not isinstance(dest, dict):
            continue
        if (dest.get("status") or "").upper() == "INVESTIGATE":
            continue
        held = _parse_usd_amount(dest.get("usd_holding_now"))
        if held is None or held < _DEST_MONITOR_MIN_USD:
            continue
        _add(
            address=dest.get("address"),
            chain=dest.get("chain") or primary_chain_lc,
            label=(
                f"Dormant holder ~${held:,.0f} — case {case_id} "
                "[monitor for movement]"
            ),
        )

    return list(seeds.values())


def persist_subscriptions(
    seeds: list[SubscriptionSeed],
    *,
    dsn: str,
) -> tuple[int, int]:
    """INSERT seeds into ``monitoring_subscriptions``. Returns
    ``(inserted, skipped)``.

    Idempotent via ``ON CONFLICT (address, chain, created_by) DO
    NOTHING`` on the existing UNIQUE constraint — re-running
    emit_brief on the same case re-derives the same seeds and inserts
    nothing.

    Each seed with ``alert_email`` set inserts with
    ``alert_channels=['email']``. Seeds without an alert_email are
    skipped (the CHECK constraint would reject them, and a webhook-
    less subscription has no deliverable channel) — the count goes
    into ``skipped`` so the caller can log.
    """
    if not seeds:
        return (0, 0)

    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        log.warning("psycopg not installed — subscription seeding skipped")
        return (0, len(seeds))

    from recupero._common import db_connect

    sql = """
        INSERT INTO public.monitoring_subscriptions (
            address, chain, trigger_type,
            alert_channels, alert_email, webhook_url,
            investigation_id,
            created_by, label, status
        ) VALUES (
            %(address)s, %(chain)s, %(trigger_type)s,
            %(channels)s::TEXT[], %(alert_email)s, NULL,
            %(investigation_id)s,
            %(created_by)s, %(label)s, 'active'
        )
        ON CONFLICT (address, chain, created_by) DO NOTHING;
    """
    inserted = 0
    skipped = 0
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            for seed in seeds:
                if not seed.alert_email:
                    # No deliverable channel — would violate the
                    # channel-targets-present CHECK. Log and skip.
                    log.info(
                        "subscriber: %s on %s skipped (no alert_email)",
                        seed.address, seed.chain,
                    )
                    skipped += 1
                    continue
                cur.execute(sql, {
                    "address": seed.address,
                    "chain": seed.chain,
                    "trigger_type": seed.trigger_type,
                    "channels": ["email"],
                    "alert_email": seed.alert_email,
                    "investigation_id": (
                        str(seed.investigation_id)
                        if seed.investigation_id else None
                    ),
                    "created_by": seed.created_by,
                    "label": seed.label,
                })
                if cur.rowcount == 1:
                    inserted += 1
                else:
                    # ON CONFLICT DO NOTHING returned 0 rows — already exists.
                    skipped += 1
        return (inserted, skipped)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "persist_subscriptions failed (%d seeds intended): %s",
            len(seeds), exc,
        )
        return (0, len(seeds))


def auto_subscribe_from_brief(
    brief: dict[str, Any],
    *,
    case_id: str,
    investigation_id: UUID | None = None,
    investigator_email: str | None = None,
    dsn: str | None = None,
) -> tuple[int, int]:
    """One-shot convenience: derive seeds + persist them. Returns
    ``(inserted, skipped)``.

    No-op (returns (0, 0)) when ``dsn`` is unset — accommodates the
    local-CLI emit_brief path where there's no Supabase Postgres.

    Never raises: every failure path is logged so emit_brief
    cannot be broken by a monitoring bookkeeping issue.
    """
    if not dsn:
        return (0, 0)
    try:
        seeds = derive_subscriptions_from_brief(
            brief,
            case_id=case_id,
            investigation_id=investigation_id,
            investigator_email=investigator_email,
        )
        if not seeds:
            return (0, 0)
        return persist_subscriptions(seeds, dsn=dsn)
    except Exception as exc:  # noqa: BLE001
        log.warning("auto_subscribe_from_brief failed: %s", exc)
        return (0, 0)


__all__ = (
    "SubscriptionSeed",
    "derive_subscriptions_from_brief",
    "persist_subscriptions",
    "auto_subscribe_from_brief",
)
