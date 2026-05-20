"""emit_brief.py — bridge between the CLI's trace data and the JS triage builders.

The JS triage builders (build_triage.js, build_triage_exhibits.js, build_readme.js)
consume a specific JSON schema. This module reads three files produced by the CLI:

    data/cases/<case_id>/case.json         (from `recupero trace`)
    data/cases/<case_id>/victim.json       (from `recupero victim`)
    data/cases/<case_id>/freeze_asks.json  (from `recupero list-freeze-targets`)

...merges them with editorial content from:

    data/cases/<case_id>/brief_editorial.json   (investigator-authored)

...and writes the merged result as:

    data/cases/<case_id>/freeze_brief.json

This freeze_brief.json is then consumed by:

    node build_triage.js <case_dir>/freeze_brief.json PREFIX <flow.dot>

Design notes:
  * Pure format translation. No new trace logic.
  * If brief_editorial.json is missing, a template is written with TODO
    placeholders and the command exits non-zero so the investigator has to
    edit before the real brief gets emitted.
  * Dollar formatting ("$47,840") is done here so the JS builders don't have to.
  * Mixer detection uses LabelCategory.mixer. Bridge/dust are not flagged as
    unrecoverable automatically — those are editorial decisions.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import defaultdict
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from recupero._common import (
    aggregate_evidence_mode_from_holdings,
    atomic_write_text,
    canonical_address_key as _ck,
    capability_blocks_freeze,
    capability_display,
    capability_is_freezable,
    investigator_defaults as _investigator_defaults,
    short_addr,
)
from recupero.models import Case, LabelCategory
from recupero.reports.brief import BRIEF_SCHEMA_VERSION as _BRIEF_SCHEMA_VERSION
from recupero.reports.victim import VictimInfo, load_victim
from recupero.storage.case_store import CaseStore

# v0.19.2 (round-13 CRIT, code-quality #1): the prior `log.info(...)` at
# `_compact_empty_freezable_only` (line ~691) referenced a name that
# was NEVER bound — emit_brief never imported logging. Whenever the
# capability-blocks-freeze path fired on every holding (the documented
# v0.16.8 case), the call raised NameError, escaped emit_brief, and
# silently broke the brief render for that case. Closed by adding
# the standard module-level logger here.
log = logging.getLogger(__name__)


# Investigator identity is resolved from env vars at call-time via
# `recupero._common.investigator_defaults()` (imported above as
# `_investigator_defaults`). Pre-v0.19.0 the function was defined
# inline here AND in reports/ai_editorial.py with the same body —
# centralized in v0.19.0 so adding a new RECUPERO_INVESTIGATOR_*
# env var lives in one place.


# v0.17.3 (round-10 audit MED): module-load cache REMOVED. Pre-v0.17.3
# `_INV = _investigator_defaults()` ran at import, so EDITORIAL_TEMPLATE's
# INVESTIGATOR_* fields were frozen at module-load — defeating the
# v0.16.9 fix that made _investigator_defaults() resolve at call time.
# `EDITORIAL_TEMPLATE` is now a dict factory; the single consumer
# (emit_editorial_template at ~line 842) calls it on every write.


def _editorial_template() -> dict[str, Any]:
    """Return a fresh dict of the editorial-template defaults, with
    investigator fields resolved at call time. Replaces the prior
    module-level EDITORIAL_TEMPLATE constant."""
    inv = _investigator_defaults()
    base = dict(_EDITORIAL_TEMPLATE_STATIC)
    base.update({
        "INVESTIGATOR_NAME": inv["INVESTIGATOR_NAME"],
        "INVESTIGATOR_EMAIL": inv["INVESTIGATOR_EMAIL"],
        "INVESTIGATOR_ENTITY": inv["INVESTIGATOR_ENTITY"],
        "INVESTIGATOR_ENTITY_FULL": inv["INVESTIGATOR_ENTITY_FULL"],
        "INVESTIGATOR_WEB": inv["INVESTIGATOR_WEB"],
    })
    return base


_EDITORIAL_TEMPLATE_STATIC: dict[str, Any] = {
    "CASE_ID": "TODO: fill in (e.g. RCP-2026-0427)",
    "REPORT_DATE": "TODO: human-readable report date (e.g. 'April 20, 2026')",
    "INCIDENT_DATE": "TODO: human-readable incident date (e.g. 'April 19, 2026')",
    "INCIDENT_TYPE": "TODO: one-line description (e.g. 'wallet drainer via phishing site posing as Uniswap governance')",
    "PRIMARY_CHAIN": "TODO: chain name for display (e.g. 'Ethereum')",
    "INCIDENT_NARRATIVE_RECUPERO": "TODO: Recupero-voice narrative (3-5 sentences, third person, describes what happened and what the trace shows).",
    "INCIDENT_NARRATIVE_FIRST_PERSON": "TODO: Victim-voice narrative (3-5 sentences, first person 'I', for the LE report and letters the victim signs).",
    "VICTIM_SUMMARY": "TODO: Plain-English summary for the victim (4-6 sentences). Covers what happened, where the money went, what Recupero is doing, expected next steps, and honest expectation-setting. No jargon. v0.15.0+.",
    "VICTIM_ADDRESS_LINE1": "TODO: victim street address (e.g. '1428 Valencia Street, Apt 3B')",
    "VICTIM_ADDRESS_LINE2": "TODO: victim city/state/zip (e.g. 'San Francisco, CA 94110')",
    "VICTIM_JURISDICTION": "TODO: victim jurisdiction for LE report (e.g. 'USA (California)')",
    "DESTINATION_NOTES": {
        "TODO: <address>": "TODO: editorial note for this address (e.g. '🟩 FREEZABLE — Circle-issued USDC, dormant 24 hours')"
    },
    "UNRECOVERABLE_ITEMS": [
        {
            "asset": "TODO: e.g. '3.2 ETH (~$6,780)'",
            "reason": "TODO: e.g. 'Sent to Tornado Cash. Mixed. Not traceable post-mixing with current techniques.'"
        }
    ],
    # v0.17.3: INVESTIGATOR_* fields populated by _editorial_template()
    # at call-time so env-var rotation takes effect without restart.
    "TEMPLATE_VERSION": "v1.0 — April 2026",
}


# v0.18.7 (round-11 arch-HIGH-005): EDITORIAL_TEMPLATE module-level
# snapshot REMOVED. It was a regression of the v0.17.3 fix:
# `_editorial_template()` reads env vars (operator name, contact)
# at CALL time so a deploy with the env vars set late doesn't get
# stamped with "(operator name not configured)". The module-level
# alias took the snapshot at IMPORT time, undoing the fix for any
# caller that imported the alias. Grep confirms no internal callers
# rely on the symbol; if external tooling did, the migration path
# is one line (`from emit_brief import _editorial_template; tpl =
# _editorial_template()`).


def _now_utc_iso_seconds() -> str:
    """UTC timestamp, second precision, ISO 8601 with trailing Z."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_usd_string(s: str) -> Decimal:
    """Parse '$47,840.12' -> Decimal('47840.12'). Returns Decimal('0') on failure."""
    s = str(s).replace("$", "").replace(",", "").strip()
    try:
        return Decimal(s)
    except Exception:
        return Decimal("0")


def usd(v: Decimal | float | int | None) -> str:
    """Format a USD amount like '$47,840' or '$47,840.12'. None -> '$0'."""
    if v is None:
        return "$0"
    d = Decimal(str(v))
    # Strip trailing zeros after decimal if it's a round number
    if d == d.to_integral_value():
        return f"${int(d):,}"
    return f"${d:,.2f}"


def iso_to_display_date(iso: str) -> str:
    """'2026-04-19T14:22:17Z' -> 'April 19, 2026'."""
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return dt.strftime("%B %d, %Y").replace(" 0", " ")


def _extract_primary_chain(case: Case) -> str:
    """Pick a human-readable chain label from the case."""
    chain_display = {
        "ethereum": "Ethereum",
        "arbitrum": "Arbitrum",
        "bsc": "BNB Chain",
        "base": "Base",
        "polygon": "Polygon",
        "solana": "Solana",
        "bitcoin": "Bitcoin",
    }
    return chain_display.get(case.chain.value, case.chain.value.capitalize())


def _extract_perp_hub(case: Case) -> dict[str, Any] | None:
    """The first downstream counterparty that received the largest USD outflow.

    Heuristic: the address with the highest total USD received in the first
    few hops from the victim wallet.
    """
    if not case.transfers:
        return None

    # Sum USD received per counterparty among transfers leaving the
    # victim wallet.
    #
    # v0.20.2 (audit-round-2 finding #8): keys are canonical
    # (lower-cased EVM / case-preserved base58) — pre-v0.20.2 we
    # used raw `t.to_address` which case-splits the USD bucket when
    # the same destination appears with EIP-55 mixed case and
    # all-lowercase across different transfers (Etherscan vs
    # Alchemy serialise checksum case differently). A real perp hub
    # could lose its "largest outflow" crown to a smaller, single-
    # case-variant destination. We still keep the original display
    # address (first occurrence) for the return value.
    per_addr_usd: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    per_addr_first_seen: dict[str, datetime] = {}
    per_addr_display: dict[str, str] = {}

    seed_canon = _ck(case.seed_address)
    for t in case.transfers:
        if _ck(t.from_address) == seed_canon:
            to_raw = t.to_address
            to_canon = _ck(to_raw)
            if t.usd_value_at_tx is not None:
                per_addr_usd[to_canon] += t.usd_value_at_tx
            if (
                to_canon not in per_addr_first_seen
                or t.block_time < per_addr_first_seen[to_canon]
            ):
                per_addr_first_seen[to_canon] = t.block_time
                # First-seen wins display so the chosen casing
                # matches the earliest on-chain reference for that
                # address.
                per_addr_display[to_canon] = to_raw

    if not per_addr_usd:
        # Victim never sent anything? Fall back to first outflow counterparty.
        return None

    hub_canon = max(per_addr_usd.items(), key=lambda kv: kv[1])[0]
    hub_addr = per_addr_display.get(hub_canon, hub_canon)
    hub_usd = per_addr_usd[hub_canon]
    hub_first_seen = per_addr_first_seen[hub_canon]

    return {
        "address": hub_addr,
        "address_short": short_addr(hub_addr),
        "chain": _extract_primary_chain(case),
        "first_seen": hub_first_seen.isoformat().replace("+00:00", "Z"),
        "usd_received": usd(hub_usd),
    }


# Dust threshold (USD) for inclusion in the DESTINATIONS list. Below this
# we drop the destination as noise — token-contract dust, MEV-bot pennies,
# wrapped-stablecoin micro-routing. Tunable via env for case-specific
# investigations that need finer granularity.
def _parse_dust_threshold() -> Decimal:
    """Parse RECUPERO_DESTINATION_DUST_USD env var safely.

    Security MED-2: the raw Decimal() call at module-load time raises
    decimal.InvalidOperation and crashes the worker if the env var is
    set to a non-numeric string (e.g. "none", "disabled", an accidental
    space). Also guards against negative values which would include ALL
    destinations regardless of size.
    """
    raw = os.environ.get("RECUPERO_DESTINATION_DUST_USD", "1000.00").strip()
    try:
        val = Decimal(raw)
        if val < 0:
            raise ValueError("negative threshold")
        return val
    except Exception:
        log.warning(
            "RECUPERO_DESTINATION_DUST_USD=%r is invalid; falling back to $1000.00",
            raw,
        )
        return Decimal("1000.00")


_DESTINATION_DUST_USD_DEFAULT = _parse_dust_threshold()


def _extract_destinations(
    case: Case,
    editorial_notes: dict[str, str],
    freeze_targets_by_addr: dict[str, dict[str, Any]],
    *,
    dust_threshold_usd: Decimal | None = None,
) -> list[dict[str, Any]]:
    """Build the DESTINATIONS list for the report.

    v0.13.4 fix (Jacob V-CFI01 follow-up):
      Previously this function filtered to ONLY addresses the AI editorial
      labeled in editorial_notes. On multi-destination cases (perp hub
      consolidates then disperses to 14+ downstream addresses, each
      holding $K-$M in freezable tokens) the AI often labeled only the
      hub, silently dropping every downstream destination from the
      customer-facing brief — so the Triage Report would render
      "Freezable: $0" when the trace had identified $3M+ in freezable
      downstream holdings.

    Now we enumerate every destination from ``case.transfers`` above a
    dust threshold (default $1,000 USD, overridable via
    RECUPERO_DESTINATION_DUST_USD env var). Editorial notes refine the
    per-destination note when present, but no longer FILTER the list.

    Each destination carries:
      * address + short form
      * role (freezable / mixer / labeled / intermediate)
      * USD currently held (from freeze_targets_by_addr if known)
      * USD received in trace (sum across all transfers in)
      * status emoji classification (from editorial_notes if AI labeled,
        else mechanical fallback based on freeze_targets / label data)
      * notes (editorial-supplied or mechanical fallback)

    Returns destinations sorted by USD received descending.
    """
    threshold = (
        dust_threshold_usd if dust_threshold_usd is not None
        else _DESTINATION_DUST_USD_DEFAULT
    )

    # v0.20.1 (Jacob V-CFI01 residual #2): canonical-key every aggregate
    # so the same on-chain address can't appear twice in the destination
    # list with different casing. Pre-v0.20.1 a wallet that surfaced both
    # in `case.transfers` (mixed case from chain explorer) and in
    # `freeze_targets_by_addr` (lowercase after the freeze_asks emitter
    # normalized) produced two rows in DESTINATIONS — the trace one with
    # the inflow USD, and the freeze one with $0 inflow but FREEZABLE
    # role. Now: key all internal dicts on canonical form, keep a
    # display-case map for output. One canonical → one row.
    per_addr_received: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    per_addr_label_name: dict[str, str | None] = {}
    per_addr_category: dict[str, str | None] = {}
    per_addr_is_mixer: dict[str, bool] = defaultdict(bool)
    per_addr_tokens: dict[str, set[str]] = defaultdict(set)
    # Display-case map: canonical → first-seen original case. Used so
    # the brief renders the EIP-55-style mixed-case form rather than
    # the lowercase canonical-key form (which is harder to spot-check
    # against block explorers).
    per_addr_display: dict[str, str] = {}

    seed_canon = _ck(case.seed_address)
    for t in case.transfers:
        to_raw = t.to_address
        to = _ck(to_raw)
        if not to or to == seed_canon:
            continue
        per_addr_display.setdefault(to, to_raw)
        if t.usd_value_at_tx is not None:
            per_addr_received[to] += t.usd_value_at_tx
        if t.token and t.token.symbol:
            per_addr_tokens[to].add(t.token.symbol)
        if t.counterparty.address == to_raw and t.counterparty.label:
            per_addr_label_name[to] = t.counterparty.label.name
            per_addr_category[to] = t.counterparty.label.category.value
            if t.counterparty.label.category == LabelCategory.mixer:
                per_addr_is_mixer[to] = True

    # Enumerate every destination >= dust_threshold. Also unconditionally
    # include addresses present in freeze_targets_by_addr (so a known
    # freezable destination with low trace-inflow but a real current
    # balance — e.g. $3M mSyrupUSDp at a wallet that only received $1
    # of trace-attributable inflow — still surfaces).
    candidate_addrs: set[str] = {
        a for a, received in per_addr_received.items()
        if received >= threshold
    }
    # freeze_targets_by_addr keys are already canonical post-v0.20.1.
    candidate_addrs.update(freeze_targets_by_addr.keys())
    for a in freeze_targets_by_addr.keys():
        per_addr_display.setdefault(a, a)
    # Editorial notes may carry mixed-case keys (operator hand-edited
    # the JSON). Canonical-key them too, but preserve the operator's
    # display-form when no other source has provided one.
    for ed_addr in editorial_notes.keys():
        canon_ed = _ck(ed_addr)
        if canon_ed:
            candidate_addrs.add(canon_ed)
            per_addr_display.setdefault(canon_ed, ed_addr)

    # Filter the victim's own seed (case-variant safe via canonical key).
    candidate_addrs = {a for a in candidate_addrs if a != seed_canon}

    # v0.20.1: canonical-key editorial_notes too so a mixed-case operator
    # edit still matches the canonical key in the candidate_addrs set.
    editorial_by_canon: dict[str, str] = {
        _ck(k): v for k, v in editorial_notes.items() if _ck(k)
    }

    destinations = []
    for addr_canon in sorted(
        candidate_addrs,
        key=lambda a: per_addr_received.get(a, Decimal("0")),
        reverse=True,
    ):
        # Render the chain-explorer-canonical case (EIP-55 mixed for
        # EVM, original case-preserved for base58 chains). v0.20.1
        # (Jacob V-CFI01 residual #2): pre-v0.20.1 the brief sometimes
        # rendered the all-lowercase canonical-key form, which makes
        # spot-checking against Etherscan harder. Now we display the
        # first-seen on-chain form.
        addr_display = per_addr_display.get(addr_canon, addr_canon)
        label_name = per_addr_label_name.get(addr_canon)
        is_freezable = addr_canon in freeze_targets_by_addr
        is_mixer = per_addr_is_mixer[addr_canon]

        # Role inference
        if is_freezable:
            freeze_info = freeze_targets_by_addr[addr_canon]
            role = f"Holds {freeze_info.get('symbol', 'tokens')} — freezable"
            holding_now = usd(Decimal(str(freeze_info.get("usd_value") or "0")))
        elif is_mixer:
            role = f"{label_name or 'Mixer deposit'}"
            holding_now = "$0 (mixed)"
        elif label_name:
            role = label_name
            holding_now = "unknown (see explorer)"
        else:
            role = "Intermediate wallet"
            holding_now = "unknown (see explorer)"

        # Editorial note if provided, otherwise mechanical fallback.
        if addr_canon in editorial_by_canon:
            notes = editorial_by_canon[addr_canon]
        else:
            notes = _mechanical_destination_note(
                addr=addr_display,
                usd_received=per_addr_received.get(addr_canon, Decimal("0")),
                tokens_observed=per_addr_tokens.get(addr_canon, set()),
                freeze_info=freeze_targets_by_addr.get(addr_canon),
                label_name=label_name,
                is_mixer=is_mixer,
            )

        # Status from editorial classification.
        if addr_canon in editorial_by_canon:
            status = _classify_address_status(
                addr_canon, {addr_canon: editorial_by_canon[addr_canon]},
            )
        else:
            status = _classify_address_status(addr_canon, {addr_canon: notes})

        destinations.append({
            "address": addr_display,
            "short": short_addr(addr_display),
            "role": role,
            "usd_holding_now": holding_now,
            "usd_received_in_trace": usd(per_addr_received.get(addr_canon, Decimal("0"))),
            "status": status,
            "notes": notes,
        })

    return destinations


def _mechanical_destination_note(
    *,
    addr: str,
    usd_received: Decimal,
    tokens_observed: set[str],
    freeze_info: dict[str, Any] | None,
    label_name: str | None,
    is_mixer: bool,
) -> str:
    """Build a fallback DESTINATION_NOTES entry when AI editorial didn't
    label this address.

    Carries the correct emoji prefix so downstream classification +
    JS rendering work identically to AI-labeled entries. This means
    a multi-destination case with sparse AI labels still surfaces
    correctly in the Triage Report.

    Heuristics:
      * Address has a freeze-asks entry → 🟩 FREEZABLE with issuer
        + USD called out.
      * Address is a known mixer → ⬛ UNRECOVERABLE.
      * Address has a counterparty label (exchange / bridge / etc.) →
        🟦 EXCHANGE if exchange-class, 🟧 INVESTIGATE otherwise.
      * Otherwise → 🟧 INVESTIGATE with the tokens observed + USD
        received. The operator reviews these in brief_editorial.json
        and re-classifies (this is the "review required" pathway).
    """
    received_str = usd(usd_received) if usd_received > 0 else "$0"
    tokens_str = "/".join(sorted(tokens_observed)) if tokens_observed else "tokens"

    if freeze_info is not None:
        issuer = freeze_info.get("issuer", "issuer")
        symbol = freeze_info.get("symbol", "tokens")
        balance_usd_raw = freeze_info.get("usd_value") or "0"
        try:
            balance_usd = Decimal(str(balance_usd_raw))
            balance_str = usd(balance_usd)
        except Exception:  # noqa: BLE001
            balance_str = "(unknown)"
        # v0.20.2 (audit-round-3 R3-11): accept both raw
        # ("yes"/"limited"/"no") AND display ("HIGH"/"MEDIUM"/"LOW")
        # forms of freeze_capability. The skip_editorial path in
        # worker/pipeline.py stores the display form; if a re-emit
        # walks through that data, this routine pre-v0.20.2 fell
        # through to "Freezability TBD" → emits "🟩 FREEZABLE …
        # Freezability TBD" on a perfectly-FREEZABLE row, which
        # contradicts itself. Route through the shared
        # capability_is_freezable / capability_blocks_freeze
        # helpers so the taxonomy is consistent across the codebase.
        capability_raw = freeze_info.get("freeze_capability")
        capability_l = (capability_raw or "").lower()
        if capability_l in ("yes", "high"):
            cap_phrase = "Freezability HIGH"
        elif capability_l in ("limited", "medium"):
            cap_phrase = "Freezability LIMITED (issuer pause / admin gate required)"
        elif capability_l in ("no", "low"):
            cap_phrase = "Freezability LOW (no issuer-level freeze pathway)"
        else:
            cap_phrase = "Freezability TBD"
        # If the issuer can't freeze (DAI / wstETH style), emit a
        # DORMANT/UNRECOVERABLE-flavored note so the operator doesn't
        # send a useless freeze letter to a non-freezing issuer.
        if capability_blocks_freeze(capability_raw):
            return (
                f"⬛ UNRECOVERABLE — Holds {balance_str} {symbol} ({issuer}). "
                f"{cap_phrase}. Candidate for seizure if perpetrator "
                "identified, but no issuer-level freeze pathway."
            )
        # Genuine freezable target (capability=yes/HIGH or
        # limited/MEDIUM both qualify — limited still has a freeze
        # pathway, just gated). Anything else still gets a
        # FREEZABLE banner for back-compat, but the phrase reflects
        # the actual capability tier.
        if not capability_is_freezable(capability_raw) and capability_l not in (
            "limited", "medium",
        ):
            cap_phrase = "Freezability TBD"
        return (
            f"🟩 FREEZABLE — Holds {balance_str} {symbol} ({issuer}). "
            f"{cap_phrase}. Received {received_str} in trace."
        )

    if is_mixer:
        return (
            f"⬛ UNRECOVERABLE — Mixer deposit ({label_name or 'unknown mixer'}). "
            f"Received {received_str}; funds mixed and not traceable."
        )

    if label_name:
        # Exchange-class labels → EXCHANGE; other service labels →
        # INVESTIGATE so the operator decides.
        label_lower = label_name.lower()
        if any(
            kw in label_lower
            for kw in ("binance", "coinbase", "kraken", "okx", "bybit",
                       "huobi", "kucoin", "gate.io", "bitfinex", "gemini")
        ):
            return (
                f"🟦 EXCHANGE — {label_name}. Received {received_str}. "
                "Recovery via subpoena to exchange compliance, not "
                "issuer freeze."
            )
        return (
            f"🟧 INVESTIGATE — Labeled {label_name}. Received {received_str} "
            f"({tokens_str}). Status pending operator review."
        )

    # Generic intermediate/transit wallet — operator should re-check.
    return (
        f"🟧 INVESTIGATE — Received {received_str} ({tokens_str}). "
        "Address is not on the issuer freeze-target list; verify "
        "whether it currently holds freezable balances before "
        "writing it off."
    )


def _classify_address_status(addr: str, editorial_notes: dict[str, str]) -> str:
    """Classify an address based on the AI editorial's status prefix.

    Returns one of:
      "FREEZABLE"    — 🟩 or [FREEZABLE] prefix; in-scope and freezable
      "INVESTIGATE"  — 🟧 or [INVESTIGATE] prefix; needs reviewer judgment
      "UNRECOVERABLE" — ⬛ or [UNRECOVERABLE] prefix; mixer/bystander/DEX agg
      "EXCHANGE"     — 🟦 or [EXCHANGE] prefix; CEX deposit (MLAT path)
      "TRANSIT"      — has a note but no recognized prefix
      "UNKNOWN"      — no editorial note for this address (conservative default)

    v0.16.10 (round-9 output-artifacts MEDIUM): ALSO recognize ASCII
    `[FLAG]` tags in addition to the emoji prefixes. Pre-v0.16.10 the
    classifier was emoji-only; Windows operators opening
    brief_editorial.json in cp1252-defaulting tools saw mojibake
    where the emoji should have been, and `_classify_address_status`
    dropped every holding to "UNKNOWN" → TOTAL_FREEZABLE_USD = $0
    on the brief despite real freezable holdings. ASCII tags are the
    durable canonical form; emojis remain a valid presentation
    affordance.

    Classification drives whether a holding contributes to
    TOTAL_FREEZABLE_USD (only "FREEZABLE" status counts).
    """
    note = editorial_notes.get(addr, "")
    if not isinstance(note, str):
        return "UNKNOWN"
    # Strip BOM + zero-width whitespace before checking for the prefix —
    # LLMs occasionally emit those invisibly before the badge.
    note = note.lstrip().lstrip("﻿​‌‍⁠")
    # Emoji-prefix detection (legacy + AI-native).
    if note.startswith("🟩"):
        return "FREEZABLE"
    if note.startswith("🟧"):
        return "INVESTIGATE"
    if note.startswith("⬛"):
        return "UNRECOVERABLE"
    if note.startswith("🟦"):
        return "EXCHANGE"
    # ASCII bracket-tag detection (v0.16.10 — encoding-safe).
    upper = note.upper().lstrip()
    if upper.startswith("[FREEZABLE]"):
        return "FREEZABLE"
    if upper.startswith("[INVESTIGATE]"):
        return "INVESTIGATE"
    if upper.startswith("[UNRECOVERABLE]"):
        return "UNRECOVERABLE"
    if upper.startswith("[EXCHANGE]"):
        return "EXCHANGE"
    if note:  # has a note but no recognized prefix
        return "TRANSIT"
    return "UNKNOWN"


def _extract_freezable(freeze_asks: dict[str, Any], issuer_metadata: dict[str, dict[str, Any]], editorial_notes: dict[str, str] | None = None, *, keep_all: bool = False) -> list[dict[str, Any]]:
    """Translate freeze_asks.json's by_issuer structure into the FREEZABLE format.

    ``keep_all=True`` bypasses the v0.16.8 actionable-totals filter so that
    UNRECOVERABLE-only entries (e.g. Sky Protocol / DAI with freeze_capability='no')
    are included. Used to build ALL_ISSUER_HOLDINGS for the LE comprehensive view.
    The default (``keep_all=False``) retains the existing behaviour: entries with
    zero actionable totals and no FREEZABLE holdings are dropped so the deliverables
    stage never generates a freeze letter asking an issuer to freeze $0.

    issuer_metadata is an optional lookup from issuer_name -> extra fields like
    contact_email, portal_url, typical_response_time, freeze_note. If missing,
    we pull what we can from freeze_asks directly.

    editorial_notes is the AI editorial's DESTINATION_NOTES dict (address -> note).
    When provided, each holding is classified by status (FREEZABLE / INVESTIGATE /
    UNRECOVERABLE / EXCHANGE / TRANSIT / UNKNOWN) and the per-issuer total_usd
    only sums FREEZABLE-status holdings. Holdings with other statuses are still
    listed (so the JS builder can render them separately) but excluded from the
    headline freezable number.
    """
    by_issuer_raw = freeze_asks.get("by_issuer", {})
    editorial_notes = editorial_notes or {}
    # v0.20.2 (audit-round-2 finding #1): canonical-key editorial_notes
    # once so the `_classify_address_status(addr, editorial_notes)`
    # lookup below matches. Pre-v0.20.2 `addr` from freeze_asks was
    # canonical (lowercased EVM, case-preserved base58) but
    # editorial_notes was operator-keyed mixed-case from etherscan
    # paste — so an operator INVESTIGATE tag on `0xA1b2…F00` (checksum)
    # silently missed when the freeze_ask carried `0xa1b2…f00`
    # (lowercase). The lookup defaulted to UNKNOWN → rescued to
    # FREEZABLE → operator's intentional INVESTIGATE tag was overridden
    # and the position landed in `TOTAL_FREEZABLE_USD` despite the
    # operator's review classifying it otherwise.
    editorial_notes_by_canon: dict[str, str] = {
        _ck(k): v for k, v in editorial_notes.items() if _ck(k)
    }
    freezable = []

    for issuer_name, asks in by_issuer_raw.items():
        if not asks:
            continue

        # Aggregate per-issuer
        total_usd = Decimal("0")          # only FREEZABLE-status holdings
        total_suspected_usd = Decimal("0")  # INVESTIGATE-status holdings
        total_excluded_usd = Decimal("0")   # UNRECOVERABLE/EXCHANGE/TRANSIT/UNKNOWN
        symbol = None
        capability = None
        primary_contact = None
        holdings = []

        for a in asks:
            addr = a["address"]
            holding_usd = Decimal(str(a.get("usd_value") or "0"))
            # v0.20.2 (audit-round-2 finding #1): look up the editorial
            # status by canonical key, not by raw addr — the operator's
            # tags are now respected regardless of address casing.
            addr_canon = _ck(addr)
            status = _classify_address_status(addr_canon, editorial_notes_by_canon)

            # Status policy:
            #   capability=no/low                  → UNRECOVERABLE
            #   FREEZABLE-tagged + freezable cap   → keep FREEZABLE
            #     (template differentiates "currently held" vs
            #      "received at" via per-row evidence_type, NOT status)
            #   UNKNOWN status + freezable cap     → rescue to
            #     FREEZABLE so AI-editorial-failure / cost-limit cases
            #     don't silently route to unrecoverable
            ask_capability = a.get("freeze_capability")
            if status == "FREEZABLE" and capability_blocks_freeze(ask_capability):
                status = "UNRECOVERABLE"
            if status == "UNKNOWN" and capability_is_freezable(ask_capability):
                status = "FREEZABLE"

            if status == "FREEZABLE":
                total_usd += holding_usd
            elif status == "INVESTIGATE":
                total_suspected_usd += holding_usd
            else:  # UNRECOVERABLE / EXCHANGE / TRANSIT / UNKNOWN
                total_excluded_usd += holding_usd

            if symbol is None:
                symbol = a.get("symbol")
            if capability is None:
                capability = a.get("freeze_capability")
            if primary_contact is None:
                primary_contact = a.get("primary_contact")
            holdings.append({
                "address": addr,
                # v0.17.4 (round-10 audit HIGH): per-holding chain.
                # Cross-chain freezable holdings render against the
                # correct explorer URL instead of always-etherscan.
                "chain": a.get("chain"),
                "amount": f"{a.get('amount', '?')} {a.get('symbol', '')}",
                "usd": usd(holding_usd),
                "status": status,
                # v0.14.9: evidence-type provenance threads through
                # so the freeze-letter template can swap language
                # for historical-inflow asks vs current-balance asks.
                "evidence_type": a.get("evidence_type", "current_balance"),
                "observed_at": a.get("observed_at"),
                "observed_transfer_count": a.get("observed_transfer_count", 1),
            })

        # Map raw freeze_capability ("yes"/"limited"/"no") → display
        # form ("HIGH"/"MEDIUM"/"LOW"). Centralized in _common.
        cap_display = capability_display(capability)

        # Look up extras from issuer_metadata if present
        meta = issuer_metadata.get(issuer_name, {})

        # Aggregate evidence_mode across this issuer's holdings so the
        # letter template can switch between "freeze NOW" and
        # "investigative request" preambles per issuer. The aggregate-
        # across-issuers mode (for the customer letter bottom line) is
        # computed separately in _victim_summary._build_context.
        n_historical = sum(
            1 for h in holdings
            if h.get("evidence_type") == "historical_inflow"
        )
        n_current = len(holdings) - n_historical
        evidence_mode = aggregate_evidence_mode_from_holdings(holdings)

        # Earliest observation across the historical holdings, for
        # the letter's "incidents observed since" line.
        earliest_observed: str | None = None
        for h in holdings:
            obs = h.get("observed_at")
            if not obs:
                continue
            if earliest_observed is None or obs < earliest_observed:
                earliest_observed = obs

        freezable.append({
            "issuer": issuer_name,
            "token": symbol or "?",
            "total_usd": usd(total_usd),
            "total_suspected_usd": usd(total_suspected_usd),
            "total_excluded_usd": usd(total_excluded_usd),
            "freeze_capability": cap_display,
            "holdings": holdings,
            "contact_email": meta.get("contact_email") or primary_contact or "",
            # primary_contact is the raw issuer-DB field; emit both so
            # downstream consumers that fall back from contact_email to
            # primary_contact get the same value via either key.
            # (Synthesizer path writes both; main path now does too.)
            "primary_contact": primary_contact or "",
            "portal_url": meta.get("portal_url", ""),
            "typical_response_time": meta.get("typical_response_time", "Variable"),
            "freeze_note": meta.get("freeze_note", ""),
            # Aggregate evidence_mode for the letter template.
            "evidence_mode": evidence_mode,
            "historical_count": n_historical,
            "current_balance_count": n_current,
            "earliest_observed": earliest_observed,
        })

    # v0.16.8 (round-9 output-artifacts HIGH): drop issuer entries with
    # zero actionable totals AND zero individual FREEZABLE holdings.
    # The capability_blocks_freeze demote path (above) could leave an
    # issuer entry with total_usd=$0 / total_suspected=$0 / holdings
    # populated but all UNRECOVERABLE — appending that to the freezable
    # list caused the LE handoff loop and the deliverables stage to
    # fire freeze letters asking the issuer to freeze $0. Issuer
    # compliance teams responding to "please freeze $0.00 at this
    # address" undermines the credibility of every subsequent ask.
    #
    # v0.20.3 (render-sim audit): keep_all=True bypasses this filter
    # so ALL_ISSUER_HOLDINGS includes UNRECOVERABLE-only entries for
    # the LE comprehensive view. The default keep_all=False preserves
    # the existing behaviour for the FREEZABLE (letters) list.
    if keep_all:
        return freezable

    filtered: list[dict[str, Any]] = []
    for entry in freezable:
        total_freezable_d = _parse_usd_string(entry.get("total_usd", "0"))
        total_suspected_d = _parse_usd_string(entry.get("total_suspected_usd", "0"))
        # Keep the entry if EITHER there's confirmed freezable value OR
        # there's investigative value (INVESTIGATE tier still warrants
        # an outreach letter).
        if total_freezable_d > 0 or total_suspected_d > 0:
            filtered.append(entry)
            continue
        # Last-resort: count actually-FREEZABLE-status holdings. If even
        # one is FREEZABLE we keep the entry (defensive — a holding may
        # have status=FREEZABLE but a $0 parsed value due to upstream
        # pricing gaps).
        if any(h.get("status") == "FREEZABLE" for h in entry.get("holdings", [])):
            filtered.append(entry)
            continue
        log.info(
            "skipping issuer %s — zero actionable + zero investigative value "
            "(was emitting empty-freeze letters pre-v0.16.8)",
            entry.get("issuer", "(unknown)"),
        )
    return filtered


def _issuer_sort_key(entry: dict) -> int:
    """Sort key: FREEZABLE/INVESTIGATE-capable issuers (0) before UNRECOVERABLE-only (1).

    Used by emit_brief() to order ALL_ISSUER_HOLDINGS so that actionable freeze
    targets always precede seizure-only entries in the LE Section 4.2 table,
    regardless of insertion order in freeze_asks.json.
    """
    cap = (entry.get("freeze_capability") or "").upper()
    return 1 if cap in ("LOW", "NO") else 0


def _count_theft_events(case: Case) -> int:
    """Count the number of individual theft transfers leaving the seed wallet.

    v0.20.3 (render-simulation audit): exposed as THEFT_EVENT_COUNT in the
    brief dict so callers can surface "6 theft events" in the brief metadata
    without reconstructing the count from TOTAL_LOSS_USD. For V-CFI01-shape
    cases (multi-event drain: 6 × $600K = $3.6M) this correctly returns 6;
    for single-event cases it returns 1.
    """
    seed_lower = _ck(case.seed_address)
    return sum(
        1 for t in case.transfers
        if _ck(t.from_address) == seed_lower and t.usd_value_at_tx is not None
    )


def _compute_total_drained(case: Case) -> Decimal:
    """Sum the USD value of transfers leaving the victim's seed wallet.

    This is the actual loss figure — the amount the victim was drained of at
    the moment of the incident — and should be used as TOTAL_LOSS_USD in the
    headline numbers, NOT a sum of current freezable + unrecoverable balances
    (which can be inflated by bystander wallets caught in graph expansion).
    """
    seed_lower = _ck(case.seed_address)
    total = Decimal("0")
    for t in case.transfers:
        if _ck(t.from_address) == seed_lower and t.usd_value_at_tx is not None:
            total += t.usd_value_at_tx
    return total


def _compute_perpetrator_holdings(
    freezable: list[dict[str, Any]],
    unrecoverable: list[dict[str, Any]],
) -> Decimal:
    """Sum the **current balances** at every identified perpetrator-
    controlled destination — across FREEZABLE + UNRECOVERABLE
    statuses.

    This is the v0.7.4 framing number: the gross dollar amount
    of funds sitting at addresses the trace identified as
    perpetrator-controlled, regardless of attribution share.
    For Zigha-shape cases (victim trace finds $153 attributable,
    but the perpetrator hub holds $655K and downstream
    destinations hold $3M+ in freezable Maple assets and $18M+
    in dormant DAI), this is the number a lawyer needs to see
    on page 1.

    Distinct from MAX_RECOVERABLE_USD (which is capped by
    TOTAL_LOSS_USD because a victim can't recover more than
    they lost) — this is the headline scoping number, not the
    customer-facing recovery ceiling.

    Excludes EXCLUDED-status holdings (CEX deposits, transit
    addresses) because those aren't perpetrator-controlled in
    any actionable sense.
    """
    # v0.18.0 (round-11 forensic CRIT): pre-v0.18.0 the comment here
    # claimed `total_suspected_usd` was FREEZABLE+INVESTIGATE and used
    # max() to avoid double-counting. The actual data at lines 596-601
    # proves the buckets are MUTUALLY EXCLUSIVE: total_usd is FREEZABLE-
    # only, total_suspected_usd is INVESTIGATE-only. The old max()
    # systematically understated perpetrator holdings whenever an issuer
    # had both FREEZABLE and INVESTIGATE addresses — e.g., $500K FREEZABLE
    # + $200K INVESTIGATE was reported as $500K instead of $700K. The
    # headline page-1 USD number on every multi-bucket issuer was 20-40%
    # too low.
    total = Decimal("0")
    for f in freezable:
        suspected = _parse_usd_string(f.get("total_suspected_usd", "0"))
        freezable_amt = _parse_usd_string(f.get("total_usd", "0"))
        total += freezable_amt + suspected
    # Add UNRECOVERABLE addresses: dormant addresses holding
    # non-issuer-freezable assets (DAI, native ETH, etc.) are
    # still perpetrator-controlled. They're "unrecoverable
    # via issuer freeze" but recoverable via seizure if the
    # perpetrator is identified.
    for u in unrecoverable:
        asset = u.get("asset", "")
        m = re.search(r"\$([0-9,]+(?:\.[0-9]+)?)", asset)
        if m:
            try:
                total += Decimal(m.group(1).replace(",", ""))
            except Exception:
                pass
    return total


def _compute_totals(case: Case, freezable: list[dict[str, Any]], unrecoverable: list[dict[str, Any]]) -> dict[str, str]:
    """Compute headline totals for the brief.

    TOTAL_LOSS_USD       — actual amount drained from the victim's wallet (from case data)
    TOTAL_FREEZABLE_USD  — sum of FREEZABLE-status holdings (raw freezable balance pool;
                           may exceed TOTAL_LOSS_USD if perpetrator pooled multiple victims)
    TOTAL_SUSPECTED_USD  — sum of INVESTIGATE-status holdings (worth investigating, do not promise)
    TOTAL_EXCLUDED_USD   — sum of UNRECOVERABLE/EXCHANGE/TRANSIT/UNKNOWN-status holdings
    TOTAL_UNRECOVERABLE_USD — sum extracted from the editorial's UNRECOVERABLE_ITEMS list
    MAX_RECOVERABLE_USD  — min(TOTAL_FREEZABLE_USD, TOTAL_LOSS_USD); the customer-facing
                           ceiling — a victim cannot recover more than they lost
    FREEZABLE_PERCENT    — TOTAL_FREEZABLE_USD / TOTAL_LOSS_USD, capped at 100%
    RECOVERABLE_PERCENT  — MAX_RECOVERABLE_USD / TOTAL_LOSS_USD (the honest number)
    """
    # The actual loss — from case data, not from freezable sum
    total_loss = _compute_total_drained(case)

    # Per-status sums from the freezable list
    total_freezable = sum((_parse_usd_string(f.get("total_usd", "0")) for f in freezable), start=Decimal("0"))
    total_suspected = sum((_parse_usd_string(f.get("total_suspected_usd", "0")) for f in freezable), start=Decimal("0"))
    total_excluded = sum((_parse_usd_string(f.get("total_excluded_usd", "0")) for f in freezable), start=Decimal("0"))

    # Unrecoverable sum from editorial's UNRECOVERABLE_ITEMS (best-effort regex parse)
    total_unrecoverable = Decimal("0")
    for u in unrecoverable:
        asset = u.get("asset", "")
        m = re.search(r"\$([0-9,]+(?:\.[0-9]+)?)", asset)
        if m:
            try:
                total_unrecoverable += Decimal(m.group(1).replace(",", ""))
            except Exception:
                pass

    # Freezable percent — capped at 100% (in case freezable somehow exceeds loss, e.g. price moves)
    freezable_pct = "0%"
    if total_loss > 0:
        pct = (total_freezable / total_loss) * 100
        pct = min(pct, Decimal("100"))
        freezable_pct = f"{round(pct)}%"
    elif total_freezable > 0:
        # Edge case: no recorded loss but we found freezable. Show "—" rather than divide-by-zero.
        freezable_pct = "—"

    # MAX_RECOVERABLE_USD — the conservative customer-facing ceiling.
    # A victim cannot claim back more than they lost, even if perpetrator wallets
    # hold larger balances (likely from other victims). This is the honest number
    # to put on the report: "up to $X is potentially recoverable for you."
    max_recoverable = min(total_freezable, total_loss) if total_loss > 0 else total_freezable

    # RECOVERABLE_PERCENT — accurate percentage based on the realistic ceiling.
    recoverable_pct = "0%"
    if total_loss > 0:
        pct = (max_recoverable / total_loss) * 100
        recoverable_pct = f"{round(pct)}%"

    # Gross perpetrator-controlled holdings — the v0.7.4 headline
    # number. Larger than TOTAL_LOSS_USD on Zigha-shape cases
    # where the perpetrator pooled funds from multiple victims;
    # this is the scoping number a downstream lawyer needs to
    # see leading the brief.
    total_perpetrator_holdings = _compute_perpetrator_holdings(
        freezable, unrecoverable,
    )

    return {
        "TOTAL_LOSS_USD": usd(total_loss),
        # New in v0.7.4. The brief headline. See
        # _compute_perpetrator_holdings docstring for the
        # commercial framing: lawyers' engagement thresholds.
        "TOTAL_PERPETRATOR_HOLDINGS_USD": usd(total_perpetrator_holdings),
        "TOTAL_FREEZABLE_USD": usd(total_freezable),
        "TOTAL_SUSPECTED_USD": usd(total_suspected),
        "TOTAL_EXCLUDED_USD": usd(total_excluded),
        "TOTAL_UNRECOVERABLE_USD": usd(total_unrecoverable),
        "MAX_RECOVERABLE_USD": usd(max_recoverable),
        "FREEZABLE_PERCENT": freezable_pct,
        "RECOVERABLE_PERCENT": recoverable_pct,
    }


def write_editorial_template(case_dir: Path) -> Path:
    """Write brief_editorial.json with TODO placeholders. Caller should exit after."""
    path = case_dir / "brief_editorial.json"
    if path.exists():
        return path
    # v0.17.3: call factory so investigator-* env-var rotation takes
    # effect without a worker restart.
    path.write_text(json.dumps(_editorial_template(), indent=2), encoding="utf-8")
    return path


def load_editorial(case_dir: Path) -> dict[str, Any]:
    """Load brief_editorial.json. Raise if any TODO values remain or AI review pending."""
    path = case_dir / "brief_editorial.json"
    if not path.exists():
        raise FileNotFoundError(str(path))
    data = json.loads(path.read_text(encoding="utf-8-sig"))

    # AI-generated review gate
    if data.get("AI_GENERATED") and data.get("REVIEW_REQUIRED"):
        msg_lines = [
            "brief_editorial.json was AI-generated and has not been marked reviewed.",
            f"  Open: {path}",
            "  1. Review every field (especially those with _AI_CONFIDENCE 'low' or 'medium')",
            "  2. Replace any remaining TODO placeholders",
            '  3. Set "REVIEW_REQUIRED": false',
            "  4. Re-run emit-brief",
        ]
        raise ValueError("\n".join(msg_lines))

    # Warn about any remaining TODO markers
    todos = _find_todos(data)
    if todos:
        raise ValueError(
            f"brief_editorial.json still has {len(todos)} TODO placeholder(s): "
            f"{todos[:3]}{'...' if len(todos) > 3 else ''}. Edit the file and re-run."
        )
    return data


def _find_todos(obj: Any, path: str = "") -> list[str]:
    """Recursively find any string values containing 'TODO:'.

    Skips top-level AI metadata fields (REVIEW_INSTRUCTIONS, etc.) which
    legitimately contain the substring 'TODO' in user-facing prose.
    """
    skip = {"AI_GENERATED", "AI_MODEL", "AI_GENERATED_AT", "REVIEW_REQUIRED", "REVIEW_INSTRUCTIONS"}
    todos = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not path and k in skip:
                continue
            todos.extend(_find_todos(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            todos.extend(_find_todos(v, f"{path}[{i}]"))
    elif isinstance(obj, str) and "TODO:" in obj:
        todos.append(path)
    return todos


def _extract_exchanges(freeze_asks: dict[str, Any]) -> list[dict[str, Any]]:
    """Translate freeze_asks.json's exchange_deposits into the EXCHANGES format
    expected by build_triage_exhibits.js.

    Groups deposits by exchange name, producing one entry per exchange with a
    list of deposit addresses. The JS builder iterates this to produce Exhibit C
    letters (one per exchange).
    """
    deposits_by_exchange: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for d in freeze_asks.get("exchange_deposits", []):
        exchange = d.get("exchange", "Unknown Exchange")
        # Format the deposit entry for the JS builder.
        # `amount` is descriptive text (not a number) — the JS puts it next to usd
        # in parentheses, e.g. "3 transfers ($1,234.56)".
        count = d.get("deposit_count", 1)
        usd_str = d.get("total_deposited_usd") or "0"
        try:
            usd_decimal = Decimal(str(usd_str))
        except Exception:
            usd_decimal = Decimal("0")
        amount_desc = f"{count} transfer(s)" if count != 1 else "1 transfer"
        # Use the last deposit date as the "date" field (most recent = most relevant)
        date_str = (d.get("last_deposit_at") or "")[:10]  # YYYY-MM-DD slice
        deposits_by_exchange[exchange].append({
            "address": d.get("address", ""),
            "amount": amount_desc,
            "usd": usd(usd_decimal),
            "date": date_str,
            "label_name": d.get("label_name", ""),
            "label_category": d.get("label_category", ""),
            "label_confidence": d.get("label_confidence", "medium"),
        })

    out = []
    for exchange_name, deposits in deposits_by_exchange.items():
        out.append({
            "exchange": exchange_name,
            "deposits": deposits,
        })
    return out


# ---- Section builders (v0.20.0 Phase C decomposition) ----
#
# Pre-v0.20.0 `emit_brief()` inlined 9 sub-section builds, each
# wrapped in its own ``try / except Exception as _exc`` block with
# a sub-section-specific empty-fallback dict. The function was ~400
# lines, the failure-mode docstrings were buried at the call site,
# and adding a new section meant grafting another 10-15 line block
# onto an already-overloaded orchestrator.
#
# Each helper below:
#   * Has a single responsibility (one brief sub-section)
#   * Catches all exceptions + logs a structured warning naming the
#     section that failed (Jacob's WARNING-grep pattern catches it)
#   * Returns the empty fallback shape that downstream templates
#     expect (no Optional wrapping required at the call site)


def _build_cross_chain_handoffs_section(case: Case) -> list[dict[str, Any]]:
    """v0.8.1: scan the case for transfers landing at known bridge
    contracts. Returned list shapes for the brief template's
    CROSS_CHAIN_HANDOFFS section."""
    try:
        from recupero.trace.cross_chain import (
            handoffs_to_brief_section,
            identify_cross_chain_handoffs,
        )
        handoffs = identify_cross_chain_handoffs(case)
        return handoffs_to_brief_section(handoffs)
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: cross-chain handoffs section build failed: "
            "%s — falling back to empty", exc,
        )
        return []


def _build_entity_clusters_section(
    case: Case, freezable: list[dict[str, Any]],
) -> dict[str, Any]:
    """v0.9.0: group addresses that appear to belong to the same actor.
    v0.18.0: cluster-member dedup keys use canonical_address_key so
    Solana / Tron / Bitcoin base58 addresses don't silently mismatch."""
    try:
        from recupero.trace.clustering import (
            cluster_addresses,
            clusters_to_brief_section,
        )
        address_balances: dict[str, Decimal] = {}
        for entry in freezable:
            for holding in entry.get("holdings") or []:
                addr = _ck(holding.get("address") or "")
                if not addr:
                    continue
                bal = _parse_usd_string(holding.get("usd"))
                address_balances[addr] = (
                    address_balances.get(addr, Decimal("0")) + bal
                )
        clusters, unclustered = cluster_addresses(case, address_balances)
        return clusters_to_brief_section(clusters, unclustered)
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: entity clusters section build failed: %s — "
            "falling back to empty", exc,
        )
        return {"clusters": [], "unclustered_addresses": []}


def _build_risk_assessment_section(
    case: Case,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """v0.9.1 / v0.10.0: direct + indirect exposure scoring.
    Returns ``(risk_assessment, high_risk_db)`` because downstream
    sections (indirect_exposure, drainer_detection) need the loaded
    high_risk_db dict; loading it twice would burn extra I/O."""
    try:
        from recupero.trace.risk_scoring import (
            load_high_risk_db,
            risk_scores_to_brief_section,
            score_addresses,
        )
        high_risk_db = load_high_risk_db()
        risk_scores = score_addresses(case, high_risk_db=high_risk_db)
        return risk_scores_to_brief_section(risk_scores), high_risk_db
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: risk assessment section build failed: %s — "
            "falling back to empty", exc,
        )
        return (
            {
                "addresses": {},
                "summary": {
                    "addresses_assessed": 0,
                    "ofac_exposed_count": 0,
                    "mixer_exposed_count": 0,
                    "highest_score": 0,
                    "highest_score_address": None,
                },
            },
            {},
        )


def _build_indirect_exposure_section(
    case: Case, high_risk_db: dict[str, Any],
) -> dict[str, Any]:
    """v0.10.0: N-hop graph traversal with decay factor. Catches the
    "funds 2-3 hops from Lazarus" case that direct-only scoring misses."""
    try:
        from recupero.trace.indirect_exposure import (
            compute_indirect_exposure,
            indirect_exposure_to_brief_section,
        )
        indirect_results = compute_indirect_exposure(case, high_risk_db)
        return indirect_exposure_to_brief_section(indirect_results)
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: indirect exposure section build failed: %s — "
            "falling back to empty", exc,
        )
        return {
            "addresses": {},
            "summary": {
                "addresses_with_indirect_exposure": 0,
                "indirect_ofac_exposed_count": 0,
                "highest_indirect_usd": "$0.00",
                "highest_indirect_address": None,
            },
        }


def _build_incident_classification_section(
    case: Case, high_risk_db: dict[str, Any],
) -> tuple[dict[str, Any], Any]:
    """v0.10.1: drainer / approval-signature detection. Returns
    ``(incident_classification, drainer_findings)`` because the
    correlation pass downstream consumes the raw findings, not just
    the brief-section view."""
    try:
        from recupero.trace.drainer_detection import (
            detect_drainer_pattern,
            drainer_findings_to_brief_section,
        )
        drainer_findings = detect_drainer_pattern(case, high_risk_db=high_risk_db)
        return drainer_findings_to_brief_section(drainer_findings), drainer_findings
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: drainer/incident classification section "
            "build failed: %s — falling back to empty", exc,
        )
        return (
            {
                "is_drainer_case": False,
                "drainer_attribution": None,
                "classification_confidence": "low",
                "signals": [],
            },
            None,
        )


def _build_dex_swaps_section(case: Case) -> list[dict[str, Any]]:
    """v0.10.2: DEX-router input/output unwrap so a trace doesn't dead-end
    at the router contract."""
    try:
        from recupero.trace.dex_swaps import (
            detect_dex_swaps,
            dex_swaps_to_brief_section,
        )
        dex_swap_records = detect_dex_swaps(case)
        return dex_swaps_to_brief_section(dex_swap_records)
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: dex swaps section build failed: %s — falling "
            "back to empty", exc,
        )
        return []


def _build_cross_case_correlation_section(
    case: Case,
    editorial: dict[str, Any],
    risk_assessment: dict[str, Any],
    drainer_findings: Any,
    freeze_targets_by_addr: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], Any]:
    """v0.11.0: per-address recidivist lookup against the cumulative
    public.address_observations index. Returns ``(correlation_section,
    case_uuid)`` so the downstream class-action pass can reuse the
    parsed case UUID without re-parsing."""
    case_uuid = None
    try:
        from uuid import UUID as _UUID
        cid_raw = getattr(case, "case_id", None) or editorial.get("CASE_ID")
        if cid_raw and isinstance(cid_raw, str):
            try:
                case_uuid = _UUID(cid_raw)
            except (ValueError, TypeError):
                case_uuid = None
    except Exception:  # noqa: BLE001
        pass
    try:
        from recupero.trace.correlation import run_correlation_pass
        section = run_correlation_pass(
            case,
            case_id=case_uuid,
            investigation_id=None,
            risk_assessment=risk_assessment,
            drainer_findings=drainer_findings,
            freeze_targets_by_addr=freeze_targets_by_addr,
        )
        return section, case_uuid
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: cross-case correlation section build failed: "
            "%s — falling back to empty", exc,
        )
        return (
            {
                "addresses": {},
                "summary": {
                    "recidivist_address_count": 0,
                    "ofac_recidivist_count": 0,
                    "drainer_recidivist_count": 0,
                    "highest_prior_case_count": 0,
                    "highest_prior_case_address": None,
                },
            },
            case_uuid,
        )


def _build_class_action_section(case: Case, case_uuid: Any) -> dict[str, Any]:
    """v0.14.3: cross-victim class-action opportunity surfacing.
    Triggered when the current case's perp infra overlaps prior cases
    in qualifying roles (perpetrator_hub / drainer_contract / etc.)."""
    try:
        from recupero.trace.class_action import run_class_action_pass
        return run_class_action_pass(case, current_case_id=case_uuid)
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: class action opportunity section build "
            "failed: %s — falling back to empty", exc,
        )
        return {
            "triggered": False,
            "potential_co_victim_case_count": 0,
            "qualifying_share_count": 0,
            "estimated_combined_loss": "$0.00",
            "shared_addresses": [],
            "investigator_note": "",
        }


def emit_brief(
    case: Case,
    victim: VictimInfo,
    editorial: dict[str, Any],
    freeze_asks: dict[str, Any],
    issuer_metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble the final freeze_brief.json dict that build_triage.js consumes."""
    issuer_metadata = issuer_metadata or {}

    # --- Basic fields ---
    primary_chain = _extract_primary_chain(case)
    report_date = editorial["REPORT_DATE"]
    report_time_utc = _now_utc_iso_seconds()

    # --- Victim fields ---
    victim_wallet = case.seed_address
    victim_wallet_short = short_addr(victim_wallet)

    # --- Perpetrator hub ---
    perp_hub = _extract_perp_hub(case)
    if perp_hub is None:
        perp_hub = {
            "address": "",
            "address_short": "",
            "chain": primary_chain,
            "first_seen": case.incident_time.isoformat().replace("+00:00", "Z"),
            "usd_received": "$0",
        }

    # --- Destinations ---
    # Build address -> freeze info map for role inference
    freeze_targets_by_addr: dict[str, dict[str, Any]] = {}
    # v0.20.1 (Jacob V-CFI01 residual #2): freeze_asks are emitted with
    # the canonical (lowercased EVM, case-preserved base58) key, but
    # `case.transfers` carries the on-chain mixed-case form. Pre-v0.20.1
    # the `candidate_addrs` union in `_extract_destinations` produced
    # duplicate entries for the same on-chain wallet — the mixed-case
    # row from the trace AND the lowercase row from freeze_asks. Now:
    # key freeze_targets by canonical form so the destination merge
    # dedups by single canonical identity.
    for issuer, asks in freeze_asks.get("by_issuer", {}).items():
        for ask in asks:
            canon = _ck(ask["address"])
            freeze_targets_by_addr[canon] = {**ask, "issuer": issuer}

    editorial_notes = editorial.get("DESTINATION_NOTES", {}) or {}
    # Filter out any placeholder keys
    editorial_notes = {k: v for k, v in editorial_notes.items() if not k.startswith("TODO")}

    destinations = _extract_destinations(case, editorial_notes, freeze_targets_by_addr)

    # --- Freezable list ---
    # Pass editorial_notes so each holding gets a `status` field and the
    # per-issuer `total_usd` only sums FREEZABLE-status holdings.
    freezable = _extract_freezable(freeze_asks, issuer_metadata, editorial_notes)
    # v0.20.3 (render-sim audit): all-issuers holdings, including
    # UNRECOVERABLE-only entries filtered out of the FREEZABLE list by
    # v0.16.8. Used to populate the LE handoff's comprehensive
    # Section 4.2 view so law enforcement sees the complete picture —
    # including Sky Protocol / DAI at $655K (seizure target, no
    # issuer-level freeze pathway). The FREEZABLE list (for letters)
    # is kept clean; this key is the LE-only comprehensive view.
    # v0.20.5 (audit-round-5 F7): sort so FREEZABLE-capable issuers (total_usd > $0)
    # precede UNRECOVERABLE-only ones in Section 4.2. Legal documents must lead
    # with actionable freeze targets regardless of insertion order in freeze_asks.json.
    _all_raw = _extract_freezable(freeze_asks, issuer_metadata, editorial_notes, keep_all=True)
    all_issuer_holdings = sorted(_all_raw, key=_issuer_sort_key)

    # --- Unrecoverable list ---
    unrecoverable = [
        item for item in editorial.get("UNRECOVERABLE_ITEMS", [])
        if isinstance(item, dict) and not any("TODO" in str(v) for v in item.values())
    ]

    # --- Exchanges (Path B) ---
    # Each entry shapes up for build_triage_exhibits.js's Exhibit C generator.
    exchanges = _extract_exchanges(freeze_asks)

    # --- Totals ---
    # TOTAL_LOSS_USD comes from actual case data (transfers leaving the seed wallet),
    # NOT from a sum of current freezable balances (which can be inflated by bystander
    # contracts caught in the trace expansion — e.g. the Lido stETH contract).
    totals = _compute_totals(case, freezable, unrecoverable)

    # --- Cross-chain handoffs (v0.8.1) --- v0.20.0 Phase C: extracted
    cross_chain_handoffs = _build_cross_chain_handoffs_section(case)

    # --- Entity clustering (v0.9.0) --- v0.20.0 Phase C: extracted
    entity_clusters = _build_entity_clusters_section(case, freezable)

    # --- Risk scoring (v0.9.1 + v0.10.0) --- v0.20.0 Phase C: extracted.
    # high_risk_db is returned alongside risk_assessment because the
    # next two subsystems (indirect_exposure, drainer_detection) need
    # the already-loaded DB; double-loading would burn extra I/O.
    risk_assessment, high_risk_db = _build_risk_assessment_section(case)

    # --- Indirect exposure (v0.10.0) --- v0.20.0 Phase C: extracted
    indirect_exposure = _build_indirect_exposure_section(case, high_risk_db)

    # --- Drainer / incident classification (v0.10.1) --- v0.20.0 Phase C
    # Returns the brief-section view + the raw drainer_findings (the
    # downstream correlation pass consumes the raw findings, not the
    # section view).
    incident_classification, drainer_findings = (
        _build_incident_classification_section(case, high_risk_db)
    )

    # --- DEX swap unwrapping (v0.10.2) --- v0.20.0 Phase C: extracted
    dex_swaps = _build_dex_swaps_section(case)

    # --- Cross-case correlation (v0.11.0) --- v0.20.0 Phase C: extracted
    # The recidivist-lookup against the cumulative
    # public.address_observations index. Returns the section + the
    # parsed case UUID so the next sub-section (class_action) can reuse it.
    cross_case_correlation, _case_uuid = _build_cross_case_correlation_section(
        case=case,
        editorial=editorial,
        risk_assessment=risk_assessment,
        drainer_findings=drainer_findings,
        freeze_targets_by_addr=freeze_targets_by_addr,
    )

    # --- Class-action / cross-victim correlation (v0.14.3) --- v0.20.0 Phase C
    class_action_opportunity = _build_class_action_section(case, _case_uuid)

    # --- Final assembly ---
    brief = {
        "CASE_ID": editorial["CASE_ID"],
        "REPORT_DATE": report_date,
        "REPORT_TIME_UTC": report_time_utc,

        "VICTIM_NAME": victim.name,
        "VICTIM_ADDRESS_LINE1": editorial.get("VICTIM_ADDRESS_LINE1") or (victim.address or "").split(",")[0].strip() or "[address line 1]",
        "VICTIM_ADDRESS_LINE2": editorial.get("VICTIM_ADDRESS_LINE2") or ", ".join([s.strip() for s in (victim.address or "").split(",")[1:]]) or "[address line 2]",
        "VICTIM_EMAIL": victim.email or "",
        "VICTIM_PHONE": victim.phone or "",
        "VICTIM_JURISDICTION": editorial["VICTIM_JURISDICTION"],
        "VICTIM_WALLET_FULL": victim_wallet,
        "VICTIM_WALLET_SHORT": victim_wallet_short,

        "INCIDENT_DATE": editorial["INCIDENT_DATE"],
        "INCIDENT_TIMESTAMP_UTC": case.incident_time.isoformat().replace("+00:00", "Z"),
        "INCIDENT_TYPE": editorial["INCIDENT_TYPE"],
        "PRIMARY_CHAIN": primary_chain,

        "TOTAL_LOSS_USD": totals["TOTAL_LOSS_USD"],
        # v0.20.3 (render-simulation audit): number of individual theft
        # events (transfers out of the seed wallet with a USD value).
        # For V-CFI01-shape multi-event drains this is 6; for ordinary
        # single-event thefts this is 1. Exposed so callers can surface
        # "6 theft events" in brief metadata without reconstructing it.
        "THEFT_EVENT_COUNT": _count_theft_events(case),
        # v0.7.4 headline: gross perpetrator-controlled holdings.
        # Brief templates lead with this; TOTAL_LOSS_USD is now
        # surfaced as the secondary "attribution scope" figure.
        "TOTAL_PERPETRATOR_HOLDINGS_USD": totals["TOTAL_PERPETRATOR_HOLDINGS_USD"],
        # v0.8.1: cross-chain handoffs (Wormhole, Stargate, etc.).
        # One entry per detected bridge-out transfer with the
        # destination-chain candidates and an investigator-actionable
        # follow-up note.
        "CROSS_CHAIN_HANDOFFS": cross_chain_handoffs,
        # v0.9.0: entity clustering. Groups addresses that appear
        # to belong to the same actor based on H1 (common funding
        # source), H2 (common withdrawal target), H3 (direct
        # transfer with round-number amount). Each cluster carries
        # evidence so the investigator can verify the heuristic
        # fired correctly.
        "ENTITY_CLUSTERS": entity_clusters,
        # v0.9.1: risk scoring (direct counterparty). Per-address
        # OFAC + mixer + darknet exposure. SANCTIONED on any direct
        # OFAC contact (dispositive — Treasury's 50% Rule).
        "RISK_ASSESSMENT": risk_assessment,
        # v0.10.0: indirect exposure (N-hop graph traversal with
        # decay + amount-share). Catches the "funds 2-3 hops from
        # Lazarus" cases that direct-only scoring misses. Same
        # shape as RISK_ASSESSMENT but with hop_count + path on
        # each entry.
        "INDIRECT_EXPOSURE": indirect_exposure,
        # v0.10.1: incident classification (drainer vs other).
        # Surfaces whether this looks like a wallet-drainer scam
        # (approval exploit pattern) vs an address-typo / social
        # engineering / custodial-mistake shape, with attribution
        # to known drainer brands when overlap is detected.
        "INCIDENT_CLASSIFICATION": incident_classification,
        # v0.10.2: DEX swap unwrapping. Each entry describes one
        # swap-through-DEX event with the output recipient + an
        # investigator action note. Lets the trace continue
        # past 1inch/Uniswap/CoW routers.
        "DEX_SWAPS": dex_swaps,
        # v0.11.0: cross-case correlation. For every address in
        # this case, this section reports prior appearances across
        # ALL previously-traced cases (read from the cumulative
        # public.address_observations index). Recidivist addresses
        # — perpetrator wallets that recycle across victims — are
        # auto-flagged with prior OFAC / mixer / drainer exposure
        # counts. The compounding-moat capability behind TRM /
        # Chainalysis.
        "CROSS_CASE_CORRELATION": cross_case_correlation,
        # v0.14.3: class-action / cross-victim correlation. When the
        # current case's perpetrator infrastructure overlaps with
        # prior cases (qualifying-role address shared), surface the
        # combined-loss figure + recommend coordinated multi-victim
        # action. Empty/untriggered when no qualifying overlap.
        "CLASS_ACTION_OPPORTUNITY": class_action_opportunity,

        "INCIDENT_NARRATIVE_RECUPERO": editorial["INCIDENT_NARRATIVE_RECUPERO"],
        "INCIDENT_NARRATIVE_FIRST_PERSON": editorial["INCIDENT_NARRATIVE_FIRST_PERSON"],
        # v0.15.0: plain-English summary for the victim. Surfaces in
        # the Triage Report front matter. Empty string when the
        # editorial doesn't carry it (pre-v0.15.0 brief_editorial files).
        "VICTIM_SUMMARY": editorial.get("VICTIM_SUMMARY", ""),

        "PERP_HUB": perp_hub,
        "DESTINATIONS": destinations,
        "FREEZABLE": freezable,
        # v0.20.3 (render-sim audit): comprehensive per-issuer holdings
        # including UNRECOVERABLE-only entries (e.g. Sky Protocol / DAI)
        # that are filtered out of FREEZABLE for freeze-letter generation.
        # Consumers (LE handoff Section 4.2) pass this to generate_briefs
        # as all_issuers_freezable so law enforcement sees the full picture.
        "ALL_ISSUER_HOLDINGS": all_issuer_holdings,
        "UNRECOVERABLE": unrecoverable,
        "EXCHANGES": exchanges,

        "TOTAL_FREEZABLE_USD": totals["TOTAL_FREEZABLE_USD"],
        "TOTAL_SUSPECTED_USD": totals["TOTAL_SUSPECTED_USD"],
        "TOTAL_EXCLUDED_USD": totals["TOTAL_EXCLUDED_USD"],
        "TOTAL_UNRECOVERABLE_USD": totals["TOTAL_UNRECOVERABLE_USD"],
        "MAX_RECOVERABLE_USD": totals["MAX_RECOVERABLE_USD"],
        "FREEZABLE_PERCENT": totals["FREEZABLE_PERCENT"],
        "RECOVERABLE_PERCENT": totals["RECOVERABLE_PERCENT"],

        # Two distinct IDs survive into the brief:
        #   - IC3_COMPLAINT_NUMBER: legacy field (kept for template
        #     compatibility). Reserved for IC3-assigned complaint
        #     numbers that come back AFTER filing.
        #   - IC3_CASE_ID: operator-curated reference captured at
        #     intake (cases.ic3_case_id). Pre-filled from the cases
        #     row by the editorial drafting stage when present; None
        #     otherwise. Surfaces in freeze-letter exhibits + LE
        #     handoffs so issuer compliance / law enforcement can
        #     cross-reference the IC3 record.
        "IC3_COMPLAINT_NUMBER": None,
        "IC3_CASE_ID": editorial.get("IC3_CASE_ID"),

        "INVESTIGATOR_NAME": editorial["INVESTIGATOR_NAME"],
        "INVESTIGATOR_EMAIL": editorial["INVESTIGATOR_EMAIL"],
        "INVESTIGATOR_ENTITY": editorial["INVESTIGATOR_ENTITY"],
        "INVESTIGATOR_ENTITY_FULL": editorial["INVESTIGATOR_ENTITY_FULL"],
        "INVESTIGATOR_WEB": editorial["INVESTIGATOR_WEB"],
        "TEMPLATE_VERSION": editorial["TEMPLATE_VERSION"],
        # Schema version — readers use it to detect stale briefs that
        # lack evidence_type / evidence_mode fields.
        "SCHEMA_VERSION": _BRIEF_SCHEMA_VERSION,
    }

    # v0.14.1: Recovery probability scoring + cost model. Computed
    # AFTER the brief dict is otherwise complete (reads FREEZABLE,
    # UNRECOVERABLE, etc.). Wrapped in try/except so a scoring
    # failure can't break the brief.
    try:
        from recupero.recovery.scorer import score_recovery
        brief["RECOVERY_ESTIMATE"] = score_recovery(brief).to_json_safe()
    except Exception as _exc:  # noqa: BLE001 — non-fatal
        log.warning("emit_brief: recovery estimate section build failed: %s — falling back to empty", _exc)
        brief["RECOVERY_ESTIMATE"] = None
    return brief


def run_emit_brief(case_id: str, case_store: CaseStore) -> tuple[Path, dict[str, Any]]:
    """Top-level orchestration: load files, validate, assemble, write.

    Returns (output_path, brief_dict). Raises if preconditions missing.
    """
    case_dir = case_store.case_dir(case_id)

    # 1. Load case
    case = case_store.read_case(case_id)

    # 2. Load victim
    victim = load_victim(case_dir)

    # 3. Load freeze asks (may be missing if user hasn't run list-freeze-targets yet)
    freeze_asks_path = case_dir / "freeze_asks.json"
    freeze_asks = {}
    if freeze_asks_path.exists():
        freeze_asks = json.loads(freeze_asks_path.read_text(encoding="utf-8-sig"))

    # 4. Load editorial (or write template and stop)
    editorial_path = case_dir / "brief_editorial.json"
    if not editorial_path.exists():
        write_editorial_template(case_dir)
        raise FileNotFoundError(
            f"Wrote template to {editorial_path}. Edit it (replace all TODO placeholders), "
            f"then re-run `recupero emit-brief {case_id}`."
        )
    editorial = load_editorial(case_dir)

    # 5. Assemble
    brief = emit_brief(case=case, victim=victim, editorial=editorial, freeze_asks=freeze_asks)

    # 6. Write
    out_path = case_dir / "freeze_brief.json"
    # Atomic write so a concurrent reader (bucket uploader, portal) can't
    # pick up a half-written JSON.
    atomic_write_text(out_path, json.dumps(brief, indent=2))
    return out_path, brief
