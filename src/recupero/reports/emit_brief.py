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
from uuid import UUID

from recupero._common import (
    aggregate_evidence_mode_from_holdings,
    atomic_write_text,
    capability_blocks_freeze,
    capability_display,
    capability_is_freezable,
    short_addr,
)
from recupero._common import (
    canonical_address_key as _ck,
)
from recupero._common import (
    investigator_defaults as _investigator_defaults,
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
    """UTC timestamp, second precision, ISO 8601 with trailing Z.

    Honors ``SOURCE_DATE_EPOCH`` for reproducible-builds workflows.
    Pre-audit-wave the bare ``datetime.now()`` made every run of the
    same case write a different ``REPORT_TIME_UTC`` — defeating the
    byte-reproducibility contract the rest of the build chain
    (manifest SHAs, ``brief.py::_resolve_render_time``) already
    honors. On parse failure, fall back to wall-clock.
    """
    src_epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if src_epoch:
        try:
            return datetime.fromtimestamp(
                int(src_epoch), tz=UTC,
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            log.warning(
                "SOURCE_DATE_EPOCH=%r is not a valid integer epoch; "
                "falling back to wall-clock", src_epoch,
            )
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_usd_string(s: str) -> Decimal:
    """Parse '$47,840.12' -> Decimal('47840.12'). Returns Decimal('0') on failure."""
    s = str(s).replace("$", "").replace(",", "").strip()
    try:
        return Decimal(s)
    except Exception:
        return Decimal("0")


def usd(v: Decimal | float | int | None) -> str:
    """Format a USD amount like '$47,840' or '$47,840.12'. None -> '$0'.

    RIGOR-Jacob Z11: NaN / Infinity inputs are clamped to ``$0`` so a
    poisoned upstream Decimal (e.g., from a cluster aggregate of a
    poisoned member case) doesn't propagate the literal "$NaN" /
    "$Infinity" into freeze_brief.json and every downstream renderer.
    """
    if v is None:
        return "$0"
    try:
        d = Decimal(str(v))
    except Exception:  # noqa: BLE001
        return "$0"
    if not d.is_finite():
        return "$0"
    # Strip trailing zeros after decimal if it's a round number
    if d == d.to_integral_value():
        return f"${int(d):,}"
    return f"${d:,.2f}"


def _extract_primary_chain(case: Case) -> str:
    """Pick a human-readable chain label from the case."""
    chain_display = {
        "ethereum": "Ethereum",
        "arbitrum": "Arbitrum",
        "bsc": "BNB Chain",
        "base": "Base",
        "polygon": "Polygon",
        "solana": "Solana",
        "tron": "Tron",
        "bitcoin": "Bitcoin",
        "hyperliquid": "Hyperliquid",
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
            # v0.30.3 (V030_2_CORRECTNESS_AUDIT T1-B): mirror the
            # _trace_report.py:209 NaN-guard pattern. Pre-v0.30.3, a
            # single Decimal('NaN') usd_value_at_tx (from a hand-edited
            # cache, a future non-CoinGecko adapter, or a corrupt
            # case-on-disk) poisoned per_addr_usd[to_canon] and
            # propagated into the max()-based perp-hub selection on the
            # LE handoff cover — yielding a randomly-chosen "largest
            # outflow" destination because NaN comparisons are False.
            if t.usd_value_at_tx is not None and t.usd_value_at_tx.is_finite():
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
        # v0.30.3 (V030_2_CORRECTNESS_AUDIT T3-B): Decimal("NaN") /
        # Decimal("Infinity") parse successfully but `val < 0` returns
        # False per IEEE 754, so the pre-v0.30.3 guard let non-finite
        # thresholds through. A NaN threshold makes EVERY destination
        # fail `received >= NaN` (False), collapsing the destination
        # list to freeze-target-only entries.
        if not val.is_finite():
            raise ValueError("non-finite threshold (NaN/Inf)")
        if val < 0:
            raise ValueError("negative threshold")
        return val
    except Exception:
        log.warning(
            "RECUPERO_DESTINATION_DUST_USD=%r is invalid; falling back to $1000.00",
            raw,
        )
        return Decimal("1000.00")


# v0.20.11 (R15-C LOW): removed the module-load-time constant. The
# env-var parse now runs at call time inside _extract_destinations()
# so an operator who rotates RECUPERO_DESTINATION_DUST_USD mid-session
# sees the change reflected without a worker restart. This mirrors the
# pattern used for _editorial_template() (v0.17.3) and is safe because
# _parse_dust_threshold() is cheap (os.environ.get + Decimal parse).


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
        else _parse_dust_threshold()
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
    # RC-8: per-destination chain. Genuine multi-chain cases (e.g. an
    # Ethereum theft bridged to an Arbitrum consolidation hub) carry the
    # destination chain only on the post-bridge transfer's ``chain`` field.
    # Surfacing it onto the DESTINATIONS row keeps the brief's structured
    # data agreeing with editorial prose that names the consolidation chain
    # (INVARIANT O grounds chains from DESTINATIONS rows). First-seen wins
    # so the row reflects the chain the funds actually landed on.
    per_addr_chain: dict[str, str] = {}
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
        # RC-8: record the chain the funds landed on for this address.
        # ``t.chain`` is a Chain enum; persist its string value. First
        # observation wins (deterministic given the ordered transfer list).
        if to not in per_addr_chain and getattr(t, "chain", None) is not None:
            chain_val = getattr(t.chain, "value", None) or str(t.chain)
            if chain_val:
                per_addr_chain[to] = str(chain_val)
        # v0.30.3 (V030_2_CORRECTNESS_AUDIT T1-B): finite-only sum so
        # a single NaN doesn't poison the destination's received-USD
        # bucket. Without this, the `received >= dust_threshold` filter
        # behaves unpredictably for any address that received any
        # NaN-priced transfer.
        if t.usd_value_at_tx is not None and t.usd_value_at_tx.is_finite():
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
    for a in freeze_targets_by_addr:
        per_addr_display.setdefault(a, a)
    # Editorial notes may carry mixed-case keys (operator hand-edited
    # the JSON). Canonical-key them too, but preserve the operator's
    # display-form when no other source has provided one.
    for ed_addr in editorial_notes:
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
            # Jacob v0.21.x residual: role text said "Holds DAI — freezable"
            # on the perp hub even though its issuer (Sky Protocol) has
            # freeze_capability='no' and the row classifies UNRECOVERABLE.
            # Respect the capability flag so the display text agrees with
            # the status / risk_category fields downstream.
            if capability_blocks_freeze(freeze_info.get("freeze_capability")):
                role = f"Holds {freeze_info.get('symbol', 'tokens')} — UNRECOVERABLE"
            else:
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
            # RC-8: chain the funds landed on for this destination (may differ
            # from PRIMARY_CHAIN for cross-chain consolidation hops). Omitted
            # (None) when no transfer recorded a chain for the address.
            "chain": per_addr_chain.get(addr_canon),
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
        # v0.32.1 (JACOB_FREEZE_LETTER_AUDIT CRIT-FR-2 / CRIT-FR-4): pull
        # corporate legal-entity name + posture notes from the first ask
        # that carries them. Issuer entries in freeze_asks.json now carry
        # these fields end-to-end from issuers.json seed → IssuerEntry →
        # serialized ask → here → the FREEZABLE issuer dict → IssuerInfo →
        # the template. None means an issuer DB entry didn't supply them
        # (or an old freeze_asks.json from before v0.32.1).
        legal_name: str | None = None
        corporate_jurisdiction: str | None = None
        issuer_freeze_notes: str | None = None
        issuer_seed_jurisdiction: str | None = None
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
            # v0.32.1 (CRIT-FR-2 / CRIT-FR-4): pull-through from the
            # first ask carrying these fields. They live on the issuer,
            # not the holding, so any ask is representative.
            if legal_name is None:
                ln = a.get("legal_name")
                if isinstance(ln, str) and ln.strip():
                    legal_name = ln
            if corporate_jurisdiction is None:
                cj = a.get("corporate_jurisdiction")
                if isinstance(cj, str) and cj.strip():
                    corporate_jurisdiction = cj
            if issuer_freeze_notes is None:
                fn = a.get("freeze_notes")
                if isinstance(fn, str) and fn.strip():
                    issuer_freeze_notes = fn
            if issuer_seed_jurisdiction is None:
                sj = a.get("jurisdiction")
                if isinstance(sj, str) and sj.strip():
                    issuer_seed_jurisdiction = sj
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
            # v0.32.1 (JACOB_FREEZE_LETTER_AUDIT CRIT-FR-2 / CRIT-FR-4):
            # corporate legal name + freeze-posture notes from issuers.json,
            # threaded through freeze_asks.json. Downstream consumers
            # (`_issuer_info_for` in worker/_deliverables.py) read these
            # to populate `IssuerInfo.name` (legal entity), `.jurisdiction`,
            # and the new `freeze_notes` field rendered in Section 6.
            "legal_name": legal_name,
            "corporate_jurisdiction": corporate_jurisdiction,
            "freeze_notes": issuer_freeze_notes,
            "issuer_jurisdiction": issuer_seed_jurisdiction,
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
    # v0.20.13 (R17-E): drop the `usd_value_at_tx is not None` filter so the
    # count matches _find_theft_events (which includes unpriced outbound
    # transfers). Previously an unpriced drain event (token not in CoinGecko)
    # would be counted here as 0 but appear in the template context as
    # is_multi_event=True — contradictory signals for the AI editorial.
    seed_lower = _ck(case.seed_address)
    return sum(
        1 for t in case.transfers
        if _ck(t.from_address) == seed_lower
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
        # v0.30.3 (V030_2_CORRECTNESS_AUDIT T1-B): finite-only. Without
        # this, a single Decimal('NaN') usd_value_at_tx poisons the
        # running total and the LE cover renders the headline as
        # "USD $NaN stolen" in front of a federal agent.
        if (
            _ck(t.from_address) == seed_lower
            and t.usd_value_at_tx is not None
            and t.usd_value_at_tx.is_finite()
        ):
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
    # v0.27.2 (Jacob 0x52Aa bleed fix, item 1): exclude INVESTIGATE
    # balances from this headline. The trace-report "Perpetrator-
    # controlled holdings: $X" cover figure shipped to AUSAs and
    # engagement lawyers needs to be the CONFIRMED number, not
    # confirmed + leads-pending-KYC. On Zigha v0.27.1 the inclusion
    # of INVESTIGATE inflated this from ~$3.5M (real) to ~$149M
    # (real + $145M of 1inch/Uniswap pool reflective liquidity) —
    # 21.6× wrong, instant credibility collapse for any lawyer or
    # LE reader doing arithmetic against the freeze_brief detail.
    #
    # The original docstring above ("FREEZABLE + UNRECOVERABLE") is
    # the right semantic. The v0.18.0 commit that added `+ suspected`
    # was correcting a different bug (the buckets-are-mutually-
    # exclusive observation) and accidentally also widened scope.
    # We revert scope to FREEZABLE + UNRECOVERABLE; INVESTIGATE has
    # its own `TOTAL_SUSPECTED_USD` field for operator visibility.
    #
    # NB: total_usd is FREEZABLE-only, total_suspected_usd is
    # INVESTIGATE-only, total_excluded_usd is UNRECOVERABLE/EXCHANGE/
    # TRANSIT/UNKNOWN — all mutually exclusive per _extract_freezable's
    # if/elif/else block.
    total = Decimal("0")
    for f in freezable:
        freezable_amt = _parse_usd_string(f.get("total_usd", "0"))
        total += freezable_amt
    # Add UNRECOVERABLE addresses: dormant addresses holding
    # non-issuer-freezable assets (DAI, native ETH, etc.) are
    # still perpetrator-controlled. They're "unrecoverable
    # via issuer freeze" but recoverable via seizure if the
    # perpetrator is identified. Two sources, mutually de-duped
    # via the (issuer, address) key so an editorially-flagged
    # UNRECOVERABLE_ITEMS entry that also appears as a per-issuer
    # UNRECOVERABLE holding only counts once.
    seen_unrec_keys: set[tuple[str, str]] = set()
    for u in unrecoverable:
        asset = u.get("asset", "")
        m = re.search(r"\$([0-9,]+(?:\.[0-9]+)?)", asset)
        if m:
            try:
                total += Decimal(m.group(1).replace(",", ""))
                key = (str(u.get("issuer", "")), str(u.get("address", "")))
                if key != ("", ""):
                    seen_unrec_keys.add(key)
            except Exception:
                pass
    # Per-issuer UNRECOVERABLE holdings (Sky DAI etc.) live in
    # total_excluded_usd by default, but we only want UNRECOVERABLE
    # specifically — not EXCHANGE/TRANSIT. Iterate per-holding so we
    # can filter precisely without over-counting EXCLUDED-status
    # holdings that aren't perpetrator-controlled.
    for f in freezable:
        issuer_name = str(f.get("issuer", ""))
        for h in (f.get("holdings") or []):
            if not isinstance(h, dict):
                continue
            # v0.27.2 post-merge hardening (audit finding #2): match
            # case-insensitively. The asymmetry between this branch
            # (was bare `!= "UNRECOVERABLE"`) and _has_freezable_holding
            # (which uses .upper()) meant a writer emitting
            # "unrecoverable" lowercase would silently drop the
            # Sky/DAI bucket from the perpetrator-holdings headline —
            # silently underreporting in the opposite direction from
            # the Zigha bleed. .upper() everywhere is the canonical
            # contract; the status set is closed and small (FREEZABLE
            # / INVESTIGATE / UNRECOVERABLE / EXCHANGE / TRANSIT)
            # and every writer should emit upper-case but we don't
            # trust hand-written editorial JSON to comply.
            if (h.get("status") or "").upper() != "UNRECOVERABLE":
                continue
            addr = str(h.get("address", ""))
            if (issuer_name, addr) in seen_unrec_keys:
                continue
            seen_unrec_keys.add((issuer_name, addr))
            try:
                total += _parse_usd_string(h.get("usd", "0"))
            except Exception:
                pass
    return total


def _compute_totals(
    case: Case,
    freezable: list[dict[str, Any]],
    unrecoverable: list[dict[str, Any]],
    *,
    all_issuer_holdings: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
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

    # Unrecoverable sum: union of two sources so neither pathway leaves
    # a $655K Sky-DAI-shaped hole in the rollup. Jacob v0.21.x audit
    # caught the pre-fix sum returning $0 when the editorial-list was
    # empty but the freeze_asks had freeze_capability='no' holdings.
    #   1. Editorial UNRECOVERABLE_ITEMS (regex-parsed asset string)
    #   2. Per-holding UNRECOVERABLE status across the freezable list
    #      (catches issuers like Sky Protocol where the freeze_asks
    #      emit but freeze_capability='no').
    # De-dup by (issuer, address) so a holding flagged in BOTH sources
    # only counts once.
    total_unrecoverable = Decimal("0")
    seen_unrecoverable_keys: set[tuple[str, str]] = set()
    for u in unrecoverable:
        asset = u.get("asset", "")
        m = re.search(r"\$([0-9,]+(?:\.[0-9]+)?)", asset)
        if m:
            try:
                total_unrecoverable += Decimal(m.group(1).replace(",", ""))
                key = (str(u.get("issuer", "")), str(u.get("address", "")))
                if key != ("", ""):
                    seen_unrecoverable_keys.add(key)
            except Exception:
                pass
    # Walk the FULL all_issuer_holdings list — `freezable` filters
    # UNRECOVERABLE-only issuers out (Sky Protocol / DAI gets dropped
    # from the letter list because there's no actionable freeze-target).
    # The rollup needs the complete picture, not the filtered one.
    for entry in (all_issuer_holdings or freezable):
        issuer_name = str(entry.get("issuer", ""))
        for h in entry.get("holdings", []):
            if h.get("status") != "UNRECOVERABLE":
                continue
            addr = str(h.get("address", ""))
            key = (issuer_name, addr)
            if key in seen_unrecoverable_keys:
                continue  # already counted via editorial list
            seen_unrecoverable_keys.add(key)
            try:
                total_unrecoverable += _parse_usd_string(h.get("usd", "0"))
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
    # v0.20.13 (R17-C): atomic write — if the worker is killed mid-write,
    # the truncated file must not survive (the `if path.exists()` guard on
    # line 1003 prevents the next run from overwriting it).
    atomic_write_text(path, json.dumps(_editorial_template(), indent=2, allow_nan=False, ensure_ascii=False))
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


def _build_wallet_clusters_section(case: Case) -> dict[str, Any]:
    """v0.31.0: minimum-viable wallet clustering (Gap #4 of the
    trace-completeness assessment).

    Complements the legacy v0.9 ENTITY_CLUSTERS section with stricter
    heuristics and stable sha256-derived cluster IDs. Returns
    ``{"clusters": [...]}`` populated only when 2+ identified
    addresses in the case cluster together via one of the MVP
    heuristics (co-spending, common CEX withdrawal ≤1h, common
    funding ≤1h, bridge round-trip). Otherwise returns
    ``{"clusters": []}``.

    Cluster IDs are sha256-derived so two runs over the same case
    JSON produce identical IDs — important for cross-references
    in the PDF brief + AI editorial templates.

    Best-effort: any failure (label store unavailable, heuristic
    crash) degrades to an empty list rather than poisoning the
    whole brief render.
    """
    try:
        from recupero.trace.clustering import compute_clusters_with_metadata

        # Best-effort label load. If config or labels are unavailable
        # we still run with label_store=None (the funding heuristic
        # still fires; only the CEX / bridge passes are label-gated).
        label_store: Any = None
        try:
            from recupero.config import load_config
            from recupero.labels.store import LabelStore
            label_store = LabelStore.load(load_config())
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "emit_brief: label store load failed for wallet clustering "
                "(%s); running without label suppression", exc,
            )
            label_store = None

        clusters = compute_clusters_with_metadata(
            case, label_store=label_store,
        )
        # Spec: only surface a section when 2+ identified addresses
        # cluster together. compute_clusters_with_metadata already
        # filters singletons, so any non-empty list satisfies that.
        return {"clusters": clusters}
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: wallet clusters section build failed: %s — "
            "falling back to empty", exc,
        )
        return {"clusters": []}


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


def _build_indirect_exposure_v031_section(
    case: Case, high_risk_db: dict[str, Any],
) -> dict[str, Any] | None:
    """v0.31.0 MVP: flat per-address 4-hop weight-decayed exposure scoring.

    Complementary to the v0.10.0 INDIRECT_EXPOSURE section above.
    Closes gap #3 from the trace-completeness assessment (TRM /
    Chainalysis 4-hop weight-decayed exposure scoring): direct-only
    scoring missed the 2-hop-removed mixer / OFAC address; this
    section surfaces it.

    Returns ``None`` when no scored address crosses the 0.1
    surface_threshold — the brief omits the section entirely rather
    than emit a noisy empty block. Otherwise returns a top-10 ranked
    list with primary_label_category + hops_from_victim + exposure_score
    + total_usd_flow per entry.

    Wired against the v0.31 MVP scorer in
    ``recupero.trace.indirect_exposure``. high_risk_db is reused
    as the label_store (it's a ``{address: HighRiskEntry}`` dict;
    the scorer's resolver handles both LabelStore and plain-dict
    shapes). Catches the previously-invisible "victim → drainer →
    laundering hop → mixer" 3-hop case.
    """
    try:
        from recupero.trace.indirect_exposure import (
            compute_label_exposure_scores,
            label_exposure_scores_to_brief_section,
        )
        scores = compute_label_exposure_scores(
            case, label_store=high_risk_db, max_hops=4, decay=0.5,
        )
        return label_exposure_scores_to_brief_section(
            case, scores, label_store=high_risk_db,
            top_n=10, surface_threshold=0.1,
        )
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: v0.31 indirect exposure section build failed: %s — "
            "omitting section", exc,
        )
        return None


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
                # v0.32.1 (CRIT-4): keep the events key in the
                # fallback so downstream consumers can assume the
                # shape regardless of whether detection succeeded.
                "events": [],
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


def _build_mev_signals_section(case: Case) -> dict[str, Any]:
    """v0.31.0 (Gap #9): MEV / sandwich-attack obfuscation detection.

    Flags hops whose tx-shape indicates Flashbots bundle / sandwich /
    JIT-LP / MEV-builder-source funding. Detection only — manual
    investigator follow-up needed per signal. Brief renders the
    MEV-obfuscated-transfers panel only when at least one signal
    clears confidence ≥ 0.5; sub-threshold counts roll up into the
    summary line for transparency."""
    try:
        from recupero.trace.mev_detection import (
            detect_mev_signals,
            mev_signals_to_brief_section,
        )
        signals = detect_mev_signals(case)
        return mev_signals_to_brief_section(signals)
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: mev signals section build failed: %s — "
            "falling back to empty", exc,
        )
        return {
            "detected": False,
            "signal_count": 0,
            "suppressed_low_confidence_count": 0,
            "signals": [],
        }


def _build_cross_case_correlation_section(
    case: Case,
    editorial: dict[str, Any],
    risk_assessment: dict[str, Any],
    drainer_findings: Any,
    freeze_targets_by_addr: dict[str, dict[str, Any]],
    investigation_id: UUID | None = None,
) -> tuple[dict[str, Any], Any]:
    """v0.11.0: per-address recidivist lookup against the cumulative
    public.address_observations index. Returns ``(correlation_section,
    case_uuid)`` so the downstream class-action pass can reuse the
    parsed case UUID without re-parsing.

    v0.23.1 (audit-fix CRIT-1): ``investigation_id`` now flows through
    to ``run_correlation_pass`` so address_observations rows are
    written with the investigation UUID populated. Pre-v0.23.1 every
    row was written with investigation_id=NULL, which made the
    cluster_builder's prior-overlap query (which excludes NULL rows)
    return zero results — multi-victim cluster detection was inert
    in production despite the v0.23.0 plumbing existing.
    """
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
            # v0.23.1 (audit-fix CRIT-1): pass the actual
            # investigation_id through (was hardcoded None).
            investigation_id=investigation_id,
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


def _build_cex_continuity_section(
    case: Case,
) -> list[dict[str, Any]]:
    """v0.31.2 (Gap #15): CEX trace continuity leads.

    When stolen funds land in a labeled CEX hot wallet the trace
    stops (KYC opaque). This section surfaces investigative LEADS
    when the SAME hot wallet emits an amount-matched outbound
    transfer in a tight time window — a correlation operators can
    pick up via subpoena, NOT a proven re-emergence claim.

    OFF by default. Adapter calls cost API budget — opt in via
    ``RECUPERO_CEX_CONTINUITY=1``. When disabled (default) this
    returns ``[]`` immediately without any adapter calls.

    Returns ``[]`` (empty list) when the feature is disabled OR
    no qualifying leads are found. The emit_brief caller OMITS
    the CEX_CONTINUITY_LEADS section key entirely on empty so
    existing brief-key-set tests stay green.
    """
    try:
        from recupero.trace.cex_continuity import (
            env_continuity_enabled,
            env_min_usd,
            env_window_hours,
            identify_cex_continuity_leads,
            leads_to_brief_section,
        )
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: cex_continuity module import failed: %s — "
            "section omitted", exc,
        )
        return []

    if not env_continuity_enabled():
        log.debug(
            "emit_brief: CEX continuity disabled "
            "(RECUPERO_CEX_CONTINUITY not set to enable value)"
        )
        return []

    try:
        from recupero.chains.base import ChainAdapter
        from recupero.config import load_config
        from recupero.labels.store import LabelStore
        cfg = load_config()
        label_store: LabelStore | None
        try:
            label_store = LabelStore.load(cfg)
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "cex_continuity: label store load failed: %s; "
                "no labeled CEXes — returning []", exc,
            )
            return []
        try:
            adapter = ChainAdapter.for_chain(case.chain, cfg)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "cex_continuity: adapter for chain %s unavailable: "
                "%s — section omitted", case.chain, exc,
            )
            return []
        try:
            leads = identify_cex_continuity_leads(
                case,
                adapter=adapter,
                label_store=label_store,
                window_hours=env_window_hours(),
                min_usd=env_min_usd(),
            )
        finally:
            # Release the adapter's HTTP client — without this, opt-
            # in operators running over thousands of cases would leak
            # httpx clients until the FD limit hits (round-10 audit
            # CRIT pattern for cross-chain continuation adapters).
            try:
                adapter.close()
            except Exception:  # noqa: BLE001
                pass
        return leads_to_brief_section(leads)
    except Exception as exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: cex_continuity section build failed: %s — "
            "section omitted", exc,
        )
        return []


def _subpoena_exchange_dicts(case: Case) -> list[dict[str, Any]]:
    """Resolve ``case.exchange_endpoints`` into the dict shape
    ``subpoena_targets.extract_subpoena_targets`` expects, INCLUDING
    transaction-level evidence (tx_hashes + chain + deposit-window
    timestamps + count) resolved from each endpoint's ``transfer_ids``
    via ``case.transfers``.

    v0.32.1 (#209 step 1): pre-fix the exchange dicts dropped
    ``transfer_ids`` entirely, so every off-ramp subpoena target shipped
    with NO tx_hash for the exchange's compliance team to grep against — a
    subpoena that says "this address received $X" with no on-chain tx
    reference is rejected on compliance review. The endpoint already
    carries the deposit window (first/last_deposit_at); we resolve the
    hashes (falling back to parsing the canonical "chain:tx_hash:logidx"
    transfer-id form when a transfer is absent from ``case.transfers``).
    """
    tinfo_by_id: dict[str, tuple[str, str | None]] = {}
    for t in (getattr(case, "transfers", None) or []):
        tid = getattr(t, "transfer_id", None)
        txh = getattr(t, "tx_hash", None)
        tch = getattr(t, "chain", None)
        cval = tch.value if hasattr(tch, "value") else (
            tch if isinstance(tch, str) else None
        )
        if isinstance(tid, str) and isinstance(txh, str) and txh:
            tinfo_by_id[tid] = (txh, cval)

    def _iso(dt: object) -> str | None:
        try:
            return dt.isoformat() if dt is not None else None  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return None

    out: list[dict[str, Any]] = []
    for e in (getattr(case, "exchange_endpoints", None) or []):
        is_d = isinstance(e, dict)
        tids = (e.get("transfer_ids") if is_d
                else getattr(e, "transfer_ids", None)) or []
        hashes: list[str] = []
        seen: set[str] = set()
        chain_from_tx: str | None = None
        for tid in tids:
            info = tinfo_by_id.get(tid)
            if info is None and isinstance(tid, str) and tid.count(":") >= 2:
                # Defensive fallback: id form is "chain:tx_hash:logidx".
                parts = tid.split(":")
                info = (parts[1], parts[0]) if parts[1] else None
            if info is None:
                continue
            txh, cval = info
            if chain_from_tx is None:
                chain_from_tx = cval
            if txh and txh not in seen:
                seen.add(txh)
                hashes.append(txh)
        first = e.get("first_deposit_at") if is_d else getattr(e, "first_deposit_at", None)
        last = e.get("last_deposit_at") if is_d else getattr(e, "last_deposit_at", None)
        chain = (e.get("chain") if is_d else getattr(e, "chain", None)) or chain_from_tx
        out.append({
            "address": e.get("address") if is_d else getattr(e, "address", None),
            "exchange": e.get("exchange") if is_d else getattr(e, "exchange", None),
            "total_received_usd": (e.get("total_received_usd") if is_d
                else str(getattr(e, "total_received_usd", "") or "")),
            "chain": chain,
            "source": "label_db",
            "tx_hashes": hashes,
            "first_deposit_at": first if is_d else _iso(first),
            "last_deposit_at": last if is_d else _iso(last),
            "transfer_count": len(tids),
        })

    # v0.32.1 (#209 step 2): augment the label-DB endpoints (the shared CEX
    # HOT WALLETS funds reached) with INFERRED per-user deposit addresses —
    # unlabeled addresses that swept funds into one of those hot wallets.
    # The hot wallet is a weak subpoena target (millions of deposits hit it);
    # the inferred deposit address is the precise one tied to a single KYC'd
    # account. Confidence is pinned low/medium (a lead, never proof) by the
    # attribution pass. Existing label-DB addresses win on dedup so we never
    # downgrade a confirmed endpoint to an inferred lead.
    try:
        from recupero.trace.cex_attribution import infer_cex_deposits_from_case
        _existing = {
            (d.get("address") or "").lower()
            for d in out if d.get("address")
        }
        for dep in infer_cex_deposits_from_case(case):
            d = dep.to_dict()
            addr_l = (d.get("address") or "").lower()
            if addr_l and addr_l not in _existing:
                out.append(d)
                _existing.add(addr_l)
    except Exception as _exc:  # noqa: BLE001 — attribution is best-effort
        log.warning(
            "emit_brief: CEX deposit-address attribution failed (%s) — "
            "subpoena targets fall back to label-DB endpoints only", _exc,
        )

    # v0.32.1 (trace-depth #2): surface UNLABELED endpoints a broader-activity
    # diversity probe judged to be likely exchange/service infrastructure
    # (populated during the trace only when RECUPERO_ENDPOINT_DIVERSITY_PROBE
    # is enabled). These are behavioral leads (confidence low/medium, never
    # proof) for venues the label DB doesn't cover. Label-DB + sweep-inferred
    # endpoints win on dedup so an inferred lead never downgrades a confirmed
    # one.
    try:
        for infra in (getattr(case, "inferred_infrastructure_endpoints", None) or []):
            addr_l = (infra.get("address") or "").lower()
            if addr_l and addr_l not in _existing:
                out.append(infra)
                _existing.add(addr_l)
    except Exception as _exc:  # noqa: BLE001 — best-effort augmentation
        log.warning(
            "emit_brief: infrastructure-endpoint augmentation failed (%s)",
            _exc,
        )
    return out


def emit_brief(
    case: Case,
    victim: VictimInfo,
    editorial: dict[str, Any],
    freeze_asks: dict[str, Any],
    issuer_metadata: dict[str, dict[str, Any]] | None = None,
    investigation_id: UUID | None = None,
) -> dict[str, Any]:
    """Assemble the final freeze_brief.json dict that build_triage.js consumes.

    v0.23.1: ``investigation_id`` (audit-fix CRIT-1) — when provided,
    flows through to cross-case correlation so address_observations
    rows are written with the investigation UUID populated. That
    unlocks the v0.23.0 multi-victim cluster detection (the cluster
    builder filters out NULL-investigation rows). Without this, the
    cluster feature is inert in production.
    """
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
    totals = _compute_totals(
        case, freezable, unrecoverable,
        all_issuer_holdings=all_issuer_holdings,
    )

    # --- Cross-chain handoffs (v0.8.1) --- v0.20.0 Phase C: extracted
    cross_chain_handoffs = _build_cross_chain_handoffs_section(case)

    # --- Entity clustering (v0.9.0) --- v0.20.0 Phase C: extracted
    entity_clusters = _build_entity_clusters_section(case, freezable)

    # --- Wallet clustering MVP (v0.31.0) ---
    # Complements ENTITY_CLUSTERS with tighter heuristics (Gap #4 of
    # the trace-completeness assessment). Stable sha256-derived
    # cluster IDs so cross-references in the brief survive re-emits.
    # Returns {"clusters": []} when nothing clusters together.
    wallet_clusters = _build_wallet_clusters_section(case)

    # --- Risk scoring (v0.9.1 + v0.10.0) --- v0.20.0 Phase C: extracted.
    # high_risk_db is returned alongside risk_assessment because the
    # next two subsystems (indirect_exposure, drainer_detection) need
    # the already-loaded DB; double-loading would burn extra I/O.
    risk_assessment, high_risk_db = _build_risk_assessment_section(case)

    # --- Indirect exposure (v0.10.0) --- v0.20.0 Phase C: extracted
    indirect_exposure = _build_indirect_exposure_section(case, high_risk_db)

    # --- Indirect exposure MVP (v0.31.0) --- complementary scoring.
    # The v0.10.0 section above carries the rich path-level attribution
    # (per-source IndirectPath records). This section adds the flat
    # 4-hop weight-decayed top-10 ranking that closes gap #3 from the
    # trace-completeness assessment. Returns None when no score crosses
    # the surface threshold, in which case the section key is omitted.
    indirect_exposure_v031 = _build_indirect_exposure_v031_section(
        case, high_risk_db,
    )

    # --- Drainer / incident classification (v0.10.1) --- v0.20.0 Phase C
    # Returns the brief-section view + the raw drainer_findings (the
    # downstream correlation pass consumes the raw findings, not the
    # section view).
    incident_classification, drainer_findings = (
        _build_incident_classification_section(case, high_risk_db)
    )

    # --- DEX swap unwrapping (v0.10.2) --- v0.20.0 Phase C: extracted
    dex_swaps = _build_dex_swaps_section(case)

    # --- MEV / sandwich obfuscation detection (v0.31.0, Gap #9) ---
    # Detection-only flag for hops whose tx-shape indicates Flashbots
    # bundle / sandwich / JIT-LP / MEV-builder-source funding. We do
    # not pretend to unwrap; the brief surfaces the flag so the
    # investigator picks up manual follow-up.
    mev_signals = _build_mev_signals_section(case)

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
        investigation_id=investigation_id,
    )

    # --- Class-action / cross-victim correlation (v0.14.3) --- v0.20.0 Phase C
    class_action_opportunity = _build_class_action_section(case, _case_uuid)

    # --- CEX trace continuity leads (v0.31.2, Gap #15) ---
    # OFF by default. Opt-in via RECUPERO_CEX_CONTINUITY=1. When a
    # large transfer lands in a labeled CEX hot wallet, fetch the
    # hot wallet's outbound transfers in a short window and surface
    # amount-matched candidates as LEADS (confidence=low). Not a
    # proof of re-emergence; CEX hot wallets commingle funds.
    # Returns [] when the feature is disabled OR no leads found —
    # the brief dict OMITS the section key on empty so existing
    # brief-key-set tests stay green.
    cex_continuity_leads = _build_cex_continuity_section(case)

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
        # v0.31.0: MVP wallet clustering (Gap #4 of the trace-
        # completeness assessment). Tighter heuristics than the v0.9
        # ENTITY_CLUSTERS pass (co-spending on Bitcoin, common CEX
        # withdrawal ≤1h, common funding ≤1h, bridge round-trip)
        # with stable sha256-derived cluster IDs. Only present when
        # 2+ addresses cluster together; otherwise the key is
        # OMITTED so existing consumers that assert on key sets stay
        # happy.
        **(
            {"WALLET_CLUSTERS": wallet_clusters}
            if wallet_clusters.get("clusters") else {}
        ),
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
        # v0.31.0: MVP 4-hop weight-decayed exposure scoring. Flat
        # {address: score} ranking that surfaces previously-invisible
        # 2/3-hop-removed mixer / OFAC / ransomware / darknet_market
        # / scam addresses. Closes gap #3 from the trace-completeness
        # assessment (TRM / Chainalysis parity at MVP fidelity). The
        # key is OMITTED from the brief when no scored address crosses
        # the 0.1 surface threshold (so existing tests / consumers
        # that assert on key sets stay happy). LE handoff template
        # consumes this in a later release.
        **(
            {"INDIRECT_EXPOSURE_V031": indirect_exposure_v031}
            if indirect_exposure_v031 is not None else {}
        ),
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
        # v0.31.0 (Gap #9): MEV / sandwich-attack obfuscation detection.
        # Surfaces hops whose tx-shape indicates Flashbots bundle /
        # sandwich / JIT-LP / MEV-builder-source funding. DETECT only —
        # the brief renders a "MEV-obfuscated transfers" panel when at
        # least one signal clears confidence ≥ 0.5 with a per-hop
        # investigator follow-up note. We don't pretend to unwrap (TRM
        # gets that via full block-shape reconstruction we lack); we
        # honestly flag the trace-discontinuity.
        "MEV_SIGNALS": mev_signals,
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
        # v0.31.2 (Gap #15): CEX trace continuity LEADS. OFF by
        # default — opt in via RECUPERO_CEX_CONTINUITY=1 (adapter
        # calls cost money). When stolen funds land in a labeled
        # CEX hot wallet, the trace stops there (KYC opaque). This
        # section flags amount-matched outbound transfers from the
        # SAME hot wallet within a tight time window as INVESTIGATIVE
        # LEADS — never as proven destinations. The key is OMITTED
        # from the brief on empty so existing brief-key-set tests
        # stay green.
        **(
            {"CEX_CONTINUITY_LEADS": cex_continuity_leads}
            if cex_continuity_leads else {}
        ),

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

    # v0.28.0 (Jacob review item 3): SUBPOENA_TARGETS — the
    # identified-but-non-freezable artifact family. For Zigha-shape
    # cases where the perpetrator-controlled position is real but
    # there's no issuer-freeze pathway (DAI / native ETH / Sky /
    # WETH), we still have leverage via the off-ramp CEX deposit's
    # KYC records. This pass walks the case's exchange endpoints +
    # editorial UNRECOVERABLE_ITEMS and emits structured subpoena-
    # ready records the renderer turns into subpoena_target_*.html +
    # subpoena_playbook_*.html artifacts. See
    # docs/v0.28_subpoena_targets_design.md and INVARIANTS C/D/E.
    try:
        from recupero.reports.subpoena_targets import extract_subpoena_targets
        # Build the dict shape the extractor expects, resolving each
        # endpoint's transfer_ids → tx-level evidence (#209 step 1; see
        # _subpoena_exchange_dicts).
        exchange_dicts = _subpoena_exchange_dicts(case)
        brief["SUBPOENA_TARGETS"] = extract_subpoena_targets(
            case=case,
            freeze_asks=freeze_asks,
            editorial=editorial,
            exchanges=exchange_dicts,
            unrecoverable=unrecoverable,
        )
    except Exception as _exc:  # noqa: BLE001
        # Never let a SUBPOENA_TARGETS extraction failure abort the
        # whole brief — log + emit empty list so the rest of the
        # pipeline proceeds. INVARIANT C will fire as a warning if
        # the absence is unexpected.
        #
        # v0.28.1 hardening: emit an _extraction_error sentinel so
        # downstream consumers (validator INVARIANT C, postmortem
        # tooling) can distinguish "no qualifying targets" (clean
        # empty list) from "extraction crashed" (sentinel present).
        # The sentinel surfaces in the brief JSON as a top-level
        # field operators can grep for.
        log.exception(
            "subpoena_targets extraction failed (%s); emitting empty "
            "list + _extraction_error sentinel for operator visibility",
            _exc,
        )
        brief["SUBPOENA_TARGETS"] = []
        brief["SUBPOENA_TARGETS_EXTRACTION_ERROR"] = (
            f"{type(_exc).__name__}: {_exc}"
        )

    # JACOB-EYEBALL fix: surface the stolen-asset block at top-level
    # so downstream readers (the output_integrity validator's check 8,
    # post-hoc inspection scripts, the API surface that exposes
    # freeze_brief to partners) can answer "what got stolen?" without
    # having to dig into FREEZABLE / theft_events / the trace.
    #
    # Previously this dict lived ONLY inside the per-letter Jinja
    # context built in generate_briefs(), so the validator's
    # stolen-vs-target check silently no-op'd whenever it ran against
    # the canonical brief JSON (the brief had no `asset` field). Now
    # the same fields appear here, derived from the primary theft
    # transfer + the issuer DB.
    try:
        from recupero.reports.brief import (
            _find_theft_events,
            _resolve_theft_asset_issuer_name,
        )
        theft_events = _find_theft_events(case)
        if theft_events:
            primary = theft_events[0]
            brief["asset"] = {
                "symbol": primary.token.symbol,
                "contract": primary.token.contract or "(native)",
                # Resolve the STOLEN-token issuer via contract DB lookup.
                # Falls back to the symbol when the contract isn't in
                # the seed DB (rare — only for non-listed assets).
                "issuer": _resolve_theft_asset_issuer_name(
                    primary, fallback=primary.token.symbol,
                ),
                "chain": getattr(primary, "chain", None) or _extract_primary_chain(case),
            }
        else:
            brief["asset"] = None
    except Exception as _exc:  # noqa: BLE001 — non-fatal
        log.warning(
            "emit_brief: stolen-asset block build failed: %s — "
            "validator check 8 will silently skip", _exc,
        )
        brief["asset"] = None

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


def run_emit_brief(
    case_id: str,
    case_store: CaseStore,
    *,
    investigation_id: UUID | None = None,
    dsn: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Top-level orchestration: load files, validate, assemble, write.

    Returns (output_path, brief_dict). Raises if preconditions missing.

    v0.21.0: optional ``investigation_id`` + ``dsn`` enable
    auto-subscription of perp wallets to live monitoring. When both
    are provided (worker pipeline path), every freezable destination
    + the perp hub get a monitoring_subscriptions row seeded with
    the investigator's email as the alert channel. When either is
    omitted (local CLI path), the brief is still emitted; only the
    monitoring bookkeeping is skipped.
    """
    case_dir = case_store.case_dir(case_id)

    # 1. Load case
    case = case_store.read_case(case_id)

    # 2. Load victim
    victim = load_victim(case_dir)

    # 3. Load freeze asks (may be missing if user hasn't run list-freeze-targets yet).
    # Tolerate a partially-corrupted file rather than crashing the whole brief
    # emission: a truncated freeze_asks.json (worker killed mid-write before the
    # v0.20.13 atomic-write fix, or an operator who hand-edited it) used to
    # raise JSONDecodeError and abort emit-brief entirely. Now: log + treat as
    # empty so the brief still lands; the freeze-ask side car can be regenerated
    # from `recupero list-freeze-targets` and emit-brief re-run.
    freeze_asks_path = case_dir / "freeze_asks.json"
    freeze_asks: dict[str, Any] = {}
    if freeze_asks_path.exists():
        try:
            freeze_asks = json.loads(
                freeze_asks_path.read_text(encoding="utf-8-sig"),
            )
        except json.JSONDecodeError as _exc:
            log.warning(
                "emit_brief: freeze_asks.json at %s is corrupt (%s) — "
                "proceeding with empty freeze-ask set. Regenerate via "
                "`recupero list-freeze-targets` and re-run emit-brief "
                "to recover.",
                freeze_asks_path, _exc,
            )
            freeze_asks = {}

    # 4. Load editorial (or write template and stop)
    editorial_path = case_dir / "brief_editorial.json"
    if not editorial_path.exists():
        write_editorial_template(case_dir)
        raise FileNotFoundError(
            f"Wrote template to {editorial_path}. Edit it (replace all TODO placeholders), "
            f"then re-run `recupero emit-brief {case_id}`."
        )
    editorial = load_editorial(case_dir)

    # 5. Assemble — v0.23.1 (audit-fix CRIT-1): pass investigation_id so
    # cross-case correlation writes address_observations rows with the
    # UUID populated, enabling cluster detection to fire in production.
    brief = emit_brief(
        case=case, victim=victim, editorial=editorial,
        freeze_asks=freeze_asks,
        investigation_id=investigation_id,
    )

    # 6. Write
    out_path = case_dir / "freeze_brief.json"
    # Atomic write so a concurrent reader (bucket uploader, portal) can't
    # pick up a half-written JSON.
    atomic_write_text(out_path, json.dumps(brief, indent=2, allow_nan=False, ensure_ascii=False))

    # 7. v0.21.0: auto-subscribe perp wallets to live monitoring.
    # Best-effort — a Supabase outage here must not break the brief
    # emission. The investigator can re-seed via the ops CLI if needed.
    if dsn:
        try:
            from recupero.monitoring.subscriber import auto_subscribe_from_brief
            inserted, skipped = auto_subscribe_from_brief(
                brief,
                case_id=case_id,
                investigation_id=investigation_id,
                investigator_email=brief.get("INVESTIGATOR_EMAIL") or None,
                dsn=dsn,
            )
            if inserted or skipped:
                log.info(
                    "emit_brief auto-subscribed perp wallets: "
                    "inserted=%d skipped=%d (case=%s)",
                    inserted, skipped, case_id,
                )
        except Exception as _exc:  # noqa: BLE001 — non-fatal
            log.warning(
                "emit_brief auto-subscribe step failed (non-fatal): %s",
                _exc,
            )

    # 8. v0.23.0: multi-victim cluster detection. Materializes the
    # case_clusters row + bridge when this case's perp wallets overlap
    # with prior cases. Surfaces the cluster summary onto the brief
    # dict (CLUSTER_MEMBERSHIP) so the LE handoff template can render
    # the "Multi-Victim Cluster" section. Best-effort; brief still
    # writes even when cluster bookkeeping fails.
    if dsn and investigation_id:
        try:
            from recupero.monitoring.cluster_builder import (
                build_or_update_cluster_for_case,
            )
            membership = build_or_update_cluster_for_case(
                brief,
                investigation_id=investigation_id,
                case_id=None,  # cases.id resolution lives in the worker
                dsn=dsn,
            )
            if membership is not None:
                # Re-write the brief JSON with the cluster info embedded.
                brief["CLUSTER_MEMBERSHIP"] = {
                    "cluster_id": str(membership.cluster_id) if membership.cluster_id else None,
                    "public_id": membership.public_id,
                    "is_new_cluster": membership.is_new_cluster,
                    "member_case_count": membership.member_case_count,
                    "co_victim_count": membership.co_victim_count,
                    "total_loss_usd": str(membership.total_loss_usd),
                    "total_loss_usd_human": (
                        f"${membership.total_loss_usd:,.2f}"
                        if membership.total_loss_usd is not None else "$0"
                    ),
                    "joined_via_address": membership.joined_via_address,
                    "joined_via_chain": membership.joined_via_chain,
                }
                atomic_write_text(out_path, json.dumps(brief, indent=2, allow_nan=False, ensure_ascii=False))
                log.info(
                    "emit_brief: case joined cluster %s "
                    "(members=%d co_victims=%d)",
                    membership.public_id,
                    membership.member_case_count,
                    membership.co_victim_count,
                )
        except Exception as _exc:  # noqa: BLE001
            log.warning(
                "emit_brief cluster-build step failed (non-fatal): %s",
                _exc,
            )

    return out_path, brief
