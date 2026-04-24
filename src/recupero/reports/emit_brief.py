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
import re
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from recupero.models import Case, LabelCategory
from recupero.reports.victim import VictimInfo, load_victim
from recupero.storage.case_store import CaseStore


EDITORIAL_TEMPLATE: dict[str, Any] = {
    "CASE_ID": "TODO: fill in (e.g. RCP-2026-0427)",
    "REPORT_DATE": "TODO: human-readable report date (e.g. 'April 20, 2026')",
    "INCIDENT_DATE": "TODO: human-readable incident date (e.g. 'April 19, 2026')",
    "INCIDENT_TYPE": "TODO: one-line description (e.g. 'wallet drainer via phishing site posing as Uniswap governance')",
    "PRIMARY_CHAIN": "TODO: chain name for display (e.g. 'Ethereum')",
    "INCIDENT_NARRATIVE_RECUPERO": "TODO: Recupero-voice narrative (3-5 sentences, third person, describes what happened and what the trace shows).",
    "INCIDENT_NARRATIVE_FIRST_PERSON": "TODO: Victim-voice narrative (3-5 sentences, first person 'I', for the LE report and letters the victim signs).",
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
    "INVESTIGATOR_NAME": "Alec Prostok",
    "INVESTIGATOR_EMAIL": "alec@recupero.io",
    "INVESTIGATOR_ENTITY": "Recupero LLC",
    "INVESTIGATOR_ENTITY_FULL": "Recupero LLC, a Delaware limited liability company",
    "INVESTIGATOR_WEB": "recupero.io",
    "TEMPLATE_VERSION": "v1.0 — April 2026",
}


def _now_utc_iso_seconds() -> str:
    """UTC timestamp, second precision, ISO 8601 with trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_usd_string(s: str) -> Decimal:
    """Parse '$47,840.12' -> Decimal('47840.12'). Returns Decimal('0') on failure."""
    s = str(s).replace("$", "").replace(",", "").strip()
    try:
        return Decimal(s)
    except Exception:
        return Decimal("0")


def short_addr(addr: str) -> str:
    """Shorten an address for display: 0xAAAAbbbb...XXXXyyyy -> 0xAA…yy (ethscan style)."""
    if len(addr) <= 10:
        return addr
    return f"{addr[:6]}…{addr[-4:]}"


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

    # Sum USD received per counterparty among transfers leaving the victim wallet
    per_addr_usd: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    per_addr_first_seen: dict[str, datetime] = {}

    seed_lower = case.seed_address.lower()
    for t in case.transfers:
        if t.from_address.lower() == seed_lower:
            to = t.to_address
            if t.usd_value_at_tx is not None:
                per_addr_usd[to] += t.usd_value_at_tx
            if to not in per_addr_first_seen or t.block_time < per_addr_first_seen[to]:
                per_addr_first_seen[to] = t.block_time

    if not per_addr_usd:
        # Victim never sent anything? Fall back to first outflow counterparty.
        return None

    hub_addr = max(per_addr_usd.items(), key=lambda kv: kv[1])[0]
    hub_usd = per_addr_usd[hub_addr]
    hub_first_seen = per_addr_first_seen[hub_addr]

    return {
        "address": hub_addr,
        "address_short": short_addr(hub_addr),
        "chain": _extract_primary_chain(case),
        "first_seen": hub_first_seen.isoformat().replace("+00:00", "Z"),
        "usd_received": usd(hub_usd),
    }


def _extract_destinations(
    case: Case,
    editorial_notes: dict[str, str],
    freeze_targets_by_addr: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the DESTINATIONS list for the report.

    Each destination is a downstream address with USD flowing INTO it from
    the trace. We rank by recent USD value (freeze targets high, others by
    received total).

    The list is filtered to addresses the AI editorial explicitly labeled
    (i.e., addresses present in editorial_notes). This keeps the customer-
    facing list to the ~10 addresses that matter, rather than the 100+
    addresses the trace touched (token contracts, intermediaries, etc.).
    If editorial_notes is empty (no AI editorial run), we fall back to
    the full ranked list so the report still works.
    """
    # Aggregate: for each downstream address, sum of USD received in trace,
    # and figure a role from counterparty labels.
    per_addr_received: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    per_addr_label_name: dict[str, str | None] = {}
    per_addr_category: dict[str, str | None] = {}
    per_addr_is_mixer: dict[str, bool] = defaultdict(bool)

    for t in case.transfers:
        to = t.to_address
        if t.usd_value_at_tx is not None:
            per_addr_received[to] += t.usd_value_at_tx
        if t.counterparty.address == to and t.counterparty.label:
            per_addr_label_name[to] = t.counterparty.label.name
            per_addr_category[to] = t.counterparty.label.category.value
            if t.counterparty.label.category == LabelCategory.mixer:
                per_addr_is_mixer[to] = True

    # Only include addresses the AI editorial explicitly labeled.
    # Fall back to all addresses if no editorial labels exist.
    if editorial_notes:
        candidate_addrs = [a for a in per_addr_received.keys() if a in editorial_notes]
    else:
        candidate_addrs = list(per_addr_received.keys())

    destinations = []
    for addr in sorted(candidate_addrs, key=lambda a: per_addr_received[a], reverse=True):
        label_name = per_addr_label_name.get(addr)
        is_freezable = addr in freeze_targets_by_addr
        is_mixer = per_addr_is_mixer[addr]

        # Role inference
        if is_freezable:
            freeze_info = freeze_targets_by_addr[addr]
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

        # Editorial note if provided, otherwise mechanical
        notes = editorial_notes.get(addr, f"Received {usd(per_addr_received[addr])} in trace")

        # Status from editorial classification (drives JS rendering)
        status = _classify_address_status(addr, editorial_notes)

        destinations.append({
            "address": addr,
            "short": short_addr(addr),
            "role": role,
            "usd_holding_now": holding_now,
            "usd_received_in_trace": usd(per_addr_received[addr]),
            "status": status,
            "notes": notes,
        })

    return destinations


def _classify_address_status(addr: str, editorial_notes: dict[str, str]) -> str:
    """Classify an address based on the AI editorial's emoji-prefixed note.

    Returns one of:
      "FREEZABLE"    — 🟩 prefix; address is confirmed in-scope and freezable
      "INVESTIGATE"  — 🟧 prefix; needs reviewer judgment, do NOT count in headline freezable total
      "UNRECOVERABLE" — ⬛ prefix; mixer/DEX-aggregator/bystander contract; exclude from freezable total
      "EXCHANGE"     — 🟦 prefix; CEX deposit address; goes through MLAT/subpoena, not issuer freeze
      "TRANSIT"      — has a note but no emoji prefix; perpetrator-controlled but no current balance
      "UNKNOWN"      — no editorial note for this address (default conservative)

    The classification drives whether a holding contributes to TOTAL_FREEZABLE_USD
    (only "FREEZABLE" status counts). Other statuses are surfaced separately so
    the JS builder can render them without including them in headline numbers.
    """
    note = editorial_notes.get(addr, "")
    if not isinstance(note, str):
        return "UNKNOWN"
    note = note.lstrip()  # tolerate whitespace before emoji
    if note.startswith("🟩"):
        return "FREEZABLE"
    if note.startswith("🟧"):
        return "INVESTIGATE"
    if note.startswith("⬛"):
        return "UNRECOVERABLE"
    if note.startswith("🟦"):
        return "EXCHANGE"
    if note:  # has a note but no recognized emoji
        return "TRANSIT"
    return "UNKNOWN"


def _extract_freezable(freeze_asks: dict[str, Any], issuer_metadata: dict[str, dict[str, Any]], editorial_notes: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Translate freeze_asks.json's by_issuer structure into the FREEZABLE format.

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
            status = _classify_address_status(addr, editorial_notes)

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
                "amount": f"{a.get('amount', '?')} {a.get('symbol', '')}",
                "usd": usd(holding_usd),
                "status": status,
            })

        # Map CLI's freeze_capability to display capability
        cap_display = {
            "yes": "HIGH",
            "limited": "MEDIUM",
            "no": "LOW",
        }.get(capability, "UNKNOWN")

        # Look up extras from issuer_metadata if present
        meta = issuer_metadata.get(issuer_name, {})

        freezable.append({
            "issuer": issuer_name,
            "token": symbol or "?",
            "total_usd": usd(total_usd),
            "total_suspected_usd": usd(total_suspected_usd),
            "total_excluded_usd": usd(total_excluded_usd),
            "freeze_capability": cap_display,
            "holdings": holdings,
            "contact_email": meta.get("contact_email") or primary_contact or "",
            "portal_url": meta.get("portal_url", ""),
            "typical_response_time": meta.get("typical_response_time", "Variable"),
            "freeze_note": meta.get("freeze_note", ""),
        })

    return freezable


def _compute_total_drained(case: Case) -> Decimal:
    """Sum the USD value of transfers leaving the victim's seed wallet.

    This is the actual loss figure — the amount the victim was drained of at
    the moment of the incident — and should be used as TOTAL_LOSS_USD in the
    headline numbers, NOT a sum of current freezable + unrecoverable balances
    (which can be inflated by bystander wallets caught in graph expansion).
    """
    seed_lower = case.seed_address.lower()
    total = Decimal("0")
    for t in case.transfers:
        if t.from_address.lower() == seed_lower and t.usd_value_at_tx is not None:
            total += t.usd_value_at_tx
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
        freezable_pct = f"{int(pct)}%"
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
        recoverable_pct = f"{int(pct)}%"

    return {
        "TOTAL_LOSS_USD": usd(total_loss),
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
    path.write_text(json.dumps(EDITORIAL_TEMPLATE, indent=2), encoding="utf-8")
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
    for issuer, asks in freeze_asks.get("by_issuer", {}).items():
        for ask in asks:
            freeze_targets_by_addr[ask["address"]] = {**ask, "issuer": issuer}

    editorial_notes = editorial.get("DESTINATION_NOTES", {}) or {}
    # Filter out any placeholder keys
    editorial_notes = {k: v for k, v in editorial_notes.items() if not k.startswith("TODO")}

    destinations = _extract_destinations(case, editorial_notes, freeze_targets_by_addr)

    # --- Freezable list ---
    # Pass editorial_notes so each holding gets a `status` field and the
    # per-issuer `total_usd` only sums FREEZABLE-status holdings.
    freezable = _extract_freezable(freeze_asks, issuer_metadata, editorial_notes)

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
        "INCIDENT_NARRATIVE_RECUPERO": editorial["INCIDENT_NARRATIVE_RECUPERO"],
        "INCIDENT_NARRATIVE_FIRST_PERSON": editorial["INCIDENT_NARRATIVE_FIRST_PERSON"],

        "PERP_HUB": perp_hub,
        "DESTINATIONS": destinations,
        "FREEZABLE": freezable,
        "UNRECOVERABLE": unrecoverable,
        "EXCHANGES": exchanges,

        "TOTAL_FREEZABLE_USD": totals["TOTAL_FREEZABLE_USD"],
        "TOTAL_SUSPECTED_USD": totals["TOTAL_SUSPECTED_USD"],
        "TOTAL_EXCLUDED_USD": totals["TOTAL_EXCLUDED_USD"],
        "TOTAL_UNRECOVERABLE_USD": totals["TOTAL_UNRECOVERABLE_USD"],
        "MAX_RECOVERABLE_USD": totals["MAX_RECOVERABLE_USD"],
        "FREEZABLE_PERCENT": totals["FREEZABLE_PERCENT"],
        "RECOVERABLE_PERCENT": totals["RECOVERABLE_PERCENT"],

        "IC3_COMPLAINT_NUMBER": None,

        "INVESTIGATOR_NAME": editorial["INVESTIGATOR_NAME"],
        "INVESTIGATOR_EMAIL": editorial["INVESTIGATOR_EMAIL"],
        "INVESTIGATOR_ENTITY": editorial["INVESTIGATOR_ENTITY"],
        "INVESTIGATOR_ENTITY_FULL": editorial["INVESTIGATOR_ENTITY_FULL"],
        "INVESTIGATOR_WEB": editorial["INVESTIGATOR_WEB"],
        "TEMPLATE_VERSION": editorial["TEMPLATE_VERSION"],
    }
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
    out_path.write_text(json.dumps(brief, indent=2), encoding="utf-8")
    return out_path, brief
