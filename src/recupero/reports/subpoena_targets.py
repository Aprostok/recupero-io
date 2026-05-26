"""SUBPOENA_TARGETS extraction (v0.28.0+, Jacob review item 3).

For positions where freeze_capability == "no" — DAI, WETH, native ETH,
Sky-issued tokens after first wrap, dormant EOAs — the existing
artifact family (freeze_request / le_handoff / victim_summary /
engagement_letter / recovery_snapshot / trace_report) has nowhere to
put them other than UNRECOVERABLE, which reads as a dead end.

These positions are NOT actually dead ends in real recovery work
(see docs/v0.28_subpoena_targets_design.md). The Zigha case is the
canonical example: ~$18M of dormant DAI at three Ethereum EOAs.
No issuer can freeze DAI (permissionless), but each receiving
address has on-chain history pointing to off-chain identifiers
(CEX deposits, dApp logins, ENS registrations, etc.) — each of
which has a subpoena recipient.

This module produces the SUBPOENA_TARGETS field — a list of
subpoena-ready records, each pointing at:
  * the recipient (CEX, ISP, KYC provider, dApp, ENS registrar)
  * the linked addresses (what we want records about)
  * the evidentiary basis (why this is a valid ask)
  * expected records (what we expect to receive)
  * follow-up pivots (what comes next)
  * priority + estimated response window

The renderer turns each entry into a subpoena_target_*.html
artifact + builds a single subpoena_playbook_*.html showing the
DAG of dependencies.

v0.28.0 scope: EVM-first. CEX-deposit recipients (label DB hit on
exchange_deposit / exchange_hot_wallet categories) + dormant-DAI
seizure-target framing. ISP / KYC-provider / ENS pivots ship as
follow-up entries (depends_on the CEX subpoena) without auto-
recipient resolution — that's an operator step until the v0.28.x
label DB expansion lands.

INVARIANTS in src/recupero/validators/output_integrity.py:
  C: every freeze_capability="no" destination above $1K USD has
     either (a) a SUBPOENA_TARGETS entry referencing it, or (b)
     an explicit UNRECOVERABLE entry with a `reason` field
     explaining why no subpoena pivot exists.
  D: every SUBPOENA_TARGETS entry resolves its depends_on
     references inside the same case's target list (no dangling
     pointers).
  E: subpoena_target_*.html files on disk == |SUBPOENA_TARGETS|
     × 1 + 1 (the playbook file).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────
# USD threshold below which we don't bother generating a subpoena.
# Operator can override later; $1K matches INVARIANT C from the design
# doc. Below this the legal-process overhead exceeds expected recovery
# value.
# ─────────────────────────────────────────────────────────────────────
SUBPOENA_USD_THRESHOLD = Decimal("1000")


# Map: exchange display name (lower-case) → operator-curated
# compliance contact. Source: each exchange's published compliance/
# legal/abuse address. Operators may override via env or
# subpoena_recipient_overrides.json at case dir. Curated minimally
# for the v0.28.0 ship; expand from Chainalysis / TRM directories in
# a v0.28.x label DB expansion.
_KNOWN_CEX_COMPLIANCE = {
    "mexc":      ("MEXC Global",       "compliance@mexc.com",     "Seychelles", 30, "medium"),
    "binance":   ("Binance Holdings",  "leinquiries@binance.com", "Cayman Islands", 21, "high"),
    "coinbase":  ("Coinbase, Inc.",    "subpoenas@coinbase.com",  "USA",        14, "high"),
    "kraken":    ("Kraken",            "complianceeu@kraken.com", "USA",        21, "high"),
    "bybit":     ("Bybit",             "compliance@bybit.com",    "Dubai",      30, "medium"),
    "kucoin":    ("KuCoin",            "compliance@kucoin.com",   "Seychelles", 30, "medium"),
    "okx":       ("OKX",               "compliance@okx.com",      "Seychelles", 30, "medium"),
    "gate.io":   ("Gate.io",           "compliance@gate.io",      "Cayman",     30, "medium"),
    "bitget":    ("Bitget",            "compliance@bitget.com",   "Seychelles", 30, "medium"),
    "huobi":     ("Huobi / HTX",       "compliance@htx.com",      "Seychelles", 30, "low"),
    "htx":       ("Huobi / HTX",       "compliance@htx.com",      "Seychelles", 30, "low"),
    "crypto.com": ("Crypto.com",       "compliance@crypto.com",   "Singapore",  21, "high"),
    "gemini":    ("Gemini",            "compliance@gemini.com",   "USA",        14, "high"),
    "bitstamp":  ("Bitstamp",          "compliance@bitstamp.net", "Luxembourg", 21, "high"),
}


@dataclass
class _LabelHit:
    """One hit from the label DB."""
    address: str
    category: str
    name: str
    exchange: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


def _load_operator_overrides() -> dict[str, tuple]:
    """v0.28.3 hardening (audit finding #31): read operator-supplied
    CEX compliance overrides from an env-var pointer.

    Set RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE to a JSON file path.
    Schema: {exchange_key_lowercase: [name, email, jurisdiction,
    days, priority]} where days is int and priority is one of
    "high"/"medium"/"low". Unknown keys are ignored; values that
    fail shape validation are logged + skipped.

    Returns the canonical map merged with overrides (overrides win
    on key collision).
    """
    import json
    import os
    out = dict(_KNOWN_CEX_COMPLIANCE)
    override_path = os.environ.get(
        "RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE", "",
    ).strip()
    if not override_path:
        return out
    try:
        with open(override_path, encoding="utf-8") as f:
            overrides = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning(
            "RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE failed to load "
            "%s: %s", override_path, exc,
        )
        return out
    if not isinstance(overrides, dict):
        log.warning(
            "RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE root is not a "
            "JSON object; ignoring.",
        )
        return out
    for k, v in overrides.items():
        if not isinstance(k, str) or not isinstance(v, list) or len(v) != 5:
            log.warning(
                "RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE entry %r has "
                "wrong shape (must be [name,email,jurisdiction,days,"
                "priority]); skipping.", k,
            )
            continue
        name, email, jurisdiction, days, prio = v
        if (not isinstance(name, str) or "@" not in str(email)
            or not isinstance(jurisdiction, str)
            or not isinstance(days, int) or days < 1 or days > 365
            or prio not in ("high", "medium", "low")):
            log.warning(
                "RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE entry %r has "
                "invalid values; skipping.", k,
            )
            continue
        out[k.lower()] = (name, email, jurisdiction, days, prio)
    return out


def _resolve_cex_recipient(
    exchange_raw: str | None,
) -> dict[str, Any] | None:
    """Look up CEX compliance contact + jurisdiction by exchange
    display name. Case-insensitive; tries exact, then substring
    match (handles 'Binance Hot Wallet 14' → 'binance').

    v0.28.3: respects operator overrides via the
    RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE env var (see
    _load_operator_overrides docstring). Override values are
    merged onto _KNOWN_CEX_COMPLIANCE at lookup time, so a typo'd
    compliance email in production can be corrected without a
    code redeploy.
    """
    if not isinstance(exchange_raw, str):
        return None
    exchange = exchange_raw.strip().lower()
    if not exchange:
        return None
    compliance_map = _load_operator_overrides()
    if exchange in compliance_map:
        name, email, jurisdiction, days, prio = compliance_map[exchange]
        return {
            "recipient_name": name,
            "recipient_compliance_email": email,
            "recipient_jurisdiction": jurisdiction,
            "estimated_response_window_days": days,
            "priority": prio,
        }
    # Substring fallback (handles "Binance 8" / "Binance Hot Wallet 14").
    for k, v in compliance_map.items():
        if k in exchange:
            name, email, jurisdiction, days, prio = v
            return {
                "recipient_name": name,
                "recipient_compliance_email": email,
                "recipient_jurisdiction": jurisdiction,
                "estimated_response_window_days": days,
                "priority": prio,
            }
    return None


# Regex to extract a dollar amount from a free-form `asset` string
# (matches the editorial UNRECOVERABLE_ITEMS shape). Same pattern
# as _compute_perpetrator_holdings — first $-amount wins.
_USD_IN_STRING_RE = re.compile(r"\$([0-9,]+(?:\.[0-9]+)?)")


def _sanitize_usd(d: Decimal) -> Decimal:
    """v0.28.1 hardening: reject NaN / Inf / negative Decimal values.
    A Decimal('NaN') compared with `< Decimal('1000')` raises
    InvalidOperation, which the emit_brief try/except would silently
    swallow into an empty SUBPOENA_TARGETS list. We canonicalize at
    the parse boundary so the rest of the module can assume positive
    finite values.

    Negative amounts are coerced to 0 — they have no meaning in this
    context (a CEX deposit can't be -$X). Inf / NaN clamp to 0.
    """
    if d.is_nan() or d.is_infinite():
        return Decimal("0")
    if d < 0:
        return Decimal("0")
    return d


def _parse_usd_from_str(s: object) -> Decimal:
    """Free-form USD amount → Decimal. Returns 0 on parse failure,
    NaN / Inf, or negative input. The caller can assume non-negative
    finite output."""
    if not isinstance(s, str):
        return Decimal("0")
    s = s.strip().lstrip("$").replace(",", "").replace(" ", "")
    if not s:
        return Decimal("0")
    try:
        return _sanitize_usd(Decimal(s))
    except (ValueError, InvalidOperation):
        return Decimal("0")


def _parse_usd_from_asset_string(s: object) -> Decimal:
    """Editorial UNRECOVERABLE_ITEMS carry a free-form `asset` string
    like 'approximately 9.98M DAI (~$9,980,000)'. We regex-extract
    the first $-prefixed number."""
    if not isinstance(s, str):
        return Decimal("0")
    m = _USD_IN_STRING_RE.search(s)
    if not m:
        return Decimal("0")
    try:
        return _sanitize_usd(Decimal(m.group(1).replace(",", "")))
    except (ValueError, InvalidOperation):
        return Decimal("0")


def _slugify(s: str) -> str:
    """Convert a recipient name into a filename-safe slug. Lowercase,
    alphanumeric + dashes."""
    if not isinstance(s, str):
        return "unknown"
    out = "".join(c.lower() if c.isalnum() else "-" for c in s).strip("-")
    out = re.sub(r"-+", "-", out)
    return out or "unknown"


def extract_subpoena_targets(
    *,
    case: Any,                       # Case (typed loosely for testability)
    freeze_asks: dict[str, Any],
    editorial: dict[str, Any] | None,
    label_db: Any | None = None,     # LabelStore (typed loosely)
    destinations: list[dict[str, Any]] | None = None,
    unrecoverable: list[dict[str, Any]] | None = None,
    exchanges: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Produce the SUBPOENA_TARGETS list for a case.

    Inputs (all optional except `case`):
      * ``freeze_asks``: the freeze-asks payload (used for rejected
        non-freezable rows + the by_issuer map).
      * ``editorial``: the editorial JSON (UNRECOVERABLE_ITEMS +
        identified subpoena pivots).
      * ``label_db``: the LabelStore (used to resolve recipient
        identity from on-chain address). If None, we fall back to
        exchange labels carried by freeze_asks / exchanges.
      * ``destinations`` / ``unrecoverable`` / ``exchanges``: pre-
        computed brief sections from emit_brief; if omitted, we
        derive them from case + freeze_asks.

    Output: a list of dicts matching the schema in
    docs/v0.28_subpoena_targets_design.md. Stable ordering: highest
    USD value first; ties broken by recipient name. Empty list when
    no qualifying targets exist (most freezable cases).
    """
    out: list[dict[str, Any]] = []
    target_idx = 0

    # ── Step 1: CEX off-ramp subpoenas ──
    # For every exchange-labeled destination above the threshold,
    # emit a CEX subpoena. The exchange's compliance contact (+
    # jurisdiction + expected window) comes from the
    # _KNOWN_CEX_COMPLIANCE map.
    exchanges_list = exchanges or []
    if not exchanges_list:
        # Fall back: scan freeze_asks for exchange_deposits entries
        # if the brief assembler hasn't already passed them in.
        ex_section = freeze_asks.get("exchange_deposits") if isinstance(freeze_asks, dict) else None
        if isinstance(ex_section, list):
            exchanges_list = ex_section

    cex_targets_by_recipient: dict[str, dict[str, Any]] = {}
    for ex in exchanges_list:
        if not isinstance(ex, dict):
            continue
        addr = ex.get("address")
        if not isinstance(addr, str):
            continue
        # Dollar amount: try multiple fields the various callers may
        # populate; default to 0 for safety.
        amt = (
            _parse_usd_from_str(ex.get("total_received_usd"))
            or _parse_usd_from_str(ex.get("usd"))
            or _parse_usd_from_str(ex.get("amount_usd"))
        )
        if amt < SUBPOENA_USD_THRESHOLD:
            continue
        recipient_info = _resolve_cex_recipient(
            ex.get("exchange") or ex.get("label_name"),
        )
        if recipient_info is None:
            # Unknown exchange — still emit a generic subpoena with
            # placeholder fields the operator must fill in. The
            # invariants only check that something is emitted.
            recipient_info = {
                "recipient_name": str(ex.get("exchange") or "(unknown CEX)"),
                "recipient_compliance_email": None,
                "recipient_jurisdiction": "(unknown — operator to research)",
                "estimated_response_window_days": 30,
                "priority": "low",
            }

        recipient_key = recipient_info["recipient_name"]
        existing = cex_targets_by_recipient.get(recipient_key)
        if existing is not None:
            # Multiple deposits at the same exchange → one
            # consolidated subpoena listing every address.
            existing["linked_addresses"].append({
                "address": addr,
                "chain": ex.get("chain") or getattr(case, "chain", None) and case.chain.value,
                "role": "off-ramp deposit (perpetrator-owned)",
                "evidence": [{
                    "amount_usd": str(amt),
                    "label_source": ex.get("source") or "label_db",
                }],
            })
            # Aggregate total USD for sort ordering.
            existing["_total_usd"] += amt
            continue

        target_idx += 1
        cex_targets_by_recipient[recipient_key] = {
            "target_id": f"subpoena-{target_idx}",
            "recipient_type": "cex",
            **recipient_info,
            "evidentiary_basis": "off_ramp_deposit",
            "linked_addresses": [{
                "address": addr,
                "chain": ex.get("chain") or (
                    getattr(case, "chain", None) and case.chain.value
                ),
                "role": "off-ramp deposit (perpetrator-owned)",
                "evidence": [{
                    "amount_usd": str(amt),
                    "label_source": ex.get("source") or "label_db",
                }],
            }],
            "expected_records": [
                "subscriber identity (name, email, phone, country)",
                "KYC documents on file (govt ID, proof of address)",
                "IP log for the relevant deposit / withdrawal / login window",
                "linked accounts via shared funding source / KYC overlap",
                "device fingerprint history (User-Agent, advertising IDs)",
            ],
            "follow_up_pivots": [
                {"if_records_show": "ip_address",
                 "next_target_type": "isp",
                 "notes": "ISP subpoena for subscriber identity at the IP"},
                {"if_records_show": "linked_account",
                 "next_target_type": "cex",
                 "notes": "Subpoena the linked exchange for fuller history"},
                {"if_records_show": "kyc_identity",
                 "next_target_type": "law_enforcement",
                 "notes": "Identity confirmed → file seizure / arrest"},
            ],
            "instrument": "grand_jury_subpoena",
            "case_role": "off_ramp",
            "depends_on": [],
            "_total_usd": amt,  # private; used for sort then stripped
        }

    # ── Step 2: Dormant non-freezable seizure-target framing ──
    # For UNRECOVERABLE_ITEMS (DAI / native ETH / Sky / WETH) above
    # the threshold, emit a seizure-target entry. These don't have
    # an issuer recipient — the recipient is law enforcement once a
    # perpetrator is identified. The follow-up pivot is "wait for
    # CEX subpoena response → identity → seizure order."
    unrec = unrecoverable
    if unrec is None and isinstance(editorial, dict):
        unrec = editorial.get("UNRECOVERABLE_ITEMS") or []
    if unrec is None:
        unrec = []

    for u in unrec:
        if not isinstance(u, dict):
            continue
        addr = u.get("address")
        # editorial UNRECOVERABLE_ITEMS sometimes carry addresses
        # only inside `asset` text; we accept either an explicit
        # `address` field or a regex extraction from `asset`. For
        # invariant compliance we DO want an address.
        amt = _parse_usd_from_asset_string(u.get("asset"))
        if amt < SUBPOENA_USD_THRESHOLD:
            continue
        target_idx += 1
        out.append({
            "target_id": f"subpoena-{target_idx}",
            "recipient_type": "law_enforcement",
            "recipient_name": "Identified law enforcement agency",
            "recipient_jurisdiction": "TBD (operator to confirm)",
            "recipient_compliance_email": None,
            "evidentiary_basis": "non_freezable_seizure_target",
            "linked_addresses": [{
                "address": addr or "(see asset string)",
                "chain": u.get("chain") or (
                    getattr(case, "chain", None) and case.chain.value
                ),
                "role": "dormant non-freezable holder",
                "evidence": [{
                    "asset": u.get("asset", ""),
                    "reason": u.get("reason", ""),
                    "amount_usd": str(amt),
                }],
            }],
            "expected_records": [
                "seizure order against the address (post-perp identification)",
                "freeze-and-hold instruction to network validators if applicable",
            ],
            "follow_up_pivots": [
                {"if_records_show": "perp_identified",
                 "next_target_type": "law_enforcement",
                 "notes": "Identity confirmed → file seizure order"},
            ],
            "instrument": "seizure_order",
            "estimated_response_window_days": 90,
            "priority": "high" if amt >= Decimal("100000") else "medium",
            "case_role": "non_freezable_holding",
            # Default: depends on every CEX subpoena (identity must
            # be established before seizure can be filed).
            "depends_on": [
                t["target_id"] for t in cex_targets_by_recipient.values()
            ],
            "_total_usd": amt,
        })

    # Merge CEX targets in, then sort + strip private keys.
    out.extend(cex_targets_by_recipient.values())
    out.sort(
        key=lambda t: (-t.get("_total_usd", Decimal("0")), t.get("recipient_name", "")),
    )
    for t in out:
        t.pop("_total_usd", None)

    # Re-number target_ids to a stable [subpoena-1, subpoena-2, ...]
    # ordering. The depends_on references must be rewritten to match.
    old_to_new = {t["target_id"]: f"subpoena-{i+1}" for i, t in enumerate(out)}
    for t in out:
        t["target_id"] = old_to_new[t["target_id"]]
        t["depends_on"] = [old_to_new.get(d, d) for d in t.get("depends_on", [])]
        # recipient_slug used by the renderer for filename.
        t["recipient_slug"] = _slugify(t.get("recipient_name", "unknown"))

    return out


__all__ = (
    "extract_subpoena_targets",
    "SUBPOENA_USD_THRESHOLD",
    "_resolve_cex_recipient",  # exported for testing
    "_KNOWN_CEX_COMPLIANCE",
)
