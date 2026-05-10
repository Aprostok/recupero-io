"""Material-change detection for follow-up investigations.

When a case is in monitoring state, the cron job (Jacob's side) inserts
a new investigation row each night. The worker then traces, finds
freeze targets, and BEFORE running the editorial, compares today's
freeze_asks.json to the prior investigation's. If nothing material
changed, we skip editorial entirely — biggest cost lever in the
nightly monitoring pipeline.

Material change is defined at the freeze_asks level (NOT at
max_recoverable_usd, which is editorial-derived). The set of
``(issuer, address)`` tuples and per-tuple USD value tells us
everything we need to decide "did anything important happen on-chain
since last time" without paying Anthropic to find out.

Public surface:

    DiffResult           — dataclass returned by run_diff_stage
    run_diff_stage(...)  — main entry point, called from pipeline.py
    compute_freeze_asks_diff(prior, current) -> dict
                         — pure function, the comparison logic
    build_summary_text(diff) -> str
                         — one-line English summary for UI list views

The pure functions are heavily tested. The I/O wrapper
(``run_diff_stage``) is the only piece that touches DB / bucket and
is integration-tested via the worker pipeline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID

log = logging.getLogger(__name__)


# ----- Thresholds for "material change" ----- #
# A USD-value delta on an existing (issuer, address) freeze ask is
# considered material if it exceeds EITHER threshold. Pure relative
# would let a $50K wallet drift unflagged at 4.9% = $2,450, which is
# operator-relevant. Pure absolute would over-fire on small wallets
# whose value moves by a few dollars due to spot-price drift.
#
# Both numbers are tunable. Bump them down to trigger more sensitively;
# bump them up to reduce alert volume. Symmetric for shrinkage (funds
# moved OUT) — the same thresholds apply in either direction since
# both are actionable.
DELTA_USD_THRESHOLD = Decimal("1000")
DELTA_PCT_THRESHOLD = Decimal("5.0")


# ----- Result dataclass ----- #


@dataclass
class DiffResult:
    """Output of ``run_diff_stage``. Maps directly to the four columns
    Jacob is adding to ``public.investigations``."""

    is_followup: bool
    """True iff this run had a prior complete investigation to compare against."""

    prior_id: UUID | None
    """Points at the row we compared to. None on first-ever runs."""

    material_change: bool
    """The headline flag. Drives Jacob's alert UI + email notifications."""

    summary: dict | None
    """Structured diff. None on first-ever runs (no comparison done).
    {} when compared but no material change. Populated dict when
    material change detected."""


# ----- Main entry point (called from pipeline.py) ----- #


def run_diff_stage(
    *,
    investigation_id: UUID,
    case_id: UUID,
    current_freeze_asks: dict[str, Any],
    fetch_prior_complete: "callable[[UUID, UUID], tuple[UUID, dict] | None]",
) -> DiffResult:
    """Compare the just-finished freeze_asks.json to the prior complete
    investigation's. Returns a DiffResult ready to write to the row.

    ``fetch_prior_complete`` is a caller-supplied function that returns
    ``(prior_inv_id, prior_freeze_asks_dict)`` for the most recent
    completed investigation on the same case_id, or None if there isn't
    one. Injected as a callable so this function is testable without
    psycopg / httpx mocks.

    The pipeline integration in ``worker/pipeline.py`` provides the
    callable as a closure over the DB + bucket store.
    """
    prior = fetch_prior_complete(case_id, investigation_id)
    if prior is None:
        return DiffResult(
            is_followup=False,
            prior_id=None,
            material_change=False,
            summary=None,
        )

    prior_id, prior_freeze_asks = prior
    if prior_id == investigation_id:
        # Should never happen with FOR UPDATE SKIP LOCKED, but if a
        # bug ever produced self-comparison the silent always-empty
        # diff would be a worse failure mode than crashing.
        log.error(
            "diff: self-comparison sentinel hit for investigation %s — aborting",
            investigation_id,
        )
        raise ValueError(
            f"diff stage self-comparison: prior_id == current_id "
            f"({investigation_id}) — indicates a re-claim bug or stale data"
        )

    diff = compute_freeze_asks_diff(prior_freeze_asks, current_freeze_asks)
    material = (
        bool(diff["new_asks"])
        or bool(diff["removed_asks"])
        or _any_changed_amount_material(diff["changed_amounts"])
    )
    diff["summary_text_for_ui"] = build_summary_text(diff)
    diff["thresholds"] = {
        "delta_usd": str(DELTA_USD_THRESHOLD),
        "delta_pct": str(DELTA_PCT_THRESHOLD),
    }

    return DiffResult(
        is_followup=True,
        prior_id=prior_id,
        material_change=material,
        summary=diff if material else {"summary_text_for_ui": diff["summary_text_for_ui"]},
    )


# ----- Pure compute (heavily tested) ----- #


def compute_freeze_asks_diff(
    prior: dict[str, Any] | None,
    current: dict[str, Any] | None,
) -> dict[str, Any]:
    """Diff two freeze_asks.json bodies. Returns a structured dict.

    Shape is stable — every key is always present, lists are sorted,
    so two diffs of equivalent inputs produce byte-identical output.
    That matters for idempotency: re-running a stale claim shouldn't
    write subtly different change_summary on retry.

    None / missing inputs are treated as empty asks. That handles the
    edge case where a prior investigation didn't produce a freeze_asks
    file (e.g., trace failed mid-stage but the row was marked complete
    by a manual operator override).
    """
    prior_asks = _flatten(prior or {})
    current_asks = _flatten(current or {})

    prior_keys = set(prior_asks.keys())
    current_keys = set(current_asks.keys())

    new_keys = current_keys - prior_keys
    removed_keys = prior_keys - current_keys
    common_keys = prior_keys & current_keys

    changed_amounts: list[dict[str, Any]] = []
    for key in sorted(common_keys):
        prior_usd = prior_asks[key]["usd_value"]
        current_usd = current_asks[key]["usd_value"]
        if prior_usd == current_usd:
            continue
        delta_usd = current_usd - prior_usd
        delta_pct = (delta_usd / prior_usd * Decimal(100)) if prior_usd > 0 else Decimal(0)
        changed_amounts.append({
            "issuer": key[0],
            # Preserve original-case address from the current ask (key[1]
            # is lowercased for case-insensitive matching only).
            "address": current_asks[key]["address"],
            "symbol": key[2],
            "prior_usd": _money(prior_usd),
            "current_usd": _money(current_usd),
            "delta_usd": _money(delta_usd),
            "delta_pct": _percent(delta_pct),
        })

    new_freezable_issuers = sorted(
        {k[0] for k in new_keys} - {k[0] for k in prior_keys}
    )
    removed_freezable_issuers = sorted(
        {k[0] for k in prior_keys} - {k[0] for k in current_keys}
    )

    return {
        "new_asks": [_describe(current_asks, k) for k in sorted(new_keys)],
        "removed_asks": [_describe(prior_asks, k) for k in sorted(removed_keys)],
        "changed_amounts": changed_amounts,
        "new_freezable_issuers": new_freezable_issuers,
        "removed_freezable_issuers": removed_freezable_issuers,
    }


def build_summary_text(diff: dict[str, Any]) -> str:
    """One-sentence English summary suitable for the alert queue list view.

    Examples:
      "2 new freeze targets (Circle, Tether)."
      "USDC at 0xe3478b... increased by $12,500."
      "1 freeze target removed (funds moved out)."
      "No material change."
    """
    parts: list[str] = []

    if diff.get("new_asks"):
        n = len(diff["new_asks"])
        issuers = sorted({a["issuer"] for a in diff["new_asks"]})
        plural = "" if n == 1 else "s"
        parts.append(
            f"{n} new freeze target{plural} ({', '.join(issuers)})"
        )

    if diff.get("removed_asks"):
        n = len(diff["removed_asks"])
        plural = "" if n == 1 else "s"
        parts.append(
            f"{n} freeze target{plural} removed (funds moved out)"
        )

    material_changes = [
        d for d in (diff.get("changed_amounts") or [])
        if _is_material(d)
    ]
    if material_changes:
        # Pick the largest absolute delta for the headline
        biggest = max(
            material_changes, key=lambda d: abs(_decimal(d["delta_usd"]))
        )
        delta = _decimal(biggest["delta_usd"])
        sign = "increased" if delta > 0 else "decreased"
        addr_short = (biggest["address"][:10] + "…") if len(biggest["address"]) > 10 else biggest["address"]
        parts.append(
            f"{biggest['symbol']} at {addr_short} {sign} by "
            f"${abs(delta):,.0f}"
        )

    if not parts:
        return "No material change."

    summary = ". ".join(p[0].upper() + p[1:] for p in parts)
    return summary + "."


# ----- Private helpers ----- #


def _flatten(freeze_asks: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Turn a freeze_asks.json body into a dict keyed by (issuer, address, symbol).

    The freeze_asks shape is::

        {
          "by_issuer": {
            "Tether": [{"address": "0x...", "symbol": "USDT", "usd_value": "263344.27", ...}, ...],
            ...
          },
          ...
        }

    We flatten to ``{(issuer, address_lower, symbol): {address: original, usd_value: Decimal, ...}}``
    so set comparisons are case-insensitive on address. Missing or
    malformed usd_value is treated as 0.
    """
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    by_issuer = freeze_asks.get("by_issuer") or {}
    for issuer, asks in by_issuer.items():
        for ask in asks or []:
            addr = ask.get("address") or ""
            symbol = ask.get("symbol") or ""
            if not addr or not symbol:
                continue
            key = (issuer, addr.lower(), symbol)
            out[key] = {
                "issuer": issuer,
                "address": addr,  # original case preserved
                "symbol": symbol,
                "usd_value": _decimal(ask.get("usd_value")),
                "amount": ask.get("amount") or "",
                "freeze_capability": ask.get("freeze_capability") or "unknown",
            }
    return out


def _describe(asks: dict[tuple[str, str, str], dict[str, Any]], key: tuple[str, str, str]) -> dict[str, Any]:
    """Render an ask entry as a UI-friendly dict (Decimal → str)."""
    a = asks[key]
    return {
        "issuer": a["issuer"],
        "address": a["address"],
        "symbol": a["symbol"],
        "usd_value": _money(a["usd_value"]),
        "amount": a["amount"],
        "freeze_capability": a["freeze_capability"],
    }


def _decimal(v: Any) -> Decimal:
    """Coerce a freeze_asks.json string/number/None to Decimal. 0 on error."""
    if v is None:
        return Decimal(0)
    if isinstance(v, Decimal):
        return v
    try:
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(0)


def _money(v: Decimal) -> str:
    """Quantize a USD value to 2dp string. Pure for hashing / equality."""
    return str(v.quantize(Decimal("0.01")))


def _percent(v: Decimal) -> str:
    """Quantize a percentage to 2dp string."""
    return str(v.quantize(Decimal("0.01")))


def _is_material(changed_amount: dict[str, Any]) -> bool:
    """A single changed_amounts entry is material if abs(delta_usd) >= USD_THRESHOLD
    OR abs(delta_pct) >= PCT_THRESHOLD."""
    delta_usd = abs(_decimal(changed_amount["delta_usd"]))
    delta_pct = abs(_decimal(changed_amount["delta_pct"]))
    return delta_usd >= DELTA_USD_THRESHOLD or delta_pct >= DELTA_PCT_THRESHOLD


def _any_changed_amount_material(changed_amounts: list[dict[str, Any]]) -> bool:
    return any(_is_material(d) for d in (changed_amounts or []))
