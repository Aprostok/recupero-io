"""Material-change detection for follow-up investigations.

When a case is in monitoring state, the cron job (Jacob's side) inserts
a new investigation row each night. The worker runs the full pipeline
(trace → freeze → editorial → emit) and AFTER editorial, compares
today's results to the prior investigation's. The diff drives:

  - Whether the row pauses at ``awaiting_review`` for operator review
  - Whether the email notification fires
  - Whether the alert UI shows the row in its "needs attention" queue

If nothing material changed, the worker auto-approves and completes
the investigation without operator involvement. The brief artifacts
from the prior run are still valid (case state didn't change → briefs
didn't change), so we skip emit + building_package as well.

Material-change definition (any of):

  1. ``max_recoverable_usd`` increased — operator-recoverable position grew
  2. ``freezable_issuers`` gained an entry — new issuer to address
  3. A freeze ask in ``freeze_asks.json`` appeared, disappeared, or
     changed by ≥$1,000 absolute or ≥5% relative — on-chain holdings shifted

(1) and (2) are editorial-derived (depend on AI's emoji classification).
(3) is deterministic (read straight from on-chain trace). All three
fire independently — any single signal triggers material_change=true.

Public surface:

    DiffResult                   — dataclass returned by run_diff_stage
    run_diff_stage(...)          — main entry point, called from pipeline.py
    compute_followup_diff(...)   — pure function, combines all three signals
    compute_freeze_asks_diff(prior, current) -> dict
                                 — sub-function, just the freeze_asks delta
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


# ----- Prior investigation snapshot ----- #


@dataclass
class PriorSnapshot:
    """Everything the diff needs from the prior investigation.

    Keeps the I/O wrapper's signature stable: callers (pipeline.py in
    prod, test fixtures in tests) build one of these and pass it in.
    """

    investigation_id: UUID
    max_recoverable_usd: Decimal | None
    freezable_issuers: list[str] | None
    freeze_asks: dict[str, Any] | None  # bucket-loaded freeze_asks.json


# ----- Main entry point (called from pipeline.py) ----- #


def run_diff_stage(
    *,
    investigation_id: UUID,
    case_id: UUID,
    current_max_recoverable_usd: Decimal | None,
    current_freezable_issuers: list[str] | None,
    current_freeze_asks: dict[str, Any] | None,
    fetch_prior: "callable[[UUID, UUID], PriorSnapshot | None]",
) -> DiffResult:
    """Compare today's editorial-finished investigation to the prior
    complete one. Returns a DiffResult ready to write to the row.

    ``fetch_prior`` is a caller-supplied callable that returns a
    ``PriorSnapshot`` for the most recent completed investigation on
    the same case_id, or None. Injected so this function is testable
    without psycopg / httpx mocks. The pipeline integration in
    ``worker/pipeline.py`` provides the callable as a closure over
    the DB + bucket store.

    Called AFTER drafting_editorial in the pipeline, so all three
    signals (max_recoverable, freezable_issuers, freeze_asks) are
    available on the current investigation. On no-change, the
    pipeline skips awaiting_review + emit + building_package and
    completes directly.
    """
    prior = fetch_prior(case_id, investigation_id)
    if prior is None:
        return DiffResult(
            is_followup=False,
            prior_id=None,
            material_change=False,
            summary=None,
        )

    if prior.investigation_id == investigation_id:
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

    diff = compute_followup_diff(
        prior_max_recoverable=prior.max_recoverable_usd,
        prior_freezable_issuers=prior.freezable_issuers,
        prior_freeze_asks=prior.freeze_asks,
        current_max_recoverable=current_max_recoverable_usd,
        current_freezable_issuers=current_freezable_issuers,
        current_freeze_asks=current_freeze_asks,
    )

    return DiffResult(
        is_followup=True,
        prior_id=prior.investigation_id,
        material_change=diff["material_change_detected"],
        summary=(
            diff
            if diff["material_change_detected"]
            else {"summary_text_for_ui": diff["summary_text_for_ui"]}
        ),
    )


def compute_followup_diff(
    *,
    prior_max_recoverable: Decimal | None,
    prior_freezable_issuers: list[str] | None,
    prior_freeze_asks: dict[str, Any] | None,
    current_max_recoverable: Decimal | None,
    current_freezable_issuers: list[str] | None,
    current_freeze_asks: dict[str, Any] | None,
) -> dict[str, Any]:
    """Combine three independent signals into a single diff dict.

    Pure function — all three checks run regardless of which fired.
    The summary is enriched with whichever signals showed change.
    Output shape is stable for idempotency (same input = same output).
    """
    # Signal 1: max_recoverable_usd delta
    prior_mr = _decimal(prior_max_recoverable)
    current_mr = _decimal(current_max_recoverable)
    mr_delta = current_mr - prior_mr

    # Signal 2: freezable_issuers set delta
    prior_issuers = set(prior_freezable_issuers or [])
    current_issuers = set(current_freezable_issuers or [])
    new_issuers = sorted(current_issuers - prior_issuers)
    removed_issuers = sorted(prior_issuers - current_issuers)

    # Signal 3: freeze_asks-level diff (per-(issuer, address) holdings)
    asks_diff = compute_freeze_asks_diff(prior_freeze_asks, current_freeze_asks)

    material = (
        mr_delta != 0
        or bool(new_issuers)
        or bool(removed_issuers)
        or bool(asks_diff["new_asks"])
        or bool(asks_diff["removed_asks"])
        or _any_changed_amount_material(asks_diff["changed_amounts"])
    )

    out = {
        "max_recoverable_was": _money(prior_mr),
        "max_recoverable_now": _money(current_mr),
        "max_recoverable_delta_usd": _money(mr_delta),
        "new_freezable_issuers": new_issuers,
        "removed_freezable_issuers": removed_issuers,
        "new_asks": asks_diff["new_asks"],
        "removed_asks": asks_diff["removed_asks"],
        "changed_amounts": asks_diff["changed_amounts"],
        "thresholds": {
            "delta_usd": str(DELTA_USD_THRESHOLD),
            "delta_pct": str(DELTA_PCT_THRESHOLD),
        },
        "material_change_detected": material,
    }
    out["summary_text_for_ui"] = build_summary_text(out)
    return out


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
      "Max recoverable amount increased by $12,500."
      "2 new freeze targets (Circle, Tether)."
      "USDC at 0xe3478b... increased by $12,500."
      "1 freeze target removed (funds moved out)."
      "No material change."
    """
    parts: list[str] = []

    # Max-recoverable change goes first — it's the most operator-relevant
    # number ("how much more money can we get back").
    mr_delta = _decimal(diff.get("max_recoverable_delta_usd"))
    if mr_delta != 0:
        sign = "increased" if mr_delta > 0 else "decreased"
        parts.append(
            f"max recoverable amount {sign} by ${abs(mr_delta):,.0f}"
        )

    if diff.get("new_freezable_issuers"):
        issuers = diff["new_freezable_issuers"]
        plural = "" if len(issuers) == 1 else "s"
        parts.append(
            f"new freezable issuer{plural}: {', '.join(issuers)}"
        )

    if diff.get("new_asks"):
        n = len(diff["new_asks"])
        issuers = sorted({a["issuer"] for a in diff["new_asks"]})
        plural = "" if n == 1 else "s"
        # Don't repeat issuer names already mentioned in new_freezable_issuers
        already_mentioned = set(diff.get("new_freezable_issuers") or [])
        new_issuers = [i for i in issuers if i not in already_mentioned]
        parts.append(
            f"{n} new freeze target{plural}"
            + (f" ({', '.join(new_issuers)})" if new_issuers else "")
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
    if material_changes and not parts:
        # Only fall back to per-ask narrative if max_recoverable AND
        # set-membership signals didn't fire. Otherwise the headline
        # is already the more operator-relevant top-level number.
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
