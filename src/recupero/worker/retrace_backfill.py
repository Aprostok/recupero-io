"""Re-trace backfill — detect cases whose trace would benefit from
re-running because the label DB has gained new bridge / mixer /
CEX-deposit entries that match counterparties already in the case.

Gap #14 (v0.31.x trace-gap audit, v0.31.2):

  The trace-time materialization of bridge handoffs + counterparty
  labels means that an existing case never benefits from a later
  bridges.json / mixers.json / cex_deposits.json update. Brief
  re-render (v0.30.0 F6) covers NAMES (a wallet gains a label, the
  rendered brief shows it on the next render) but does NOT cover
  the trace-time SHAPE of the case (new handoffs that the BFS would
  have followed, new exchange endpoints that would have produced
  freeze targets).

  This cron is a sibling of ``scripts/retrace_on_label_update.py``
  but with a broader scope: any "investigatively meaningful" label
  category (bridge / mixer / exchange_deposit / exchange_hot_wallet /
  perpetrator) that was added to the label DB AFTER the case's
  ``trace_completed_at`` and matches a counterparty already in
  ``case.transfers`` produces a re-trace candidate row.

The cron does NOT auto-re-trace by default — it produces a REPORT
listing cases that would benefit from re-trace, with the specific
new labels that now match. Operators decide which to re-trace.

Algorithm:

  1. Load LabelStore (current state). Walk every label in the store
     and partition by ``added_at`` so we have an O(1) "is this label
     newer than X" predicate per category.
  2. For each case in the CaseStore:
       - Read ``trace_completed_at``. Skip cases with no value (the
         trace never finished) or a value we can't parse.
       - Build the set of counterparty addresses present in
         ``case.transfers`` (canonical-keyed via
         ``recupero._common.canonical_address_key`` so EVM and
         non-EVM addresses key consistently with how the label store
         keys them).
       - For each counterparty: look up the current label, and if
         the label's ``added_at`` is strictly after
         ``trace_completed_at`` AND the label's category is
         "investigatively meaningful" (bridge / mixer /
         exchange_deposit / exchange_hot_wallet / perpetrator), count
         it as a new-label match for this case.
  3. Emit a JSON report at ``data/retrace_candidates.json`` with:
       - case_id, trace_completed_at, count of new-label-matched
         counterparties, breakdown by label category, top 3
         counterparties as examples.

This is OBSERVABILITY first, not auto-action. Operators get a list
they can sort by impact and decide what to re-trace.

Critical constraints (locked by the test fixture):
  * ``find_retrace_candidates`` is a pure function. No disk, no
    network, no LabelStore mutation. Tests inject synthetic stores.
  * Labels with no ``added_at`` are treated as "ancient" (epoch=0,
    UTC) so they NEVER trigger as "new since trace" — a label whose
    provenance we lost can't manufacture a fake candidate.
  * Cases with a non-datetime / NaN / garbage ``trace_completed_at``
    are skipped gracefully (logged + continue), not crashed.
  * No mutation of LabelStore: we read it via the existing public-
    ish ``_by_addr_lower`` mapping (the canonical key dict). This
    matches how ``cross_chain.ingest_bridge_seeds`` and similar
    consumers read the store today.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from recupero._common import (
    atomic_write_text,
    canonical_address_key,
    resolve_render_time,
)
from recupero.config import RecuperoConfig, load_config
from recupero.labels.store import LabelStore
from recupero.models import Case, LabelCategory
from recupero.storage.case_store import CaseStore

log = logging.getLogger(__name__)


# Label categories that, when newly added, justify a re-trace. A new
# "unknown" / "defi_protocol" / "staking" / "victim" label changes the
# brief NAMES but not the shape of the BFS — those go through the
# brief-render re-resolution path (v0.30.0 F6) and don't need a
# re-trace. Bridges + mixers + exchange-related + perpetrator labels
# all change the SHAPE: a bridge would have been followed across
# chains, an exchange would have appeared as a freeze target, a
# perpetrator label would have re-anchored attribution.
RETRACE_TRIGGER_CATEGORIES: frozenset[LabelCategory] = frozenset({
    LabelCategory.bridge,
    LabelCategory.mixer,
    LabelCategory.exchange_deposit,
    LabelCategory.exchange_hot_wallet,
    LabelCategory.perpetrator,
})


# Number of example counterparties to include in each candidate row.
# Keeps the report compact for archives with thousands of cases while
# still giving the operator enough specificity to triage by hand.
_TOP_COUNTERPARTIES_LIMIT = 3


# Default output path (relative to the caller's cwd). The CLI accepts
# --out to override; this constant exists so the in-process callers
# (e.g. the ops command wrapper) can default consistently.
DEFAULT_OUT_RELATIVE = "data/retrace_candidates.json"


# Epoch sentinel used when a label is missing ``added_at``. UTC-aware
# so comparison against any UTC-aware ``trace_completed_at`` doesn't
# trip the offset-naive/offset-aware TypeError trap.
_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=UTC)


# --------------------------------------------------------------------- #
# Pure function — the heart of the cron.
# --------------------------------------------------------------------- #


def _coerce_aware_utc(dt: Any) -> datetime | None:
    """Best-effort coerce ``dt`` to a UTC-aware datetime.

    Returns None on any failure (None input, non-datetime, garbage
    string). The cron uses this to skip cases whose
    ``trace_completed_at`` would crash a naive ``>`` comparison —
    each individual case's failure stays local; the rest of the run
    proceeds.
    """
    if dt is None:
        return None
    if not isinstance(dt, datetime):
        # Not a datetime — caller passed garbage. Caller-friendly to
        # return None rather than raise; the cron loop treats this as
        # "skip this case".
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _case_counterparty_addresses(case: Case) -> list[tuple[str, str]]:
    """Return a list of (canonical_key, display_address) pairs for
    every distinct counterparty in ``case.transfers``.

    De-duplicated by canonical key. Display address is the FIRST
    counterparty.address value we see for that key, preserving its
    original case so report consumers can paste it into an explorer
    URL verbatim.
    """
    seen: dict[str, str] = {}
    for t in case.transfers:
        # ``to_address`` is the active counterparty for the v0.31.x
        # BFS (outbound from victim → counterparty). We deliberately
        # do NOT include ``from_address`` because that's typically
        # the seed wallet itself or an upstream hop, and gaining a
        # label on the seed wallet wouldn't change the trace shape.
        cp_addr = t.to_address
        key = canonical_address_key(cp_addr)
        if not key:
            continue
        if key in seen:
            continue
        seen[key] = cp_addr
    return list(seen.items())


def find_retrace_candidates(
    *,
    case_store: CaseStore,
    label_store: LabelStore,
) -> list[dict[str, Any]]:
    """Pure function — return the list of re-trace candidates.

    Walks every case directory under ``case_store.cases_root``, reads
    each case via the public ``CaseStore.read_case`` API, and matches
    counterparties against the label store. Cases that hit no new
    labels are omitted from the result entirely — the report is the
    actionable subset, not a full catalog.

    Each returned dict has the schema:

      {
        "case_id": "<str>",
        "trace_completed_at": "<ISO-8601 or None>",
        "new_label_matches": <int>,
        "by_category": {"bridge": <int>, "mixer": <int>, ...},
        "top_counterparties": [
            {
              "address": "<verbatim display address>",
              "new_label_name": "<label.name>",
              "new_label_category": "<category.value>",
              "new_label_added_at": "<ISO-8601>",
            },
            ...
        ],
      }

    The list is NOT sorted — sorting is the caller's responsibility
    (``write_retrace_report`` sorts by ``new_label_matches`` DESC).
    Keeping the pure function order-agnostic lets unit tests assert
    membership without coupling to sort tie-breaking.
    """
    candidates: list[dict[str, Any]] = []

    # CaseStore exposes the cases_root directory; we walk it directly
    # rather than introducing a list_cases() method on CaseStore (the
    # task brief explicitly forbids modifying LabelStore, and we
    # extend that "minimum surface" principle to CaseStore too).
    cases_root = case_store.cases_root
    if not cases_root.is_dir():
        log.info(
            "retrace_backfill: cases_root %s does not exist — "
            "nothing to scan", cases_root,
        )
        return candidates

    try:
        case_dirs = sorted(
            p for p in cases_root.iterdir() if p.is_dir()
        )
    except OSError as exc:
        log.warning(
            "retrace_backfill: iterdir(%s) failed: %s — skipping run",
            cases_root, exc,
        )
        return candidates

    for case_dir in case_dirs:
        case_id = case_dir.name
        # case_store.read_case validates the case_id + reads case.json
        # with size-cap + symlink guards. Any failure (missing file,
        # malformed JSON, traversal-shape id) is per-case isolated —
        # log + continue.
        try:
            case = case_store.read_case(case_id)
        except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError):
            log.debug(
                "retrace_backfill: %s case.json unreadable — skipping",
                case_id,
            )
            continue
        except Exception as exc:  # noqa: BLE001
            # Defense-in-depth: a Pydantic validation error or anything
            # else exotic must not break the whole run.
            log.debug(
                "retrace_backfill: %s case.json load raised %s — skipping",
                case_id, type(exc).__name__,
            )
            continue

        result = _analyze_case(case, label_store)
        if result is not None:
            candidates.append(result)

    log.info(
        "retrace_backfill: scanned %d case(s), produced %d candidate(s)",
        len(case_dirs), len(candidates),
    )
    return candidates


def _analyze_case(
    case: Case,
    label_store: LabelStore,
) -> dict[str, Any] | None:
    """Per-case analysis: return a candidate dict or None.

    Returns None when:
      * ``trace_completed_at`` is missing / unparseable (the trace
        never finished, or the field carries garbage).
      * No counterparty matches a "new since trace" trigger label.
    """
    trace_done = _coerce_aware_utc(case.trace_completed_at)
    if trace_done is None:
        log.debug(
            "retrace_backfill: %s — no trace_completed_at, skipping",
            case.case_id,
        )
        return None

    counterparties = _case_counterparty_addresses(case)
    if not counterparties:
        return None

    # Walk the label store's canonical-key map directly. This is the
    # narrowest "read-only" surface we can use without modifying
    # LabelStore — the dict is named ``_by_addr_lower`` for back-
    # compat but per the store's docstring it is "chain-aware" and
    # serves as the canonical-key index. We never mutate it.
    label_index = label_store._by_addr_lower  # noqa: SLF001 — read-only access

    by_category: dict[str, int] = {}
    matched: list[dict[str, Any]] = []

    for key, display_addr in counterparties:
        label = label_index.get(key)
        if label is None:
            continue
        if label.category not in RETRACE_TRIGGER_CATEGORIES:
            continue
        # Label with no added_at is treated as "ancient" (epoch).
        # This matches the edge-case requirement from the brief:
        # an undated label can never trigger as "new since trace".
        added_at = _coerce_aware_utc(label.added_at) or _EPOCH_UTC
        if added_at <= trace_done:
            # The label was already present when we last traced.
            # Either the trace already accounted for it, or the
            # operator decided it wasn't worth re-tracing. Either
            # way: not a new finding.
            continue

        cat_str = label.category.value
        by_category[cat_str] = by_category.get(cat_str, 0) + 1
        matched.append({
            "address": display_addr,
            "new_label_name": label.name,
            "new_label_category": cat_str,
            "new_label_added_at": added_at.isoformat(),
        })

    if not matched:
        return None

    # Top-N by ``new_label_added_at`` DESC — the freshest matches go
    # first, which is what an operator wants when triaging "what
    # changed recently". Stable order on ties via the address string.
    matched.sort(
        key=lambda r: (r["new_label_added_at"], r["address"]),
        reverse=True,
    )

    return {
        "case_id": case.case_id,
        "trace_completed_at": trace_done.isoformat(),
        "new_label_matches": len(matched),
        "by_category": by_category,
        "top_counterparties": matched[:_TOP_COUNTERPARTIES_LIMIT],
    }


# --------------------------------------------------------------------- #
# Report writer.
# --------------------------------------------------------------------- #


def write_retrace_report(
    candidates: list[dict[str, Any]],
    out_path: Path,
) -> None:
    """Write the candidate list as a JSON report.

    The report wraps the candidate list in a small envelope so future
    schema evolutions (e.g. a v2 that adds per-chain summaries) don't
    break readers that only know the v1 shape. ``generated_at`` honors
    ``SOURCE_DATE_EPOCH`` via ``resolve_render_time`` so re-running
    the cron with the same inputs produces byte-identical output —
    important for the 3x determinism regression.

    Candidates are sorted by ``new_label_matches`` DESC (most impactful
    case first); ties break on ``case_id`` ascending for stable output.
    Uses ``atomic_write_text`` so a cron crash mid-write can't leave a
    truncated file that crashes the next reader.
    """
    sorted_candidates = sorted(
        candidates,
        key=lambda c: (-int(c.get("new_label_matches", 0)), str(c.get("case_id", ""))),
    )
    payload = {
        "schema_version": 1,
        "generated_at": resolve_render_time().isoformat(),
        "candidate_count": len(sorted_candidates),
        "candidates": sorted_candidates,
    }
    atomic_write_text(
        out_path,
        json.dumps(payload, indent=2, allow_nan=False, ensure_ascii=False),
    )
    log.info(
        "retrace_backfill: wrote %d candidate(s) to %s",
        len(sorted_candidates), out_path,
    )


# --------------------------------------------------------------------- #
# CLI entry point.
# --------------------------------------------------------------------- #


def _resolve_out_path(arg: str | None) -> Path:
    """Pick the report output path from --out or fall back to
    ``<repo-root>/data/retrace_candidates.json`` (cwd-relative)."""
    if arg:
        return Path(arg)
    return Path(DEFAULT_OUT_RELATIVE)


def run_backfill_scan(
    *,
    config: RecuperoConfig,
    out_path: Path,
) -> int:
    """Top-level scan driver. Returns the candidate count.

    Loads CaseStore + LabelStore from the live config, walks the
    cases dir, writes the report. Never raises — failures inside
    ``find_retrace_candidates`` are per-case isolated, and the only
    way this function can fail is a disk-write error on the report
    itself (which propagates so the cron exit code reflects it).
    """
    case_store = CaseStore(config)
    label_store = LabelStore.load(config)
    candidates = find_retrace_candidates(
        case_store=case_store,
        label_store=label_store,
    )
    write_retrace_report(candidates, out_path)
    return len(candidates)


def main(argv: list[str] | None = None) -> int:
    """CLI entry — load config, scan, write report. Always returns 0.

    This is OBSERVABILITY ONLY. A "no candidates" outcome is the
    happy path; a "100 candidates" outcome is the cron doing its
    job. Neither is a failure. Genuine errors (disk full on the
    report write, config load explosion) propagate as a Python
    traceback to the cron host's stderr; they should be paged on
    via the cron host's standard mechanism, not exit-code parsing.
    """
    p = argparse.ArgumentParser(
        description=(
            "Scan all cases for re-trace candidates based on label DB "
            "updates. OBSERVABILITY ONLY — does not auto-re-trace."
        ),
    )
    p.add_argument(
        "--out", default=None,
        help=(
            "Output path for the report JSON (default: "
            f"{DEFAULT_OUT_RELATIVE})."
        ),
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose logging (DEBUG).",
    )
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    config, _env = load_config()
    out_path = _resolve_out_path(args.out)
    n = run_backfill_scan(config=config, out_path=out_path)
    log.info("retrace_backfill: SUMMARY candidates=%d out=%s", n, out_path)
    return 0


__all__ = (
    "DEFAULT_OUT_RELATIVE",
    "RETRACE_TRIGGER_CATEGORIES",
    "find_retrace_candidates",
    "main",
    "run_backfill_scan",
    "write_retrace_report",
)


if __name__ == "__main__":
    sys.exit(main())
