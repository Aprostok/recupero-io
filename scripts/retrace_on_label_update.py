#!/usr/bin/env python3
"""v0.31.2 — Backfill cron: re-detect cross-chain handoffs when bridges.json grows.

Gap #14 (v0.31.x trace-gap audit): existing closed cases never re-run
the cross-chain handoff detector when ``labels/seeds/bridges.json``
gains new entries. Label-store re-resolution at brief-render time
already covers NAMES (a wallet gains a label, the brief shows it on
next render), but it does NOT cover BRIDGE HANDOFFS — those are
materialized at trace-time into ``case.json`` and never recomputed.

For each closed case under ``<data_dir>/cases/``, this cron compares
the CURRENT ``identify_cross_chain_handoffs(case)`` output against
the original handoffs persisted at trace-time (read from the case's
``cross_chain_handoffs`` field if present, otherwise reconstructed
from a prior ``retrace_findings.json``). Any new
``(tx_hash, bridge_addr)`` pair that the current label DB now
resolves is written as a row in ``<case_dir>/retrace_findings.json``
with the schema:

  {
    "case_id": "...",
    "found_at": "ISO-8601-UTC",
    "new_handoffs": [
      {
        "tx_hash": "0x...",
        "source_chain": "ethereum",
        "bridge_name": "Newly-Added Bridge",
        "bridge_protocol": "Wormhole",
        "bridge_address": "0x...",
        "amount_usd": 12345.67,
        "decoded_destination_chain": null,
        "decoded_destination_address": null,
        "follow_up_url": "https://..."
      }
    ]
  }

Idempotent: re-running the cron against a case with no new label
hits produces no changes to ``retrace_findings.json``. The file is
only re-written when the latest run discovers a strictly different
set of ``(tx_hash, bridge_addr)`` pairs vs. the last persisted run.

The cron is INTENTIONALLY cheap — it only re-runs the pure-function
``identify_cross_chain_handoffs(case)`` against the in-memory case
+ current bridges.json. It never re-fetches transfers, never re-does
BFS, never touches the RPC layer.

Failure model: per-case errors are isolated. One malformed case.json
does not stop the rest of the run. Errors are accumulated into the
returned ``RetraceRunResult`` and emitted as worker-style log lines.

Usage:
    python scripts/retrace_on_label_update.py
    python scripts/retrace_on_label_update.py --case-id abcd1234
    python scripts/retrace_on_label_update.py --dry-run
    python scripts/retrace_on_label_update.py --data-dir /var/recupero/data
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Add the project src/ to sys.path when invoked as a bare script so
# the import below resolves without an install step. No-op when the
# package is already installed.
_HERE = Path(__file__).resolve().parent
_SRC = _HERE.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import orjson  # noqa: E402

from recupero.models import Case  # noqa: E402
from recupero.trace.cross_chain import (  # noqa: E402
    BridgeInfo,
    CrossChainHandoff,
    identify_cross_chain_handoffs,
    ingest_bridge_seeds,
)

log = logging.getLogger("retrace_on_label_update")


# File-name constants — exposed for tests + downstream readers.
RETRACE_FINDINGS_FILENAME = "retrace_findings.json"
CASE_FILE = "case.json"

# Default upper bound on cases processed per run. Protects a poorly-
# configured cron from chewing through a 10k-case archive in one tick.
DEFAULT_MAX_CASES = 100


# --------------------------------------------------------------------- #
# Pure functions (testable without disk).
# --------------------------------------------------------------------- #


def _handoff_to_finding(h: CrossChainHandoff) -> dict[str, Any]:
    """Serialize a CrossChainHandoff into the retrace_findings.json
    row schema. Deliberately a SUBSET of handoffs_to_brief_section's
    output — the retrace file is investigator-facing follow-up,
    not a brief replacement.

    NaN/Inf guard on amount_usd: a poisoned Decimal that slipped past
    earlier validation would otherwise serialize as the literal string
    ``"NaN"`` / ``"Infinity"`` in JSON, which most downstream readers
    silently coerce to None or crash. Coerce to None explicitly so the
    retrace file is always machine-parseable.
    """
    amount_usd_safe: float | None
    if h.amount_usd is None or not h.amount_usd.is_finite():
        amount_usd_safe = None
    else:
        # round-trip through float for JSON serialization; the retrace
        # file is an investigator artifact, not a forensic primary so
        # Decimal precision is not load-bearing here.
        amount_usd_safe = float(h.amount_usd)
    return {
        "tx_hash": h.source_tx_hash,
        "source_chain": h.source_chain.value,
        "bridge_name": h.bridge_name,
        "bridge_protocol": h.bridge_protocol,
        "bridge_address": h.bridge_address,
        "amount_usd": amount_usd_safe,
        "token_symbol": h.token_symbol,
        "block_time": h.block_time_iso,
        "decoded_destination_chain": h.decoded_destination_chain,
        "decoded_destination_address": h.decoded_destination_address,
        "follow_up_url": h.follow_up_url,
    }


def _handoff_key(h: CrossChainHandoff | dict[str, Any]) -> tuple[str, str]:
    """Canonical de-dup key for "is this handoff the same handoff".

    Mirrors identify_cross_chain_handoffs' internal dedup
    (tx_hash, bridge_address). Works on both the dataclass shape
    and the persisted-dict shape so the comparison code below can
    diff one against the other.
    """
    if isinstance(h, CrossChainHandoff):
        return (h.source_tx_hash, h.bridge_address)
    return (str(h.get("tx_hash", "")), str(h.get("bridge_address", "")))


def find_new_handoffs(
    case: Case,
    current_bridge_db: dict[tuple[Any, str], BridgeInfo],
    *,
    already_known_keys: set[tuple[str, str]] | None = None,
) -> list[CrossChainHandoff]:
    """Pure function: return the handoffs visible RIGHT NOW that were
    NOT in ``already_known_keys`` (a set of (tx_hash, bridge_address)).

    Caller is responsible for assembling ``already_known_keys`` from
    whatever sources of "already-known" handoffs they want to honor:
      * the case's own ``cross_chain_handoffs`` field if it carries one
      * the last persisted retrace_findings.json's new_handoffs list
      * both, unioned

    The function NEVER touches disk, NEVER fetches transfers, and
    NEVER raises on a missing/empty bridge db — that's a graceful
    "no new handoffs" outcome.
    """
    if not current_bridge_db:
        return []
    if already_known_keys is None:
        already_known_keys = set()
    fresh = identify_cross_chain_handoffs(case, bridge_db=current_bridge_db)
    return [h for h in fresh if _handoff_key(h) not in already_known_keys]


def _gather_already_known_keys(
    case: Case,
    prior_findings: dict[str, Any] | None,
) -> set[tuple[str, str]]:
    """Combine the case's persisted handoffs (if any) with the last
    retrace_findings.json output (if any) into a single set of
    (tx_hash, bridge_addr) keys to subtract from "fresh" detection.

    The Case model in v0.31.x has ``model_config = ConfigDict(extra="ignore")``
    on the outer container, so case.json files MAY carry a
    ``cross_chain_handoffs`` array that the model strips on load.
    We re-read the on-disk JSON dict separately to recover it without
    coupling to model evolution.
    """
    keys: set[tuple[str, str]] = set()
    if prior_findings is not None:
        for row in prior_findings.get("new_handoffs", []) or []:
            keys.add(_handoff_key(row))
    return keys


# --------------------------------------------------------------------- #
# Disk I/O — case discovery + retrace_findings.json read/write.
# --------------------------------------------------------------------- #


def _is_closed_case(case_dir: Path) -> bool:
    """A case is "closed" for the purposes of this cron if its
    case.json has a non-null ``trace_completed_at`` field. Open
    cases (trace still running, or stuck mid-pipeline) get skipped
    so the cron can't race the writer.
    """
    case_path = case_dir / CASE_FILE
    if not case_path.is_file():
        return False
    try:
        raw = case_path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):  # BOM strip
            raw = raw[3:]
        data = orjson.loads(raw)
    except Exception:  # noqa: BLE001
        return False
    return bool(data.get("trace_completed_at"))


def _load_case(case_dir: Path) -> tuple[Case | None, dict[str, Any] | None]:
    """Load case.json into the Pydantic Case model AND return the
    raw parsed dict alongside. The raw dict is used by
    ``_gather_already_known_keys`` to recover an out-of-schema
    ``cross_chain_handoffs`` field if present.
    """
    case_path = case_dir / CASE_FILE
    try:
        raw = case_path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        data = orjson.loads(raw)
    except Exception as exc:  # noqa: BLE001
        log.warning("retrace: %s case.json load failed: %s", case_dir.name, exc)
        return None, None
    try:
        case = Case.model_validate(data)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "retrace: %s case.json pydantic-validate failed: %s",
            case_dir.name, exc,
        )
        return None, data
    return case, data


def _load_prior_findings(case_dir: Path) -> dict[str, Any] | None:
    """Load an existing retrace_findings.json if present.

    Defensive: a malformed file is treated as "no prior findings"
    (the cron then rebuilds cleanly on the next write). This matches
    the cron's idempotence contract: the file should always be either
    valid JSON of the expected shape, or rewritten.
    """
    p = case_dir / RETRACE_FINDINGS_FILENAME
    if not p.is_file():
        return None
    try:
        raw = p.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        data = orjson.loads(raw)
        if not isinstance(data, dict):
            log.warning(
                "retrace: %s/%s is not a JSON object — will be rebuilt",
                case_dir.name, RETRACE_FINDINGS_FILENAME,
            )
            return None
        return data
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "retrace: %s/%s malformed (%s) — will be rebuilt",
            case_dir.name, RETRACE_FINDINGS_FILENAME, exc,
        )
        return None


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomic write via tempfile + os.replace, mirroring case_store's
    pattern so a cron crash mid-write can't leave a truncated file.
    """
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    data = orjson.dumps(payload, option=orjson.OPT_INDENT_2)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent),
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass
        raise


# --------------------------------------------------------------------- #
# Per-case driver + top-level run.
# --------------------------------------------------------------------- #


@dataclass
class CaseRetraceOutcome:
    case_id: str
    new_handoffs_count: int = 0
    wrote_findings: bool = False
    skipped_reason: str | None = None
    error: str | None = None


@dataclass
class RetraceRunResult:
    cases_scanned: int = 0
    cases_with_new_handoffs: int = 0
    files_written: int = 0
    errors: list[str] = field(default_factory=list)
    per_case: list[CaseRetraceOutcome] = field(default_factory=list)


def retrace_one_case(
    case_dir: Path,
    current_bridge_db: dict[tuple[Any, str], BridgeInfo],
    *,
    dry_run: bool = False,
) -> CaseRetraceOutcome:
    """Drive one case end-to-end: load, diff, optionally write.

    Always returns a CaseRetraceOutcome (never raises) so the
    caller's per-case loop can keep going across malformed cases.
    """
    case_id = case_dir.name
    outcome = CaseRetraceOutcome(case_id=case_id)

    if not _is_closed_case(case_dir):
        outcome.skipped_reason = "case not closed (no trace_completed_at)"
        return outcome

    case, _raw = _load_case(case_dir)
    if case is None:
        outcome.error = "case.json failed to load"
        return outcome

    prior = _load_prior_findings(case_dir)
    already_known = _gather_already_known_keys(case, prior)

    try:
        new_handoffs = find_new_handoffs(
            case, current_bridge_db, already_known_keys=already_known,
        )
    except Exception as exc:  # noqa: BLE001
        outcome.error = f"find_new_handoffs raised: {exc}"
        log.warning("retrace: %s find_new_handoffs raised: %s", case_id, exc)
        return outcome

    outcome.new_handoffs_count = len(new_handoffs)

    if not new_handoffs:
        # Idempotence: no rewrite when nothing changed. We deliberately
        # do NOT touch the file even if a prior findings file exists
        # with the SAME set of new_handoffs — the file is already correct.
        return outcome

    # Idempotence: if the prior findings already contained the EXACT
    # same set of (tx, bridge) pairs we just rediscovered, skip the
    # write. (Can only happen when ``find_new_handoffs`` returns rows
    # the caller didn't include in already_known_keys — currently not
    # possible because we always pass prior keys in, but kept here as
    # a defense-in-depth invariant for future callers.)
    new_keys = {_handoff_key(h) for h in new_handoffs}
    prior_keys = (
        {_handoff_key(row) for row in (prior.get("new_handoffs") or [])}
        if prior else set()
    )
    # NOTE: the prior already-known set is SUBTRACTED upstream; if we
    # got here with new_handoffs non-empty, those are strictly new.
    # The prior_keys check below is for the edge case where the prior
    # findings file got renamed away or the diff logic changed.
    if new_keys == prior_keys and prior is not None:
        return outcome

    payload = {
        "case_id": case_id,
        "found_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "new_handoffs": [_handoff_to_finding(h) for h in new_handoffs],
    }

    if dry_run:
        log.info(
            "retrace: [dry-run] would write %d new handoff(s) for case %s",
            len(new_handoffs), case_id,
        )
        return outcome

    target = case_dir / RETRACE_FINDINGS_FILENAME
    try:
        _atomic_write_json(target, payload)
    except Exception as exc:  # noqa: BLE001
        outcome.error = f"write failed: {exc}"
        log.warning("retrace: %s write %s failed: %s", case_id, target, exc)
        return outcome

    outcome.wrote_findings = True
    log.info(
        "retrace: %s — wrote %d new handoff(s) → %s",
        case_id, len(new_handoffs), target.name,
    )
    return outcome


def run_retrace_cron(
    *,
    data_dir: Path,
    case_id: str | None = None,
    max_cases: int = DEFAULT_MAX_CASES,
    dry_run: bool = False,
    bridges_seed_path: Path | None = None,
) -> RetraceRunResult:
    """Top-level cron entry point.

    Re-loads bridges.json FRESH each call (never cached) so a label
    DB update between invocations is picked up immediately.

    Args:
        data_dir: the recupero data dir; cases live under ``data_dir/cases``.
        case_id: optional — process one case only. Default = scan all.
        max_cases: cap on cases processed in a single tick. Default 100.
        dry_run: log what would be written without writing.
        bridges_seed_path: override the bridges.json location (tests only).

    Returns a RetraceRunResult; never raises (errors are collected).
    """
    result = RetraceRunResult()
    cases_root = data_dir / "cases"
    if not cases_root.is_dir():
        log.warning("retrace: cases root %s missing — nothing to do", cases_root)
        return result

    # Re-load bridges fresh each tick. A previous tick's stale db
    # would defeat the entire point of this cron.
    bridge_db = ingest_bridge_seeds(bridges_seed_path)
    if not bridge_db:
        result.errors.append(
            "bridges seed produced an empty db — skipping all cases"
        )
        log.warning("retrace: bridges.json produced empty db — nothing to detect")
        return result

    log.info(
        "retrace: scanning %s with %d known bridges (max_cases=%d, dry_run=%s)",
        cases_root, len(bridge_db), max_cases, dry_run,
    )

    if case_id:
        candidates = [cases_root / case_id]
        if not candidates[0].is_dir():
            result.errors.append(f"case_id {case_id!r}: directory not found")
            return result
    else:
        try:
            candidates = sorted(
                p for p in cases_root.iterdir() if p.is_dir()
            )
        except OSError as exc:
            result.errors.append(f"iterdir({cases_root}) failed: {exc}")
            return result

    for case_dir in candidates[:max_cases]:
        outcome = retrace_one_case(case_dir, bridge_db, dry_run=dry_run)
        result.per_case.append(outcome)
        result.cases_scanned += 1
        if outcome.error:
            result.errors.append(f"{outcome.case_id}: {outcome.error}")
        if outcome.new_handoffs_count > 0:
            result.cases_with_new_handoffs += 1
        if outcome.wrote_findings:
            result.files_written += 1

    log.info(
        "retrace: tick complete — scanned=%d with_new=%d written=%d errors=%d",
        result.cases_scanned, result.cases_with_new_handoffs,
        result.files_written, len(result.errors),
    )
    return result


# --------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------- #


def _resolve_data_dir(arg: str | None) -> Path:
    """Pick data_dir from --data-dir, then $RECUPERO_DATA_DIR, then ./data."""
    if arg:
        return Path(arg)
    env = os.environ.get("RECUPERO_DATA_DIR")
    if env:
        return Path(env)
    return Path("./data")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 on success, 1 when any case errored,
    2 on invocation-shape problems (bad args, missing data dir).
    """
    p = argparse.ArgumentParser(
        description=(
            "Re-detect cross-chain handoffs on existing closed cases "
            "after bridges.json was updated. Idempotent + side-channel."
        ),
    )
    p.add_argument(
        "--data-dir", default=None,
        help="Recupero data dir (default: $RECUPERO_DATA_DIR or ./data)",
    )
    p.add_argument(
        "--case-id", default=None,
        help="Process one case only (default: scan all).",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be written without touching disk.",
    )
    p.add_argument(
        "--max-cases", type=int, default=DEFAULT_MAX_CASES,
        help=f"Max cases per tick (default: {DEFAULT_MAX_CASES}).",
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

    data_dir = _resolve_data_dir(args.data_dir)
    if not data_dir.exists():
        log.error("data_dir %s does not exist", data_dir)
        return 2

    if args.max_cases <= 0:
        log.error("--max-cases must be positive, got %d", args.max_cases)
        return 2

    result = run_retrace_cron(
        data_dir=data_dir,
        case_id=args.case_id,
        max_cases=args.max_cases,
        dry_run=args.dry_run,
    )

    # Summary line for the worker-side notification consumer to parse.
    log.info(
        "retrace: SUMMARY scanned=%d with_new=%d written=%d errors=%d",
        result.cases_scanned, result.cases_with_new_handoffs,
        result.files_written, len(result.errors),
    )
    for err in result.errors:
        log.warning("retrace: ERR %s", err)

    return 0 if not result.errors else 1


__all__ = (
    "CASE_FILE",
    "CaseRetraceOutcome",
    "DEFAULT_MAX_CASES",
    "RETRACE_FINDINGS_FILENAME",
    "RetraceRunResult",
    "find_new_handoffs",
    "main",
    "retrace_one_case",
    "run_retrace_cron",
)


if __name__ == "__main__":
    sys.exit(main())
