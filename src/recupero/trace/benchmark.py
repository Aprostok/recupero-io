"""Ground-truth trace-quality benchmark (v0.35.12 — roadmap J1).

Incumbents (TRM / Chainalysis internal QA) score their tracing engine against a
battery of known public hacks every release. This is that harness: given a
finished trace and an operator-supplied, independently-verified ground-truth set
of the case's true fund-flow endpoints, it computes:

  * **recall** — of the known endpoints, how many did the trace reach? (the
    headline "did we get there" number);
  * **endpoint precision** — of the addresses the trace REPORTED as endpoints
    (destinations / exchanges / freezable holders), how many were real?;
  * **F1** — harmonic mean of the two;
  * the explicit **missed** and **spurious** address lists, for triage.

Forensic posture: the ground-truth is INPUT DATA the operator supplies from an
independent, verified source (a published incident report, an indictment, a
recovered-funds record). This module never fabricates a ground truth and never
infers one from the trace itself (that would be circular). Address comparison is
canonical-keyed so EIP-55 / lowercase / base58 variants match.

Use:
    recupero-ops benchmark --case <case_dir> --truth <ground_truth.json>
where ground_truth.json is ``{"case_id": "...", "endpoints": ["0x...", ...],
"by_category": {"exchange": ["0x..."], "mixer": ["0x..."]}, "notes": "..."}``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class GroundTruth:
    """Independently-verified expected endpoints for one benchmark case."""
    case_id: str
    endpoints: frozenset[str]
    by_category: dict[str, frozenset[str]] = field(default_factory=dict)
    notes: str = ""


@dataclass(frozen=True)
class BenchmarkScore:
    """Trace-quality score against a ground truth. All counts canonical-keyed."""
    case_id: str
    recall: float
    endpoint_precision: float
    f1: float
    ground_truth_count: int
    reached_truth_count: int       # truth endpoints the trace reached
    flagged_count: int             # addresses the trace reported as endpoints
    flagged_true_count: int        # flagged ∩ truth
    missed: tuple[str, ...]        # truth endpoints NOT reached
    spurious: tuple[str, ...]      # flagged endpoints NOT in truth
    by_category_recall: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "recall": round(self.recall, 4),
            "endpoint_precision": round(self.endpoint_precision, 4),
            "f1": round(self.f1, 4),
            "ground_truth_count": self.ground_truth_count,
            "reached_truth_count": self.reached_truth_count,
            "flagged_count": self.flagged_count,
            "flagged_true_count": self.flagged_true_count,
            "missed": list(self.missed),
            "spurious": list(self.spurious),
            "by_category_recall": {
                k: round(v, 4) for k, v in self.by_category_recall.items()
            },
        }


def _ck(addr: str) -> str:
    """Canonical address key (lazy import to keep this module light)."""
    from recupero._common import canonical_address_key
    return canonical_address_key(addr)


def _ckset(addrs: Any) -> set[str]:
    if not addrs:
        return set()
    out: set[str] = set()
    for a in addrs:
        s = str(a or "").strip()
        if s:
            out.add(_ck(s))
    return out


def score_trace(
    *,
    reached: set[str] | list[str],
    flagged_endpoints: set[str] | list[str],
    truth: GroundTruth,
) -> BenchmarkScore:
    """PURE: score a trace against a ground truth.

    Args:
      reached: ALL addresses the trace touched (for recall — did we get there?).
      flagged_endpoints: addresses the trace REPORTED as final
        destinations/exchanges/holders (for endpoint precision — were our
        reported endpoints real?).
      truth: the verified expected-endpoint set.

    recall = |truth ∩ reached| / |truth|
    endpoint_precision = |truth ∩ flagged| / |flagged|
    Both default to 0.0 when their denominator is 0 (empty truth → recall 0.0
    with a logged warning; empty flagged → precision 0.0).
    """
    truth_set = {_ck(a) for a in truth.endpoints}
    reached_set = _ckset(reached)
    flagged_set = _ckset(flagged_endpoints)

    if not truth_set:
        log.warning(
            "benchmark: ground truth for %s has no endpoints — recall undefined",
            truth.case_id,
        )

    reached_truth = truth_set & reached_set
    flagged_true = truth_set & flagged_set

    recall = (len(reached_truth) / len(truth_set)) if truth_set else 0.0
    precision = (len(flagged_true) / len(flagged_set)) if flagged_set else 0.0
    f1 = (
        2 * recall * precision / (recall + precision)
        if (recall + precision) > 0 else 0.0
    )

    by_cat: dict[str, float] = {}
    for cat, addrs in (truth.by_category or {}).items():
        cat_truth = {_ck(a) for a in addrs}
        if cat_truth:
            by_cat[cat] = len(cat_truth & reached_set) / len(cat_truth)

    return BenchmarkScore(
        case_id=truth.case_id,
        recall=recall,
        endpoint_precision=precision,
        f1=f1,
        ground_truth_count=len(truth_set),
        reached_truth_count=len(reached_truth),
        flagged_count=len(flagged_set),
        flagged_true_count=len(flagged_true),
        # Report missed/spurious in display form (sorted for determinism).
        missed=tuple(sorted(truth_set - reached_set)),
        spurious=tuple(sorted(flagged_set - truth_set)),
        by_category_recall=by_cat,
    )


def load_ground_truth(path: Path) -> GroundTruth:
    """Load a ground-truth JSON. Raises ValueError on a malformed file."""
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"ground-truth {path} must be a JSON object")
    endpoints = data.get("endpoints")
    if not isinstance(endpoints, list):
        raise ValueError(f"ground-truth {path} requires an 'endpoints' list")
    by_cat_raw = data.get("by_category") or {}
    by_cat: dict[str, frozenset[str]] = {}
    if isinstance(by_cat_raw, dict):
        for k, v in by_cat_raw.items():
            if isinstance(v, list):
                by_cat[str(k)] = frozenset(str(a) for a in v if a)
    return GroundTruth(
        case_id=str(data.get("case_id") or path.stem),
        endpoints=frozenset(str(a) for a in endpoints if a),
        by_category=by_cat,
        notes=str(data.get("notes") or ""),
    )


def _field(obj: Any, name: str) -> Any:
    """Read ``name`` from a dataclass/model attribute OR a dict key.

    Lets the extractor work on both a live ``Case`` (transfer objects) and a
    deserialized ``case.json`` (transfer dicts) without a separate code path.
    """
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def extract_trace_addresses(
    case: Any, brief: dict[str, Any] | None = None,
) -> tuple[set[str], set[str]]:
    """Derive ``(reached, flagged_endpoints)`` from a Case OR case.json dict
    (+ optional brief).

    reached = every address appearing in transfers (from/to/counterparty).
    flagged_endpoints = addresses the brief reported as destinations / exchanges
    / freezable holders (the trace's claimed terminals). When no brief is given,
    flagged falls back to empty (recall-only benchmarking).
    """
    transfers = _field(case, "transfers") or []
    reached: set[str] = set()
    for t in transfers:
        for attr in ("from_address", "to_address"):
            v = _field(t, attr)
            if v:
                reached.add(_ck(str(v)))
        cp = _field(t, "counterparty")
        cp_addr = _field(cp, "address") if cp is not None else None
        if cp_addr:
            reached.add(_ck(str(cp_addr)))

    flagged: set[str] = set()
    if brief:
        for key in ("DESTINATIONS", "EXCHANGES", "FREEZABLE"):
            for row in (brief.get(key) or []):
                if isinstance(row, dict) and row.get("address"):
                    flagged.add(_ck(str(row["address"])))
    return reached, flagged


def score_case_dir(case_dir: Path, truth: GroundTruth) -> BenchmarkScore:
    """Operator entry point: read ``case.json`` (reached) + ``freeze_brief.json``
    (flagged endpoints) from ``case_dir`` and score against ``truth``.

    Either file may be absent: missing case.json → empty reached (recall 0);
    missing brief → flagged-empty (precision 0). Malformed JSON is treated as
    absent (logged), never raised — a benchmark run must not crash on one bad
    case in a battery.
    """
    def _read(name: str) -> dict[str, Any]:
        p = case_dir / name
        if not p.exists():
            return {}
        try:
            data = json.loads(p.read_text(encoding="utf-8-sig"))
            return data if isinstance(data, dict) else {}
        except Exception as exc:  # noqa: BLE001
            log.warning("benchmark: %s unreadable (%s) — treating as absent", p, exc)
            return {}

    case_json = _read("case.json")
    brief = _read("freeze_brief.json")
    reached, flagged = extract_trace_addresses(case_json, brief)
    return score_trace(reached=reached, flagged_endpoints=flagged, truth=truth)


__all__ = (
    "GroundTruth",
    "BenchmarkScore",
    "score_trace",
    "load_ground_truth",
    "extract_trace_addresses",
    "score_case_dir",
)
