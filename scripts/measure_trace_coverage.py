"""Quantify trace recall against an operator-curated ground-truth file.

The ``destinations_superset_of_ground_truth`` validator in
``src/recupero/validators/output_integrity.py`` gives a binary
pass/fail: every ground-truth address is either present in the brief's
identified-address set, or it fires a critical violation. That is the
right shape for a CI gate, but it answers "did we regress?" — not "how
COMPLETE is this trace?".

This module answers the second question. Given a brief and a
ground-truth file it computes a recall percentage (how many of the
operator-confirmed destinations the worker actually surfaced) plus the
explicit gap list (which addresses were missed, with the curated role +
source for triage). That number is the headline metric for a trace-
coverage deliverable; the gap list is the actionable follow-up.

It mirrors the validator EXACTLY on the question of "which addresses
does the brief claim to have identified": the same six surfaces
(DESTINATIONS, PERP_HUB, FREEZABLE.holdings, EXCHANGES, UNRECOVERABLE,
ALL_ISSUER_HOLDINGS), the same EVM-lowercase canonicalization. The
gathering logic is re-implemented locally (a small, self-contained copy)
rather than importing the validator's private ``_extract_brief_addresses``
— this module stays dependency-light (stdlib only) and has no import-cycle
risk against the validator package.

Ground-truth shape (matches tests/fixtures/zigha_ground_truth.json):

    {
      "case_id": "...",
      "expected_destinations": [
        {"address": "0x...", "chain": "ethereum",
         "role": "...", "source": "...", "approx_usd": 9980000},
        ...
      ]
    }

CLI:

    python -m scripts.measure_trace_coverage <case_dir>

reads ``<case_dir>/freeze_brief.json`` + ``<case_dir>/ground_truth.json``
and prints the coverage report as JSON to stdout. Missing files produce
a clear message on stderr and a non-zero exit. Pure + offline: stdlib
only (json, sys, pathlib, re), no network, no clock/random nondeterminism.

FORENSIC POSTURE: this is a measurement, never a fabrication. An address
is "found" only when it appears in one of the brief's own identified
surfaces; the ground-truth file is operator-curated. The tool invents
nothing.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

__all__ = ["coverage_report", "main"]

# EVM address shape (0x + 40 hex). Mirrors the validator's
# _GROUND_TRUTH_ADDR_RE — non-EVM ground-truth is not yet supported, so a
# malformed / non-EVM expected address is dropped from the comparison (it
# cannot be found, but neither do we want to crash on it). EVM addresses
# are case-insensitive at the identity layer (EIP-55 is a checksum, not an
# identity) so we compare canonical-lowercase.
_EVM_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

# The six brief surfaces the output_integrity validator gathers
# identified addresses from. Kept here as a named constant so a reviewer
# can confirm at a glance that this module reads exactly the same set.
BRIEF_ADDRESS_SURFACES = (
    "DESTINATIONS",
    "PERP_HUB",
    "FREEZABLE.holdings",
    "EXCHANGES",
    "UNRECOVERABLE",
    "ALL_ISSUER_HOLDINGS",
)


def _canonicalize(addr: object) -> str | None:
    """Canonical comparison key for an address, or None if it isn't a
    usable string. Lower-case + whitespace-strip — the project's
    canonical_address_key convention for EVM addresses, re-implemented
    locally so this module imports nothing from recupero."""
    if not isinstance(addr, str):
        return None
    c = addr.strip().lower()
    return c or None


def _gather_brief_addresses(brief: dict[str, Any]) -> set[str]:
    """Collect every address the brief reports as identified, across the
    same six surfaces the output_integrity validator reads:

      * DESTINATIONS[].address          (list of dicts)
      * PERP_HUB.address                (single dict)
      * FREEZABLE[].holdings[].address  (list of dicts of lists of dicts)
      * EXCHANGES[].address             (list of dicts)
      * UNRECOVERABLE[].address         (list of dicts)
      * ALL_ISSUER_HOLDINGS[].address   (list of dicts)

    Returns canonical (lower-cased) keys so the recall comparison is a
    direct set-membership test. Defensive against malformed shapes — a
    non-dict entry or a missing/typed-wrong address is skipped, never
    raised.
    """
    out: set[str] = set()

    def _add(addr: object) -> None:
        c = _canonicalize(addr)
        if c:
            out.add(c)

    if not isinstance(brief, dict):
        return out

    # DESTINATIONS — primary surface (every destination the BFS found).
    for d in brief.get("DESTINATIONS") or []:
        if isinstance(d, dict):
            _add(d.get("address"))

    # PERP_HUB — consolidation address (single dict or None).
    perp = brief.get("PERP_HUB")
    if isinstance(perp, dict):
        _add(perp.get("address"))

    # FREEZABLE[].holdings — each per-issuer holding carries an address.
    for f in brief.get("FREEZABLE") or []:
        if not isinstance(f, dict):
            continue
        for h in f.get("holdings") or []:
            if isinstance(h, dict):
                _add(h.get("address"))

    # EXCHANGES — off-ramp deposit addresses.
    for ex in brief.get("EXCHANGES") or []:
        if isinstance(ex, dict):
            _add(ex.get("address"))

    # UNRECOVERABLE — dormant DAI / Sky / native positions.
    for u in brief.get("UNRECOVERABLE") or []:
        if isinstance(u, dict):
            _add(u.get("address"))

    # ALL_ISSUER_HOLDINGS — Section 4.2 complete inventory may carry
    # addresses not in DESTINATIONS (e.g. UNRECOVERABLE-only issuers).
    for e in brief.get("ALL_ISSUER_HOLDINGS") or []:
        if isinstance(e, dict):
            _add(e.get("address"))

    return out


def coverage_report(brief: dict[str, Any], ground_truth: dict[str, Any]) -> dict[str, Any]:
    """Compute trace recall of ``brief`` against ``ground_truth``.

    Returns::

        {
            "expected": int,        # # of valid expected destinations
            "found": int,           # # of those present in the brief
            "recall_pct": float,    # 100 * found / expected, 1 decimal
            "missing": [            # one entry per gap, curated metadata
                {"address": str, "role": str, "source": str},
                ...
            ],
        }

    ``ground_truth`` follows the on-disk fixture shape — an
    ``expected_destinations`` list of ``{address, role, source, ...}``
    dicts. Entries whose address is missing / not a valid EVM hex string
    are skipped (they can't participate in an EVM set comparison); this
    mirrors the validator's EVM-hex guard so prefix-only placeholder rows
    don't distort the recall number.

    Empty / absent expected list → recall_pct is 100.0 (vacuously
    complete: there is nothing the trace was required to find, so it
    missed nothing) and ``missing`` is []. This matches the validator,
    which treats an empty ``expected_destinations`` as a trivially-
    satisfied invariant.

    Pure: no I/O, no global state, deterministic. ``missing`` preserves
    the order expected destinations appear in the fixture.
    """
    found_addrs = _gather_brief_addresses(brief if isinstance(brief, dict) else {})

    expected_raw = []
    if isinstance(ground_truth, dict):
        ed = ground_truth.get("expected_destinations")
        if isinstance(ed, list):
            expected_raw = ed

    expected = 0
    found = 0
    missing: list[dict[str, Any]] = []
    for item in expected_raw:
        if not isinstance(item, dict):
            # Malformed entry — not a comparable destination. Skip (the
            # validator surfaces this as a separate high; here we simply
            # don't count it toward recall).
            continue
        addr = item.get("address")
        canon = _canonicalize(addr)
        if canon is None or not _EVM_ADDR_RE.match(canon):
            # Non-EVM / placeholder / prefix-only — not a comparable
            # destination. Skip so it doesn't distort recall.
            continue
        expected += 1
        if canon in found_addrs:
            found += 1
        else:
            missing.append({
                "address": addr,
                "role": item.get("role") or "(no role specified)",
                "source": item.get("source") or "(no source specified)",
            })

    recall_pct = (
        100.0 if expected == 0 else round(100.0 * found / expected, 1)
    )

    return {
        "expected": expected,
        "found": found,
        "recall_pct": recall_pct,
        "missing": missing,
    }


def _load_json_file(path: Path) -> dict[str, Any]:
    """Read + parse a JSON object from ``path``. Raises FileNotFoundError
    when absent, ValueError when unparseable or not a JSON object — the
    CLI converts both into a clear message + non-zero exit."""
    if not path.is_file():
        raise FileNotFoundError(f"required file not found: {path}")
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not parse {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(
            f"{path} must contain a JSON object at the root, got "
            f"{type(parsed).__name__}"
        )
    return parsed


def main(argv: list[str] | None = None) -> int:
    """CLI: ``python -m scripts.measure_trace_coverage <case_dir>``.

    Reads ``<case_dir>/freeze_brief.json`` + ``<case_dir>/ground_truth.json``,
    prints the coverage report as indented JSON to stdout, returns 0.

    On any missing / malformed input prints a clear message to stderr and
    returns a non-zero exit code (2 for usage, 1 for missing/bad files) so
    the tool is safe to wire into a CI gate.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print(
            "usage: python -m scripts.measure_trace_coverage <case_dir>",
            file=sys.stderr,
        )
        return 2

    case_dir = Path(args[0])
    if not case_dir.is_dir():
        print(f"error: case_dir is not a directory: {case_dir}", file=sys.stderr)
        return 1

    brief_path = case_dir / "freeze_brief.json"
    gt_path = case_dir / "ground_truth.json"

    try:
        brief = _load_json_file(brief_path)
        ground_truth = _load_json_file(gt_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    report = coverage_report(brief, ground_truth)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
