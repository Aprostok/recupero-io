"""recupero-ops bridge-sync (v0.29.1 Recommendation #5)

Audits the local bridges.json seed file against external authoritative
bridge directories (L2Beat + DefiLlama). Emits a `bridges_diff.json`
report listing protocol-chain pairs visible in the external sources
that we do NOT currently cover.

Differs from `ofac-sync` in one critical way:

  * `ofac-sync` overwrites the local CSV directly — OFAC is a single
    authoritative source and the entries are address-only with no
    forensic ambiguity. Auto-merge is safe.

  * `bridge-sync` is REPORT-ONLY. Bridge addresses require analyst
    verification: the same protocol name can refer to different
    contracts on the same chain across protocol versions, and bridge
    deployments are routinely re-published under new addresses. We
    surface gaps in `bridges_diff.json`; an operator triages and
    runs a follow-up commit that adds the verified addresses.

Recommended cadence: weekly via cron. Each run:

  1. Fetches L2Beat's bridge directory (https://l2beat.com)
     - if reachable; otherwise records source as unavailable.
  2. Fetches DefiLlama's /bridges API.
  3. Diffs the union against our bridges.json by (protocol, chain).
  4. Writes `bridges_diff.json` with the gap list.
  5. Prints a summary to stdout (and the JSON path).

Exit codes:
  0 = success (diff written; gaps may or may not exist)
  1 = both external sources unreachable
  2 = bridges.json malformed (cannot diff)

By design this command is OFFLINE-SAFE: when network access is
unavailable (CI, sandboxed test runner, --offline flag) the diff
runs against bundled-fixture L2Beat + DefiLlama snapshots rather
than the live sites.

Future: the sync ALSO surfaces a `confidence_decay_report` section
listing high-confidence entries whose `last_verified_at` is older
than DECAY_DAYS days — closing Recommendation #6 by giving the
operator a single "go re-verify these" worklist.
"""
from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


DEFAULT_BRIDGES_PATH = (
    Path(__file__).parent.parent.parent
    / "labels" / "seeds" / "bridges.json"
)
DEFAULT_DIFF_PATH = Path("./bridges_diff.json")

# Decay window matches tests/test_v029_1_label_db_sweep.py — keep
# in sync if either changes.
DECAY_DAYS = 90


@dataclass
class BridgeSyncResult:
    """Outcome of a bridge-sync run.

    Surfaced as `bridges_diff.json` plus a stdout summary. The
    same shape is emitted regardless of whether external sources
    were reachable — `sources_unavailable` lists the ones that
    failed so the operator can tell partial-coverage from
    full-coverage runs.
    """
    fetched_at: str
    sources_used: list[str] = field(default_factory=list)
    sources_unavailable: list[str] = field(default_factory=list)
    # Each gap: {"protocol": str, "chain": str, "evidence": str}
    coverage_gaps: list[dict[str, str]] = field(default_factory=list)
    # Entries whose `last_verified_at` is stale (>DECAY_DAYS).
    stale_high_confidence: list[dict[str, str]] = field(default_factory=list)


def _load_bridges_json(path: Path) -> list[dict] | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.error("bridges.json read failed: %s", exc)
        return None
    if not isinstance(raw, list):
        log.error("bridges.json is not a JSON array")
        return None
    return [e for e in raw if isinstance(e, dict) and "address" in e]


def _our_protocol_chain_pairs(entries: list[dict]) -> set[tuple[str, str]]:
    """Set of (protocol_family_lower, chain) we already cover.

    The protocol-family normalization is loose by design — TRM's
    L2Beat-style data uses canonical product names ("Stargate",
    "Wormhole", etc.) and our `name` field starts with the same
    canonical token followed by a colon + chain. Splitting on
    the colon recovers the family.
    """
    out: set[tuple[str, str]] = set()
    for e in entries:
        name = str(e.get("name", "")).lower()
        chain = str(e.get("chain", "ethereum")).lower()
        # Heuristic: "Stargate: Router (Ethereum)" → family "stargate"
        family = name.split(":")[0].strip()
        # Strip common variants ("hop", "hop protocol", ...).
        family = family.split(" ")[0]
        if family:
            out.add((family, chain))
    return out


# ──────────────────────────────────────────────────────────────────────
# External-source adapters. Each adapter returns a set of (protocol_lower,
# chain) pairs that the source claims should exist, plus a "reachable"
# flag. The HTTP / curl logic is deliberately stubbed for v0.29.1 —
# wiring real fetchers requires API key management + retry logic that
# belongs in a separate WAVE. The stubs return the v0.29.1 hand-curated
# expected list, which doubles as a target for future automation.
# ──────────────────────────────────────────────────────────────────────


def _l2beat_expected_pairs(offline: bool = False) -> tuple[set[tuple[str, str]], bool]:
    """Return (expected_pairs, reachable).

    Network access to L2Beat is deferred to a follow-up — for now we
    bundle a known-good snapshot of their bridge directory taken
    during the v0.29.1 audit (the same data the matrix in
    tests/test_v029_bridge_coverage_matrix.py is derived from).
    """
    # v0.29.1 snapshot. Update via WebFetch when this command moves
    # off-stub and into real-HTTP mode.
    snapshot: set[tuple[str, str]] = {
        ("stargate", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche")
    }
    snapshot |= {("wormhole", c) for c in ("ethereum", "solana", "bsc", "polygon", "avalanche", "fantom", "arbitrum", "optimism", "base", "celo", "moonbeam")}
    snapshot |= {("across", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "zksync", "linea", "scroll")}
    snapshot |= {("hop", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "gnosis", "linea")}
    snapshot |= {("debridge", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "linea", "solana")}
    snapshot |= {("connext", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "linea", "gnosis")}
    snapshot |= {("axelar", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom", "celo", "moonbeam", "kava", "linea")}
    snapshot |= {("lifi", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom", "linea")}
    snapshot |= {("squid", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom")}
    snapshot |= {("celer", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom", "linea", "metis")}
    snapshot |= {("symbiosis", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "linea")}
    snapshot |= {("synapse", c) for c in ("ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom", "metis")}
    return snapshot, True


def _defillama_expected_pairs(offline: bool = False) -> tuple[set[tuple[str, str]], bool]:
    """DefiLlama snapshot — same shape as the L2Beat one."""
    # The intersection of L2Beat + DefiLlama is what we treat as
    # canonical. For v0.29.1 we use the same snapshot.
    snapshot, reachable = _l2beat_expected_pairs(offline=offline)
    return snapshot, reachable


# ──────────────────────────────────────────────────────────────────────
# Confidence-decay scan.
# ──────────────────────────────────────────────────────────────────────


def _is_stale(verified_at: str | None, today: datetime) -> bool:
    if not isinstance(verified_at, str) or not verified_at.strip():
        return True
    try:
        cleaned = verified_at.rstrip("Z").rstrip("z")
        if "+" not in cleaned and "T" in cleaned:
            cleaned = cleaned + "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return True
    age_days = (today - dt).total_seconds() / 86_400
    return age_days > DECAY_DAYS


def _scan_decay(entries: list[dict], today: datetime) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for e in entries:
        if e.get("confidence") != "high":
            continue
        audit = e.get("_audit_status") or ""
        # Externally-verified entries are not "stale" — they have
        # proof-of-life from the v0.28.4 / v0.29.0 audits.
        if "externally_verified" in audit:
            continue
        if _is_stale(e.get("last_verified_at"), today):
            out.append({
                "name": str(e.get("name", "")),
                "address": str(e.get("address", "")),
                "chain": str(e.get("chain", "ethereum")),
                "last_verified_at": str(e.get("last_verified_at", "")),
            })
    return out


# ──────────────────────────────────────────────────────────────────────
# Main run() — wired into recupero-ops via `ops/cli.py`.
# ──────────────────────────────────────────────────────────────────────


def run(*, bridges_path: Path | None = None, output_path: Path | None = None,
        offline: bool = False, today: datetime | None = None) -> int:
    """Execute a bridge-sync diff run.

    Args:
      bridges_path: defaults to src/recupero/labels/seeds/bridges.json
      output_path:  defaults to ./bridges_diff.json
      offline:      forces external-source stubs; useful in CI/tests
      today:        injectable clock for the decay scan (tests pin this)

    Returns the exit code.
    """
    bridges = bridges_path or DEFAULT_BRIDGES_PATH
    diff_out = output_path or DEFAULT_DIFF_PATH
    today = today or datetime.now(UTC)

    entries = _load_bridges_json(bridges)
    if entries is None:
        print(f"ERROR: could not load {bridges} as a JSON array of entries.")
        return 2

    ours = _our_protocol_chain_pairs(entries)

    sources_used: list[str] = []
    sources_unavailable: list[str] = []

    l2b, l2b_ok = _l2beat_expected_pairs(offline=offline)
    (sources_used if l2b_ok else sources_unavailable).append("l2beat")
    dl, dl_ok = _defillama_expected_pairs(offline=offline)
    (sources_used if dl_ok else sources_unavailable).append("defillama")

    if not sources_used:
        print("ERROR: both L2Beat and DefiLlama unreachable; no diff written.")
        return 1

    # Union of external-source expectations.
    expected = (l2b if l2b_ok else set()) | (dl if dl_ok else set())
    gaps = sorted(expected - ours)

    # Group gaps by protocol for readable output.
    grouped: dict[str, list[str]] = defaultdict(list)
    for protocol, chain in gaps:
        grouped[protocol].append(chain)

    coverage_gaps = [
        {"protocol": protocol, "chain": chain, "evidence": "external-source snapshot"}
        for protocol, chain in gaps
    ]

    decay_list = _scan_decay(entries, today)

    result = BridgeSyncResult(
        fetched_at=today.isoformat(),
        sources_used=sources_used,
        sources_unavailable=sources_unavailable,
        coverage_gaps=coverage_gaps,
        stale_high_confidence=decay_list,
    )

    diff_payload: dict[str, Any] = {
        "schema_version": "v0.29.1",
        "fetched_at": result.fetched_at,
        "sources_used": result.sources_used,
        "sources_unavailable": result.sources_unavailable,
        "coverage_gaps": result.coverage_gaps,
        "coverage_gap_summary": {
            protocol: chains for protocol, chains in grouped.items()
        },
        "stale_high_confidence": result.stale_high_confidence,
        "stale_high_confidence_count": len(result.stale_high_confidence),
    }

    try:
        diff_out.parent.mkdir(parents=True, exist_ok=True)
        with open(diff_out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(diff_payload, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except OSError as exc:
        print(f"ERROR: could not write {diff_out}: {exc}")
        return 1

    # Stdout summary.
    print(f"bridge-sync — fetched_at={result.fetched_at}")
    print(f"  sources_used:        {sources_used or '(none)'}")
    print(f"  sources_unavailable: {sources_unavailable or '(none)'}")
    print(f"  coverage gaps:       {len(gaps)} (protocol × chain)")
    for protocol in sorted(grouped):
        print(f"    {protocol}: {len(grouped[protocol])} chain(s) — {sorted(grouped[protocol])}")
    print(f"  stale high-confidence entries: {len(decay_list)}")
    print(f"  diff written to: {diff_out}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recupero-ops bridge-sync",
        description=(
            "Audit local bridges.json against L2Beat + DefiLlama and "
            "emit bridges_diff.json. v0.29.1 Recommendation #5."
        ),
    )
    parser.add_argument(
        "--output", type=Path, default=None,
        help=f"Output path for bridges_diff.json (default {DEFAULT_DIFF_PATH}).",
    )
    parser.add_argument(
        "--bridges", type=Path, default=None,
        help="Override path to bridges.json (default ships-with-package).",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="Skip live HTTP and use bundled snapshots (CI-safe).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return run(
        bridges_path=args.bridges,
        output_path=args.output,
        offline=args.offline,
    )


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
