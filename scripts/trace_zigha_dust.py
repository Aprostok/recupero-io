"""Batch tracer for the Zigha case dust wallets.

Mr. Zigha controls 22 wallets that were drained in a coordinated attack.
Two large wallets (ZIGHA-VERIFY, ZIGHA-VERIFY-W2) are already traced.
This script traces the remaining 20 "dust" wallets and writes one case folder
per wallet, then prints an aggregate summary.

Run from project root:

    python scripts/trace_zigha_dust.py

The script is idempotent — running it again refreshes each case from current
chain state. Estimated run time: 15-25 minutes (20 wallets × ~30-60s each,
constrained by Etherscan rate limits).
"""

from __future__ import annotations

import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure src/ is importable when run directly
SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from recupero.config import load_config  # noqa: E402
from recupero.logging_setup import setup_logging  # noqa: E402
from recupero.models import Chain  # noqa: E402
from recupero.storage.case_store import CaseStore  # noqa: E402
from recupero.trace.tracer import run_trace  # noqa: E402


# The 20 Zigha-controlled "dust" wallets, in the order he provided them.
# (The two large wallets — primary 0x0cdC902f... and secondary 0x3A9F97C6... —
# already have their own cases and are excluded here.)
DUST_WALLETS = [
    "0x1640b4f3FfA48e3474A79A44a1B482303aC3CDB3",
    "0x1adffaf87096828a49f9dafb45eef0e204ef0f10",
    "0x9ad73884b8bA7C71641F5db3399b8D1B8c311C9a",
    "0x701bFC0893d6b1B295EeDB6f080A4427d2c8e7B2",
    "0xC69f9eE29809d33094E768D24B39b7CccE54d407",
    "0x7d7ad58833ea7d12a8d7bf2e2ea83ae0c9394724",
    "0x9E31d7f9115fD5e03DC12B9B310572d13C0b79E2",
    "0x5c41E18c64f11BbC1043c2166a55A4C7aEa1c0aa",
    "0x95BE283576DaDF7a9A50BD98d5Ea26De118aE4aD",
    "0x89af08c62eCD4EB4d300897d857e35382C575Fe0",
    "0xEfE96c714D5ae999e5C3BD9DdEd46F10EdBAd226",
    "0x2bFD9C47132614f81f61837dC862329fD363A4C8",
    "0xBcBb3DA1F36378235346cf0839EC246F6E39DdCA",
    "0xF6A74a145758ae4391C2C7EF8485918dD3EaaCF5",
    "0x03e73136515B30ca861E7167d32AED30898e8FB0",
    "0xb6E4bf0CaA560eFe833A6f20bBB7E109C0700C10",
    "0x0A09c09d5E52d79dC6027914325B9AbFECEFB0a5",
    "0xECA29393CD2208B63D1A1BC624c53025D52D479A",
    "0x4315dB860E1BF58a1D850661C8ca546046E0960A",
    "0x9B6f8D0669AE5aFb6d452274AfA2ED6CdCF54C4B",
]

# Start the trace from Sept 1, 2025 — three weeks before the secondary wallet
# went silent. Captures the full attack window across all wallets.
INCIDENT_TIME = datetime(2025, 9, 1, tzinfo=timezone.utc)


def main() -> int:
    cfg, env = load_config()
    if not env.ETHERSCAN_API_KEY:
        print("ERROR: missing ETHERSCAN_API_KEY in .env", file=sys.stderr)
        return 2
    setup_logging(cfg.logging.level)
    log = logging.getLogger("trace_zigha_dust")

    store = CaseStore(cfg)
    results: list[dict] = []
    started = time.time()

    print(f"\n=== Tracing {len(DUST_WALLETS)} Zigha dust wallets ===\n")

    for i, wallet in enumerate(DUST_WALLETS, 1):
        case_id = f"ZIGHA-DUST-{i:02d}"
        print(f"[{i:>2}/{len(DUST_WALLETS)}] {wallet} -> {case_id}")
        wallet_started = time.time()
        try:
            case_dir = store.case_dir(case_id)
            case = run_trace(
                chain=Chain.ethereum,
                seed_address=wallet,
                incident_time=INCIDENT_TIME,
                case_id=case_id,
                config=cfg,
                env=env,
                case_dir=case_dir,
            )
            store.write_case(case)
            elapsed = time.time() - wallet_started
            transfers = len(case.transfers)
            priced = [t.usd_value_at_tx for t in case.transfers if t.usd_value_at_tx is not None]
            total_usd = sum(priced) if priced else None
            results.append({
                "wallet": wallet,
                "case_id": case_id,
                "transfers": transfers,
                "total_usd": total_usd,
                "elapsed_s": elapsed,
                "status": "ok",
            })
            usd_str = f"${total_usd:,.2f}" if total_usd else "(no priced transfers)"
            print(f"     -> {transfers} transfers, {usd_str}, {elapsed:.1f}s\n")
        except Exception as e:  # noqa: BLE001
            elapsed = time.time() - wallet_started
            log.error("trace failed for %s: %s", wallet, e)
            results.append({
                "wallet": wallet,
                "case_id": case_id,
                "transfers": 0,
                "total_usd": None,
                "elapsed_s": elapsed,
                "status": f"error: {e}",
            })
            print(f"     -> FAILED: {e}\n")

    total_elapsed = time.time() - started
    print(f"\n=== Done in {total_elapsed/60:.1f} min ===\n")
    print(f"{'Case':<18} {'Wallet':<44} {'#Tx':>5} {'Total USD':>16}  Status")
    print("-" * 110)
    for r in results:
        usd_str = f"${r['total_usd']:,.2f}" if r["total_usd"] else "—"
        print(f"{r['case_id']:<18} {r['wallet']:<44} {r['transfers']:>5} {usd_str:>16}  {r['status']}")

    ok = [r for r in results if r["status"] == "ok"]
    nonzero = [r for r in ok if r["transfers"] > 0]
    print(f"\nTraced {len(ok)}/{len(results)} successfully; {len(nonzero)} had outflows.")
    print("\nNext step: run aggregation —")
    print("  recupero aggregate --cases ZIGHA-VERIFY,ZIGHA-VERIFY-W2," + ",".join(r["case_id"] for r in nonzero))
    return 0


if __name__ == "__main__":
    sys.exit(main())
