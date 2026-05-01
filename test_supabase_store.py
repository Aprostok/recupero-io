"""test_supabase_store.py — round-trip test for SupabaseCaseStore.

Writes a minimal Case to Supabase Storage under a fresh UUID prefix, exercises
every public method, then deletes everything (the cleanup runs even if checks
fail — leaving test files behind in production storage is unacceptable).

Bypasses pytest. Run from the repo root with the venv active:

    python test_supabase_store.py

Exit codes:
    0 = all checks passed
    1 = one or more checks failed
    2 = setup problem (missing .env entries, missing config, etc.)
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from dotenv import load_dotenv

from recupero.config import load_config
from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.storage.supabase_case_store import SupabaseCaseStore


def _build_minimal_case(case_id: str) -> Case:
    now = datetime.now(timezone.utc)
    incident = now - timedelta(hours=1)
    seed = "0x0000000000000000000000000000000000000001"
    counterparty_addr = "0x000000000000000000000000000000000000dEaD"

    transfer = Transfer(
        transfer_id="t-1",
        chain=Chain.ethereum,
        tx_hash="0xdeadbeef",
        block_number=18_000_000,
        block_time=now,
        log_index=0,
        from_address=seed,
        to_address=counterparty_addr,
        counterparty=Counterparty(address=counterparty_addr, is_contract=False),
        token=TokenRef(chain=Chain.ethereum, contract=None, symbol="ETH", decimals=18),
        amount_raw="1000000000000000000",
        amount_decimal=Decimal("1.0"),
        usd_value_at_tx=Decimal("3000.00"),
        pricing_source="test",
        hop_depth=1,
        fetched_at=now,
        explorer_url="https://etherscan.io/tx/0xdeadbeef",
    )

    return Case(
        case_id=f"test-{case_id}",
        seed_address=seed,
        chain=Chain.ethereum,
        incident_time=incident,
        transfers=[transfer],
        trace_started_at=now,
        trace_completed_at=now,
        total_usd_out=Decimal("3000.00"),
    )


def main() -> int:
    # Windows cp1252 consoles choke on the ✓/✗ check marks — force UTF-8.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

    load_dotenv()
    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    service_role_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not supabase_url or not service_role_key:
        print(
            "ERROR: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env\n"
            "Add to .env at the repo root:\n"
            '  SUPABASE_URL="https://YOUR-PROJECT-REF.supabase.co"\n'
            '  SUPABASE_SERVICE_ROLE_KEY="sb_secret_..."'
        )
        return 2

    test_uuid = uuid.uuid4()
    print("=" * 70)
    print(f"SupabaseCaseStore round-trip test")
    print(f"Test investigation_id: {test_uuid}")
    print(f"Storage prefix:        investigations/{test_uuid}/")
    print("=" * 70)

    cfg, _env = load_config()
    case = _build_minimal_case(str(test_uuid))

    failures: list[str] = []

    def check(label: str, fn) -> None:
        try:
            fn()
            print(f"  ✓ {label}")
        except Exception as e:
            print(f"  ✗ {label}: {e}")
            failures.append(label)

    store = SupabaseCaseStore(
        cfg,
        supabase_url,
        service_role_key,
        investigation_id=str(test_uuid),
    )

    try:
        print("\n[checks]")

        def _write_case() -> None:
            p = store.write_case(case)
            expected = f"investigations/{test_uuid}/case.json"
            assert p == expected, f"unexpected path: {p!r} (expected {expected!r})"
        check("write_case writes case.json + manifest.json + transfers.csv", _write_case)

        def _read_case() -> None:
            got = store.read_case()
            assert got.case_id == case.case_id, (
                f"case_id mismatch: {got.case_id!r} != {case.case_id!r}"
            )
            assert got.chain == case.chain, f"chain mismatch: {got.chain} != {case.chain}"
            assert got.seed_address == case.seed_address, "seed_address mismatch"
            assert len(got.transfers) == len(case.transfers), (
                f"transfer count: {len(got.transfers)} != {len(case.transfers)}"
            )
            assert got.transfers[0].tx_hash == case.transfers[0].tx_hash, "tx_hash mismatch"
            assert got.transfers[0].amount_decimal == case.transfers[0].amount_decimal, (
                "amount_decimal mismatch (Decimal round-trip broken)"
            )
        check("read_case returns equivalent Case", _read_case)

        check(
            "write_json('freeze_asks.json', ...) succeeds",
            lambda: store.write_json("freeze_asks.json", {"test": "data"}),
        )

        def _read_json() -> None:
            data = store.read_json("freeze_asks.json")
            assert data == {"test": "data"}, f"unexpected payload: {data!r}"
        check("read_json returns the same payload", _read_json)

        def _exists_true() -> None:
            assert store.exists("freeze_asks.json") is True, "expected True"
        check("exists('freeze_asks.json') is True", _exists_true)

        def _exists_false() -> None:
            assert store.exists("definitely-not-there.json") is False, "expected False"
        check("exists('definitely-not-there.json') is False", _exists_false)

        check(
            "write_evidence('0xdeadbeef', ...) succeeds",
            lambda: store.write_evidence("0xdeadbeef", {"some": "evidence"}),
        )

        def _list_evidence() -> None:
            ev = store.list_evidence()
            assert "0xdeadbeef" in ev, f"got {ev!r}"
        check("list_evidence contains '0xdeadbeef'", _list_evidence)

        def _list_files() -> None:
            files = store.list_files()
            for required in ("case.json", "manifest.json", "transfers.csv", "freeze_asks.json"):
                assert required in files, f"{required} missing from list_files: {files!r}"
        check("list_files contains case.json, manifest.json, transfers.csv, freeze_asks.json",
              _list_files)

        def _missing_text() -> None:
            try:
                store.read_text("nope-not-here.txt")
            except FileNotFoundError:
                return
            raise AssertionError("expected FileNotFoundError, got no exception")
        check("read_text on missing file raises FileNotFoundError", _missing_text)

    finally:
        print("\n[cleanup]")
        try:
            count = store.delete_all()
            print(f"  deleted {count} object(s) under investigations/{test_uuid}/")
            if count == 0:
                print("  WARNING: delete_all returned 0 — nothing to remove")
                failures.append("cleanup returned 0 deleted objects")
        except Exception as e:
            print(f"  cleanup FAILED: {e}")
            failures.append("cleanup (delete_all)")
        finally:
            store.close()

    print()
    print("=" * 70)
    if failures:
        print(f"FAIL ({len(failures)} check(s) failed):")
        for f in failures:
            print(f"  - {f}")
        print("=" * 70)
        return 1
    print("PASS — all checks succeeded")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
