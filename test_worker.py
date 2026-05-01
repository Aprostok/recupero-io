"""test_worker.py — end-to-end integration test for the Phase 2 worker.

What this test does:
  1. Inserts a synthetic public.investigations row in the user's Supabase db.
  2. Mocks the network-bound pipeline stages (run_trace, list-freeze-targets,
     run_ai_editorial) so the test stays offline. The local I/O, the storage
     adapter, the DB layer, and the state machine are all real.
  3. Manually claims the row via the worker's DB layer and calls
     ``pipeline.run_one()`` directly. Drives by id so a busy queue with other
     rows in flight doesn't interfere with the test.
  4. Verifies the row reaches ``review_required`` and that the expected
     artifacts landed in the bucket.
  5. Flips the row to ``review_approved``, re-claims, runs ``run_one()`` a
     second time, and verifies the row reaches ``completed`` with
     ``freeze_brief.json`` in the bucket.
  6. Cleans up DB row + bucket prefix in a try/finally — runs even on failure.

Bypasses pytest. Run from the repo root with the venv active:

    python test_worker.py

Required .env entries:
    SUPABASE_URL=https://YOUR-PROJECT-REF.supabase.co
    SUPABASE_SERVICE_ROLE_KEY=sb_secret_...
    SUPABASE_DB_URL=postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres

Schema assumption: this test targets the schema currently deployed in the
admin UI's Supabase project (verified via PostgREST OpenAPI on 2026-05-01).
``investigations.case_id`` is a UUID FK to ``cases.id``, so the test inserts
a synthetic ``cases`` row first and links the investigation to it.

The test never modifies pre-existing cases rows — it inserts a new one with
a unique ``case_number`` and deletes both rows in cleanup.

Exit codes:
    0 = all checks passed
    1 = one or more checks failed
    2 = setup problem (missing .env, missing table, etc.)
"""

from __future__ import annotations

import json
import os
import socket
import sys
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest.mock import patch

import psycopg
from dotenv import load_dotenv

from recupero.config import load_config
from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.storage.supabase_case_store import SupabaseCaseStore
from recupero.worker import state as S
from recupero.worker.db import T_CASES, T_INV, WorkerDB
from recupero.worker.pipeline import run_one


# ---------- Fixtures ---------- #


def _build_fixture_case(case_id: str) -> Case:
    """A tiny but valid Case the trace mock returns."""
    now = datetime.now(timezone.utc)
    seed = "0x0000000000000000000000000000000000000001"
    cp = "0x000000000000000000000000000000000000dEaD"

    transfer = Transfer(
        transfer_id="t-1",
        chain=Chain.ethereum,
        tx_hash="0xfeedface",
        block_number=18_000_000,
        block_time=now,
        log_index=0,
        from_address=seed,
        to_address=cp,
        counterparty=Counterparty(address=cp, is_contract=False),
        token=TokenRef(chain=Chain.ethereum, contract=None, symbol="ETH", decimals=18),
        amount_raw="1000000000000000000",
        amount_decimal=Decimal("1.0"),
        usd_value_at_tx=Decimal("3000.00"),
        pricing_source="test",
        hop_depth=1,
        fetched_at=now,
        explorer_url="https://etherscan.io/tx/0xfeedface",
    )
    return Case(
        case_id=case_id,
        seed_address=seed,
        chain=Chain.ethereum,
        incident_time=now - timedelta(hours=1),
        transfers=[transfer],
        trace_started_at=now,
        trace_completed_at=now,
        total_usd_out=Decimal("3000.00"),
    )


def _fake_run_trace(*, case_id: str, **_kwargs: Any) -> Case:
    """Stand-in for run_trace — returns the fixture Case without hitting Etherscan."""
    return _build_fixture_case(case_id)


def _fake_run_ai_editorial(case_id: str, case_store: Any, victim_narrative: str | None = None,
                            api_key: str | None = None) -> tuple[Path, dict[str, Any]]:
    """Stand-in for run_ai_editorial — writes a valid editorial directly with
    REVIEW_REQUIRED=true. Schema mirrors what emit_brief.py expects."""
    case_dir: Path = case_store.case_dir(case_id)
    editorial = {
        "AI_GENERATED": True,
        "REVIEW_REQUIRED": True,
        "CASE_ID": case_id,
        "REPORT_DATE": datetime.now(timezone.utc).strftime("%B %d, %Y"),
        "VICTIM_JURISDICTION": "California, USA",
        "VICTIM_ADDRESS_LINE1": "[fixture]",
        "VICTIM_ADDRESS_LINE2": "[fixture]",
        "INCIDENT_DATE": datetime.now(timezone.utc).strftime("%B %d, %Y"),
        "INCIDENT_TYPE": "Test fixture incident",
        "INCIDENT_NARRATIVE_RECUPERO": "Synthetic narrative for worker test.",
        "INCIDENT_NARRATIVE_FIRST_PERSON": "Synthetic first-person narrative.",
        "INVESTIGATOR_NAME": "Test Investigator",
        "INVESTIGATOR_EMAIL": "test@example.com",
        "INVESTIGATOR_ENTITY": "Recupero Test",
        "INVESTIGATOR_ENTITY_FULL": "Recupero Test, LLC",
        "INVESTIGATOR_WEB": "https://example.com",
        "TEMPLATE_VERSION": "test-1.0",
        "DESTINATION_NOTES": {},
        "UNRECOVERABLE_ITEMS": [],
    }
    out = case_dir / "brief_editorial.json"
    out.write_text(json.dumps(editorial, indent=2, ensure_ascii=False), encoding="utf-8")
    return out, editorial


def _fake_freeze_stage(inv, case_id_str, config, env, local_store, case_dir, bucket):
    """Stand-in for the freeze stage — writes an empty-but-valid
    freeze_asks.json and syncs. Avoids the dormant scan (which requires
    Etherscan) and matches the schema emit_brief.py reads."""
    from recupero.worker.sync import upload_case_dir

    payload = {
        "case_id": case_id_str,
        "total_asks": 0,
        "by_issuer": {},
        "exchange_deposits": [],
    }
    (case_dir / "freeze_asks.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8",
    )
    upload_case_dir(case_dir, bucket)


# ---------- DB helpers ---------- #


def _insert_case(dsn: str, *, case_number: str, victim: dict[str, Any]) -> uuid.UUID:
    """Insert a synthetic cases row with all NOT NULL fields populated."""
    case_id = uuid.uuid4()
    sql = f"""
        INSERT INTO {T_CASES} (
            id, case_number, status, client_name, client_email, country,
            preferred_contact, loss_types, asset_location, wallet_addresses,
            incident_date, awareness_date, reported_to_law_enforcement,
            ic3_reminder_sent_at, description, phone, created_at
        )
        VALUES (
            %(id)s, %(case_number)s, %(status)s, %(name)s, %(email)s, %(country)s,
            %(contact)s, %(loss)s, %(assets)s, %(wallets)s,
            %(incident_date)s, %(awareness_date)s, %(reported)s,
            %(ic3_reminders)s, %(desc)s, %(phone)s, NOW()
        );
    """
    today = datetime.now(timezone.utc).date()
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, {
                "id": case_id,
                "case_number": case_number,
                "status": "intake",
                "name": victim["name"],
                "email": victim["email"],
                "country": victim.get("country", "USA"),
                "contact": "email",
                "loss": ["other"],
                "assets": ["self_custody"],
                "wallets": victim["wallet_address"],
                "incident_date": today - timedelta(days=2),
                "awareness_date": today - timedelta(days=1),
                "reported": False,
                "ic3_reminders": [],  # empty timestamptz[]
                "desc": "Synthetic narrative for end-to-end worker test.",
                "phone": victim.get("phone"),
            })
    return case_id


def _insert_investigation(dsn: str, *, case_id: uuid.UUID) -> uuid.UUID:
    """Insert a queued investigations row pointing at the synthetic cases row."""
    inv_id = uuid.uuid4()
    sql = f"""
        INSERT INTO {T_INV} (
            id, case_id, status, triggered_by, triggered_at,
            chain, seed_address, incident_time, max_depth, dust_threshold_usd
        )
        VALUES (
            %(id)s, %(case_id)s, %(status)s, %(by)s, NOW(),
            %(chain)s, %(seed)s, %(incident)s, %(depth)s, %(dust)s
        );
    """
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, {
                "id": inv_id,
                "case_id": case_id,
                "status": S.QUEUED,
                "by": "worker-test",
                "chain": "ethereum",
                "seed": "0x0000000000000000000000000000000000000001",
                "incident": datetime.now(timezone.utc) - timedelta(hours=2),
                "depth": 1,
                "dust": Decimal("50.0"),
            })
    return inv_id


def _read_status(dsn: str, inv_id: uuid.UUID) -> str:
    sql = f"SELECT status FROM {T_INV} WHERE id = %s;"
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (inv_id,))
            row = cur.fetchone()
    return row[0] if row else "__missing__"


def _set_status(dsn: str, inv_id: uuid.UUID, new_status: str) -> None:
    sql = (
        f"UPDATE {T_INV} SET status = %s, "
        f"worker_id = NULL, last_heartbeat_at = NULL WHERE id = %s;"
    )
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (new_status, inv_id))


def _delete_rows(dsn: str, *, inv_id: uuid.UUID, case_id: uuid.UUID) -> None:
    """Delete the investigation first (FK-respecting), then the case row."""
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f"DELETE FROM {T_INV} WHERE id = %s;", (inv_id,))
            cur.execute(f"DELETE FROM {T_CASES} WHERE id = %s;", (case_id,))


# ---------- Test driver ---------- #


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

    load_dotenv()
    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    service_role_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    db_url = os.environ.get("SUPABASE_DB_URL", "").strip()

    missing = [k for k, v in {
        "SUPABASE_URL": supabase_url,
        "SUPABASE_SERVICE_ROLE_KEY": service_role_key,
        "SUPABASE_DB_URL": db_url,
    }.items() if not v]
    if missing:
        print(
            f"ERROR: missing .env entries: {', '.join(missing)}\n"
            "See the top of this file for the expected format and the table DDL."
        )
        return 2

    cfg, env = load_config()
    worker_id = f"{socket.gethostname()}-{os.getpid()}-test"

    # cases.case_number is varchar(8) — keep it short. "T-" prefix marks test rows.
    case_number = f"T-{uuid.uuid4().hex[:6]}"
    victim_payload = {
        "name": "Test Victim",
        "wallet_address": "0x0000000000000000000000000000000000000001",
        "email": "victim@example.com",
        "phone": "+1-555-0100",
        "country": "USA",
    }

    print("=" * 70)
    print("Phase 2 worker integration test")
    print(f"case_number: {case_number}")
    print(f"worker_id:   {worker_id}")
    print("=" * 70)

    failures: list[str] = []

    def check(label: str, fn) -> None:
        try:
            fn()
            print(f"  ✓ {label}")
        except Exception as e:
            print(f"  ✗ {label}: {e}")
            failures.append(label)

    inv_id: uuid.UUID | None = None
    case_id: uuid.UUID | None = None
    db = WorkerDB(db_url, worker_id=worker_id)

    try:
        # 1. Insert a synthetic cases row, then an investigations row that
        #    points at it (the FK is NOT NULL).
        case_id = _insert_case(db_url, case_number=case_number, victim=victim_payload)
        inv_id = _insert_investigation(db_url, case_id=case_id)
        print(f"\nInserted case_id (FK)    {case_id}")
        print(f"Inserted investigation   {inv_id}")
        print(f"Bucket prefix:           investigations/{inv_id}/")

        patches = [
            patch("recupero.trace.tracer.run_trace", side_effect=_fake_run_trace),
            patch("recupero.reports.ai_editorial.run_ai_editorial",
                  side_effect=_fake_run_ai_editorial),
            patch("recupero.worker.pipeline._stage_list_freeze_targets",
                  side_effect=_fake_freeze_stage),
        ]
        for p in patches:
            p.start()

        try:
            # 2. Pass 1: claim, run_one — should pause at review_required.
            print("\n[Pass 1: queued → review_required]")
            inv = db.claim_one()
            if inv is None or inv.id != inv_id:
                raise RuntimeError(
                    f"claim_one did not pick up our row (got {inv.id if inv else None}, "
                    f"expected {inv_id}). Is another worker draining the queue?"
                )
            print(f"  claimed inv id={inv.id} status={inv.status}")

            with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                    investigation_id=str(inv.id)) as store:
                run_one(inv, config=cfg, env=env, db=db, store=store)

            def _check_review_required():
                status = _read_status(db_url, inv_id)
                assert status == S.REVIEW_REQUIRED, (
                    f"expected status={S.REVIEW_REQUIRED}, got {status!r}"
                )
            check("row reaches review_required", _check_review_required)

            # 3. Bucket contents after pass 1
            with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                    investigation_id=str(inv_id)) as store:
                check("case.json exists in bucket",
                      lambda: store.exists("case.json") or _raise("missing"))
                check("manifest.json exists in bucket",
                      lambda: store.exists("manifest.json") or _raise("missing"))
                check("transfers.csv exists in bucket",
                      lambda: store.exists("transfers.csv") or _raise("missing"))
                check("freeze_asks.json exists in bucket",
                      lambda: store.exists("freeze_asks.json") or _raise("missing"))
                check("brief_editorial.json exists in bucket",
                      lambda: store.exists("brief_editorial.json") or _raise("missing"))

                def _editorial_review_required_true():
                    ed = store.read_json("brief_editorial.json")
                    assert ed.get("REVIEW_REQUIRED") is True, "REVIEW_REQUIRED should be true"
                check("brief_editorial.json has REVIEW_REQUIRED=true",
                      _editorial_review_required_true)

            # 4. Simulate UI approval: flip REVIEW_REQUIRED=false in the file
            #    AND flip the row status to review_approved.
            print("\n[Simulating UI approval]")
            with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                    investigation_id=str(inv_id)) as store:
                ed = store.read_json("brief_editorial.json")
                ed["REVIEW_REQUIRED"] = False
                store.write_json("brief_editorial.json", ed)
            _set_status(db_url, inv_id, S.REVIEW_APPROVED)

            # 5. Pass 2: re-claim, run_one — should run emit and complete.
            print("\n[Pass 2: review_approved → completed]")
            inv2 = db.claim_one()
            if inv2 is None or inv2.id != inv_id:
                raise RuntimeError(
                    f"claim_one (pass 2) did not pick up our row "
                    f"(got {inv2.id if inv2 else None}, expected {inv_id})."
                )
            print(f"  claimed inv id={inv2.id} status={inv2.status}")

            with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                    investigation_id=str(inv_id)) as store:
                run_one(inv2, config=cfg, env=env, db=db, store=store)

            def _check_completed():
                status = _read_status(db_url, inv_id)
                assert status == S.COMPLETED, f"expected status={S.COMPLETED}, got {status!r}"
            check("row reaches completed", _check_completed)

            with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                    investigation_id=str(inv_id)) as store:
                check("freeze_brief.json exists in bucket",
                      lambda: store.exists("freeze_brief.json") or _raise("missing"))

        finally:
            for p in patches:
                try:
                    p.stop()
                except Exception:
                    pass

    finally:
        # Cleanup — must run even on failure.
        print("\n[cleanup]")
        if inv_id is not None:
            try:
                with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                        investigation_id=str(inv_id)) as store:
                    deleted = store.delete_all()
                print(f"  deleted {deleted} bucket object(s)")
            except Exception as e:
                print(f"  bucket cleanup FAILED: {e}")
                failures.append("bucket cleanup")
        if inv_id is not None and case_id is not None:
            try:
                _delete_rows(db_url, inv_id=inv_id, case_id=case_id)
                print(f"  deleted DB rows (inv={inv_id}, case={case_id})")
            except Exception as e:
                print(f"  DB cleanup FAILED: {e}")
                failures.append("DB cleanup")
        db.close()

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


def _raise(msg: str) -> bool:
    raise AssertionError(msg)


if __name__ == "__main__":
    sys.exit(main())
