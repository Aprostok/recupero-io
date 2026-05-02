"""test_worker_e2e.py — full real-API end-to-end test of the worker pipeline.

Drives the worker pipeline against real Supabase + real Etherscan + real
CoinGecko + real Anthropic, with no mocks. Same code Railway is running;
controlled from your laptop so you see live progress.

Use: a final smoke test BEFORE handing off to Jacob, to catch any
real-pipeline issues (like packaging gaps) that the mocked test_worker.py
doesn't exercise.

Cost per run:
  - ~$0.50 in Anthropic (Opus 4.7, ~10K input + ~3K output tokens)
  - Etherscan: ~50 free-tier calls
  - CoinGecko: ~30 free-tier calls
  - Wallclock: 10-15 minutes (depending on transfer count + AI response time)

Cleanup is in a try/finally and runs even on failure — synthesized cases
+ investigations rows AND the bucket prefix all get deleted.

Run from repo root:  python test_worker_e2e.py
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import psycopg
from dotenv import load_dotenv

# ----- TEST INPUTS ----- #
TEST_SEED_ADDRESS = "0x8E3b200f356724299643402148a25FD4B852Bd53"
TEST_CHAIN = "ethereum"
TEST_INCIDENT = "2026-01-02T00:00:00Z"
TEST_MAX_DEPTH = 1
TEST_DUST_THRESHOLD_USD = 50.0


def _utf8_console() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass


def _fill_todos(obj: Any, _depth: int = 0) -> int:
    """Walk an editorial dict and replace every "TODO: ..." string with a
    deterministic test value. Mirrors what the admin UI's review flow
    must do before flipping to review_approved.

    Returns the count of placeholders replaced.
    """
    count = 0
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(v, str) and v.startswith("TODO:"):
                obj[k] = f"[E2E test fill-in for {k}]"
                count += 1
            else:
                count += _fill_todos(v, _depth + 1)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str) and item.startswith("TODO:"):
                obj[i] = f"[E2E test fill-in #{i}]"
                count += 1
            else:
                count += _fill_todos(item, _depth + 1)
    return count


def _insert_case(dsn: str, *, case_number: str, wallet: str) -> uuid.UUID:
    """Synthetic cases row with all NOT NULL fields filled."""
    case_id = uuid.uuid4()
    today = datetime.now(timezone.utc).date()
    sql = """
        INSERT INTO public.cases (
            id, case_number, status, client_name, client_email, country,
            preferred_contact, loss_types, asset_location, wallet_addresses,
            incident_date, awareness_date, reported_to_law_enforcement,
            ic3_reminder_sent_at, description, created_at
        ) VALUES (
            %(id)s, %(num)s, 'intake', 'E2E Test Victim', 'e2e@test.local',
            'USA', 'email', %(loss)s, %(assets)s, %(wallet)s,
            %(incident)s, %(awareness)s, false, %(ic3)s, %(desc)s, NOW()
        );
    """
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, {
                "id": case_id, "num": case_number, "loss": ["other"],
                "assets": ["self_custody"], "wallet": wallet,
                "incident": today - timedelta(days=10),
                "awareness": today - timedelta(days=8),
                "ic3": [],
                "desc": (
                    "Real-API end-to-end test. The victim noticed unauthorized "
                    "outflows from this wallet on the morning of Jan 2nd; suspected "
                    "compromise via a phishing site that requested a token approval "
                    "the victim signed without inspecting calldata."
                ),
            })
    return case_id


def _insert_investigation_pre_claimed(
    dsn: str,
    *,
    case_id: uuid.UUID,
    chain: str,
    seed: str,
    incident_iso: str,
    max_depth: int,
    dust_threshold_usd: float,
    worker_id: str,
) -> uuid.UUID:
    """Insert directly into 'claimed' state with our worker_id.

    Skips the pending state entirely so Railway's running worker can't race
    us. The PIPELINE code path (db.transition + heartbeat + mark_*) is
    identical to a normal claim — it just keys off worker_id matching.
    """
    inv_id = uuid.uuid4()
    sql = """
        INSERT INTO public.investigations (
            id, case_id, status, triggered_by, triggered_at,
            chain, seed_address, incident_time, max_depth, dust_threshold_usd,
            worker_id, claimed_at, last_heartbeat_at
        ) VALUES (
            %(id)s, %(case)s, 'claimed', 'e2e-test-script', NOW(),
            %(chain)s, %(seed)s, %(incident)s, %(depth)s, %(dust)s,
            %(worker)s, NOW(), NOW()
        );
    """
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, {
                "id": inv_id, "case": case_id,
                "chain": chain, "seed": seed,
                "incident": datetime.fromisoformat(incident_iso.replace("Z", "+00:00")),
                "depth": max_depth, "dust": Decimal(str(dust_threshold_usd)),
                "worker": worker_id,
            })
    return inv_id


def _reclaim_for_test(dsn: str, inv_id: uuid.UUID, worker_id: str) -> None:
    """Pre-claim the row for pass 2 — sets status='claimed' + worker_id
    atomically so we don't have to call claim_one() and race Railway.
    """
    sql = ("UPDATE public.investigations "
           "SET status='claimed', worker_id=%s, claimed_at=NOW(), "
           "last_heartbeat_at=NOW() "
           "WHERE id=%s;")
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (worker_id, inv_id))


def _read_inv(dsn: str, inv_id: uuid.UUID) -> dict[str, Any] | None:
    sql = """
        SELECT status, worker_id, started_at, completed_at, failed_at,
               review_required_at, error_message, error_stage,
               total_loss_usd, max_recoverable_usd, api_costs_usd,
               freezable_issuers, supabase_storage_path
          FROM public.investigations WHERE id = %s;
    """
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (inv_id,))
            row = cur.fetchone()
            if not row:
                return None
            cols = [d.name for d in cur.description]
            return dict(zip(cols, row))


def _set_status(dsn: str, inv_id: uuid.UUID, new: str) -> None:
    sql = ("UPDATE public.investigations SET status=%s, "
           "worker_id=NULL, last_heartbeat_at=NULL WHERE id=%s;")
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (new, inv_id))


def _delete_rows(dsn: str, *, inv_id: uuid.UUID, case_id: uuid.UUID) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM public.investigations WHERE id=%s;", (inv_id,))
            cur.execute("DELETE FROM public.cases WHERE id=%s;", (case_id,))


def main() -> int:
    _utf8_console()
    # override=True so a stale empty value in the shell env (e.g. from a prior
    # `export ANTHROPIC_API_KEY=""`) doesn't shadow the real one in .env.
    load_dotenv(override=True)

    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    service_role_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    db_url = os.environ.get("SUPABASE_DB_URL", "").strip()
    etherscan = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    anthropic = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    missing = [k for k, v in {
        "SUPABASE_URL": supabase_url,
        "SUPABASE_SERVICE_ROLE_KEY": service_role_key,
        "SUPABASE_DB_URL": db_url,
        "ETHERSCAN_API_KEY": etherscan,
        "ANTHROPIC_API_KEY": anthropic,
    }.items() if not v]
    if missing:
        print(f"ERROR: missing env vars: {', '.join(missing)}")
        return 2

    # Lazy imports — keeps startup fast and surfaces import problems clearly
    from recupero.config import load_config
    from recupero.storage.supabase_case_store import SupabaseCaseStore
    from recupero.worker import state as S
    from recupero.worker.db import Investigation, WorkerDB
    from recupero.worker.pipeline import run_one

    cfg, env = load_config()
    worker_id = f"{socket.gethostname()}-{os.getpid()}-e2e"

    case_number = f"E-{uuid.uuid4().hex[:6]}"
    print("=" * 78)
    print("Phase 3 worker E2E — full real-API run")
    print(f"  case_number:        {case_number}")
    print(f"  test_seed_address:  {TEST_SEED_ADDRESS}")
    print(f"  chain:              {TEST_CHAIN}")
    print(f"  incident_time:      {TEST_INCIDENT}")
    print(f"  max_depth:          {TEST_MAX_DEPTH}")
    print(f"  worker_id:          {worker_id}")
    print("=" * 78)

    inv_id: uuid.UUID | None = None
    case_id: uuid.UUID | None = None
    db = WorkerDB(db_url, worker_id=worker_id)
    failures: list[str] = []

    def step(label: str) -> None:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {label}")

    try:
        # ----- Setup -----
        step("Insert cases + investigations rows (investigation pre-claimed by us)")
        case_id = _insert_case(db_url, case_number=case_number, wallet=TEST_SEED_ADDRESS)
        inv_id = _insert_investigation_pre_claimed(
            db_url, case_id=case_id, chain=TEST_CHAIN, seed=TEST_SEED_ADDRESS,
            incident_iso=TEST_INCIDENT, max_depth=TEST_MAX_DEPTH,
            dust_threshold_usd=TEST_DUST_THRESHOLD_USD,
            worker_id=worker_id,
        )
        print(f"  case_id (FK):     {case_id}")
        print(f"  investigation_id: {inv_id}")
        print(f"  bucket prefix:    investigations/{inv_id}/")
        print(f"  status:           claimed (Railway can't race us)")

        # ----- Pass 1: build Investigation model, run real pipeline -----
        step("Pass 1: run real pipeline (trace -> freeze -> editorial)")
        print("  This will take 5-15 min. Real Etherscan, real CoinGecko, real Anthropic.")
        # Pull the row back as an Investigation model
        with psycopg.connect(db_url, autocommit=True) as conn:
            from psycopg.rows import dict_row
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT * FROM public.investigations WHERE id=%s;", (inv_id,))
                row = cur.fetchone()
        inv = Investigation.model_validate(row)
        print(f"  loaded inv id={inv.id} status={inv.status}")

        pass1_start = time.time()
        with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                investigation_id=str(inv.id)) as store:
            run_one(inv, config=cfg, env=env, db=db, store=store)
        elapsed = int(time.time() - pass1_start)
        print(f"  pass 1 wallclock: {elapsed}s")

        # ----- Verify pass 1 outputs -----
        step("Verify pass 1: DB state + bucket artifacts")
        row = _read_inv(db_url, inv_id)
        assert row is not None, "investigation row vanished"
        if row["status"] != S.REVIEW_REQUIRED:
            err = row.get("error_message") or "(no error message)"
            raise RuntimeError(
                f"expected status={S.REVIEW_REQUIRED}, got status={row['status']!r} "
                f"error_stage={row.get('error_stage')!r} error={err}"
            )
        print(f"  status:             {row['status']}")
        print(f"  started_at:         {row['started_at']}")
        print(f"  review_required_at: {row['review_required_at']}")

        with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                investigation_id=str(inv_id)) as store:
            for f in ("case.json", "manifest.json", "transfers.csv",
                      "freeze_asks.json", "brief_editorial.json"):
                assert store.exists(f), f"missing in bucket: {f}"
                print(f"  bucket [OK]:        {f}")

            case_data = store.read_json("case.json")
            n_transfers = len(case_data.get("transfers", []))
            print(f"  case.json transfers: {n_transfers}")
            assert n_transfers >= 0, "negative transfer count?"

            freeze_data = store.read_json("freeze_asks.json")
            print(f"  freeze_asks.json by_issuer: "
                  f"{list(freeze_data.get('by_issuer', {}).keys())}")

            ed = store.read_json("brief_editorial.json")
            assert ed.get("REVIEW_REQUIRED") is True, "editorial REVIEW_REQUIRED not true"
            assert ed.get("AI_GENERATED") is True, "editorial AI_GENERATED not true"
            narrative = (ed.get("INCIDENT_NARRATIVE_RECUPERO") or "")[:200]
            print(f"  editorial narrative (first 200 chars):")
            print(f"    {narrative!r}")

            evidence_files = store.list_evidence()
            print(f"  evidence/*.json count: {len(evidence_files)}")

        # ----- Simulate UI review approval -----
        # Faithful simulation: the admin UI is responsible for filling in
        # any TODO: placeholders the worker left for human review (e.g.
        # VICTIM_ADDRESS_LINE1/2 — cases has no postal-address column,
        # so the worker can't populate those automatically). emit-brief
        # rejects an editorial with leftover TODOs, so we replace them
        # all with sensible test values before flipping the status.
        step("Simulate UI approval (fill TODOs + flip REVIEW_REQUIRED + status)")
        with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                investigation_id=str(inv_id)) as store:
            ed = store.read_json("brief_editorial.json")
            todos_filled = _fill_todos(ed)
            ed["REVIEW_REQUIRED"] = False
            store.write_json("brief_editorial.json", ed)
        _set_status(db_url, inv_id, S.REVIEW_APPROVED)
        print(f"  bucket: filled {todos_filled} TODO placeholder(s)")
        print("  bucket: REVIEW_REQUIRED -> false")
        print(f"  db: status -> {S.REVIEW_APPROVED}")

        # ----- Pass 2: re-claim (atomically; skip claim_one to avoid Railway race) -----
        step("Pass 2: pre-claim + emit-brief (real)")
        _reclaim_for_test(db_url, inv_id, worker_id)
        with psycopg.connect(db_url, autocommit=True) as conn:
            from psycopg.rows import dict_row
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT * FROM public.investigations WHERE id=%s;", (inv_id,))
                row = cur.fetchone()
        inv2 = Investigation.model_validate(row)
        print(f"  re-claimed inv status={inv2.status}")

        pass2_start = time.time()
        with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                investigation_id=str(inv_id)) as store:
            run_one(inv2, config=cfg, env=env, db=db, store=store)
        elapsed = int(time.time() - pass2_start)
        print(f"  pass 2 wallclock: {elapsed}s")

        # ----- Verify pass 2 outputs -----
        step("Verify pass 2: complete + summary fields populated")
        row = _read_inv(db_url, inv_id)
        assert row is not None
        if row["status"] != S.COMPLETED:
            err = row.get("error_message") or "(no error)"
            raise RuntimeError(
                f"expected status={S.COMPLETED}, got status={row['status']!r} "
                f"error_stage={row.get('error_stage')!r} error={err}"
            )
        print(f"  status:                 {row['status']}")
        print(f"  completed_at:           {row['completed_at']}")
        print(f"  total_loss_usd:         {row['total_loss_usd']}")
        print(f"  max_recoverable_usd:    {row['max_recoverable_usd']}")
        print(f"  api_costs_usd:          {row['api_costs_usd']}")
        print(f"  freezable_issuers:      {row['freezable_issuers']}")
        print(f"  supabase_storage_path:  {row['supabase_storage_path']}")

        with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                investigation_id=str(inv_id)) as store:
            assert store.exists("freeze_brief.json"), "freeze_brief.json missing"
            print(f"  bucket [OK]:            freeze_brief.json")
            brief = store.read_json("freeze_brief.json")
            print(f"  brief CASE_ID:          {brief.get('CASE_ID')}")
            print(f"  brief TOTAL_LOSS_USD:   {brief.get('TOTAL_LOSS_USD')}")
            print(f"  brief MAX_RECOVERABLE:  {brief.get('MAX_RECOVERABLE_USD')}")
            print(f"  brief FREEZABLE count:  {len(brief.get('FREEZABLE', []))}")
            print(f"  brief DESTINATIONS:     {len(brief.get('DESTINATIONS', []))}")

    except Exception as e:
        print(f"\n[FAIL] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        failures.append(str(e))

    finally:
        # Cleanup runs even on failure
        print()
        print("[cleanup]")
        if inv_id is not None:
            try:
                with SupabaseCaseStore(cfg, supabase_url, service_role_key,
                                        investigation_id=str(inv_id)) as store:
                    n = store.delete_all()
                print(f"  bucket: deleted {n} object(s)")
            except Exception as e:
                print(f"  bucket cleanup FAILED: {e}")
                failures.append("bucket cleanup")
        if inv_id is not None and case_id is not None:
            try:
                _delete_rows(db_url, inv_id=inv_id, case_id=case_id)
                print(f"  db: deleted inv + cases rows")
            except Exception as e:
                print(f"  db cleanup FAILED: {e}")
                failures.append("db cleanup")
        db.close()

    print()
    print("=" * 78)
    if failures:
        print(f"FAIL ({len(failures)})")
        for f in failures:
            print(f"  - {f}")
        print("=" * 78)
        return 1
    print("PASS — full real pipeline completed end-to-end")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
