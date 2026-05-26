"""Single-command end-to-end smoke test against the live Railway worker.

Runs the full pipeline cycle:

  1. Insert a fresh pending investigation row (small cheap trace).
  2. Wait for it to claim → trace → freeze → editorial → awaiting_review.
  3. Auto-approve the editorial (fills any TODO placeholders).
  4. Wait for building_package → complete.
  5. Assert the expected artifacts landed in the Supabase bucket.
  6. Print a summary; optionally clean up the test rows.

Designed as the production-ready replacement for the ad-hoc reset+poll
loops we've been running by hand all day. One invocation either prints
"PASS" + a clean summary, or "FAIL" with the specific check that broke.

Use:
    python scripts/e2e_smoke.py                       # ethereum default
    python scripts/e2e_smoke.py --seed 0xABC... --chain ethereum --max-depth 3
    python scripts/e2e_smoke.py --keep                # leave the row + bucket prefix
    python scripts/e2e_smoke.py --timeout-sec 1800    # cap wait time

Exit codes:
    0   PASS — pipeline completed end-to-end + all artifacts present
    1   FAIL — pipeline failed, timed out, or artifacts missing
    2   USAGE — missing env vars / unparseable arguments
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

# Force UTF-8 on Windows so the unicode status chars don't choke cp1252.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402


def _pooled(dsn: str) -> str:
    if "db." in dsn and ".supabase.co" in dsn:
        m = re.search(
            r"postgres(?:ql)?://([^:]+):([^@]+)@db\.([^.]+)\.supabase\.co",
            dsn,
        )
        if m:
            user, pwd, ref = m.group(1), m.group(2), m.group(3)
            return (
                f"postgresql://{user}.{ref}:{pwd}"
                f"@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
            )
    return dsn


def _step(label: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {label}", flush=True)


def _fail(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"\nFAIL: {msg}", flush=True)
    sys.exit(1)


def _insert_case_and_inv(*, dsn: str, seed: str, chain: str,
                         incident_iso: str, max_depth: int) -> tuple[uuid.UUID, uuid.UUID]:
    case_id = uuid.uuid4()
    inv_id = uuid.uuid4()
    case_number = f"S-{uuid.uuid4().hex[:6]}"
    today = datetime.now(timezone.utc).date()
    incident = datetime.fromisoformat(incident_iso.replace("Z", "+00:00"))

    with psycopg.connect(_pooled(dsn), autocommit=True,
                         prepare_threshold=None, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO public.cases (
                    id, case_number, status, client_name, client_email,
                    country, preferred_contact, loss_types, asset_location,
                    wallet_addresses, incident_date, awareness_date,
                    reported_to_law_enforcement, ic3_reminder_sent_at,
                    description, created_at
                ) VALUES (
                    %s, %s, 'intake', 'E2E Smoke', 'e2e@test.local',
                    'USA', 'email', %s, %s, %s, %s, %s,
                    false, %s, %s, NOW()
                );
            """, (
                case_id, case_number, ["other"], ["self_custody"], seed,
                today - timedelta(days=10), today - timedelta(days=8),
                [], "End-to-end smoke test row",
            ))
            cur.execute("""
                INSERT INTO public.investigations (
                    id, case_id, status, triggered_by, triggered_at,
                    chain, seed_address, incident_time, max_depth,
                    dust_threshold_usd
                ) VALUES (
                    %s, %s, 'pending', 'e2e-smoke-script', NOW(),
                    %s, %s, %s, %s, %s
                );
            """, (
                inv_id, case_id, chain, seed, incident,
                max_depth, Decimal("50.0"),
            ))
    return case_id, inv_id


def _poll_until(*, dsn: str, inv_id: uuid.UUID, target_status: str,
                timeout_sec: int) -> dict | None:
    """Poll the investigations row until it's at ``target_status`` or
    a terminal state (failed). Returns the final row or None on timeout."""
    deadline = time.time() + timeout_sec
    last_status = None
    last_hb = None
    while time.time() < deadline:
        with psycopg.connect(_pooled(dsn), prepare_threshold=None,
                             row_factory=dict_row, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT status, worker_id, last_heartbeat_at, completed_at, "
                    "review_required_at, api_costs_usd, error_stage, "
                    "error_message FROM public.investigations WHERE id=%s;",
                    (inv_id,),
                )
                r = cur.fetchone()
                if not r:
                    return None
                state = (r["status"], r["last_heartbeat_at"])
                if state != (last_status, last_hb):
                    print(
                        f"  [{datetime.now().strftime('%H:%M:%S')}] "
                        f"status={r['status']} worker={r['worker_id']} "
                        f"hb={r['last_heartbeat_at']}",
                        flush=True,
                    )
                    last_status, last_hb = state
                if r["status"] == target_status:
                    return r
                if r["status"] == "failed":
                    return r
        time.sleep(8)
    return None


def _approve_editorial(*, dsn: str, supabase_url: str, service_role: str,
                       inv_id: uuid.UUID, cfg) -> None:
    """Fill TODO placeholders + flip the bucket editorial +
    DB status to review_approved — same shape as Jacob's UI flow."""
    from recupero.storage.supabase_case_store import SupabaseCaseStore

    def _fill(obj, depth=0, path=""):
        skip = {"AI_GENERATED", "AI_MODEL", "AI_GENERATED_AT",
                "REVIEW_REQUIRED", "REVIEW_INSTRUCTIONS"}
        n = 0
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if not path and k in skip:
                    continue
                if isinstance(v, str) and "TODO:" in v:
                    obj[k] = f"[e2e-smoke fill-in for {k}]"
                    n += 1
                else:
                    n += _fill(v, depth + 1, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str) and "TODO:" in item:
                    obj[i] = f"[e2e-smoke fill-in #{i}]"
                    n += 1
                else:
                    n += _fill(item, depth + 1, f"{path}[{i}]")
        return n

    with SupabaseCaseStore(cfg, supabase_url, service_role,
                            investigation_id=str(inv_id)) as store:
        ed = store.read_json("brief_editorial.json")
        filled = _fill(ed)
        ed["REVIEW_REQUIRED"] = False
        store.write_json("brief_editorial.json", ed)
        print(f"  filled {filled} TODO placeholder(s)", flush=True)

    with psycopg.connect(_pooled(dsn), autocommit=True,
                         prepare_threshold=None, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE public.investigations SET status='review_approved', "
                "worker_id=NULL, last_heartbeat_at=NULL WHERE id=%s;",
                (inv_id,),
            )


def _assert_artifacts(*, supabase_url: str, service_role: str,
                      inv_id: uuid.UUID, cfg) -> list[str]:
    """Return the list of missing-expected-artifacts (empty = success)."""
    from recupero.storage.supabase_case_store import SupabaseCaseStore
    missing: list[str] = []
    must_have_top = {"case.json", "manifest.json", "transfers.csv",
                     "freeze_asks.json", "brief_editorial.json",
                     "freeze_brief.json"}
    with SupabaseCaseStore(cfg, supabase_url, service_role,
                            investigation_id=str(inv_id)) as store:
        for f in must_have_top:
            if not store.exists(f):
                missing.append(f)
        briefs = sorted(store.list_files("briefs"))
        if not any(b.startswith("freeze_request_") for b in briefs):
            missing.append("briefs/freeze_request_*.html")
        if not any(b.startswith("le_handoff_") for b in briefs):
            missing.append("briefs/le_handoff_*.html")
        if not any(b.endswith(".pdf") for b in briefs):
            missing.append("briefs/*.pdf")
        if not any(b.startswith("flow_") and b.endswith(".svg") for b in briefs):
            missing.append("briefs/flow_*.svg")
    return missing


def _cleanup(*, dsn: str, supabase_url: str, service_role: str,
             inv_id: uuid.UUID, case_id: uuid.UUID, cfg) -> None:
    from recupero.storage.supabase_case_store import SupabaseCaseStore
    try:
        with SupabaseCaseStore(cfg, supabase_url, service_role,
                                investigation_id=str(inv_id)) as store:
            n = store.delete_all()
            print(f"  bucket: deleted {n} object(s)", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"  bucket cleanup FAILED: {e}", flush=True)
    try:
        with psycopg.connect(_pooled(dsn), autocommit=True,
                             prepare_threshold=None, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM public.investigations WHERE id=%s;",
                            (inv_id,))
                cur.execute("DELETE FROM public.cases WHERE id=%s;",
                            (case_id,))
        print("  db: deleted inv + cases rows", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"  db cleanup FAILED: {e}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--seed", default="0x8E3b200f356724299643402148a25FD4B852Bd53",
        help="Seed wallet address. Default: the ALEC-TEST-2026 fixture.",
    )
    parser.add_argument(
        "--chain", default="ethereum",
        choices=["ethereum", "arbitrum", "base", "polygon",
                 "bsc", "solana", "hyperliquid"],
    )
    parser.add_argument("--max-depth", type=int, default=1)
    parser.add_argument(
        "--incident", default="2026-01-02T00:00:00Z",
    )
    parser.add_argument(
        "--timeout-sec", type=int, default=None,
        help="Max total wait time for awaiting_review. Default scales "
             "with max_depth: 900s (15 min) at depth 1, 2700s (45 min) "
             "at depth >=3. Override with this flag for tighter ceilings.",
    )
    parser.add_argument(
        "--keep", action="store_true",
        help="Don't clean up the test row + bucket prefix after PASS — "
             "useful for inspecting artifacts manually.",
    )
    args = parser.parse_args()

    # Scale the awaiting_review timeout with max_depth — a depth=3
    # trace on a fan-out-heavy wallet legitimately takes 25-35 min;
    # depth=1 is 30-60s. A flat 15-min default was rejecting healthy
    # depth=3 runs as timeouts.
    if args.timeout_sec is None:
        args.timeout_sec = 2700 if args.max_depth >= 3 else 900

    load_dotenv(override=True)
    # v0.30.2 (V030_2_SCRIPTS_AUDIT T1-A): refuse to run against a
    # prod-shaped DSN unless the operator explicitly opts in via
    # RECUPERO_ALLOW_PROD_DSN=1. e2e_smoke writes a synthetic row to
    # public.cases + public.investigations and DELETEs it on cleanup
    # (lines ~243-247); if pointed at prod, the row briefly exists
    # and would consume a Stripe webhook before cleanup. Refuse by
    # default; require explicit opt-in.
    from _prod_dsn_guard import assert_not_prod_dsn  # noqa: E402
    assert_not_prod_dsn("e2e_smoke: synthetic case lifecycle with INSERT+DELETE on public.cases")
    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    service_role = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not all([dsn, supabase_url, service_role]):
        print("FAIL: SUPABASE_DB_URL / SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY required")
        return 2

    from recupero.config import load_config
    cfg, _ = load_config()

    case_id, inv_id = None, None
    try:
        _step("Insert pending investigation row")
        case_id, inv_id = _insert_case_and_inv(
            dsn=dsn, seed=args.seed, chain=args.chain,
            incident_iso=args.incident, max_depth=args.max_depth,
        )
        print(f"  case_id={case_id}")
        print(f"  inv_id={inv_id}")

        _step("Wait for awaiting_review (Railway claims + runs trace+freeze+editorial)")
        r = _poll_until(dsn=dsn, inv_id=inv_id,
                        target_status="awaiting_review",
                        timeout_sec=args.timeout_sec)
        if r is None:
            _fail(f"timed out waiting for awaiting_review after {args.timeout_sec}s")
        if r["status"] == "failed":
            _fail(f"pipeline failed at {r['error_stage']}: {r['error_message']}")
        print(f"  reached awaiting_review at {r['review_required_at']}")
        print(f"  api_costs so far: ${r['api_costs_usd']}")

        _step("Approve editorial (fill TODOs + flip status)")
        _approve_editorial(dsn=dsn, supabase_url=supabase_url,
                           service_role=service_role, inv_id=inv_id, cfg=cfg)

        _step("Wait for complete (building_package runs)")
        r = _poll_until(dsn=dsn, inv_id=inv_id,
                        target_status="complete",
                        timeout_sec=180)  # building_package is fast
        if r is None:
            _fail("timed out waiting for complete after approval")
        if r["status"] != "complete":
            _fail(f"expected complete, got {r['status']}: {r.get('error_message')}")
        print(f"  total api_costs: ${r['api_costs_usd']}")

        _step("Verify bucket artifacts")
        missing = _assert_artifacts(
            supabase_url=supabase_url, service_role=service_role,
            inv_id=inv_id, cfg=cfg,
        )
        if missing:
            _fail(f"missing expected artifacts: {missing}")
        print("  all expected artifacts present")

        print(f"\nPASS — pipeline completed end-to-end")
        return 0
    finally:
        if not args.keep and inv_id is not None and case_id is not None:
            _step("Cleanup (use --keep to skip this)")
            _cleanup(dsn=dsn, supabase_url=supabase_url,
                     service_role=service_role,
                     inv_id=inv_id, case_id=case_id, cfg=cfg)


if __name__ == "__main__":
    raise SystemExit(main())
