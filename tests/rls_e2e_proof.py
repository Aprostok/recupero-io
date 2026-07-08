"""Live proof that genuine RLS enforces tenant isolation (migration 043 + the
dual-connection deps wiring). NOT a unit test — needs a real Postgres with two
roles, so it is run by hand / in the RLS rollout gate, not the default suite.

Two roles model the prod design:
  * ``postgres``  — superuser, always bypasses RLS  → the service / worker role.
  * ``app_rw``    — NOSUPERUSER NOBYPASSRLS, non-owner → the restricted API role.

Env expected (set by the runner):
  RECUPERO_DATABASE_URL       -> app_rw DSN   (tenant conn; RLS-subject)
  RECUPERO_AUTH_DATABASE_URL  -> postgres DSN (auth/bypass conn)
  RECUPERO_PLATFORM_JWT_SECRET, RECUPERO_ASSISTANT_ENABLED unset

Proves:
  1. Signup/login work (they run on the BYPASSRLS auth conn).
  2. Through the real API, org A cannot see org B's watched addresses.
  3. Raw SQL as app_rw (bypassing the app's WHERE org_id) — RLS ITSELF scopes
     rows by app.current_org, denies cross-tenant, and returns nothing with no
     GUC. The superuser sees all (worker-bypass holds, incl. investigations).
"""
from __future__ import annotations

import os
import sys

import psycopg
from fastapi.testclient import TestClient

ok = 0
fail = 0


def check(label: str, cond: bool, extra: str = "") -> None:
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
    print(f"[{'PASS' if cond else 'FAIL'}] {label} {extra}")


def main() -> None:
    from recupero.api.app import app

    tenant_dsn = os.environ["RECUPERO_DATABASE_URL"]       # app_rw (restricted)
    svc_dsn = os.environ["RECUPERO_AUTH_DATABASE_URL"]     # postgres (bypass)
    c = TestClient(app)

    # 1) signup two orgs (runs on the auth/bypass conn)
    a = c.post("/v2/auth/signup", json={"email": "a@t.io", "password": "pw-aaaaaaaa", "org_name": "OrgA"})
    b = c.post("/v2/auth/signup", json={"email": "b@t.io", "password": "pw-bbbbbbbb", "org_name": "OrgB"})
    check("signup orgA 201", a.status_code == 201, str(a.status_code))
    check("signup orgB 201", b.status_code == 201, str(b.status_code))
    tok_a = {"authorization": f"Bearer {a.json()['access_token']}"}
    tok_b = {"authorization": f"Bearer {b.json()['access_token']}"}
    org_a, org_b = a.json()["org_id"], b.json()["org_id"]

    # login works under RLS (reads memberships/org on the bypass conn)
    la = c.post("/v2/auth/login", json={"email": "a@t.io", "password": "pw-aaaaaaaa"})
    check("login orgA 200", la.status_code == 200, str(la.status_code))

    # 2) each org adds a watched address (writes via the tenant conn, GUC-scoped)
    ADDR_A = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
    ADDR_B = "0x8589427373D6D84E98730D7795D8f6f8731FDA16"
    ra = c.post("/v2/guard/addresses", headers=tok_a, json={"address": ADDR_A, "chain": "ethereum", "label": "A-only"})
    rb = c.post("/v2/guard/addresses", headers=tok_b, json={"address": ADDR_B, "chain": "ethereum", "label": "B-only"})
    check("orgA add watched 201", ra.status_code == 201, str(ra.status_code))
    check("orgB add watched 201", rb.status_code == 201, str(rb.status_code))

    # org A lists — must see ONLY its own (RLS denies B's row)
    la_list = c.get("/v2/guard/addresses", headers=tok_a).json()["addresses"]
    lb_list = c.get("/v2/guard/addresses", headers=tok_b).json()["addresses"]
    a_addrs = {w["address"].lower() for w in la_list}
    b_addrs = {w["address"].lower() for w in lb_list}
    check("API: orgA sees only its address", a_addrs == {ADDR_A.lower()}, str(a_addrs))
    check("API: orgB sees only its address", b_addrs == {ADDR_B.lower()}, str(b_addrs))
    check("API: no cross-tenant bleed", a_addrs.isdisjoint(b_addrs))

    # 3) RAW SQL as the restricted role — bypasses the app's WHERE org_id, so this
    #    isolates RLS ITSELF. (autocommit so each set_config+select is its own txn;
    #    is_local=true needs a txn, so use a transaction block per org.)
    def count_as(dsn: str, org_id: str | None) -> int:
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            if org_id is not None:
                cur.execute("SELECT set_config('app.current_org', %s, true)", (org_id,))
            cur.execute("SELECT count(*) FROM public.watched_addresses")
            return int(cur.fetchone()[0])

    check("RLS(app_rw, GUC=A): sees 1 row", count_as(tenant_dsn, org_a) == 1)
    check("RLS(app_rw, GUC=B): sees 1 row", count_as(tenant_dsn, org_b) == 1)
    check("RLS(app_rw, no GUC): sees 0 rows", count_as(tenant_dsn, None) == 0)
    check("BYPASS(postgres): sees BOTH rows", count_as(svc_dsn, None) == 2)

    # cross-tenant WRITE denial: as app_rw scoped to A, try to delete B's rows
    with psycopg.connect(tenant_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('app.current_org', %s, true)", (org_a,))
        cur.execute("DELETE FROM public.watched_addresses WHERE address = %s", (ADDR_B,))
        deleted = cur.rowcount
    check("RLS: orgA cannot delete orgB's row", deleted == 0, f"rowcount={deleted}")

    # investigations (the job queue): superuser/worker drains across all orgs
    with psycopg.connect(svc_dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.investigations (seed_address, chain, status, org_id) "
            "VALUES ('0xseedA','ethereum','queued',%s), ('0xseedB','ethereum','queued',%s)",
            (org_a, org_b),
        )
    with psycopg.connect(svc_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.investigations WHERE seed_address LIKE '0xseed%'")
        svc_sees = int(cur.fetchone()[0])
    with psycopg.connect(tenant_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('app.current_org', %s, true)", (org_a,))
        cur.execute("SELECT count(*) FROM public.investigations WHERE seed_address LIKE '0xseed%'")
        tenant_sees = int(cur.fetchone()[0])
    check("worker(bypass) drains BOTH orgs' investigations", svc_sees == 2, f"saw {svc_sees}")
    check("tenant sees only its own investigation", tenant_sees == 1, f"saw {tenant_sees}")

    print(f"\n==== {ok} passed, {fail} failed ====")
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
