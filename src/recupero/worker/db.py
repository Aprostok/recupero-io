"""Postgres layer for the worker.

Matches the real public.investigations / public.cases schema in Jacob's
admin UI repo (verified via PostgREST OpenAPI on 2026-05-01). Differences
from the original Phase 2 spec doc:

  * ``investigations.case_id`` is a UUID FK to ``cases.id``, not freeform text.
  * Victim/narrative data lives on ``cases``, not on ``investigations``.
  * No ``priority``, ``current_stage``, ``updated_at``, or ``created_at`` columns
    on ``investigations``. Ordering uses ``triggered_at``.
  * Richer timestamp set: ``started_at``, ``failed_at``, ``review_required_at``,
    ``reviewed_at``.
  * Worker writes outputs back to dedicated columns (``total_loss_usd``,
    ``max_recoverable_usd``, ``freezable_issuers``, ``supabase_storage_path``).

If the schema drifts further, every column name is a constant near the top
so updates stay surgical.

Connection target is the Supabase transaction-mode pooler (port 6543). Every
method opens a short-lived connection per call — no long-lived transactions,
so the pooler is happy.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict

from recupero.worker import state as S

log = logging.getLogger(__name__)

# ----- Schema constants ----- #

T_INV = "public.investigations"
T_CASES = "public.cases"

# investigations columns we read or write
COL_ID = "id"
COL_CASE_ID = "case_id"               # UUID FK -> cases.id
COL_STATUS = "status"
COL_TRIGGERED_BY = "triggered_by"
COL_TRIGGERED_AT = "triggered_at"
COL_WORKER_ID = "worker_id"
COL_CLAIMED_AT = "claimed_at"
COL_HEARTBEAT = "last_heartbeat_at"
COL_STARTED_AT = "started_at"
COL_COMPLETED_AT = "completed_at"
COL_FAILED_AT = "failed_at"
COL_ERROR_MESSAGE = "error_message"
COL_ERROR_STAGE = "error_stage"
COL_REVIEW_REQUIRED_AT = "review_required_at"
COL_CHAIN = "chain"
COL_SEED_ADDRESS = "seed_address"
COL_INCIDENT_TIME = "incident_time"
COL_MAX_DEPTH = "max_depth"
COL_DUST_THRESHOLD = "dust_threshold_usd"
COL_STORAGE_PATH = "supabase_storage_path"
COL_TOTAL_LOSS = "total_loss_usd"
COL_MAX_RECOVERABLE = "max_recoverable_usd"
COL_API_COSTS = "api_costs_usd"
COL_FREEZABLE_ISSUERS = "freezable_issuers"

# cases columns we read for victim info / narrative
COL_CASE_NUMBER = "case_number"
COL_CLIENT_NAME = "client_name"
COL_CLIENT_EMAIL = "client_email"
COL_CLIENT_PHONE = "phone"
COL_COUNTRY = "country"
COL_DESCRIPTION = "description"
COL_INCIDENT_DATE = "incident_date"
# Postal address + jurisdiction + IC3 reference, added in PR #12 on
# the admin-UI side. The worker reads these to pre-fill the
# editorial-drafting TODOs so the operator review form stops being
# a data-entry exercise on case-driven runs. See Jacob's reliability
# Ask #2 (v0.5.2): the AI no longer hallucinates a TODO when the
# cases row already has the answer.
COL_ADDRESS_LINE1 = "address_line1"
COL_ADDRESS_LINE2 = "address_line2"
COL_JURISDICTION = "jurisdiction"
COL_IC3_CASE_ID = "ic3_case_id"


# ----- Row models ----- #


class Investigation(BaseModel):
    """The investigations row the worker cares about. Extra columns ignored."""

    model_config = ConfigDict(extra="ignore")

    id: UUID
    # case_id nullable as of the wallet-trace migration — rows with
    # case_id=NULL are "scratch" wallet traces (intake calls,
    # ZachXBT-tagged wallets, internal R&D). They have no associated
    # cases row, no victim info, and typically run with skip_editorial
    # and skip_freeze_briefs both set. The pipeline branches on this:
    # see worker/pipeline.py for the null-case_id codepath.
    case_id: UUID | None = None
    status: str
    triggered_by: str | None = None
    triggered_at: datetime | None = None
    worker_id: str | None = None
    claimed_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failed_at: datetime | None = None
    error_message: str | None = None
    error_stage: str | None = None
    review_required_at: datetime | None = None
    chain: str
    seed_address: str
    # Nullable for wallet-trace rows (case_id=NULL) — Jacob's admin UI
    # doesn't collect an incident moment when the operator just wants to
    # trace a wallet's full history. The pipeline's _stage_trace defaults
    # this to an early-chain timestamp on the wallet-trace path so the
    # trace covers everything the seed address ever touched.
    #
    # IMPORTANT: this MUST stay nullable. The previous non-null version
    # caused claim_one() to UPDATE the row to `claimed` and THEN raise a
    # pydantic ValidationError, leaving the row stuck in `claimed`
    # status with heartbeat==claimed_at until the reaper killed it 5min
    # later. Three workers in a row hit this exact pattern in prod
    # before we caught it. See test_claim_one_with_null_incident_time.
    incident_time: datetime | None = None
    max_depth: int = 1
    dust_threshold_usd: Decimal | None = None

    # Wallet-trace metadata (Phase 4 — Jacob spec, migration adds
    # label / skip_editorial / skip_freeze_briefs columns). Existing
    # case-driven rows ignore these (defaults match pre-migration
    # behavior — no label, no skips).
    label: str | None = None
    skip_editorial: bool = False
    skip_freeze_briefs: bool = False


class CaseData(BaseModel):
    """Subset of public.cases the worker reads to build victim.json + narrative."""

    model_config = ConfigDict(extra="ignore")

    id: UUID
    case_number: str | None = None
    client_name: str | None = None
    client_email: str | None = None
    phone: str | None = None
    country: str | None = None
    description: str | None = None

    # Postal address + jurisdiction + IC3 reference. These come from
    # PR #12's intake form on the admin-UI side. When present, the
    # editorial-drafting stage uses them to pre-fill the corresponding
    # placeholders so the operator review form is a 30-second sanity
    # check rather than a re-typing exercise. nullable for backward
    # compatibility with pre-PR-#12 rows.
    address_line1: str | None = None
    address_line2: str | None = None
    jurisdiction: str | None = None
    ic3_case_id: str | None = None


# ----- DB layer ----- #


class WorkerDB:
    """Thin psycopg wrapper. One instance per worker process."""

    # v0.16.7 (round-9 worker-resilience HIGH): standard psycopg.connect kwargs
    # for every call site. The two flags matter:
    #
    #   * prepare_threshold=None — Supabase's transaction-mode pooler
    #     (port 6543) does NOT support prepared statements. psycopg auto-
    #     prepares after 5 executions of the same SQL, then the pooler
    #     errors `DuplicatePreparedStatement`. The other Recupero modules
    #     already pass this; worker/db.py was the inconsistent odd one out.
    #
    #   * connect_timeout=10 — default is OS-level TCP timeout (minutes).
    #     A 3-minute Supabase outage would otherwise hang the worker's
    #     heartbeat + claim threads for the full outage; the reaper can't
    #     recover what it can't see. Fail-fast lets the supervisor restart
    #     us cleanly.
    _PSYCOPG_KW = {"prepare_threshold": None, "connect_timeout": 10}

    def __init__(self, dsn: str, worker_id: str) -> None:
        if not dsn:
            raise ValueError("dsn (SUPABASE_DB_URL) is required")
        if not worker_id:
            raise ValueError("worker_id is required")
        self._dsn = dsn
        self.worker_id = worker_id
        # v0.17.8 (round-10 ops HIGH): the previous v0.16.13 connection-
        # pool prelude allocated `self._pool` but no DB method ever
        # consumed it — every _exec / _query / claim_one path went
        # straight to psycopg.connect(dsn, ...). The dead init opened
        # a pool, held its slots against Supabase's quota, and the
        # close() teardown returned them. Net effect: real per-call
        # connects PLUS phantom pool overhead. Removed.
        #
        # Supabase's transaction-mode pooler (port 6543) already does
        # the connection multiplexing on its side — for any reasonable
        # claim throughput the per-call connect is fine. If client-side
        # pooling becomes necessary we'll wire it through every method
        # in one PR, not leave a half-built scaffold.
        if (os.environ.get("RECUPERO_DB_POOL_SIZE", "") or "").strip():
            log.warning(
                "RECUPERO_DB_POOL_SIZE is set but client-side pooling "
                "was removed in v0.17.8 (the prior code initialized a "
                "pool but never used it). Unset the env var; rely on "
                "Supabase's transaction-mode pooler instead."
            )

    @property
    def dsn(self) -> str:
        return self._dsn

    def close(self) -> None:
        # v0.17.8: no client-side pool to release. Method preserved
        # for callers that already invoke it (WorkerDB is used as a
        # context manager in main.py).
        return None

    def __enter__(self) -> WorkerDB:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ----- Queries ----- #

    def claim_one(self) -> Investigation | None:
        """Atomically claim the next available investigation.

        Returns the claimed row, or None if nothing is available.
        Uses FOR UPDATE SKIP LOCKED so multiple workers don't fight.

        Per the contract, only ``pending`` and ``review_approved`` rows
        are claimable. Stale active-state rows are NOT silently
        re-claimed — that's the reaper's job (``reap_stale_claims``).
        Failed rows stay terminal; humans re-queue by inserting a fresh
        investigation, not by mutating an old one.

        Validation-failure recovery
        ---------------------------

        If pydantic model construction raises (e.g., a schema/model
        mismatch like the incident_time-NULL regression we just fixed),
        the row has ALREADY been UPDATEd to ``claimed`` by the time we
        try to validate. Leaving it there wedges the row for 5 minutes
        until the reaper kills it with a generic "heartbeat older than
        300s" message — which masks the real cause and made the
        original bug invisible for 12 hours of production.

        Recovery: catch ``ValidationError`` here, mark the row as
        ``failed`` with stage='claim_validation_failed' carrying the
        actual pydantic error text, and re-raise. The polling loop
        catches the re-raise in ``_try_claim`` and continues with
        other rows. The admin UI now sees the real cause in seconds,
        not minutes.
        """
        claimable_list = ",".join(f"'{s}'" for s in sorted(S.CLAIMABLE_STATUSES))
        sql = f"""
            UPDATE {T_INV}
               SET {COL_STATUS} = %(claimed)s,
                   {COL_WORKER_ID} = %(worker)s,
                   {COL_CLAIMED_AT} = NOW(),
                   {COL_HEARTBEAT} = NOW()
             WHERE {COL_ID} = (
                    SELECT {COL_ID} FROM {T_INV}
                     WHERE {COL_STATUS} IN ({claimable_list})
                     ORDER BY {COL_TRIGGERED_AT} ASC NULLS LAST
                     LIMIT 1
                     FOR UPDATE SKIP LOCKED
                  )
            RETURNING *;
        """
        with psycopg.connect(self._dsn, autocommit=True, row_factory=dict_row, **self._PSYCOPG_KW) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql,
                    {"claimed": S.CLAIMED, "worker": self.worker_id},
                )
                row = cur.fetchone()
        if row is None:
            return None
        try:
            return Investigation.model_validate(row)
        except Exception as e:  # noqa: BLE001
            # The UPDATE already committed (autocommit=True) — we have
            # to mark the row as failed ourselves or the reaper will
            # take 5min to do it with a misleading message.
            inv_id = row.get("id")
            err_msg = (
                f"claim_validation_failed: {type(e).__name__}: {e} "
                f"(row schema doesn't match Investigation model — "
                f"likely a missing migration or a model field that "
                f"should be optional but isn't)"
            )
            try:
                self.mark_failed(
                    inv_id, stage="claim_validation_failed", error=err_msg,
                )
            except Exception as cleanup_err:  # noqa: BLE001
                # Surface BOTH the original error and the cleanup
                # failure — operator needs to see them together to
                # diagnose. Don't let cleanup-failure mask the real
                # cause.
                raise RuntimeError(
                    f"claim_one validation failed AND cleanup failed; "
                    f"row {inv_id} likely stuck in 'claimed'. "
                    f"validation_err={err_msg!r} cleanup_err={cleanup_err!r}"
                ) from e
            raise

    def reap_post_deploy_orphans(
        self,
        *,
        stale_after_sec: int = 90,
    ) -> list[tuple[UUID, str]]:
        """Eager one-shot reaper for rows orphaned by a Railway redeploy.

        Called once on worker startup, BEFORE the main poll loop.
        Catches rows whose previous worker container got SIGKILL'd
        during a deploy + restart cycle, faster than the standard
        300s reaper.

        Risk profile and threshold choice
        ---------------------------------

        The standard reaper uses 300s = 10x the 30s heartbeat
        interval — generous because the worker may legitimately spend
        minutes in a single stage (deep trace, slow Anthropic response).
        That margin is wasted on the post-deploy path: by the time a
        worker has started up and reached this point, any heartbeat
        older than ~3 missed ticks (90s) means the OLD container is
        either dead or hung-and-not-coming-back.

        Filter is identical to the standard reaper EXCEPT we exclude
        rows owned by self.worker_id — newly-started workers haven't
        claimed anything yet, but the guard is defensive against
        future code paths that might claim before this is called.

        Returns the same shape as reap_stale_claims so callers can
        log identically.
        """
        active_list = ",".join(f"'{s}'" for s in sorted(S.ACTIVE_STATUSES))
        sql = f"""
            WITH stale AS (
                SELECT {COL_ID}, {COL_STATUS}
                  FROM {T_INV}
                 WHERE {COL_STATUS} IN ({active_list})
                   AND {COL_WORKER_ID} IS DISTINCT FROM %(self_worker)s
                   AND {COL_HEARTBEAT} IS NOT NULL
                   AND {COL_HEARTBEAT} < NOW() - make_interval(secs => %(stale)s)
                 FOR UPDATE SKIP LOCKED
            )
            UPDATE {T_INV} i
               SET {COL_STATUS} = %(failed)s,
                   {COL_FAILED_AT} = NOW(),
                   {COL_ERROR_MESSAGE} = %(msg)s,
                   {COL_ERROR_STAGE} = stale.{COL_STATUS},
                   -- v0.18.1 (round-11 worker-HIGH-005): also clear
                   -- worker_id and heartbeat so the doomed worker's
                   -- still-alive heartbeat thread can't re-write
                   -- last_heartbeat_at (producing "failed but
                   -- heartbeating" rows) and so the zombie worker's
                   -- subsequent mark_* UPDATE can't drive the row to
                   -- `complete` via its now-stale worker_id filter.
                   {COL_WORKER_ID} = NULL,
                   {COL_HEARTBEAT} = NULL
              FROM stale
             WHERE i.{COL_ID} = stale.{COL_ID}
            RETURNING i.{COL_ID}, stale.{COL_STATUS};
        """
        with psycopg.connect(self._dsn, autocommit=True, **self._PSYCOPG_KW) as conn, conn.cursor() as cur:
            cur.execute(
                sql,
                {
                    "stale": stale_after_sec,
                    "self_worker": self.worker_id,
                    "failed": S.FAILED,
                    "msg": (
                        f"post-deploy reaper: heartbeat older than "
                        f"{stale_after_sec}s — orphaned during deploy/restart"
                    ),
                },
            )
            rows = cur.fetchall()
        return [(r[0], r[1]) for r in rows]

    def reap_stale_claims(self, *, stale_after_sec: int) -> list[tuple[UUID, str]]:
        """Mark active-state rows whose heartbeat has lapsed as ``failed``.

        Returns a list of ``(investigation_id, prior_status)`` for each
        row that was reaped, so callers can log them.

        This implements the v2 stale-claim recovery the contract
        documents: when a worker crashes mid-pipeline, its row stays
        in an active state forever because nothing transitions it. The
        reaper notices the silent heartbeat and surfaces the failure to
        the admin UI as a regular ``failed`` row. The operator can then
        decide whether re-running is safe (e.g., the editorial stage
        may have partially called Anthropic) and insert a fresh row.

        Idempotent and lock-safe: ``FOR UPDATE SKIP LOCKED`` means
        concurrent workers don't double-reap the same row.
        """
        active_list = ",".join(f"'{s}'" for s in sorted(S.ACTIVE_STATUSES))
        sql = f"""
            WITH stale AS (
                SELECT {COL_ID}, {COL_STATUS}
                  FROM {T_INV}
                 WHERE {COL_STATUS} IN ({active_list})
                   AND {COL_HEARTBEAT} IS NOT NULL
                   AND {COL_HEARTBEAT} < NOW() - make_interval(secs => %(stale)s)
                 FOR UPDATE SKIP LOCKED
            )
            UPDATE {T_INV} i
               SET {COL_STATUS} = %(failed)s,
                   {COL_FAILED_AT} = NOW(),
                   {COL_ERROR_MESSAGE} = %(msg)s,
                   {COL_ERROR_STAGE} = stale.{COL_STATUS},
                   -- v0.18.1 (round-11 worker-HIGH-005): also clear
                   -- worker_id and heartbeat so the doomed worker's
                   -- still-alive heartbeat thread can't re-write
                   -- last_heartbeat_at (producing "failed but
                   -- heartbeating" rows) and so the zombie worker's
                   -- subsequent mark_* UPDATE can't drive the row to
                   -- `complete` via its now-stale worker_id filter.
                   {COL_WORKER_ID} = NULL,
                   {COL_HEARTBEAT} = NULL
              FROM stale
             WHERE i.{COL_ID} = stale.{COL_ID}
            RETURNING i.{COL_ID}, stale.{COL_STATUS};
        """
        with psycopg.connect(self._dsn, autocommit=True, **self._PSYCOPG_KW) as conn, conn.cursor() as cur:
            cur.execute(
                sql,
                {
                    "stale": stale_after_sec,
                    "failed": S.FAILED,
                    "msg": (
                        f"reaper: heartbeat older than {stale_after_sec}s "
                        "— worker presumed dead"
                    ),
                },
            )
            rows = cur.fetchall()
        return [(r[0], r[1]) for r in rows]

    def fetch_case(self, case_id: UUID) -> CaseData | None:
        """Look up the cases row referenced by an investigation."""
        cols = [
            COL_ID, COL_CASE_NUMBER, COL_CLIENT_NAME, COL_CLIENT_EMAIL,
            COL_CLIENT_PHONE, COL_COUNTRY, COL_DESCRIPTION,
            # Editorial pre-fill (v0.5.2). Columns are nullable so
            # we accept NULL on pre-PR-#12 rows without erroring.
            COL_ADDRESS_LINE1, COL_ADDRESS_LINE2, COL_JURISDICTION,
            COL_IC3_CASE_ID,
        ]
        sql = f"SELECT {', '.join(cols)} FROM {T_CASES} WHERE {COL_ID} = %s;"
        with psycopg.connect(self._dsn, autocommit=True, row_factory=dict_row, **self._PSYCOPG_KW) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (case_id,))
                row = cur.fetchone()
        if row is None:
            return None
        return CaseData.model_validate(row)

    def heartbeat(self, investigation_id: UUID) -> None:
        sql = f"""
            UPDATE {T_INV}
               SET {COL_HEARTBEAT} = NOW()
             WHERE {COL_ID} = %(id)s
               AND {COL_WORKER_ID} = %(worker)s;
        """
        self._exec(sql, {"id": investigation_id, "worker": self.worker_id})

    def transition(self, investigation_id: UUID, *, status: str) -> None:
        """Move an investigation to a new status.

        Refreshes heartbeat as a side effect, and stamps started_at the
        first time the worker writes a real stage status (anything past
        CLAIMED). The first stage is TRACING by convention; if a future
        flow starts somewhere else, this still works because COALESCE
        keeps any prior value.
        """
        sql = f"""
            UPDATE {T_INV}
               SET {COL_STATUS} = %(status)s,
                   {COL_HEARTBEAT} = NOW(),
                   {COL_STARTED_AT} = COALESCE({COL_STARTED_AT}, NOW())
             WHERE {COL_ID} = %(id)s
               AND {COL_WORKER_ID} = %(worker)s;
        """
        self._exec(
            sql,
            {
                "status": status,
                "id": investigation_id,
                "worker": self.worker_id,
            },
        )

    def record_api_cost(
        self,
        investigation_id: UUID,
        api_costs_usd: Decimal,
    ) -> None:
        """Accumulate editorial-stage API spend onto the row.

        v0.18.1 (round-11 worker-CRIT-004): pre-v0.18.1 this method
        OVERWROTE api_costs_usd with the passed value. Combined with
        the no-worker_id-filter docstring intent ("over-record rather
        than lose"), a cross-worker resume on the same row silently
        LOST the pass-1 spend. Sequence:
          1. Worker A pass-1 spends $0.40, record_api_cost($0.40) → $0.40
          2. Worker A crashes, row reaped to `failed`
          3. UI re-queues row; Worker B claims at fresh `pending`
          4. Worker B re-runs editorial, spends $0.30
          5. record_api_cost($0.30) → OVERWRITES → $0.30 (lost $0.40)

        New behavior: COALESCE(existing, 0) + delta. Pipeline calls
        with the per-pass DELTA (the cost incurred during this run
        only). mark_review_required and mark_built_package no longer
        accept api_costs_usd — record_api_cost is the sole writer.

        We intentionally accept worker_id mismatch here (no
        AND worker_id = me clause): pass 2 may legitimately run on
        a different worker, and we want to preserve the audit trail
        across that handoff.
        """
        sql = f"""
            UPDATE {T_INV}
               SET {COL_API_COSTS} = COALESCE({COL_API_COSTS}, 0) + %(api)s
             WHERE {COL_ID} = %(id)s;
        """
        self._exec(
            sql,
            {
                "api": api_costs_usd,
                "id": investigation_id,
            },
        )

    def mark_review_required(
        self,
        investigation_id: UUID,
        *,
        api_costs_usd: Decimal | None = None,
    ) -> None:
        """Pause point. Drop the worker_id so re-claim after UI review is clean.

        Optionally records api_costs_usd from the editorial stage. We
        write it here (rather than at mark_built_package) because run_one
        loses track of the cost across the review checkpoint — pass 2
        starts with a fresh local variable. Once stored on the row,
        mark_built_package's COALESCE preserves it through completion.
        """
        # v0.18.1 (round-11 worker-HIGH-006): terminal-state guard.
        # Prevents a zombie worker whose row was reaped to `failed`
        # from later flipping it to `review_required`. The reaper
        # already clears worker_id (v0.18.1 HIGH-005) so the
        # `worker_id = me` predicate normally protects this, but
        # belt-and-suspenders.
        sql = f"""
            UPDATE {T_INV}
               SET {COL_STATUS} = %(status)s,
                   {COL_REVIEW_REQUIRED_AT} = NOW(),
                   {COL_WORKER_ID} = NULL,
                   {COL_HEARTBEAT} = NULL,
                   {COL_API_COSTS} = COALESCE(%(api)s, {COL_API_COSTS})
             WHERE {COL_ID} = %(id)s
               AND {COL_WORKER_ID} = %(worker)s
               AND {COL_STATUS} NOT IN ('failed', 'complete');
        """
        self._exec(
            sql,
            {
                "status": S.REVIEW_REQUIRED,
                "api": api_costs_usd,
                "id": investigation_id,
                "worker": self.worker_id,
            },
        )

    def mark_built_package(
        self,
        investigation_id: UUID,
        *,
        storage_path: str | None = None,
        total_loss_usd: Decimal | None = None,
        max_recoverable_usd: Decimal | None = None,
        api_costs_usd: Decimal | None = None,
        freezable_issuers: list[str] | None = None,
    ) -> None:
        """Transition status → building_package and write the output columns.

        Per the contract (docs/investigation-integration.md), the
        ``emitting → building_package`` transition is where the worker
        records its outputs (totals, freezable_issuers, storage_path).
        The subsequent ``building_package → complete`` transition just
        stamps ``completed_at``.

        For v1 the JS-builder step is deferred, so the worker passes
        through ``building_package`` immediately and calls
        ``mark_completed`` next.
        """
        # v0.18.1 (round-11 worker-HIGH-006): terminal-state guard.
        sql = f"""
            UPDATE {T_INV}
               SET {COL_STATUS} = %(status)s,
                   {COL_HEARTBEAT} = NOW(),
                   {COL_STORAGE_PATH} = COALESCE(%(path)s, {COL_STORAGE_PATH}),
                   {COL_TOTAL_LOSS} = COALESCE(%(loss)s, {COL_TOTAL_LOSS}),
                   {COL_MAX_RECOVERABLE} = COALESCE(%(maxrec)s, {COL_MAX_RECOVERABLE}),
                   {COL_API_COSTS} = COALESCE(%(api)s, {COL_API_COSTS}),
                   {COL_FREEZABLE_ISSUERS} = COALESCE(%(issuers)s, {COL_FREEZABLE_ISSUERS})
             WHERE {COL_ID} = %(id)s
               AND {COL_WORKER_ID} = %(worker)s
               AND {COL_STATUS} NOT IN ('failed', 'complete');
        """
        self._exec(
            sql,
            {
                "status": S.BUILDING_PACKAGE,
                "path": storage_path,
                "loss": total_loss_usd,
                "maxrec": max_recoverable_usd,
                "api": api_costs_usd,
                "issuers": freezable_issuers,
                "id": investigation_id,
                "worker": self.worker_id,
            },
        )

    def mark_completed(self, investigation_id: UUID) -> None:
        """Final transition: status → complete, set completed_at = now().

        Per the contract this is purely a timestamp + status flip.
        Output columns are written by ``mark_built_package`` in the
        prior transition.
        """
        # v0.18.1 (round-11 worker-HIGH-006): terminal-state guard
        # prevents a zombie-worker race from flipping a reaped-failed
        # row to `complete`.
        sql = f"""
            UPDATE {T_INV}
               SET {COL_STATUS} = %(status)s,
                   {COL_COMPLETED_AT} = NOW(),
                   {COL_HEARTBEAT} = NOW()
             WHERE {COL_ID} = %(id)s
               AND {COL_WORKER_ID} = %(worker)s
               AND {COL_STATUS} NOT IN ('failed', 'complete');
        """
        self._exec(
            sql,
            {
                "status": S.COMPLETED,
                "id": investigation_id,
                "worker": self.worker_id,
            },
        )

    def mark_failed(
        self,
        investigation_id: UUID,
        *,
        stage: str,
        error: str,
    ) -> None:
        sql = f"""
            UPDATE {T_INV}
               SET {COL_STATUS} = %(status)s,
                   {COL_FAILED_AT} = NOW(),
                   {COL_ERROR_STAGE} = %(stage)s,
                   {COL_ERROR_MESSAGE} = %(error)s,
                   {COL_HEARTBEAT} = NOW()
             WHERE {COL_ID} = %(id)s
               AND {COL_WORKER_ID} = %(worker)s;
        """
        self._exec(
            sql,
            {
                "status": S.FAILED,
                "stage": stage,
                "error": error[:4000],
                "id": investigation_id,
                "worker": self.worker_id,
            },
        )

    # ----- internals ----- #

    def _exec(self, sql: str, params: dict[str, Any]) -> None:
        with psycopg.connect(self._dsn, autocommit=True, **self._PSYCOPG_KW) as conn, conn.cursor() as cur:
            cur.execute(sql, params)
