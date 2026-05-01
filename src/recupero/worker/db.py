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


# ----- Row models ----- #


class Investigation(BaseModel):
    """The investigations row the worker cares about. Extra columns ignored."""

    model_config = ConfigDict(extra="ignore")

    id: UUID
    case_id: UUID
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
    incident_time: datetime
    max_depth: int = 1
    dust_threshold_usd: Decimal | None = None


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


# ----- DB layer ----- #


class WorkerDB:
    """Thin psycopg wrapper. One instance per worker process."""

    def __init__(self, dsn: str, worker_id: str) -> None:
        if not dsn:
            raise ValueError("dsn (SUPABASE_DB_URL) is required")
        if not worker_id:
            raise ValueError("worker_id is required")
        self._dsn = dsn
        self.worker_id = worker_id

    def close(self) -> None:
        # No persistent connection to close.
        pass

    def __enter__(self) -> WorkerDB:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ----- Queries ----- #

    def claim_one(self, *, stale_after_sec: int) -> Investigation | None:
        """Atomically claim the next available investigation.

        Returns the claimed row, or None if nothing is available.
        Uses FOR UPDATE SKIP LOCKED so multiple workers don't fight.
        """
        active_list = ",".join(f"'{s}'" for s in sorted(S.ACTIVE_STATUSES))
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
                        OR ({COL_STATUS} IN ({active_list})
                            AND ({COL_HEARTBEAT} IS NULL
                                 OR {COL_HEARTBEAT} < NOW() - make_interval(secs => %(stale)s)))
                     ORDER BY {COL_TRIGGERED_AT} ASC NULLS LAST
                     LIMIT 1
                     FOR UPDATE SKIP LOCKED
                  )
            RETURNING *;
        """
        with psycopg.connect(self._dsn, autocommit=True, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql,
                    {
                        "claimed": S.CLAIMED,
                        "worker": self.worker_id,
                        "stale": stale_after_sec,
                    },
                )
                row = cur.fetchone()
        if row is None:
            return None
        return Investigation.model_validate(row)

    def fetch_case(self, case_id: UUID) -> CaseData | None:
        """Look up the cases row referenced by an investigation."""
        cols = [
            COL_ID, COL_CASE_NUMBER, COL_CLIENT_NAME, COL_CLIENT_EMAIL,
            COL_CLIENT_PHONE, COL_COUNTRY, COL_DESCRIPTION,
        ]
        sql = f"SELECT {', '.join(cols)} FROM {T_CASES} WHERE {COL_ID} = %s;"
        with psycopg.connect(self._dsn, autocommit=True, row_factory=dict_row) as conn:
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

    def mark_review_required(self, investigation_id: UUID) -> None:
        """Pause point. Drop the worker_id so re-claim after UI review is clean."""
        sql = f"""
            UPDATE {T_INV}
               SET {COL_STATUS} = %(status)s,
                   {COL_REVIEW_REQUIRED_AT} = NOW(),
                   {COL_WORKER_ID} = NULL,
                   {COL_HEARTBEAT} = NULL
             WHERE {COL_ID} = %(id)s
               AND {COL_WORKER_ID} = %(worker)s;
        """
        self._exec(
            sql,
            {
                "status": S.REVIEW_REQUIRED,
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
               AND {COL_WORKER_ID} = %(worker)s;
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
        sql = f"""
            UPDATE {T_INV}
               SET {COL_STATUS} = %(status)s,
                   {COL_COMPLETED_AT} = NOW(),
                   {COL_HEARTBEAT} = NOW()
             WHERE {COL_ID} = %(id)s
               AND {COL_WORKER_ID} = %(worker)s;
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
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
