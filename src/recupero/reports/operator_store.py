"""Persistence for operator graph annotations + saved views (Phase 3.9).

Thin CRUD over two tables (see ``migrations/032_operator_graph_annotations.sql``):

  * ``operator_graph_annotations`` — one investigator note per
    (investigation, node).
  * ``operator_graph_snapshots`` — named, shareable saved view config
    (layout / filters / groups / colour-by) as JSONB.

Everything is keyed by ``investigation_id`` so notes and saved views travel
with the case and any operator holding the admin key sees the same state.
All functions use the shared :func:`recupero._common.db_connect` and raise
on DB error — callers (the API layer) decide whether to degrade (reads) or
surface a 503 (writes) so deploying the code before the migration is non-fatal.
"""

from __future__ import annotations

import logging
from typing import Any

from recupero._common import db_connect

log = logging.getLogger(__name__)


def get_annotations(dsn: str, investigation_id: str) -> dict[str, str]:
    """Return ``{node_id: note}`` for the investigation (possibly empty)."""
    with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT node_id, note FROM public.operator_graph_annotations "
            "WHERE investigation_id = %s",
            (investigation_id,),
        )
        return {row[0]: row[1] for row in cur.fetchall()}


def upsert_annotation(
    dsn: str, investigation_id: str, node_id: str, note: str
) -> None:
    """Upsert a node note. An empty/blank note deletes the row."""
    note = (note or "").strip()
    with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
        if not note:
            cur.execute(
                "DELETE FROM public.operator_graph_annotations "
                "WHERE investigation_id = %s AND node_id = %s",
                (investigation_id, node_id),
            )
            return
        cur.execute(
            """
            INSERT INTO public.operator_graph_annotations
                (investigation_id, node_id, note, updated_at)
            VALUES (%s, %s, %s, now())
            ON CONFLICT (investigation_id, node_id)
            DO UPDATE SET note = EXCLUDED.note, updated_at = now()
            """,
            (investigation_id, node_id, note),
        )


def list_snapshots(dsn: str, investigation_id: str) -> list[dict[str, Any]]:
    """Return ``[{name, created_at}]`` (newest first), no state payload."""
    with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT name, created_at FROM public.operator_graph_snapshots "
            "WHERE investigation_id = %s ORDER BY created_at DESC",
            (investigation_id,),
        )
        out: list[dict[str, Any]] = []
        for row in cur.fetchall():
            created = row[1]
            out.append({
                "name": row[0],
                "created_at": created.isoformat() if hasattr(created, "isoformat") else str(created),
            })
        return out


def save_snapshot(
    dsn: str, investigation_id: str, name: str, state: dict[str, Any]
) -> None:
    """Upsert a named saved view config."""
    from psycopg.types.json import Json
    with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.operator_graph_snapshots
                (investigation_id, name, state, created_at)
            VALUES (%s, %s, %s, now())
            ON CONFLICT (investigation_id, name)
            DO UPDATE SET state = EXCLUDED.state, created_at = now()
            """,
            (investigation_id, name, Json(state)),
        )


def load_snapshot(
    dsn: str, investigation_id: str, name: str
) -> dict[str, Any] | None:
    """Return the saved state dict for ``name``, or ``None`` if absent."""
    with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT state FROM public.operator_graph_snapshots "
            "WHERE investigation_id = %s AND name = %s",
            (investigation_id, name),
        )
        row = cur.fetchone()
        return row[0] if row else None


__all__ = (
    "get_annotations",
    "upsert_annotation",
    "list_snapshots",
    "save_snapshot",
    "load_snapshot",
)
