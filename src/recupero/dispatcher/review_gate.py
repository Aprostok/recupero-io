"""Mandatory human-review gate for every case-output artifact
(v0.32 Tier-0 gap #1).

Public surface
--------------

* ``BriefNotReviewedError`` — raised by ``require_review_approved``
  when the artifact has no approved review row.
* ``require_review_approved(case_id, artifact_kind, artifact_path)`` —
  hard gate. Call this BEFORE any external-facing send.
* ``create_review_row(case_id, kind, path)`` — insert one row in
  ``brief_reviews`` (status='awaiting_review') keyed by the artifact's
  SHA-256.  Used by ``build_all_deliverables`` after each artifact is
  written to disk.
* ``insert_review_rows_for_deliverables(case_id, paths)`` — helper
  used by the worker: classifies each path and inserts an
  ``awaiting_review`` row.
* ``classify_artifact_kind(path)`` — filename → enum kind.
* ``compute_sha256(path)`` — small helper kept here so callers don't
  have to import hashlib.

Local-dev / test-runs without a DSN skip the gate (with a WARN log)
so the test suite + local iteration aren't blocked.  The DSN-present
production path is the only one that enforces.

Schema is migration ``028_brief_review_status.sql``.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Iterable
from uuid import UUID

log = logging.getLogger(__name__)

# Mirror the SQL CHECK on the artifact_kind column. Keep in sync with
# migrations/028_brief_review_status.sql — a kind not in this set is a
# programmer error that should fail loudly, not insert garbage.
ARTIFACT_KINDS: frozenset[str] = frozenset({
    "brief",
    "le_handoff",
    "freeze_request",
    "engagement_letter",
    "subpoena",
    "recovery_snapshot",
    "cooperation_dashboard",
})

# Status enum (matches the SQL CHECK).
REVIEW_STATUS_AWAITING = "awaiting_review"
REVIEW_STATUS_REVIEWER_ASSIGNED = "reviewer_assigned"
REVIEW_STATUS_APPROVED = "human_reviewed_approved"
REVIEW_STATUS_REJECTED = "human_reviewed_rejected"
REVIEW_STATUS_OVERRIDDEN = "overridden_unreviewed"


class BriefNotReviewedError(RuntimeError):
    """Raised by the dispatcher when an artifact is about to be sent
    without an approved review row.

    The whole point of the gate is that this exception SHOULD NEVER
    BE CAUGHT silently — let it propagate up to whatever cron / API
    handler triggered the send so the operator gets a loud signal
    that something tried to dispatch an unreviewed artifact.
    """


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def compute_sha256(path: Path | str) -> str:
    """Return the lowercased hex SHA-256 of the file at ``path``.

    Raises ``FileNotFoundError`` if the file is missing — the caller
    is responsible for ensuring the artifact was actually written
    before computing its review-identity hash.
    """
    p = Path(path)
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        # 1 MiB chunks bound memory on a 100MB+ PDF without hurting
        # throughput meaningfully.
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# Filename-prefix → artifact_kind mapping. Mirrors the prefixes used
# by build_all_deliverables in worker/_deliverables.py + brief.py +
# subpoena_renderer.py. Anything not matched here is treated as a
# non-customer-facing supplementary file (no review row).
_KIND_BY_PREFIX: tuple[tuple[str, str], ...] = (
    ("freeze_request_", "freeze_request"),
    ("le_handoff_", "le_handoff"),
    ("engagement_letter_", "engagement_letter"),
    ("recovery_snapshot_", "recovery_snapshot"),
    ("victim_summary_", "brief"),
    ("trace_report_", "brief"),
    ("subpoena_target_", "subpoena"),
    ("subpoena_playbook_", "subpoena"),
    ("cooperation_dashboard", "cooperation_dashboard"),
)


def classify_artifact_kind(path: Path | str) -> str | None:
    """Map a deliverable filename to the corresponding artifact_kind
    enum value.

    Returns ``None`` for files that don't need a review row (manifests,
    CSV/JSON exports, flow SVGs). The dispatcher only gates the HTML/PDF
    artifacts that go to external recipients.
    """
    name = Path(path).name
    for prefix, kind in _KIND_BY_PREFIX:
        if name.startswith(prefix):
            # Only the customer-facing HTML/PDF deliverables get reviews.
            # The .csv/.json/.svg supplementary files (investigator
            # exports + flow diagrams) ride along with the reviewed
            # parent artifact.
            suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if suffix in ("html", "pdf"):
                return kind
            return None
    return None


def _dsn() -> str | None:
    """Resolve the production DSN, or None if unset."""
    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    return dsn or None


def _coerce_case_uuid(case_id: UUID | str | None) -> str | None:
    """Coerce a case_id of various shapes to a canonical UUID string,
    or return None if the value is unusable (we silently skip in that
    case — the gate is a fail-CLOSED safety net but a malformed
    case_id is a separate bug to surface higher up, not a reason to
    block legitimate dispatch by raising here)."""
    if case_id is None:
        return None
    if isinstance(case_id, UUID):
        return str(case_id)
    s = str(case_id).strip()
    if not s:
        return None
    try:
        return str(UUID(s))
    except (ValueError, TypeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Insert review rows when artifacts are produced
# ─────────────────────────────────────────────────────────────────────────────


def create_review_row(
    *,
    case_id: UUID | str,
    artifact_kind: str,
    artifact_path: Path | str,
    dsn: str | None = None,
) -> bool:
    """Insert one ``brief_reviews`` row in status ``awaiting_review``.

    Idempotent on (case_id, artifact_kind, artifact_sha256) — the
    unique constraint in the schema means re-running the same
    deliverables build doesn't duplicate rows.

    Returns True on insert success, False on any failure (DB
    unavailable, kind invalid, file missing). All failures are
    logged; this function never raises so a one-off DB blip doesn't
    kill the building_package stage.
    """
    if artifact_kind not in ARTIFACT_KINDS:
        log.warning(
            "create_review_row: unknown artifact_kind=%r (path=%s)",
            artifact_kind, artifact_path,
        )
        return False

    case_uuid = _coerce_case_uuid(case_id)
    if case_uuid is None:
        # v0.32 — v_cfi01-shape test cases use string IDs like
        # "V-CFI01", not UUIDs. The brief_reviews table requires a
        # UUID. Real production case_ids ARE UUIDs (enforced at
        # CaseStore.create); a non-UUID at this point means we're
        # inside a fixture / local-dev flow that doesn't have a DB
        # to write to anyway. Log at DEBUG, not WARNING — the
        # legitimate-fixture path was generating noise in the
        # v_cfi01 silent-error audit.
        log.debug(
            "create_review_row: case_id=%r is not a UUID — likely "
            "test fixture (path=%s)",
            case_id, artifact_path,
        )
        return False

    path = Path(artifact_path)
    if not path.is_file():
        log.warning(
            "create_review_row: artifact missing on disk: %s", path,
        )
        return False

    dsn = dsn or _dsn()
    if not dsn:
        # Local dev / test mode — no DB to insert into. The dispatcher
        # gate also short-circuits when DSN is None, so this is a
        # consistent "review gate inactive in dev" mode.
        log.info(
            "create_review_row: DSN unset — skipping (local dev mode); "
            "case=%s kind=%s path=%s",
            case_uuid, artifact_kind, path.name,
        )
        return False

    try:
        sha = compute_sha256(path)
    except OSError as exc:
        log.warning(
            "create_review_row: sha256 failed for %s: %s", path, exc,
        )
        return False

    try:
        from recupero._common import db_connect
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.brief_reviews
                    (case_id, artifact_kind, artifact_path,
                     artifact_sha256, status)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (case_id, artifact_kind, artifact_sha256)
                DO NOTHING
                """,
                (case_uuid, artifact_kind, str(path), sha,
                 REVIEW_STATUS_AWAITING),
            )
        log.info(
            "brief_reviews: awaiting_review for case=%s kind=%s "
            "sha=%s file=%s",
            case_uuid, artifact_kind, sha[:12], path.name,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "create_review_row: DB insert failed (case=%s kind=%s): %s",
            case_uuid, artifact_kind, exc,
        )
        return False


def insert_review_rows_for_deliverables(
    *,
    case_id: UUID | str | None,
    paths: Iterable[Path | str],
    dsn: str | None = None,
) -> int:
    """Walk a list of deliverable paths, classify each, and insert an
    ``awaiting_review`` row for the customer-facing ones.

    Returns the number of rows successfully inserted. Skips silently
    when ``case_id`` is None (wallet-trace path: no case = no review
    surface).
    """
    if case_id is None:
        log.info(
            "insert_review_rows_for_deliverables: case_id is None "
            "(wallet trace?) — skipping review-row creation",
        )
        return 0

    inserted = 0
    for raw_path in paths:
        path = Path(raw_path)
        kind = classify_artifact_kind(path)
        if kind is None:
            continue
        if create_review_row(
            case_id=case_id, artifact_kind=kind,
            artifact_path=path, dsn=dsn,
        ):
            inserted += 1
    return inserted


# ─────────────────────────────────────────────────────────────────────────────
# Hard dispatcher gate
# ─────────────────────────────────────────────────────────────────────────────


def require_review_approved(
    *,
    case_id: UUID | str,
    artifact_kind: str,
    artifact_path: Path | str,
    dsn: str | None = None,
) -> None:
    """Raise ``BriefNotReviewedError`` if no approved review row exists
    for the EXACT SHA-256 of the artifact at ``artifact_path``.

    Resolution rules:

      * No DSN configured → local dev mode → SKIP gate (log WARN).
        This keeps test runs unblocked.  The DSN-present production
        path is the only one that enforces.

      * Row exists with ``status='human_reviewed_approved'`` →
        permit (return).

      * Row exists with ``status='overridden_unreviewed'`` AND a
        non-empty ``override_reason`` → permit + log WARN. The
        permanent audit row makes the override accountable.

      * Row exists with any other status (awaiting_review,
        reviewer_assigned, human_reviewed_rejected, overridden
        without a documented reason) → raise.

      * No row at all → raise. A re-render with different bytes
        produces a different SHA → no matching row → raise. This is
        the load-bearing property of the (case, kind, sha256) UNIQUE
        constraint: you can't approve once and ship a different
        version.
    """
    if artifact_kind not in ARTIFACT_KINDS:
        raise BriefNotReviewedError(
            f"unknown artifact_kind={artifact_kind!r} — "
            f"must be one of {sorted(ARTIFACT_KINDS)}"
        )

    case_uuid = _coerce_case_uuid(case_id)
    if case_uuid is None:
        raise BriefNotReviewedError(
            f"invalid case_id={case_id!r} — refusing to dispatch "
            "without a valid case identifier"
        )

    path = Path(artifact_path)
    if not path.is_file():
        raise BriefNotReviewedError(
            f"artifact file does not exist on disk: {path}"
        )

    dsn = dsn or _dsn()
    if not dsn:
        # CRITICAL DESIGN NOTE: we DO NOT block local-dev iteration.
        # The dispatcher gate is operational only in environments
        # with a configured production DSN. Without one, we log loud
        # and continue so the worker + test suite still run.
        log.warning(
            "review_gate: SUPABASE_DB_URL unset — SKIPPING review "
            "gate (local dev / test mode). case=%s kind=%s file=%s",
            case_uuid, artifact_kind, path.name,
        )
        return

    try:
        sha = compute_sha256(path)
    except OSError as exc:
        raise BriefNotReviewedError(
            f"could not hash artifact for review lookup: {exc}"
        ) from exc

    try:
        from recupero._common import db_connect
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT status, override_reason
                  FROM public.brief_reviews
                 WHERE case_id = %s
                   AND artifact_kind = %s
                   AND artifact_sha256 = %s
                 LIMIT 1
                """,
                (case_uuid, artifact_kind, sha),
            )
            row = cur.fetchone()
    except Exception as exc:  # noqa: BLE001
        # Fail-CLOSED on DB blip. The whole point is no operator can
        # bypass without an audit trail; a DB outage cannot become a
        # silent bypass either. Operators get a loud signal so they
        # can retry once the DB is back.
        log.warning(
            "review_gate: DB lookup failed — failing CLOSED "
            "(case=%s kind=%s sha=%s): %s",
            case_uuid, artifact_kind, sha[:12], exc,
        )
        raise BriefNotReviewedError(
            f"review gate DB lookup failed for {artifact_kind}/"
            f"{sha[:8]} — refusing to send"
        ) from exc

    if row is None:
        raise BriefNotReviewedError(
            f"no review row exists for {artifact_kind}/{sha[:8]} "
            f"(case={case_uuid}) — artifact was not registered for "
            "review before dispatch, OR the bytes changed since the "
            "review was completed"
        )

    status, override_reason = row[0], row[1]

    if status == REVIEW_STATUS_APPROVED:
        log.info(
            "review_gate: APPROVED — case=%s kind=%s sha=%s",
            case_uuid, artifact_kind, sha[:12],
        )
        return

    if status == REVIEW_STATUS_OVERRIDDEN:
        if not override_reason or not str(override_reason).strip():
            raise BriefNotReviewedError(
                f"override without documented reason for "
                f"{artifact_kind}/{sha[:8]} (case={case_uuid}) — "
                "refusing to send"
            )
        log.warning(
            "review_gate: brief sent under OVERRIDE — case=%s kind=%s "
            "sha=%s reason=%r",
            case_uuid, artifact_kind, sha[:12], override_reason,
        )
        return

    raise BriefNotReviewedError(
        f"brief not approved (status={status!r}) for "
        f"{artifact_kind}/{sha[:8]} (case={case_uuid})"
    )
