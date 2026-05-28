"""Tests for the v0.32 Tier-0 mandatory human-review gate.

Covers STEP 6 of the task spec:
  * Dispatch attempt before review row exists → BriefNotReviewedError
  * Dispatch attempt while awaiting_review → raises
  * Dispatch attempt after approved → succeeds
  * Dispatch attempt after rejected → raises
  * Override path: dispatch with override but no reason → raises
  * Override path: dispatch with documented override → succeeds (logs WARN)
  * Re-rendering changes SHA → new awaiting_review row needed
  * API endpoints respect admin auth
  * 24h SLA cron job flags overdue rows

Tests use an in-memory psycopg.connect mock so they don't require a
live DB. The mock supports the small subset of SQL we issue from
the gate + the API endpoints.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Lightweight in-memory store + connect-mock
# ─────────────────────────────────────────────────────────────────────────────


class _Store:
    """In-memory `brief_reviews` rows. Keyed by (case_id, kind, sha)."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str, str], dict] = {}
        self._id_counter = 0

    def insert_awaiting(
        self, *, case_id: str, kind: str, sha: str,
        artifact_path: str = "",
        created_at: datetime | None = None,
    ) -> int:
        key = (case_id, kind, sha)
        self._id_counter += 1
        row = {
            "id": self._id_counter,
            "case_id": case_id,
            "artifact_kind": kind,
            "artifact_path": artifact_path,
            "artifact_sha256": sha,
            "status": "awaiting_review",
            "reviewer_email": None,
            "review_completed_at_utc": None,
            "review_notes": None,
            "override_reason": None,
            "override_acknowledged_legal_risk": False,
            "created_at_utc": created_at or datetime.now(timezone.utc),
        }
        self.rows[key] = row
        return row["id"]

    def find_by_sha(self, case_id: str, kind: str, sha: str) -> dict | None:
        return self.rows.get((case_id, kind, sha))

    def find_by_id(self, review_id: int) -> dict | None:
        for r in self.rows.values():
            if r["id"] == review_id:
                return r
        return None

    def update_status(
        self, *, review_id: int, status: str,
        reviewer_email: str | None = None,
        review_notes: str | None = None,
        override_reason: str | None = None,
        override_acknowledged_legal_risk: bool | None = None,
    ) -> dict | None:
        row = self.find_by_id(review_id)
        if row is None:
            return None
        row["status"] = status
        if reviewer_email is not None:
            row["reviewer_email"] = reviewer_email
        if review_notes is not None:
            row["review_notes"] = review_notes
        if override_reason is not None:
            row["override_reason"] = override_reason
        if override_acknowledged_legal_risk is not None:
            row["override_acknowledged_legal_risk"] = (
                override_acknowledged_legal_risk
            )
        row["review_completed_at_utc"] = datetime.now(timezone.utc)
        return row


class _FakeCursor:
    def __init__(self, store: _Store) -> None:
        self.store = store
        self._result: list[tuple] | None = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql: str, params=()) -> None:
        sql_lower = " ".join(sql.lower().split())
        if "insert into public.brief_reviews" in sql_lower:
            case_id, kind, path, sha, status = params
            key = (str(case_id), kind, sha)
            if key not in self.store.rows:
                self.store.insert_awaiting(
                    case_id=str(case_id), kind=kind, sha=sha,
                    artifact_path=path,
                )
            self._result = []
            return
        if "select status, override_reason" in sql_lower:
            case_id, kind, sha = params
            row = self.store.find_by_sha(str(case_id), kind, sha)
            if row is None:
                self._result = []
            else:
                self._result = [
                    (row["status"], row["override_reason"])
                ]
            return
        if "select id, case_id, artifact_kind, artifact_path" in sql_lower:
            # Either the queue list query OR the SLA scan.
            if "where status = %s and created_at_utc <" in sql_lower:
                # SLA scan
                status_filter, cutoff = params
                self._result = [
                    (
                        r["id"], r["case_id"], r["artifact_kind"],
                        r["artifact_path"], r["artifact_sha256"],
                        r["created_at_utc"],
                    )
                    for r in self.store.rows.values()
                    if r["status"] == status_filter
                    and r["created_at_utc"] < cutoff
                ]
            else:
                # Queue list
                status_filter, limit = params
                rows = [
                    (
                        r["id"], r["case_id"], r["artifact_kind"],
                        r["artifact_path"], r["artifact_sha256"],
                        r["status"], r["created_at_utc"],
                    )
                    for r in self.store.rows.values()
                    if r["status"] == status_filter
                ]
                self._result = rows[: int(limit)]
            return
        if sql_lower.startswith("update public.brief_reviews"):
            (
                new_status, reviewer_email, review_notes,
                override_reason, override_ack, review_id,
            ) = params
            row = self.store.update_status(
                review_id=review_id, status=new_status,
                reviewer_email=reviewer_email,
                review_notes=review_notes,
                override_reason=override_reason,
                override_acknowledged_legal_risk=override_ack,
            )
            if row is None:
                self._result = []
            else:
                self._result = [(
                    row["id"], row["case_id"], row["artifact_kind"],
                    row["artifact_sha256"], row["status"],
                    row["reviewer_email"], row["review_notes"],
                    row["override_reason"],
                    row["override_acknowledged_legal_risk"],
                    row["review_completed_at_utc"],
                )]
            return
        # Unknown SQL — store empty result.
        self._result = []

    def fetchone(self):
        if not self._result:
            return None
        return self._result[0]

    def fetchall(self):
        return list(self._result or [])


class _FakeConn:
    def __init__(self, store: _Store) -> None:
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return _FakeCursor(self.store)


@pytest.fixture
def store(monkeypatch) -> _Store:
    """Provide an in-memory store + patch `recupero._common.db_connect`
    so every call in the dispatcher / API layer routes there.
    Also sets SUPABASE_DB_URL so the gate engages."""
    s = _Store()

    def _fake_db_connect(dsn, **kwargs):
        return _FakeConn(s)

    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake/db")
    monkeypatch.setattr(
        "recupero._common.db_connect", _fake_db_connect,
    )
    return s


@pytest.fixture
def case_id() -> str:
    return str(uuid4())


@pytest.fixture
def artifact_path(tmp_path: Path) -> Path:
    p = tmp_path / "victim_summary_recoverable_abc123.html"
    p.write_text("<!DOCTYPE html><html>v0</html>", encoding="utf-8")
    return p


# ─────────────────────────────────────────────────────────────────────────────
# Gate behaviour
# ─────────────────────────────────────────────────────────────────────────────


def test_dispatch_raises_when_no_review_row(store, case_id, artifact_path):
    """No row → raises."""
    from recupero.dispatcher import (
        BriefNotReviewedError, require_review_approved,
    )
    with pytest.raises(BriefNotReviewedError):
        require_review_approved(
            case_id=case_id, artifact_kind="brief",
            artifact_path=artifact_path,
        )


def test_dispatch_raises_while_awaiting_review(
    store, case_id, artifact_path,
):
    """awaiting_review → raises."""
    from recupero.dispatcher import (
        BriefNotReviewedError, compute_sha256,
        create_review_row, require_review_approved,
    )
    assert create_review_row(
        case_id=case_id, artifact_kind="brief",
        artifact_path=artifact_path,
    )
    sha = compute_sha256(artifact_path)
    assert store.find_by_sha(case_id, "brief", sha) is not None
    with pytest.raises(BriefNotReviewedError, match="not approved"):
        require_review_approved(
            case_id=case_id, artifact_kind="brief",
            artifact_path=artifact_path,
        )


def test_dispatch_succeeds_after_approval(
    store, case_id, artifact_path,
):
    """approved → returns without raising."""
    from recupero.dispatcher import (
        REVIEW_STATUS_APPROVED, compute_sha256,
        create_review_row, require_review_approved,
    )
    create_review_row(
        case_id=case_id, artifact_kind="brief",
        artifact_path=artifact_path,
    )
    sha = compute_sha256(artifact_path)
    row = store.find_by_sha(case_id, "brief", sha)
    store.update_status(
        review_id=row["id"], status=REVIEW_STATUS_APPROVED,
        reviewer_email="alice@recupero.io",
    )
    # Should not raise.
    require_review_approved(
        case_id=case_id, artifact_kind="brief",
        artifact_path=artifact_path,
    )


def test_dispatch_raises_after_rejection(
    store, case_id, artifact_path,
):
    """rejected → raises."""
    from recupero.dispatcher import (
        BriefNotReviewedError, REVIEW_STATUS_REJECTED,
        compute_sha256, create_review_row,
        require_review_approved,
    )
    create_review_row(
        case_id=case_id, artifact_kind="brief",
        artifact_path=artifact_path,
    )
    sha = compute_sha256(artifact_path)
    row = store.find_by_sha(case_id, "brief", sha)
    store.update_status(
        review_id=row["id"], status=REVIEW_STATUS_REJECTED,
        reviewer_email="alice@recupero.io",
        review_notes="Wrong issuer",
    )
    with pytest.raises(BriefNotReviewedError):
        require_review_approved(
            case_id=case_id, artifact_kind="brief",
            artifact_path=artifact_path,
        )


def test_override_without_reason_raises(
    store, case_id, artifact_path,
):
    """override with no documented reason → raises."""
    from recupero.dispatcher import (
        BriefNotReviewedError, REVIEW_STATUS_OVERRIDDEN,
        compute_sha256, create_review_row,
        require_review_approved,
    )
    create_review_row(
        case_id=case_id, artifact_kind="brief",
        artifact_path=artifact_path,
    )
    sha = compute_sha256(artifact_path)
    row = store.find_by_sha(case_id, "brief", sha)
    # Force the row into override status with no reason.
    row["status"] = REVIEW_STATUS_OVERRIDDEN
    row["override_reason"] = None
    with pytest.raises(BriefNotReviewedError, match="documented reason"):
        require_review_approved(
            case_id=case_id, artifact_kind="brief",
            artifact_path=artifact_path,
        )


def test_override_with_documented_reason_succeeds(
    store, case_id, artifact_path, caplog,
):
    """override + documented reason → succeeds + WARN log."""
    import logging
    from recupero.dispatcher import (
        REVIEW_STATUS_OVERRIDDEN, compute_sha256,
        create_review_row, require_review_approved,
    )
    create_review_row(
        case_id=case_id, artifact_kind="brief",
        artifact_path=artifact_path,
    )
    sha = compute_sha256(artifact_path)
    row = store.find_by_sha(case_id, "brief", sha)
    store.update_status(
        review_id=row["id"], status=REVIEW_STATUS_OVERRIDDEN,
        reviewer_email="alice@recupero.io",
        override_reason="urgent_FBI_request_signed_by_AUSA_Smith",
        override_acknowledged_legal_risk=True,
    )
    with caplog.at_level(logging.WARNING):
        require_review_approved(
            case_id=case_id, artifact_kind="brief",
            artifact_path=artifact_path,
        )
    assert any("OVERRIDE" in r.message for r in caplog.records)


def test_resave_changes_sha_requires_new_row(
    store, case_id, artifact_path,
):
    """Re-rendering → new SHA → no matching row → raises."""
    from recupero.dispatcher import (
        BriefNotReviewedError, REVIEW_STATUS_APPROVED,
        compute_sha256, create_review_row,
        require_review_approved,
    )
    create_review_row(
        case_id=case_id, artifact_kind="brief",
        artifact_path=artifact_path,
    )
    sha_v0 = compute_sha256(artifact_path)
    row = store.find_by_sha(case_id, "brief", sha_v0)
    store.update_status(
        review_id=row["id"], status=REVIEW_STATUS_APPROVED,
        reviewer_email="alice@recupero.io",
    )
    # First call passes.
    require_review_approved(
        case_id=case_id, artifact_kind="brief",
        artifact_path=artifact_path,
    )
    # Re-render with different bytes — gate must refuse.
    artifact_path.write_text(
        "<!DOCTYPE html><html>v1 different</html>", encoding="utf-8",
    )
    sha_v1 = compute_sha256(artifact_path)
    assert sha_v0 != sha_v1
    with pytest.raises(BriefNotReviewedError, match="no review row"):
        require_review_approved(
            case_id=case_id, artifact_kind="brief",
            artifact_path=artifact_path,
        )


def test_local_dev_skips_gate_when_dsn_unset(
    monkeypatch, case_id, artifact_path, caplog,
):
    """DSN unset → gate logs WARN + returns (test runs unblocked)."""
    import logging
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    from recupero.dispatcher import require_review_approved
    with caplog.at_level(logging.WARNING):
        # Must not raise.
        require_review_approved(
            case_id=case_id, artifact_kind="brief",
            artifact_path=artifact_path,
        )
    assert any(
        "SKIPPING review gate" in r.message for r in caplog.records
    )


# ─────────────────────────────────────────────────────────────────────────────
# Filename → kind classification
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("freeze_request_circle_BRIEF-X.html", "freeze_request"),
        ("le_handoff_tether_BRIEF-X.pdf", "le_handoff"),
        ("engagement_letter_abc.html", "engagement_letter"),
        ("recovery_snapshot_abc.html", "recovery_snapshot"),
        ("victim_summary_recoverable_abc.html", "brief"),
        ("trace_report_abc.html", "brief"),
        ("subpoena_target_5_abc.html", "subpoena"),
        ("subpoena_playbook_abc.html", "subpoena"),
        ("cooperation_dashboard_abc.html", "cooperation_dashboard"),
        # Non-HTML/PDF supplementary files don't get a review row.
        ("investigator_findings.csv", None),
        ("manifest_case_abc.json", None),
        ("flow_abc.svg", None),
        # Unknown prefix.
        ("random_file.html", None),
    ],
)
def test_classify_artifact_kind(filename, expected):
    from recupero.dispatcher import classify_artifact_kind
    assert classify_artifact_kind(Path(filename)) == expected


# ─────────────────────────────────────────────────────────────────────────────
# API endpoints — admin auth
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def api_client(store, monkeypatch):
    """Build a FastAPI TestClient with the review router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from recupero.dispatcher.review_api import router

    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "test-admin-secret")
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_queue_endpoint_requires_admin_key(api_client, store, case_id):
    resp = api_client.get("/v1/reviews/queue")
    assert resp.status_code == 401


def test_queue_endpoint_rejects_invalid_key(api_client):
    resp = api_client.get(
        "/v1/reviews/queue",
        headers={"X-Recupero-Admin-Key": "wrong"},
    )
    assert resp.status_code == 401


def test_queue_endpoint_returns_awaiting_rows(
    api_client, store, case_id,
):
    store.insert_awaiting(
        case_id=case_id, kind="brief", sha="a" * 64,
        artifact_path="/cases/x/briefs/victim_summary_recoverable_x.html",
    )
    resp = api_client.get(
        "/v1/reviews/queue",
        headers={"X-Recupero-Admin-Key": "test-admin-secret"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["reviews"][0]["artifact_kind"] == "brief"


def test_approve_endpoint(api_client, store, case_id):
    rid = store.insert_awaiting(
        case_id=case_id, kind="brief", sha="a" * 64,
    )
    resp = api_client.post(
        f"/v1/reviews/{rid}/approve",
        headers={"X-Recupero-Admin-Key": "test-admin-secret"},
        json={"reviewer_email": "alice@recupero.io"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "human_reviewed_approved"
    assert store.find_by_id(rid)["status"] == "human_reviewed_approved"


def test_reject_endpoint_requires_notes(api_client, store, case_id):
    rid = store.insert_awaiting(
        case_id=case_id, kind="brief", sha="a" * 64,
    )
    # Missing notes → 422.
    resp = api_client.post(
        f"/v1/reviews/{rid}/reject",
        headers={"X-Recupero-Admin-Key": "test-admin-secret"},
        json={"reviewer_email": "alice@recupero.io"},
    )
    assert resp.status_code == 422
    # With notes → 200.
    resp = api_client.post(
        f"/v1/reviews/{rid}/reject",
        headers={"X-Recupero-Admin-Key": "test-admin-secret"},
        json={
            "reviewer_email": "alice@recupero.io",
            "review_notes": "wrong issuer name in narrative",
        },
    )
    assert resp.status_code == 200
    assert store.find_by_id(rid)["status"] == "human_reviewed_rejected"


def test_override_endpoint_requires_ack(api_client, store, case_id):
    rid = store.insert_awaiting(
        case_id=case_id, kind="brief", sha="a" * 64,
    )
    # ack=false → 422.
    resp = api_client.post(
        f"/v1/reviews/{rid}/override",
        headers={"X-Recupero-Admin-Key": "test-admin-secret"},
        json={
            "reviewer_email": "alice@recupero.io",
            "override_reason": "FBI urgent request",
            "override_acknowledged_legal_risk": False,
        },
    )
    assert resp.status_code == 422
    # ack=true → 200.
    resp = api_client.post(
        f"/v1/reviews/{rid}/override",
        headers={"X-Recupero-Admin-Key": "test-admin-secret"},
        json={
            "reviewer_email": "alice@recupero.io",
            "override_reason": "FBI urgent request",
            "override_acknowledged_legal_risk": True,
        },
    )
    assert resp.status_code == 200
    row = store.find_by_id(rid)
    assert row["status"] == "overridden_unreviewed"
    assert row["override_reason"] == "FBI urgent request"


# ─────────────────────────────────────────────────────────────────────────────
# 24h SLA cron
# ─────────────────────────────────────────────────────────────────────────────


def test_sla_scan_flags_overdue_rows(store, case_id, caplog):
    """Rows older than 24h in awaiting_review are surfaced."""
    import logging
    now = datetime.now(timezone.utc)
    old = now - timedelta(hours=30)
    fresh = now - timedelta(hours=1)
    store.insert_awaiting(
        case_id=case_id, kind="brief", sha="a" * 64,
        created_at=old,
    )
    store.insert_awaiting(
        case_id=case_id, kind="le_handoff", sha="b" * 64,
        created_at=fresh,
    )
    from recupero.dispatcher.sla import run_review_sla_job
    with caplog.at_level(logging.WARNING):
        n = run_review_sla_job()
    assert n == 1
    assert any(
        "PAGE operator-on-call" in r.message for r in caplog.records
    )


def test_sla_scan_no_overdue(store, case_id):
    """Recent rows do not trip the SLA."""
    store.insert_awaiting(
        case_id=case_id, kind="brief", sha="a" * 64,
        created_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    from recupero.dispatcher.sla import run_review_sla_job
    assert run_review_sla_job() == 0
