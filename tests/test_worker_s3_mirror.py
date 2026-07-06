"""Tests for the worker→object-storage artifact mirror at case completion.

The mirror is best-effort + env-gated: no object-storage config → it must not
touch the DB or S3, and any failure must never propagate out of completion.
"""

from __future__ import annotations

from recupero.platform import objectstore
from recupero.worker import pipeline


class _FakeDB:
    def __init__(self, org_id):
        self._org_id = org_id
        self.lookups = 0

    def org_id_for(self, investigation_id):
        self.lookups += 1
        return self._org_id


def test_mirror_noop_when_unconfigured(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(objectstore, "is_configured", lambda: False)
    called = {"upload": 0}
    monkeypatch.setattr(objectstore, "upload_case_artifacts",
                        lambda *a, **k: called.__setitem__("upload", called["upload"] + 1))
    db = _FakeDB(org_id="org1")
    pipeline._maybe_mirror_artifacts_to_s3(db, "inv1", tmp_path)
    # Short-circuits before any DB lookup or upload.
    assert db.lookups == 0
    assert called["upload"] == 0


def test_mirror_uploads_under_org_prefix_when_configured(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(objectstore, "is_configured", lambda: True)
    seen = {}
    monkeypatch.setattr(
        objectstore, "upload_case_artifacts",
        lambda org_id, inv_id, case_dir, *, now: seen.update(org=org_id, inv=inv_id) or 3,
    )
    db = _FakeDB(org_id="org9")
    pipeline._maybe_mirror_artifacts_to_s3(db, "inv9", tmp_path)
    assert db.lookups == 1
    assert seen == {"org": "org9", "inv": "inv9"}


def test_mirror_skips_when_org_unresolved(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(objectstore, "is_configured", lambda: True)
    called = {"upload": 0}
    monkeypatch.setattr(objectstore, "upload_case_artifacts",
                        lambda *a, **k: called.__setitem__("upload", called["upload"] + 1))
    pipeline._maybe_mirror_artifacts_to_s3(_FakeDB(org_id=None), "inv1", tmp_path)
    assert called["upload"] == 0


def test_mirror_never_raises(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(objectstore, "is_configured", lambda: True)

    class _BoomDB:
        def org_id_for(self, _id):
            raise RuntimeError("db down")

    # Must swallow the error — completion must not fail because of the mirror.
    pipeline._maybe_mirror_artifacts_to_s3(_BoomDB(), "inv1", tmp_path)
