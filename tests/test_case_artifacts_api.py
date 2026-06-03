"""Per-case artifact browser API — list + traversal-guarded content serving.

The operator console's "click a case → view its files" feature. These tests
exercise the two new admin-gated routes in isolation (local FastAPI app
mounting only ``case_index_api.router``), with ``RECUPERO_DATA_DIR`` pointed at
a tmp cases_root seeded with a representative case.

Security is the focus: the content route MUST refuse path traversal, absolute
paths, and symlink escapes, and must size-cap.
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from recupero.api.case_index_api import router

_CASE_ID = "artifacts-test-case"
_KEY = "test-admin-key"
_AUTH = {"X-Recupero-Admin-Key": _KEY}


def _seed(tmp_path, monkeypatch) -> TestClient:
    cases = tmp_path / "cases" / _CASE_ID
    (cases / "briefs").mkdir(parents=True)
    (cases / "regulatory_filing").mkdir(parents=True)
    (cases / "exhibit_pack").mkdir(parents=True)
    (cases / "custody").mkdir(parents=True)
    (cases / "case.json").write_text('{"case_id": "x"}', encoding="utf-8")
    (cases / "freeze_brief.json").write_text('{"FREEZABLE": []}', encoding="utf-8")
    (cases / "briefs" / "le_handoff_acme.html").write_text(
        "<html><body>LE HANDOFF MARKER</body></html>", encoding="utf-8")
    (cases / "briefs" / "freeze_request_circle.html").write_text(
        "<html>freeze</html>", encoding="utf-8")
    (cases / "briefs" / "victim_summary_v.html").write_text(
        "<html>victim</html>", encoding="utf-8")
    (cases / "regulatory_filing" / "us_fincen_sar.html").write_text(
        "<html>sar</html>", encoding="utf-8")
    (cases / "exhibit_pack" / "exhibit_pack.html").write_text(
        "<html>exhibit</html>", encoding="utf-8")
    (cases / "custody" / "chain.jsonl").write_text(
        '{"entry_index": 0}\n', encoding="utf-8")
    (cases / "notes.bin").write_bytes(b"\x00\x01\x02opaque")
    monkeypatch.setenv("RECUPERO_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", _KEY)
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_list_artifacts_sorted_and_categorized(tmp_path, monkeypatch) -> None:
    client = _seed(tmp_path, monkeypatch)
    res = client.get(f"/v1/cases/{_CASE_ID}/artifacts", headers=_AUTH)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["case_id"] == _CASE_ID
    by_path = {a["path"]: a for a in body["artifacts"]}
    assert by_path["briefs/le_handoff_acme.html"]["category"] == "Law Enforcement"
    assert by_path["briefs/freeze_request_circle.html"]["category"] == "Freeze"
    assert by_path["regulatory_filing/us_fincen_sar.html"]["category"] == "Regulatory"
    assert by_path["briefs/victim_summary_v.html"]["category"] == "Victim / Engagement"
    assert by_path["exhibit_pack/exhibit_pack.html"]["category"] == "Exhibit & Custody"
    assert by_path["custody/chain.jsonl"]["category"] == "Exhibit & Custody"
    assert by_path["freeze_brief.json"]["category"] == "Forensics"
    assert by_path["case.json"]["category"] == "Manifests"
    assert by_path["notes.bin"]["view"] == "download"
    assert by_path["briefs/le_handoff_acme.html"]["view"] == "html"
    # Sorted: Law Enforcement category appears before Other (notes.bin).
    cats = [a["category"] for a in body["artifacts"]]
    assert cats.index("Law Enforcement") < cats.index("Other")


def test_serve_html_artifact_inline(tmp_path, monkeypatch) -> None:
    client = _seed(tmp_path, monkeypatch)
    res = client.get(
        f"/v1/cases/{_CASE_ID}/artifact",
        params={"path": "briefs/le_handoff_acme.html"}, headers=_AUTH)
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    assert "LE HANDOFF MARKER" in res.text
    assert res.headers.get("x-content-type-options") == "nosniff"


def test_serve_json_and_binary(tmp_path, monkeypatch) -> None:
    client = _seed(tmp_path, monkeypatch)
    j = client.get(f"/v1/cases/{_CASE_ID}/artifact",
                   params={"path": "freeze_brief.json"}, headers=_AUTH)
    assert j.status_code == 200
    assert j.headers["content-type"].startswith("application/json")
    assert json.loads(j.text) == {"FREEZABLE": []}
    b = client.get(f"/v1/cases/{_CASE_ID}/artifact",
                   params={"path": "notes.bin"}, headers=_AUTH)
    assert b.status_code == 200
    assert b.headers["content-type"] == "application/octet-stream"
    assert "attachment" in b.headers.get("content-disposition", "")


def test_traversal_and_absolute_paths_rejected(tmp_path, monkeypatch) -> None:
    client = _seed(tmp_path, monkeypatch)
    for bad in ["../../../etc/passwd", "/etc/passwd", "briefs/../../secret",
                "..\\..\\windows\\system32"]:
        res = client.get(f"/v1/cases/{_CASE_ID}/artifact",
                         params={"path": bad}, headers=_AUTH)
        assert res.status_code == 400, f"{bad!r} not rejected: {res.status_code}"


def test_symlink_escape_rejected(tmp_path, monkeypatch) -> None:
    client = _seed(tmp_path, monkeypatch)
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("SECRET", encoding="utf-8")
    link = tmp_path / "cases" / _CASE_ID / "briefs" / "leak.html"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable (e.g. win32 without privilege)")
    res = client.get(f"/v1/cases/{_CASE_ID}/artifact",
                     params={"path": "briefs/leak.html"}, headers=_AUTH)
    # Resolved target is outside the case dir -> blocked (400). Never 200/SECRET.
    assert res.status_code == 400
    assert "SECRET" not in res.text


def test_missing_case_and_missing_artifact(tmp_path, monkeypatch) -> None:
    client = _seed(tmp_path, monkeypatch)
    assert client.get("/v1/cases/no-such-case/artifacts", headers=_AUTH).status_code == 404
    res = client.get(f"/v1/cases/{_CASE_ID}/artifact",
                     params={"path": "briefs/does_not_exist.html"}, headers=_AUTH)
    assert res.status_code == 404


def test_auth_gating(tmp_path, monkeypatch) -> None:
    client = _seed(tmp_path, monkeypatch)
    # wrong key -> 401
    assert client.get(
        f"/v1/cases/{_CASE_ID}/artifacts",
        headers={"X-Recupero-Admin-Key": "nope"}).status_code == 401
    # key unset -> 503
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    assert client.get(f"/v1/cases/{_CASE_ID}/artifacts").status_code == 503
