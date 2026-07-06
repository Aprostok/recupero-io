"""Unit tests for the stdlib S3 SigV4 presigner + artifact helpers.

The presigner is validated against AWS's PUBLISHED example vector (docs:
"Signature Version 4 — GET, presigned URL"): bucket ``examplebucket``, object
``test.txt``, us-east-1, the canonical example credentials + fixed date, 86400s
expiry → a known-exact signature. Matching it byte-for-byte proves the canonical
request, string-to-sign, and signing-key derivation are all correct.
"""

from __future__ import annotations

from datetime import UTC, datetime

from recupero.platform import objectstore, router

# AWS documented example credentials (public, from the SigV4 docs).
_AWS_EX_KEY = "AKIAIOSFODNN7EXAMPLE"
_AWS_EX_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
_AWS_EX_SIG = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"


def test_presign_matches_aws_documented_vector() -> None:
    url = objectstore.presign_get(
        bucket="examplebucket",
        key="test.txt",
        region="us-east-1",
        access_key=_AWS_EX_KEY,
        secret_key=_AWS_EX_SECRET,
        expires=86400,
        now=datetime(2013, 5, 24, 0, 0, 0, tzinfo=UTC),
    )
    assert url.startswith(
        "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256",
    )
    assert f"X-Amz-Signature={_AWS_EX_SIG}" in url
    # Credential path components are %2F-encoded in the query.
    assert "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" in url
    assert "X-Amz-Expires=86400" in url


def test_presign_regional_host_and_token() -> None:
    url = objectstore.presign_get(
        bucket="b", key="k.pdf", region="eu-west-1",
        access_key="AK", secret_key="SK", expires=60,
        now=datetime(2026, 1, 1, tzinfo=UTC), session_token="tok/123",
    )
    assert url.startswith("https://b.s3.eu-west-1.amazonaws.com/k.pdf?")
    # session token is included + URL-encoded
    assert "X-Amz-Security-Token=tok%2F123" in url


def test_presign_custom_endpoint() -> None:
    url = objectstore.presign_get(
        bucket="b", key="k", region="us-east-1", access_key="AK", secret_key="SK",
        now=datetime(2026, 1, 1, tzinfo=UTC), endpoint="https://minio.local:9000/b",
    )
    assert url.startswith("https://minio.local:9000/b/k?")


def test_presign_put_is_valid_and_method_specific() -> None:
    kw = {
        "bucket": "b", "key": "k.pdf", "region": "us-east-1",
        "access_key": "AK", "secret_key": "SK", "now": datetime(2026, 1, 1, tzinfo=UTC),
    }
    put_url = objectstore.presign_put(**kw)
    get_url = objectstore.presign_get(**kw)
    assert put_url.startswith("https://b.s3.amazonaws.com/k.pdf?")
    assert "X-Amz-Signature=" in put_url
    # PUT canonical request differs from GET → different signature.
    assert put_url.split("X-Amz-Signature=")[1] != get_url.split("X-Amz-Signature=")[1]


def test_upload_bytes_puts_to_presigned_url(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_ARTIFACT_BUCKET", "b")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AK")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "SK")
    seen = {}

    class _Resp:
        status_code = 200

    import httpx
    monkeypatch.setattr(
        httpx, "put",
        lambda url, content=None, timeout=None: seen.update(url=url, content=content) or _Resp(),
    )
    ok = objectstore.upload_bytes("orgs/o/investigations/i/brief.pdf", b"PDF",
                                  now=datetime(2026, 1, 1, tzinfo=UTC))
    assert ok is True
    assert seen["content"] == b"PDF"
    assert "brief.pdf?X-Amz-Algorithm=" in seen["url"]


def test_upload_bytes_noop_when_unconfigured(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_ARTIFACT_BUCKET", raising=False)
    assert objectstore.upload_bytes("k", b"x", now=datetime(2026, 1, 1, tzinfo=UTC)) is False


def test_upload_case_artifacts_walks_dir(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("RECUPERO_ARTIFACT_BUCKET", "b")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AK")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "SK")
    (tmp_path / "brief.pdf").write_bytes(b"a")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "transfers.csv").write_bytes(b"b")
    keys: list[str] = []
    monkeypatch.setattr(objectstore, "upload_bytes", lambda key, data, now: keys.append(key) or True)
    n = objectstore.upload_case_artifacts("org1", "inv1", tmp_path,
                                          now=datetime(2026, 1, 1, tzinfo=UTC))
    assert n == 2
    assert "orgs/org1/investigations/inv1/brief.pdf" in keys
    assert "orgs/org1/investigations/inv1/sub/transfers.csv" in keys


def test_artifact_key_is_org_prefixed() -> None:
    assert objectstore.artifact_key("org1", "inv9", "brief.pdf") == \
        "orgs/org1/investigations/inv9/brief.pdf"


def test_is_safe_name_rejects_traversal() -> None:
    assert objectstore.is_safe_name("trace_report.html")
    assert not objectstore.is_safe_name("../secret")
    assert not objectstore.is_safe_name("a/b")
    assert not objectstore.is_safe_name("")


def test_is_configured_requires_bucket_and_creds(monkeypatch) -> None:
    for k in ("RECUPERO_ARTIFACT_BUCKET", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert objectstore.is_configured() is False
    monkeypatch.setenv("RECUPERO_ARTIFACT_BUCKET", "b")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AK")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "SK")
    assert objectstore.is_configured() is True


def test_presign_artifact_none_when_unconfigured(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_ARTIFACT_BUCKET", raising=False)
    assert objectstore.presign_artifact(
        org_id="o", investigation_id="i", name="x.pdf", now=datetime(2026, 1, 1, tzinfo=UTC),
    ) is None


# ---- endpoint guards (Depends bypassed via direct call) ---- #

def _principal():
    from recupero.platform import store
    return store.OrgContext(org_id="org1", plan="pro", user_id="u1", role="member")


def test_artifact_endpoint_rejects_bad_name() -> None:
    import pytest
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        router.trace_artifact_url("inv1", "../../etc/passwd", principal=_principal(), conn=object())
    assert ei.value.status_code == 422


def test_artifact_endpoint_404_when_trace_not_owned(monkeypatch) -> None:
    import pytest
    from fastapi import HTTPException

    from recupero.platform import store
    monkeypatch.setattr(store, "get_trace_status", lambda conn, **k: None)
    with pytest.raises(HTTPException) as ei:
        router.trace_artifact_url("inv1", "brief.pdf", principal=_principal(), conn=object())
    assert ei.value.status_code == 404


def test_artifact_endpoint_501_when_unconfigured(monkeypatch) -> None:
    import pytest
    from fastapi import HTTPException

    from recupero.platform import store
    monkeypatch.setattr(store, "get_trace_status", lambda conn, **k: {"investigation_id": "inv1"})
    monkeypatch.delenv("RECUPERO_ARTIFACT_BUCKET", raising=False)
    with pytest.raises(HTTPException) as ei:
        router.trace_artifact_url("inv1", "brief.pdf", principal=_principal(), conn=object())
    assert ei.value.status_code == 501
