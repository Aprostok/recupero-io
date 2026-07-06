"""Object storage for case artifacts — pure-stdlib S3 SigV4 presigned GET URLs.

Case deliverables (brief PDF, transfers CSV, trace report, exhibit pack) belong
in object storage (S3 / any S3-compatible: GCS-XML, R2, MinIO) with per-org key
prefixes, served to the customer as short-lived **presigned** URLs — the API
never proxies the bytes. This module implements the AWS Signature V4 query-auth
presigner with only the stdlib (hmac/hashlib/urllib) so it carries NO boto3
dependency, and it is verified against AWS's published example vector.

Configuration (all optional — unset ⇒ ``is_configured()`` is False and the
artifact endpoint returns 501):
  RECUPERO_ARTIFACT_BUCKET, RECUPERO_ARTIFACT_REGION (default us-east-1),
  RECUPERO_S3_ENDPOINT (override host for S3-compatible providers),
  RECUPERO_ARTIFACT_URL_TTL_SEC (default 900), plus standard AWS credentials
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from datetime import datetime
from typing import Any
from urllib.parse import quote

_ALGORITHM = "AWS4-HMAC-SHA256"
# Artifact file names are a fixed safe charset — no path traversal into other
# orgs' prefixes (the key prefix is server-built from org + investigation id).
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k_date = _sign(("AWS4" + secret).encode("utf-8"), datestamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


def _host_for(bucket: str, region: str, endpoint: str | None) -> str:
    if endpoint:
        return endpoint.replace("https://", "").replace("http://", "").rstrip("/")
    if region == "us-east-1":
        return f"{bucket}.s3.amazonaws.com"
    return f"{bucket}.s3.{region}.amazonaws.com"


def presign_get(
    *,
    bucket: str,
    key: str,
    region: str,
    access_key: str,
    secret_key: str,
    expires: int = 900,
    now: datetime,
    endpoint: str | None = None,
    session_token: str | None = None,
) -> str:
    """Return a presigned S3 GET URL (SigV4 query auth). ``now`` is injected for
    determinism/testing. Pure stdlib — matches AWS's documented example vector."""
    host = _host_for(bucket, region, endpoint)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    scope = f"{datestamp}/{region}/s3/aws4_request"
    canonical_uri = "/" + quote(key.lstrip("/"), safe="/~")

    params = {
        "X-Amz-Algorithm": _ALGORITHM,
        "X-Amz-Credential": f"{access_key}/{scope}",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(int(expires)),
        "X-Amz-SignedHeaders": "host",
    }
    if session_token:
        params["X-Amz-Security-Token"] = session_token
    canonical_qs = "&".join(
        f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in sorted(params.items())
    )

    canonical_request = (
        "GET\n"
        f"{canonical_uri}\n"
        f"{canonical_qs}\n"
        f"host:{host}\n\n"
        "host\n"
        "UNSIGNED-PAYLOAD"
    )
    string_to_sign = (
        f"{_ALGORITHM}\n{amz_date}\n{scope}\n"
        + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    )
    signature = hmac.new(
        _signing_key(secret_key, datestamp, region, "s3"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"https://{host}{canonical_uri}?{canonical_qs}&X-Amz-Signature={signature}"


def presign_put(
    *,
    bucket: str,
    key: str,
    region: str,
    access_key: str,
    secret_key: str,
    expires: int = 900,
    now: datetime,
    endpoint: str | None = None,
    session_token: str | None = None,
) -> str:
    """Presigned S3 **PUT** URL (SigV4 query auth, UNSIGNED-PAYLOAD, host-only
    signed headers so a plain ``PUT <url>`` with the raw bytes uploads). Same
    stdlib construction as ``presign_get`` with ``GET`` → ``PUT``."""
    host = _host_for(bucket, region, endpoint)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    scope = f"{datestamp}/{region}/s3/aws4_request"
    canonical_uri = "/" + quote(key.lstrip("/"), safe="/~")
    params = {
        "X-Amz-Algorithm": _ALGORITHM,
        "X-Amz-Credential": f"{access_key}/{scope}",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(int(expires)),
        "X-Amz-SignedHeaders": "host",
    }
    if session_token:
        params["X-Amz-Security-Token"] = session_token
    canonical_qs = "&".join(
        f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in sorted(params.items())
    )
    canonical_request = (
        "PUT\n"
        f"{canonical_uri}\n"
        f"{canonical_qs}\n"
        f"host:{host}\n\n"
        "host\n"
        "UNSIGNED-PAYLOAD"
    )
    string_to_sign = (
        f"{_ALGORITHM}\n{amz_date}\n{scope}\n"
        + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    )
    signature = hmac.new(
        _signing_key(secret_key, datestamp, region, "s3"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"https://{host}{canonical_uri}?{canonical_qs}&X-Amz-Signature={signature}"


def artifact_key(org_id: str, investigation_id: str, name: str) -> str:
    """Per-org, per-investigation object key. Prefixing by org means a leaked or
    mis-scoped key can never resolve into another tenant's artifacts."""
    return f"orgs/{org_id}/investigations/{investigation_id}/{name}"


def is_safe_name(name: str) -> bool:
    return bool(_SAFE_NAME_RE.match(name or ""))


def is_configured() -> bool:
    return bool(
        os.environ.get("RECUPERO_ARTIFACT_BUCKET")
        and os.environ.get("AWS_ACCESS_KEY_ID")
        and os.environ.get("AWS_SECRET_ACCESS_KEY")
    )


def _ttl() -> int:
    try:
        return max(1, int(os.environ.get("RECUPERO_ARTIFACT_URL_TTL_SEC", "900")))
    except (TypeError, ValueError):
        return 900


def presign_artifact(
    *, org_id: str, investigation_id: str, name: str, now: datetime,
) -> tuple[str, int] | None:
    """Presign a download URL for one artifact, or None if storage is not
    configured. Returns ``(url, expires_in_seconds)``."""
    if not is_configured():
        return None
    ttl = _ttl()
    url = presign_get(
        bucket=os.environ["RECUPERO_ARTIFACT_BUCKET"],
        key=artifact_key(org_id, investigation_id, name),
        region=os.environ.get("RECUPERO_ARTIFACT_REGION", "us-east-1"),
        access_key=os.environ["AWS_ACCESS_KEY_ID"],
        secret_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        session_token=os.environ.get("AWS_SESSION_TOKEN") or None,
        endpoint=os.environ.get("RECUPERO_S3_ENDPOINT") or None,
        expires=ttl,
        now=now,
    )
    return url, ttl


def _presign_put_for(key: str, now: datetime) -> str | None:
    if not is_configured():
        return None
    return presign_put(
        bucket=os.environ["RECUPERO_ARTIFACT_BUCKET"],
        key=key,
        region=os.environ.get("RECUPERO_ARTIFACT_REGION", "us-east-1"),
        access_key=os.environ["AWS_ACCESS_KEY_ID"],
        secret_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        session_token=os.environ.get("AWS_SESSION_TOKEN") or None,
        endpoint=os.environ.get("RECUPERO_S3_ENDPOINT") or None,
        expires=_ttl(),
        now=now,
    )


def upload_bytes(key: str, data: bytes, *, now: datetime) -> bool:
    """PUT ``data`` to object ``key`` via a presigned URL. Returns True on 2xx,
    False if storage is unconfigured or the PUT fails (best-effort mirror — never
    raises; the case artifacts still live in the primary case store)."""
    url = _presign_put_for(key, now)
    if url is None:
        return False
    try:
        import httpx

        resp = httpx.put(url, content=data, timeout=30.0)
        return 200 <= resp.status_code < 300
    except Exception:
        return False


def upload_case_artifacts(
    org_id: str, investigation_id: str, case_dir: Any, *, now: datetime,
) -> int:
    """Mirror every file in ``case_dir`` to ``orgs/{org_id}/investigations/{id}/``.
    Returns the count uploaded (0 when unconfigured). Best-effort; a per-file
    failure is skipped, never fatal."""
    if not is_configured():
        return 0
    from pathlib import Path

    root = Path(case_dir)
    if not root.is_dir():
        return 0
    uploaded = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        key = f"orgs/{org_id}/investigations/{investigation_id}/{rel}"
        try:
            if upload_bytes(key, path.read_bytes(), now=now):
                uploaded += 1
        except Exception:
            continue
    return uploaded


__all__ = (
    "presign_get", "presign_put", "artifact_key", "is_safe_name", "is_configured",
    "presign_artifact", "upload_bytes", "upload_case_artifacts",
)
