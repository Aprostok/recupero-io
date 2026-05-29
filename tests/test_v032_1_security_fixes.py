"""v0.32.1 — Jacob security-audit fixes (CRIT-1 + HIGH-1 + HIGH-3 + HIGH-5).

Closes the four findings from ``docs/JACOB_SECURITY_AUDIT_v032.md``:

  * CRIT-1 — Label-promote injection: validate every promotable field
    against a chain-aware shape, an enum allow-list, and a Unicode-
    trojan reject set BEFORE any disk write. Plus a second confirm
    header (X-Recupero-Promote-Confirm) so an admin-key leak with an
    unintended row payload fails closed.
  * HIGH-1 — Auto-ingest SSRF: strict allow-list of upstream hosts,
    https-only scheme, DNS-resolve + private-IP block, no redirects,
    10MB body cap.
  * HIGH-3 — CSRF: require AT LEAST ONE of Origin / Referer on the
    intake POST. Both absent → 403.
  * HIGH-5 — /cron/healthz unauth: strip last_error_message from the
    public payload entirely; surface it via a NEW admin-gated
    /v1/cron/jobs endpoint.

The test scaffolding mirrors ``tests/test_v032_auto_ingest.py`` and
``tests/test_api_route_authz.py`` so no new fixtures are required.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import UUID

import httpx
import pytest
import respx
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Shared fake-DB infrastructure (matches the shape in test_v032_auto_ingest.py)
# ─────────────────────────────────────────────────────────────────────────────


class _FakeCursor:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self.rows_for_fetchone: list[Any] = []
        self.rows_for_fetchall: list[list[Any]] = []

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.executed.append((sql, params))

    def fetchone(self) -> Any:
        if self.rows_for_fetchone:
            return self.rows_for_fetchone.pop(0)
        return None

    def fetchall(self) -> list[Any]:
        if self.rows_for_fetchall:
            return self.rows_for_fetchall.pop(0)
        return []

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *args: Any) -> None:
        return None


class _FakeConn:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def cursor(self) -> _FakeCursor:
        return self._cursor

    def __enter__(self) -> "_FakeConn":
        return self

    def __exit__(self, *args: Any) -> None:
        return None


@pytest.fixture
def fake_db(monkeypatch: pytest.MonkeyPatch) -> _FakeCursor:
    cur = _FakeCursor()
    conn = _FakeConn(cur)

    def _fake_db_connect(dsn: str, **kwargs: Any) -> _FakeConn:
        return conn

    monkeypatch.setattr(
        "recupero._common.db_connect", _fake_db_connect, raising=True,
    )
    import recupero._common as _common
    monkeypatch.setattr(_common, "db_connect", _fake_db_connect, raising=True)
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://test@localhost/x")
    return cur


# ─────────────────────────────────────────────────────────────────────────────
# CRIT-1 — promote_candidate field validation
# ─────────────────────────────────────────────────────────────────────────────


def _seed_promote_row(
    fake_db: _FakeCursor,
    *,
    address: str = "0x" + "a" * 40,
    chain: str = "ethereum",
    category: str = "bridge",
    name: str = "Legit Bridge",
    source: str = "defillama_new_protocol",
    status: str = "pending_review",
) -> None:
    """Queue a fake-DB row for the next _read_candidate SELECT, plus
    the UPDATE ... RETURNING that follows on the happy path."""
    fake_db.rows_for_fetchone = [
        # _read_candidate SELECT
        (
            42, address, chain, category, name,
            "low", source, "", {}, status,
        ),
        # UPDATE ... RETURNING id (only consumed on the happy path)
        (42,),
    ]


def test_promote_rejects_invalid_evm_address(
    fake_db: _FakeCursor, tmp_path: Path,
) -> None:
    """0xZZ... (non-hex) on an EVM chain → ValueError, no disk write."""
    from recupero.labels import auto_ingest

    bad_addr = "0xZZZZ" + "Z" * 36
    _seed_promote_row(fake_db, address=bad_addr, chain="ethereum")

    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    bridges_path = seeds_dir / "bridges.json"
    bridges_path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="valid EVM hex address"):
        auto_ingest.promote_candidate(
            candidate_id=42, reviewer="ops@recupero.io",
            seeds_dir=seeds_dir, confirm_sha256=None,
        )

    # Disk untouched — bridges.json is still empty.
    assert bridges_path.read_text(encoding="utf-8") == "[]"


def test_promote_rejects_unknown_chain(
    fake_db: _FakeCursor, tmp_path: Path,
) -> None:
    """chain='atlantis' → ValueError, no disk write."""
    from recupero.labels import auto_ingest

    _seed_promote_row(fake_db, chain="atlantis")

    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    with pytest.raises(ValueError, match="Chain enum member"):
        auto_ingest.promote_candidate(
            candidate_id=42, reviewer="ops@recupero.io",
            seeds_dir=seeds_dir, confirm_sha256=None,
        )


def test_promote_rejects_unknown_category(
    fake_db: _FakeCursor, tmp_path: Path,
) -> None:
    """proposed_category='totally_made_up' (which can sneak in via
    DB direct-write) → ValueError pre-write."""
    from recupero.labels import auto_ingest

    _seed_promote_row(fake_db, category="totally_made_up")
    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    with pytest.raises(ValueError):
        auto_ingest.promote_candidate(
            candidate_id=42, reviewer="ops@recupero.io",
            seeds_dir=seeds_dir, confirm_sha256=None,
        )


def test_promote_rejects_name_with_control_chars(
    fake_db: _FakeCursor, tmp_path: Path,
) -> None:
    """A newline / NUL / bidi-override in proposed_name → reject."""
    from recupero.labels import auto_ingest

    _seed_promote_row(
        fake_db,
        name="Legit\nBridge\x00with bidi ‮trick",
    )
    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    with pytest.raises(ValueError, match="control character|Unicode"):
        auto_ingest.promote_candidate(
            candidate_id=42, reviewer="ops@recupero.io",
            seeds_dir=seeds_dir, confirm_sha256=None,
        )


def test_promote_rejects_name_with_zero_width_unicode(
    fake_db: _FakeCursor, tmp_path: Path,
) -> None:
    """Zero-width space (U+200B) inside the name → reject."""
    from recupero.labels import auto_ingest

    _seed_promote_row(fake_db, name="Co​inbase Bridge")
    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    with pytest.raises(ValueError, match="invisible Unicode"):
        auto_ingest.promote_candidate(
            candidate_id=42, reviewer="ops@recupero.io",
            seeds_dir=seeds_dir, confirm_sha256=None,
        )


def test_promote_rejects_source_with_injection_chars(
    fake_db: _FakeCursor, tmp_path: Path,
) -> None:
    """source containing a quote / semicolon / shell metachar → reject."""
    from recupero.labels import auto_ingest

    _seed_promote_row(fake_db, source='upstream";rm -rf /;"')
    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    with pytest.raises(ValueError, match="source"):
        auto_ingest.promote_candidate(
            candidate_id=42, reviewer="ops@recupero.io",
            seeds_dir=seeds_dir, confirm_sha256=None,
        )


def test_promote_requires_confirm_hash_via_api(
    fake_db: _FakeCursor, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The /v1/labels/candidates/{id}/promote endpoint MUST 400 when
    X-Recupero-Promote-Confirm is absent."""
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "test-admin-key")
    from recupero.api.app import app

    client = TestClient(app)
    resp = client.post(
        "/v1/labels/candidates/42/promote",
        json={"reviewer_email": "ops@recupero.io", "confidence": "medium"},
        headers={"X-Recupero-Admin-Key": "test-admin-key"},
    )
    # 400 — missing confirm header.
    assert resp.status_code == 400, (
        f"promote without X-Recupero-Promote-Confirm should 400; "
        f"got {resp.status_code}: {resp.text}"
    )
    assert "Promote-Confirm" in resp.text or "confirm" in resp.text.lower()


def test_promote_confirm_hash_mismatch_rejected(
    fake_db: _FakeCursor, tmp_path: Path,
) -> None:
    """A bogus confirm_sha256 (wrong hex) → ValueError. Library-level
    pin — API tests cover the header-level path separately."""
    from recupero.labels import auto_ingest

    _seed_promote_row(fake_db)
    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    (seeds_dir / "bridges.json").write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="confirm_sha256 mismatch"):
        auto_ingest.promote_candidate(
            candidate_id=42, reviewer="ops@recupero.io",
            seeds_dir=seeds_dir, confirm_sha256="0" * 64,
        )


def test_promote_confirm_hash_match_allows_write(
    fake_db: _FakeCursor, tmp_path: Path,
) -> None:
    """When the operator sends the correct hash, the promote proceeds
    (modulo the seeds-validator gate)."""
    from recupero.labels import auto_ingest

    _seed_promote_row(fake_db)
    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    (seeds_dir / "bridges.json").write_text("[]", encoding="utf-8")

    # Compute the expected hash exactly as the module does.
    row_fields = {
        "address": "0x" + "a" * 40,
        "chain": "ethereum",
        "proposed_category": "bridge",
        "proposed_name": "Legit Bridge",
        "source": "defillama_new_protocol",
    }
    canon = json.dumps(
        row_fields, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    )
    expected = hashlib.sha256(canon.encode("utf-8")).hexdigest()

    # No raise → success.
    # v0.32.1+ wave-6: this test pins the confirm_sha256 happy-path; the
    # multi-source-confirm gate (W2 wire-up) would otherwise reject the
    # single-source promote. The bypass_multi_source kwarg is provided
    # for exactly this scenario — testing the hash flow in isolation.
    result = auto_ingest.promote_candidate(
        candidate_id=42, reviewer="ops@recupero.io",
        seeds_dir=seeds_dir, confirm_sha256=expected,
        bypass_multi_source=True,
    )
    assert result["promoted_to"] == str(seeds_dir / "bridges.json")
    after = json.loads((seeds_dir / "bridges.json").read_text(encoding="utf-8"))
    assert len(after) == 1
    assert after[0]["address"] == "0x" + "a" * 40


# ─────────────────────────────────────────────────────────────────────────────
# HIGH-1 — Auto-ingest SSRF defense
# ─────────────────────────────────────────────────────────────────────────────


def test_safe_http_get_json_refuses_unknown_host() -> None:
    """A URL whose host is not on the allow-list returns None."""
    from recupero.labels.auto_ingest import _safe_http_get_json

    result = _safe_http_get_json(
        "https://evil.com/protocols", source_name="attacker",
    )
    assert result is None


def test_safe_http_get_json_refuses_http_scheme() -> None:
    """An http:// URL returns None even if the host is on the allow-list."""
    from recupero.labels.auto_ingest import _safe_http_get_json

    result = _safe_http_get_json(
        "http://api.llama.fi/protocols",
        source_name="defillama_protocols",
    )
    assert result is None


def test_safe_http_get_json_refuses_other_schemes() -> None:
    """file:// / ftp:// / gopher:// are all refused."""
    from recupero.labels.auto_ingest import _safe_http_get_json

    for url in (
        "file:///etc/passwd",
        "ftp://api.llama.fi/protocols",
        "gopher://api.llama.fi/protocols",
    ):
        assert _safe_http_get_json(url, source_name="attacker") is None


def test_safe_http_get_json_refuses_private_ip_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DNS-rebound host that resolves to 192.168.1.1 is refused even
    when the host string is on the allow-list."""
    import socket as _socket

    def _fake_getaddrinfo(host, port, *args, **kwargs):
        # All allow-listed hosts resolve to a private IP.
        return [
            (
                _socket.AF_INET, _socket.SOCK_STREAM, 0, "",
                ("192.168.1.1", port or 443),
            ),
        ]

    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo)
    from recupero.labels.auto_ingest import _safe_http_get_json, _ssrf_validate_url

    ok, reason = _ssrf_validate_url("https://api.llama.fi/protocols")
    assert not ok
    assert "private" in reason or "192.168" in reason

    # End-to-end via the public wrapper.
    result = _safe_http_get_json(
        "https://api.llama.fi/protocols",
        source_name="defillama_protocols",
    )
    assert result is None


@respx.mock
def test_safe_http_get_json_disables_redirects() -> None:
    """A 302 → another URL must NOT be followed. The upstream sends a
    redirect; the function returns None instead of chasing it."""
    from recupero.labels.auto_ingest import _safe_http_get_json

    respx.get("https://api.llama.fi/protocols").mock(
        return_value=httpx.Response(
            302, headers={"Location": "https://api.llama.fi/elsewhere"},
        ),
    )
    result = _safe_http_get_json(
        "https://api.llama.fi/protocols",
        source_name="defillama_protocols",
    )
    # 302 != 200, so we treat as "unreachable" → None. The defense is
    # that we didn't actually fetch the Location URL.
    assert result is None


@respx.mock
def test_safe_http_get_json_caps_body_size() -> None:
    """A 50MB response body is refused before the JSON is parsed."""
    from recupero.labels.auto_ingest import _safe_http_get_json

    # Build a JSON list bigger than the cap.
    huge_body = b'["' + (b"x" * (11 * 1024 * 1024)) + b'"]'
    respx.get("https://api.llama.fi/protocols").mock(
        return_value=httpx.Response(200, content=huge_body),
    )
    result = _safe_http_get_json(
        "https://api.llama.fi/protocols",
        source_name="defillama_protocols",
    )
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# HIGH-3 — Intake POST CSRF: no Origin AND no Referer → 403
# ─────────────────────────────────────────────────────────────────────────────


_API_SECRET_A = "secret-acme-aaaaaaaaaa"
_KEY_A = "exchange-acme"

_VALID_INTAKE_FORM = {
    "client_name": "Jane Doe",
    "client_email": "jane@example.com",
    "chain": "ethereum",
    "seed_address": "0x" + "a" * 40,
    "incident_date": "2026-04-01",
    "description": "x" * 50,
    "country": "US",
}


@pytest.fixture(autouse=True)
def _isolate_intake_rl(monkeypatch):
    """Reset per-IP intake rate-limit buckets so CSRF tests don't trip
    over the 5/min cap."""
    from recupero.api import app as _app_mod
    _app_mod._intake_rl_state.clear()
    yield
    _app_mod._intake_rl_state.clear()


@pytest.fixture
def csrf_client(monkeypatch):
    monkeypatch.setenv("RECUPERO_API_KEYS", f"{_KEY_A}:{_API_SECRET_A}")
    monkeypatch.delenv("RECUPERO_API_KEY_ADMINS", raising=False)
    monkeypatch.delenv("RECUPERO_API_KEY_ISSUERS", raising=False)
    monkeypatch.delenv("RECUPERO_API_KEY_CASES", raising=False)
    monkeypatch.delenv("RECUPERO_API_AUTH_OPTIONAL", raising=False)
    monkeypatch.delenv("RECUPERO_INTAKE_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import app
    return TestClient(app)


def test_intake_post_headerless_rejected_in_strict_mode(csrf_client, monkeypatch):
    """v0.32.1 strict-CSRF opt-in. By DEFAULT header-less POSTs (no
    Origin AND no Referer — curl, server-side integrations, tests) are
    ALLOWED: a header-less request is not a browser-CSRF vector (a
    browser always attaches Origin to a cross-origin form POST), and bot
    abuse is handled by the per-IP rate limiter keyed on the rightmost
    trusted XFF hop. Operators fronting the endpoint with a browser-only
    origin opt into a hard gate via RECUPERO_INTAKE_REQUIRE_ORIGIN=true —
    this pins that strict mode still 403s a header-less POST.

    (The default-allow path is covered by test_api_route_authz and
    tests/test_v0_25_intake*.)"""
    monkeypatch.setenv("RECUPERO_INTAKE_REQUIRE_ORIGIN", "true")
    resp = csrf_client.post(
        "/v1/intake", data=_VALID_INTAKE_FORM,
        follow_redirects=False,
    )
    assert resp.status_code == 403, (
        f"strict mode (RECUPERO_INTAKE_REQUIRE_ORIGIN=true) must 403 a "
        f"header-less intake POST; got {resp.status_code}"
    )


def test_intake_post_accepts_when_referer_present(csrf_client):
    """Sibling pin: with Referer alone (no Origin — common in
    same-origin form POSTs), the CSRF gate passes."""
    with patch(
        "recupero.portal.intake.create_case_from_intake",
        return_value=UUID("33333333-3333-3333-3333-333333333333"),
    ), patch(
        "recupero.payments.payment_links.build_diagnostic_link",
        return_value="https://buy.stripe.com/test",
    ):
        resp = csrf_client.post(
            "/v1/intake", data=_VALID_INTAKE_FORM,
            headers={
                "referer": "http://testserver/intake",
                "host": "testserver",
            },
            follow_redirects=False,
        )
    assert resp.status_code != 403, (
        f"Referer-only intake POST got {resp.status_code}, expected non-403"
    )


# ─────────────────────────────────────────────────────────────────────────────
# HIGH-5 — /cron/healthz strips last_error_message; /v1/cron/jobs admin-gated
# ─────────────────────────────────────────────────────────────────────────────


def test_public_cron_healthz_payload_omits_last_error_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``build_cron_healthz_payload(include_error_message=False)``
    must NEVER include the error text for any job — even when the
    underlying row has a populated last_error_message."""
    from recupero.worker import cron_scheduler

    # Build a synthetic row with a populated error message that would
    # leak if the payload weren't filtered.
    class _Cur:
        def __init__(self, rows):
            self._rows = rows

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, sql, params=()):
            return None

        def fetchall(self):
            return self._rows

    class _Conn:
        def __init__(self, rows):
            self._rows = rows

        def cursor(self):
            return _Cur(self._rows)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    leaky_msg = "DSN connection lost: re_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    rows = [
        (
            j.name,
            datetime.now(UTC) - timedelta(hours=1),  # last_success_utc
            datetime.now(UTC) - timedelta(hours=2),  # last_error_utc
            leaky_msg,
            3,
        )
        for j in cron_scheduler._build_default_jobs()
    ]

    def _fake_db_connect(dsn, **kwargs):
        return _Conn(rows)

    monkeypatch.setattr(
        "recupero._common.db_connect", _fake_db_connect, raising=True,
    )
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://test")

    payload = cron_scheduler.build_cron_healthz_payload(
        include_error_message=False,
    )
    assert "jobs" in payload
    for name, job in payload["jobs"].items():
        assert "last_error_message" not in job, (
            f"job {name!r} payload leaked last_error_message: {job!r}"
        )
        assert "last_error_utc" not in job, (
            f"job {name!r} payload leaked last_error_utc: {job!r}"
        )
        # And the leaky string must not appear ANYWHERE in the payload.
        assert leaky_msg not in json.dumps(payload), (
            "leaky error message smuggled into the public payload"
        )


def test_admin_cron_jobs_endpoint_requires_admin_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /v1/cron/jobs without X-Recupero-Admin-Key → 401."""
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "test-admin-key")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import app
    client = TestClient(app)
    resp = client.get("/v1/cron/jobs")
    assert resp.status_code == 401


def test_admin_cron_jobs_endpoint_with_key_includes_error_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /v1/cron/jobs WITH valid admin key → 200 + last_error_message
    visible in each job payload."""
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "test-admin-key")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")

    from recupero.worker import cron_scheduler

    class _Cur:
        def __init__(self, rows):
            self._rows = rows

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, sql, params=()):
            return None

        def fetchall(self):
            return self._rows

    class _Conn:
        def __init__(self, rows):
            self._rows = rows

        def cursor(self):
            return _Cur(self._rows)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    rows = [
        (
            j.name,
            datetime.now(UTC) - timedelta(hours=1),
            datetime.now(UTC) - timedelta(hours=2),
            "test error text (redacted upstream)",
            3,
        )
        for j in cron_scheduler._build_default_jobs()
    ]

    def _fake_db_connect(dsn, **kwargs):
        return _Conn(rows)

    monkeypatch.setattr(
        "recupero._common.db_connect", _fake_db_connect, raising=True,
    )

    from recupero.api.app import app
    client = TestClient(app)
    resp = client.get(
        "/v1/cron/jobs",
        headers={"X-Recupero-Admin-Key": "test-admin-key"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "jobs" in body
    # Every job carries last_error_message (the admin-gated payload).
    for name, job in body["jobs"].items():
        assert "last_error_message" in job, (
            f"admin payload missing last_error_message for {name!r}"
        )
        assert job["last_error_message"] == (
            "test error text (redacted upstream)"
        )


def test_admin_cron_jobs_endpoint_disabled_without_admin_key_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When RECUPERO_ADMIN_KEY is unset, the admin endpoint 503s
    (deny-by-default)."""
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    from recupero.api.app import app
    client = TestClient(app)
    resp = client.get(
        "/v1/cron/jobs",
        headers={"X-Recupero-Admin-Key": "anything"},
    )
    assert resp.status_code == 503


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v", "--tb=short"])
