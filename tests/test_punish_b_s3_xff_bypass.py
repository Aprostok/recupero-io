"""PUNISH-B S-3: X-Forwarded-For leftmost-extraction bypass on /v1/intake.

The v0.25.1 IP rate limit at api/app.py:_intake_rl_client_ip used
the LEFTMOST element of X-Forwarded-For as "the client IP". Railway
+ Cloudflare both APPEND their own value to that header rather than
strip it — so the leftmost is attacker-controlled. A bot rotating
the leftmost IP per request gets unlimited submissions.

The fix is the same pattern used in portal/server.py:_extract_client_ip:
honor a configured `RECUPERO_TRUSTED_PROXY_HOPS` count + take the
N-th-from-the-right element (the last hop before our trusted
infra), and fall back to `request.client.host` when the env var
is unset.

This test demonstrates the bypass on the pre-fix code and the
hardened behavior after the fix.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    # Default to 1 trusted proxy hop — matches a typical Railway
    # deploy (one CDN/edge in front of the app).
    monkeypatch.setenv("RECUPERO_TRUSTED_PROXY_HOPS", "1")
    from recupero.api.app import app, _intake_rl_state
    _intake_rl_state.clear()
    return TestClient(app)


def _valid_intake_data():
    return {
        "client_name": "Jane",
        "client_email": "jane@example.com",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2026-05-01",
        "description": "drained",
    }


def test_rate_limit_uses_rightmost_trusted_hop_not_leftmost(client):
    """Send a string of requests with a rotating LEFTMOST XFF but a
    constant rightmost. Pre-fix this bypassed the limit because
    every leftmost looked like a fresh IP. Post-fix the rightmost
    (the trusted-hop entry) is what matters and the bucket fills
    after 5."""
    # Use a stable rightmost IP — this is what should be the real
    # client identity after the proxy hop.
    real_client = "203.0.113.42"

    # Bot strategy: rotate the leftmost (spoofed client) IP every
    # request, but Railway appends `real_client` as the LAST hop
    # before reaching our app.
    statuses = []
    for i in range(8):
        spoofed_leftmost = f"10.{i}.{i}.{i}"
        xff = f"{spoofed_leftmost}, {real_client}"
        with patch_client_host_to_known_value():
            resp = client.post(
                "/v1/intake",
                data=_valid_intake_data(),
                headers={"X-Forwarded-For": xff},
            )
        statuses.append(resp.status_code)

    # Requests 1-5 should succeed (or fail validation, but NOT 429).
    # Request 6+ MUST be 429 — the rightmost trusted hop is identified
    # as the same client across all attempts.
    rate_limit_hits = sum(1 for s in statuses if s == 429)
    assert rate_limit_hits >= 3, (
        f"X-Forwarded-For bypass still works — only {rate_limit_hits} "
        f"of 8 requests rate-limited (expected 3+). Statuses: {statuses}. "
        "The leftmost XFF extraction is letting a bot rotate IPs and "
        "evade the v0.25.1 limit."
    )


def test_rate_limit_blocks_repeated_real_client(client):
    """Sanity: with NO XFF header, a single client (same socket peer)
    hits 429 after 5 POSTs. This is the v0.25.1-correct behavior."""
    statuses = []
    for _ in range(8):
        resp = client.post("/v1/intake", data=_valid_intake_data())
        statuses.append(resp.status_code)
    rate_limit_hits = sum(1 for s in statuses if s == 429)
    assert rate_limit_hits >= 3, (
        f"socket-peer rate limit failed: only {rate_limit_hits}/8 "
        f"hit 429. Statuses: {statuses}"
    )


def test_rate_limit_isolates_two_real_clients(client):
    """Two DIFFERENT trusted-hop IPs each get their own budget.
    Partner A's burst must not starve partner B."""
    client_a = "203.0.113.10"
    client_b = "198.51.100.20"

    # Client A burns through their budget.
    for _ in range(6):
        client.post(
            "/v1/intake",
            data=_valid_intake_data(),
            headers={"X-Forwarded-For": f"10.0.0.1, {client_a}"},
        )

    # Client B's first request must NOT be 429.
    resp = client.post(
        "/v1/intake",
        data=_valid_intake_data(),
        headers={"X-Forwarded-For": f"10.0.0.2, {client_b}"},
    )
    assert resp.status_code != 429, (
        "Client B's first request was rate-limited because of "
        "Client A's burst — IP isolation broken"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helper — TestClient defaults request.client.host to 'testclient'
# which is constant across requests. Patching not needed for these tests.
# ─────────────────────────────────────────────────────────────────────────────


from contextlib import contextmanager  # noqa: E402


@contextmanager
def patch_client_host_to_known_value():
    """No-op context manager — TestClient already presents a stable
    request.client.host across requests. Kept as a clear marker
    in the test for what the fixture is assuming."""
    yield
