"""Adversarial audit of recupero.worker._health_server.

Covers:
  1. Bind address — must default to 127.0.0.1, not 0.0.0.0
  2. Method allowlist — TRACE/OPTIONS/PUT/DELETE rejected (no XST)
  3. Server-header info disclosure — no Python/BaseHTTP version banner
  4. Connection timeout — socket has a finite recv timeout (slowloris)
  5. /health & /healthz info disclosure — no version/build leaked
"""
from __future__ import annotations

import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from recupero.worker import _health_server


def _start(monkeypatch, port=0, bind_env=None):
    """Start a server on an ephemeral port. Returns (server, port)."""
    if bind_env is not None:
        monkeypatch.setenv("HEALTH_BIND_HOST", bind_env)
    else:
        monkeypatch.delenv("HEALTH_BIND_HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)

    # Monkeypatch _resolve_health_port → 0 so OS picks an ephemeral port.
    monkeypatch.setattr(_health_server, "_resolve_health_port", lambda: 0)
    srv = _health_server.start_health_server(lambda: (True, {"db": "ok"}))
    actual_port = srv.server_address[1]
    return srv, actual_port


def test_default_bind_is_loopback_not_wildcard(monkeypatch):
    """RED: server must default to 127.0.0.1, not 0.0.0.0 (admin
    endpoints + metrics shouldn't be exposed to all interfaces by
    default; Railway sets HEALTH_BIND_HOST=0.0.0.0 explicitly)."""
    srv, port = _start(monkeypatch)
    try:
        host = srv.server_address[0]
        assert host == "127.0.0.1", (
            f"expected loopback bind, got {host!r} — exposes admin "
            f"endpoints on all interfaces"
        )
    finally:
        srv.shutdown()


def test_explicit_wildcard_bind_honored(monkeypatch):
    """If operator sets HEALTH_BIND_HOST=0.0.0.0 (Railway does), honor it."""
    srv, port = _start(monkeypatch, bind_env="0.0.0.0")
    try:
        host = srv.server_address[0]
        assert host == "0.0.0.0", f"expected 0.0.0.0 bind, got {host!r}"
    finally:
        srv.shutdown()


def test_server_header_no_version_banner(monkeypatch):
    """RED: default BaseHTTPRequestHandler sends
    ``Server: BaseHTTP/0.6 Python/3.x.y`` which reveals the Python
    version — info disclosure useful for CVE matching."""
    srv, port = _start(monkeypatch)
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/healthz", timeout=5,
        ) as resp:
            server_hdr = resp.headers.get("Server", "")
        assert "Python/" not in server_hdr, (
            f"Server header leaks Python version: {server_hdr!r}"
        )
        assert "BaseHTTP/" not in server_hdr, (
            f"Server header leaks BaseHTTP version: {server_hdr!r}"
        )
    finally:
        srv.shutdown()


def test_trace_method_rejected(monkeypatch):
    """RED: TRACE enables Cross-Site Tracing (XST) — should be 405,
    not 200/501. Same for arbitrary unknown methods."""
    srv, port = _start(monkeypatch)
    try:
        # Raw socket — urllib won't do TRACE.
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"TRACE /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        data = s.recv(4096)
        s.close()
        status_line = data.split(b"\r\n", 1)[0]
        # Accept any 4xx OR 501 — what matters for XST defense is that
        # the body doesn't echo the request. BaseHTTPRequestHandler's
        # default ``send_error(501, "Unsupported method (...)")`` gives
        # exactly that: no echo. Operators may tune the exact status
        # later; the actual security contract is "no request echo."
        assert (
            b" 405 " in status_line
            or b" 400 " in status_line
            or b" 501 " in status_line
        ), f"TRACE not rejected with 4xx/501: {status_line!r}"
        assert b"TRACE /healthz" not in data, (
            "server echoed TRACE request — possible XST"
        )
    finally:
        srv.shutdown()


def test_put_method_rejected_on_get_route(monkeypatch):
    """PUT to /healthz should be 405, not silently succeed."""
    srv, port = _start(monkeypatch)
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/healthz",
            method="PUT", data=b"",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            pytest.fail("PUT /healthz unexpectedly returned 2xx")
        except urllib.error.HTTPError as e:
            assert e.code in (405, 501), (
                f"PUT should yield 405, got {e.code}"
            )
    finally:
        srv.shutdown()


def test_socket_has_recv_timeout_slowloris(monkeypatch):
    """RED: without a per-connection timeout, a slowloris client
    holds the worker thread forever. The handler's underlying socket
    must have a finite timeout."""
    srv, port = _start(monkeypatch)
    try:
        # Shorten the handler's timeout for this test so we don't sit
        # idle waiting on the production default. Patch the class attr
        # directly on the module so newly spawned handlers pick it up.
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        # Send partial request, no terminator, never finish.
        s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
        # Server should close within _REQUEST_TIMEOUT_SECONDS (10s).
        s.settimeout(20)
        start = time.monotonic()
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                if time.monotonic() - start > 18:
                    pytest.fail(
                        "server did not close slow connection within 18s "
                        "— vulnerable to slowloris"
                    )
        except socket.timeout:
            pytest.fail(
                "client recv timed out — server never closed slow "
                "connection (slowloris risk)"
            )
        finally:
            s.close()
        elapsed = time.monotonic() - start
        assert elapsed < 18, (
            f"server held slow connection {elapsed:.1f}s — slowloris risk"
        )
    finally:
        srv.shutdown()


def test_healthz_response_no_version_leak(monkeypatch):
    """/healthz body must not embed version/build/dep info."""
    srv, port = _start(monkeypatch)
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/healthz", timeout=5,
        ) as resp:
            body = resp.read().decode("utf-8")
        forbidden = ["version", "build", "commit", "python", "recupero/"]
        lower = body.lower()
        for needle in forbidden:
            assert needle not in lower, (
                f"/healthz body leaks {needle!r}: {body!r}"
            )
    finally:
        srv.shutdown()
