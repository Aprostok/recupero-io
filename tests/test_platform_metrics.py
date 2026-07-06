"""Tests for the SaaS /v2 Prometheus counters + the /v2/metrics endpoint.

Reuses the existing hardened observability registry (observability/metrics.py);
this only locks the platform-specific counters + exposition.
"""

from __future__ import annotations

from recupero.observability import metrics as obs
from recupero.platform import router


def test_record_signup_and_request_render_in_exposition() -> None:
    obs.record_signup()
    obs.record_platform_request("submit_trace", "pro")
    text = obs.metrics_endpoint_text()
    assert "recupero_platform_signups_total" in text
    assert "recupero_platform_requests_total" in text
    # label is emitted in exposition format
    assert 'endpoint="submit_trace"' in text and 'plan="pro"' in text
    # counter TYPE line present
    assert "# TYPE recupero_platform_requests_total counter" in text


def test_metrics_endpoint_returns_prometheus_text() -> None:
    obs.record_platform_request("submit_trace", "free")
    resp = router.prometheus_metrics()
    assert resp.status_code == 200
    assert resp.media_type.startswith("text/plain")
    body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
    assert "recupero_platform_requests_total" in body


def test_platform_counters_registered_on_singleton() -> None:
    assert hasattr(obs.METRICS, "platform_requests_total")
    assert hasattr(obs.METRICS, "platform_signups_total")
    assert set(obs.__all__) >= {"record_platform_request", "record_signup"}
