"""Adversarial-input tests for observability/metrics + observability/sentry.

Patterns covered:
  * Prometheus label sanitization (CR/LF/NUL/bidi smuggle attempts)
  * Label cardinality cap (memory blow-up via unbounded distinct values)
  * Histogram NaN/Inf rejection (poisoned aggregates)
  * Sentry tag sanitization (NUL/CRLF/bidi in case_id / investigation_id)
  * SENTRY_TRACES_SAMPLE_RATE NaN/Inf/out-of-range handling
  * start_metrics_server port validation + local bind default
"""

from __future__ import annotations

import math
import os
from unittest.mock import patch


def _fresh_metrics_module():
    """Return a fresh metrics-module instance — necessary because the
    METRICS singleton retains counter state across tests in the same
    process. We mutate `_values` directly to reset between tests."""
    from recupero.observability import metrics as m
    # Reset all counters and histograms so cross-test order doesn't matter.
    for c in (
        m.METRICS.claims_total, m.METRICS.stage_runs_total,
        m.METRICS.freeze_letters_total, m.METRICS.alerts_fired_total,
    ):
        with c._lock:
            c._values.clear()
    for h in (
        m.METRICS.stage_duration, m.METRICS.trace_transfers, m.METRICS.brief_render,
    ):
        with h._lock:
            h._data.clear()
    return m


# ---- Metrics: label sanitization ---- #


def test_counter_label_crlf_is_stripped() -> None:
    """A label value carrying CR/LF must not produce a forged
    exposition line on the rendered /metrics output.

    The forged-line risk is: an attacker injects "\r\n# HELP fake\r\n
    faked_metric 999" into a label value, hoping the renderer emits
    "faked_metric 999" as a separate Prometheus line. After
    sanitization the CR/LF is stripped so the whole payload is one
    label-value string; it shows up as part of a label, NOT as its
    own line.
    """
    m = _fresh_metrics_module()
    m.METRICS.claims_total.inc(
        outcome="ok\r\n# HELP injected_metric forged\r\nfaked_metric 999"
    )
    out = m.metrics_endpoint_text()
    # Any HELP must belong to a REAL Recupero metric — no injected one.
    real_help_lines = [l for l in out.splitlines() if l.startswith("# HELP ")]
    for l in real_help_lines:
        assert l.startswith("# HELP recupero_"), f"unexpected HELP: {l!r}"
    # The label value must appear on EXACTLY ONE line (not split into
    # multiple lines by raw CR/LF). The counter line is the one
    # carrying our label.
    label_lines = [
        l for l in out.splitlines()
        if l.startswith("recupero_claims_total{")
    ]
    assert len(label_lines) == 1
    # And there are no stray CR characters in the body.
    assert "\r" not in out


def test_counter_label_nul_byte_is_stripped() -> None:
    m = _fresh_metrics_module()
    m.METRICS.claims_total.inc(outcome="ok\x00poisoned")
    out = m.metrics_endpoint_text()
    assert "\x00" not in out
    # The NUL is stripped, leaving the legit suffix concatenated.
    assert "okpoisoned" in out


def test_counter_label_bidi_override_stripped() -> None:
    """Right-to-left override (U+202E) can disguise a malicious label
    in operator logs (Trojan-Source style). Strip it before render."""
    m = _fresh_metrics_module()
    m.METRICS.claims_total.inc(outcome="ok‮moc.live")
    out = m.metrics_endpoint_text()
    assert "‮" not in out


def test_counter_label_oversize_is_truncated() -> None:
    m = _fresh_metrics_module()
    huge = "A" * 10_000
    m.METRICS.claims_total.inc(outcome=huge)
    out = m.metrics_endpoint_text()
    assert "A" * 10_000 not in out
    assert "(truncated)" in out


# ---- Metrics: cardinality cap ---- #


def test_counter_cardinality_cap_holds(monkeypatch) -> None:
    """Emitting more distinct label-tuples than the cap collapses
    everything past the cap into a single overflow series so the
    in-process registry can't grow without bound."""
    m = _fresh_metrics_module()
    # Temporarily shrink the cap so the test is fast.
    monkeypatch.setattr(m, "_MAX_LABEL_CARDINALITY", 20)
    for i in range(50):
        m.METRICS.alerts_fired_total.inc(trigger_type=f"t{i}")
    snap = m.METRICS.alerts_fired_total.snapshot()
    # Allow one extra slot for the overflow sentinel series.
    assert len(snap) <= 21
    # The overflow series should be present.
    overflow_present = any(
        m._OVERFLOW_SENTINEL in dict(k).values()
        for k in snap
    )
    assert overflow_present


# ---- Metrics: histogram non-finite rejection ---- #


def test_histogram_rejects_nan() -> None:
    m = _fresh_metrics_module()
    m.METRICS.stage_duration.observe(float("nan"), stage="trace")
    out = m.metrics_endpoint_text()
    assert "nan" not in out.lower()
    # The snapshot must not record the NaN observation.
    assert m.METRICS.stage_duration.snapshot() == {}


def test_histogram_rejects_positive_infinity() -> None:
    m = _fresh_metrics_module()
    m.METRICS.stage_duration.observe(float("inf"), stage="trace")
    assert m.METRICS.stage_duration.snapshot() == {}


def test_histogram_rejects_negative_infinity() -> None:
    m = _fresh_metrics_module()
    m.METRICS.stage_duration.observe(float("-inf"), stage="trace")
    assert m.METRICS.stage_duration.snapshot() == {}


def test_counter_rejects_nan_amount() -> None:
    m = _fresh_metrics_module()
    m.METRICS.claims_total.inc(amount=float("nan"), outcome="ok")
    assert m.METRICS.claims_total.snapshot() == {}


def test_counter_rejects_negative_amount() -> None:
    m = _fresh_metrics_module()
    m.METRICS.claims_total.inc(amount=-1.0, outcome="ok")
    assert m.METRICS.claims_total.snapshot() == {}


# ---- Metrics: server port validation ---- #


def test_start_metrics_server_rejects_zero_port() -> None:
    from recupero.observability.metrics import start_metrics_server
    try:
        start_metrics_server(0)
    except ValueError:
        return
    raise AssertionError("expected ValueError for port=0")


def test_start_metrics_server_rejects_negative_port() -> None:
    from recupero.observability.metrics import start_metrics_server
    try:
        start_metrics_server(-1)
    except ValueError:
        return
    raise AssertionError("expected ValueError for port=-1")


def test_start_metrics_server_rejects_overflow_port() -> None:
    from recupero.observability.metrics import start_metrics_server
    try:
        start_metrics_server(99999)
    except ValueError:
        return
    raise AssertionError("expected ValueError for port=99999")


def test_start_metrics_server_rejects_non_int_port() -> None:
    from recupero.observability.metrics import start_metrics_server
    try:
        start_metrics_server("abc")  # type: ignore[arg-type]
    except ValueError:
        return
    raise AssertionError("expected ValueError for port='abc'")


# ---- Sentry: tag sanitization ---- #


def test_sentry_merge_run_context_strips_crlf() -> None:
    """Run-context fields with CR/LF must not produce a forged tag
    value in the Sentry event payload."""
    from recupero.logging_setup import run_context
    from recupero.observability.sentry import _merge_run_context

    with run_context(
        investigation_id="legit-id\r\nfake_tag: pwn",
        case_id="ZIGHA\n2025\n",
    ):
        event: dict = {}
        _merge_run_context(event)

    tags = event["tags"]
    assert "\r" not in tags["investigation_id"]
    assert "\n" not in tags["investigation_id"]
    assert "\n" not in tags["case_id"]


def test_sentry_merge_run_context_strips_nul() -> None:
    from recupero.logging_setup import run_context
    from recupero.observability.sentry import _merge_run_context

    with run_context(case_id="ZIGHA\x00stuffed"):
        event: dict = {}
        _merge_run_context(event)

    assert "\x00" not in event["tags"]["case_id"]


def test_sentry_merge_run_context_truncates_oversize() -> None:
    from recupero.logging_setup import run_context
    from recupero.observability.sentry import _merge_run_context

    huge = "X" * 5000
    with run_context(case_id=huge):
        event: dict = {}
        _merge_run_context(event)

    assert len(event["tags"]["case_id"]) <= 250  # cap + truncation marker
    assert "(truncated)" in event["tags"]["case_id"]


# ---- Sentry: traces_sample_rate clamping ---- #


def _run_fake_init(env_vars: dict[str, str]) -> dict:
    """Helper: install fake sentry_sdk modules, set env, call init_sentry,
    capture the kwargs the SDK would have received. Resets the
    `_sentry_enabled` module flag on teardown so other tests aren't
    polluted by this one."""
    import sys
    import types
    from recupero.observability import sentry as s

    captured: dict = {}

    def _fake_init(**kwargs):
        captured.update(kwargs)

    fake_mod = types.ModuleType("sentry_sdk")
    fake_mod.init = _fake_init  # type: ignore[attr-defined]
    fake_int_mod = types.ModuleType("sentry_sdk.integrations.logging")

    class _FakeLoggingIntegration:
        def __init__(self, **_kwargs):
            pass
    fake_int_mod.LoggingIntegration = _FakeLoggingIntegration  # type: ignore[attr-defined]
    fake_integrations = types.ModuleType("sentry_sdk.integrations")

    real_modules = {
        k: sys.modules[k]
        for k in (
            "sentry_sdk",
            "sentry_sdk.integrations",
            "sentry_sdk.integrations.logging",
        )
        if k in sys.modules
    }
    original_enabled = s._sentry_enabled
    try:
        with patch.dict(os.environ, env_vars, clear=False):
            sys.modules["sentry_sdk"] = fake_mod
            sys.modules["sentry_sdk.integrations"] = fake_integrations
            sys.modules["sentry_sdk.integrations.logging"] = fake_int_mod
            s._sentry_enabled = False
            s.init_sentry()
    finally:
        # Restore sys.modules + the global flag so we don't pollute
        # downstream tests that expect a clean sentry surface.
        for k in (
            "sentry_sdk",
            "sentry_sdk.integrations",
            "sentry_sdk.integrations.logging",
        ):
            sys.modules.pop(k, None)
        for k, v in real_modules.items():
            sys.modules[k] = v
        s._sentry_enabled = original_enabled
    return captured


def test_sentry_traces_sample_rate_nan_falls_back_to_zero() -> None:
    """init_sentry() with SENTRY_TRACES_SAMPLE_RATE=nan must NOT
    pass a NaN to sentry_sdk.init — clamp to 0 deterministically."""
    captured = _run_fake_init({
        "SENTRY_DSN": "https://abc@example.io/123",
        "SENTRY_TRACES_SAMPLE_RATE": "nan",
    })
    assert "traces_sample_rate" in captured
    assert math.isfinite(captured["traces_sample_rate"])
    assert captured["traces_sample_rate"] == 0.0


def test_sentry_traces_sample_rate_above_one_is_clamped() -> None:
    captured = _run_fake_init({
        "SENTRY_DSN": "https://abc@example.io/123",
        "SENTRY_TRACES_SAMPLE_RATE": "5.0",
    })
    assert captured["traces_sample_rate"] == 1.0


def test_sentry_traces_sample_rate_negative_falls_back_to_zero() -> None:
    captured = _run_fake_init({
        "SENTRY_DSN": "https://abc@example.io/123",
        "SENTRY_TRACES_SAMPLE_RATE": "-0.5",
    })
    assert captured["traces_sample_rate"] == 0.0


def test_sentry_disabled_when_no_dsn() -> None:
    """init_sentry returns False (and doesn't import sentry_sdk) when
    SENTRY_DSN is unset — adversarial input here is a stray malformed
    DSN, which should still cleanly no-op."""
    from recupero.observability import sentry as s
    with patch.dict(os.environ, {"SENTRY_DSN": "   "}, clear=False):
        assert s.init_sentry() is False


def test_sentry_label_sanitizer_handles_none() -> None:
    """Coverage for the helper itself — None input shouldn't crash."""
    from recupero.observability.sentry import _sanitize_tag_value
    assert _sanitize_tag_value(None) == ""
    assert _sanitize_tag_value(123) == "123"
    assert _sanitize_tag_value("‮") == ""
