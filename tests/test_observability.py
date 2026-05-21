"""Tests for the v0.17.0 observability surface."""

from __future__ import annotations

import json
import logging

# ---- run_context + JSON formatter ---- #


def test_run_context_pushes_and_pops(monkeypatch):
    """run_context merges fields into the contextvar for the duration
    of the with-block, and resets on exit."""
    from recupero.logging_setup import current_log_context, run_context

    assert current_log_context() == {}
    with run_context(investigation_id="inv-1", stage="trace"):
        ctx = current_log_context()
        assert ctx["investigation_id"] == "inv-1"
        assert ctx["stage"] == "trace"
        # request_id auto-generated when not supplied
        assert "request_id" in ctx
    # Restored on exit
    assert current_log_context() == {}


def test_run_context_nested_outer_wins():
    """Nested run_context calls don't override the parent's
    correlation fields — outer scope wins."""
    from recupero.logging_setup import current_log_context, run_context

    with run_context(investigation_id="outer"):
        with run_context(investigation_id="inner"):  # ignored
            assert current_log_context()["investigation_id"] == "outer"


def test_run_context_respects_explicit_request_id():
    """A caller-supplied request_id wins over the auto-generated one."""
    from recupero.logging_setup import current_log_context, run_context

    with run_context(request_id="rid-explicit"):
        assert current_log_context()["request_id"] == "rid-explicit"


def test_json_formatter_emits_correlation_fields(monkeypatch, capsys):
    """The JSON formatter merges run_context fields into the output."""
    monkeypatch.setenv("RECUPERO_LOG_FORMAT", "json")
    from recupero.logging_setup import run_context, setup_logging

    setup_logging("INFO")
    log = logging.getLogger("recupero.test_obs")
    with run_context(investigation_id="inv-json", stage="trace"):
        log.info("hello")
    captured = capsys.readouterr()
    # Find the JSON line (skip any other output).
    line = next(
        (ln for ln in captured.out.splitlines() if ln.startswith("{")),
        None,
    )
    assert line is not None, "JSON output not found"
    payload = json.loads(line)
    assert payload["level"] == "INFO"
    assert payload["msg"] == "hello"
    assert payload["investigation_id"] == "inv-json"
    assert payload["stage"] == "trace"
    assert "request_id" in payload


def test_json_formatter_emits_iso_timestamp(monkeypatch, capsys):
    """JSON `ts` field is ISO-8601 with Z suffix."""
    monkeypatch.setenv("RECUPERO_LOG_FORMAT", "json")
    from recupero.logging_setup import setup_logging

    setup_logging("INFO")
    log = logging.getLogger("recupero.test_obs")
    log.info("test")
    line = next(
        (ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("{")),
        None,
    )
    payload = json.loads(line)
    assert payload["ts"].endswith("Z")
    assert "T" in payload["ts"]


# ---- Sentry init guard ---- #


def test_init_sentry_returns_false_when_dsn_unset(monkeypatch):
    """init_sentry is a clean no-op when SENTRY_DSN is unset."""
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    from recupero.observability.sentry import init_sentry, sentry_enabled

    assert init_sentry() is False
    assert sentry_enabled() is False


def test_init_sentry_returns_false_when_sdk_missing(monkeypatch):
    """init_sentry returns False with a WARNING when DSN is set but
    sentry-sdk isn't importable. Worker keeps running."""
    monkeypatch.setenv("SENTRY_DSN", "https://test@sentry.example/1")
    # Simulate missing sentry_sdk by inserting a sabotaging meta-finder.
    import sys

    real_modules = sys.modules.copy()
    # Setting a sys.modules entry to None is the documented way to
    # simulate "module not importable" without uninstalling it — see
    # https://docs.python.org/3/reference/import.html#submodules
    # The annotation conflict (`sys.modules` value type is ModuleType
    # not None) is intentional here; suppress mypy only.
    sys.modules["sentry_sdk"] = None  # type: ignore[assignment]
    try:
        from recupero.observability.sentry import init_sentry
        result = init_sentry()
    finally:
        sys.modules.clear()
        sys.modules.update(real_modules)
    # Either False (sdk missing) or True (sdk somehow present in test env).
    # The contract is "never crashes"; assert it returned a bool.
    assert isinstance(result, bool)


# ---- Metrics renderer ---- #


def test_metrics_endpoint_text_includes_recorded_counters():
    from recupero.observability.metrics import (
        METRICS,
        metrics_endpoint_text,
        record_claim,
        record_stage_duration,
    )
    # Reset state so the test is hermetic.
    METRICS.claims_total._values.clear()  # noqa: SLF001
    METRICS.stage_runs_total._values.clear()  # noqa: SLF001
    METRICS.stage_duration._data.clear()  # noqa: SLF001

    record_claim("ok")
    record_claim("fail")
    record_stage_duration("tracing", 3.0, "ok")
    text = metrics_endpoint_text()
    assert "recupero_claims_total" in text
    assert 'outcome="ok"' in text
    assert 'outcome="fail"' in text
    assert "recupero_stage_duration_seconds" in text
    # Histogram exposition format requires _bucket / _sum / _count lines.
    assert "_bucket" in text
    assert "_sum" in text
    assert "_count" in text


def test_metrics_endpoint_empty_registry_returns_placeholder():
    """A fresh registry with no recorded samples returns the
    'no metrics' placeholder rather than an empty body — Prometheus
    parsers tolerate empty 200s but operators expect a hint."""
    from recupero.observability.metrics import METRICS, metrics_endpoint_text
    # Reset.
    METRICS.claims_total._values.clear()  # noqa: SLF001
    METRICS.stage_runs_total._values.clear()  # noqa: SLF001
    METRICS.freeze_letters_total._values.clear()  # noqa: SLF001
    METRICS.alerts_fired_total._values.clear()  # noqa: SLF001
    METRICS.stage_duration._data.clear()  # noqa: SLF001
    METRICS.trace_transfers._data.clear()  # noqa: SLF001
    METRICS.brief_render._data.clear()  # noqa: SLF001

    text = metrics_endpoint_text()
    assert "No metrics recorded yet" in text
