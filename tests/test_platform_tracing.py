"""Tests for the opt-in, dependency-optional OpenTelemetry init.

The otel packages are NOT a base dependency, so in this environment the
"enabled but packages absent" path is what runs — it must return False and never
raise (telemetry can't break boot).
"""

from __future__ import annotations

from recupero.platform import tracing


class _FakeApp:
    """Stand-in for the FastAPI app — init_tracing must not touch it on the
    no-op paths."""


def test_disabled_by_default_is_noop(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_OTEL_ENABLED", raising=False)
    assert tracing.init_tracing(_FakeApp()) is False


def test_enabled_env_parsing(monkeypatch) -> None:
    for val in ("1", "true", "YES", "on"):
        monkeypatch.setenv("RECUPERO_OTEL_ENABLED", val)
        assert tracing._enabled() is True
    for val in ("0", "false", "", "no"):
        monkeypatch.setenv("RECUPERO_OTEL_ENABLED", val)
        assert tracing._enabled() is False


def test_enabled_without_packages_returns_false_not_raise(monkeypatch) -> None:
    # Enabled, but the [otel] extra isn't installed in the test env → the import
    # guard must swallow it and return False (never raise).
    monkeypatch.setenv("RECUPERO_OTEL_ENABLED", "1")
    assert tracing.init_tracing(_FakeApp()) is False
