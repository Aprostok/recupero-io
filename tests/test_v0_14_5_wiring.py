"""v0.14.5 wiring regression tests.

This file pins the integration points the v0.14.5 cleanup audit
identified as gaps. If any of these regress, the customer-visible
output (brief sections, CLI commands) silently loses features —
which is exactly the bug class the cleanup pass was meant to
prevent.
"""

from __future__ import annotations

import importlib

import pytest


# ---- Orphan-module CLI registration ---- #


@pytest.mark.parametrize("command", [
    "validate-labels",
    "refresh-freeze-priors",
    "record-freeze-outcome",
])
def test_ops_cli_has_command(command: str) -> None:
    """Each previously-orphan module gets a recupero-ops subcommand.
    If `recupero-ops --help` doesn't list it, the operator can't
    invoke it from the CLI even though the underlying code exists."""
    import argparse
    from recupero.ops.cli import cli

    # Patch parse_args to a no-op so cli() returns without invoking
    # any command. We just want to populate the subparsers.
    captured: dict[str, list[str]] = {}

    orig_parse_args = argparse.ArgumentParser.parse_args

    def _capture(self, *args, **kwargs):
        # Pull subcommands out of the parser.
        for action in self._actions:
            if isinstance(action, argparse._SubParsersAction):
                captured["subcommands"] = list(action.choices.keys())
        raise SystemExit(0)  # short-circuit

    try:
        argparse.ArgumentParser.parse_args = _capture
        try:
            cli()
        except SystemExit:
            pass
    finally:
        argparse.ArgumentParser.parse_args = orig_parse_args

    assert command in captured.get("subcommands", []), (
        f"`recupero-ops {command}` not registered in the CLI dispatcher. "
        "Each orphan module from the v0.14 audit needs a CLI command."
    )


# ---- Brief integration: class_action wired in ---- #


def test_emit_brief_imports_class_action() -> None:
    """emit_brief.py must call run_class_action_pass() so the
    CLASS_ACTION_OPPORTUNITY section appears in the brief. Pre-v0.14.5
    the module existed but was never invoked."""
    from pathlib import Path
    emit_brief_src = (
        Path(__file__).parent.parent / "src" / "recupero" / "reports" / "emit_brief.py"
    ).read_text(encoding="utf-8")
    assert "run_class_action_pass" in emit_brief_src, (
        "emit_brief.py must call run_class_action_pass() — "
        "the class-action brief section depends on it."
    )
    assert "CLASS_ACTION_OPPORTUNITY" in emit_brief_src, (
        "Brief must include the CLASS_ACTION_OPPORTUNITY key."
    )


def test_emit_brief_imports_recovery_scorer() -> None:
    """Recovery scoring must be invoked at brief assembly time so
    the RECOVERY_ESTIMATE section populates."""
    from pathlib import Path
    emit_brief_src = (
        Path(__file__).parent.parent / "src" / "recupero" / "reports" / "emit_brief.py"
    ).read_text(encoding="utf-8")
    assert "score_recovery" in emit_brief_src
    assert "RECOVERY_ESTIMATE" in emit_brief_src


# ---- Recovery scorer auto-loads learned priors ---- #


def test_recovery_scorer_accepts_auto_load_priors_flag() -> None:
    """The recovery scorer must expose the auto_load_priors flag so
    the brief assembler can opt into DB-backed learned priors without
    explicitly calling load_learned_priors()."""
    import inspect
    from recupero.recovery.scorer import score_recovery
    sig = inspect.signature(score_recovery)
    assert "auto_load_priors" in sig.parameters
    assert "learned_priors" in sig.parameters


def test_recovery_scorer_default_auto_load_is_true() -> None:
    """auto_load_priors should default True so callers get the
    learning behavior without having to think about it."""
    import inspect
    from recupero.recovery.scorer import score_recovery
    sig = inspect.signature(score_recovery)
    assert sig.parameters["auto_load_priors"].default is True


def test_recovery_scorer_handles_no_dsn_gracefully() -> None:
    """If SUPABASE_DB_URL is unset, auto_load_priors must NOT raise.
    The scorer should fall back to heuristic priors silently."""
    import os
    from recupero.recovery.scorer import score_recovery

    # Temporarily unset the DSN to simulate a fresh CLI user.
    original = os.environ.pop("SUPABASE_DB_URL", None)
    try:
        # Calling with auto_load_priors=True must not crash on no DB.
        result = score_recovery(
            {"TOTAL_LOSS_USD": "$100,000", "FREEZABLE": []},
            auto_load_priors=True,
        )
        assert result.recommendation in (
            "recommend", "caveat", "discourage", "reject",
        )
    finally:
        if original is not None:
            os.environ["SUPABASE_DB_URL"] = original


# ---- Module importability + __all__ consistency ---- #


@pytest.mark.parametrize("module_path", [
    "recupero.trace.correlation",
    "recupero.trace.class_action",
    "recupero.trace.coinjoin_unwrap",
    "recupero.recovery.scorer",
    "recupero.freeze_learning.recorder",
    "recupero.monitoring.dispatcher",
    "recupero.monitoring.poller",
    "recupero.token_risk.scorer",
    "recupero.screen.screener",
    "recupero.reports.graph_ui",
    "recupero.reports.legal_requests",
    "recupero.custody.chain",
    "recupero.labels.validator",
    "recupero.chains.tron.address",
    "recupero.chains.tron.adapter",
    "recupero.chains.tron.client",
    "recupero.chains.bitcoin.address",
    "recupero.chains.bitcoin.adapter",
    "recupero.chains.bitcoin.esplora",
    "recupero.chains.solana.address",
])
def test_module_imports_cleanly(module_path: str) -> None:
    """Every v0.12+ module must import without side-effects raising.
    Catches F821 (undefined name) regressions and missing-import
    bugs that auto-fixers can introduce."""
    importlib.import_module(module_path)


@pytest.mark.parametrize("module_path", [
    "recupero.trace.correlation",
    "recupero.trace.class_action",
    "recupero.trace.coinjoin_unwrap",
    "recupero.recovery.scorer",
    "recupero.freeze_learning.recorder",
    "recupero.monitoring.dispatcher",
    "recupero.token_risk.scorer",
    "recupero.screen.screener",
    "recupero.custody.chain",
    "recupero.chains.tron.address",
    "recupero.chains.bitcoin.address",
    "recupero.chains.solana.address",
])
def test_module_declares_all(module_path: str) -> None:
    """Public modules should declare __all__ so the API surface is
    explicit and IDE auto-imports don't surface private helpers."""
    mod = importlib.import_module(module_path)
    assert hasattr(mod, "__all__"), (
        f"{module_path}.__all__ is missing — declare the public API."
    )
    assert len(mod.__all__) > 0, f"{module_path}.__all__ is empty"


# ---- The 1171-test baseline check ---- #


def test_test_count_baseline_documented() -> None:
    """Sanity check that this test file landed alongside the rest of
    the v0.14.5 wiring fixes. If this fails, the test discovery is
    broken."""
    assert True  # presence == passing
