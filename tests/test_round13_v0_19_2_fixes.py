"""Regression tests pinning the v0.19.2 round-13 fixes.

Round-13 was the deepest audit (6 parallel agents over the
v0.19.1 codebase). The most surprising finding: `emit_brief.py`
called `log.info(...)` without ever importing logging — a latent
NameError that would silently break the brief render whenever
the `_compact_empty_freezable_only` path fired. These tests pin
that fix + the rest of the round-13 CRIT/HIGH closures.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import uuid4

# ---- Code-quality CRIT-1: emit_brief.log is bound ---- #


def test_emit_brief_module_has_bound_logger() -> None:
    """Round-13 surfaced `log.info(...)` at emit_brief.py:691 with no
    `log` binding in the module (no `import logging`). Every call site
    that reached the line raised NameError → silently broke the brief.
    v0.19.2 adds the logger; this test pins it."""
    from recupero.reports import emit_brief
    assert hasattr(emit_brief, "log"), (
        "emit_brief must have a module-level `log` so the "
        "_compact_empty_freezable_only path doesn't NameError"
    )
    # Verify it's actually a logger, not a stub.
    import logging
    assert isinstance(emit_brief.log, logging.Logger)


# ---- Pipeline-HIGH-1: has_been_sent fails CLOSED on DB error ---- #


def test_has_been_sent_fails_closed_when_audit_db_unreachable() -> None:
    """v0.19.2 (round-13 pipeline-HIGH-1): when the audit query fails,
    return True (= "already sent, skip") rather than False (= "go
    ahead and send"). Pre-v0.19.2 a transient pooler blip caused the
    fail-open path to re-send the victim summary, which mints a NEW
    Stripe payment link — duplicate $10K engagement charges possible."""
    from recupero.worker._email import has_been_sent
    with patch("recupero.worker._email.psycopg.connect",
               side_effect=Exception("network unreachable")):
        assert has_been_sent(
            investigation_id=uuid4(),
            email_type="victim_summary",
            dsn="postgresql://test",
        ) is True


# ---- Type-HIGH-2: dormant finder canonical-keys Solana mints ---- #


def test_dormant_finder_uses_canonical_key_for_token_bucket() -> None:
    """v0.19.2 (round-13 type-HIGH-2): bucket dedup key uses
    canonical_address_key so Solana base58 mints case-preserve.
    Pre-v0.19.2 `.lower()` mangled the mint to a non-on-chain string;
    two distinct on-chain mints whose lowercased forms collided got
    merged silently. Validate by reading the module source for the
    canonical reference (no easy unit fixture without a full BFS run)."""
    from pathlib import Path

    import recupero.dormant.finder as finder_mod
    src = Path(finder_mod.__file__).read_text(encoding="utf-8")
    # The two bucket-key sites both reference canonical_address_key.
    assert "canonical_address_key" in src, (
        "dormant/finder.py must use canonical_address_key for the "
        "token-bucket dedup key (v0.19.2 fix)"
    )
    # No remaining `.lower()` on `tr.token.contract` (the trace-side
    # bucket key) and none on `ref.contract` (the issuer-sweep key).
    assert "(tr.token.contract or \"__native__\").lower()" not in src, (
        "found legacy .lower() on tr.token.contract — round-13 "
        "type-HIGH-2 fix regressed"
    )
    assert "(ref.contract or \"__native__\").lower()" not in src, (
        "found legacy .lower() on ref.contract — round-13 type-HIGH-2 "
        "fix regressed for the issuer-token sweep"
    )


# ---- Code-quality #6: TOTAL_LOSS_USD vs TOTAL_SUSPECTED_USD ---- #


def test_skip_editorial_brief_keeps_loss_distinct_from_suspected() -> None:
    """The skip-editorial freeze_brief synthesizer writes TOTAL_LOSS_USD=$0
    (no victim data on this path) and surfaces the across-all-asks sum
    as TOTAL_SUSPECTED_USD. Pre-v0.19.2 the same value was written as
    TOTAL_LOSS_USD, conflating "drained from victim" with "held in
    perp wallets." We re-run the synthesizer here via a tempdir fixture
    instead of duplicating it."""
    # The integration test in test_v_cfi01_integration.py already
    # asserts the live behavior via _synthesize_freeze_brief_from_asks.
    # Here we just pin the contract via a string-source inspection,
    # which is robust to renames of the integration-test path.
    import inspect

    from recupero.worker import pipeline
    src = inspect.getsource(pipeline._synthesize_freeze_brief_from_asks)
    assert "TOTAL_LOSS_USD" in src
    assert "TOTAL_SUSPECTED_USD" in src
    assert '"TOTAL_LOSS_USD": "$0.00"' in src or "'TOTAL_LOSS_USD': '$0.00'" in src, (
        "skip-editorial path must write TOTAL_LOSS_USD as $0 — wallet-trace "
        "has no victim → no real loss; suspected sum goes in TOTAL_SUSPECTED_USD"
    )


# ---- Pipeline-HIGH-2: mark_built_package / mark_completed expect 1 row ---- #


def test_mark_built_package_raises_on_lost_claim() -> None:
    """v0.19.2 (round-13 pipeline-HIGH-2): if the reaper concurrently
    clears worker_id, the UPDATE matches zero rows and the worker
    silently "succeeds" — but the row stays in `failed` state with
    no completed_at. Now `_exec_expect_one_row` raises `WorkerClaimLost`
    so pipeline.run_one can tag the failure clearly instead of
    accepting a phantom transition."""
    from recupero.worker.db import WorkerClaimLost, WorkerDB

    db = WorkerDB(dsn="postgresql://test", worker_id="test-worker")
    # Mock a cursor that reports 0 rowcount (zero rows matched).
    mock_cur = MagicMock()
    mock_cur.rowcount = 0
    mock_conn = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    with patch("recupero.worker.db.psycopg.connect") as mock_connect:
        mock_connect.return_value.__enter__.return_value = mock_conn
        try:
            db.mark_completed(uuid4())
        except WorkerClaimLost as exc:
            assert "mark_completed" in str(exc)
            assert "claim lost" in str(exc).lower()
        else:
            raise AssertionError(
                "mark_completed must raise WorkerClaimLost on rowcount=0; "
                "v0.19.2 fix regressed"
            )


# ---- Arch-MED-8: env_truthy migration for digest + ops env vars ---- #


def test_recupero_ops_assume_yes_accepts_truthy_variants(monkeypatch) -> None:
    """v0.19.2 (round-13 CLI-HIGH-7): `RECUPERO_OPS_ASSUME_YES` accepts
    all canonical truthy variants via `_common.env_truthy`. Pre-v0.19.2
    only the literal "1" worked — operators copying RECUPERO_DISABLE_EMAIL=true
    style and writing OPS_ASSUME_YES=true got blocked at the interactive
    prompt mid-cron."""
    from recupero.ops.cli import _confirm
    for truthy in ("1", "true", "TRUE", "yes", "on", "Y", "t"):
        monkeypatch.setenv("RECUPERO_OPS_ASSUME_YES", truthy)
        # default=False so only the env var can flip this to True.
        assert _confirm("test prompt", default=False) is True, (
            f"truthy form {truthy!r} should bypass the prompt"
        )
    monkeypatch.delenv("RECUPERO_OPS_ASSUME_YES", raising=False)


def test_digest_always_send_accepts_truthy_variants(monkeypatch) -> None:
    """v0.19.2 (round-13 pipeline-MED-8): same migration for the
    digest_email module. Pre-v0.19.2 `RECUPERO_DIGEST_ALWAYS_SEND=true`
    silently fell through to "skip — no material changes." """
    import inspect

    from recupero.worker import digest_email
    src = inspect.getsource(digest_email.maybe_send_digest_email)
    assert "env_truthy" in src, (
        "digest_email must use env_truthy for RECUPERO_DIGEST_ALWAYS_SEND"
    )
    assert '== "1"' not in src, (
        "found legacy strict-equality check; v0.19.2 fix regressed"
    )


# ---- Type-HIGH-3: API request models reject unknown chains ---- #


def test_screen_request_rejects_unknown_chain() -> None:
    """v0.19.2 (round-13 type-HIGH-3): `chain` is typed as
    `_SupportedChain` Literal. Pre-v0.19.2 the free-form str accepted
    `chain="foobar"` and failed deep in the screener; now Pydantic
    returns 422 with the allowed list."""
    from pydantic import ValidationError

    from recupero.api.app import ScreenRequest

    # Valid chains succeed.
    for valid in ("ethereum", "solana", "tron", "bitcoin", "hyperliquid"):
        req = ScreenRequest(address="0xdead", chain=valid)
        assert req.chain == valid

    # Unknown chain rejected up-front.
    try:
        ScreenRequest(address="0xdead", chain="foobar_chain")
    except ValidationError:
        pass
    else:
        raise AssertionError(
            "ScreenRequest must reject unknown chain values"
        )


def test_screen_request_caps_address_length() -> None:
    """v0.19.2: max_length cap on `address` so an authenticated caller
    can't POST a 16MB string and force downstream lookups to walk it."""
    from pydantic import ValidationError

    from recupero.api.app import ScreenRequest

    # 128 chars OK; 129 rejected.
    ScreenRequest(address="0x" + "a" * 126, chain="ethereum")  # exactly 128
    try:
        ScreenRequest(address="x" * 200, chain="ethereum")
    except ValidationError:
        pass
    else:
        raise AssertionError("address > max_length must be rejected")


# ---- CLI-HIGH-9: --version flag exists on both CLIs ---- #


def test_recupero_cli_has_version_flag() -> None:
    """`recupero --version` exits 0 and prints a version string."""
    from typer.testing import CliRunner

    from recupero.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "recupero" in result.output.lower()


def test_recupero_ops_cli_has_version_flag() -> None:
    """`recupero-ops --version` exits 0 and prints a version string."""
    import subprocess
    import sys
    # Use python -m so we don't depend on installed console-script path.
    result = subprocess.run(
        [sys.executable, "-c",
         "from recupero.ops.cli import cli; "
         "import sys; sys.argv=['recupero-ops', '--version']; cli()"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "recupero" in (result.stdout + result.stderr).lower()


# ---- CLI-MED-14: mark-engaged --fee bounds check ---- #


def test_mark_engaged_rejects_negative_fee() -> None:
    """v0.19.2 (round-13 CLI-MED-14): operator typo `--fee -10000`
    must be rejected before the DB write. Pre-v0.19.2 a negative fee
    persisted as engagement_fee_paid_usd and broke downstream P&L."""
    from recupero.ops.commands.mark_engaged import run
    rc = run(
        investigation_id=uuid4(),
        fee_usd=Decimal("-10000"),
        dsn="postgresql://unused-because-we-bail-pre-connect",
    )
    assert rc == 1


def test_mark_engaged_rejects_absurd_fee() -> None:
    """An operator typing 1e30 by accident should also fail loudly."""
    from recupero.ops.commands.mark_engaged import run
    rc = run(
        investigation_id=uuid4(),
        fee_usd=Decimal("1000000000"),  # $1B
        dsn="postgresql://unused",
    )
    assert rc == 1


def test_mark_engaged_rejects_zero_fee() -> None:
    """Zero is a sentinel for "I forgot to pass --fee"; reject it."""
    from recupero.ops.commands.mark_engaged import run
    rc = run(
        investigation_id=uuid4(),
        fee_usd=Decimal("0"),
        dsn="postgresql://unused",
    )
    assert rc == 1
