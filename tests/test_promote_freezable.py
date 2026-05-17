"""Tests for `recupero-ops promote-freezable`.

The command's I/O is straightforward — fetch the row, validate
the reason, UPDATE is_freezeable + kyc_* columns. We cover the
guard rails (reason length, already-FREEZABLE handling,
confirmation bail-out) since those are the bug-magnets.

The live happy-path is exercised in the canary dry-run at
release time.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

from recupero.ops.commands.promote_freezable import run


def _yes(_prompt: str) -> bool:
    return True


def _no(_prompt: str) -> bool:
    return False


def _mk_row(**overrides):
    base = {
        "id": str(uuid4()),
        "chain": "ethereum",
        "address": "0xabc123",
        "status": "active",
        "is_freezeable": False,
        "issuer": "circle",
        "last_balance_usd": 12345,
        "kyc_confirmed_at": None,
        "kyc_confirmed_by_operator": None,
        "kyc_confirmation_note": None,
    }
    base.update(overrides)
    return base


def test_promote_freezable_rejects_short_reason() -> None:
    """A reason shorter than 10 chars is rejected before any DB
    roundtrip. The audit trail needs enough text to re-verify the
    promotion later — 'ok' or 'good' isn't enough."""
    rc = run(
        watchlist_id=uuid4(), reason="ok", force=False,
        dsn="fake-dsn", confirm=_yes,
    )
    assert rc == 1


def test_promote_freezable_404s_on_unknown_id() -> None:
    """Watchlist row doesn't exist → exit 1 + helpful message."""
    with patch("recupero.ops.commands.promote_freezable.psycopg.connect") as mc:
        cur = MagicMock()
        cur.fetchone.return_value = None
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mc.return_value.__enter__.return_value = conn

        rc = run(
            watchlist_id=uuid4(),
            reason="Circle confirmed KYC via ticket #4242",
            force=False, dsn="fake-dsn", confirm=_yes,
        )
    assert rc == 1


def test_promote_freezable_already_freezeable_no_force_warns_and_exits_zero() -> None:
    """Row already FREEZABLE + no --force → print the existing audit
    info + exit 0 (idempotent no-op). We don't fail because the
    operator may have re-run the command unintentionally and we
    don't want to look like there's a real error."""
    with patch("recupero.ops.commands.promote_freezable.psycopg.connect") as mc:
        cur = MagicMock()
        cur.fetchone.return_value = _mk_row(
            is_freezeable=True,
            kyc_confirmed_at="2026-05-01",
            kyc_confirmed_by_operator="ops@recupero",
            kyc_confirmation_note="Circle ticket #1",
        )
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mc.return_value.__enter__.return_value = conn

        rc = run(
            watchlist_id=uuid4(),
            reason="Circle confirmed KYC via ticket #4242",
            force=False, dsn="fake-dsn", confirm=_yes,
        )
    assert rc == 0
    # No UPDATE should have been issued.
    update_calls = [c for c in cur.execute.call_args_list
                    if "UPDATE public.watchlist" in c.args[0]]
    assert update_calls == []


def test_promote_freezable_bails_on_confirm_no() -> None:
    """Operator typed 'n' at the prompt → no DB write, exit 0
    (intentional bail-out, not an error)."""
    with patch("recupero.ops.commands.promote_freezable.psycopg.connect") as mc:
        cur = MagicMock()
        cur.fetchone.return_value = _mk_row(is_freezeable=False)
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mc.return_value.__enter__.return_value = conn

        rc = run(
            watchlist_id=uuid4(),
            reason="Circle confirmed KYC via ticket #4242",
            force=False, dsn="fake-dsn", confirm=_no,
        )
    assert rc == 0
    update_calls = [c for c in cur.execute.call_args_list
                    if "UPDATE public.watchlist" in c.args[0]]
    assert update_calls == []


def test_promote_freezable_happy_path_updates_columns() -> None:
    """Confirmed promotion → issues an UPDATE with is_freezeable=TRUE
    and writes the kyc_* audit columns."""
    with patch("recupero.ops.commands.promote_freezable.psycopg.connect") as mc:
        cur = MagicMock()
        # 1st fetchone = select row, 2nd = UPDATE RETURNING.
        cur.fetchone.side_effect = [
            _mk_row(is_freezeable=False),
            {"kyc_confirmed_at": "2026-05-15"},
        ]
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mc.return_value.__enter__.return_value = conn

        rc = run(
            watchlist_id=uuid4(),
            reason="Circle confirmed KYC via ticket #4242 — 2026-05-15",
            force=False, dsn="fake-dsn", confirm=_yes,
        )
    assert rc == 0
    update_calls = [c for c in cur.execute.call_args_list
                    if "UPDATE public.watchlist" in c.args[0]]
    assert len(update_calls) == 1
    sql = update_calls[0].args[0]
    assert "is_freezeable = TRUE" in sql
    assert "kyc_confirmed_at = NOW()" in sql
    assert "kyc_confirmed_by_operator" in sql


def test_promote_freezable_force_overwrites_existing_audit() -> None:
    """With --force, an already-FREEZABLE row goes through the same
    UPDATE path. Used when the original promotion was made with a
    typo'd operator name."""
    with patch("recupero.ops.commands.promote_freezable.psycopg.connect") as mc:
        cur = MagicMock()
        cur.fetchone.side_effect = [
            _mk_row(is_freezeable=True, kyc_confirmed_at="2026-04-01"),
            {"kyc_confirmed_at": "2026-05-15"},
        ]
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mc.return_value.__enter__.return_value = conn

        rc = run(
            watchlist_id=uuid4(),
            reason="Re-confirming KYC — original note was unclear (#5566)",
            force=True, dsn="fake-dsn", confirm=_yes,
        )
    assert rc == 0
    update_calls = [c for c in cur.execute.call_args_list
                    if "UPDATE public.watchlist" in c.args[0]]
    assert len(update_calls) == 1
