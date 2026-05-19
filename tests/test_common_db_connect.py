"""Regression for `recupero._common.db_connect`.

v0.18.1 (round-11 arch-CRIT-001): pre-v0.18.1 this helper raised
TypeError on first call ("got multiple values for keyword argument
'prepare_threshold'") because both `**kwargs` and explicit
`prepare_threshold=None, connect_timeout=10` were passed to
`psycopg.connect`. The helper was a planted bomb. This test pins
that the call signature works — calling it (with a mocked psycopg)
must NOT raise.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock


def test_db_connect_does_not_double_pass_kwargs() -> None:
    """Verify db_connect can be called without TypeError.

    We patch psycopg.connect to capture the kwargs handed to it.
    """
    from recupero._common import db_connect

    with patch("psycopg.connect", new=MagicMock()) as mock_connect:
        db_connect("postgresql://user:pw@host/db")
        mock_connect.assert_called_once()
        # Inspect the kwargs that were actually passed.
        _, kwargs = mock_connect.call_args
        # Pooler-safe defaults should be present exactly once.
        assert kwargs["prepare_threshold"] is None
        assert kwargs["connect_timeout"] == 10
        assert kwargs["autocommit"] is True


def test_db_connect_overrides_take_precedence() -> None:
    """Caller-supplied overrides win over the defaults."""
    from recupero._common import db_connect

    with patch("psycopg.connect", new=MagicMock()) as mock_connect:
        db_connect(
            "postgresql://user:pw@host/db",
            connect_timeout=30,
            autocommit=False,
        )
        _, kwargs = mock_connect.call_args
        assert kwargs["connect_timeout"] == 30
        assert kwargs["autocommit"] is False
        # Non-overridden default still applies.
        assert kwargs["prepare_threshold"] is None
