"""Adversarial-input tests for config + models + logging_setup.

Patterns covered:
  * load_config: malformed YAML override doesn't poison defaults
  * load_config: YAML that introduces unexpected types is rejected
  * Transfer.amount_raw rejects negative-signed integer strings
  * Transfer.amount_raw rejects non-integer strings
  * logging_setup _redact + _strip_log_injection together strip CR/LF
  * logging_setup: log-record CRLF injection is neutralized
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

# ---- config: YAML override hardening ---- #


def test_load_config_default_loads_cleanly() -> None:
    """Baseline: load_config must not raise on the bundled default."""
    from recupero.config import load_config
    cfg, env = load_config()
    assert cfg is not None
    assert env is not None


def test_load_config_rejects_yaml_with_garbage_types(tmp_path: Path) -> None:
    """A YAML override that supplies a wrong-typed value for a field
    (e.g. trace.max_depth as a string) must raise a clear validation
    error — not silently coerce."""
    from recupero.config import load_config

    bad = tmp_path / "bad.yaml"
    bad.write_text(
        yaml.safe_dump({"trace": {"max_depth": "not-an-int"}}),
        encoding="utf-8",
    )
    with pytest.raises(Exception):
        load_config(bad)


def test_load_config_empty_yaml_passes(tmp_path: Path) -> None:
    """An empty YAML file must NOT crash — `yaml.safe_load("") → None`
    is handled by the `or {}` fallback."""
    from recupero.config import load_config
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    cfg, _ = load_config(empty)
    assert cfg is not None


# ---- models.Transfer.amount_raw ---- #


def test_amount_raw_rejects_negative_int_string() -> None:
    """v0.16.7 regression: a leading-minus integer string indicates
    a parser bug upstream; the validator must reject it."""
    from datetime import UTC, datetime

    from recupero.models import Chain, Counterparty, TokenRef, Transfer

    base_kwargs: dict[str, Any] = {
        "transfer_id": "t1",
        "chain": Chain.ethereum,
        "tx_hash": "0x" + "a" * 64,
        "block_number": 1,
        "block_time": datetime.now(UTC),
        "from_address": "0x" + "1" * 40,
        "to_address": "0x" + "2" * 40,
        "counterparty": Counterparty(
            address="0x" + "2" * 40,
            is_contract=False,
        ),
        "token": TokenRef(
            chain=Chain.ethereum,
            contract="0x" + "3" * 40,
            symbol="USDC",
            decimals=6,
        ),
        "amount_decimal": 0,  # type: ignore[arg-type]
        "fetched_at": datetime.now(UTC),
        "explorer_url": "https://etherscan.io/tx/abc",
    }
    with pytest.raises(ValueError):
        Transfer(amount_raw="-1234", **base_kwargs)


def test_amount_raw_rejects_decimal_string() -> None:
    from datetime import UTC, datetime

    from recupero.models import Chain, Counterparty, TokenRef, Transfer

    base_kwargs: dict[str, Any] = {
        "transfer_id": "t1",
        "chain": Chain.ethereum,
        "tx_hash": "0x" + "a" * 64,
        "block_number": 1,
        "block_time": datetime.now(UTC),
        "from_address": "0x" + "1" * 40,
        "to_address": "0x" + "2" * 40,
        "counterparty": Counterparty(
            address="0x" + "2" * 40,
            is_contract=False,
        ),
        "token": TokenRef(
            chain=Chain.ethereum,
            contract="0x" + "3" * 40,
            symbol="USDC",
            decimals=6,
        ),
        "amount_decimal": 0,  # type: ignore[arg-type]
        "fetched_at": datetime.now(UTC),
        "explorer_url": "https://etherscan.io/tx/abc",
    }
    with pytest.raises(ValueError):
        Transfer(amount_raw="1.5", **base_kwargs)


def test_amount_raw_rejects_hex_string() -> None:
    from datetime import UTC, datetime

    from recupero.models import Chain, Counterparty, TokenRef, Transfer

    base_kwargs: dict[str, Any] = {
        "transfer_id": "t1",
        "chain": Chain.ethereum,
        "tx_hash": "0x" + "a" * 64,
        "block_number": 1,
        "block_time": datetime.now(UTC),
        "from_address": "0x" + "1" * 40,
        "to_address": "0x" + "2" * 40,
        "counterparty": Counterparty(
            address="0x" + "2" * 40,
            is_contract=False,
        ),
        "token": TokenRef(
            chain=Chain.ethereum,
            contract="0x" + "3" * 40,
            symbol="USDC",
            decimals=6,
        ),
        "amount_decimal": 0,  # type: ignore[arg-type]
        "fetched_at": datetime.now(UTC),
        "explorer_url": "https://etherscan.io/tx/abc",
    }
    with pytest.raises(ValueError):
        Transfer(amount_raw="0xff", **base_kwargs)


# ---- models: extra="forbid" on inner models ---- #


def test_token_ref_rejects_extra_fields() -> None:
    """Inner models should reject unknown keys so an attacker who
    controls a JSON payload can't smuggle an alternative field into
    the model state."""
    from recupero.models import Chain, TokenRef
    with pytest.raises(Exception):
        TokenRef.model_validate({
            "chain": Chain.ethereum,
            "symbol": "USDC",
            "decimals": 6,
            "MALICIOUS_FIELD": "hi",
        })


# ---- logging_setup: log-injection defense ---- #


def test_redact_secrets_preserves_normal_message() -> None:
    from recupero.logging_setup import _redact
    assert _redact("hello world") == "hello world"


def test_redact_dsn_password() -> None:
    from recupero.logging_setup import _redact
    out = _redact("connect to postgresql://u:secret123@host/db failed")
    assert "secret123" not in out
    assert "***" in out


def test_strip_log_injection_removes_crlf() -> None:
    """The plain-text log formatter would otherwise emit a forged
    log line when given a multi-line message."""
    from recupero.logging_setup import _strip_log_injection
    out = _strip_log_injection(
        "case=ZIGHA\r\n2026-05-22T00:00:00 ERROR security: fake breach\n"
    )
    assert "\r" not in out
    assert "\n" not in out


def test_strip_log_injection_removes_nul() -> None:
    from recupero.logging_setup import _strip_log_injection
    assert "\x00" not in _strip_log_injection("ok\x00stuffed")


def test_strip_log_injection_removes_bidi_overrides() -> None:
    """U+202E (right-to-left override) can disguise the visible
    content of a log line. Strip it."""
    from recupero.logging_setup import _strip_log_injection
    out = _strip_log_injection("legit‮moc.evil")
    assert "‮" not in out


def test_strip_log_injection_keeps_tabs() -> None:
    """Tabs are operator-friendly inside multi-line tracebacks; keep
    them while still stripping other C0 control chars."""
    from recupero.logging_setup import _strip_log_injection
    assert _strip_log_injection("col1\tcol2") == "col1\tcol2"


def test_secret_redacting_filter_blocks_crlf_forgery() -> None:
    """End-to-end: a log record whose message carries CR/LF + a
    forged log line must come out with the CR/LF collapsed."""
    import logging

    from recupero.logging_setup import _SecretRedactingFilter

    rec = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="case_id=%s",
        args=("ZIGHA\r\n2026-05-22 FATAL forged log line",),
        exc_info=None,
    )
    flt = _SecretRedactingFilter()
    assert flt.filter(rec) is True
    final = rec.getMessage()
    assert "\r" not in final
    assert "\n" not in final


# ---- logging_setup: run_context ---- #


def test_run_context_isolates_between_blocks() -> None:
    from recupero.logging_setup import current_log_context, run_context

    with run_context(investigation_id="A"):
        assert current_log_context()["investigation_id"] == "A"
        with run_context(investigation_id="B"):
            # Inner block can't override outer — defended by setdefault.
            assert current_log_context()["investigation_id"] == "A"
    # Outside the block, context is empty (or at least doesn't carry A).
    assert current_log_context().get("investigation_id") is None
