"""RIGOR-Jacob M: harden CaseStore.read_case against adversarial input.

Two real bugs in ``read_case``:

  1. **Path traversal** — read_case(case_id) was building
     ``cases_root / case_id / "case.json"`` directly, BYPASSING the
     ``_validate_case_id`` allow-list that case_dir() uses. The
     RIGOR-K hardening only fixed the write path; an attacker who
     reaches read_case with ``case_id="../../etc/passwd"`` reads
     outside the data dir.

  2. **No size cap on f.read()** — the worker reads the entire
     case.json into memory before parsing. A hostile (or accidentally
     corrupted) case.json of multi-GB size OOMs the worker process.
     Realistic case.json size: V-CFI01 is ~150KB; 100MB is a
     generous ceiling that bounds the memory footprint while
     allowing every realistic case to load.

Lock the contract: both shapes raise ``ValueError`` / ``IOError``
before the file is fully read into memory.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _build_store(tmp_path: Path):
    """Construct a CaseStore at a temporary data dir."""
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    return CaseStore(cfg), tmp_path / "cases"


def test_read_case_traversal_actually_blocked(tmp_path: Path) -> None:
    """RIGOR-Jacob M: a planted file OUTSIDE cases_root must NOT be
    readable via a traversal case_id. This is the strict contract —
    NOT just "raises some exception" (which a non-existent file does
    anyway), but "the file outside cases_root is never accessed
    even when it exists".

    Pre-fix: read_case("../escape") would attempt to open
    cases_root/../escape/case.json, which IS accessible. With the
    traversal fix, it must raise BEFORE opening that file.
    """
    store, cases_root = _build_store(tmp_path)
    # Plant an attacker-readable file outside cases_root.
    escape_dir = cases_root.parent / "escape"
    escape_dir.mkdir()
    target = escape_dir / "case.json"
    target.write_text('{"secret":"leaked"}', encoding="utf-8")
    assert target.exists()

    # If the traversal is not blocked, read_case would attempt to
    # open this file (and fail downstream on Pydantic validation,
    # but the FILE WAS READ). With the fix, the validator raises
    # before any open() call.
    #
    # Use a Python-level mock of Path.open to detect whether the
    # traversal-resolved path is ever opened, regardless of the
    # downstream parse outcome.
    opens_seen: list[str] = []
    orig_open = type(target).open
    def watched_open(self, *args, **kwargs):
        opens_seen.append(str(self))
        return orig_open(self, *args, **kwargs)

    # Patch only on the path objects the store would touch.
    try:
        type(target).open = watched_open  # type: ignore[method-assign]
        with pytest.raises((ValueError, OSError)):
            store.read_case("../escape")
    finally:
        type(target).open = orig_open  # type: ignore[method-assign]

    # The escape file must NOT have been opened.
    escape_path_str = str(target)
    for opened in opens_seen:
        assert opened != escape_path_str, (
            f"RIGOR-Jacob M broken: read_case opened {opened!r} "
            f"(outside cases_root). The traversal validator must "
            f"raise BEFORE any open() of the escape path."
        )


@pytest.mark.parametrize("invalid_id", [
    "..",
    "case\x00null",
    "",
    "  ",
    "case/with/slash",
    "case\\with\\backslash",
])
def test_read_case_rejects_shape_violations(
    tmp_path: Path, invalid_id: str,
) -> None:
    """case_ids with shape violations must raise ValueError BEFORE
    file I/O. This is a defense-in-depth check separate from the
    traversal escape test."""
    store, _ = _build_store(tmp_path)
    with pytest.raises(ValueError):
        store.read_case(invalid_id)


def test_read_case_rejects_oversized_file_via_stat(tmp_path: Path) -> None:
    """A case.json over the size cap must be rejected by st_size
    inspection BEFORE the file is read into memory.

    Validates the strict contract: error message mentions the cap,
    not a downstream "invalid JSON" surrogate. Otherwise a 100GB file
    would be loaded fully into memory before erroring out — the
    OOM the cap is supposed to prevent.

    Uses a SMALL planted file + stat() monkey-patch to simulate a
    big file without actually writing 100GB to disk (slow + flaky).
    """
    store, cases_root = _build_store(tmp_path)

    case_dir = cases_root / "PRETEND_BIG"
    case_dir.mkdir(parents=True)
    case_path = case_dir / "case.json"
    # File on disk is tiny — but we'll lie about its size.
    case_path.write_text('{"case_id":"PRETEND_BIG"}', encoding="utf-8")

    import os
    orig_stat = os.stat
    def fake_stat(p, *args, **kwargs):
        result = orig_stat(p, *args, **kwargs)
        if str(p).endswith("case.json"):
            class FakeStat:
                st_size = 200_000_000  # 200MB
                # Forward the other attrs in case downstream reads them
                def __getattr__(self, name):
                    return getattr(result, name)
            return FakeStat()
        return result

    with pytest.MonkeyPatch.context() as m:
        m.setattr(os, "stat", fake_stat)
        try:
            store.read_case("PRETEND_BIG")
        except ValueError as e:
            # Acceptable — the size cap raised. Verify the error
            # message references the size, not a downstream parse
            # failure.
            assert "size" in str(e).lower() or "too large" in str(e).lower() \
                or "100" in str(e).lower() or "mb" in str(e).lower(), (
                f"Size-cap error must mention 'size' / 'too large' / 'MB'; "
                f"got {e!r}. Otherwise downstream consumers can't tell "
                f"the OOM-prevention path from generic parse failure."
            )
            return
        except OSError:
            return  # acceptable (raised by os.stat itself)
        raise AssertionError(
            "read_case accepted a 200MB-claimed file — would OOM worker"
        )


def test_read_case_accepts_realistic_size(tmp_path: Path) -> None:
    """Sanity: a normal-sized case.json (small) still loads fine."""
    from datetime import UTC, datetime
    from decimal import Decimal

    from recupero.models import (
        Case,
        Chain,
        Counterparty,
        TokenRef,
        Transfer,
    )

    store, _ = _build_store(tmp_path)
    now = datetime(2024, 1, 1, tzinfo=UTC)
    case = Case(
        case_id="NORMAL",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=now,
        trace_started_at=now,
        trace_completed_at=now,
        transfers=[
            Transfer(
                transfer_id="ethereum:0x1:0",
                chain=Chain.ethereum,
                tx_hash="0x" + "1" * 64,
                block_number=1,
                block_time=now,
                from_address="0x" + "a" * 40,
                to_address="0x" + "b" * 40,
                counterparty=Counterparty(
                    address="0x" + "b" * 40, label=None,
                    is_contract=False,
                ),
                token=TokenRef(
                    chain=Chain.ethereum, contract=None,
                    symbol="ETH", decimals=18,
                    coingecko_id="ethereum",
                ),
                amount_raw="1000000000000000000",
                amount_decimal=Decimal("1.0"),
                usd_value_at_tx=Decimal("100.00"),
                hop_depth=0,
                fetched_at=now,
                explorer_url="https://etherscan.io/tx/0x1",
            ),
        ],
    )
    store.write_case(case)
    # Read it back — should not raise.
    loaded = store.read_case("NORMAL")
    assert loaded.case_id == "NORMAL"
    assert len(loaded.transfers) == 1
