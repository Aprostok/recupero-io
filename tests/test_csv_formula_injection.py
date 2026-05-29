"""RIGOR-Jacob L: CSV formula injection (CWE-1236) hardening.

``transfers.csv`` is the primary handoff artifact for law-enforcement
review. LE analysts open it in Excel, LibreOffice Calc, or Google
Sheets. ANY cell whose content starts with ``=``, ``+``, ``-``,
``@``, or a tab/CR is interpreted as a FORMULA by these tools — not
text.

An attacker can deploy an ERC-20 contract with a malicious symbol
(``=HYPERLINK("https://phish.com", "Click")``, ``=cmd|'/c calc'!A0``,
``=IMPORTXML(...)``) and trick a victim into receiving funds from
it. When the trace runs, the symbol lands in ``transfers.csv``. When
the LE analyst opens the file, the formula runs in their environment
— up to and including arbitrary command execution on Windows /
arbitrary URL fetch on Google Sheets.

The standard fix (OWASP): prefix any cell starting with
``= + - @ TAB CR`` with a single quote ``'`` so the spreadsheet
treats it as literal text. Locked here.

Attacker-controlled fields in our CSV:
  * token_symbol (from on-chain ERC-20 contract)
  * token_contract (chain address — bounded shape, safer)
  * to_label / to_label_category / to_exchange (from label DB —
    operator-controlled, lower risk, but defense-in-depth)
  * pricing_error / pricing_source (largely operator-controlled
    but could include adversarial token symbols on error)
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime
from decimal import Decimal
from io import StringIO
from pathlib import Path


def _build_transfer_with_symbol(symbol: str):
    """Construct a minimal Transfer object with the given token symbol."""
    from recupero.models import (
        Case,
        Chain,
        Counterparty,
        TokenRef,
        Transfer,
    )

    now = datetime(2024, 1, 1, tzinfo=UTC)
    transfer = Transfer(
        transfer_id="ethereum:0xabc:0",
        chain=Chain.ethereum,
        tx_hash="0x" + "a" * 64,
        block_number=18_000_000,
        block_time=now,
        from_address="0x" + "f" * 40,
        to_address="0x" + "e" * 40,
        counterparty=Counterparty(
            address="0x" + "e" * 40, label=None, is_contract=False,
        ),
        token=TokenRef(
            chain=Chain.ethereum,
            contract="0x" + "1" * 40,
            symbol=symbol,
            decimals=18,
            coingecko_id=None,
        ),
        amount_raw="1000000000000000000",
        amount_decimal=Decimal("1.0"),
        usd_value_at_tx=Decimal("1000.00"),
        hop_depth=0,
        fetched_at=now,
        explorer_url="https://etherscan.io/tx/0xabc",
    )
    case = Case(
        case_id="TEST",
        seed_address="0x" + "f" * 40,
        chain=Chain.ethereum,
        incident_time=now,
        trace_started_at=now,
        trace_completed_at=now,
        transfers=[transfer],
    )
    return case


def _write_csv_to_string(case) -> str:
    """Exercise the real _write_transfers_csv but write to a tmp file
    then read back the raw text."""
    import tempfile

    from recupero.storage.case_store import CaseStore
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False, encoding="utf-8",
    ) as f:
        path = Path(f.name)
    try:
        CaseStore._write_transfers_csv(case, path)
        return path.read_text(encoding="utf-8")
    finally:
        path.unlink(missing_ok=True)


def _parse_symbol_cell(csv_text: str) -> str:
    """Extract the token_symbol cell from the first data row."""
    reader = csv.DictReader(StringIO(csv_text))
    rows = list(reader)
    assert rows, f"no rows in CSV:\n{csv_text}"
    return rows[0]["token_symbol"]


def test_csv_formula_injection_equals_prefixed() -> None:
    """A token symbol starting with ``=`` is a documented formula-
    injection vector. The cell must be prefixed with ``'`` so Excel
    treats it as text."""
    case = _build_transfer_with_symbol('=cmd|" /C calc"!A0')
    csv_text = _write_csv_to_string(case)
    cell = _parse_symbol_cell(csv_text)
    assert cell.startswith("'"), (
        f"Token symbol starting with '=' must be prefixed with quote "
        f"to neutralize Excel formula execution; got {cell!r}.\n"
        f"Full CSV:\n{csv_text}"
    )


def test_csv_formula_injection_plus_prefixed() -> None:
    """``+`` is also a formula prefix in Excel."""
    case = _build_transfer_with_symbol("+SUM(A1:A99)")
    csv_text = _write_csv_to_string(case)
    cell = _parse_symbol_cell(csv_text)
    assert cell.startswith("'")


def test_csv_formula_injection_minus_prefixed() -> None:
    """``-`` is also a formula prefix in Excel."""
    case = _build_transfer_with_symbol("-2+3*A1")
    csv_text = _write_csv_to_string(case)
    cell = _parse_symbol_cell(csv_text)
    assert cell.startswith("'")


def test_csv_formula_injection_at_prefixed() -> None:
    """``@`` is the SUM range invoker in older Excel."""
    case = _build_transfer_with_symbol("@SUM(1,2)")
    csv_text = _write_csv_to_string(case)
    cell = _parse_symbol_cell(csv_text)
    assert cell.startswith("'")


def test_csv_formula_injection_tab_prefixed() -> None:
    """A leading tab character can also trigger formula evaluation
    in some Excel versions."""
    case = _build_transfer_with_symbol("\t=cmd|stuff")
    csv_text = _write_csv_to_string(case)
    cell = _parse_symbol_cell(csv_text)
    # Either the tab is stripped (so the = is now leading and gets
    # quoted) OR the entire cell is quote-prefixed. Both are
    # acceptable; the explicit failure mode is "raw =cmd remains
    # at column-zero".
    assert "=cmd" not in cell or cell.startswith("'"), (
        f"Tab-prefixed formula cell {cell!r} not safely escaped"
    )


def test_csv_legitimate_symbol_unchanged() -> None:
    """Sanity: a legitimate symbol like USDT or USDC isn't
    over-quoted (would break LE's automated parsing)."""
    case = _build_transfer_with_symbol("USDT")
    csv_text = _write_csv_to_string(case)
    cell = _parse_symbol_cell(csv_text)
    assert cell == "USDT", (
        f"Legitimate symbol 'USDT' was modified to {cell!r} — would "
        f"break LE's automated CSV parsing"
    )


def test_csv_legitimate_symbol_with_hyphen_unchanged() -> None:
    """Some legitimate tokens contain hyphens or unusual chars
    (e.g., yvWETH, ARB-USD). Make sure those still pass through."""
    for sym in ("yvWETH", "ARB-USD", "wstETH", "1INCH"):
        case = _build_transfer_with_symbol(sym)
        csv_text = _write_csv_to_string(case)
        cell = _parse_symbol_cell(csv_text)
        assert cell == sym, (
            f"Symbol {sym!r} should pass through unchanged; got {cell!r}"
        )
