"""Adversarial-input audit for ``src/recupero/worker/_trace_report.py``.

The trace report is emitted on EVERY investigation (the primary
internal artifact for the wallet-trace admin UI). A crash here means
the entire deliverable disappears for that investigation — the
caller swallows the exception and returns ``None``. That silent
failure is the worst possible outcome: operators see "no report"
and assume nothing was found, rather than seeing diagnostic output.

Bugs covered by these RED-first tests:

  * TR-ADV-1 (HIGH): ``Decimal('NaN')`` in any transfer's
    ``usd_value_at_tx`` poisons the running total in
    ``_compute_stats`` (silently produces ``$NaN`` sum, which
    ``fmt_usd`` then clamps to ``$0`` — losing the entire
    aggregate USD figure) AND causes the destinations-table sort
    at the end of ``_build_destinations_table`` to raise
    ``decimal.InvalidOperation`` (``NaN > Decimal(0)`` is invalid),
    which kills the whole render via the outer ``except`` — no
    report file at all.

  * TR-ADV-2 (HIGH): Same shape with ``Decimal('Infinity')`` — the
    sort survives (Infinity is comparable) but the running total
    becomes Infinity. ``fmt_usd`` clamps Infinity but the per-row
    ``usd_value_human`` for the offending transfer renders ``$0``
    silently, hiding a corrupt upstream price.

  * TR-ADV-3 (MEDIUM): A label / counterparty name containing CRLF
    + NUL bytes survives into the destinations table row's
    ``label`` field unsanitized — the template renders it via
    autoescape (which escapes ``<>&"'`` but NOT control chars),
    so the bytes land in the HTML as-is. CRLF in an HTML attribute
    context can split rendered headers when the same template runs
    through the email dispatcher (the dispatcher shares the
    template directory with the brief generator).

  * TR-ADV-4 (MEDIUM): A bidi-override character (U+202E) in a
    label name is not stripped at the row-building layer. Without
    explicit ``safe_text`` at the build site, the rendered
    HTML displays a flipped address-label that operator-eye
    auditing can't catch — the very threat ``safe_text`` was
    introduced to defend against.

  * TR-ADV-5 (LOW): A freeze-brief holding row with the literal
    string ``"$NaN"`` in ``usd`` (concrete upstream trigger:
    a poisoned Decimal hits ``fmt_usd`` upstream, then a
    pre-RIGOR-Z11 brief emits ``"$NaN"`` — old brief artifacts
    on disk still carry the poisoned text) causes ``_usd_key``'s
    ``float("NaN")`` parse to succeed and inject NaN into the
    sort key. ``nan < nan == False`` makes the resulting sort
    order non-deterministic; the table can render in different
    orders on different platforms / Python builds, breaking
    determinism / golden-file diffing.

  * TR-ADV-6 (LOW): ``_build_destinations_table`` uses
    ``t.chain.value if hasattr(t.chain, "value") else str(t.chain)``
    on line ~270. If a stub / mock pipeline passes a chain object
    with a ``.value`` attribute that is None / int / bytes, the
    resulting ``row_chain`` is passed to ``_explorer_url`` which
    does a dict lookup — non-string keys silently produce ``""``,
    losing the explorer link without warning. We assert the
    builder either raises loud or recovers via str() coercion.

Each test is RED-first (fails on current code), then GREEN after
the in-place minimal fix.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from recupero.models import Case, Chain, Counterparty, Label, LabelCategory, TokenRef, Transfer
from recupero.worker._trace_report import (
    _build_destinations_table,
    _build_freezable_table,
    _compute_stats,
    render_trace_report,
)

# --------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------- #


def _mk_transfer(
    *,
    to_addr: str,
    suffix: str,
    usd: Decimal | None,
    label_name: str | None = None,
    chain: Chain = Chain.ethereum,
) -> Transfer:
    tx_hash = "0x" + (suffix * 16)[:64]
    label = None
    if label_name is not None:
        label = Label(
            address=to_addr,
            name=label_name,
            category=LabelCategory.unknown,
            source="test",
            added_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    # Pydantic's `Transfer` model already rejects non-finite Decimals
    # at construction time (`finite_number` constraint on
    # `usd_value_at_tx`). The trace-report renderer is the second line
    # of defense — meant to survive a future refactor that drops the
    # type-level constraint, or a model produced via `model_construct`
    # (which bypasses validators). To exercise that defense-in-depth
    # without fighting Pydantic, we build with a placeholder finite
    # value and then mutate the field directly when NaN/Inf is asked
    # for. `model_construct` is the documented Pydantic v2 way to
    # bypass validation (see pydantic.dev/v/finite_number).
    safe_usd = usd if (usd is None or usd.is_finite()) else Decimal("0")
    t = Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:1",
        chain=chain,
        tx_hash=tx_hash,
        block_number=1,
        block_time=datetime(2026, 1, 1, tzinfo=UTC),
        from_address="0x" + "0" * 40,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=label, is_contract=False),
        token=TokenRef(
            chain=chain,
            contract="0x" + "c" * 40,
            symbol="USDC",
            decimals=6,
            coingecko_id="usd-coin",
        ),
        amount_raw="1000",
        amount_decimal=Decimal("1"),
        usd_value_at_tx=safe_usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    # Direct attribute write bypasses Pydantic validators on assignment
    # (Transfer is configured without `validate_assignment=True`). This
    # smuggles the adversarial value past the type system the same way
    # a malformed upstream input could after a constraint regression.
    if usd is not None and not usd.is_finite():
        object.__setattr__(t, "usd_value_at_tx", usd)
    return t


def _mk_case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="tr-adv-test",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="t",
        config_used={},
    )


# --------------------------------------------------------------- #
# TR-ADV-1: NaN USD value poisons compute_stats + destinations sort
# --------------------------------------------------------------- #


def test_compute_stats_survives_nan_usd_value() -> None:
    """Pre-fix: any NaN ``usd_value_at_tx`` makes the running sum
    NaN. ``fmt_usd`` clamps NaN→``$0`` so the rendered top-line
    total reads $0 even though there's $500 of real volume —
    silent data loss in the headline figure."""
    b = "0x" + "b" * 40
    c = "0x" + "c" * 40
    transfers = [
        _mk_transfer(to_addr=b, suffix="11", usd=Decimal("500")),
        _mk_transfer(to_addr=c, suffix="22", usd=Decimal("NaN")),
    ]
    case = _mk_case(transfers)

    # Must not crash, and must not silently zero-out a real $500.
    stats = _compute_stats(case)
    # The contract: NaN entries are skipped; legitimate values still summed.
    assert stats["total_flow_usd"] == "$500.00", (
        f"NaN entry poisoned the running total — got {stats['total_flow_usd']!r}"
    )


def test_destinations_table_survives_nan_usd_value_sort() -> None:
    """Pre-fix: ``rows.sort(key=lambda r: r['_usd'], reverse=True)``
    raises ``decimal.InvalidOperation`` because ``Decimal('NaN')``
    can't be ordered against ``Decimal(0)``. The render outer
    try/except catches → ``render_trace_report`` returns ``None``
    → the operator gets NO trace report at all on a case with a
    single NaN-priced transfer. Catastrophic silent failure."""
    b = "0x" + "b" * 40
    c = "0x" + "c" * 40
    d = "0x" + "d" * 40
    transfers = [
        _mk_transfer(to_addr=b, suffix="11", usd=Decimal("500")),
        _mk_transfer(to_addr=c, suffix="22", usd=Decimal("NaN")),
        _mk_transfer(to_addr=d, suffix="33", usd=Decimal("100")),
    ]
    case = _mk_case(transfers)

    # Must not raise InvalidOperation.
    rows = _build_destinations_table(case)
    assert len(rows) == 3
    # Rows still ordered highest-USD-first; NaN row sinks to the bottom.
    assert rows[0]["address"] == b
    # The NaN row must have rendered a fallback string, not the literal "$NaN".
    nan_row = next(r for r in rows if r["address"] == c)
    assert "nan" not in nan_row["usd_value_human"].lower(), (
        f"NaN leaked into rendered usd_value_human: {nan_row['usd_value_human']!r}"
    )


# --------------------------------------------------------------- #
# TR-ADV-2: Infinity USD value
# --------------------------------------------------------------- #


def test_compute_stats_survives_infinity_usd_value() -> None:
    """Pre-fix: ``+= Decimal('Infinity')`` makes the running sum
    Infinity. ``fmt_usd`` clamps→``$0.00`` so the headline reads
    $0 despite $500 + $300 of real flow. Silent data loss."""
    b = "0x" + "b" * 40
    c = "0x" + "c" * 40
    d = "0x" + "d" * 40
    transfers = [
        _mk_transfer(to_addr=b, suffix="11", usd=Decimal("500")),
        _mk_transfer(to_addr=c, suffix="22", usd=Decimal("Infinity")),
        _mk_transfer(to_addr=d, suffix="33", usd=Decimal("300")),
    ]
    case = _mk_case(transfers)
    stats = _compute_stats(case)
    assert stats["total_flow_usd"] == "$800.00", (
        f"Infinity poisoned the sum; got {stats['total_flow_usd']!r}"
    )


# --------------------------------------------------------------- #
# TR-ADV-3: CRLF/NUL in label name leaks into row
# --------------------------------------------------------------- #


def test_destinations_table_strips_crlf_and_nul_from_label() -> None:
    """Pre-fix: a label name containing CRLF/NUL flows verbatim
    into row['label']. Jinja autoescape escapes ``<>&"'`` but NOT
    ``\\r\\n\\x00`` — when the same template runs through the email
    dispatcher path the bytes can split rendered headers."""
    b = "0x" + "b" * 40
    poisoned = "Cluster A\r\nX-Injected: evil\x00\r\n"
    t = _mk_transfer(
        to_addr=b, suffix="11", usd=Decimal("500"), label_name=poisoned,
    )
    case = _mk_case([t])
    rows = _build_destinations_table(case)
    assert len(rows) == 1
    lbl = rows[0]["label"] or ""
    assert "\r" not in lbl and "\n" not in lbl and "\x00" not in lbl, (
        f"CRLF/NUL bytes survived into row label: {lbl!r}"
    )


# --------------------------------------------------------------- #
# TR-ADV-4: bidi-override in label name not stripped
# --------------------------------------------------------------- #


def test_destinations_table_strips_bidi_override_from_label() -> None:
    """Pre-fix: U+202E RIGHT-TO-LEFT-OVERRIDE in a label name
    survives into the row. The trace_report template does NOT
    pipe row['label'] through ``| safe_text``, so the rendered
    HTML shows a visually flipped label — the exact spoof
    ``safe_text`` exists to prevent. Strip at the build site."""
    b = "0x" + "b" * 40
    # "alice" then RLO then "gnp.exe" reads as "aliceexe.png" visually.
    poisoned = "alice‮gnp.exe"
    t = _mk_transfer(
        to_addr=b, suffix="11", usd=Decimal("500"), label_name=poisoned,
    )
    case = _mk_case([t])
    rows = _build_destinations_table(case)
    lbl = rows[0]["label"] or ""
    assert "‮" not in lbl, (
        f"Bidi-override U+202E leaked into row label: {lbl!r}"
    )


# --------------------------------------------------------------- #
# TR-ADV-5: "$NaN" string in freezable usd → non-deterministic sort
# --------------------------------------------------------------- #


def test_freezable_table_sort_is_deterministic_with_nan_string() -> None:
    """Pre-fix: ``float('$NaN'.replace('$','').replace(',',''))`` =
    ``float('NaN')`` succeeds → NaN injected into sort key →
    Python's Timsort with NaN keys produces order-dependent,
    non-deterministic output. The trace report's golden-diff /
    3x-determinism contract is broken silently. Treat unparseable
    or non-finite USD strings as 0.0 so sort is stable."""
    freeze_brief = {
        "FREEZABLE": [
            {
                "issuer": "Circle",
                "token": "USDC",
                "freeze_capability": "HIGH",
                "holdings": [
                    {"address": "0x" + "1" * 40, "amount": "1", "usd": "$100.00"},
                    {"address": "0x" + "2" * 40, "amount": "1", "usd": "$NaN"},
                    {"address": "0x" + "3" * 40, "amount": "1", "usd": "$50.00"},
                    {"address": "0x" + "4" * 40, "amount": "1", "usd": "$Infinity"},
                ],
            },
        ],
    }
    # Run twice — same input, same output (basic determinism).
    rows1 = _build_freezable_table(freeze_brief, "ethereum")
    rows2 = _build_freezable_table(freeze_brief, "ethereum")
    addrs1 = [r["address"] for r in rows1]
    addrs2 = [r["address"] for r in rows2]
    assert addrs1 == addrs2, (
        f"Non-deterministic sort with $NaN/$Infinity input: {addrs1} vs {addrs2}"
    )
    # Strongest contract: the $100 row sorts above the $50 row regardless
    # of where the NaN/Infinity rows land (treated as 0).
    pos_100 = addrs1.index("0x" + "1" * 40)
    pos_50  = addrs1.index("0x" + "3" * 40)
    assert pos_100 < pos_50, (
        f"$100 row didn't sort above $50 row: order {addrs1}"
    )


# --------------------------------------------------------------- #
# TR-ADV-6: per-tx chain with non-string ``.value``
# --------------------------------------------------------------- #


def test_destinations_table_handles_non_string_chain_value() -> None:
    """Pre-fix: row_chain = t.chain.value when t.chain has a
    ``.value`` attribute. If a stub / fuzz layer feeds a chain
    object whose ``.value`` is None / an int, the ``str()``
    fallback never runs (the ``hasattr`` branch wins) and
    ``_explorer_url`` does a dict lookup with the non-string
    key, silently returning ``""``. Better: coerce to str at
    the build site, or fall back via a try block."""
    class WeirdChain:
        value = 1234  # non-string ``.value`` from a fuzz-shaped pipeline stub.

    b = "0x" + "b" * 40
    t = _mk_transfer(to_addr=b, suffix="11", usd=Decimal("500"))
    # Bypass Pydantic immutability: swap the chain post-validation.
    object.__setattr__(t, "chain", WeirdChain())
    case = _mk_case([t])

    # Must not raise; row_chain coerced to str before explorer lookup.
    rows = _build_destinations_table(case)
    assert len(rows) == 1
    # explorer_url falls back to "" for unknown chain string, not crash.
    assert isinstance(rows[0]["explorer_url"], str)


# --------------------------------------------------------------- #
# TR-ADV-7: end-to-end — render survives all poisoned inputs
# --------------------------------------------------------------- #


def test_render_trace_report_survives_nan_transfer(tmp_path: Path) -> None:
    """End-to-end: a single NaN-priced transfer must not nullify
    the entire trace_report deliverable. Pre-fix: the NaN sort
    crash propagates → caller logs a warning and returns None →
    no HTML file is written → operator's wallet-trace UI shows
    'no report' for this investigation. UNACCEPTABLE failure mode."""
    b = "0x" + "b" * 40
    c = "0x" + "c" * 40
    transfers = [
        _mk_transfer(to_addr=b, suffix="11", usd=Decimal("500")),
        _mk_transfer(to_addr=c, suffix="22", usd=Decimal("NaN")),
    ]
    case = _mk_case(transfers)
    out = render_trace_report(
        case=case,
        freeze_brief={},
        briefs_dir=tmp_path,
        flow_filename=None,
        investigation_id="tr-adv-e2e",
        label=None,
    )
    assert out is not None, "render_trace_report returned None on NaN input"
    assert out.exists()
    body = out.read_text(encoding="utf-8")
    # Sanity: the rendered HTML does not contain literal '$NaN'.
    assert "$NaN" not in body, "Literal '$NaN' leaked into rendered HTML"
