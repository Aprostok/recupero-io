"""RIGOR-Jacob Z6: adversarial-input hunt for src/recupero/trace/*.

Bugs covered:

  * Z6-1 (HIGH): ``cross_chain.ingest_bridge_seeds`` crashes with
    ``AttributeError: 'int' object has no attribute 'lower'`` when a
    bridges.json entry has a non-string ``chain`` field. Because the
    crash propagates out of the per-entry loop, the entire bridge DB
    fails to load → every CROSS_CHAIN_HANDOFFS section degrades to
    empty silently (the outer ``try`` in the loader catches at the
    json.loads layer, but a non-string ``chain`` triggers the
    AttributeError *inside* the loop body, which is wrapped only by
    the file-load try). Worse: today the ``ingest_bridge_seeds(path)``
    helper used by tests + ad-hoc workflows raises directly,
    propagating into ``identify_cross_chain_handoffs``'s callers.

  * Z6-2 (HIGH): ``clustering.cluster_addresses`` crashes with
    ``decimal.InvalidOperation`` when ``address_balances`` contains
    a ``Decimal('NaN')`` for any address that ends up in a cluster.
    Concrete trigger: upstream ``_parse_usd_string('$NaN')`` returns
    ``Decimal('NaN')`` (the parser strips ``$`` + commas and feeds
    the rest to ``Decimal(…)``). The emit_brief caller wraps the call
    in try/except BLE001 but the failure silently drops the entire
    ENTITY_CLUSTERS section. Two-or-more clusters with one NaN
    balance trigger the crash at the ``clusters.sort`` step.

  * Z6-3 (MEDIUM): ``risk_scoring.load_high_risk_db`` aborts loading
    the *entire* mixers.json seed when a single malformed entry has a
    non-string ``notes`` field. The line ``notes.lower()`` raises
    AttributeError, which is caught by the outer try/except — but
    that try wraps the whole for-loop, so every subsequent (valid)
    mixer entry, including curated Tornado Cash / Sinbad rows,
    silently disappears from the risk DB. This degrades OFAC
    coverage to zero on the mixers side from a single bad row.

Each test is a RED-first contract: it fails on the current (unfixed)
code, then passes after the in-place hardening.
"""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.trace.clustering import cluster_addresses
from recupero.trace.cross_chain import ingest_bridge_seeds
from recupero.trace.risk_scoring import load_high_risk_db


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    block_time: datetime,
    suffix: str,
    usd: Decimal = Decimal("500"),
) -> Transfer:
    tx_hash = "0x" + (suffix * 16)[:64]
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:1",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=1,
        block_time=block_time,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(
            chain=Chain.ethereum,
            contract="0x" + "c" * 40,
            symbol="USDC",
            decimals=6,
            coingecko_id="usd-coin",
        ),
        amount_raw="1000",
        amount_decimal=Decimal("1"),
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=block_time,
    )


def _mk_case(transfers: list[Transfer], seed: str = "0x" + "a" * 40) -> Case:
    return Case(
        case_id="x",
        seed_address=seed,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="t",
        config_used={},
    )


# ─────────────────────────────────────────────────────────────────
# Z6-1: cross_chain.ingest_bridge_seeds non-string chain field
# ─────────────────────────────────────────────────────────────────


def test_ingest_bridge_seeds_skips_non_string_chain_field() -> None:
    """RIGOR-Jacob Z6-1: an attacker (or schema-drift author) who puts
    a non-string ``chain`` field on a bridges.json entry must not be
    able to crash the bridge-seed loader. The malformed row should be
    skipped; subsequent valid rows must still load.

    Pre-fix: ``(entry.get("chain") or "ethereum").lower()`` raises
    ``AttributeError: 'int' object has no attribute 'lower'`` and
    bombs out of the ``for entry in entries`` loop. The whole bridge
    DB returns {} → every cross-chain handoff silently disappears
    from the brief.
    """
    payload = [
        # malformed: chain is an int (e.g., JSON schema drift)
        {"address": "0x" + "a" * 40, "chain": 1, "name": "BadBridge"},
        # malformed: chain is a list
        {"address": "0x" + "b" * 40, "chain": ["ethereum"], "name": "AlsoBad"},
        # malformed: chain is a dict
        {"address": "0x" + "c" * 40, "chain": {"v": "ethereum"}, "name": "ObjBad"},
        # well-formed: should still load
        {
            "address": "0x" + "d" * 40,
            "chain": "ethereum",
            "name": "Wormhole: Token Bridge",
            "protocol": "Wormhole",
            "confidence": "high",
        },
    ]
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "bridges.json"
        p.write_text(json.dumps(payload))
        out = ingest_bridge_seeds(p)

    # The good row must still load.
    assert (Chain.ethereum, "0x" + "d" * 40) in out
    assert out[(Chain.ethereum, "0x" + "d" * 40)].name == "Wormhole: Token Bridge"
    # The malformed rows must not appear.
    assert (Chain.ethereum, "0x" + "a" * 40) not in out
    assert (Chain.ethereum, "0x" + "b" * 40) not in out
    assert (Chain.ethereum, "0x" + "c" * 40) not in out


# ─────────────────────────────────────────────────────────────────
# Z6-2: clustering.cluster_addresses NaN balance crashes sort
# ─────────────────────────────────────────────────────────────────


def test_cluster_addresses_survives_nan_in_address_balances() -> None:
    """RIGOR-Jacob Z6-2: when ``address_balances`` contains a NaN
    Decimal (concrete upstream trigger: ``_parse_usd_string('$NaN')``
    in emit_brief's ``_build_entity_clusters_section`` consumes
    ``freezable[].holdings[].usd`` which can be the literal string
    "$NaN" if upstream sections poisoned the brief), the clustering
    pass must not crash.

    Pre-fix: with ≥2 clusters and any NaN ``total_balance_usd``,
    ``clusters.sort(key=lambda c: c.total_balance_usd, …)`` raises
    ``decimal.InvalidOperation`` mid-sort. The emit_brief caller
    swallows it with BLE001 → the entire ENTITY_CLUSTERS section
    becomes ``{"clusters": [], "unclustered_addresses": []}`` —
    silently losing forensically critical perpetrator clustering.
    """
    seed = "0x" + "a" * 40
    # Two independent clusters: (b,c) funded by src1 and (d,e) funded by src2.
    b = "0x" + "b" * 40
    c = "0x" + "c" * 40
    d = "0x" + "d" * 40
    e = "0x" + "e" * 40
    src1 = "0x" + "1" * 40
    src2 = "0x" + "2" * 40
    when = datetime(2026, 1, 1, tzinfo=UTC)
    transfers = [
        _mk_transfer(from_addr=src1, to_addr=b, block_time=when, suffix="11"),
        _mk_transfer(from_addr=src1, to_addr=c, block_time=when, suffix="22"),
        _mk_transfer(from_addr=src2, to_addr=d, block_time=when, suffix="33"),
        _mk_transfer(from_addr=src2, to_addr=e, block_time=when, suffix="44"),
    ]
    case = _mk_case(transfers, seed=seed)

    # One NaN balance poisons one cluster; the other cluster is fine.
    balances = {
        b: Decimal("NaN"),
        c: Decimal("100"),
        d: Decimal("500"),
        e: Decimal("300"),
    }

    # Must not raise.
    clusters, unclustered = cluster_addresses(case, balances)

    # Both clusters must be produced (NaN gets sanitized → 0).
    assert len(clusters) == 2, (
        "Both common-funding clusters should survive NaN address_balances."
    )
    # No cluster should retain a NaN balance — it must be sanitized
    # (otherwise downstream brief formatting emits literal '$NaN').
    for cl in clusters:
        assert cl.total_balance_usd.is_finite(), (
            f"cluster {cl.cluster_id} carries non-finite balance "
            f"{cl.total_balance_usd!r} — would render '$NaN' in brief"
        )


def test_cluster_addresses_survives_infinity_in_address_balances() -> None:
    """RIGOR-Jacob Z6-2 (companion): Decimal('Infinity') in a balance
    must not poison the sort either. Different InvalidOperation /
    sort-comparison surface than NaN but same root cause."""
    seed = "0x" + "a" * 40
    b = "0x" + "b" * 40
    c = "0x" + "c" * 40
    d = "0x" + "d" * 40
    e = "0x" + "e" * 40
    src1 = "0x" + "1" * 40
    src2 = "0x" + "2" * 40
    when = datetime(2026, 1, 1, tzinfo=UTC)
    transfers = [
        _mk_transfer(from_addr=src1, to_addr=b, block_time=when, suffix="11"),
        _mk_transfer(from_addr=src1, to_addr=c, block_time=when, suffix="22"),
        _mk_transfer(from_addr=src2, to_addr=d, block_time=when, suffix="33"),
        _mk_transfer(from_addr=src2, to_addr=e, block_time=when, suffix="44"),
    ]
    case = _mk_case(transfers, seed=seed)

    balances = {
        b: Decimal("Infinity"),
        c: Decimal("100"),
        d: Decimal("500"),
        e: Decimal("300"),
    }
    clusters, _ = cluster_addresses(case, balances)
    assert len(clusters) == 2
    for cl in clusters:
        assert cl.total_balance_usd.is_finite(), (
            f"cluster {cl.cluster_id} balance {cl.total_balance_usd!r} "
            "must be sanitized to a finite Decimal"
        )


# ─────────────────────────────────────────────────────────────────
# Z6-3: risk_scoring.load_high_risk_db non-string notes aborts mixers
# ─────────────────────────────────────────────────────────────────


def test_load_high_risk_db_continues_past_malformed_mixer_entry() -> None:
    """RIGOR-Jacob Z6-3: a single malformed mixers.json entry with
    a non-string ``notes`` field (e.g., a list — schema drift, or an
    operator who pasted YAML-ish data into the JSON) must not abort
    loading of every subsequent entry.

    Pre-fix: line ``"ofac" in notes.lower()`` raises AttributeError
    when ``notes`` is a list. The outer try wraps the ENTIRE for-loop,
    so on the first malformed row, every subsequent (valid) Tornado
    Cash / Sinbad / Railgun row silently drops out of the risk DB.

    This is forensically critical: a single accidental edit downstream
    would silently disable mixer screening, and the user-visible
    symptom is only "RISK_ASSESSMENT shows no exposures" — easy to
    miss in an audit.
    """
    mixers_payload = [
        # Malformed: notes is a list (schema drift / human error).
        {
            "address": "0x" + "a" * 40,
            "name": "MalformedMixerA",
            "notes": ["this", "should", "be", "a", "string"],
        },
        # Valid: Tornado-Cash-shape entry with OFAC mention in notes.
        # Pre-fix: never loaded because earlier row aborted the loop.
        {
            "address": "0x" + "b" * 40,
            "name": "TornadoCashShape",
            "notes": "OFAC-sanctioned mixer",
        },
        # Valid: non-OFAC mixer.
        {
            "address": "0x" + "c" * 40,
            "name": "GenericMixerShape",
            "notes": "high-volume coinjoin",
        },
    ]
    with tempfile.TemporaryDirectory() as td:
        hr = Path(td) / "hr.json"
        hr.write_text(json.dumps({"addresses": []}))
        mx = Path(td) / "mx.json"
        mx.write_text(json.dumps(mixers_payload))
        rw = Path(td) / "rw.json"
        rw.write_text(json.dumps({"addresses": []}))
        db = load_high_risk_db(hr, mx, rw)

    # The malformed row must be skipped, but the two valid rows
    # after it must still load.
    assert "0x" + "b" * 40 in db, (
        "Tornado-shape mixer entry was silently dropped because an "
        "earlier malformed row aborted the loop."
    )
    assert "0x" + "c" * 40 in db, (
        "Generic mixer entry was silently dropped — same root cause."
    )
    # Sanity: the OFAC-noted entry is promoted correctly.
    assert db["0x" + "b" * 40].severity == 4
    assert db["0x" + "b" * 40].risk_category == "mixer_sanctioned"
    # The malformed row: notes coerced to None (since not-a-string),
    # so it loads as mixer_high_risk (severity 3) — the conservative
    # choice. The key forensic property is that it didn't kill the
    # loader's continuation. We assert the row is either skipped or
    # loaded with notes sanitized to non-string-noise.
    bad = db.get("0x" + "a" * 40)
    if bad is not None:
        assert bad.notes is None or isinstance(bad.notes, str), (
            "Malformed mixer entry leaked non-string notes into DB."
        )


def test_load_high_risk_db_continues_past_malformed_high_risk_entry() -> None:
    """RIGOR-Jacob Z6-3 (companion): same shape for the high_risk.json
    loader — a single malformed entry (e.g., entry.get("address")
    returns the empty string after canonicalization) inside an
    otherwise-good seed file must not abort loading of subsequent
    curated Lazarus / Garantex rows.

    The high_risk.json block already isinstance-checks ``addr`` and
    ``severity`` is try/except'd around int(), but the HighRiskEntry
    construction at the end of the loop calls _canonical_address_key
    which returns "" on garbage. We must not crash on weird inputs;
    we must move on.
    """
    hr_payload = {
        "addresses": [
            # Garbage address — canonicalization returns "".
            {"address": "garbage-not-an-address", "name": "Junk",
             "risk_category": "ofac_sanctioned", "severity": 4},
            # Valid Lazarus-shape entry.
            {
                "address": "0x" + "1" * 40,
                "name": "Lazarus Group (DPRK)",
                "risk_category": "ofac_sanctioned",
                "severity": 4,
                "notes": "Treasury / OFAC SDN",
            },
        ]
    }
    with tempfile.TemporaryDirectory() as td:
        hr = Path(td) / "hr.json"
        hr.write_text(json.dumps(hr_payload))
        mx = Path(td) / "mx.json"
        mx.write_text("[]")
        rw = Path(td) / "rw.json"
        rw.write_text(json.dumps({"addresses": []}))
        db = load_high_risk_db(hr, mx, rw)

    assert "0x" + "1" * 40 in db, (
        "Curated Lazarus row was lost because a junk address upstream "
        "aborted the loader."
    )
