"""v0.35.6 (E5) — multi-regime sanctions ingest from OpenSanctions.

Pins the parser contract (only CryptoWallet + sanction topic + a real publicKey;
EVM lowercased; regime captured; dedup), the CSV round-trip, and the
risk_scoring integration (severity-4 `intl_sanctioned`, NOT `ofac_sanctioned`).
"""

from __future__ import annotations

from pathlib import Path

from recupero.labels.sanctions_intl import (
    import_opensanctions_file,
    load_intl_sanctions_csv,
    parse_opensanctions_crypto,
    write_intl_sanctions_csv,
)

_EVM = "0x" + "a" * 40


def _wallet(addr=_EVM, topics=("sanction",), currency="eth", program="EU FSF",
            schema="CryptoWallet", datasets=("eu_fsf",), caption="EU Sanctioned"):
    return {
        "schema": schema,
        "caption": caption,
        "datasets": list(datasets),
        "properties": {
            "publicKey": [addr] if addr else [],
            "currency": [currency],
            "topics": list(topics),
            "program": [program] if program else [],
        },
    }


def test_parse_basic_sanctioned_wallet():
    entries = parse_opensanctions_crypto([_wallet(addr="0x" + "AbCd" * 10)])
    assert len(entries) == 1
    e = entries[0]
    assert e.address == "0x" + "abcd" * 10        # EVM lowercased
    assert e.chain == "ethereum"
    assert e.regime == "EU FSF"
    assert "eu_fsf" in e.source_dataset


def test_parse_skips_non_sanction_topic():
    # A CryptoWallet flagged only "crime"/"role.pep" is NOT a sanction.
    assert parse_opensanctions_crypto([_wallet(topics=("crime",))]) == []


def test_parse_skips_non_cryptowallet_and_missing_address():
    assert parse_opensanctions_crypto([_wallet(schema="Person")]) == []
    assert parse_opensanctions_crypto([_wallet(addr="")]) == []


def test_parse_chain_from_currency_and_dedup():
    btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    recs = [
        _wallet(addr=btc, currency="btc"),
        _wallet(addr=btc, currency="btc"),  # dup → collapsed
    ]
    entries = parse_opensanctions_crypto(recs)
    assert len(entries) == 1
    assert entries[0].chain == "bitcoin"
    assert entries[0].address == btc           # non-EVM preserved verbatim


def test_csv_round_trip(tmp_path: Path):
    entries = parse_opensanctions_crypto([_wallet()])
    out = tmp_path / "intl.csv"
    write_intl_sanctions_csv(out, entries)
    loaded = load_intl_sanctions_csv(out)
    assert len(loaded) == 1
    assert loaded[0].address == _EVM and loaded[0].regime == "EU FSF"


def test_load_missing_csv_returns_empty(tmp_path: Path):
    assert load_intl_sanctions_csv(tmp_path / "nope.csv") == []


def test_import_file_ndjson(tmp_path: Path):
    import json
    src = tmp_path / "os.ndjson"
    src.write_text(
        json.dumps(_wallet()) + "\n" + json.dumps(_wallet(schema="Person")) + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "intl.csv"
    n = import_opensanctions_file(src, out)
    assert n == 1 and load_intl_sanctions_csv(out)[0].address == _EVM


def test_risk_scoring_picks_up_intl_sanctioned(tmp_path: Path):
    from recupero.trace.risk_scoring import load_high_risk_db
    addr = "0x" + "bd" * 20
    write_intl_sanctions_csv(
        tmp_path / "intl.csv",
        parse_opensanctions_crypto([_wallet(
            addr=addr, program="UK HMT/OFSI", datasets=("gb_hmt_sanctions",),
        )]),
    )
    db = load_high_risk_db(
        ofac_csv_path=tmp_path / "no_ofac.csv",       # isolate from live OFAC
        intl_sanctions_csv_path=tmp_path / "intl.csv",
    )
    assert addr in db
    entry = db[addr]
    assert entry.risk_category == "intl_sanctioned"   # NOT ofac_sanctioned
    assert entry.severity == 4
    assert "UK HMT/OFSI" in (entry.notes or "")
