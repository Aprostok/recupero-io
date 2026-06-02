"""v0.35.9 (B1/B2) — generic free-OSS attribution-feed harvest.

Pins the harvest contract: free feeds map onto the existing candidate→review
pipeline (never auto-promote), categories are normalized to the supported set,
unsupported categories + malformed rows are SKIPPED and counted (never
fabricated), and field/chain header synonyms are tolerated.
"""

from __future__ import annotations

import json
from pathlib import Path

from recupero.labels.attribution_feed import (
    import_attribution_file,
    parse_attribution_rows,
)

_EVM = "0x" + "ab" * 20


def test_parse_exchange_and_bridge_rows():
    rows = [
        {"address": _EVM, "chain": "ethereum", "category": "exchange", "name": "Binance"},
        {"address": "0x" + "cd" * 20, "chain": "ethereum", "category": "bridge", "name": "Hop"},
    ]
    cands, skipped = parse_attribution_rows(rows)
    assert skipped == {}
    cats = sorted(c.proposed_category for c in cands)
    assert cats == ["bridge", "exchange_hot_wallet"]
    assert all(c.proposed_confidence == "low" for c in cands)   # never auto-high


def test_category_synonyms_normalized():
    rows = [
        {"address": _EVM, "category": "cex", "chain": "eth"},
        {"address": "0x" + "11" * 20, "category": "deposit", "chain": "eth"},
        {"address": "0x" + "22" * 20, "category": "cross-chain", "chain": "eth"},
    ]
    cands, skipped = parse_attribution_rows(rows)
    assert skipped == {}
    assert {c.proposed_category for c in cands} == {
        "exchange_hot_wallet", "exchange_deposit", "bridge",
    }


def test_unsupported_category_skipped_not_fabricated():
    # mixer/sanctioned have their own promotion paths — a bulk attribution
    # import must NOT write them; they are reported as skipped.
    rows = [
        {"address": _EVM, "category": "mixer", "chain": "ethereum"},
        {"address": "0x" + "33" * 20, "category": "sanctioned", "chain": "ethereum"},
    ]
    cands, skipped = parse_attribution_rows(rows)
    assert cands == []
    assert skipped.get("unsupported_category:mixer") == 1
    assert skipped.get("unsupported_category:sanctioned") == 1


def test_missing_address_skipped():
    cands, skipped = parse_attribution_rows([{"category": "exchange", "chain": "eth"}])
    assert cands == []
    assert skipped.get("missing_address") == 1


def test_chain_inference_and_synonyms():
    rows = [
        {"address": _EVM, "category": "exchange"},                       # no chain → eth (EVM-shaped)
        {"address": "0x" + "44" * 20, "category": "bridge", "chain": "arb"},  # synonym
        {"address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "category": "exchange"},  # non-EVM, no chain
    ]
    cands, skipped = parse_attribution_rows(rows)
    by_addr = {c.address: c.chain for c in cands}
    assert by_addr[_EVM] == "ethereum"
    assert by_addr["0x" + "44" * 20] == "arbitrum"
    assert skipped.get("missing_chain") == 1   # the BTC-looking row, no chain hint


def test_field_aliases_tolerated():
    # A feed using wallet/type/entity headers instead of address/category/name.
    rows = [{"wallet": _EVM, "type": "hot wallet", "entity": "Kraken", "network": "ethereum"}]
    cands, skipped = parse_attribution_rows(rows)
    assert skipped == {}
    assert len(cands) == 1
    assert cands[0].proposed_category == "exchange_hot_wallet"
    assert cands[0].proposed_name == "Kraken"


def test_source_sanitized_to_identifier():
    rows = [{"address": _EVM, "category": "exchange", "chain": "eth",
             "source": "Some Feed; rm -rf /"}]
    cands, _ = parse_attribution_rows(rows)
    assert len(cands) == 1
    # No spaces, quotes, or shell metachars survive into the source id.
    assert " " not in cands[0].source
    assert ";" not in cands[0].source
    assert cands[0].source  # non-empty


def test_import_csv_file_local_noop(tmp_path: Path):
    src = tmp_path / "feed.csv"
    src.write_text(
        "address,chain,category,name\n"
        f"{_EVM},ethereum,exchange,Binance\n"
        f"0x{'cd' * 20},ethereum,bridge,Hop\n"
        f"0x{'ef' * 20},ethereum,mixer,TornadoLike\n",   # unsupported → skipped
        encoding="utf-8",
    )
    # dsn="" forces the local-dev no-op in persist_candidates (no DB write).
    result = import_attribution_file(src, dsn="")
    assert result.parsed == 2
    assert result.skipped == 1
    assert result.persisted == 0
    assert any(k.startswith("unsupported_category:mixer") for k in result.skipped_reasons)


def test_import_ndjson_file_local_noop(tmp_path: Path):
    src = tmp_path / "feed.ndjson"
    src.write_text(
        json.dumps({"address": _EVM, "chain": "eth", "category": "cex", "name": "OKX"}) + "\n"
        + json.dumps({"address": "0x" + "12" * 20, "category": "deposit", "chain": "eth"}) + "\n",
        encoding="utf-8",
    )
    result = import_attribution_file(src, dsn="")
    assert result.parsed == 2
    assert result.skipped == 0
