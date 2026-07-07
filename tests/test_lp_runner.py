"""Roadmap-v4 Tier-2 #7 (slice 1): Uniswap V3 LP park-and-withdraw leads.

Fixtures are REAL mainnet logs captured live (2026-06) from the verified
NonfungiblePositionManager — tx 0x997f9235… emits DecreaseLiquidity + Collect
for the same tokenId 0xe3fa0 with the recipient in Collect data word 0.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from recupero.trace.lp_runner import (
    NPM_COLLECT_TOPIC0,
    NPM_INCREASE_LIQUIDITY_TOPIC0,
    UNISWAP_V3_NPM_BY_CHAIN,
    collect_exits_from_logs,
    find_lp_parks,
    leads_to_json,
    lp_leads_enabled,
    position_ids_from_receipt_logs,
    run_lp_leads,
)

_NPM = UNISWAP_V3_NPM_BY_CHAIN["ethereum"]
_PARKER = "0x" + "aa" * 20
_OTHER = "0x" + "bb" * 20

# REAL Collect log (live-captured 2026-06): tokenId 0xe3fa0 (=933792),
# recipient 0xba7a03a37c0799a4182d1c4ca3bf3321f8ba3329 in data word 0.
_REAL_COLLECT_LOG = {
    "address": _NPM,
    "topics": [
        NPM_COLLECT_TOPIC0,
        "0x00000000000000000000000000000000000000000000000000000000000e3fa0",
    ],
    "data": (
        "0x000000000000000000000000ba7a03a37c0799a4182d1c4ca3bf3321f8ba3329"
        "0000000000000000000000000000000000000000000000000000000054b614f7"
        "000000000000000000000000000000000000000000000000000000005289df3a"
    ),
    "transactionHash":
        "0x997f923537a1d4139aad4ddf38bd8875c8ab11f3d8969c8e9bf94da129d0d59b",
    "blockNumber": "0x152a4e1",
}

# REAL IncreaseLiquidity log shape (live-captured): tokenId = topic 1.
def _increase_log(token_id_hex: str) -> dict[str, Any]:
    return {
        "address": _NPM,
        "topics": [NPM_INCREASE_LIQUIDITY_TOPIC0, token_id_hex],
        "data": "0x" + "00" * 96,
    }


def _transfer(to, frm=_PARKER, tx="0xpark"):
    return SimpleNamespace(
        from_address=frm, to_address=to, chain="ethereum", tx_hash=tx,
    )


class _StubAdapter:
    def __init__(self, *, receipt_logs, collect_logs):
        self.receipt_logs = receipt_logs
        self.collect_logs = collect_logs
        self.fetch_logs_calls: list[dict[str, Any]] = []

    def fetch_evidence_receipt(self, tx_hash):
        return SimpleNamespace(
            block_number=22_000_000,
            raw_receipt={"logs": self.receipt_logs},
        )

    def fetch_logs(self, address, topic0, *, from_block, to_block, topics=None):
        self.fetch_logs_calls.append({
            "address": address, "topic0": topic0, "topics": topics,
            "from_block": from_block,
        })
        return self.collect_logs


def test_gate_default_off(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_LP_LEADS", raising=False)
    assert lp_leads_enabled() is False
    assert run_lp_leads(
        transfers=[_transfer(_NPM)], adapter=None,
    ) == []  # adapter never touched when gated off
    monkeypatch.setenv("RECUPERO_LP_LEADS", "on")
    assert lp_leads_enabled() is True


def test_find_lp_parks_only_npm_destinations() -> None:
    transfers = [
        _transfer(_NPM, tx="0x1"),
        _transfer(_OTHER, tx="0x2"),          # not the NPM
        _transfer(_NPM, tx="0x1"),            # duplicate (parker, tx)
    ]
    parks = find_lp_parks(transfers)
    assert len(parks) == 1
    assert parks[0]["parker"] == _PARKER
    assert parks[0]["npm"] == _NPM


def test_position_ids_require_npm_emitter() -> None:
    tid = "0x00000000000000000000000000000000000000000000000000000000000e3fa0"
    logs = [
        _increase_log(tid),
        {**_increase_log(tid), "address": _OTHER},  # spoofed emitter — ignored
    ]
    assert position_ids_from_receipt_logs(logs, npm=_NPM) == [0xE3FA0]


def test_collect_exit_parses_real_log() -> None:
    exits = collect_exits_from_logs([_REAL_COLLECT_LOG])
    assert len(exits) == 1
    ex = exits[0]
    assert ex["token_id"] == 0xE3FA0
    assert ex["recipient"] == "0xba7a03a37c0799a4182d1c4ca3bf3321f8ba3329"
    assert ex["amount0_raw"] == str(0x54B614F7)
    assert ex["amount1_raw"] == str(0x5289DF3A)


def test_collect_rejects_non_address_word() -> None:
    bad = dict(_REAL_COLLECT_LOG)
    # First data word has non-zero top bytes → not an address-shaped word.
    bad["data"] = "0x" + "ff" * 32 + _REAL_COLLECT_LOG["data"][66:]
    assert collect_exits_from_logs([bad]) == []


def test_run_lp_leads_end_to_end_different_recipient_is_medium() -> None:
    tid_hex = "0x00000000000000000000000000000000000000000000000000000000000e3fa0"
    adapter = _StubAdapter(
        receipt_logs=[_increase_log(tid_hex)],
        collect_logs=[_REAL_COLLECT_LOG],
    )
    leads = run_lp_leads(
        transfers=[_transfer(_NPM)], adapter=adapter, force=True,
    )
    assert len(leads) == 1
    ld = leads[0]
    assert ld["position_token_id"] == str(0xE3FA0)
    assert ld["exit_recipient"] == "0xba7a03a37c0799a4182d1c4ca3bf3321f8ba3329"
    assert ld["recipient_is_parker"] is False
    assert ld["position_link_confidence"] == "high"     # tokenId match = protocol identity
    assert ld["actor_attribution_confidence"] == "medium"
    # the Collect query was filtered by the position's tokenId topic
    assert adapter.fetch_logs_calls[0]["topics"] == [tid_hex]
    assert adapter.fetch_logs_calls[0]["from_block"] == 22_000_000


def test_run_lp_leads_same_owner_is_high() -> None:
    tid_hex = "0x" + format(7, "064x")
    collect = dict(_REAL_COLLECT_LOG)
    collect["topics"] = [NPM_COLLECT_TOPIC0, tid_hex]
    # recipient word = the parker
    collect["data"] = ("0x" + "0" * 24 + _PARKER[2:]
                       + _REAL_COLLECT_LOG["data"][66:])
    adapter = _StubAdapter(
        receipt_logs=[_increase_log(tid_hex)], collect_logs=[collect],
    )
    leads = run_lp_leads(
        transfers=[_transfer(_NPM)], adapter=adapter, force=True,
    )
    assert len(leads) == 1
    assert leads[0]["recipient_is_parker"] is True
    assert leads[0]["actor_attribution_confidence"] == "high"


def test_collect_recipient_uppercase_hex_is_normalized() -> None:
    # Adversarial-review HIGH: a provider returning checksum/uppercase hex in
    # the Collect recipient data word must not break the same-owner comparison.
    upper = dict(_REAL_COLLECT_LOG)
    upper["data"] = (
        "0x000000000000000000000000BA7A03A37C0799A4182D1C4CA3BF3321F8BA3329"
        + _REAL_COLLECT_LOG["data"][66:]
    )
    exits = collect_exits_from_logs([upper])
    assert len(exits) == 1
    assert exits[0]["recipient"] == "0xba7a03a37c0799a4182d1c4ca3bf3321f8ba3329"


def test_uppercase_recipient_same_owner_still_high() -> None:
    # End-to-end: an uppercase-hex recipient that IS the parker still yields a
    # high same-owner round-trip (not a silent medium downgrade).
    tid_hex = "0x" + format(7, "064x")
    collect = dict(_REAL_COLLECT_LOG)
    collect["topics"] = [NPM_COLLECT_TOPIC0, tid_hex]
    collect["data"] = ("0x" + "0" * 24 + _PARKER[2:].upper()
                       + _REAL_COLLECT_LOG["data"][66:])
    adapter = _StubAdapter(
        receipt_logs=[_increase_log(tid_hex)], collect_logs=[collect],
    )
    leads = run_lp_leads(transfers=[_transfer(_NPM)], adapter=adapter, force=True)
    assert len(leads) == 1
    assert leads[0]["recipient_is_parker"] is True
    assert leads[0]["actor_attribution_confidence"] == "high"


def test_leads_to_json_artifact_shape() -> None:
    doc = leads_to_json([{"x": 1}])
    assert doc["kind"] == "recupero_lp_leads"
    assert doc["lead_count"] == 1
    assert "never a followed destination" in doc["disclaimer"]
    assert "protocol identity" in doc["disclaimer"]


def test_lp_park_cap_warns_when_reached(caplog) -> None:
    """No silent caps: reaching the park cap stops querying further LP
    positions — must WARN, not INFO."""
    import logging
    transfers = [_transfer(_NPM, tx=f"0x{i}") for i in range(30)]  # > _MAX_PARKS
    with caplog.at_level(logging.WARNING):
        parks = find_lp_parks(transfers)
    assert len(parks) == 25  # _MAX_PARKS
    assert "park cap" in caplog.text


def test_lp_park_cap_no_warn_under_limit(caplog) -> None:
    import logging
    transfers = [_transfer(_NPM, tx=f"0x{i}") for i in range(5)]
    with caplog.at_level(logging.WARNING):
        parks = find_lp_parks(transfers)
    assert len(parks) == 5
    assert "park cap" not in caplog.text
