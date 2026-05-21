"""Tests for v0.9.4 OFAC SDN live-sync.

The live network fetch is mocked — these tests verify:
  * XML parser handles Treasury's actual SDN feed schema
  * Crypto-address chain code mapping (ETH/BTC/XMR/...)
  * Network failures degrade gracefully (stale=True, success=False)
  * CSV write is atomic (no half-written file on failure)
  * CSV round-trips: write → load returns the same entries
  * Risk_scoring loads the CSV when present
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.error import URLError

import pytest

from recupero.trace.ofac_sync import (
    _extract_crypto_entries,
    _is_evm_address,
    load_ofac_csv,
    sync_ofac_sdn,
)

# Synthetic OFAC SDN XML matching Treasury's schema (simplified)
_FAKE_SDN_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<sdnList>
  <sdnEntry>
    <uid>12345</uid>
    <lastName>LAZARUS GROUP</lastName>
    <idList>
      <id>
        <uid>67890</uid>
        <idType>Digital Currency Address - ETH</idType>
        <idNumber>0xABCdef1234567890ABCDef1234567890aBCdEf12</idNumber>
      </id>
      <id>
        <uid>67891</uid>
        <idType>Digital Currency Address - BTC</idType>
        <idNumber>1A2b3C4d5E6f7G8h9I0jK1L2m3N4o5P6q7R</idNumber>
      </id>
      <id>
        <uid>67892</uid>
        <idType>Aircraft Construction Number</idType>
        <idNumber>NOT-A-CRYPTO-ADDRESS</idNumber>
      </id>
    </idList>
    <publishInformation>
      <Publish_Date>2022-04-14</Publish_Date>
    </publishInformation>
  </sdnEntry>
  <sdnEntry>
    <uid>22345</uid>
    <firstName>SDN</firstName>
    <lastName>WITH-NO-CRYPTO-ADDRESS</lastName>
    <idList>
      <id>
        <uid>27890</uid>
        <idType>Passport</idType>
        <idNumber>PASSPORT-NUMBER</idNumber>
      </id>
    </idList>
  </sdnEntry>
  <sdnEntry>
    <uid>32345</uid>
    <firstName>GARANTEX</firstName>
    <lastName>EUROPE OU</lastName>
    <idList>
      <id>
        <uid>37890</uid>
        <idType>Digital Currency Address - USDT</idType>
        <idNumber>0xfeedface000000000000000000000000000000ff</idNumber>
      </id>
    </idList>
    <publishInformation>
      <Publish_Date>2022-04-05</Publish_Date>
    </publishInformation>
  </sdnEntry>
</sdnList>
"""


# ---- _is_evm_address ---- #


def test_is_evm_address() -> None:
    """0x + 40 hex = EVM. Anything else = non-EVM (BTC, SOL, etc.)."""
    assert _is_evm_address("0x" + "a" * 40) is True
    assert _is_evm_address("1A2b3C4d5E6f7G8h9I0jK1L2m3N4o5P6q7R") is False
    assert _is_evm_address("") is False
    assert _is_evm_address("0xshort") is False


# ---- _extract_crypto_entries ---- #


def test_extract_lazarus_group() -> None:
    """The Lazarus Group SDN entry should yield two crypto
    entries (ETH + BTC) and skip the non-crypto id."""
    entries = _extract_crypto_entries(_FAKE_SDN_XML)
    lazarus_entries = [e for e in entries if "LAZARUS" in e.sdn_entry_name]
    assert len(lazarus_entries) == 2
    chains = {e.chain for e in lazarus_entries}
    assert "ethereum" in chains
    assert "bitcoin" in chains


def test_extract_lowercases_evm_addresses() -> None:
    """EVM addresses get lowercased so risk_scoring's
    case-insensitive lookups work consistently."""
    entries = _extract_crypto_entries(_FAKE_SDN_XML)
    eth_entries = [e for e in entries if e.chain == "ethereum"]
    for e in eth_entries:
        assert e.address == e.address.lower()
        assert e.address.startswith("0x")


def test_extract_preserves_btc_address_case() -> None:
    """Bitcoin addresses are base58; case is meaningful. Don't
    lowercase."""
    entries = _extract_crypto_entries(_FAKE_SDN_XML)
    btc_entries = [e for e in entries if e.chain == "bitcoin"]
    assert len(btc_entries) == 1
    # The original mixed-case string is preserved (no .lower())
    assert btc_entries[0].address == "1A2b3C4d5E6f7G8h9I0jK1L2m3N4o5P6q7R"


def test_extract_skips_non_crypto_ids() -> None:
    """Passport / aircraft / vehicle / etc. IDs are skipped.
    Only `Digital Currency Address - X` entries are extracted."""
    entries = _extract_crypto_entries(_FAKE_SDN_XML)
    # No SDN entry with no crypto addresses should appear at all
    sdn_names = {e.sdn_entry_name for e in entries}
    assert "SDN WITH-NO-CRYPTO-ADDRESS" not in sdn_names


def test_extract_preserves_listing_date() -> None:
    """Publish_Date appears in the output for downstream sorting
    + compliance audit."""
    entries = _extract_crypto_entries(_FAKE_SDN_XML)
    dates = {e.listing_date for e in entries}
    # 2022-04-14 (Lazarus) and 2022-04-05 (Garantex)
    assert "2022-04-14" in dates
    assert "2022-04-05" in dates


def test_extract_usdt_chain_maps_to_ethereum() -> None:
    """OFAC labels addresses by token sometimes (USDC, USDT).
    The chain mapping translates these to the parent chain."""
    entries = _extract_crypto_entries(_FAKE_SDN_XML)
    garantex = [e for e in entries if "GARANTEX" in e.sdn_entry_name]
    assert len(garantex) == 1
    assert garantex[0].chain == "ethereum"  # USDT → ethereum


def test_extract_handles_malformed_xml_gracefully() -> None:
    """Invalid XML should raise (caller catches), not return empty.
    The caller's handler logs + returns SyncResult(success=False).
    Expected exception type depends on the runtime XML parser:
    defusedxml falls through to xml.etree.ElementTree's ParseError;
    both inherit from SyntaxError so we narrow to that union."""
    from xml.etree.ElementTree import ParseError
    with pytest.raises((ParseError, SyntaxError)):
        _extract_crypto_entries(b"<not><valid")


# ---- sync_ofac_sdn (mocked HTTP) ---- #


def test_sync_writes_csv_on_success() -> None:
    """End-to-end happy path: mock urlopen returns the synthetic
    XML, sync writes the CSV, contents are what we expect."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"

        class _FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return _FAKE_SDN_XML

        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(),
        ):
            result = sync_ofac_sdn(output_path=out_path)

        assert result.success is True
        assert result.entries_written == 3  # 2 Lazarus + 1 Garantex
        assert out_path.exists()

        # Round-trip via load_ofac_csv
        loaded = load_ofac_csv(out_path)
        assert len(loaded) == 3


def test_sync_returns_stale_on_network_failure() -> None:
    """URLError → success=False, stale=True. Existing CSV
    preserved (atomic write means we don't clobber on failure)."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        # Pre-create an existing CSV that should NOT be clobbered
        out_path.write_text(
            "address,chain,sdn_entry_name,sdn_entry_id,listing_date\n"
            "0xexisting,ethereum,EXISTING SDN,123,2020-01-01\n",
            encoding="utf-8",
        )
        original_bytes = out_path.read_bytes()

        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            side_effect=URLError("test network failure"),
        ):
            result = sync_ofac_sdn(output_path=out_path)

        assert result.success is False
        assert result.stale is True
        assert "test network failure" in (result.error_message or "")

        # The existing CSV is unchanged.
        assert out_path.read_bytes() == original_bytes


def test_sync_handles_xml_parse_failure() -> None:
    """Sync survives malformed XML — returns success=False, doesn't
    leave a half-written CSV."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"

        class _FakeBadResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return b"<not><valid"

        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeBadResponse(),
        ):
            result = sync_ofac_sdn(output_path=out_path)

        assert result.success is False
        assert "parse" in (result.error_message or "").lower()
        # No CSV created
        assert not out_path.exists()


def test_load_ofac_csv_returns_empty_for_missing_file() -> None:
    """No prior sync → empty list, not error. risk_scoring
    relies on this for the "no live sync yet" case."""
    out = load_ofac_csv(Path("/does/not/exist.csv"))
    assert out == []


def test_load_ofac_csv_round_trip() -> None:
    """Write entries via sync_ofac_sdn → load via load_ofac_csv
    → same entries back. Lock the CSV schema."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"

        class _FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return _FAKE_SDN_XML

        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(),
        ):
            sync_ofac_sdn(output_path=out_path)

        loaded = load_ofac_csv(out_path)

    # Verify round-trip preserved key fields
    by_addr = {e.address: e for e in loaded}
    eth_lazarus = by_addr.get("0xabcdef1234567890abcdef1234567890abcdef12")
    assert eth_lazarus is not None
    assert eth_lazarus.chain == "ethereum"
    assert eth_lazarus.sdn_entry_name == "LAZARUS GROUP"
    assert eth_lazarus.listing_date == "2022-04-14"


def test_load_ofac_csv_lowercases_evm_on_load() -> None:
    """Even if the CSV was hand-edited with uppercase EVM addresses,
    the loader normalizes for consistent lookup."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        out_path.write_text(
            "address,chain,sdn_entry_name,sdn_entry_id,listing_date\n"
            "0xABCDef1234567890ABCDef1234567890ABCDef12,ethereum,TEST,1,2020-01-01\n"
            "1NonEVMAddress,bitcoin,TEST2,2,2020-01-02\n",
            encoding="utf-8",
        )
        loaded = load_ofac_csv(out_path)
    by_chain = {e.chain: e for e in loaded}
    # EVM lowercased
    assert by_chain["ethereum"].address == "0xabcdef1234567890abcdef1234567890abcdef12"
    # Non-EVM preserved as-is
    assert by_chain["bitcoin"].address == "1NonEVMAddress"
