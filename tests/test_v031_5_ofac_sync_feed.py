"""v0.31.5 — OFAC sync plumbed to the live Treasury feed.

Closes the `docs/V031_3_HONEST_GAPS.md` §5c gap: "OFAC sync has no
scheduled refresh ... whatever freshness OFAC has is whatever was
last manually run." The v0.31.4 cron scheduler runs the sync daily;
this version ensures the sync itself:

  * Points at the canonical Treasury source (sdn.xml)
  * Writes a `last_synced_utc` freshness sidecar
  * Is idempotent on identical input (byte-stable CSV)
  * Fails loud in `strict=True` mode (cron path) instead of silently
    "returning success=False" which a cron with `except Exception:
    log.warning` would just log and continue with stale data
  * Tracks `removed_at_utc` for entries that disappear from the feed
    rather than silently dropping them
  * Preserves the RIGOR-2a XXE/billion-laughs hardening

Tests are 100% offline — `urllib.request.urlopen` is patched so no
network call ever leaves this process.
"""

from __future__ import annotations

import csv
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.error import URLError

import pytest

from recupero.trace.ofac_sync import (
    OFAC_SDN_XML_URL,
    OFACSyncError,
    _extract_crypto_entries,
    _meta_path_for,
    load_ofac_csv,
    read_ofac_meta,
    sync_ofac_sdn,
)

# ─────────────────────────────────────────────────────────────────────────────
# Test fixtures
# ─────────────────────────────────────────────────────────────────────────────


# 5 SDN entries: 3 with digitalCurrencyAddress, 2 without.
# Hand-built to match Treasury's actual SDN feed schema.
_FIXTURE_FIVE_ENTRIES = b"""<?xml version="1.0" encoding="UTF-8"?>
<sdnList>
  <sdnEntry>
    <uid>11111</uid>
    <lastName>LAZARUS GROUP</lastName>
    <idList>
      <id>
        <uid>11112</uid>
        <idType>Digital Currency Address - ETH</idType>
        <idNumber>0xAAAAaaaaaaAAAAaaaaAAAAaaaaaaAAAAaaaa1111</idNumber>
      </id>
    </idList>
    <publishInformation>
      <Publish_Date>2022-04-14</Publish_Date>
    </publishInformation>
  </sdnEntry>
  <sdnEntry>
    <uid>22222</uid>
    <firstName>GARANTEX</firstName>
    <lastName>EUROPE OU</lastName>
    <idList>
      <id>
        <uid>22223</uid>
        <idType>Digital Currency Address - USDT</idType>
        <idNumber>0xBBBBbbbbbbBBBBbbbbBBBBbbbbbbBBBBbbbb2222</idNumber>
      </id>
    </idList>
    <publishInformation>
      <Publish_Date>2022-04-05</Publish_Date>
    </publishInformation>
  </sdnEntry>
  <sdnEntry>
    <uid>33333</uid>
    <lastName>HYDRA MARKET</lastName>
    <idList>
      <id>
        <uid>33334</uid>
        <idType>Digital Currency Address - BTC</idType>
        <idNumber>1HydraMarketAddress0000000000000000</idNumber>
      </id>
    </idList>
    <publishInformation>
      <Publish_Date>2022-04-05</Publish_Date>
    </publishInformation>
  </sdnEntry>
  <sdnEntry>
    <uid>44444</uid>
    <firstName>SOMEONE</firstName>
    <lastName>WITHOUT-CRYPTO</lastName>
    <idList>
      <id>
        <uid>44445</uid>
        <idType>Passport</idType>
        <idNumber>P1234567</idNumber>
      </id>
    </idList>
  </sdnEntry>
  <sdnEntry>
    <uid>55555</uid>
    <lastName>VESSEL-ENTITY-NO-CRYPTO</lastName>
    <idList>
      <id>
        <uid>55556</uid>
        <idType>Vessel Registration Identification</idType>
        <idNumber>IMO9876543</idNumber>
      </id>
    </idList>
  </sdnEntry>
</sdnList>
"""

# Same data minus one entry — used to test removed_at_utc.
_FIXTURE_AFTER_REMOVAL = b"""<?xml version="1.0" encoding="UTF-8"?>
<sdnList>
  <sdnEntry>
    <uid>11111</uid>
    <lastName>LAZARUS GROUP</lastName>
    <idList>
      <id>
        <uid>11112</uid>
        <idType>Digital Currency Address - ETH</idType>
        <idNumber>0xAAAAaaaaaaAAAAaaaaAAAAaaaaaaAAAAaaaa1111</idNumber>
      </id>
    </idList>
    <publishInformation>
      <Publish_Date>2022-04-14</Publish_Date>
    </publishInformation>
  </sdnEntry>
  <sdnEntry>
    <uid>33333</uid>
    <lastName>HYDRA MARKET</lastName>
    <idList>
      <id>
        <uid>33334</uid>
        <idType>Digital Currency Address - BTC</idType>
        <idNumber>1HydraMarketAddress0000000000000000</idNumber>
      </id>
    </idList>
    <publishInformation>
      <Publish_Date>2022-04-05</Publish_Date>
    </publishInformation>
  </sdnEntry>
</sdnList>
"""


class _FakeResponse:
    """In-process stand-in for `urllib.response.addinfourl`. We never
    let a real urlopen escape these tests (the OFAC endpoint is a
    public Treasury service — accidentally hitting it would be
    flaky/slow and would also violate the project's no-network-in-
    tests rule)."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n: int | None = None):
        if n is None:
            return self._payload
        return self._payload[: n]


# ─────────────────────────────────────────────────────────────────────────────
# 1. Canonical Treasury URL still wired
# ─────────────────────────────────────────────────────────────────────────────


def test_default_url_points_at_canonical_treasury_source() -> None:
    """Regression guard: a future edit must not silently swap the URL
    to a third-party mirror. OFAC compliance reviews against the
    Treasury-published feed; using a mirror breaks the chain of
    custody."""
    assert OFAC_SDN_XML_URL.startswith("https://www.treasury.gov/")
    assert "sdn.xml" in OFAC_SDN_XML_URL


# ─────────────────────────────────────────────────────────────────────────────
# 2. Fixture parses correctly: 5 SDN entries → 3 high-risk crypto entries
# ─────────────────────────────────────────────────────────────────────────────


def test_fixture_extracts_three_crypto_entries() -> None:
    """5 SDN entries (3 with digitalCurrencyAddress, 2 without) →
    3 OFACCryptoEntry rows. The non-crypto entries (Passport, Vessel)
    must be skipped entirely."""
    entries = _extract_crypto_entries(_FIXTURE_FIVE_ENTRIES)
    assert len(entries) == 3
    sdn_names = {e.sdn_entry_name for e in entries}
    assert "LAZARUS GROUP" in sdn_names
    assert "HYDRA MARKET" in sdn_names
    assert "GARANTEX EUROPE OU" in sdn_names
    # Non-crypto SDN entries must not appear.
    assert "SOMEONE WITHOUT-CRYPTO" not in sdn_names
    assert "VESSEL-ENTITY-NO-CRYPTO" not in sdn_names


# ─────────────────────────────────────────────────────────────────────────────
# 3. Idempotency — two syncs with identical upstream data → byte-identical CSV
# ─────────────────────────────────────────────────────────────────────────────


def test_sync_is_byte_idempotent_on_identical_input() -> None:
    """Running the sync twice over the same upstream XML MUST produce
    byte-identical CSV output. A diff-on-cron-output monitoring strategy
    relies on this — otherwise it floods with phantom churn.
    Likewise removed_at_utc timestamps must NOT bump on re-sync over
    the same data."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"

        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(_FIXTURE_FIVE_ENTRIES),
        ):
            r1 = sync_ofac_sdn(output_path=out_path)
            first_bytes = out_path.read_bytes()
            r2 = sync_ofac_sdn(output_path=out_path)
            second_bytes = out_path.read_bytes()

        assert r1.success and r2.success
        assert first_bytes == second_bytes, (
            "OFAC sync is not idempotent — re-running over identical "
            "upstream data produced a different CSV."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Network failure raises in strict mode
# ─────────────────────────────────────────────────────────────────────────────


def test_network_failure_raises_in_strict_mode() -> None:
    """The cron path uses ``strict=True``. A network failure MUST raise
    so the scheduler logs an ERROR + operator sees the failure. The
    silent `success=False` path would let a 6-week feed outage go
    unnoticed."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            side_effect=URLError("simulated outage"),
        ), pytest.raises(OFACSyncError) as exc_info:
            sync_ofac_sdn(output_path=out_path, strict=True)
        assert "simulated outage" in str(exc_info.value)
        # The wrapped SyncResult is available for inspection.
        assert exc_info.value.result is not None
        assert exc_info.value.result.stale is True


def test_network_failure_does_not_clobber_existing_csv() -> None:
    """Critical: a network failure must NOT silently update with
    empty data which would erase existing sanctions. The atomic-
    write design means we only replace the CSV on a successful
    parse, but a regression here would be catastrophic."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        out_path.write_text(
            "address,chain,sdn_entry_name,sdn_entry_id,listing_date\n"
            "0xexisting,ethereum,EXISTING_SDN,777,2020-01-01\n",
            encoding="utf-8",
        )
        original = out_path.read_bytes()
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            side_effect=URLError("outage"),
        ):
            # Non-strict path: returns SyncResult(success=False).
            result = sync_ofac_sdn(output_path=out_path)
        assert result.success is False
        # The pre-existing CSV is byte-identical — sanctions preserved.
        assert out_path.read_bytes() == original


# ─────────────────────────────────────────────────────────────────────────────
# 5. Malformed XML raises with clear error (RIGOR-2a still holds)
# ─────────────────────────────────────────────────────────────────────────────


def test_malformed_xml_raises_parse_error() -> None:
    """The RIGOR-2a defusedxml hardening must remain intact:
    malformed input raises (caller decides what to do)."""
    from xml.etree.ElementTree import ParseError
    with pytest.raises((ParseError, SyntaxError)):
        _extract_crypto_entries(b"<sdnList><sdn")


def test_malformed_xml_sync_returns_failure() -> None:
    """End-to-end: malformed XML in the feed → sync returns
    success=False with a parse-failed error message. CSV NOT written."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(b"<not><valid>"),
        ):
            result = sync_ofac_sdn(output_path=out_path)
        assert result.success is False
        assert "parse" in (result.error_message or "").lower()
        assert not out_path.exists()


def test_malformed_xml_raises_in_strict_mode() -> None:
    """Strict-mode equivalent: parse error → OFACSyncError raised."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(b"<not><valid>"),
        ), pytest.raises(OFACSyncError):
            sync_ofac_sdn(output_path=out_path, strict=True)


# ─────────────────────────────────────────────────────────────────────────────
# 6. last_synced_utc freshness sidecar
# ─────────────────────────────────────────────────────────────────────────────


def test_last_synced_utc_field_set_on_successful_sync() -> None:
    """After a successful sync, the `<csv>.meta.json` sidecar must
    exist with a `last_synced_utc` ISO-8601 UTC timestamp. The cron
    health probe + the stale-label alert read this to detect
    'OFAC hasn't been refreshed in N days.'"""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(_FIXTURE_FIVE_ENTRIES),
        ):
            sync_ofac_sdn(output_path=out_path)
        meta = read_ofac_meta(out_path)
    assert meta is not None
    assert "last_synced_utc" in meta
    assert isinstance(meta["last_synced_utc"], str)
    assert "T" in meta["last_synced_utc"]  # ISO format
    assert meta["entries_written"] == 3
    assert meta["entries_removed"] == 0
    assert meta["source_url"].startswith("https://www.treasury.gov/")
    assert meta["schema_version"] == 1


def test_meta_sidecar_absent_when_sync_fails() -> None:
    """A failed sync MUST NOT write a sidecar — otherwise the
    freshness timestamp would advance on every failure and the
    stale-label alert would never fire."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            side_effect=URLError("down"),
        ):
            sync_ofac_sdn(output_path=out_path)
        assert read_ofac_meta(out_path) is None
        assert not _meta_path_for(out_path).exists()


def test_meta_sidecar_path_is_csv_plus_meta_json() -> None:
    """Sidecar lives at `<csv>.meta.json` next to the CSV (so a
    directory-listing tooling that scans for related files finds it)."""
    csv_path = Path("/tmp/ofac_crypto_live.csv")
    assert _meta_path_for(csv_path).name == "ofac_crypto_live.csv.meta.json"


# ─────────────────────────────────────────────────────────────────────────────
# 7. removed_at_utc — addresses that disappear from feed are marked
# ─────────────────────────────────────────────────────────────────────────────


def test_removed_entries_get_removed_at_timestamp() -> None:
    """If a previously-listed address vanishes from the upstream feed,
    the merged CSV must mark it with `removed_at_utc` rather than
    silently dropping it. A compliance audit asking 'was this address
    ever OFAC-listed?' can still answer yes."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"

        # First sync — 3 entries (Lazarus, Garantex, Hydra).
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(_FIXTURE_FIVE_ENTRIES),
        ):
            r1 = sync_ofac_sdn(output_path=out_path)
        assert r1.entries_written == 3

        # Second sync — only Lazarus + Hydra remain (Garantex
        # delisted upstream).
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(_FIXTURE_AFTER_REMOVAL),
        ):
            r2 = sync_ofac_sdn(output_path=out_path)

        # `entries_written` counts live entries only.
        assert r2.entries_written == 2

        # The CSV still has 3 rows total (live + removed).
        rows = list(_read_csv_rows(out_path))
        assert len(rows) == 3
        removed = [r for r in rows if r.get("removed_at_utc")]
        assert len(removed) == 1
        assert "GARANTEX" in removed[0]["sdn_entry_name"]

        # Meta reflects 2 live, 1 removed.
        meta = read_ofac_meta(out_path)
        assert meta["entries_written"] == 2
        assert meta["entries_removed"] == 1


def test_removed_at_timestamp_does_not_bump_on_re_sync() -> None:
    """Re-running the sync over the same already-stale upstream data
    must NOT bump the `removed_at_utc` timestamp. Idempotency
    invariant: only the FIRST disappearance sets the timestamp."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(_FIXTURE_FIVE_ENTRIES),
        ):
            sync_ofac_sdn(output_path=out_path)
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(_FIXTURE_AFTER_REMOVAL),
        ):
            sync_ofac_sdn(output_path=out_path)
        rows_after_first_remove = list(_read_csv_rows(out_path))
        removed_ts_first = next(
            r["removed_at_utc"] for r in rows_after_first_remove
            if "GARANTEX" in r["sdn_entry_name"]
        )

        # Re-sync over the same "after removal" data.
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(_FIXTURE_AFTER_REMOVAL),
        ):
            sync_ofac_sdn(output_path=out_path)
        rows_after_re_sync = list(_read_csv_rows(out_path))
        removed_ts_second = next(
            r["removed_at_utc"] for r in rows_after_re_sync
            if "GARANTEX" in r["sdn_entry_name"]
        )

    assert removed_ts_first == removed_ts_second, (
        "removed_at_utc bumped on re-sync — breaks idempotency invariant."
    )


def test_removed_entry_returns_to_feed_clears_marker() -> None:
    """If an upstream removal is REVERSED (Tornado Cash partial 2024
    ruling, etc.), the next sync that sees the address back should
    clear its `removed_at_utc` marker."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        # Sync, remove, sync again, then restore.
        for payload, expected_live in [
            (_FIXTURE_FIVE_ENTRIES, 3),
            (_FIXTURE_AFTER_REMOVAL, 2),
            (_FIXTURE_FIVE_ENTRIES, 3),
        ]:
            with patch(
                "recupero.trace.ofac_sync.urllib.request.urlopen",
                return_value=_FakeResponse(payload),
            ):
                r = sync_ofac_sdn(output_path=out_path)
            assert r.entries_written == expected_live

        # After restoration, no rows should be marked removed.
        rows = list(_read_csv_rows(out_path))
        removed = [r for r in rows if r.get("removed_at_utc")]
        assert removed == []


# ─────────────────────────────────────────────────────────────────────────────
# 8. Backward compatibility — load_ofac_csv still works
# ─────────────────────────────────────────────────────────────────────────────


def test_load_ofac_csv_handles_new_removed_at_column() -> None:
    """The CSV gained a `removed_at_utc` column. The loader must
    populate it; downstream consumers that don't know about it
    just ignore the field on the dataclass."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(_FIXTURE_FIVE_ENTRIES),
        ):
            sync_ofac_sdn(output_path=out_path)
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_FakeResponse(_FIXTURE_AFTER_REMOVAL),
        ):
            sync_ofac_sdn(output_path=out_path)
        entries = load_ofac_csv(out_path, staleness_warn_days=0)
    # 3 entries total (2 live + 1 removed).
    assert len(entries) == 3
    removed_entries = [e for e in entries if e.removed_at_utc]
    assert len(removed_entries) == 1
    assert "GARANTEX" in removed_entries[0].sdn_entry_name


def test_load_ofac_csv_legacy_csv_without_removed_column() -> None:
    """A CSV written by an older v0.31.4 OFAC sync (5 columns, no
    removed_at_utc) must still load. Defaulting the missing column
    to empty string preserves backward compat."""
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ofac.csv"
        out_path.write_text(
            "address,chain,sdn_entry_name,sdn_entry_id,listing_date\n"
            "0xabc123,ethereum,LEGACY_SDN,9999,2022-01-01\n",
            encoding="utf-8",
        )
        entries = load_ofac_csv(out_path, staleness_warn_days=0)
    assert len(entries) == 1
    assert entries[0].removed_at_utc == ""


# ─────────────────────────────────────────────────────────────────────────────
# 9. Cron-job entry point uses strict mode
# ─────────────────────────────────────────────────────────────────────────────


def test_cron_job_uses_strict_mode_so_failures_raise() -> None:
    """The cron job (`_job_ofac_sync` in worker/cron_scheduler.py)
    MUST call `sync_ofac_sdn(strict=True)` — otherwise a feed outage
    silently degrades and the scheduler's per-job try/except logs
    only a soft `WARN` instead of `ERROR`.

    We invoke the job directly with urlopen patched to fail; the
    expected behavior is `OFACSyncError` propagates out of the job
    function (the scheduler then catches it in its outer wrapper)."""
    from recupero.worker.cron_scheduler import _job_ofac_sync
    with patch(
        "recupero.trace.ofac_sync.urllib.request.urlopen",
        side_effect=URLError("simulated cron-time outage"),
    ), pytest.raises(OFACSyncError):
        _job_ofac_sync()


# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────


def _read_csv_rows(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            yield row
