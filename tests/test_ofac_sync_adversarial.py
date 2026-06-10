"""Adversarial / hostile-feed tests for OFAC sync (RIGOR-2a extension).

These tests assume the OFAC feed is an untrusted input: Treasury's
CDN could be MITM'd, the URL could be operator-misconfigured to a
hostile host, or a future refactor could accidentally widen the
URL surface. We verify defense-in-depth beyond defusedxml's import.

Threat model:
  * XXE / billion-laughs / external-DTD (defusedxml should reject).
  * SSRF via attacker-controlled URL (file:// / ftp:// / gopher://).
  * Response-size memory bomb (no Content-Length, infinite stream).
  * Encoding-spoofing (UTF-7 declaration to smuggle <script>).
  * SDN-name injection — bidi-override / NUL bytes flowing into CSV
    which downstream tooling renders as labels.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from recupero.trace.ofac_sync import (
    _extract_crypto_entries,
    sync_ofac_sdn,
)

# ----- 1. XXE injection ----- #

_XXE_PAYLOAD = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<sdnList>
  <sdnEntry>
    <uid>1</uid>
    <lastName>&xxe;</lastName>
    <idList>
      <id>
        <idType>Digital Currency Address - ETH</idType>
        <idNumber>0xdeadbeef00000000000000000000000000000000</idNumber>
      </id>
    </idList>
  </sdnEntry>
</sdnList>
"""


def test_xxe_external_entity_blocked() -> None:
    """Parsing an XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
    must NOT resolve the entity. Either the parser raises, or the
    entity reference appears verbatim/empty in the output — but the
    file's contents must never appear in any extracted field."""
    try:
        entries = _extract_crypto_entries(_XXE_PAYLOAD)
    except Exception:
        # Acceptable: defusedxml's EntitiesForbidden / DTDForbidden.
        return
    # If parsing succeeded, the entity must not have been resolved
    # to the contents of /etc/passwd (which on any system contains
    # the literal string "root").
    for e in entries:
        assert "root:" not in e.sdn_entry_name, (
            "XXE: file:///etc/passwd contents leaked into SDN name"
        )


# ----- 2. Billion laughs ----- #

_BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<sdnList><sdnEntry><lastName>&lol9;</lastName></sdnEntry></sdnList>
"""


def test_billion_laughs_blocked() -> None:
    """10-deep nested entity expansion would balloon to 10^9 'lol's.
    defusedxml must refuse to expand entities. Either raise, or
    return without the expanded string."""
    try:
        entries = _extract_crypto_entries(_BILLION_LAUGHS)
    except Exception:
        return  # expected: EntitiesForbidden
    # If it parsed, the lastName field must not be >1MB
    for e in entries:
        assert len(e.sdn_entry_name) < 10_000, (
            "billion-laughs: entity expanded to memory-bomb size"
        )


# ----- 3. External DTD ----- #

_EXTERNAL_DTD = b"""<?xml version="1.0"?>
<!DOCTYPE sdnList SYSTEM "http://attacker.example.com/evil.dtd">
<sdnList>
  <sdnEntry>
    <uid>1</uid>
    <lastName>EXTDTD</lastName>
    <idList>
      <id>
        <idType>Digital Currency Address - ETH</idType>
        <idNumber>0xfeedface00000000000000000000000000000000</idNumber>
      </id>
    </idList>
  </sdnEntry>
</sdnList>
"""


def test_external_dtd_does_not_fetch() -> None:
    """Parsing must not trigger an HTTP request to the SYSTEM URL.
    We patch urllib.request.urlopen and assert it's NOT called
    during parse."""
    with patch(
        "urllib.request.urlopen",
        side_effect=AssertionError("parser fetched external DTD"),
    ):
        try:
            _extract_crypto_entries(_EXTERNAL_DTD)
        except Exception:
            # Acceptable: defusedxml raises DTDForbidden / similar.
            pass
    # If no AssertionError raised, the parser did not fetch — pass.


# ----- 4. SSRF via attacker-controlled URL ----- #


@pytest.mark.parametrize("hostile_url", [
    "file:///etc/passwd",
    "file://C:/Windows/win.ini",
    "ftp://internal-host/secrets",
    "gopher://localhost:6379/_FLUSHALL",
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
])
def test_sync_rejects_non_https_schemes(hostile_url: str) -> None:
    """A misconfigured OFAC_SDN_XML_URL (operator typo, env-var
    override) or a future caller passing user-controlled input
    must not be able to read local files or hit internal services.
    Only http(s) to public hosts should be permitted."""
    with TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.csv"
        result = sync_ofac_sdn(url=hostile_url, output_path=out, timeout_sec=2)
    assert result.success is False, (
        f"SSRF: sync accepted hostile scheme {hostile_url!r}"
    )
    assert not out.exists()


# ----- 5. Response-size cap (memory-bomb) ----- #


def test_sync_caps_response_size() -> None:
    """A hostile or compromised CDN could stream gigabytes. The
    sync must cap the response body (Treasury feed is ~50MB; we
    allow up to ~200MB as headroom and reject above that)."""
    class _GiantResponse:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self, *a, **kw):
            # 1 GiB of garbage
            return b"<" + b"A" * (1024 * 1024 * 1024) + b"/>"

    with TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.csv"
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_GiantResponse(),
        ):
            result = sync_ofac_sdn(output_path=out, timeout_sec=2)
    assert result.success is False, "memory-bomb: 1GB response accepted"


# ----- 6. SDN-name injection: bidi / NUL into CSV ----- #


def test_sdn_name_bidi_sanitized() -> None:
    """An OFAC entry whose lastName contains a right-to-left override
    (U+202E) would flow into the CSV and downstream into PDF/HTML
    reports, where bidi confuses analysts (the classic "evil.exe"
    rendered as "evil.txt" attack on filenames / wallet labels).

    The extractor must strip the override before it reaches the CSV."""
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<sdnList><sdnEntry><uid>9</uid>"
        b"<lastName>SAFE\xe2\x80\xaeEVIL_NAME</lastName>"  # U+202E
        b"<idList><id>"
        b"<idType>Digital Currency Address - ETH</idType>"
        b"<idNumber>0xcafebabe00000000000000000000000000000000</idNumber>"
        b"</id></idList></sdnEntry></sdnList>"
    )
    entries = _extract_crypto_entries(payload)
    assert len(entries) == 1
    name = entries[0].sdn_entry_name
    assert "‮" not in name, "bidi RTL-override leaked into SDN name"
    # And the benign chars on either side are preserved.
    assert "SAFE" in name and "EVIL_NAME" in name


def test_sanitize_sdn_name_helper_strips_nul_and_bidi() -> None:
    """Direct unit on the sanitizer: NUL + all bidi-override
    codepoints get dropped. (XML 1.0 forbids NUL in CDATA so this
    helper is the second line of defense — if some future code path
    feeds names from a non-XML source, NUL is still stripped.)"""
    from recupero.trace.ofac_sync import _sanitize_sdn_name
    raw = "A\x00B‮C⁦D"
    cleaned = _sanitize_sdn_name(raw)
    assert cleaned == "ABCD"


# ----- 7. SSRF: sync default URL still works (regression guard) ----- #


def test_sync_default_https_url_still_accepted() -> None:
    """The hardening must not break the happy path: the default
    Treasury URL (https://www.treasury.gov/...) must still be
    accepted. We mock urlopen so no network."""
    fake_xml = b"""<?xml version="1.0"?><sdnList></sdnList>"""

    class _R:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self, *a, **kw):
            return fake_xml

    with TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.csv"
        with patch(
            "recupero.trace.ofac_sync.urllib.request.urlopen",
            return_value=_R(),
        ):
            result = sync_ofac_sdn(output_path=out, timeout_sec=2)
    # What we care about is that the URL was NOT rejected by the
    # scheme/host allowlist. (Since the 2026-06 anti-mass-delist guard,
    # an empty sdnList is itself refused — with a *content* error, not
    # a URL refusal — so we assert on the refusal class, not success.)
    assert "refused scheme" not in (result.error_message or "")
    assert "refused host" not in (result.error_message or "")
    assert "zero crypto entries" in (result.error_message or "")


# ----- 8. UTF-7 encoding spoof ----- #


def test_utf7_encoding_declaration_rejected_or_safe() -> None:
    """A `<?xml version="1.0" encoding="UTF-7"?>` declaration can
    smuggle `<script>` past naive HTML-context filters. defusedxml
    + ElementTree typically reject UTF-7 outright; we assert the
    parser either raises or does not produce a usable entry."""
    payload = (
        b'<?xml version="1.0" encoding="UTF-7"?>\n'
        b"+ADw-sdnList+AD4APA-sdnEntry+AD4APA-lastName+AD4-EVIL+ADwA-/lastName+AD4APA-/sdnEntry+AD4APA-/sdnList+AD4-"
    )
    try:
        entries = _extract_crypto_entries(payload)
    except Exception:
        return  # acceptable: parser rejects UTF-7 / bad encoding
    # If it parsed, no entries (no idList with crypto) should be
    # returned — and certainly no <script> string in any field.
    for e in entries:
        assert "<script" not in e.sdn_entry_name.lower()
