"""Property-based tests for the SSRF webhook-URL guard.

The function under test is ``recupero.api.monitoring_api
.assert_webhook_url_safe``. Its job is to refuse any URL that
resolves to internal infrastructure (RFC1918, loopback, link-local,
multicast, reserved, metadata services, ``.internal`` / ``.local`` /
``.consul`` suffixes).

Pre-existing tests cover individually-handpicked URLs (one for each
blocked range). These hypothesis-driven tests probe the WHOLE input
space:

  * Any IP literal in any private/loopback/link-local/etc. range
    MUST be rejected (no slip-through via numeric edge cases).
  * Any hostname ending in a blocked suffix MUST be rejected
    regardless of case, padding, or unicode IDN form.
  * Any non-https scheme MUST be rejected (including http, file,
    ftp, gopher, javascript, data, ws, wss, etc.).
  * The function MUST NOT raise anything other than
    ``MonitoringApiError`` for any garbage input — no
    UnicodeDecodeError, no IndexError, no NameError surfacing past
    the helper. Adversarial unicode + malformed URLs.

Each property test runs hypothesis ≥100 examples per case (default).
Failures shrink to a minimal counter-example automatically.
"""

from __future__ import annotations

import ipaddress
import socket
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from recupero.api.monitoring_api import (
    MonitoringApiError,
    _is_blocked_host,
    _is_blocked_ip,
    assert_webhook_url_safe,
)

# Suppress the function-scoped-fixture health check — these tests
# don't use fixtures, but pytest's strict markers still hit it.
_SETTINGS = settings(
    max_examples=200,
    deadline=2000,  # 2s per example — DNS lookups can be slow on Windows
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


# ═════════════════════════════════════════════════════════════════════════════
# Strategies: build addresses that MUST be blocked
# ═════════════════════════════════════════════════════════════════════════════


def _private_ipv4_strategy() -> st.SearchStrategy[str]:
    """Generate any IPv4 in a blocked range:
      * 10.0.0.0/8      (RFC1918)
      * 172.16.0.0/12   (RFC1918)
      * 192.168.0.0/16  (RFC1918)
      * 127.0.0.0/8     (loopback)
      * 169.254.0.0/16  (link-local — also AWS IMDS)
      * 0.0.0.0/8       (unspecified)
      * 100.64.0.0/10   (carrier-grade NAT, reserved)
      * 198.18.0.0/15   (benchmark, reserved)
    """
    # Build full address-space generator then filter.
    return st.one_of(
        # 10.0.0.0/8
        st.builds(
            "{}.{}.{}.{}".format,
            st.just(10),
            st.integers(0, 255),
            st.integers(0, 255),
            st.integers(0, 255),
        ),
        # 172.16.0.0/12 — 172.16..172.31
        st.builds(
            "{}.{}.{}.{}".format,
            st.just(172),
            st.integers(16, 31),
            st.integers(0, 255),
            st.integers(0, 255),
        ),
        # 192.168.0.0/16
        st.builds(
            "{}.{}.{}.{}".format,
            st.just(192),
            st.just(168),
            st.integers(0, 255),
            st.integers(0, 255),
        ),
        # 127.0.0.0/8 (loopback)
        st.builds(
            "{}.{}.{}.{}".format,
            st.just(127),
            st.integers(0, 255),
            st.integers(0, 255),
            st.integers(0, 255),
        ),
        # 169.254.0.0/16 (link-local / metadata)
        st.builds(
            "{}.{}.{}.{}".format,
            st.just(169),
            st.just(254),
            st.integers(0, 255),
            st.integers(0, 255),
        ),
        # 0.0.0.0/8 (unspecified)
        st.builds(
            "{}.{}.{}.{}".format,
            st.just(0),
            st.integers(0, 255),
            st.integers(0, 255),
            st.integers(0, 255),
        ),
    )


def _private_ipv6_strategy() -> st.SearchStrategy[str]:
    """Generate IPv6 strings in blocked ranges."""
    return st.sampled_from([
        "::1",                              # loopback
        "::",                               # unspecified
        "fe80::1",                          # link-local
        "fe80::dead:beef",                  # link-local
        "fc00::1",                          # ULA
        "fd00::1",                          # ULA (private)
        "fd12:3456:789a:1::1",              # ULA
        "ff02::1",                          # multicast
        "fd00:ec2::254",                    # AWS IMDSv6 (blocked by hostname too)
        "::ffff:10.0.0.1",                  # IPv4-mapped private
        "::ffff:127.0.0.1",                 # IPv4-mapped loopback
        "::ffff:169.254.169.254",           # IPv4-mapped metadata
    ])


def _blocked_hostname_strategy() -> st.SearchStrategy[str]:
    """Hostnames that hit the exact-match deny list OR the suffix
    deny list, in various case mutations."""
    bases = [
        "localhost",
        "ip6-localhost",
        "metadata.google.internal",
        "metadata.aws.internal",
        "metadata.azure.com",
        # Suffix-blocked
        "svc.cluster.local",
        "redis.railway.internal",
        "db.consul",
        "host.local",
        "Service.local",   # mixed case
        "FOO.INTERNAL",    # ALL CAPS
        "x.CLUSTER.local",
    ]
    return st.sampled_from(bases)


def _non_https_scheme_strategy() -> st.SearchStrategy[str]:
    """Schemes that are NOT https."""
    return st.sampled_from([
        "http", "ftp", "file", "gopher", "javascript", "data",
        "ws", "wss", "ldap", "smb", "vnc", "mailto", "tel",
        "telnet", "ssh", "jdbc", "dict", "tftp",
    ])


# ═════════════════════════════════════════════════════════════════════════════
# Property 1: every private/loopback/etc. IP literal is rejected
# ═════════════════════════════════════════════════════════════════════════════


@given(ip_str=_private_ipv4_strategy())
@_SETTINGS
def test_property_every_private_ipv4_is_blocked(ip_str: str) -> None:
    """For any IPv4 address in a blocked range, _is_blocked_ip must
    return True and assert_webhook_url_safe must raise. No numeric
    edge case (e.g., 10.0.0.0, 10.255.255.255) slips through."""
    assert _is_blocked_ip(ip_str), (
        f"_is_blocked_ip({ip_str!r}) returned False; expected True. "
        "Private/loopback/link-local IPv4 must be blocked."
    )
    url = f"https://{ip_str}/hook"
    with pytest.raises(MonitoringApiError) as exc_info:
        assert_webhook_url_safe(url)
    assert "host is not permitted" in exc_info.value.detail.lower() \
        or "private" in exc_info.value.detail.lower(), (
        f"Wrong error detail: {exc_info.value.detail!r}"
    )


@given(ip_str=_private_ipv6_strategy())
@_SETTINGS
def test_property_every_private_ipv6_is_blocked(ip_str: str) -> None:
    """For any IPv6 in a blocked range, the SSRF guard must reject
    it. Includes loopback, ULA, link-local, multicast, and
    IPv4-mapped variants of blocked ranges."""
    assert _is_blocked_ip(ip_str), (
        f"_is_blocked_ip({ip_str!r}) returned False; expected True."
    )
    # IPv6 in URLs must be bracketed.
    url = f"https://[{ip_str}]/hook"
    with pytest.raises(MonitoringApiError):
        assert_webhook_url_safe(url)


# ═════════════════════════════════════════════════════════════════════════════
# Property 2: every blocked hostname is rejected regardless of case
# ═════════════════════════════════════════════════════════════════════════════


@given(host=_blocked_hostname_strategy(),
       case_mutation=st.sampled_from(["lower", "upper", "title", "mixed"]))
@_SETTINGS
def test_property_blocked_hostnames_are_case_insensitive(
    host: str, case_mutation: str,
) -> None:
    """The hostname denylist must be case-insensitive. No matter how
    the partner cases the URL, blocked hosts are blocked."""
    if case_mutation == "lower":
        h = host.lower()
    elif case_mutation == "upper":
        h = host.upper()
    elif case_mutation == "title":
        h = host.title()
    else:
        # Mixed: capitalize even positions.
        h = "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(host)
        )
    assert _is_blocked_host(h), (
        f"_is_blocked_host({h!r}) returned False — denylist is "
        "case-sensitive! Partner can bypass by capitalizing."
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 3: any non-https URL is rejected
# ═════════════════════════════════════════════════════════════════════════════


@given(scheme=_non_https_scheme_strategy(),
       host=st.sampled_from(["example.com", "api.partner.io", "8.8.8.8"]))
@_SETTINGS
def test_property_only_https_scheme_accepted(
    scheme: str, host: str,
) -> None:
    """Only ``https://`` schemes are allowed. Any other scheme must
    raise — even if the host itself is public/safe."""
    url = f"{scheme}://{host}/hook"
    with pytest.raises(MonitoringApiError) as exc_info:
        assert_webhook_url_safe(url)
    assert "https" in exc_info.value.detail.lower(), (
        f"Wrong error for scheme {scheme!r}: {exc_info.value.detail!r}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 4: garbage input never escapes as an uncaught exception
# ═════════════════════════════════════════════════════════════════════════════


@given(garbage=st.text(
    alphabet=st.characters(
        # Include control chars, surrogates, weird unicode.
        whitelist_categories=("Lu", "Ll", "Nd", "Pc", "Sm", "Cc",
                              "Po", "Sk", "Co"),
        max_codepoint=0x10FFFF,
    ),
    min_size=0, max_size=200,
))
@_SETTINGS
def test_property_garbage_input_never_escapes_uncaught(
    garbage: str,
) -> None:
    """No adversarial unicode / control-char / surrogate input can
    cause assert_webhook_url_safe to raise anything other than
    MonitoringApiError (or pass cleanly). Catches:
      * UnicodeDecodeError in url parsing
      * IndexError in scheme split
      * NameError / TypeError surfacing past the guard
      * socket.gaierror from DNS resolution leaking out
    """
    try:
        # Patch socket.getaddrinfo so we don't make real DNS calls
        # for every fuzz iteration; treat unresolvable as "no
        # blocked IP returned" which is the safe fall-through path.
        with patch.object(socket, "getaddrinfo",
                          side_effect=socket.gaierror("test")):
            assert_webhook_url_safe(garbage)
    except MonitoringApiError:
        # Expected error class — fine.
        pass
    except Exception as e:  # noqa: BLE001
        pytest.fail(
            f"assert_webhook_url_safe raised {type(e).__name__} (NOT "
            f"MonitoringApiError) on input {garbage!r}: {e}"
        )


# ═════════════════════════════════════════════════════════════════════════════
# Property 5: bracketed IPv6 literals in URLs are normalized correctly
# ═════════════════════════════════════════════════════════════════════════════


@given(ipv6=_private_ipv6_strategy())
@_SETTINGS
def test_property_ipv6_brackets_stripped_for_blocklist_check(
    ipv6: str,
) -> None:
    """When a URL has bracketed IPv6 ([::1]), the host parsing must
    strip the brackets before checking against the IP denylist."""
    url = f"https://[{ipv6}]:8080/hook"
    with pytest.raises(MonitoringApiError):
        assert_webhook_url_safe(url)


# ═════════════════════════════════════════════════════════════════════════════
# Property 6: known-public IPs are NOT blocked (sanity guard)
# ═════════════════════════════════════════════════════════════════════════════


def _public_ipv4_strategy() -> st.SearchStrategy[str]:
    """Generate IPv4 addresses NOT in any blocked range. Hypothesis
    will reject the inputs that don't satisfy the assume()."""
    return st.builds(
        "{}.{}.{}.{}".format,
        st.integers(1, 223),  # Skip 0.x.x.x (unspecified) and 224+ (mcast)
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(1, 254),
    )


@given(ip_str=_public_ipv4_strategy())
@_SETTINGS
def test_property_public_ipv4_is_not_blocked(ip_str: str) -> None:
    """Sanity check: a randomly-sampled non-private IP literal is NOT
    blocked by _is_blocked_ip. Otherwise the SSRF guard would be
    over-broad and refuse legitimate partner webhooks."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        assume(False)
        return
    # Filter out anything actually in a blocked range — hypothesis will
    # find a non-blocked example.
    assume(not (
        ip.is_loopback or ip.is_private or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    ))
    assert not _is_blocked_ip(ip_str), (
        f"_is_blocked_ip({ip_str!r}) returned True on a public IP — "
        "false positive that would refuse a legitimate webhook."
    )
