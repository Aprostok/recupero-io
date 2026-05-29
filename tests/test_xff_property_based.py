"""Property-based tests for the XFF rate-limit IP extractor (S-3 fix).

PUNISH-B S-3 was about the rate-limit bucketing reading the LEFTMOST
X-Forwarded-For element as "the client IP". On Railway + Cloudflare,
that's whatever-the-client-typed — easily rotated to bypass the 5/min
intake limit. The fix walks N trusted hops back from the tail of the
chain (env: RECUPERO_TRUSTED_PROXY_HOPS).

These property tests probe the WHOLE input space:

  * For any XFF chain of length L and any trusted_hops N, the chosen
    IP is the (L-N)-th element (or the leftmost if L < N).
  * For trusted_hops=0 (default), XFF is IGNORED — falls through to
    x-real-ip then socket peer.
  * Adversarial chains (empty, all-whitespace, single-element with
    trailing commas) never crash.
  * An attacker rotating the LEFTMOST XFF value cannot influence the
    bucket as long as trusted_hops is configured correctly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from recupero.api.app import _intake_rl_client_ip

_SETTINGS = settings(
    max_examples=200,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


# ─────────────────────────────────────────────────────────────────────────────
# Mock Request type — enough surface for _intake_rl_client_ip
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class _FakeClient:
    host: str = "127.0.0.1"


@dataclass
class _FakeRequest:
    headers: dict[str, str]
    client: Any = None


# IP strategies. We use simple integer-tuple IPs that we then format.
# Doesn't need to be syntactically valid (the function passes the
# value through without re-validating); just unique strings.
def _ip_strategy() -> st.SearchStrategy[str]:
    return st.builds(
        "{}.{}.{}.{}".format,
        st.integers(1, 255),
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(1, 254),
    )


def _xff_chain_strategy() -> st.SearchStrategy[list[str]]:
    """A chain of 1-8 IPs as XFF would carry them."""
    return st.lists(_ip_strategy(), min_size=1, max_size=8)


# ═════════════════════════════════════════════════════════════════════════════
# Property 1: with trusted_hops=N AND len(chain) >= N, the chosen IP is
# the (L-N)-th element of the chain.
#
# RIGOR-S-3b update: when trusted_hops > len(chain), the contract was
# promoted to FAIL-CLOSED (return "unknown" rather than chain[0]). That
# misconfig path is covered exhaustively in
# tests/test_xff_misconfig_hardening.py. This property only asserts the
# well-configured case so it remains a clean tail-pick proof.
# ═════════════════════════════════════════════════════════════════════════════


@given(chain=_xff_chain_strategy(), trusted_hops=st.integers(1, 5))
@_SETTINGS
def test_property_trusted_hops_picks_correct_element(
    chain: list[str], trusted_hops: int,
) -> None:
    """For a chain `[a, b, c, d]` with trusted_hops=2, the function
    must pick `c` (chain[-2]). The misconfigured case (trusted_hops >
    len(chain)) is excluded — covered by test_xff_misconfig_hardening."""
    assume(trusted_hops <= len(chain))

    raw = ", ".join(chain)
    req = _FakeRequest(headers={"x-forwarded-for": raw})

    with patch.dict("os.environ",
                    {"RECUPERO_TRUSTED_PROXY_HOPS": str(trusted_hops)}):
        result = _intake_rl_client_ip(req)

    expected_idx = len(chain) - trusted_hops
    expected = chain[expected_idx]
    assert result == expected, (
        f"chain={chain}, trusted_hops={trusted_hops}, "
        f"expected chain[{expected_idx}]={expected!r}, got {result!r}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 2: with trusted_hops=0, XFF is COMPLETELY IGNORED
# ═════════════════════════════════════════════════════════════════════════════


@given(chain=_xff_chain_strategy(),
       real_ip=_ip_strategy(),
       socket_ip=_ip_strategy())
@_SETTINGS
def test_property_trusted_hops_zero_ignores_xff_completely(
    chain: list[str], real_ip: str, socket_ip: str,
) -> None:
    """With RECUPERO_TRUSTED_PROXY_HOPS=0 (the default), the function
    must NOT use XFF at all. An attacker who controls XFF cannot
    influence the bucket. Fallback is x-real-ip, then socket peer."""
    raw_xff = ", ".join(chain)
    req = _FakeRequest(
        headers={
            "x-forwarded-for": raw_xff,
            "x-real-ip": real_ip,
        },
        client=_FakeClient(host=socket_ip),
    )

    with patch.dict("os.environ",
                    {"RECUPERO_TRUSTED_PROXY_HOPS": "0"}):
        result = _intake_rl_client_ip(req)

    # With trusted_hops=0, x-real-ip is the next preference.
    assert result == real_ip, (
        f"With trusted_hops=0, XFF must be ignored. Got {result!r}; "
        f"x-real-ip={real_ip!r}. XFF chain was {chain!r}."
    )
    # And critically: no element of the XFF chain should leak through.
    # The attacker's leftmost value must NEVER be picked.
    assert result not in chain or result == real_ip, (
        f"Leakage: trusted_hops=0 but XFF element {result!r} was "
        f"chosen. Attacker can bypass rate-limit by rotating XFF."
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 3: attacker control over LEFTMOST XFF can't bypass the
# rate limit when trusted_hops > 0
# ═════════════════════════════════════════════════════════════════════════════


@given(attacker_ip=_ip_strategy(),
       trusted_proxies=st.lists(_ip_strategy(), min_size=2, max_size=4,
                                unique=True),
       trusted_hops=st.integers(1, 3))
@_SETTINGS
def test_property_attacker_xff_rotation_does_not_bypass_rate_limit(
    attacker_ip: str, trusted_proxies: list[str], trusted_hops: int,
) -> None:
    """The S-3 race-closure proof, properly scoped.

    Real-world XFF semantics: the attacker controls the LEFTMOST
    entry (whatever XFF header they sent before Cloudflare).
    Subsequent proxies APPEND their observed peer IP. With
    correctly-configured trusted_hops, the function selects from
    the TRUSTED tail of the chain.

    Precondition: chain length > trusted_hops (real production setup).
    Misconfiguration scenario where ops sets trusted_hops >= chain
    length is documented as "leftmost-fallback" and is a config
    issue, not a code bug. The function MUST NOT pick the attacker-
    controlled leftmost when there are MORE entries than trusted
    hops.
    """
    assume(attacker_ip not in trusted_proxies)
    assume(len(trusted_proxies) > trusted_hops)
    chain = [attacker_ip] + trusted_proxies
    raw = ", ".join(chain)
    req = _FakeRequest(headers={"x-forwarded-for": raw})

    with patch.dict("os.environ",
                    {"RECUPERO_TRUSTED_PROXY_HOPS": str(trusted_hops)}):
        result = _intake_rl_client_ip(req)

    assert result != attacker_ip, (
        f"Attacker bypass! XFF={chain!r}, trusted_hops={trusted_hops}, "
        f"chose attacker-controlled IP {attacker_ip!r}. "
        f"Pre-PUNISH-B-S-3 this was the exact rate-limit bypass."
    )
    # The result must be in the trusted-proxy segment.
    assert result in trusted_proxies, (
        f"Result {result!r} not in trusted-proxy segment "
        f"{trusted_proxies!r}; trusted_hops={trusted_hops}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 4 + "documented misconfig behavior" tests REMOVED.
#
# RIGOR-S-3b: the contract was promoted from "fall back to leftmost
# (chain[0]) when trusted_hops >= len(chain)" to "skip the XFF path
# entirely". The new positive lock lives in
# tests/test_xff_misconfig_hardening.py — that file's
# test_misconfig_chain_too_short_falls_through_to_real_ip and friends
# pin the fail-closed contract. The two former property tests here
# (``test_property_short_chain_takes_leftmost`` and
# ``test_documented_short_chain_falls_back_to_leftmost``) asserted the
# OLD behavior; their docstrings explicitly noted "a code change
# promoting this to fail-closed should also remove this test."
# Removing them keeps the property test suite consistent with the
# hardened contract.
# ═════════════════════════════════════════════════════════════════════════════


# ═════════════════════════════════════════════════════════════════════════════
# Property 5: empty / malformed XFF doesn't crash
# ═════════════════════════════════════════════════════════════════════════════


@given(xff=st.text(max_size=200),
       trusted_hops=st.integers(0, 5))
@_SETTINGS
def test_property_malformed_xff_does_not_crash(
    xff: str, trusted_hops: int,
) -> None:
    """Adversarial XFF input (empty, whitespace, only-commas, unicode,
    extremely long) must never crash the rate-limit path."""
    req = _FakeRequest(
        headers={"x-forwarded-for": xff},
        client=_FakeClient(host="127.0.0.1"),
    )
    with patch.dict("os.environ",
                    {"RECUPERO_TRUSTED_PROXY_HOPS": str(trusted_hops)}):
        try:
            result = _intake_rl_client_ip(req)
        except Exception as e:  # noqa: BLE001
            pytest.fail(
                f"_intake_rl_client_ip raised {type(e).__name__} on "
                f"xff={xff!r}, trusted_hops={trusted_hops}: {e}"
            )
    # Must return a string (could be "unknown" in degenerate case).
    assert isinstance(result, str)
    assert result != ""  # We promise a non-empty bucket key.
