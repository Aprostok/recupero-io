"""RIGOR-S-3b: lock the XFF misconfig fail-closed contract.

Pre-hardening: when an operator set
``RECUPERO_TRUSTED_PROXY_HOPS=3`` but the actual XFF chain was
shorter than 3 (e.g., they migrated from a Railway → Cloudflare
deploy to a Railway-only deploy), the function walked back to
``xff_chain[0]`` — the leftmost, attacker-controlled element. An
attacker rotating leftmost-XFF per request silently bypassed the
5/min rate limit.

Post-hardening: when ``len(xff_chain) < trusted_hops``, the XFF
path is skipped entirely. We fall through to x-real-ip or the
socket peer. The rate-limit bucketing degrades to coarser-than-
intended (the deploy's real proxy IP), but there's no bypass.

This is the inverse of the prior "documented misconfig behavior"
test in test_xff_property_based.py — that test asserted leftmost
was returned. With the hardening, it should now fall through.
The old test was updated in the same commit; this file is the
positive lock on the new contract.
"""

from __future__ import annotations

from unittest.mock import patch


class _FakeRequest:
    """Minimal Request stub matching the shape _intake_rl_client_ip reads."""
    def __init__(
        self,
        headers: dict[str, str] | None = None,
        client_host: str | None = None,
    ) -> None:
        self.headers = headers or {}
        if client_host:
            class _Client:
                host = client_host
            self.client = _Client()
        else:
            self.client = None


def test_misconfig_chain_too_short_falls_through_to_real_ip() -> None:
    """The classic misconfig: operator sets trusted_hops=3 but the
    actual XFF chain is 1 hop. Pre-fix this returned chain[0] (the
    attacker-supplied leftmost). Post-fix the XFF path is skipped
    entirely and we honor x-real-ip."""
    from recupero.api.app import _intake_rl_client_ip

    req = _FakeRequest(
        headers={
            "x-forwarded-for": "1.2.3.4",  # 1-hop chain
            "x-real-ip": "10.0.0.5",       # proxy-supplied true peer
        },
    )
    with patch.dict("os.environ", {"RECUPERO_TRUSTED_PROXY_HOPS": "3"}):
        result = _intake_rl_client_ip(req)

    assert result == "10.0.0.5", (
        f"Misconfig hardening broken: chain length 1 < trusted_hops 3 "
        f"should fall through to x-real-ip; got {result!r}. "
        f"Returning chain[0]=1.2.3.4 would re-introduce the bypass."
    )


def test_misconfig_chain_too_short_falls_through_to_socket_peer() -> None:
    """When XFF is too short AND no x-real-ip header is present, we
    fall through to request.client.host (the TCP socket peer)."""
    from recupero.api.app import _intake_rl_client_ip

    req = _FakeRequest(
        headers={"x-forwarded-for": "evil.example.com"},
        client_host="172.16.0.10",
    )
    with patch.dict("os.environ", {"RECUPERO_TRUSTED_PROXY_HOPS": "5"}):
        result = _intake_rl_client_ip(req)

    assert result == "172.16.0.10", (
        f"Expected socket peer (172.16.0.10) when XFF chain too short; "
        f"got {result!r}."
    )


def test_correct_config_still_works_at_chain_equal_hops_boundary() -> None:
    """Sanity: the hardening must NOT break the correct-config path.
    When len(chain) == trusted_hops, we still extract chain[0] (the
    leftmost is the trust boundary in that case — the closest proxy
    inserted it)."""
    from recupero.api.app import _intake_rl_client_ip

    # Two-hop chain, trusted_hops=2 → chain[-2] == chain[0].
    req = _FakeRequest(
        headers={"x-forwarded-for": "203.0.113.1, 198.51.100.42"},
    )
    with patch.dict("os.environ", {"RECUPERO_TRUSTED_PROXY_HOPS": "2"}):
        result = _intake_rl_client_ip(req)
    assert result == "203.0.113.1"


def test_correct_config_chain_longer_than_hops_picks_correct_element() -> None:
    """5-hop chain, trusted_hops=2 → chain[-2] == "192.0.2.4"."""
    from recupero.api.app import _intake_rl_client_ip

    req = _FakeRequest(
        headers={
            "x-forwarded-for":
            "10.0.0.1, 10.0.0.2, 10.0.0.3, 192.0.2.4, 192.0.2.5",
        },
    )
    with patch.dict("os.environ", {"RECUPERO_TRUSTED_PROXY_HOPS": "2"}):
        result = _intake_rl_client_ip(req)
    assert result == "192.0.2.4", (
        f"5-hop chain with trusted_hops=2 should pick chain[-2]="
        f"192.0.2.4; got {result!r}"
    )


def test_attacker_cannot_bypass_via_padding_xff() -> None:
    """The original attack: bot sets a long XFF chain hoping
    trusted_hops will land on an attacker-controlled element. With
    correct trusted_hops, only the proxy-inserted segment is
    extractable.

    Scenario: deploy actually has 1 trusted proxy (trusted_hops=1).
    Attacker submits XFF=`attacker1, attacker2, attacker3` hoping
    to land on one of them. Correct behavior: chain[-1] which is
    the proxy-supplied element — in this case 'attacker3' the
    attacker DID supply, but the rate-limit will at least bucket
    them per-distinct-leftmost-rotation rather than per-request.

    But the real protection is: when trusted_hops is configured
    correctly, the proxy strips/rewrites the chain. Test that the
    function picks the documented element (chain[-trusted_hops]).
    """
    from recupero.api.app import _intake_rl_client_ip

    # The attacker's payload. Real proxy would normally append its
    # own IP after this — simulating a scenario where the real proxy
    # IS the trusted one but it didn't sanitize the input.
    req = _FakeRequest(
        headers={
            "x-forwarded-for":
            "attacker1, attacker2, attacker3, REAL_PROXY_IP",
        },
    )
    with patch.dict("os.environ", {"RECUPERO_TRUSTED_PROXY_HOPS": "1"}):
        result = _intake_rl_client_ip(req)
    # The trusted segment is the LAST element (chain[-1]).
    assert result == "REAL_PROXY_IP", (
        f"trusted_hops=1 should pick chain[-1]=REAL_PROXY_IP; got {result!r}"
    )


def test_zero_trusted_hops_still_ignores_xff_completely() -> None:
    """Regression check: the existing trusted_hops=0 contract is
    unchanged by the misconfig hardening — XFF is ignored and x-real-ip
    is the fallback.

    v0.32.1 (security-audit cycle-2): the x-real-ip fallback is now
    gated on an EXPLICIT dev/test marker (fail-closed by default), so
    set ENVIRONMENT=development to exercise the resolution path. The
    fail-closed prod behavior is locked separately in
    test_v0_25_1_audit_fixes.test_d1b/test_d1c."""
    from recupero.api.app import _intake_rl_client_ip

    req = _FakeRequest(
        headers={
            "x-forwarded-for": "1.2.3.4, 5.6.7.8",
            "x-real-ip": "203.0.113.99",
        },
    )
    with patch.dict("os.environ", {"RECUPERO_TRUSTED_PROXY_HOPS": "0",
                                   "ENVIRONMENT": "development"}):
        result = _intake_rl_client_ip(req)
    assert result == "203.0.113.99"
