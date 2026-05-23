"""Adversarial audit for exchange/compliance API modules.

Asserts the module does not exist. If/when added, this test fails so the
adversarial suite (authn, tenant isolation, address validation, pagination,
NaN/Inf rejection, unicode trojans, export bounds, audit logging) must be
written before merge.
"""

from pathlib import Path


def test_exchange_compliance_api_modules_absent() -> None:
    api_dir = Path(__file__).resolve().parents[1] / "src" / "recupero" / "api"
    matches = sorted(
        p.name
        for p in api_dir.glob("*.py")
        if p.name.startswith(("exchange", "compliance"))
    )
    assert matches == [], (
        f"exchange/compliance API module(s) appeared: {matches}. "
        "Expand tests/test_exchange_api_adversarial.py with adversarial "
        "coverage (authn, tenant isolation, address shape gate, pagination "
        "cap, NaN/Inf rejection, unicode trojan rejection, export size "
        "bounds, audit logging) before merging."
    )
