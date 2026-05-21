"""S-1 (v0.28.0): Multi-tenant authorization for /v1/freeze-outcomes.

Pins the v0.27.1-audit CRIT-1 fix:

  * Pre-fix, ANY valid API key could write outcomes for ANY case/issuer.
  * Pre-fix, 404 detail leaked the supplied (case_id, issuer,
    target_address) triple — an enumeration oracle.

After this commit:

  1. Endpoint refuses when the calling key is neither in
     RECUPERO_API_KEY_ADMINS nor allow-listed for the issuer in
     RECUPERO_API_KEY_ISSUERS — returns 404 with a generic detail.
  2. The 404 detail for missing letters is the same as the 404 detail
     for unauthorized writes — indistinguishable from outside.
  3. Admins (RECUPERO_API_KEY_ADMINS) get universal write access.
  4. Partners (RECUPERO_API_KEY_ISSUERS) can write only for issuers
     in their per-key allow-list; case-insensitive comparison.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient


CASE_ID = UUID("11111111-1111-1111-1111-111111111111")
TARGET = "0x" + "a" * 40
OUTCOME_ID = UUID("22222222-2222-2222-2222-222222222222")


def _post(client, secret, payload):
    return client.post(
        "/v1/freeze-outcomes",
        json=payload,
        headers={"X-Recupero-API-Key": secret},
    )


def _default_payload(issuer="Tether"):
    return {
        "case_id": str(CASE_ID),
        "issuer": issuer,
        "target_address": TARGET,
        "outcome_type": "acknowledged",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helper: is_authorized_to_record_outcome — unit tests
# ─────────────────────────────────────────────────────────────────────────────


def test_admin_key_authorized_for_any_issuer(monkeypatch):
    from recupero.api.auth import is_authorized_to_record_outcome
    monkeypatch.setenv("RECUPERO_API_KEY_ADMINS", "ops-team")
    monkeypatch.delenv("RECUPERO_API_KEY_ISSUERS", raising=False)
    assert is_authorized_to_record_outcome(
        api_key_name="ops-team", issuer="Random-New-Exchange",
    ) is True


def test_partner_key_authorized_only_for_allowlisted_issuers(monkeypatch):
    from recupero.api.auth import is_authorized_to_record_outcome
    monkeypatch.delenv("RECUPERO_API_KEY_ADMINS", raising=False)
    monkeypatch.setenv(
        "RECUPERO_API_KEY_ISSUERS",
        "exchange-acme:Tether|Circle,partner-b:Coinbase",
    )
    # acme allowed for Tether + Circle.
    assert is_authorized_to_record_outcome(
        api_key_name="exchange-acme", issuer="Tether",
    ) is True
    assert is_authorized_to_record_outcome(
        api_key_name="exchange-acme", issuer="Circle",
    ) is True
    # acme NOT allowed for Coinbase.
    assert is_authorized_to_record_outcome(
        api_key_name="exchange-acme", issuer="Coinbase",
    ) is False
    # partner-b allowed for Coinbase.
    assert is_authorized_to_record_outcome(
        api_key_name="partner-b", issuer="Coinbase",
    ) is True
    # partner-b NOT allowed for Tether.
    assert is_authorized_to_record_outcome(
        api_key_name="partner-b", issuer="Tether",
    ) is False


def test_partner_key_issuer_comparison_is_case_insensitive(monkeypatch):
    from recupero.api.auth import is_authorized_to_record_outcome
    monkeypatch.delenv("RECUPERO_API_KEY_ADMINS", raising=False)
    monkeypatch.setenv("RECUPERO_API_KEY_ISSUERS", "exchange-acme:Tether")
    # Same letter case.
    assert is_authorized_to_record_outcome(
        api_key_name="exchange-acme", issuer="Tether",
    ) is True
    # Different case.
    assert is_authorized_to_record_outcome(
        api_key_name="exchange-acme", issuer="tether",
    ) is True
    assert is_authorized_to_record_outcome(
        api_key_name="exchange-acme", issuer="TETHER",
    ) is True
    # Whitespace also stripped.
    assert is_authorized_to_record_outcome(
        api_key_name="exchange-acme", issuer="  Tether  ",
    ) is True


def test_unknown_key_denied_by_default(monkeypatch):
    """Key with no entry in either env var → denied."""
    from recupero.api.auth import is_authorized_to_record_outcome
    monkeypatch.delenv("RECUPERO_API_KEY_ADMINS", raising=False)
    monkeypatch.delenv("RECUPERO_API_KEY_ISSUERS", raising=False)
    assert is_authorized_to_record_outcome(
        api_key_name="unknown-partner", issuer="Tether",
    ) is False


def test_admin_takes_precedence_over_issuer_restriction(monkeypatch):
    """A key listed in BOTH admins AND issuers gets universal access
    (admin trumps the narrower allow-list)."""
    from recupero.api.auth import is_authorized_to_record_outcome
    monkeypatch.setenv("RECUPERO_API_KEY_ADMINS", "k1")
    monkeypatch.setenv("RECUPERO_API_KEY_ISSUERS", "k1:Tether")
    # Issuer NOT in k1's narrow list but k1 is admin → True.
    assert is_authorized_to_record_outcome(
        api_key_name="k1", issuer="Coinbase",
    ) is True


# ─────────────────────────────────────────────────────────────────────────────
# Full FastAPI route — partner-key scoping
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def partner_client(monkeypatch):
    """API client with TWO partner keys configured:
      * exchange-acme: only allowed to record outcomes for Tether
      * partner-b:     only allowed to record outcomes for Coinbase
    Neither is an admin.
    """
    monkeypatch.setenv(
        "RECUPERO_API_KEYS",
        "exchange-acme:secret-acme,partner-b:secret-b",
    )
    monkeypatch.setenv(
        "RECUPERO_API_KEY_ISSUERS",
        "exchange-acme:Tether,partner-b:Coinbase",
    )
    monkeypatch.delenv("RECUPERO_API_KEY_ADMINS", raising=False)
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import app
    return TestClient(app)


def test_partner_can_write_for_allowlisted_issuer(partner_client):
    """Happy path: exchange-acme posts for Tether → 201."""
    with patch(
        "recupero.freeze_learning.recorder.record_outcome_by_target",
        return_value=OUTCOME_ID,
    ):
        resp = _post(partner_client, "secret-acme",
                     _default_payload(issuer="Tether"))
    assert resp.status_code == 201
    assert resp.json()["outcome_id"] == str(OUTCOME_ID)


def test_partner_denied_for_foreign_issuer(partner_client):
    """exchange-acme tries to write for Coinbase → 404 with the
    SAME generic detail as the missing-letter path. The recorder
    is NEVER called (verified via a call_count assertion)."""
    with patch(
        "recupero.freeze_learning.recorder.record_outcome_by_target",
    ) as recorder_mock:
        resp = _post(partner_client, "secret-acme",
                     _default_payload(issuer="Coinbase"))
    assert resp.status_code == 404
    assert resp.json()["detail"] == "freeze outcome not recorded"
    # Recorder was NEVER invoked — denial happened pre-DB.
    assert recorder_mock.call_count == 0


def test_partner_denied_response_indistinguishable_from_missing_letter(partner_client):
    """The auth-denied response and the letter-not-found response
    must be byte-identical so an attacker cannot probe for valid
    (case_id, issuer, target_address) triples."""
    from recupero.freeze_learning.recorder import LetterNotFoundError
    # First: unauthorized attempt (foreign issuer).
    with patch(
        "recupero.freeze_learning.recorder.record_outcome_by_target",
    ):
        unauth_resp = _post(
            partner_client, "secret-acme",
            _default_payload(issuer="Coinbase"),
        )
    # Second: authorized but letter doesn't exist.
    with patch(
        "recupero.freeze_learning.recorder.record_outcome_by_target",
        side_effect=LetterNotFoundError(
            f"no match (case={CASE_ID} issuer=Tether target={TARGET})",
        ),
    ):
        missing_resp = _post(
            partner_client, "secret-acme",
            _default_payload(issuer="Tether"),
        )
    # Both 404. Both same body. Outside view = no oracle.
    assert unauth_resp.status_code == 404
    assert missing_resp.status_code == 404
    assert unauth_resp.json() == missing_resp.json()
    assert "Coinbase" not in unauth_resp.text  # input not echoed
    assert "Tether" not in missing_resp.text   # input not echoed


def test_unknown_api_key_returns_401_not_404(partner_client):
    """A completely unknown API secret returns 401 (auth layer),
    NOT 404 (we don't even reach the multi-tenant gate)."""
    resp = _post(partner_client, "totally-bogus-secret",
                 _default_payload(issuer="Tether"))
    assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Source-level guard: the endpoint MUST call the gate
# ─────────────────────────────────────────────────────────────────────────────


def test_endpoint_source_invokes_authorization_gate():
    """Defense-in-depth: a future refactor that drops the call to
    `is_authorized_to_record_outcome` would silently re-open the
    vulnerability. Pin the call site at source level."""
    import inspect
    from recupero.api import app as app_mod
    src = inspect.getsource(app_mod.record_freeze_outcome_endpoint)
    assert "is_authorized_to_record_outcome" in src
    # The gate must run BEFORE the recorder call.
    gate_pos = src.find("is_authorized_to_record_outcome")
    recorder_pos = src.find("record_outcome_by_target")
    assert gate_pos > 0 and recorder_pos > gate_pos, (
        "authorization gate must run before the DB write"
    )
