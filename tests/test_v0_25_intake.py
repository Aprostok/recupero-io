"""v0.25.0 — Victim intake form tests.

Covers:
  * validate_intake_payload — every field-level validation rule
  * IntakeValidationError surfaces (field, detail) correctly
  * create_case_from_intake — mocked-DB happy path + error path
  * GET /v1/intake — returns the form HTML
  * POST /v1/intake — happy path → 303 to Stripe; validation error → 422 + form re-render
  * POST /v1/intake — DSN unset → 503 with generic detail (no leak)
  * POST /v1/intake — payment link config missing → 503 with helpful detail
"""

from __future__ import annotations

import os
from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from recupero.portal.intake import (
    IntakePayload,
    IntakeValidationError,
    validate_intake_payload,
)


# ─────────────────────────────────────────────────────────────────────────────
# validate_intake_payload — pure function
# ─────────────────────────────────────────────────────────────────────────────


def _good_form(**overrides) -> dict:
    form = {
        "client_name": "Jane Doe",
        "client_email": "jane@example.com",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2026-05-01",
        "description": "Phishing site drained my wallet on May 1.",
        "country": "United States",
    }
    form.update(overrides)
    return form


def test_validate_happy_path_returns_intake_payload():
    payload = validate_intake_payload(_good_form())
    assert isinstance(payload, IntakePayload)
    assert payload.client_name == "Jane Doe"
    assert payload.client_email == "jane@example.com"  # lowercased
    assert payload.chain == "ethereum"
    assert payload.seed_address == "0x" + "a" * 40
    assert payload.incident_date_iso == "2026-05-01"
    assert payload.country == "United States"


def test_validate_email_lowercased():
    payload = validate_intake_payload(_good_form(client_email="JANE@Example.COM"))
    assert payload.client_email == "jane@example.com"


def test_validate_empty_name_rejected():
    with pytest.raises(IntakeValidationError) as exc:
        validate_intake_payload(_good_form(client_name=""))
    assert exc.value.field == "client_name"


def test_validate_email_must_have_at_sign():
    with pytest.raises(IntakeValidationError) as exc:
        validate_intake_payload(_good_form(client_email="not-an-email"))
    assert exc.value.field == "client_email"
    assert "doesn't look like a valid email" in exc.value.detail


def test_validate_chain_must_be_supported():
    with pytest.raises(IntakeValidationError) as exc:
        validate_intake_payload(_good_form(chain="dogecoin"))
    assert exc.value.field == "chain"
    assert "don't yet support" in exc.value.detail


def test_validate_evm_address_shape_rejects_bad_input():
    with pytest.raises(IntakeValidationError) as exc:
        validate_intake_payload(_good_form(seed_address="not-an-address"))
    assert exc.value.field == "seed_address"


def test_validate_evm_address_too_short_rejected():
    with pytest.raises(IntakeValidationError):
        validate_intake_payload(_good_form(seed_address="0xabc"))


def test_validate_evm_address_with_uppercase_hex_accepted():
    payload = validate_intake_payload(_good_form(
        seed_address="0x" + "A" * 20 + "b" * 20,
    ))
    assert payload.seed_address.startswith("0x")


def test_validate_solana_address_accepted():
    payload = validate_intake_payload(_good_form(
        chain="solana",
        seed_address="9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    ))
    assert payload.chain == "solana"


def test_validate_tron_address_accepted():
    payload = validate_intake_payload(_good_form(
        chain="tron",
        seed_address="TKzxdSv2FZKQrEqkKVgp5DcwEXBEKMg2Ax",
    ))
    assert payload.chain == "tron"


def test_validate_bitcoin_bech32_accepted():
    payload = validate_intake_payload(_good_form(
        chain="bitcoin",
        seed_address="bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    ))
    assert payload.chain == "bitcoin"


def test_validate_incident_date_required():
    with pytest.raises(IntakeValidationError) as exc:
        validate_intake_payload(_good_form(incident_date=""))
    assert exc.value.field == "incident_date"


def test_validate_incident_date_must_be_iso_shaped():
    with pytest.raises(IntakeValidationError) as exc:
        validate_intake_payload(_good_form(incident_date="May 1, 2026"))
    assert exc.value.field == "incident_date"


def test_validate_description_required():
    with pytest.raises(IntakeValidationError) as exc:
        validate_intake_payload(_good_form(description=""))
    assert exc.value.field == "description"


def test_validate_description_truncated_to_2000_chars():
    long_desc = "x" * 5000
    payload = validate_intake_payload(_good_form(description=long_desc))
    assert len(payload.description) == 2000


def test_validate_country_is_optional():
    payload = validate_intake_payload(_good_form(country=""))
    assert payload.country is None


# ─────────────────────────────────────────────────────────────────────────────
# create_case_from_intake — DB mocked
# ─────────────────────────────────────────────────────────────────────────────


def test_create_case_returns_uuid_on_success():
    """Happy path — INSERT succeeds, RETURNING id flows back."""
    from recupero.portal import intake as intake_mod

    fake_id = UUID("11111111-1111-1111-1111-111111111111")

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchone(self):
            return (str(fake_id),)
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    payload = validate_intake_payload(_good_form())
    with patch.object(intake_mod, "db_connect", return_value=_StubConn(), create=True):
        # The function imports db_connect lazily — patch at source.
        with patch("recupero._common.db_connect", return_value=_StubConn()):
            result = intake_mod.create_case_from_intake(payload, dsn="postgres://fake")
    assert result == fake_id


def test_create_case_raises_runtime_error_on_db_failure():
    """DB error → RuntimeError with generic detail (no DSN leak)."""
    from recupero.portal import intake as intake_mod

    payload = validate_intake_payload(_good_form())
    with patch(
        "recupero._common.db_connect",
        side_effect=RuntimeError("FATAL: password authentication failed at db.xxx.supabase.co:6543"),
    ):
        with pytest.raises(RuntimeError) as exc:
            intake_mod.create_case_from_intake(payload, dsn="postgres://fake")
    # Generic message — no DSN leak.
    assert "case creation failed" in str(exc.value)
    assert "password" not in str(exc.value)
    assert "supabase" not in str(exc.value)


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI endpoint tests
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def intake_client(monkeypatch):
    """TestClient with Stripe + DSN env configured so the POST
    happy path can build the diagnostic Payment Link."""
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    monkeypatch.setenv(
        "RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK",
        "https://buy.stripe.com/test_diagnostic_link",
    )
    # Disable auth optionalness — intake routes are public anyway.
    from recupero.api.app import app
    return TestClient(app, follow_redirects=False)


def test_get_intake_returns_html_form(intake_client):
    """GET /v1/intake returns the intake form HTML (no auth required)."""
    resp = intake_client.get("/v1/intake")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    # Key form elements present
    assert "Crypto stolen?" in resp.text
    assert 'name="client_name"' in resp.text
    assert 'name="seed_address"' in resp.text


def test_post_intake_happy_path_redirects_to_stripe(intake_client):
    """POST /v1/intake with valid form → 303 redirect to Stripe URL."""
    fake_id = UUID("22222222-2222-2222-2222-222222222222")
    with patch(
        "recupero.portal.intake.create_case_from_intake",
        return_value=fake_id,
    ):
        resp = intake_client.post(
            "/v1/intake",
            data=_good_form(),
        )
    assert resp.status_code == 303
    location = resp.headers.get("location", "")
    assert location.startswith("https://buy.stripe.com/")
    # case_id encoded into client_reference_id
    assert str(fake_id) in location


def test_post_intake_validation_error_renders_form_with_422(intake_client):
    """POST with bad email → 422 + HTML form re-rendered with error banner."""
    resp = intake_client.post(
        "/v1/intake",
        data=_good_form(client_email="not-an-email"),
    )
    assert resp.status_code == 422
    assert "text/html" in resp.headers.get("content-type", "")
    # Jinja autoescape converts apostrophes to &#39; — assert on a
    # substring that's stable across escape semantics.
    assert "valid email address" in resp.text
    assert "error-banner" in resp.text
    # Form should re-populate prior values
    assert "Jane Doe" in resp.text


def test_post_intake_missing_dsn_returns_503(intake_client, monkeypatch):
    """No SUPABASE_DB_URL → 503 with generic detail (no leak)."""
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    resp = intake_client.post("/v1/intake", data=_good_form())
    assert resp.status_code == 503
    body = resp.json()
    assert "temporarily unavailable" in body["detail"].lower()
    assert "supabase" not in body["detail"].lower()
    assert "postgres" not in body["detail"].lower()


def test_post_intake_db_failure_returns_503_without_leaking(intake_client):
    """DB write failure → 503 with generic detail. DSN / SQL error
    must NOT appear in the response body."""
    with patch(
        "recupero.portal.intake.create_case_from_intake",
        side_effect=RuntimeError("DB error at host=db.xxx.supabase.co"),
    ):
        resp = intake_client.post("/v1/intake", data=_good_form())
    assert resp.status_code == 503
    body = resp.json()
    assert "supabase" not in body["detail"].lower()
    assert "postgres" not in body["detail"].lower()
    assert "Something went wrong" in body["detail"]


def test_post_intake_stripe_config_missing_returns_503_helpful(intake_client, monkeypatch):
    """No RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK → 503 with helpful
    detail (the case IS recorded; operator can follow up manually)."""
    monkeypatch.delenv("RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK", raising=False)
    with patch(
        "recupero.portal.intake.create_case_from_intake",
        return_value=UUID("33333333-3333-3333-3333-333333333333"),
    ):
        resp = intake_client.post("/v1/intake", data=_good_form())
    assert resp.status_code == 503
    body = resp.json()
    # Tells the victim we have their info — important UX so they
    # don't panic and pay twice.
    assert "recorded your intake" in body["detail"].lower()
