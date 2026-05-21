"""PUNISH-A: punishing tests for v0.25 victim intake portal.

The intake form is the first thing a panicking victim sees minutes
after losing money. The intake confirmation email is the first
message they get from Recupero. Both are customer-facing — both
must be perfect.

Tests below mirror what a real victim or operator would notice on
inspection. No "if found" / "may contain" softening — every check
is unconditional and quotes the failing string on a fail.
"""

from __future__ import annotations

import re
from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def api_client(monkeypatch):
    """FastAPI TestClient with intake routes available.

    Resets the v0.25.1 IP rate-limit state per test so each test
    gets a fresh budget — without this every test after the 5th
    POST hits 429 from the shared module-global dict. (Real
    operators don't share IPs across legitimate sessions; the
    rate limit is right in production, just needs test isolation.)
    """
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import _intake_rl_state, app
    _intake_rl_state.clear()
    return TestClient(app)


def _get_intake_html(client) -> str:
    resp = client.get("/v1/intake")
    assert resp.status_code == 200, (
        f"GET /v1/intake returned {resp.status_code}, expected 200. "
        "The intake form is the funnel entry — it MUST be reachable."
    )
    return resp.text


# ─────────────────────────────────────────────────────────────────────────────
# GET /v1/intake — empty form structural checks
# ─────────────────────────────────────────────────────────────────────────────


def test_form_html_starts_with_doctype(api_client):
    html = _get_intake_html(api_client)
    assert html.lstrip().startswith("<!DOCTYPE"), (
        "intake form must be a proper HTML doc (starts with <!DOCTYPE)"
    )


def test_form_title_names_the_product(api_client):
    """The browser tab title must identify the product — a victim
    landing here from a Google search shouldn't see a blank tab."""
    html = _get_intake_html(api_client)
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    assert m, "no <title> tag"
    title = m.group(1).strip()
    assert "Recupero" in title, (
        f"<title> is {title!r} — must include 'Recupero'"
    )


def test_form_has_every_required_field(api_client):
    """The intake spec requires: client_name, client_email, chain,
    seed_address, incident_date, description. Each field must have
    an <input>/<select>/<textarea> with the right `name` attribute."""
    html = _get_intake_html(api_client)
    required = [
        "client_name", "client_email", "chain",
        "seed_address", "incident_date", "description",
    ]
    missing = [
        n for n in required
        if f'name="{n}"' not in html
    ]
    assert not missing, (
        f"intake form missing required input(s): {missing}"
    )


def test_form_chain_dropdown_lists_every_supported_chain(api_client):
    """Every chain in intake.py:_SUPPORTED_CHAINS must appear as an
    <option> in the dropdown. A user with a Hyperliquid wallet
    landing here and not seeing 'hyperliquid' as an option is told,
    falsely, that we don't support their case."""
    from recupero.portal.intake import _SUPPORTED_CHAINS
    html = _get_intake_html(api_client)
    missing = [
        chain for chain in _SUPPORTED_CHAINS
        if f'value="{chain}"' not in html
    ]
    assert not missing, (
        f"chain dropdown missing options: {missing}. "
        "intake.py validates these chains as supported but the "
        "form doesn't let the user pick them."
    )


def test_form_has_no_unrendered_jinja(api_client):
    """The intake form must not leak {{ ... }} or {% ... %} blocks."""
    html = _get_intake_html(api_client)
    var_matches = re.findall(r"\{\{[^}]+\}\}", html)
    block_matches = re.findall(r"\{%[^%]+%\}", html)
    assert not var_matches, (
        f"intake form has {len(var_matches)} unrendered Jinja vars: "
        f"{var_matches[:3]!r}"
    )
    assert not block_matches, (
        f"intake form has {len(block_matches)} unrendered Jinja blocks"
    )


def test_form_has_no_placeholder_strings(api_client):
    """No TODO/FIXME/TBD/PLACEHOLDER on the public form."""
    html = _get_intake_html(api_client)
    forbidden = ["TODO", "FIXME", "XXX", "TBD", "PLACEHOLDER"]
    leaked = [w for w in forbidden if w in html]
    assert not leaked, (
        f"intake form leaked: {leaked}"
    )


def test_form_has_visible_submit_button(api_client):
    html = _get_intake_html(api_client)
    assert re.search(r"<button[^>]*type=\"submit\"", html, re.IGNORECASE), (
        "no submit button found"
    )


def test_form_explains_what_recupero_will_do(api_client):
    """A panicking victim needs reassurance text — the form must
    explain what Recupero will actually do with their info, and
    what they should expect after submitting."""
    html = _get_intake_html(api_client)
    plain = re.sub(r"<[^>]+>", " ", html).lower()
    # Must mention "trace" + something about timeline or report
    assert "trace" in plain, (
        "form body does not mention 'trace' — the core service"
    )
    assert any(w in plain for w in ("24 hours", "report", "minutes", "diagnostic")), (
        "form body has no timeline / deliverable expectation"
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /v1/intake — validation-error re-rendering
# ─────────────────────────────────────────────────────────────────────────────


def test_post_invalid_email_returns_422_with_error_banner(api_client):
    """Posting a bad email must re-render the form with an error
    banner. The banner must surface the field name AND a victim-
    friendly explanation."""
    resp = api_client.post("/v1/intake", data={
        "client_name": "Jane Doe",
        "client_email": "not-an-email",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2026-05-01",
        "description": "drained",
        "country": "US",
    })
    assert resp.status_code == 422, (
        f"expected 422 on invalid email, got {resp.status_code}"
    )
    text = resp.text
    assert "error-banner" in text, (
        "no error-banner CSS class in the 422 re-render"
    )
    assert "email" in text.lower(), (
        "422 body doesn't mention the failing field 'email'"
    )


def test_post_invalid_email_preserves_other_form_values(api_client):
    """When the form 422s, the user's OTHER inputs (name, chain,
    description) must be preserved so they don't have to retype
    everything. Failing to preserve == frustrated victim abandons."""
    resp = api_client.post("/v1/intake", data={
        "client_name": "Jane Doe",
        "client_email": "not-an-email",
        "chain": "polygon",
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2026-05-01",
        "description": "My funds were drained at 3am.",
        "country": "US",
    })
    text = resp.text
    # Name preserved
    assert 'value="Jane Doe"' in text, (
        "client_name not preserved on form re-render"
    )
    # Chain selection preserved
    assert 'value="polygon" selected' in text or 'selected>Polygon' in text, (
        "chain selection not preserved"
    )
    # Description preserved
    assert "My funds were drained at 3am." in text, (
        "description not preserved"
    )


def test_post_html_escapes_form_values_with_special_chars(api_client):
    """An evil name like '<script>alert(1)</script>' must appear in
    the re-rendered form as HTML-escaped — never as a raw script tag."""
    resp = api_client.post("/v1/intake", data={
        "client_name": "<script>alert(1)</script>",
        "client_email": "not-an-email",  # forces 422 re-render
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2026-05-01",
        "description": "drained",
        "country": "US",
    })
    text = resp.text
    assert "<script>alert(1)</script>" not in text, (
        "raw <script> tag found in re-rendered form — XSS hazard"
    )
    assert "&lt;script&gt;" in text, (
        "<script> should be HTML-escaped to &lt;script&gt;"
    )


def test_post_invalid_chain_returns_422(api_client):
    resp = api_client.post("/v1/intake", data={
        "client_name": "Jane",
        "client_email": "jane@example.com",
        "chain": "dogecoin",  # not supported
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2026-05-01",
        "description": "drained",
    })
    assert resp.status_code == 422


def test_post_future_incident_date_rejected(api_client):
    """v0.25.1 added bounds: incident_date must be in past 10 years
    and not in the future."""
    resp = api_client.post("/v1/intake", data={
        "client_name": "Jane",
        "client_email": "jane@example.com",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2099-01-01",  # far future
        "description": "drained",
    })
    assert resp.status_code == 422, (
        "future incident_date must be rejected (v0.25.1 CRIT A-1)"
    )


def test_post_long_description_rejected(api_client):
    """v0.25.1 changed silent truncation → explicit rejection."""
    resp = api_client.post("/v1/intake", data={
        "client_name": "Jane",
        "client_email": "jane@example.com",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2026-05-01",
        "description": "x" * 2500,  # > 2000
    })
    assert resp.status_code == 422, (
        "description > 2000 chars must be rejected (v0.25.1 HIGH A-3) "
        "not silently truncated"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Intake confirmation email HTML
# ─────────────────────────────────────────────────────────────────────────────


def _build_confirmation_html(**kwargs) -> str:
    from recupero.portal.intake_notifications import _build_confirmation_html
    defaults = {
        "client_name": "Jane Doe",
        "case_number": "RCP-CASE-2026-001",
        "portal_url": "https://recupero.io/portal/abc123",
    }
    defaults.update(kwargs)
    return _build_confirmation_html(**defaults)


def test_confirmation_email_names_the_victim(api_client):
    html = _build_confirmation_html(client_name="Jane Doe")
    assert "Jane Doe" in html, (
        "confirmation email does not greet the victim by name"
    )


def test_confirmation_email_includes_case_number(api_client):
    html = _build_confirmation_html(case_number="RCP-INTAKE-2026-abc12345")
    assert "RCP-INTAKE-2026-abc12345" in html, (
        "confirmation email omits the case number — victim can't "
        "reference their case in a reply"
    )


def test_confirmation_email_has_portal_url_button(api_client):
    """The 'View case status' button must be wired to the portal URL.
    A button with href='#' or missing href would be a silent dead-end."""
    html = _build_confirmation_html(
        portal_url="https://recupero.io/portal/sample-token-xyz",
    )
    # The portal URL must appear in an href attribute.
    assert 'href="https://recupero.io/portal/sample-token-xyz"' in html, (
        "portal URL not wired to a clickable href"
    )


def test_confirmation_email_lists_what_happens_next(api_client):
    """The 'what happens next' section calms the victim. All 4 steps
    must render: trace start, report timeline, engagement decision,
    refund-if-not-recoverable."""
    html = _build_confirmation_html()
    plain = re.sub(r"<[^>]+>", " ", html).lower()
    # The email body lists 4 numbered/bulleted items per the
    # template — confirm each concept appears.
    expected_concepts = [
        "minute",   # "within minutes"
        "24 hours",
        "engage",   # "engage us / engagement decision"
        "refund",   # "refund the $499"
    ]
    missing = [c for c in expected_concepts if c not in plain]
    assert not missing, (
        f"confirmation email body missing 'what happens next' "
        f"concepts: {missing}"
    )


def test_confirmation_email_html_escapes_apostrophe_in_name(api_client):
    """A name like O'Brien must render with HTML-safe escaping —
    the raw apostrophe in an HTML attribute could break the markup,
    and a name like <script>...</script> obviously can't render."""
    html = _build_confirmation_html(
        client_name="O'Brien <script>alert(1)</script>",
    )
    assert "<script>alert(1)</script>" not in html, (
        "raw <script> tag in email body — XSS hazard via name"
    )
    assert "&lt;script&gt;" in html, (
        "script tag should be HTML-escaped"
    )
    # apostrophe should be escaped (&#x27; or &#39; both acceptable)
    assert ("&#x27;" in html) or ("&#39;" in html), (
        "apostrophe in name should be HTML-escaped"
    )


def test_confirmation_email_has_no_unrendered_jinja(api_client):
    html = _build_confirmation_html()
    assert "{{ " not in html, "unrendered Jinja {{ }} in email"
    assert "{% " not in html, "unrendered Jinja {% %} in email"


def test_confirmation_email_has_no_placeholder_strings(api_client):
    html = _build_confirmation_html()
    forbidden = ["TODO", "FIXME", "XXX", "TBD", "PLACEHOLDER"]
    leaked = [w for w in forbidden if w in html]
    assert not leaked, (
        f"confirmation email leaked: {leaked}"
    )


def test_confirmation_email_brands_recupero(api_client):
    """The email must visibly identify itself as from Recupero —
    spam filters and the recipient both need that signal."""
    html = _build_confirmation_html()
    assert "Recupero" in html, (
        "confirmation email does not say 'Recupero' anywhere"
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST happy path
# ─────────────────────────────────────────────────────────────────────────────


def test_post_happy_path_303_redirect_to_stripe(api_client):
    """A valid intake POST must create a case + return 303 with a
    Location header pointing at Stripe Checkout. Any other status
    code or destination is a customer-experience break."""
    fake_case_id = UUID("11111111-1111-1111-1111-111111111111")
    fake_stripe_url = "https://checkout.stripe.com/c/pay/cs_test_123"
    with patch(
        "recupero.portal.intake.create_case_from_intake",
        return_value=fake_case_id,
    ), patch(
        "recupero.payments.payment_links.build_diagnostic_link",
        return_value=fake_stripe_url,
    ):
        resp = api_client.post(
            "/v1/intake",
            data={
                "client_name": "Jane Doe",
                "client_email": "jane@example.com",
                "chain": "ethereum",
                "seed_address": "0x" + "a" * 40,
                "incident_date": "2026-05-01",
                "description": "drained at 3am",
                "country": "US",
            },
            follow_redirects=False,
        )
    assert resp.status_code == 303, (
        f"happy-path POST returned {resp.status_code}, "
        "expected 303 redirect"
    )
    assert resp.headers.get("location", "").startswith(
        "https://checkout.stripe.com"
    ), (
        f"303 Location header is {resp.headers.get('location')!r}, "
        "expected Stripe checkout URL"
    )
