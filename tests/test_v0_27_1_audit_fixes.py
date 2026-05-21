"""v0.27.1 audit-fix regression tests.

Each test pins one v0.27.0 audit finding so the bug cannot quietly
regress.

  * CRIT-1 — SSRF defense: assert_webhook_url_safe blocks
    loopback / private / link-local / metadata / .internal hosts;
    enforces https-only
  * CRIT-2 — bulk-screen per-element 128-char cap (Pydantic
    field_validator)
  * CRIT-3 — bulk-screen broad exception catch (per-row tolerance)
  * HIGH-1 — webhook_secret minimum length 16 chars
  * HIGH-3 — api-key-mint secret goes to stderr (stdout redacted)
  * HIGH-4 — list/get responses mask webhook_url
  * HIGH-5 — list/delete distinguish DB error (raise) from no-row
"""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# CRIT-1 — SSRF defense
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("url", [
    # AWS / GCP / Azure instance-metadata
    "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "https://metadata.google.internal/computeMetadata/v1/instance/",
    "https://metadata.aws.internal/v1/",
    # Loopback (IPv4 + IPv6)
    "https://127.0.0.1:6379/",
    "https://localhost:8080/admin",
    "https://[::1]/",
    # Private RFC1918
    "https://10.0.0.5/webhook",
    "https://192.168.1.1/webhook",
    "https://172.16.0.99/webhook",
    # Railway / Docker / Kubernetes internal
    "https://supabase-db.railway.internal/",
    "https://some-svc.docker.internal/",
    "https://app.cluster.local/webhook",
    "https://foo.local/",
    # Cleartext HTTP also rejected (MED-3 fold-in)
    "http://api.example.com/webhook",
])
def test_crit1_blocked_webhook_urls_rejected(url):
    from recupero.api.monitoring_api import (
        MonitoringApiError,
        assert_webhook_url_safe,
    )
    with pytest.raises(MonitoringApiError) as exc:
        assert_webhook_url_safe(url)
    assert exc.value.field == "webhook_url"


def test_crit1_public_https_url_accepted():
    """Defense-in-depth: a normal public webhook must still work."""
    from recupero.api.monitoring_api import assert_webhook_url_safe
    # Should not raise — example.com resolves to a public IP.
    # If DNS isn't available at test time the resolve check returns
    # False and we still pass the static checks.
    assert_webhook_url_safe("https://hooks.example.com/recupero")


def test_crit1_ssrf_check_invoked_from_subscription_validator():
    """Validation chain MUST run assert_webhook_url_safe — not only
    the regex match (which the audit found accepts loopback)."""
    from recupero.api.monitoring_api import (
        MonitoringApiError,
        _validate_subscription_input,
    )
    with pytest.raises(MonitoringApiError) as exc:
        _validate_subscription_input(
            address="0x" + "a" * 40, chain="ethereum",
            trigger_type="any_movement", threshold_usd=None,
            webhook_url="https://169.254.169.254/leak",
            label=None, webhook_secret=None,
        )
    assert exc.value.field == "webhook_url"


# ─────────────────────────────────────────────────────────────────────────────
# CRIT-2 — bulk-screen per-element length cap
# ─────────────────────────────────────────────────────────────────────────────


def test_crit2_bulk_screen_rejects_oversized_address():
    """A single 129-char element should fail validation. Otherwise
    a partner could POST 100 × 16MB strings as a memory DoS."""
    from pydantic import ValidationError

    from recupero.api.app import BulkScreenRequest
    huge = "0x" + "a" * 200  # 202 chars > 128 cap
    with pytest.raises(ValidationError):
        BulkScreenRequest(addresses=["0x" + "b" * 40, huge])


def test_crit2_bulk_screen_rejects_empty_string_element():
    """Empty strings in the list must fail validation."""
    from pydantic import ValidationError

    from recupero.api.app import BulkScreenRequest
    with pytest.raises(ValidationError):
        BulkScreenRequest(addresses=["0x" + "a" * 40, ""])


def test_crit2_bulk_screen_accepts_valid_addresses():
    """A normal batch of EVM-shaped addresses passes."""
    from recupero.api.app import BulkScreenRequest
    req = BulkScreenRequest(addresses=["0x" + "a" * 40] * 5)
    assert len(req.addresses) == 5


# ─────────────────────────────────────────────────────────────────────────────
# CRIT-3 — bulk-screen broad exception catch
# ─────────────────────────────────────────────────────────────────────────────


def test_crit3_bulk_screen_source_catches_broad_exception():
    """The handler MUST catch broad Exception so a per-row DB outage
    doesn't 500 the whole batch (contract documented in the
    docstring at v0.27.0)."""
    import inspect

    from recupero.api import app as app_mod
    src = inspect.getsource(app_mod.screen_bulk_endpoint)
    # Must have a `except Exception` clause (not only TypeError /
    # ValueError).
    assert "except Exception" in src
    # Per-row error returned, not propagated.
    assert "screening failed for this address" in src


# ─────────────────────────────────────────────────────────────────────────────
# HIGH-1 — webhook_secret minimum length
# ─────────────────────────────────────────────────────────────────────────────


def test_high1_short_webhook_secret_rejected():
    from recupero.api.monitoring_api import (
        MonitoringApiError,
        _validate_subscription_input,
    )
    with pytest.raises(MonitoringApiError) as exc:
        _validate_subscription_input(
            address="0x" + "a" * 40, chain="ethereum",
            trigger_type="any_movement", threshold_usd=None,
            webhook_url="https://example.com/hook", label=None,
            webhook_secret="too-short",  # 9 chars < 16
        )
    assert exc.value.field == "webhook_secret"


def test_high1_empty_webhook_secret_rejected():
    """Empty-string secret is the silent-downgrade bug from the
    audit — must fail validation."""
    from recupero.api.monitoring_api import (
        MonitoringApiError,
        _validate_subscription_input,
    )
    with pytest.raises(MonitoringApiError) as exc:
        _validate_subscription_input(
            address="0x" + "a" * 40, chain="ethereum",
            trigger_type="any_movement", threshold_usd=None,
            webhook_url="https://example.com/hook", label=None,
            webhook_secret="",
        )
    assert exc.value.field == "webhook_secret"


def test_high1_none_webhook_secret_allowed():
    """Omitting the secret entirely is fine — partner just won't get
    HMAC signatures on their webhook."""
    from recupero.api.monitoring_api import _validate_subscription_input
    _validate_subscription_input(
        address="0x" + "a" * 40, chain="ethereum",
        trigger_type="any_movement", threshold_usd=None,
        webhook_url="https://example.com/hook", label=None,
        webhook_secret=None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# HIGH-3 — api-key-mint secret prints to stderr, not stdout
# ─────────────────────────────────────────────────────────────────────────────


def test_high3_api_key_mint_secret_on_stderr_not_stdout():
    """Run `python -m recupero.ops.cli api-key-mint exchange-x` and
    verify the secret appears in stderr while stdout shows the
    redacted ('***') marker."""
    proc = subprocess.run(
        [sys.executable, "-m", "recupero.ops.cli",
         "api-key-mint", "exchange-test", "--bytes", "16"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, (
        f"command failed: stderr={proc.stderr!r}"
    )
    # Stdout MUST NOT contain a 32+ hex-char run (would be the
    # secret). The redacted snippet contains "***".
    assert "***" in proc.stdout, (
        f"redacted marker missing from stdout: {proc.stdout!r}"
    )
    # Find any 32+ consecutive hex char string in stdout — there
    # should be NONE (the secret should only be in stderr).
    import re as _re
    hex_runs = _re.findall(r"[0-9a-f]{32,}", proc.stdout)
    assert not hex_runs, (
        f"stdout leaked a hex-secret-shaped string: {hex_runs}"
    )
    # Stderr DOES contain a hex-shaped secret (32 hex chars from
    # --bytes 16).
    stderr_hex = _re.findall(r"[0-9a-f]{32,}", proc.stderr)
    assert stderr_hex, (
        f"stderr should have contained the secret: {proc.stderr!r}"
    )
    # And the "DO NOT COPY" banner is present.
    assert "DO NOT COPY" in proc.stderr


# ─────────────────────────────────────────────────────────────────────────────
# HIGH-4 — list/get responses mask the webhook URL
# ─────────────────────────────────────────────────────────────────────────────


def test_high4_mask_webhook_url_helper():
    from recupero.api.monitoring_api import _mask_webhook_url
    masked = _mask_webhook_url(
        "https://compliance.acme-exchange.com/webhooks/recupero/secret-token-abc"
    )
    # Scheme + host kept; only first path segment retained.
    assert "compliance.acme-exchange.com" in masked
    assert "/webhooks" in masked
    # Secret tail must be gone.
    assert "secret-token-abc" not in masked
    assert masked.endswith("/…")


def test_high4_subscription_record_to_json_safe_masks_by_default_off():
    """The default (mask_webhook_url=False) preserves full URL — for
    the immediate create-response (partner needs the round-trip
    confirmation). Default-OFF behavior intentionally."""
    from recupero.api.monitoring_api import SubscriptionRecord
    rec = SubscriptionRecord(
        id=UUID("11111111-1111-1111-1111-111111111111"),
        address="0xabc", chain="ethereum", trigger_type="any_movement",
        threshold_usd=None,
        webhook_url="https://acme.example.com/webhooks/recupero/secret123",
        label="x", status="active",
        created_at=None, last_alerted_at=None, expires_at=None,
    )
    full = rec.to_json_safe()  # default: mask=False
    masked = rec.to_json_safe(mask_webhook_url=True)
    assert "secret123" in full["webhook_url"]
    assert "secret123" not in masked["webhook_url"]


# ─────────────────────────────────────────────────────────────────────────────
# HIGH-5 — list/delete distinguish DB error from no-row
# ─────────────────────────────────────────────────────────────────────────────


def test_high5_list_subscriptions_raises_on_db_error():
    """A Supabase blip during list MUST raise MonitoringDbError —
    the API layer surfaces this as 503. Pre-fix code returned []
    and the partner saw "no subscriptions" which is misleading."""
    from recupero.api.monitoring_api import (
        MonitoringDbError,
        list_subscriptions,
    )

    def _boom(*a, **kw):
        raise RuntimeError("simulated supabase outage")

    with patch("recupero._common.db_connect", side_effect=_boom):
        with pytest.raises(MonitoringDbError):
            list_subscriptions(
                api_key_name="partner-x", dsn="postgres://fake",
                limit=50,
            )


def test_high5_soft_delete_raises_on_db_error():
    """DB blip during delete must NOT return False (which would
    surface as a misleading 404). Must raise so the API returns 503
    with retry semantics."""
    from recupero.api.monitoring_api import (
        MonitoringDbError,
        soft_delete_subscription,
    )

    def _boom(*a, **kw):
        raise RuntimeError("simulated supabase outage")

    with patch("recupero._common.db_connect", side_effect=_boom):
        with pytest.raises(MonitoringDbError):
            soft_delete_subscription(
                api_key_name="x",
                subscription_id=UUID("11111111-1111-1111-1111-111111111111"),
                dsn="postgres://fake",
            )


def test_high5_get_subscription_raises_on_db_error():
    """Same contract for get."""
    from recupero.api.monitoring_api import (
        MonitoringDbError,
        get_subscription,
    )

    def _boom(*a, **kw):
        raise RuntimeError("simulated supabase outage")

    with patch("recupero._common.db_connect", side_effect=_boom):
        with pytest.raises(MonitoringDbError):
            get_subscription(
                api_key_name="x",
                subscription_id=UUID("11111111-1111-1111-1111-111111111111"),
                dsn="postgres://fake",
            )


def test_high5_get_returns_none_when_no_row_matches():
    """A successful query that returns no rows STILL returns None
    (not MonitoringDbError) — the API layer maps to 404."""
    from recupero.api.monitoring_api import get_subscription

    cur = MagicMock()
    cur.fetchone.return_value = None
    cur.execute = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)

    with patch("recupero._common.db_connect", return_value=conn):
        result = get_subscription(
            api_key_name="x",
            subscription_id=UUID("11111111-1111-1111-1111-111111111111"),
            dsn="postgres://fake",
        )
    assert result is None
