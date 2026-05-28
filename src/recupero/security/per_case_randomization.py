"""Per-case randomized thresholds — defeat adversary code-reading.

JACOB_ADVERSARY_AUDIT_v032.md (M-5, ranks #4 + #15 in the top-gaps
table) showed that every Recupero threshold — ``min_fanout=10``,
``service_wallet_outflow_threshold=200``, ``_SHARED_INFRA_PARTNER_THRESHOLD=5``,
the CEX-continuity window, the clustering minimums — is fixed in the
source and trivially readable by an adversary who has cloned the repo.
The adversary then picks one less:

    fanout 10 known    → adversary fans out to 9
    outflows 200 known → adversary sends 199 outflows
    shared-infra 5     → adversary touches exactly 4 partners

Each evasion is one bit cheaper than the previous: the perpetrator
spends nothing while Recupero gives up coverage of the entire
adversarial near-threshold band.

The fix is per-case randomization. For every threshold T with base
value B, we resolve T as ``B * (1 + jitter)`` where ``jitter`` is
deterministically derived from HMAC-SHA256 of ``(case_id, threshold_name)``
under a server-side secret ``RECUPERO_RANDOMIZATION_SECRET``. The
output is bounded to ``[1-jitter_pct, 1+jitter_pct] * B`` (default
±30%). The result:

* **Deterministic**: same case_id + threshold_name → same threshold
  on every re-run. Reproducibility is preserved, which matters for
  briefs that may need to be regenerated for court.
* **Per-case unpredictable**: across 100 cases the threshold
  distribution is uniformly spread across the jitter band (verified
  in tests via Pearson correlation < 0.1).
* **Secret-bound**: an adversary who reads the source but does NOT
  have the env-var secret cannot predict any threshold. The secret
  is held server-side and rotated independently of code releases.
* **Forensic-friendly**: every resolved threshold is rendered in the
  brief's "case configuration" footer so a reviewer can audit what
  values were used.

Dev-mode fallback
-----------------

When ``RECUPERO_RANDOMIZATION_SECRET`` is unset (local dev, CI without
a secret store, smoke tests), the module falls back to the literal
string ``"DEV_FALLBACK_NOT_FOR_PRODUCTION"`` and logs a one-time
WARN. Production deployments MUST set this var; the runbook covers
rotation. The fallback is intentionally a constant rather than zero
randomization so dev-mode behavior remains close to prod-mode (the
randomization still happens, it's just predictable to anyone who
reads this file).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import struct
from typing import NamedTuple

log = logging.getLogger(__name__)


# Sentinel used in dev / CI when no secret is configured. Intentionally
# verbose so a grep of any deployment artifact reveals it instantly.
_DEV_FALLBACK_SECRET = "DEV_FALLBACK_NOT_FOR_PRODUCTION"

# Env var name. Documented in .env.example.
_SECRET_ENV_VAR = "RECUPERO_RANDOMIZATION_SECRET"

# Module-level flag so we only log the dev-fallback WARN once per
# process. Resetting this is permitted from tests (the module exposes
# a ``_reset_warn_state`` hook for that).
_warned_about_fallback = False


def _resolve_secret() -> tuple[bytes, bool]:
    """Resolve the HMAC secret from env.

    Returns ``(secret_bytes, is_dev_fallback)``. The dev-fallback
    branch logs WARN once per process. We always return at least 16
    bytes of key material (the dev sentinel is much longer than that).
    """
    raw = (os.environ.get(_SECRET_ENV_VAR, "") or "").strip()
    if raw:
        return raw.encode("utf-8"), False
    global _warned_about_fallback
    if not _warned_about_fallback:
        log.warning(
            "%s not set — falling back to %r. "
            "This is fine for local dev / CI smoke tests but "
            "MUST be set in production. An adversary who reads "
            "the source code can predict every per-case threshold "
            "without this secret.",
            _SECRET_ENV_VAR,
            _DEV_FALLBACK_SECRET,
        )
        _warned_about_fallback = True
    return _DEV_FALLBACK_SECRET.encode("utf-8"), True


def _reset_warn_state() -> None:
    """Reset the module-level "have we warned about dev-fallback" flag.

    Used by tests that need to assert the WARN is emitted exactly once.
    Not part of the public API; do not call from production code.
    """
    global _warned_about_fallback
    _warned_about_fallback = False


def _hmac_unit_interval(case_id: str, threshold_name: str, secret: bytes) -> float:
    """HMAC-SHA256 to a float in ``[0, 1)``.

    Uses the first 8 bytes of the digest as an unsigned 64-bit
    integer, divided by ``2**64``. This gives ~1e-19 spacing — plenty
    for any threshold size we care about. We do NOT use ``random``
    seeded from the HMAC because Python's PRNG is not guaranteed to
    be a perfect random oracle on the HMAC output across versions.
    """
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id must be a non-empty string")
    if not isinstance(threshold_name, str) or not threshold_name:
        raise ValueError("threshold_name must be a non-empty string")
    msg = f"{case_id}:{threshold_name}".encode("utf-8")
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    (n,) = struct.unpack(">Q", digest[:8])
    return n / float(1 << 64)


def case_threshold(
    case_id: str,
    threshold_name: str,
    base_value: int,
    jitter_pct: float = 0.30,
) -> int:
    """HMAC-derived per-case threshold within ``±jitter_pct`` of ``base_value``.

    The returned integer is deterministic per ``(case_id, threshold_name)``
    AND a server-held secret. An adversary who reads the source but
    does not have the secret cannot predict the value.

    Args:
        case_id: Stable case identifier (typically the case UUID
            stringified). Empty string is rejected.
        threshold_name: Short identifier of which threshold is being
            resolved (e.g. ``"dust_min_fanout"``). The same name must
            be used at the lookup site and any test that pins behavior.
            Empty string is rejected.
        base_value: The configured default value the jitter wraps
            around. Must be ``>= 1``; values less than ``1`` are
            silently clamped to ``1`` after jitter (so the floor of
            any threshold is 1 — useful for fanout / outflow counters
            that must be a positive integer).
        jitter_pct: The half-width of the jitter band, expressed as
            a fraction of ``base_value``. Default 0.30 (±30%). Values
            outside ``(0.0, 1.0)`` raise ``ValueError`` — a jitter
            >= 100% would let the threshold cross zero, and a
            non-positive jitter is a useless no-op.

    Returns:
        The randomized integer threshold.

    Raises:
        ValueError: on bad inputs.
    """
    if not isinstance(base_value, int) or base_value < 1:
        raise ValueError(
            f"base_value must be a positive int; got {base_value!r}"
        )
    if not isinstance(jitter_pct, (int, float)) or not (0.0 < jitter_pct < 1.0):
        raise ValueError(
            f"jitter_pct must be in (0.0, 1.0); got {jitter_pct!r}"
        )
    secret, _is_fallback = _resolve_secret()
    u = _hmac_unit_interval(case_id, threshold_name, secret)
    # Map u in [0, 1) to a multiplier in [1-jitter_pct, 1+jitter_pct].
    multiplier = (1.0 - jitter_pct) + (2.0 * jitter_pct) * u
    # Round to nearest int, floor at 1 so the threshold is never 0
    # (which would degenerate most detectors to "always-fire").
    return max(1, int(round(base_value * multiplier)))


class CaseThresholds(NamedTuple):
    """Resolved per-case thresholds bundle.

    Returned by :func:`get_case_thresholds`. Each field is the
    randomized value for one named threshold. Field documentation
    notes the source default in the upstream module so reviewers
    can correlate the brief footer with the trace source.

    Field naming convention: ``<module>_<thing>`` so the brief
    footer can group them by area.
    """

    #: Min number of distinct dust destinations from a single source
    #: for the dust-attack pattern to fire. Upstream default 10
    #: (``recupero.trace.dust_attack.identify_dust_attack_destinations``).
    dust_min_fanout: int
    #: Min outflow count for the service-wallet detector. Upstream
    #: default 200 (``config.py``). An adversary fanning out to 199
    #: was the audit's Route 3 evasion.
    service_wallet_outflow: int
    #: Max distinct interaction-partners before an address is treated
    #: as shared infrastructure (CEX hot wallet, popular router) and
    #: skipped for clustering. Upstream default 5
    #: (``recupero.trace.clustering._SHARED_INFRA_PARTNER_THRESHOLD``).
    shared_infra_partner: int
    #: Min USD value for a transfer to contribute to clustering.
    #: Upstream default $100 (``clustering._MIN_CLUSTERING_USD``).
    min_clustering_usd: int
    #: CEX continuity window in hours. Upstream default 6
    #: (``cex_continuity._DEFAULT_WINDOW_HOURS``). The audit's
    #: Route 1 off-ramp spread deposits across 36h precisely to
    #: defeat this window.
    cex_continuity_window_h: int
    #: Per-transfer dust threshold in USD. Upstream default $1
    #: (``dust_attack.identify_dust_attack_destinations``).
    dust_threshold_usd: int
    #: Common-funding clustering window in hours. Upstream default 24
    #: (``clustering._COMMON_FUNDING_WINDOW``).
    common_funding_window_h: int


def get_case_thresholds(case_id: str) -> CaseThresholds:
    """Resolve all per-case-randomized thresholds for ``case_id``.

    Each call returns a new ``CaseThresholds`` NamedTuple whose
    fields are deterministic per ``(case_id, secret)``. The base
    values match the upstream module defaults at the time this
    function was written; if the upstream defaults change, update
    them HERE (single source of truth) and the new band-center
    propagates automatically.

    See the per-field docstring on :class:`CaseThresholds` for the
    upstream-module reference of each base value.
    """
    return CaseThresholds(
        dust_min_fanout=case_threshold(case_id, "dust_min_fanout", 10),
        service_wallet_outflow=case_threshold(case_id, "service_wallet_outflow", 200),
        shared_infra_partner=case_threshold(case_id, "shared_infra_partner", 5),
        min_clustering_usd=case_threshold(case_id, "min_clustering_usd", 100),
        cex_continuity_window_h=case_threshold(case_id, "cex_continuity_window_h", 6),
        dust_threshold_usd=case_threshold(case_id, "dust_threshold_usd", 1),
        common_funding_window_h=case_threshold(case_id, "common_funding_window_h", 24),
    )
