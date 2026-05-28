"""Security primitives for adversary-resistant trace operation.

Modules here close gaps identified in JACOB_ADVERSARY_AUDIT_v032.md:
an adversary with READ access to the repository source designs a route
specifically to evade Recupero's fixed thresholds. The defenses here
make per-case behavior unpredictable WITHOUT compromising
reproducibility for the case-owner (every threshold is deterministic
from a HMAC of case_id + a server-held secret).
"""

from recupero.security.per_case_randomization import (
    CaseThresholds,
    case_threshold,
    get_case_thresholds,
)

__all__ = [
    "CaseThresholds",
    "case_threshold",
    "get_case_thresholds",
]
