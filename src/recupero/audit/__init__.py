"""Append-only audit logging (SOC 2 CC6/CC7).

A guarded, never-raising audit trail of security-sensitive actions — the first
concrete control toward SOC 2 / enterprise procurement. ``record_audit_event``
writes one row; there is no update/delete path (append-only by convention).
Writers call it best-effort: a missing table or DB error is logged, never
propagated into the action being audited. Reads degrade to an empty list when
the DSN / table is absent.
"""

from recupero.audit.store import (
    AuditEvent,
    list_audit_events,
    record_audit_event,
)

__all__ = ("AuditEvent", "record_audit_event", "list_audit_events")
