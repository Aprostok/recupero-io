"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { ApiError, AuditEvent, api } from "@/lib/api";

const ACTION_LABELS: Record<string, string> = {
  "org.created": "Organization created",
  "auth.login": "Signed in",
  "apikey.created": "API key created",
  "apikey.revoked": "API key revoked",
  "member.invited": "Member invited",
  "invite.accepted": "Invite accepted",
  "invite.revoked": "Invite revoked",
  "member.role_changed": "Role changed",
  "member.removed": "Member removed",
};

export default function ActivityPage() {
  const { token } = useAuth();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const { events } = await api.listAudit(token);
      setEvents(events);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "failed to load activity");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <section className="panel">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h3 style={{ margin: 0 }}>Security activity</h3>
        <button className="ghost" onClick={refresh} disabled={loading}>
          {loading ? "…" : "Refresh"}
        </button>
      </div>
      {error && <div className="error">{error}</div>}
      {events.length === 0 && !loading ? (
        <p className="muted">No activity recorded yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Event</th>
              <th>Target</th>
              <th>Actor</th>
              <th>Outcome</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td className="muted">
                  {e.occurred_at
                    ? new Date(e.occurred_at).toLocaleString()
                    : "—"}
                </td>
                <td>{ACTION_LABELS[e.action] || e.action}</td>
                <td className="mono">{e.target || "—"}</td>
                <td className="mono">{e.actor}</td>
                <td>
                  <span
                    className={`badge ${e.outcome === "success" ? "ok" : "warn"}`}
                  >
                    {e.outcome}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
