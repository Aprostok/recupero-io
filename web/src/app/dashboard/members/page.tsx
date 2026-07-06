"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { ApiError, Invite, Member, api } from "@/lib/api";

const ROLES = ["admin", "member", "viewer"];

export default function MembersPage() {
  const { token } = useAuth();
  const [members, setMembers] = useState<Member[]>([]);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");
  const [inviting, setInviting] = useState(false);
  const [inviteLink, setInviteLink] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [m, i] = await Promise.all([
        api.listMembers(token),
        api.listInvites(token).catch(() => ({ invites: [] })),
      ]);
      setMembers(m.members);
      setInvites(i.invites);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "failed to load members");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onInvite(e: FormEvent) {
    e.preventDefault();
    if (!token) return;
    setInviting(true);
    setError(null);
    setInviteLink(null);
    try {
      const res = await api.createInvite(token, email, role);
      setInviteLink(res.accept_url);
      setEmail("");
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "invite failed");
    } finally {
      setInviting(false);
    }
  }

  async function onRole(userId: string, newRole: string) {
    if (!token) return;
    setError(null);
    try {
      await api.setMemberRole(token, userId, newRole);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "role change failed");
    }
  }

  async function onRemove(userId: string) {
    if (!token) return;
    setError(null);
    try {
      await api.removeMember(token, userId);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "remove failed");
    }
  }

  async function onRevoke(inviteId: string) {
    if (!token) return;
    try {
      await api.revokeInvite(token, inviteId);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "revoke failed");
    }
  }

  return (
    <div className="stack" style={{ gap: 24 }}>
      <section className="panel">
        <h3 style={{ marginTop: 0 }}>Invite a teammate</h3>
        <form className="row" onSubmit={onInvite}>
          <input
            style={{ flex: 2, minWidth: 220 }}
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="teammate@company.com"
            required
          />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <button type="submit" disabled={inviting}>
            {inviting ? "Inviting…" : "Send invite"}
          </button>
        </form>
        {inviteLink && (
          <div className="stack" style={{ marginTop: 12 }}>
            <label>Invite link — share it with the invitee (shown once)</label>
            <input className="mono" readOnly value={inviteLink} />
          </div>
        )}
        {error && (
          <div className="error" style={{ marginTop: 8 }}>
            {error}
          </div>
        )}
      </section>

      <section className="panel">
        <h3 style={{ marginTop: 0 }}>Members</h3>
        {members.length === 0 && !loading ? (
          <p className="muted">No members.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Role</th>
                <th>Joined</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <tr key={m.user_id}>
                  <td>
                    {m.email}
                    {m.name ? <span className="muted"> · {m.name}</span> : null}
                  </td>
                  <td>
                    {m.role === "owner" ? (
                      <span className="badge">owner</span>
                    ) : (
                      <select
                        value={m.role}
                        onChange={(e) => onRole(m.user_id, e.target.value)}
                      >
                        {ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    )}
                  </td>
                  <td className="muted">
                    {m.joined_at
                      ? new Date(m.joined_at).toLocaleDateString()
                      : "—"}
                  </td>
                  <td>
                    {m.role !== "owner" && (
                      <button
                        className="danger"
                        onClick={() => onRemove(m.user_id)}
                      >
                        Remove
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {invites.length > 0 && (
        <section className="panel">
          <h3 style={{ marginTop: 0 }}>Pending invites</h3>
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Role</th>
                <th>Expires</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {invites.map((i) => (
                <tr key={i.id}>
                  <td>{i.email}</td>
                  <td>{i.role}</td>
                  <td className="muted">
                    {new Date(i.expires_at).toLocaleDateString()}
                  </td>
                  <td>
                    <button className="danger" onClick={() => onRevoke(i.id)}>
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
