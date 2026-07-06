"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { ApiKeySummary, ApiError, api } from "@/lib/api";

export default function KeysPage() {
  const { token } = useAuth();
  const [keys, setKeys] = useState<ApiKeySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const { keys } = await api.listKeys(token);
      setKeys(keys);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "failed to load keys");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    if (!token) return;
    setCreating(true);
    setError(null);
    setNewKey(null);
    try {
      const res = await api.createKey(token, name);
      setNewKey(res.api_key);
      setName("");
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "create failed");
    } finally {
      setCreating(false);
    }
  }

  async function onRevoke(id: string) {
    if (!token) return;
    setError(null);
    try {
      await api.revokeKey(token, id);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "revoke failed");
    }
  }

  return (
    <div className="stack" style={{ gap: 24 }}>
      <section className="panel">
        <h3 style={{ marginTop: 0 }}>Create API key</h3>
        <form className="row" onSubmit={onCreate}>
          <input
            style={{ flex: 1, minWidth: 200 }}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. production-server"
            required
          />
          <button type="submit" disabled={creating}>
            {creating ? "Creating…" : "Create key"}
          </button>
        </form>
        {newKey && (
          <div className="stack" style={{ marginTop: 12 }}>
            <label>New key — copy it now, it will not be shown again</label>
            <input className="mono" readOnly value={newKey} />
          </div>
        )}
        {error && (
          <div className="error" style={{ marginTop: 8 }}>
            {error}
          </div>
        )}
      </section>

      <section className="panel">
        <h3 style={{ marginTop: 0 }}>Keys</h3>
        {keys.length === 0 && !loading ? (
          <p className="muted">No keys yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Key</th>
                <th>Created</th>
                <th>Last used</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td className="mono">rk_live_…{k.last4}</td>
                  <td className="muted">
                    {new Date(k.created_at).toLocaleDateString()}
                  </td>
                  <td className="muted">
                    {k.last_used_at
                      ? new Date(k.last_used_at).toLocaleString()
                      : "never"}
                  </td>
                  <td>
                    {k.revoked ? (
                      <span className="badge muted">revoked</span>
                    ) : (
                      <button
                        className="danger"
                        onClick={() => onRevoke(k.id)}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
