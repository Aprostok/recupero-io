"use client";

import { FormEvent, Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

/**
 * Public invite-acceptance page: `/invite?token=…`. The token in the URL is the
 * proof the invitee received the emailed link. Existing users join instantly;
 * new users set a password to create their account. On success we store the
 * returned session and drop into the dashboard.
 */
function AcceptInvite() {
  const params = useSearchParams();
  const router = useRouter();
  const { setSession } = useAuth();
  const inviteToken = params.get("token") || "";

  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const out = await api.acceptInvite(
        inviteToken,
        password || undefined,
        name || undefined,
      );
      setSession(out.access_token, out.org_id);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "could not accept invite");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="brand" style={{ marginBottom: 24 }}>
        Recupero
      </div>
      <div className="panel">
        {!inviteToken ? (
          <p className="error">Missing invite token.</p>
        ) : (
          <form className="stack" onSubmit={onSubmit}>
            <h2 style={{ margin: 0 }}>Accept invitation</h2>
            <p className="muted" style={{ margin: 0, fontSize: 12 }}>
              Joining an existing account? Leave the password blank. New here?
              Set a password (10+ chars) to create your account.
            </p>
            <div className="stack">
              <label htmlFor="name">Name (optional)</label>
              <input
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="stack">
              <label htmlFor="password">Password (new accounts only)</label>
              <input
                id="password"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {error && <div className="error">{error}</div>}
            <button type="submit" disabled={busy}>
              {busy ? "Joining…" : "Join organization"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default function InvitePage() {
  return (
    <Suspense fallback={<div className="auth-shell"><p className="muted">Loading…</p></div>}>
      <AcceptInvite />
    </Suspense>
  );
}
