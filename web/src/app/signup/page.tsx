"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { ApiError } from "@/lib/api";
import { Brand } from "@/components/Brand";

export default function SignupPage() {
  const { signup } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await signup(email, password, orgName);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "signup failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-shell">
      <Brand style={{ marginBottom: 24 }} />
      <div className="panel">
        <form className="stack" onSubmit={onSubmit}>
          <h2 style={{ margin: 0 }}>Create your organization</h2>
          <div className="stack">
            <label htmlFor="org">Organization name</label>
            <input
              id="org"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              required
            />
          </div>
          <div className="stack">
            <label htmlFor="email">Work email</label>
            <input
              id="email"
              type="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="stack">
            <label htmlFor="password">Password (10+ characters)</label>
            <input
              id="password"
              type="password"
              autoComplete="new-password"
              minLength={10}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {error && <div className="error">{error}</div>}
          <button type="submit" disabled={busy}>
            {busy ? "Creating…" : "Create account"}
          </button>
          <p className="muted" style={{ margin: 0, fontSize: 12 }}>
            Starts on the free plan — {`5 traces/mo`}. Upgrade anytime.
          </p>
        </form>
      </div>
      <p className="muted" style={{ marginTop: 16 }}>
        Already have an account? <Link href="/login">Sign in</Link>
      </p>
    </div>
  );
}
