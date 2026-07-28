"use client";

/**
 * Password reset — BOTH halves of the flow.
 *
 * The backend emails `{APP_BASE_URL}/reset?token=…` (platform/router.py
 * request_password_reset), but this page did not exist, so every reset link
 * 404'd and a forgotten password was a permanent lockout.
 *
 *  * no `?token=`  → ask for the email and request a link
 *  * with `?token=` → set the new password
 *
 * The request step ALWAYS reports the same "check your email" result, matching
 * the server's deliberate no-user-enumeration contract (always 202, token never
 * returned in the response).
 */

import { FormEvent, Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { Brand } from "@/components/Brand";

function ResetPasswordInner() {
  const params = useSearchParams();
  const token = params?.get("token") || "";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onRequest(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.requestPasswordReset(email.trim());
      setSent(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "request failed");
    } finally {
      setBusy(false);
    }
  }

  async function onConfirm(e: FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("The two passwords don't match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.confirmPasswordReset(token, password);
      setDone(true);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.status === 400
            ? "That reset link is invalid or has expired — request a new one."
            : err.detail
          : "reset failed",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-shell stack" style={{ gap: 20 }}>
      <Brand size={26} />

      {/* ---- Step 2: a token is present → set the new password ---- */}
      {token ? (
        done ? (
          <section className="panel stack">
            <h3 style={{ marginTop: 0 }}>Password updated</h3>
            <p className="muted" style={{ margin: 0 }}>
              You can now sign in with your new password.
            </p>
            <Link href="/login">
              <button>Go to sign in</button>
            </Link>
          </section>
        ) : (
          <section className="panel stack">
            <h3 style={{ marginTop: 0 }}>Choose a new password</h3>
            <form className="stack" onSubmit={onConfirm}>
              <div className="stack">
                <label htmlFor="pw">New password</label>
                <input
                  id="pw"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  minLength={10}
                  required
                  autoComplete="new-password"
                />
                <span className="muted" style={{ fontSize: 12 }}>
                  At least 10 characters.
                </span>
              </div>
              <div className="stack">
                <label htmlFor="pw2">Confirm new password</label>
                <input
                  id="pw2"
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  minLength={10}
                  required
                  autoComplete="new-password"
                />
              </div>
              <button type="submit" disabled={busy}>
                {busy ? "Updating…" : "Update password"}
              </button>
              {error && <p className="error">{error}</p>}
            </form>
          </section>
        )
      ) : /* ---- Step 1: no token → request a reset link ---- */
      sent ? (
        <section className="panel stack">
          <h3 style={{ marginTop: 0 }}>Check your email</h3>
          <p className="muted" style={{ margin: 0 }}>
            If an account exists for that address, we&apos;ve sent a reset link.
            It expires in one hour.
          </p>
          <Link href="/login" className="muted">
            ← Back to sign in
          </Link>
        </section>
      ) : (
        <section className="panel stack">
          <h3 style={{ marginTop: 0 }}>Reset your password</h3>
          <p className="muted" style={{ marginTop: 0 }}>
            Enter your email and we&apos;ll send you a reset link.
          </p>
          <form className="stack" onSubmit={onRequest}>
            <div className="stack">
              <label htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
              />
            </div>
            <button type="submit" disabled={busy}>
              {busy ? "Sending…" : "Send reset link"}
            </button>
            {error && <p className="error">{error}</p>}
          </form>
          <Link href="/login" className="muted">
            ← Back to sign in
          </Link>
        </section>
      )}
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense
      fallback={
        <div className="auth-shell">
          <p className="muted">Loading…</p>
        </div>
      }
    >
      <ResetPasswordInner />
    </Suspense>
  );
}
